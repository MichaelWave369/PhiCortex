"""Mutually authenticated TLS transport for signed PhiCortex heartbeats only.

Real loopback/LAN HTTPS I/O, no remote commands, permits or task dispatch.
Both a CA-verified client certificate *and* a pinned node-specific cert
fingerprint bound to an Ed25519-signed heartbeat are required.
"""
from __future__ import annotations

import argparse
from contextlib import closing
import hashlib
from http.client import HTTPSConnection
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
import ipaddress
import json
from pathlib import Path
import re
import sqlite3
import ssl
import time

from .mesh import MeshError, NodeRegistry, MAX_PACKET_BYTES, canonical

PATH = "/mesh/v1/heartbeats"
MAX_REPLY_BYTES = 8192
RFC1918 = (
    ipaddress.ip_network("10.0.0.0/8"),
    ipaddress.ip_network("172.16.0.0/12"),
    ipaddress.ip_network("192.168.0.0/16"),
)


class TransportError(RuntimeError):
    pass


def validate_endpoint(host: str, port: int, *, allow_lan: bool = False,
                      ephemeral: bool = False) -> str:
    """Explicitly disallow binding on public, wildcard, or IPv6 addresses."""
    try:
        addr = ipaddress.ip_address(host)
    except ValueError as exc:
        raise TransportError("host must be an explicit numeric IPv4 address") from exc
    if addr.version != 4 or addr.is_unspecified or addr.is_multicast:
        raise TransportError("wildcard, multicast and IPv6 addresses are refused")
    if type(port) is not int or not (0 if ephemeral else 1) <= port <= 65535:
        raise TransportError("port is outside permitted range")
    if addr.is_loopback:
        return str(addr)
    if not (allow_lan and any(addr in block for block in RFC1918)):
        raise TransportError("LAN requires --allow-lan and an RFC1918 IPv4 address")
    return str(addr)


def _read_cert(path: Path) -> bytes:
    """Read public X.509 cert in PEM or DER for operator pinning."""
    if path.is_symlink():
        raise TransportError("symlinked TLS certificate is refused")
    try:
        if not path.is_file() or path.stat().st_size > 65536:
            raise TransportError("invalid TLS certificate file")
        data = path.read_bytes()
        if data.startswith(b"-----BEGIN CERTIFICATE-----"):
            der = ssl.PEM_cert_to_DER_cert(data.decode("ascii"))
        else:
            der = data
        # Parsing prevents pinning arbitrary non-certificate bytes.
        from cryptography import x509
        x509.load_der_x509_certificate(der)
        return der
    except (OSError, UnicodeError, ValueError, ssl.SSLError) as exc:
        raise TransportError("could not parse client certificate") from exc


class TransportPins:
    """Operator-only certificate binding, within the node SQLite registry."""

    def __init__(self, database: Path):
        self.nodes = NodeRegistry(database)
        with closing(self.nodes._connect()) as db:
            with db:
                db.execute("""CREATE TABLE IF NOT EXISTS node_tls_pins (
                    node_id TEXT PRIMARY KEY REFERENCES nodes(id),
                    certificate_sha256 TEXT NOT NULL UNIQUE,
                    bound_at INTEGER NOT NULL
                )""")

    def bind(self, node_id: str, cert: Path, *, now: int | None = None) -> dict:
        from .mesh import _id
        _id(node_id)
        fingerprint = hashlib.sha256(_read_cert(cert)).hexdigest()
        when = int(time.time()) if now is None else now
        if type(when) is not int or when < 0:
            raise TransportError("invalid binding timestamp")
        with closing(self.nodes._connect()) as db:
            db.execute("BEGIN IMMEDIATE")
            try:
                node = db.execute("SELECT revoked FROM nodes WHERE id=?",
                                  (node_id,)).fetchone()
                if node is None or node["revoked"]:
                    raise TransportError("only non-revoked enrolled nodes can be bound")
                try:
                    db.execute("""INSERT INTO node_tls_pins
                        (node_id,certificate_sha256,bound_at)
                        VALUES (?,?,?)""", (node_id, fingerprint, when))
                except sqlite3.IntegrityError as exc:
                    raise TransportError("certificate or node already bound; revoke and re-enroll to rotate") from exc
                db.commit()
            except BaseException:
                db.rollback()
                raise
        return {"node_id": node_id, "certificate_sha256": fingerprint,
                "bound_at": when, "execution_authorized": False}


def server_context(server_cert: Path, server_key: Path, client_ca: Path) -> ssl.SSLContext:
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    ctx.minimum_version = ssl.TLSVersion.TLSv1_3
    ctx.verify_mode = ssl.CERT_REQUIRED
    ctx.load_verify_locations(cafile=str(client_ca))
    ctx.load_cert_chain(certfile=str(server_cert), keyfile=str(server_key))
    return ctx


def client_context(server_ca: Path, client_cert: Path, client_key: Path) -> ssl.SSLContext:
    # Trust *only* the supplied local CA, not the entire OS trust store.
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    ctx.minimum_version = ssl.TLSVersion.TLSv1_3
    ctx.verify_mode = ssl.CERT_REQUIRED
    ctx.check_hostname = True
    ctx.load_verify_locations(cafile=str(server_ca))
    ctx.load_cert_chain(certfile=str(client_cert), keyfile=str(client_key))
    return ctx


def handler_factory(nodes: NodeRegistry):
    class Handler(BaseHTTPRequestHandler):
        protocol_version = "HTTP/1.0"

        def log_message(self, fmt, *args):
            # Do not log signed packets or private coordinator metadata.
            return

        def answer(self, status: int, data: dict) -> None:
            body = canonical(data)
            self.send_response(status)
            self.send_header("Content-Type", "application/json")
            self.send_header("Cache-Control", "no-store")
            self.send_header("X-Content-Type-Options", "nosniff")
            self.send_header("Content-Length", str(len(body)))
            self.send_header("Connection", "close")
            self.end_headers()
            self.wfile.write(body)

        def do_GET(self):
            self.answer(404, {"error": "no read-only remote API"})

        def do_POST(self):
            if self.path != PATH:
                self.answer(404, {"error": "unknown endpoint"})
                return
            lengths = self.headers.get_all("Content-Length", [])
            if (self.headers.get("Transfer-Encoding") is not None or len(lengths) != 1
                    or not lengths[0].isdigit()):
                self.answer(400, {"error": "a fixed content length is required"})
                return
            size = int(lengths[0])
            if not 1 <= size <= MAX_PACKET_BYTES:
                self.answer(413, {"error": "packet too large or empty"})
                return
            if self.headers.get("Content-Type", "").split(";")[0].strip().lower() != "application/json":
                self.answer(415, {"error": "expected JSON"})
                return
            cert = self.connection.getpeercert(binary_form=True)
            if not cert:
                self.answer(403, {"error": "client certificate required"})
                return
            try:
                data = json.loads(self.rfile.read(size).decode("utf-8"))
                result = nodes.accept(
                    data, tls_peer_sha256=hashlib.sha256(cert).hexdigest())
            except (ValueError, UnicodeError):
                self.answer(400, {"error": "invalid JSON"})
            except MeshError:
                # No node-enumeration details returned to remote peers.
                self.answer(403, {"error": "heartbeat not authorized"})
            else:
                self.answer(200, {
                    "node_id": result["node_id"], "sequence": result["sequence"],
                    "status": result["status"], "expires_at": result["expires_at"],
                    "execution_authorized": False, "task_dispatched": False})
    return Handler


class TransportHTTPServer(ThreadingHTTPServer):
    daemon_threads = True
    request_queue_size = 8


def start_server(nodes: NodeRegistry, ctx: ssl.SSLContext,
                 host: str = "127.0.0.1", port: int = 8766,
                 *, allow_lan: bool = False) -> TransportHTTPServer:
    host = validate_endpoint(host, port, allow_lan=allow_lan, ephemeral=True)
    server = TransportHTTPServer((host, port), handler_factory(nodes))
    try:
        server.socket = ctx.wrap_socket(server.socket, server_side=True)
    except BaseException:
        server.server_close()
        raise
    return server


def send_heartbeat(host: str, port: int, packet: dict,
                   ca: Path, cert: Path, key: Path,
                   *, allow_lan: bool = False) -> dict:
    host = validate_endpoint(host, port, allow_lan=allow_lan)
    payload = canonical(packet)
    if not 1 <= len(payload) <= MAX_PACKET_BYTES:
        raise TransportError("heartbeat exceeds packet size limit")
    context = client_context(ca, cert, key)
    conn = HTTPSConnection(host, port, context=context, timeout=5)
    try:
        conn.request("POST", PATH, body=payload,
                     headers={"Content-Type": "application/json",
                              "Content-Length": str(len(payload))})
        response = conn.getresponse()
        body = response.read(MAX_REPLY_BYTES + 1)
        if len(body) > MAX_REPLY_BYTES:
            raise TransportError("coordinator reply exceeds limit")
        if response.status != 200:
            raise TransportError(f"coordinator rejected heartbeat (HTTP {response.status})")
        reply = json.loads(body.decode("utf-8"))
        if (not isinstance(reply, dict) or reply.get("execution_authorized") is not False
                or reply.get("task_dispatched") is not False):
            raise TransportError("invalid coordinator response")
        return reply
    except (OSError, ssl.SSLError, UnicodeError, ValueError) as exc:
        raise TransportError("secure heartbeat exchange failed") from exc
    finally:
        conn.close()


def main(argv=None) -> int:
    parser = argparse.ArgumentParser(
        description="Opt-in mutually authenticated TLS transport for signed heartbeats only")
    commands = parser.add_subparsers(dest="action", required=True)
    bind = commands.add_parser("bind-client-cert", help="trusted local operator action")
    bind.add_argument("--db", type=Path, required=True)
    bind.add_argument("--node-id", required=True)
    bind.add_argument("--cert", type=Path, required=True)
    serve = commands.add_parser("serve", help="start restricted mTLS heartbeat listener")
    serve.add_argument("--db", type=Path, required=True)
    serve.add_argument("--cert", type=Path, required=True)
    serve.add_argument("--key", type=Path, required=True)
    serve.add_argument("--client-ca", type=Path, required=True)
    serve.add_argument("--listen", default="127.0.0.1")
    serve.add_argument("--port", type=int, default=8766)
    serve.add_argument("--allow-lan", action="store_true")
    send = commands.add_parser("send", help="transmit a signed heartbeat packet")
    send.add_argument("--host", required=True)
    send.add_argument("--port", type=int, default=8766)
    send.add_argument("--packet", type=Path, required=True)
    send.add_argument("--ca", type=Path, required=True)
    send.add_argument("--cert", type=Path, required=True)
    send.add_argument("--key", type=Path, required=True)
    send.add_argument("--allow-lan", action="store_true")
    args = parser.parse_args(argv)
    try:
        if args.action == "bind-client-cert":
            result = TransportPins(args.db).bind(args.node_id, args.cert)
            print(json.dumps(result, indent=2))
        elif args.action == "serve":
            validate_endpoint(args.listen, args.port, allow_lan=args.allow_lan)
            pins = TransportPins(args.db)
            context = server_context(args.cert, args.key, args.client_ca)
            server = start_server(pins.nodes, context, args.listen, args.port,
                                  allow_lan=args.allow_lan)
            try:
                print(f"Mesh heartbeat mTLS listener on {args.listen}:{args.port} "
                      "(NO task execution)", flush=True)
                server.serve_forever(poll_interval=0.1)
            except KeyboardInterrupt:
                pass
            finally:
                server.server_close()
        else:
            if args.packet.stat().st_size > MAX_PACKET_BYTES:
                raise TransportError("packet file too large")
            payload = json.loads(args.packet.read_text(encoding="utf-8"))
            result = send_heartbeat(args.host, args.port, payload,
                                    args.ca, args.cert, args.key,
                                    allow_lan=args.allow_lan)
            print(json.dumps(result, indent=2, sort_keys=True))
        return 0
    except (TransportError, MeshError, OSError, ValueError, ssl.SSLError) as exc:
        parser.exit(2, f"refused: {exc}\n")


if __name__ == "__main__":
    raise SystemExit(main())
