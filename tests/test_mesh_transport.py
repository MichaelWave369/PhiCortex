"""Real local loopback mTLS heartbeat tests.

These exercise TLS 1.3 handshakes, certificate pinning, signed heartbeat
validation and network refusal. No worker code is dispatched or executed.
"""
from __future__ import annotations

from concurrent.futures import ThreadPoolExecutor
from datetime import datetime, timedelta, timezone
import hashlib
import http.client
import sqlite3
import json
import ipaddress
from pathlib import Path
import ssl
import tempfile
import threading
import time
import unittest
from uuid import uuid4

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.x509.oid import ExtendedKeyUsageOID, NameOID

from phicortex.mesh import NodeRegistry, sign_heartbeat
from phicortex.leases import TaskLeases
from phicortex.lease_exchange import sign_exchange
from phicortex.mesh_transport import (
    TransportError, TransportPins, client_context, server_context,
    start_server, send_heartbeat, send_lease_request, validate_endpoint, PATH
)


def write(path: Path, data: bytes) -> Path:
    path.write_bytes(data)
    if path.suffix == ".key":
        path.chmod(0o600)
    return path


def pem_key(key) -> bytes:
    return key.private_bytes(serialization.Encoding.PEM,
                             serialization.PrivateFormat.PKCS8,
                             serialization.NoEncryption())


class PKI:
    """Ephemeral local X.509 authority; certificates never leave the tests."""

    def __init__(self, root: Path):
        self.root = root
        self.now = datetime.now(timezone.utc)
        self.key = ec.generate_private_key(ec.SECP256R1())
        name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "PhiCortex Test CA")])
        self.ca = (x509.CertificateBuilder()
                   .subject_name(name).issuer_name(name).public_key(self.key.public_key())
                   .serial_number(x509.random_serial_number())
                   .not_valid_before(self.now - timedelta(days=1))
                   .not_valid_after(self.now + timedelta(days=2))
                   .add_extension(x509.BasicConstraints(ca=True, path_length=0), critical=True)
                   .add_extension(x509.KeyUsage(
                       digital_signature=True, content_commitment=False,
                       key_encipherment=False, data_encipherment=False,
                       key_agreement=False, key_cert_sign=True, crl_sign=True,
                       encipher_only=False, decipher_only=False), critical=True)
                   .sign(self.key, hashes.SHA256()))
        self.ca_path = write(root / "ca.pem", self.ca.public_bytes(serialization.Encoding.PEM))

    def identity(self, name: str, *, role: str = "client") -> tuple[Path, Path]:
        key = ec.generate_private_key(ec.SECP256R1())
        subject = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, name)])
        usage = ExtendedKeyUsageOID.SERVER_AUTH if role == "server" else ExtendedKeyUsageOID.CLIENT_AUTH
        builder = (x509.CertificateBuilder()
                   .subject_name(subject).issuer_name(self.ca.subject)
                   .public_key(key.public_key())
                   .serial_number(x509.random_serial_number())
                   .not_valid_before(self.now - timedelta(days=1))
                   .not_valid_after(self.now + timedelta(days=1))
                   .add_extension(x509.BasicConstraints(ca=False, path_length=None), critical=True)
                   .add_extension(x509.ExtendedKeyUsage([usage]), critical=False))
        if role == "server":
            builder = builder.add_extension(
                x509.SubjectAlternativeName([x509.IPAddress(
                    ipaddress.ip_address("127.0.0.1"))]), critical=False)
        cert = builder.sign(self.key, hashes.SHA256())
        cert_file = write(self.root / (name + ".pem"),
                          cert.public_bytes(serialization.Encoding.PEM))
        key_file = write(self.root / (name + ".key"), pem_key(key))
        return cert_file, key_file


class EndpointTests(unittest.TestCase):
    def test_loopback_is_default_and_only_explicit_rfc1918_lan_allowed(self):
        self.assertEqual(validate_endpoint("127.0.0.1", 8766), "127.0.0.1")
        for ip in ("0.0.0.0", "8.8.8.8", "169.254.3.2", "::1", "example.com"):
            with self.subTest(ip=ip), self.assertRaises(TransportError):
                validate_endpoint(ip, 8766, allow_lan=True)
        with self.assertRaises(TransportError):
            validate_endpoint("192.168.1.20", 8766)
        self.assertEqual(validate_endpoint("192.168.1.20", 8766, allow_lan=True),
                         "192.168.1.20")
        self.assertEqual(validate_endpoint("10.1.2.3", 8766, allow_lan=True),
                         "10.1.2.3")
        with self.assertRaises(TransportError):
            validate_endpoint("127.0.0.1", 0)


class TransportIntegrationTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        root = Path(self.tmp.name)
        self.pki = PKI(root)
        self.server_cert, self.server_key = self.pki.identity("server", role="server")
        self.client_cert, self.client_key = self.pki.identity("client")
        self.other_cert, self.other_key = self.pki.identity("other-client")
        self.database = root / "mesh.sqlite3"
        self.pins = TransportPins(self.database)
        self.node_id = str(uuid4())
        node_private = Ed25519PrivateKey.generate()
        self.node_key = node_private.private_bytes(
            serialization.Encoding.Raw, serialization.PrivateFormat.Raw,
            serialization.NoEncryption())
        node_pub = node_private.public_key().public_bytes(
            serialization.Encoding.Raw, serialization.PublicFormat.Raw)
        self.pins.nodes.enroll(self.node_id, "TLS Node 1", node_pub,
                               ["test"], now=int(time.time()))
        self.pins.bind(self.node_id, self.client_cert)
        self.server = start_server(
            self.pins.nodes,
            server_context(self.server_cert, self.server_key, self.pki.ca_path),
            port=0)
        self.thread = threading.Thread(target=self.server.serve_forever, daemon=True)
        self.thread.start()
        self.addCleanup(self.stop_server)

    def stop_server(self):
        self.server.shutdown()
        self.server.server_close()
        self.thread.join(timeout=4)

    @property
    def port(self):
        return self.server.server_port

    def packet(self, seq=1):
        return sign_heartbeat(self.node_id, seq, self.node_key)

    def send(self, packet, cert=None, key=None, ca=None):
        return send_heartbeat(
            "127.0.0.1", self.port, packet,
            ca or self.pki.ca_path,
            cert or self.client_cert,
            key or self.client_key)

    def test_real_mutual_tls_and_signed_heartbeat(self):
        result = self.send(self.packet(1))
        self.assertEqual(result["node_id"], self.node_id)
        self.assertEqual(result["status"], "online")
        self.assertFalse(result["execution_authorized"])
        self.assertFalse(result["task_dispatched"])
        self.assertEqual(self.pins.nodes.list_nodes()[0]["last_sequence"], 1)

    def test_replay_packet_refused_over_real_tls(self):
        packet = self.packet()
        self.send(packet)
        with self.assertRaisesRegex(TransportError, "403"):
            self.send(packet)

    def test_different_ca_trusted_client_cert_is_not_pinned(self):
        # Other cert is valid under the trusted CA, but not operator-bound
        # to this enrolled Ed25519 node identity.
        with self.assertRaisesRegex(TransportError, "403"):
            self.send(self.packet(), cert=self.other_cert, key=self.other_key)
        self.assertEqual(self.pins.nodes.list_nodes()[0]["status"], "enrolled")

    def test_tampered_signed_heartbeat_refused_over_tls(self):
        packet = self.packet()
        packet["body"]["state"] = "draining"
        with self.assertRaisesRegex(TransportError, "403"):
            self.send(packet)

    def test_revoked_node_refused_over_tls(self):
        self.pins.nodes.revoke(self.node_id)
        with self.assertRaisesRegex(TransportError, "403"):
            self.send(self.packet())

    def test_unpinned_fresh_node_cannot_send(self):
        new_key = Ed25519PrivateKey.generate()
        another = str(uuid4())
        self.pins.nodes.enroll(
            another, "No TLS Binding",
            new_key.public_key().public_bytes(
                serialization.Encoding.Raw, serialization.PublicFormat.Raw),
            ["test"])
        packet = sign_heartbeat(another, 1, new_key.private_bytes(
            serialization.Encoding.Raw, serialization.PrivateFormat.Raw,
            serialization.NoEncryption()))
        with self.assertRaisesRegex(TransportError, "403"):
            self.send(packet)

    def test_untrusted_server_ca_refused(self):
        with tempfile.TemporaryDirectory() as other:
            wrong_ca = PKI(Path(other)).ca_path
            with self.assertRaisesRegex(TransportError, "secure heartbeat"):
                self.send(self.packet(), ca=wrong_ca)

    def test_tls_client_certificate_required(self):
        ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
        ctx.minimum_version = ssl.TLSVersion.TLSv1_3
        ctx.check_hostname = True
        ctx.verify_mode = ssl.CERT_REQUIRED
        ctx.load_verify_locations(cafile=str(self.pki.ca_path))
        conn = http.client.HTTPSConnection("127.0.0.1", self.port,
                                           context=ctx, timeout=3)
        try:
            with self.assertRaises((OSError, ssl.SSLError, http.client.HTTPException)):
                conn.request("POST", PATH, body=b"{}",
                             headers={"Content-Type": "application/json"})
                response = conn.getresponse()
                response.read()
        finally:
            conn.close()

    def test_no_remote_execution_endpoint(self):
        conn = http.client.HTTPSConnection(
            "127.0.0.1", self.port,
            context=client_context(self.pki.ca_path, self.client_cert, self.client_key),
            timeout=3)
        try:
            conn.request("POST", "/v1/execute", body=b'{"shell":"whoami"}',
                         headers={"Content-Type": "application/json"})
            reply = conn.getresponse()
            self.assertEqual(reply.status, 404)
            self.assertNotIn("shell", reply.read().decode())
        finally:
            conn.close()

    def test_content_length_limit_is_enforced(self):
        conn = http.client.HTTPSConnection(
            "127.0.0.1", self.port,
            context=client_context(self.pki.ca_path, self.client_cert, self.client_key),
            timeout=3)
        try:
            conn.request("POST", PATH, body=b"x" * 5000,
                         headers={"Content-Type": "application/json"})
            reply = conn.getresponse()
            self.assertEqual(reply.status, 413)
            reply.read()
        finally:
            conn.close()

    def test_operator_cannot_rebind_client_certificate(self):
        with self.assertRaisesRegex(TransportError, "already bound"):
            self.pins.bind(self.node_id, self.other_cert)
        with self.assertRaises(TransportError):
            self.pins.bind(str(uuid4()), self.other_cert)

    def test_concurrent_identical_signed_heartbeats_only_one_accepted(self):
        packet = self.packet(1)
        def send_once(_):
            try:
                return self.send(packet)["sequence"]
            except TransportError:
                return None
        with ThreadPoolExecutor(max_workers=3) as executor:
            results = list(executor.map(send_once, range(3)))
        self.assertEqual(results.count(1), 1)
        self.assertEqual(results.count(None), 2)


    def assign_lease(self):
        self.send(self.packet(1))
        ledger = TaskLeases(self.database)
        task_id = str(uuid4())
        ledger.create(task_id, "test", "b" * 64)
        return ledger.lease(task_id, self.node_id, seconds=45)

    def lease_request(self, seq, *, action="preview", lease_id=None,
                      client_cert=None, client_key=None, signing_key=None):
        signed = sign_exchange(
            self.node_id, seq, self.node_key if signing_key is None else signing_key,
            action, lease_id=lease_id)
        return send_lease_request(
            "127.0.0.1", self.port, signed, action,
            self.pki.ca_path, client_cert or self.client_cert,
            client_key or self.client_key)

    def test_authenticated_lease_preview_is_metadata_only(self):
        assigned = self.assign_lease()
        result = self.lease_request(2)
        self.assertEqual(result["lease"]["task_id"], assigned["task_id"])
        self.assertEqual(result["lease"]["lease_id"], assigned["lease_id"])
        self.assertEqual(result["lease"]["task_sha256"], "b" * 64)
        self.assertFalse(result["lease"]["acknowledged"])
        self.assertFalse(result["execution_authorized"])
        self.assertFalse(result["task_dispatched"])
        self.assertFalse(result["task_payload_included"])
        self.assertFalse(result["governor_permit_included"])
        self.assertEqual(
            set(result["lease"]),
            {"task_id", "lease_id", "mode", "task_sha256", "deadline", "acknowledged"})
        self.assertNotIn("argv", json.dumps(result))
        self.assertNotIn("shell", json.dumps(result))

    def test_authenticated_ack_is_durable_and_idempotent_with_fresh_sequence(self):
        assigned = self.assign_lease()
        first = self.lease_request(2, action="ack", lease_id=assigned["lease_id"])
        self.assertTrue(first["lease"]["acknowledged"])
        again = self.lease_request(3, action="ack", lease_id=assigned["lease_id"])
        self.assertTrue(again["lease"]["acknowledged"])
        ledger = TaskLeases(self.database)
        events = [x["kind"] for x in ledger.events(assigned["task_id"])]
        self.assertEqual(events.count("lease_metadata_ack"), 1)
        self.assertEqual(ledger.get(assigned["task_id"])["status"], "leased")
        self.assertFalse(ledger.get(assigned["task_id"])["execution_authorized"])

    def test_ack_does_not_grant_execution_permission(self):
        assigned = self.assign_lease()
        result = self.lease_request(2, action="ack", lease_id=assigned["lease_id"])
        self.assertFalse(result["execution_authorized"])
        self.assertFalse(result["task_dispatched"])
        self.assertEqual(TaskLeases(self.database).get(assigned["task_id"])["status"], "leased")

    def test_no_active_task_returns_empty_preview(self):
        self.send(self.packet(1))
        result = self.lease_request(2)
        self.assertIsNone(result["lease"])

    def test_wrong_but_ca_trusted_certificate_cannot_preview(self):
        self.assign_lease()
        with self.assertRaisesRegex(TransportError, "403"):
            self.lease_request(2, client_cert=self.other_cert, client_key=self.other_key)

    def test_wrong_ed25519_key_cannot_preview(self):
        self.assign_lease()
        private = Ed25519PrivateKey.generate().private_bytes(
            serialization.Encoding.Raw, serialization.PrivateFormat.Raw,
            serialization.NoEncryption())
        with self.assertRaisesRegex(TransportError, "403"):
            self.lease_request(2, signing_key=private)

    def test_replayed_and_out_of_order_lease_requests_refused(self):
        self.assign_lease()
        self.lease_request(4)
        for number in (2, 3, 4):
            with self.assertRaisesRegex(TransportError, "403"):
                self.lease_request(number)
        self.assertEqual(self.pins.nodes.list_nodes()[0]["last_sequence"], 4)

    def test_signed_action_cannot_be_retargeted_to_ack_endpoint(self):
        assigned = self.assign_lease()
        bad = sign_exchange(self.node_id, 2, self.node_key, "preview")
        with self.assertRaisesRegex(TransportError, "403"):
            send_lease_request("127.0.0.1", self.port, bad, "ack",
                               self.pki.ca_path, self.client_cert, self.client_key)
        self.assertEqual(TaskLeases(self.database).get(assigned["task_id"])["status"], "leased")

    def test_wrong_lease_id_ack_refused_without_receipt(self):
        assigned = self.assign_lease()
        with self.assertRaisesRegex(TransportError, "403"):
            self.lease_request(2, action="ack", lease_id=str(uuid4()))
        events = TaskLeases(self.database).events(assigned["task_id"])
        self.assertEqual([e["kind"] for e in events], ["created", "leased"])

    def test_revoked_or_draining_node_cannot_preview(self):
        self.assign_lease()
        self.send(sign_heartbeat(self.node_id, 2, self.node_key, state="draining"))
        with self.assertRaisesRegex(TransportError, "403"):
            self.lease_request(3)
        self.pins.nodes.revoke(self.node_id)
        with self.assertRaisesRegex(TransportError, "403"):
            self.lease_request(4)

    def test_expired_heartbeat_refuses_lease_metadata(self):
        self.assign_lease()
        with sqlite3.connect(self.database) as db:
            db.execute("UPDATE nodes SET expires_at=? WHERE id=?",
                       (int(time.time()) - 1, self.node_id))
        with self.assertRaisesRegex(TransportError, "403"):
            self.lease_request(2)

    def test_expired_lease_cannot_be_acked_or_previews_as_active(self):
        task = self.assign_lease()
        with sqlite3.connect(self.database) as db:
            db.execute("UPDATE task_leases SET deadline=? WHERE task_id=?",
                       (int(time.time()) - 1, task["task_id"]))
        self.assertIsNone(self.lease_request(2)["lease"])
        with self.assertRaisesRegex(TransportError, "403"):
            self.lease_request(3, action="ack", lease_id=task["lease_id"])

    def test_concurrent_same_signed_preview_is_replay_safe(self):
        self.assign_lease()
        signed = sign_exchange(self.node_id, 2, self.node_key, "preview")
        def do(_):
            try:
                return send_lease_request(
                    "127.0.0.1", self.port, signed, "preview",
                    self.pki.ca_path, self.client_cert, self.client_key)["sequence"]
            except TransportError:
                return None
        with ThreadPoolExecutor(max_workers=4) as pool:
            values = list(pool.map(do, range(4)))
        self.assertEqual(values.count(2), 1)
        self.assertEqual(values.count(None), 3)

    def test_connection_failure_and_recovery_does_not_replay_leases(self):
        task = self.assign_lease()
        self.stop_server()
        with self.assertRaises(TransportError):
            self.lease_request(2)
        self.server = start_server(
            self.pins.nodes, server_context(
                self.server_cert, self.server_key, self.pki.ca_path), port=0)
        self.thread = threading.Thread(target=self.server.serve_forever, daemon=True)
        self.thread.start()
        result = self.lease_request(3)
        self.assertEqual(result["lease"]["lease_id"], task["lease_id"])
        events = TaskLeases(self.database).events(task["task_id"])
        self.assertEqual([e["kind"] for e in events], ["created", "leased"])


if __name__ == "__main__":
    unittest.main()
