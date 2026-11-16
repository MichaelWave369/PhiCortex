"""Operator-driven mesh preflight and real mTLS heartbeat/lease diagnostics.

No remote execution, task assignment, code delivery, key upload or auto-retry.
The probe uses the worker's persistent Ed25519 sequence ledger. Failure
classification is observational, never proof of a particular physical cause.
"""
from __future__ import annotations

import argparse
from dataclasses import dataclass
from datetime import datetime, timezone
import hashlib
import json
import os
from pathlib import Path
import re
import sqlite3
import stat
import time
from uuid import uuid4

from .mesh import (MeshError, _id, _write_exclusive, next_sequence,
                   sign_heartbeat, canonical)
from .lease_exchange import SCHEMA as EXCHANGE_SCHEMA, sign_exchange
from .mesh_transport import (TransportError, send_heartbeat,
                             send_lease_request, validate_endpoint)

SCHEMA = "phicortex.mesh.diagnostic.v1"
HEX = re.compile(r"[0-9a-f]{64}\Z")
WARNING_DAYS = 14
HEARTBEAT_KEYS = frozenset({
    "node_id", "sequence", "status", "expires_at",
    "execution_authorized", "task_dispatched"
})
PREVIEW_KEYS = frozenset({
    "schema", "action", "node_id", "sequence", "lease",
    "execution_authorized", "task_dispatched",
    "governor_permit_included", "task_payload_included"
})
LEASE_KEYS = frozenset({
    "task_id", "lease_id", "mode", "task_sha256", "deadline", "acknowledged"
})


class DoctorError(RuntimeError):
    pass


@dataclass(frozen=True)
class DoctorConfig:
    host: str
    port: int
    allow_lan: bool
    server_ca: Path
    client_cert: Path
    client_key: Path
    node_id: str
    node_signing_key: Path
    counter_db: Path
    expected_node_sha256: str
    expected_cert_sha256: str


def _crypto():
    try:
        from cryptography import x509
        from cryptography.hazmat.primitives import serialization
        from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
        from cryptography.x509.oid import ExtendedKeyUsageOID
    except ImportError as exc:
        raise DoctorError("install optional requirements-worker.txt") from exc
    return x509, serialization, Ed25519PrivateKey, ExtendedKeyUsageOID


def _regular(path: Path, *, secret: bool, limit: int = 64 * 1024) -> bytes:
    if path.is_symlink():
        raise DoctorError("symlinked certificate or key file refused")
    try:
        metadata = path.stat()
        if not stat.S_ISREG(metadata.st_mode) or metadata.st_size > limit:
            raise DoctorError("invalid or oversized certificate or key file")
        if secret and os.name == "posix" and (metadata.st_mode & 0o077):
            raise DoctorError("private key has unsafe Unix file permissions")
        return path.read_bytes()
    except OSError as exc:
        raise DoctorError("required credential file unavailable") from exc


def _certificate(data: bytes, x509):
    try:
        if data.startswith(b"-----BEGIN CERTIFICATE-----"):
            return x509.load_pem_x509_certificate(data)
        return x509.load_der_x509_certificate(data)
    except (ValueError, TypeError) as exc:
        raise DoctorError("invalid X.509 certificate") from exc


def _expiration(cert, now: datetime, label: str, warnings: list[str]) -> None:
    if not cert.not_valid_before_utc <= now < cert.not_valid_after_utc:
        raise DoctorError(f"{label} certificate outside its validity period")
    remaining = (cert.not_valid_after_utc - now).total_seconds()
    if remaining <= WARNING_DAYS * 86400:
        warnings.append(f"{label} certificate expires within {WARNING_DAYS} days")


def preflight(config: DoctorConfig, *, now: datetime | None = None) -> dict:
    """Only local file reads. Does not touch the network or sequence DB."""
    x509, serialization, Ed25519PrivateKey, EKU = _crypto()
    host = validate_endpoint(config.host, config.port, allow_lan=config.allow_lan)
    try:
        node_id = _id(config.node_id)
    except Exception as exc:
        raise DoctorError("invalid enrolled node UUID") from exc
    for digest in (config.expected_node_sha256, config.expected_cert_sha256):
        if not isinstance(digest, str) or not HEX.fullmatch(digest):
            raise DoctorError("expected fingerprints must be lowercase SHA-256")
    current = now or datetime.now(timezone.utc)
    if current.tzinfo is None:
        raise DoctorError("certificate validation time must include timezone")
    warnings = []
    ca = _certificate(_regular(config.server_ca, secret=False), x509)
    cert = _certificate(_regular(config.client_cert, secret=False), x509)
    _expiration(ca, current, "server CA", warnings)
    _expiration(cert, current, "client TLS", warnings)
    try:
        constraints = ca.extensions.get_extension_for_class(x509.BasicConstraints).value
    except x509.ExtensionNotFound as exc:
        raise DoctorError("server CA lacks CA basic constraints") from exc
    if not constraints.ca:
        raise DoctorError("supplied server CA is not a certificate authority")
    # This is an early consistency check, not full chain validation.
    # The real TLS handshake validates the server chain and exact IP SAN.
    if cert.issuer != ca.subject:
        warnings.append("client certificate issuer differs from server CA; TLS must validate trust")
    try:
        usage = cert.extensions.get_extension_for_class(x509.ExtendedKeyUsage).value
    except x509.ExtensionNotFound as exc:
        raise DoctorError("client certificate lacks ExtendedKeyUsage") from exc
    if EKU.CLIENT_AUTH not in usage:
        raise DoctorError("TLS client certificate is not marked for clientAuth")
    raw_cert = cert.public_bytes(serialization.Encoding.DER)
    cert_fp = hashlib.sha256(raw_cert).hexdigest()
    if cert_fp != config.expected_cert_sha256:
        raise DoctorError("client TLS certificate does not match operator enrollment pin")
    tls_key_bytes = _regular(config.client_key, secret=True, limit=128 * 1024)
    try:
        tls_key = serialization.load_pem_private_key(tls_key_bytes, password=None)
        key_spki = tls_key.public_key().public_bytes(
            serialization.Encoding.DER,
            serialization.PublicFormat.SubjectPublicKeyInfo)
        cert_spki = cert.public_key().public_bytes(
            serialization.Encoding.DER,
            serialization.PublicFormat.SubjectPublicKeyInfo)
    except (ValueError, TypeError, AttributeError) as exc:
        raise DoctorError("invalid, encrypted or unsupported TLS private key") from exc
    if key_spki != cert_spki:
        raise DoctorError("TLS client certificate and private key do not match")
    node_key_bytes = _regular(config.node_signing_key, secret=True, limit=32)
    if len(node_key_bytes) != 32:
        raise DoctorError("node Ed25519 private key must be 32 raw bytes")
    node_public = Ed25519PrivateKey.from_private_bytes(node_key_bytes).public_key().public_bytes_raw()
    node_fp = hashlib.sha256(node_public).hexdigest()
    if node_fp != config.expected_node_sha256:
        raise DoctorError("node signing key differs from operator-enrolled public key")
    if config.counter_db.is_symlink():
        raise DoctorError("symlinked sequence ledger refused")
    if any(config.counter_db.expanduser().absolute() == p.expanduser().absolute()
           for p in (config.client_key, config.node_signing_key,
                     config.client_cert, config.server_ca)):
        raise DoctorError("sequence ledger must be distinct from credential files")
    return {
        "schema": SCHEMA, "status": "warning" if warnings else "ready",
        "node_id": node_id,
        "server": {"host": host, "port": config.port,
                   "lan_opt_in": config.allow_lan},
        "identity": {"node_key_sha256": node_fp, "client_cert_sha256": cert_fp},
        "checks": ["endpoint_scope", "credential_file_safety", "certificate_validity",
                   "client_auth_usage", "operator_fingerprint_pins",
                   "tls_private_key_match", "node_signing_key_match"],
        "warnings": warnings, "network_checked": False,
        "hardware_isolation_attested": False,
        "execution_authorized": False
    }


def _validate_heartbeat(response: dict, node_id: str, seq: int) -> None:
    if (not isinstance(response, dict) or set(response) != HEARTBEAT_KEYS
            or response["node_id"] != node_id or response["sequence"] != seq
            or response["execution_authorized"] is not False
            or response["task_dispatched"] is not False
            or response["status"] != "online"):
        raise DoctorError("heartbeat response violated no-execution identity contract")


def _validate_exchange(response: dict, node_id: str, action: str, seq: int) -> None:
    if (not isinstance(response, dict) or set(response) != PREVIEW_KEYS
            or response["schema"] != EXCHANGE_SCHEMA
            or response["node_id"] != node_id
            or response["action"] != action
            or response["sequence"] != seq
            or any(response[k] is not False for k in (
                "execution_authorized", "task_dispatched",
                "governor_permit_included", "task_payload_included"))):
        raise DoctorError("lease exchange violated no-execution protocol")
    lease = response["lease"]
    if lease is not None and (not isinstance(lease, dict)
                              or set(lease) != LEASE_KEYS):
        raise DoctorError("unexpected executable or unrecognized lease fields")


def _failure_kind(exc: Exception) -> str:
    detail = str(exc)
    if "HTTP 403" in detail:
        return "authorization_refused"
    if detail.startswith("secure heartbeat exchange failed") or detail.startswith(
            "secure lease exchange failed"):
        return "connectivity_or_tls_failed"
    return "transport_or_protocol_failure"


def probe(config: DoctorConfig, *, acknowledge: bool = False,
          expect_denied: bool = False) -> dict:
    """One operator-triggered probe. No periodic background activity."""
    if acknowledge and expect_denied:
        raise DoctorError("cannot acknowledge a lease during a denial test")
    check = preflight(config)
    report = {
        "schema": SCHEMA, "run_id": str(uuid4()),
        "node_id": check["node_id"],
        "preflight_status": check["status"],
        "warnings": check["warnings"],
        "server": check["server"],
        "steps": [],
        "outcome": "not_started",
        "network_checked": True,
        "physical_pc_verified": False,
        "hardware_isolation_attested": False,
        "execution_authorized": False,
        "task_dispatched": False
    }
    raw_key = _regular(config.node_signing_key, secret=True, limit=32)
    def next_packet(kind: str, lease_id: str | None = None) -> tuple[int, dict]:
        seq = next_sequence(config.counter_db, config.node_id)
        if kind == "heartbeat":
            return seq, sign_heartbeat(config.node_id, seq, raw_key)
        return seq, sign_exchange(config.node_id, seq, raw_key, kind, lease_id=lease_id)
    try:
        seq, heartbeat = next_packet("heartbeat")
        started = time.monotonic()
        reply = send_heartbeat(config.host, config.port, heartbeat,
                               config.server_ca, config.client_cert, config.client_key,
                               allow_lan=config.allow_lan)
        _validate_heartbeat(reply, config.node_id, seq)
        report["steps"].append({"step": "heartbeat", "outcome": "accepted",
                                "sequence": seq,
                                "latency_ms": round((time.monotonic() - started) * 1000, 2)})
        if expect_denied:
            raise DoctorError("expected explicit HTTP 403, heartbeat was accepted")
        seq, packet = next_packet("preview")
        started = time.monotonic()
        reply = send_lease_request(
            config.host, config.port, packet, "preview", config.server_ca,
            config.client_cert, config.client_key, allow_lan=config.allow_lan)
        _validate_exchange(reply, config.node_id, "preview", seq)
        lease = reply["lease"]
        report["steps"].append({
            "step": "lease_preview", "outcome": "accepted",
            "sequence": seq,
            "latency_ms": round((time.monotonic() - started) * 1000, 2),
            "active_lease": lease is not None,
            "acknowledged": lease["acknowledged"] if lease else None
        })
        if acknowledge:
            if lease is None:
                raise DoctorError("cannot acknowledge: no active lease")
            seq, packet = next_packet("ack", lease["lease_id"])
            started = time.monotonic()
            reply = send_lease_request(
                config.host, config.port, packet, "ack", config.server_ca,
                config.client_cert, config.client_key, allow_lan=config.allow_lan)
            _validate_exchange(reply, config.node_id, "ack", seq)
            if reply["lease"] is None or not reply["lease"]["acknowledged"] or (
                    reply["lease"]["lease_id"] != lease["lease_id"]):
                raise DoctorError("coordinator did not confirm the selected lease receipt")
            report["steps"].append({"step": "lease_ack", "outcome": "accepted",
                                    "sequence": seq,
                                    "latency_ms": round((time.monotonic() - started) * 1000, 2)})
        report["outcome"] = "protocol_passed"
    except TransportError as exc:
        kind = _failure_kind(exc)
        report["steps"].append({"step": "transport", "outcome": kind,
                                "sequence": seq})
        if expect_denied and kind == "authorization_refused":
            report["outcome"] = "explicit_403_observed"
            report["denial_reason_attested"] = False
        else:
            report["outcome"] = kind
    except DoctorError as exc:
        report["steps"].append({"step": "protocol", "outcome": "refused",
                                "category": str(exc)})
        report["outcome"] = "protocol_refused"
    except (MeshError, sqlite3.Error, OSError) as exc:
        # No exception paths, credentials or raw OS errors in exported reports.
        report["steps"].append({"step": "local_state", "outcome": "refused",
                                "category": type(exc).__name__})
        report["outcome"] = "local_state_refused"
    return report


def main(argv=None) -> int:
    parser = argparse.ArgumentParser(
        description="Human-invoked two-PC mesh preflight and signed mTLS diagnostic; no code execution")
    parser.add_argument("--host", required=True)
    parser.add_argument("--port", type=int, default=8766)
    parser.add_argument("--allow-lan", action="store_true")
    parser.add_argument("--server-ca", type=Path, required=True)
    parser.add_argument("--client-cert", type=Path, required=True)
    parser.add_argument("--client-key", type=Path, required=True)
    parser.add_argument("--node-id", required=True)
    parser.add_argument("--node-signing-key", type=Path, required=True)
    parser.add_argument("--counter-db", type=Path, required=True)
    parser.add_argument("--expected-node-sha256", required=True)
    parser.add_argument("--expected-cert-sha256", required=True)
    parser.add_argument("--preflight-only", action="store_true")
    choice = parser.add_mutually_exclusive_group()
    choice.add_argument("--acknowledge", action="store_true",
                        help="explicitly record a receipt for the active lease's metadata")
    choice.add_argument("--expect-denied", action="store_true",
                        help="negative auth test: only explicit HTTP 403 counts")
    parser.add_argument("--out", type=Path, help="write exclusive private report JSON")
    args = parser.parse_args(argv)
    config = DoctorConfig(
        host=args.host, port=args.port, allow_lan=args.allow_lan,
        server_ca=args.server_ca, client_cert=args.client_cert,
        client_key=args.client_key, node_id=args.node_id,
        node_signing_key=args.node_signing_key, counter_db=args.counter_db,
        expected_node_sha256=args.expected_node_sha256,
        expected_cert_sha256=args.expected_cert_sha256)
    try:
        if args.preflight_only and (args.acknowledge or args.expect_denied):
            raise DoctorError("preflight-only cannot acknowledge or test denial")
        report = (preflight(config) if args.preflight_only
                  else probe(config, acknowledge=args.acknowledge,
                             expect_denied=args.expect_denied))
        data = canonical(report) + b"\n"
        if args.out:
            target = args.out.expanduser().absolute()
            if any(target == secret.expanduser().absolute()
                   for secret in (config.client_key, config.node_signing_key,
                                  config.counter_db, config.server_ca, config.client_cert)):
                raise DoctorError("report cannot replace credentials or sequence ledger")
            _write_exclusive(target, data)
        print(json.dumps(report, indent=2, sort_keys=True))
        allowed = ({"ready", "warning"} if args.preflight_only
                   else {"protocol_passed", "explicit_403_observed"})
        return 0 if report["status" if args.preflight_only else "outcome"] in allowed else 1
    except (DoctorError, OSError, ValueError, TransportError) as exc:
        parser.exit(2, f"refused: {exc}\n")


if __name__ == "__main__":
    raise SystemExit(main())
