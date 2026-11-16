"""Operator-signed, offline task-envelope *validation* for one leased worker.

This is an authorization cross-reference, NOT authorization to execute.
No network endpoint, worker dispatch, Governor nonce consumption, or
source/artifact transfer is implemented here.

Security limitations: the snapshot is a mutable host-side copy; checking
its digest does not eliminate TOCTOU risk. The SQLite registry and operator
account remain trusted. Real gVisor/physical node attestation is pending.
"""
from __future__ import annotations

import argparse
from contextlib import closing
import hashlib
import hmac
import json
from pathlib import Path
import re
import sqlite3
import time
from uuid import UUID, uuid4

from .approval_v1 import _crypto, _load, _write_new, SCHEMA as PERMIT_SCHEMA
from .governor import canonical, task_fields, MAX_TTL
from .leases import TaskLeases, _clock
from .mesh import _id, MODES
from .snapshot import verify_snapshot
from .worker import plan

SCHEMA = "phicortex.mesh.signed_envelope.v1"
REFERENCE_SCHEMA = "phicortex.mesh.approved_task_ref.v1"
MAX_ENVELOPE_BYTES = 4096
MAX_PERMIT_BYTES = 16384
MAX_ENVELOPE_TTL = 120
HEX64 = re.compile(r"[0-9a-f]{64}\Z")
HEX128 = re.compile(r"[0-9a-f]{128}\Z")
PERMIT_KEYS = frozenset({
    "schema", "issued_at", "expires_at", "nonce", "job",
    "snapshot_manifest", "workspace_sha256", "manifest_sha256", "signature"
})
ENVELOPE_KEYS = frozenset({
    "schema", "issued_at", "expires_at", "nonce", "task_id", "lease_id",
    "node_id", "mode", "task_sha256", "permit_sha256", "workspace_sha256",
    "manifest_sha256", "node_key_sha256", "tls_cert_sha256",
    "operator_key_sha256", "signature"
})


class EnvelopeError(RuntimeError):
    pass


def _uuid(value: str) -> str:
    try:
        if not isinstance(value, str) or str(UUID(value)) != value:
            raise ValueError("noncanonical UUID")
    except (ValueError, TypeError, AttributeError) as exc:
        raise EnvelopeError("invalid UUID in task contract") from exc
    return value


def _hex(value: str, pattern=HEX64) -> str:
    if not isinstance(value, str) or not pattern.fullmatch(value):
        raise EnvelopeError("invalid SHA-256 or signature encoding")
    return value


def _size(value: object, maximum: int) -> bytes:
    try:
        data = canonical(value)
    except (TypeError, ValueError) as exc:
        raise EnvelopeError("invalid signed JSON structure") from exc
    if len(data) > maximum:
        raise EnvelopeError("signed payload exceeds limit")
    return data


def _now(now: int | None) -> int:
    try:
        return _clock(now)
    except Exception as exc:
        raise EnvelopeError("invalid current time") from exc


def inspect_permit(permit: dict, operator_public: bytes, *,
                   now: int | None = None) -> dict:
    """Verify operator signature, exact job scope and current snapshot, no consumption.

    Existing Governor execution still requires its own independent
    verify_and_consume and gVisor checks. This cannot replace those.
    """
    current = _now(now)
    if not isinstance(permit, dict) or set(permit) != PERMIT_KEYS:
        raise EnvelopeError("invalid Governor permit schema")
    _size(permit, MAX_PERMIT_BYTES)
    if not isinstance(operator_public, bytes) or len(operator_public) != 32:
        raise EnvelopeError("invalid operator public key")
    if permit["schema"] != PERMIT_SCHEMA:
        raise EnvelopeError("only Ed25519 Governor permits are accepted")
    signed = _hex(permit["signature"], HEX128)
    Invalid, _, Public = _crypto()
    try:
        Public.from_public_bytes(operator_public).verify(
            bytes.fromhex(signed),
            canonical({k: v for k, v in permit.items() if k != "signature"}))
    except (Invalid, ValueError, TypeError) as exc:
        raise EnvelopeError("Governor permit signature invalid") from exc
    issued, expires = permit["issued_at"], permit["expires_at"]
    if (type(issued) is not int or type(expires) is not int or
            not 1 <= expires - issued <= MAX_TTL or
            issued > current + 5 or current >= expires):
        raise EnvelopeError("Governor permit expired or outside validity window")
    _uuid(permit["nonce"])
    job = permit["job"]
    if not isinstance(job, dict) or set(job) != {
            "mode", "authorized_root", "workspace", "image", "timeout_seconds"}:
        raise EnvelopeError("Governor task fields are missing or unexpected")
    if not isinstance(job["mode"], str) or job["mode"] not in MODES:
        raise EnvelopeError("unapproved worker mode")
    for key in ("authorized_root", "workspace", "image"):
        if not isinstance(job[key], str):
            raise EnvelopeError("invalid Governor job field type")
    if type(job["timeout_seconds"]) is not int:
        raise EnvelopeError("invalid Governor timeout")
    try:
        # Validates fixed allowlist, image SHA pin, root and source safety.
        canonical_job = plan(job["mode"], Path(job["authorized_root"]),
                             Path(job["workspace"]), job["image"],
                             job["timeout_seconds"], platform_name="Linux")
        if job != task_fields(canonical_job):
            raise EnvelopeError("Governor job contract does not match validated plan")
        manifest = Path(permit["snapshot_manifest"])
        if not manifest.is_absolute() or manifest.is_symlink():
            raise EnvelopeError("invalid snapshot manifest location")
        meta = verify_snapshot(manifest, expected_workspace=job["workspace"])
        manifest_data = manifest.read_bytes()
        if not hmac.compare_digest(
                hashlib.sha256(manifest_data).hexdigest(), _hex(permit["manifest_sha256"])):
            raise EnvelopeError("Governor snapshot manifest changed")
        if not hmac.compare_digest(meta["workspace_sha256"], _hex(permit["workspace_sha256"])):
            raise EnvelopeError("Governor-approved workspace changed")
    except (OSError, ValueError, TypeError, KeyError) as exc:
        raise EnvelopeError("Governor snapshot or job is unavailable") from exc
    except EnvelopeError:
        raise
    except Exception as exc:
        # SnapshotError and WorkerError are not authorization success.
        raise EnvelopeError("Governor snapshot or job failed verification") from exc
    return {"job": job, "workspace_sha256": permit["workspace_sha256"],
            "manifest_sha256": permit["manifest_sha256"],
            "permit_sha256": hashlib.sha256(canonical(permit)).hexdigest(),
            "permit_expires_at": expires}


def approved_task_digest(permit: dict, operator_public: bytes,
                         *, now: int | None = None) -> str:
    """Deterministic task hash used when *manually* creating the lease."""
    verified = inspect_permit(permit, operator_public, now=now)
    reference = {"schema": REFERENCE_SCHEMA, "job": verified["job"],
                 "workspace_sha256": verified["workspace_sha256"],
                 "manifest_sha256": verified["manifest_sha256"]}
    return hashlib.sha256(canonical(reference)).hexdigest()


def _bound_lease(dbpath: Path, task_id: str, current: int,
                 expected_task_hash: str, mode: str) -> dict:
    """Read the complete manual acknowledgment and enrollment binding.

    A lease must already exist, be assigned locally, and have a signed
    metadata acknowledgment from the enrolled worker. No state mutations.
    """
    _uuid(task_id)
    ledger = TaskLeases(dbpath)
    try:
        with closing(ledger._connect()) as db:
            db.execute("BEGIN IMMEDIATE")
            try:
                lease = db.execute(
                    """SELECT * FROM task_leases WHERE task_id=?""",
                    (task_id,)).fetchone()
                if lease is None or lease["status"] != "leased":
                    raise EnvelopeError("no active manually assigned lease")
                if (lease["task_sha256"] != expected_task_hash or
                        lease["mode"] != mode):
                    raise EnvelopeError("lease task digest or mode differs from permit")
                if lease["deadline"] is None or current >= lease["deadline"]:
                    raise EnvelopeError("lease deadline passed; manual review required")
                node_id = _uuid(lease["node_id"])
                lease_id = _uuid(lease["lease_id"])
                node = db.execute(
                    """SELECT revoked, last_seen, last_state, expires_at,
                       pubkey_sha256, approved_modes_json FROM nodes WHERE id=?""",
                    (node_id,)).fetchone()
                if (node is None or node["revoked"] or node["last_seen"] is None
                        or current < node["last_seen"] or
                        node["expires_at"] is None or current >= node["expires_at"]
                        or node["last_state"] != "ready"):
                    raise EnvelopeError("enrolled worker is not live and ready")
                real_pub = db.execute("SELECT pubkey FROM nodes WHERE id=?", (node_id,)).fetchone()
                if real_pub is None or hashlib.sha256(real_pub["pubkey"]).hexdigest() != node["pubkey_sha256"]:
                    raise EnvelopeError("node public-key fingerprint is inconsistent")
                if mode not in json.loads(node["approved_modes_json"]):
                    raise EnvelopeError("node is not approved for this worker mode")
                pinned = db.execute(
                    """SELECT certificate_sha256 FROM node_tls_pins WHERE node_id=?""",
                    (node_id,)).fetchone()
                if pinned is None:
                    raise EnvelopeError("worker TLS identity has no operator pin")
                receipt = db.execute(
                    """SELECT task_id,node_id FROM lease_receipts WHERE lease_id=?""",
                    (lease_id,)).fetchone()
                if (receipt is None or receipt["task_id"] != task_id
                        or receipt["node_id"] != node_id):
                    raise EnvelopeError("worker has not acknowledged this lease")
                binding = {
                    "task_id": task_id, "lease_id": lease_id,
                    "node_id": node_id, "mode": mode,
                    "task_sha256": expected_task_hash,
                    "node_key_sha256": _hex(node["pubkey_sha256"]),
                    "tls_cert_sha256": _hex(pinned["certificate_sha256"]),
                    "lease_deadline": lease["deadline"],
                    "heartbeat_expires_at": node["expires_at"]
                }
                db.commit()
                return binding
            except BaseException:
                db.rollback()
                raise
    except sqlite3.Error as exc:
        raise EnvelopeError("enrollment, receipt, or lease ledger unavailable") from exc


def sign_envelope(database: Path, task_id: str, permit: dict,
                  operator_private: bytes, operator_public: bytes,
                  *, ttl: int = 60, now: int | None = None) -> dict:
    """Operator-only. Return a signed proof of a *currently* valid binding."""
    current = _now(now)
    if type(ttl) is not int or not 1 <= ttl <= MAX_ENVELOPE_TTL:
        raise EnvelopeError("envelope TTL must be between 1 and 120 seconds")
    if not isinstance(operator_private, bytes) or len(operator_private) != 32:
        raise EnvelopeError("private signing key must contain 32 raw bytes")
    if not isinstance(operator_public, bytes) or len(operator_public) != 32:
        raise EnvelopeError("invalid operator verifier key")
    _, Private, _ = _crypto()
    key = Private.from_private_bytes(operator_private)
    if not hmac.compare_digest(key.public_key().public_bytes_raw(), operator_public):
        raise EnvelopeError("private signing key does not match configured Governor public key")
    permit_ok = inspect_permit(permit, operator_public, now=current)
    task_hash = approved_task_digest(permit, operator_public, now=current)
    bound = _bound_lease(database, task_id, current, task_hash, permit_ok["job"]["mode"])
    expiry = min(current + ttl, permit_ok["permit_expires_at"],
                 bound["lease_deadline"], bound["heartbeat_expires_at"])
    if expiry <= current:
        raise EnvelopeError("insufficient remaining permit, lease or heartbeat validity")
    body = {"schema": SCHEMA, "issued_at": current, "expires_at": expiry,
            "nonce": str(uuid4()),
            "task_id": bound["task_id"], "lease_id": bound["lease_id"],
            "node_id": bound["node_id"], "mode": bound["mode"],
            "task_sha256": task_hash, "permit_sha256": permit_ok["permit_sha256"],
            "workspace_sha256": permit_ok["workspace_sha256"],
            "manifest_sha256": permit_ok["manifest_sha256"],
            "node_key_sha256": bound["node_key_sha256"],
            "tls_cert_sha256": bound["tls_cert_sha256"],
            "operator_key_sha256": hashlib.sha256(operator_public).hexdigest()}
    body["signature"] = key.sign(canonical(body)).hex()
    _size(body, MAX_ENVELOPE_BYTES)
    return body


def verify_envelope(envelope: dict, database: Path, permit: dict,
                    operator_public: bytes, *, now: int | None = None) -> dict:
    """Read-only, fail-closed inspection. Does not consume Governor permits."""
    current = _now(now)
    if not isinstance(envelope, dict) or set(envelope) != ENVELOPE_KEYS:
        raise EnvelopeError("invalid signed envelope schema")
    _size(envelope, MAX_ENVELOPE_BYTES)
    if envelope["schema"] != SCHEMA:
        raise EnvelopeError("unsupported envelope version")
    if not isinstance(operator_public, bytes) or len(operator_public) != 32:
        raise EnvelopeError("invalid operator public verifier")
    signed = _hex(envelope["signature"], HEX128)
    Invalid, _, Public = _crypto()
    try:
        Public.from_public_bytes(operator_public).verify(
            bytes.fromhex(signed),
            canonical({k: v for k, v in envelope.items() if k != "signature"}))
    except (Invalid, ValueError, TypeError) as exc:
        raise EnvelopeError("operator envelope signature invalid") from exc
    issued, expires = envelope["issued_at"], envelope["expires_at"]
    if (type(issued) is not int or type(expires) is not int or
            not 1 <= expires - issued <= MAX_ENVELOPE_TTL or
            issued > current + 5 or current >= expires):
        raise EnvelopeError("task envelope expired or outside validity window")
    _uuid(envelope["nonce"])
    _uuid(envelope["task_id"])
    permit_ok = inspect_permit(permit, operator_public, now=current)
    task_hash = approved_task_digest(permit, operator_public, now=current)
    bound = _bound_lease(database, envelope["task_id"], current, task_hash,
                         permit_ok["job"]["mode"])
    expected = {
        "task_id": bound["task_id"], "lease_id": bound["lease_id"],
        "node_id": bound["node_id"], "mode": bound["mode"],
        "task_sha256": task_hash, "permit_sha256": permit_ok["permit_sha256"],
        "workspace_sha256": permit_ok["workspace_sha256"],
        "manifest_sha256": permit_ok["manifest_sha256"],
        "node_key_sha256": bound["node_key_sha256"],
        "tls_cert_sha256": bound["tls_cert_sha256"],
        "operator_key_sha256": hashlib.sha256(operator_public).hexdigest()
    }
    for key, value in expected.items():
        if envelope[key] != value:
            raise EnvelopeError("signed envelope no longer matches current node or task binding")
    if expires > min(permit_ok["permit_expires_at"], bound["lease_deadline"],
                     bound["heartbeat_expires_at"]):
        raise EnvelopeError("envelope expires after a required safety deadline")
    return {"schema": SCHEMA, "status": "validated_metadata_only",
            "task_id": bound["task_id"], "lease_id": bound["lease_id"],
            "node_id": bound["node_id"], "mode": bound["mode"],
            "task_sha256": task_hash, "expires_at": expires,
            "execution_authorized": False, "task_dispatched": False,
            "permit_consumed": False, "worker_isolation_attested": False}


def main(argv=None) -> int:
    parser = argparse.ArgumentParser(
        description="Operator-only signed envelope inspection; never executes or sends tasks")
    subs = parser.add_subparsers(dest="action", required=True)
    for cmd in ("task-digest", "sign", "verify"):
        action = subs.add_parser(cmd)
        action.add_argument("--permit", required=True, type=Path)
        action.add_argument("--public", required=True, type=Path)
        if cmd != "task-digest":
            action.add_argument("--db", required=True, type=Path)
        if cmd == "sign":
            action.add_argument("--private", required=True, type=Path)
            action.add_argument("--task-id", required=True)
            action.add_argument("--ttl", type=int, default=60)
            action.add_argument("--out", required=True, type=Path)
        elif cmd == "verify":
            action.add_argument("--envelope", required=True, type=Path)
    args = parser.parse_args(argv)
    try:
        if args.permit.stat().st_size > MAX_PERMIT_BYTES:
            raise EnvelopeError("Governor permit file exceeds limit")
        permit = json.loads(args.permit.read_text(encoding="utf-8"))
        public = _load(args.public, private=False)
        if args.action == "task-digest":
            result = {"task_sha256": approved_task_digest(permit, public)}
        elif args.action == "sign":
            private_path = args.private.expanduser().resolve(strict=True)
            output = args.out.expanduser().absolute()
            workspace = Path(permit["job"]["workspace"]).resolve(strict=True)
            if any(p == workspace or workspace in p.parents
                   for p in (private_path, output)):
                raise EnvelopeError("private key and envelope must stay outside workspace")
            envelope = sign_envelope(args.db, args.task_id, permit,
                                     _load(args.private, private=True), public,
                                     ttl=args.ttl)
            _write_new(args.out, canonical(envelope) + b"\n", 0o600)
            result = {"signed_envelope_written": str(args.out),
                      "execution_authorized": False}
        else:
            if args.envelope.stat().st_size > MAX_ENVELOPE_BYTES:
                raise EnvelopeError("envelope file exceeds limit")
            envelope = json.loads(args.envelope.read_text(encoding="utf-8"))
            result = verify_envelope(envelope, args.db, permit, public)
        print(json.dumps(result, sort_keys=True, indent=2))
        return 0
    except (EnvelopeError, OSError, ValueError, TypeError, KeyError) as exc:
        parser.exit(2, f"refused: {exc}\n")


if __name__ == "__main__":
    raise SystemExit(main())
