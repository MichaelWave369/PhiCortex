"""Offline signed node enrollment and heartbeat registry, no task dispatch.

Node enrollment and revocation are trusted *local operator* operations. A
heartbeat proves possession of an enrolled private key, not trusted hardware,
sandbox containment, or permission to run code. No network server is exposed.
"""
from __future__ import annotations

import argparse
from contextlib import closing
import hashlib
import json
import os
from pathlib import Path
import re
import sqlite3
import time
from uuid import UUID

SCHEMA = "phicortex.mesh.heartbeat.v1"
MAX_AGE_SECONDS = 60
MAX_FUTURE_SECONDS = 10
ONLINE_TTL_SECONDS = 90
MAX_PACKET_BYTES = 4096
MODES = frozenset({"build-check", "test"})
LABEL = re.compile(r"^[A-Za-z0-9][A-Za-z0-9 ._-]{0,63}$")
HEARTBEAT_STATES = frozenset({"ready", "draining"})
MAX_SEQUENCE = 2**63 - 1


class MeshError(RuntimeError):
    pass


def canonical(value: object) -> bytes:
    return json.dumps(value, sort_keys=True, separators=(",", ":"),
                      ensure_ascii=False, allow_nan=False).encode("utf-8")


def _ed25519():
    try:
        from cryptography.exceptions import InvalidSignature
        from cryptography.hazmat.primitives.asymmetric.ed25519 import (
            Ed25519PrivateKey, Ed25519PublicKey)
    except ImportError as exc:
        raise MeshError("worker identity requires optional cryptography package") from exc
    return InvalidSignature, Ed25519PrivateKey, Ed25519PublicKey


def _id(value: str) -> str:
    try:
        if not isinstance(value, str) or str(UUID(value)) != value:
            raise ValueError("noncanonical ID")
    except (TypeError, ValueError, AttributeError) as exc:
        raise MeshError("node ID must be a canonical UUID") from exc
    return value


def _public_bytes(value: bytes) -> bytes:
    if not isinstance(value, bytes) or len(value) != 32:
        raise MeshError("node public key must be 32 raw bytes")
    return value


def sign_heartbeat(node_id: str, sequence: int, private_key: bytes, *,
                   state: str = "ready", now: int | None = None) -> dict:
    """Node-side packet generation. Caller owns monotonic sequence persistence."""
    _id(node_id)
    if type(sequence) is not int or not 1 <= sequence <= MAX_SEQUENCE:
        raise MeshError("sequence must be a positive 63-bit integer")
    if state not in HEARTBEAT_STATES:
        raise MeshError("invalid heartbeat state")
    if not isinstance(private_key, bytes) or len(private_key) != 32:
        raise MeshError("node signing key must contain 32 raw bytes")
    when = int(time.time()) if now is None else now
    if type(when) is not int:
        raise MeshError("heartbeat timestamp must be an integer")
    body = {"schema": SCHEMA, "node_id": node_id, "sequence": sequence,
            "issued_at": when, "state": state}
    _, Private, _ = _ed25519()
    return {"body": body,
            "signature": Private.from_private_bytes(private_key).sign(canonical(body)).hex()}


def _check_packet(packet: dict, *, now: int) -> tuple[dict, bytes]:
    if not isinstance(packet, dict) or set(packet) != {"body", "signature"}:
        raise MeshError("malformed signed heartbeat")
    try:
        size = len(canonical(packet))
    except (TypeError, ValueError) as exc:
        raise MeshError("heartbeat is not valid JSON data") from exc
    if size > MAX_PACKET_BYTES:
        raise MeshError("heartbeat exceeds maximum size")
    body, signature = packet["body"], packet["signature"]
    if not isinstance(body, dict) or set(body) != {
            "schema", "node_id", "sequence", "issued_at", "state"}:
        raise MeshError("heartbeat contains unexpected or missing fields")
    if body["schema"] != SCHEMA:
        raise MeshError("unsupported heartbeat schema")
    _id(body["node_id"])
    seq = body["sequence"]
    timestamp = body["issued_at"]
    if type(seq) is not int or not 1 <= seq <= MAX_SEQUENCE:
        raise MeshError("heartbeat has invalid sequence")
    if type(timestamp) is not int or not now - MAX_AGE_SECONDS <= timestamp <= now + MAX_FUTURE_SECONDS:
        raise MeshError("heartbeat is stale or clock is outside allowed window")
    if not isinstance(body["state"], str) or body["state"] not in HEARTBEAT_STATES:
        raise MeshError("unrecognized heartbeat state")
    if not isinstance(signature, str) or len(signature) != 128 or not re.fullmatch(r"[0-9a-f]{128}", signature):
        raise MeshError("malformed Ed25519 signature")
    return body, bytes.fromhex(signature)


class NodeRegistry:
    """SQLite registry opened per operation to avoid Windows file-handle leaks."""

    def __init__(self, database: Path):
        database = database.expanduser().absolute()
        if database.is_symlink():
            raise MeshError("symlinked registry database refused")
        database.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
        self.database = database
        with closing(self._connect()) as db:
            with db:
                db.execute("""CREATE TABLE IF NOT EXISTS nodes (
                    id TEXT PRIMARY KEY,
                    label TEXT NOT NULL,
                    pubkey BLOB NOT NULL UNIQUE,
                    pubkey_sha256 TEXT NOT NULL,
                    approved_modes_json TEXT NOT NULL,
                    enrolled_at INTEGER NOT NULL,
                    revoked INTEGER NOT NULL DEFAULT 0,
                    last_sequence INTEGER NOT NULL DEFAULT 0,
                    last_seen INTEGER,
                    last_state TEXT,
                    expires_at INTEGER
                )""")

    def _connect(self):
        # No key material is ever stored in the registry, only public keys.
        db = sqlite3.connect(self.database, timeout=5)
        db.row_factory = sqlite3.Row
        return db

    def enroll(self, node_id: str, label: str, public_key: bytes,
               approved_modes: list[str], *, now: int | None = None) -> dict:
        """Trusted local admin action only. No unauthenticated enrollment API."""
        _id(node_id)
        key = _public_bytes(public_key)
        if not isinstance(label, str) or not LABEL.fullmatch(label):
            raise MeshError("node label has invalid characters or length")
        if (not isinstance(approved_modes, list) or not approved_modes or
                not all(type(mode) is str and mode in MODES for mode in approved_modes) or
                len(set(approved_modes)) != len(approved_modes)):
            raise MeshError("approved modes must be a nonempty unique allowlist")
        stamp = int(time.time()) if now is None else now
        if type(stamp) is not int:
            raise MeshError("enrollment timestamp must be integer")
        fingerprint = hashlib.sha256(key).hexdigest()
        with closing(self._connect()) as db:
            try:
                with db:
                    db.execute("""INSERT INTO nodes
                        (id, label, pubkey, pubkey_sha256, approved_modes_json, enrolled_at)
                        VALUES (?, ?, ?, ?, ?, ?)""",
                        (node_id, label, key, fingerprint,
                         json.dumps(sorted(approved_modes)), stamp))
            except sqlite3.IntegrityError as exc:
                raise MeshError("node ID or public key already enrolled") from exc
        return {"node_id": node_id, "label": label, "public_key_sha256": fingerprint,
                "approved_modes": sorted(approved_modes), "status": "enrolled"}

    def accept(self, packet: dict, *, now: int | None = None,
               tls_peer_sha256: str | None = None) -> dict:
        """Verify enrolled key, timestamp and atomic monotonic sequence.

        When a TLS peer fingerprint is supplied, require its explicit
        operator-created binding to the same enrolled node, in this very
        transaction. Offline operator packet imports remain supported.
        """
        when = int(time.time()) if now is None else now
        if type(when) is not int:
            raise MeshError("server timestamp must be integer")
        body, signature = _check_packet(packet, now=when)
        node_id, sequence = body["node_id"], body["sequence"]
        Invalid, _, Public = _ed25519()
        with closing(self._connect()) as db:
            # BEGIN IMMEDIATE serializes checks across independent processes.
            db.execute("BEGIN IMMEDIATE")
            try:
                node = db.execute("SELECT pubkey, revoked, last_sequence FROM nodes WHERE id=?",
                                  (node_id,)).fetchone()
                if node is None or node["revoked"]:
                    raise MeshError("worker is not enrolled or has been revoked")
                if tls_peer_sha256 is not None:
                    if (not isinstance(tls_peer_sha256, str) or
                            not re.fullmatch(r"[0-9a-f]{64}", tls_peer_sha256)):
                        raise MeshError("invalid TLS certificate fingerprint")
                    pin = db.execute("""SELECT certificate_sha256 FROM node_tls_pins
                                        WHERE node_id=?""", (node_id,)).fetchone()
                    if pin is None or pin["certificate_sha256"] != tls_peer_sha256:
                        raise MeshError("TLS certificate is not bound to this enrolled worker")
                try:
                    Public.from_public_bytes(node["pubkey"]).verify(signature, canonical(body))
                except (Invalid, ValueError) as exc:
                    raise MeshError("heartbeat signature invalid") from exc
                if sequence <= node["last_sequence"]:
                    raise MeshError("replayed or out-of-order heartbeat sequence")
                expires_at = when + ONLINE_TTL_SECONDS
                db.execute("""UPDATE nodes SET last_sequence=?, last_seen=?,
                            last_state=?, expires_at=? WHERE id=?""",
                           (sequence, when, body["state"], expires_at, node_id))
                db.commit()
            except BaseException:
                db.rollback()
                raise
        return {"node_id": node_id, "status": "online" if body["state"] == "ready" else "draining",
                "last_seen": when, "expires_at": expires_at, "sequence": sequence,
                "execution_authorized": False}

    def revoke(self, node_id: str) -> None:
        """Trusted local operator action; never reactivates a revoked ID."""
        _id(node_id)
        with closing(self._connect()) as db:
            with db:
                updated = db.execute("UPDATE nodes SET revoked=1 WHERE id=? AND revoked=0",
                                     (node_id,)).rowcount
                if updated != 1:
                    raise MeshError("node not enrolled or already revoked")

    def list_nodes(self, *, now: int | None = None) -> list[dict]:
        when = int(time.time()) if now is None else now
        if type(when) is not int:
            raise MeshError("server timestamp must be integer")
        with closing(self._connect()) as db:
            rows = db.execute("""SELECT id, label, pubkey_sha256, approved_modes_json,
                revoked, last_sequence, last_seen, last_state, expires_at
                FROM nodes ORDER BY label, id""").fetchall()
        result = []
        for row in rows:
            if row["revoked"]:
                status = "revoked"
            elif row["last_seen"] is None:
                status = "enrolled"
            elif when >= row["expires_at"]:
                status = "offline"
            elif row["last_state"] == "draining":
                status = "draining"
            else:
                status = "online"
            result.append({"node_id": row["id"], "label": row["label"],
                           "public_key_sha256": row["pubkey_sha256"],
                           "approved_modes": json.loads(row["approved_modes_json"]),
                           "status": status, "last_sequence": row["last_sequence"],
                           "last_seen": row["last_seen"], "expires_at": row["expires_at"],
                           "execution_authorized": False,
                           "hardware_capabilities_verified": False})
        return result


def next_sequence(database: Path, node_id: str) -> int:
    """Node-local durable sequence counter; losing it requires re-enrollment.

    This is not proof against a malicious process with the same filesystem
    privileges. It avoids accidental reuse on normal process restarts.
    """
    _id(node_id)
    database = database.expanduser().absolute()
    if database.is_symlink():
        raise MeshError("symlinked node counter database refused")
    database.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
    with closing(sqlite3.connect(database, timeout=5)) as db:
        db.execute("BEGIN IMMEDIATE")
        try:
            db.execute("CREATE TABLE IF NOT EXISTS counter (node_id TEXT PRIMARY KEY, sequence INTEGER NOT NULL)")
            row = db.execute("SELECT sequence FROM counter WHERE node_id=?", (node_id,)).fetchone()
            sequence = 1 if row is None else row[0] + 1
            if sequence > MAX_SEQUENCE:
                raise MeshError("node sequence exhausted")
            db.execute("INSERT INTO counter (node_id,sequence) VALUES (?,?) "
                       "ON CONFLICT(node_id) DO UPDATE SET sequence=excluded.sequence",
                       (node_id, sequence))
            db.commit()
            return sequence
        except BaseException:
            db.rollback()
            raise


def _read_key(path: Path, *, private: bool = False) -> bytes:
    if path.is_symlink():
        raise MeshError("symlinked key refused")
    try:
        metadata = path.stat()
        if private and os.name == "posix" and (metadata.st_mode & 0o077):
            raise MeshError("private node key must not be group/world accessible")
        value = path.read_bytes()
    except OSError as exc:
        raise MeshError("key file unavailable") from exc
    if len(value) != 32:
        raise MeshError("key file must contain 32 raw bytes")
    return value


def _write_exclusive(path: Path, data: bytes) -> None:
    path = path.expanduser().absolute()
    path.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
    try:
        fd = os.open(path, os.O_CREAT | os.O_EXCL | os.O_WRONLY, 0o600)
    except FileExistsError as exc:
        raise MeshError("destination exists; refusing overwrite") from exc
    try:
        with os.fdopen(fd, "wb") as out:
            out.write(data)
    except BaseException:
        path.unlink(missing_ok=True)
        raise


def main(argv=None) -> int:
    cli = argparse.ArgumentParser(description="Offline, manually enrolled PhiCortex node identities")
    commands = cli.add_subparsers(dest="action", required=True)
    keys = commands.add_parser("new-keys")
    keys.add_argument("--private", type=Path, required=True)
    keys.add_argument("--public", type=Path, required=True)
    enrolled = commands.add_parser("enroll")
    enrolled.add_argument("--db", required=True, type=Path)
    enrolled.add_argument("--id", required=True)
    enrolled.add_argument("--label", required=True)
    enrolled.add_argument("--public", type=Path, required=True)
    enrolled.add_argument("--modes", nargs="+", choices=sorted(MODES), required=True)
    heartbeat = commands.add_parser("heartbeat")
    heartbeat.add_argument("--id", required=True)
    heartbeat.add_argument("--private", type=Path, required=True)
    seq = heartbeat.add_mutually_exclusive_group(required=True)
    seq.add_argument("--sequence", type=int, help="manual monotonic sequence for testing")
    seq.add_argument("--counter-db", type=Path, help="persistent node-side sequence ledger")
    heartbeat.add_argument("--state", choices=sorted(HEARTBEAT_STATES), default="ready")
    heartbeat.add_argument("--out", type=Path, required=True)
    ingest = commands.add_parser("accept")
    ingest.add_argument("--db", required=True, type=Path)
    ingest.add_argument("--packet", required=True, type=Path)
    revoke = commands.add_parser("revoke")
    revoke.add_argument("--db", required=True, type=Path)
    revoke.add_argument("--id", required=True)
    listing = commands.add_parser("list")
    listing.add_argument("--db", required=True, type=Path)
    args = cli.parse_args(argv)
    try:
        if args.action == "new-keys":
            from .approval_v1 import create_keypair, ApprovalError
            try:
                create_keypair(args.private, args.public)
            except ApprovalError as exc:
                raise MeshError(str(exc)) from exc
            print("Created worker signing key and enrollment public key; protect the private key")
        elif args.action == "heartbeat":
            sequence = (next_sequence(args.counter_db, args.id)
                        if args.counter_db is not None else args.sequence)
            packet = sign_heartbeat(args.id, sequence, _read_key(args.private, private=True), state=args.state)
            _write_exclusive(args.out, canonical(packet) + b"\n")
            print(f"Signed offline heartbeat: {args.out}")
        else:
            registry = NodeRegistry(args.db)
            if args.action == "enroll":
                result = registry.enroll(args.id, args.label, _read_key(args.public), args.modes)
            elif args.action == "accept":
                path = args.packet
                if path.stat().st_size > MAX_PACKET_BYTES:
                    raise MeshError("heartbeat file exceeds size limit")
                result = registry.accept(json.loads(path.read_text(encoding="utf-8")))
            elif args.action == "revoke":
                registry.revoke(args.id)
                result = {"node_id": args.id, "status": "revoked"}
            else:
                result = registry.list_nodes()
            print(json.dumps(result, indent=2, sort_keys=True))
        return 0
    except (MeshError, OSError, ValueError) as exc:
        cli.exit(2, f"refused: {exc}\n")


if __name__ == "__main__":
    raise SystemExit(main())
