"""Offline durable task lease ledger for PhiCortex's manually enrolled nodes.

This module does NOT send tasks, execute commands, grant Governor permits, or
implement an authenticated network transport. A lease means coordination
metadata only; permission to execute always comes from a separate Governor.
"""
from __future__ import annotations

import argparse
from contextlib import closing
import hashlib
import json
from pathlib import Path
import re
import sqlite3
import time
from uuid import uuid4

from .mesh import NodeRegistry, _ed25519, _id, _read_key, canonical, MODES
from .vault import Vault, VaultError

SCHEMA = "phicortex.mesh.lease.v1"
RESULT_SCHEMA = "phicortex.mesh.result.v1"
MAX_LEASE_SECONDS = 120
RESULT_FRESH_SECONDS = 60
FUTURE_SKEW_SECONDS = 10
MAX_RESULT_PACKET = 4096
DIGEST = re.compile(r"^[0-9a-f]{64}$")
RESULTS = frozenset({"passed", "failed", "inconclusive"})
STATUSES = ("pending", "leased", "review_required", "completed", "closed", "cancelled")


class LeaseError(RuntimeError):
    pass


def _clock(now: int | None) -> int:
    value = int(time.time()) if now is None else now
    if type(value) is not int or value < 0:
        raise LeaseError("time must be a nonnegative integer")
    return value


def _digest(value: str) -> str:
    if not isinstance(value, str) or not DIGEST.fullmatch(value):
        raise LeaseError("expected a lowercase 64-character SHA-256 hex digest")
    return value


def _uuid(value: str) -> str:
    try:
        return _id(value)
    except Exception as exc:
        raise LeaseError("expected a canonical UUID") from exc


def _task_spec(mode: str, task_sha256: str) -> dict:
    if not isinstance(mode, str) or mode not in MODES:
        raise LeaseError("task mode is not in the fixed worker allowlist")
    return {"mode": mode, "task_sha256": _digest(task_sha256)}


def _require_lease_seconds(seconds: int) -> int:
    if type(seconds) is not int or not 1 <= seconds <= MAX_LEASE_SECONDS:
        raise LeaseError("lease duration must be 1..120 seconds")
    return seconds


def _ensure_node(db: sqlite3.Connection, node_id: str, mode: str, now: int) -> sqlite3.Row:
    row = db.execute("""SELECT revoked, last_seen, last_state, expires_at,
                        approved_modes_json, pubkey FROM nodes WHERE id=?""",
                     (node_id,)).fetchone()
    if row is None or row["revoked"]:
        raise LeaseError("worker is not enrolled or is revoked")
    if row["last_seen"] is None or row["expires_at"] is None or now >= row["expires_at"]:
        raise LeaseError("worker heartbeat is not fresh")
    if row["last_state"] != "ready":
        raise LeaseError("worker is draining or not ready")
    if mode not in json.loads(row["approved_modes_json"]):
        raise LeaseError("worker is not enrolled for this task mode")
    return row


def _row(row: sqlite3.Row) -> dict:
    return {
        "task_id": row["task_id"],
        "mode": row["mode"],
        "task_sha256": row["task_sha256"],
        "status": row["status"],
        "created_at": row["created_at"],
        "node_id": row["node_id"],
        "lease_id": row["lease_id"],
        "deadline": row["deadline"],
        "result_status": row["result_status"],
        "evidence_sha256": row["evidence_sha256"],
        "resolution": row["resolution"],
        "execution_authorized": False,
        "task_dispatched": False,
    }


def sign_result(task_id: str, lease_id: str, node_id: str, private_key: bytes,
                manifest_sha256: str, result_status: str, *,
                now: int | None = None) -> dict:
    """Worker signs a result claim. This is NOT proof the work ran."""
    _uuid(task_id)
    _uuid(lease_id)
    _uuid(node_id)
    _digest(manifest_sha256)
    if not isinstance(result_status, str) or result_status not in RESULTS:
        raise LeaseError("unrecognized result status")
    if not isinstance(private_key, bytes) or len(private_key) != 32:
        raise LeaseError("invalid worker private key")
    body = {
        "schema": RESULT_SCHEMA,
        "task_id": task_id, "lease_id": lease_id, "node_id": node_id,
        "manifest_sha256": manifest_sha256, "result_status": result_status,
        "issued_at": _clock(now)
    }
    _, Private, _ = _ed25519()
    return {"body": body, "signature": Private.from_private_bytes(private_key).sign(
        canonical(body)).hex()}


def _validate_result_packet(packet: dict, now: int) -> tuple[dict, bytes]:
    if not isinstance(packet, dict) or set(packet) != {"body", "signature"}:
        raise LeaseError("malformed signed result")
    try:
        if len(canonical(packet)) > MAX_RESULT_PACKET:
            raise LeaseError("result packet exceeds size limit")
    except (ValueError, TypeError) as exc:
        raise LeaseError("result is not valid JSON data") from exc
    body, signature = packet["body"], packet["signature"]
    if not isinstance(body, dict) or set(body) != {
            "schema", "task_id", "lease_id", "node_id",
            "manifest_sha256", "result_status", "issued_at"}:
        raise LeaseError("result contains unexpected or missing fields")
    if body["schema"] != RESULT_SCHEMA:
        raise LeaseError("unsupported result schema")
    for key in ("task_id", "lease_id", "node_id"):
        _uuid(body[key])
    _digest(body["manifest_sha256"])
    if not isinstance(body["result_status"], str) or body["result_status"] not in RESULTS:
        raise LeaseError("unrecognized result status")
    issued = body["issued_at"]
    if type(issued) is not int or not now - RESULT_FRESH_SECONDS <= issued <= now + FUTURE_SKEW_SECONDS:
        raise LeaseError("result has stale or invalid timestamp")
    if not isinstance(signature, str) or not re.fullmatch("[0-9a-f]{128}", signature):
        raise LeaseError("invalid result signature encoding")
    return body, bytes.fromhex(signature)


class TaskLeases:
    """SQLite-backed, operator-only task coordination.

    All state changes use BEGIN IMMEDIATE in the existing node registry DB to
    atomically check enrolled node status, tasks, and one-active-lease-per-node.
    """

    def __init__(self, database: Path):
        # The same database must contain the authoritative node table.
        self.nodes = NodeRegistry(database)
        self.database = self.nodes.database
        with closing(self._connect()) as db:
            with db:
                db.execute("""CREATE TABLE IF NOT EXISTS task_leases (
                    task_id TEXT PRIMARY KEY,
                    mode TEXT NOT NULL,
                    task_sha256 TEXT NOT NULL,
                    status TEXT NOT NULL CHECK(status IN
                      ('pending','leased','review_required','completed','closed','cancelled')),
                    created_at INTEGER NOT NULL,
                    node_id TEXT,
                    lease_id TEXT UNIQUE,
                    deadline INTEGER,
                    result_status TEXT,
                    evidence_sha256 TEXT,
                    resolution TEXT
                )""")
                db.execute("""CREATE INDEX IF NOT EXISTS task_leases_node_status
                    ON task_leases(node_id, status)""")
                db.execute("""CREATE TABLE IF NOT EXISTS task_lease_events (
                    event_id INTEGER PRIMARY KEY AUTOINCREMENT,
                    task_id TEXT NOT NULL,
                    at INTEGER NOT NULL,
                    kind TEXT NOT NULL,
                    detail TEXT NOT NULL
                )""")

    def _connect(self) -> sqlite3.Connection:
        db = sqlite3.connect(self.database, timeout=5)
        db.row_factory = sqlite3.Row
        return db

    @staticmethod
    def _event(db: sqlite3.Connection, task_id: str, at: int,
               kind: str, detail: dict) -> None:
        db.execute("""INSERT INTO task_lease_events(task_id,at,kind,detail)
                      VALUES (?,?,?,?)""", (task_id, at, kind, canonical(detail).decode("utf-8")))

    def create(self, task_id: str, mode: str, task_sha256: str,
               *, now: int | None = None) -> dict:
        """Trusted operator records intent. Repeated same task ID is idempotent."""
        _uuid(task_id)
        spec = _task_spec(mode, task_sha256)
        when = _clock(now)
        with closing(self._connect()) as db:
            db.execute("BEGIN IMMEDIATE")
            try:
                existing = db.execute("SELECT * FROM task_leases WHERE task_id=?", (task_id,)).fetchone()
                if existing is not None:
                    if existing["mode"] != spec["mode"] or existing["task_sha256"] != spec["task_sha256"]:
                        raise LeaseError("task id reused for a different immutable specification")
                    db.commit()
                    return _row(existing)
                db.execute("""INSERT INTO task_leases
                    (task_id,mode,task_sha256,status,created_at)
                    VALUES (?,?,?,'pending',?)""",
                    (task_id, mode, task_sha256, when))
                self._event(db, task_id, when, "created", spec)
                created = db.execute("SELECT * FROM task_leases WHERE task_id=?", (task_id,)).fetchone()
                db.commit()
                return _row(created)
            except BaseException:
                db.rollback()
                raise

    def lease(self, task_id: str, node_id: str, seconds: int = 30,
              *, now: int | None = None) -> dict:
        """Trusted local operator records ownership; does not send or run work."""
        _uuid(task_id)
        _uuid(node_id)
        seconds = _require_lease_seconds(seconds)
        when = _clock(now)
        with closing(self._connect()) as db:
            db.execute("BEGIN IMMEDIATE")
            try:
                task = db.execute("SELECT * FROM task_leases WHERE task_id=?", (task_id,)).fetchone()
                if task is None or task["status"] != "pending":
                    raise LeaseError("only pending tasks can be leased")
                node = _ensure_node(db, node_id, task["mode"], when)
                busy = db.execute("""SELECT task_id FROM task_leases
                                     WHERE node_id=? AND status='leased'""", (node_id,)).fetchone()
                if busy:
                    raise LeaseError("worker already owns a lease; reconcile it first")
                # Lease cannot outlive the most recent signed heartbeat's validity.
                deadline = min(when + seconds, node["expires_at"])
                if deadline <= when:
                    raise LeaseError("node heartbeat has expired")
                lease_id = str(uuid4())
                db.execute("""UPDATE task_leases SET status='leased', node_id=?,
                              lease_id=?, deadline=? WHERE task_id=?""",
                           (node_id, lease_id, deadline, task_id))
                self._event(db, task_id, when, "leased",
                            {"node_id": node_id, "lease_id": lease_id,
                             "deadline": deadline, "execution_authorized": False})
                leased = db.execute("SELECT * FROM task_leases WHERE task_id=?", (task_id,)).fetchone()
                db.commit()
                return _row(leased)
            except BaseException:
                db.rollback()
                raise

    def reconcile(self, *, now: int | None = None) -> list[str]:
        """Mark uncertain leases for manual review. NEVER silently requeue."""
        when = _clock(now)
        changed = []
        with closing(self._connect()) as db:
            db.execute("BEGIN IMMEDIATE")
            try:
                rows = db.execute("""SELECT t.task_id, t.deadline, n.revoked,
                       n.last_seen, n.expires_at, n.last_state
                       FROM task_leases AS t LEFT JOIN nodes AS n
                       ON t.node_id=n.id WHERE t.status='leased'""").fetchall()
                for row in rows:
                    reason = None
                    if row["deadline"] <= when:
                        reason = "lease_deadline_elapsed"
                    elif row["revoked"] is None or row["revoked"]:
                        reason = "node_missing_or_revoked"
                    elif row["expires_at"] is None or row["expires_at"] <= when:
                        reason = "node_heartbeat_expired"
                    # A draining node is allowed to finish its existing lease.
                    if reason:
                        db.execute("""UPDATE task_leases SET status='review_required',
                                      resolution=? WHERE task_id=?""",
                                   (reason, row["task_id"]))
                        self._event(db, row["task_id"], when, "review_required",
                                    {"reason": reason, "automatic_retry": False})
                        changed.append(row["task_id"])
                db.commit()
            except BaseException:
                db.rollback()
                raise
        return changed

    def complete(self, packet: dict, vault_root: Path, manifest: Path,
                 *, now: int | None = None) -> dict:
        """Verify signed result claim and content integrity before recording outcome.

        This does not attest real execution, sandbox safety or worker honesty.
        """
        when = _clock(now)
        body, signature = _validate_result_packet(packet, when)
        vault = Vault(vault_root)
        try:
            if not vault.verify(manifest):
                raise LeaseError("evidence manifest could not be verified")
            raw_manifest = manifest.read_bytes()
        except (VaultError, OSError) as exc:
            raise LeaseError("evidence is missing or corrupt") from exc
        if hashlib.sha256(raw_manifest).hexdigest() != body["manifest_sha256"]:
            raise LeaseError("signed evidence digest mismatch")
        # A signer cannot label a failed worker report as a passing result.
        evidence_status = json.loads(raw_manifest)["evidence_status"]
        expected = body["result_status"]
        if expected in ("passed", "failed"):
            if evidence_status != expected:
                raise LeaseError("signed outcome conflicts with evidence report")
        elif evidence_status not in ("inconclusive", "timed_out", "output_limit",
                                      "cleanup_unverified", "failed"):
            raise LeaseError("inconclusive result has incompatible evidence report")
        Invalid, _, Public = _ed25519()
        with closing(self._connect()) as db:
            db.execute("BEGIN IMMEDIATE")
            try:
                row = db.execute("SELECT * FROM task_leases WHERE task_id=?",
                                 (body["task_id"],)).fetchone()
                if (row is None or row["status"] != "leased"
                        or row["node_id"] != body["node_id"]
                        or row["lease_id"] != body["lease_id"]):
                    raise LeaseError("result has no matching active lease")
                if when >= row["deadline"]:
                    raise LeaseError("lease deadline passed; operator review required")
                node = db.execute("""SELECT pubkey, revoked, last_seen, expires_at
                       FROM nodes WHERE id=?""", (body["node_id"],)).fetchone()
                if (node is None or node["revoked"] or node["last_seen"] is None or
                        node["expires_at"] is None or when < node["last_seen"] or
                        when >= node["expires_at"]):
                    raise LeaseError("worker no longer has a fresh enrolled identity")
                try:
                    Public.from_public_bytes(node["pubkey"]).verify(signature, canonical(body))
                except (Invalid, ValueError) as exc:
                    raise LeaseError("result signature does not match enrolled worker") from exc
                uncertain = body["result_status"] == "inconclusive"
                state = "review_required" if uncertain else "completed"
                db.execute("""UPDATE task_leases SET status=?, result_status=?,
                              evidence_sha256=?, resolution=? WHERE task_id=?""",
                           (state, body["result_status"], body["manifest_sha256"],
                            "inconclusive_result" if uncertain else None, body["task_id"]))
                self._event(db, body["task_id"], when, state, {
                    "node_id": body["node_id"], "lease_id": body["lease_id"],
                    "result_status": body["result_status"],
                    "evidence_sha256": body["manifest_sha256"],
                    "execution_verified": False
                })
                result = db.execute("SELECT * FROM task_leases WHERE task_id=?",
                                    (body["task_id"],)).fetchone()
                db.commit()
                return _row(result)
            except BaseException:
                db.rollback()
                raise

    def close(self, task_id: str, reason: str, *, now: int | None = None) -> dict:
        """Operator explicitly closes review-required task; never auto-requeues."""
        _uuid(task_id)
        if not isinstance(reason, str) or not 1 <= len(reason.strip()) <= 250:
            raise LeaseError("a short operator review reason is required")
        when = _clock(now)
        with closing(self._connect()) as db:
            db.execute("BEGIN IMMEDIATE")
            try:
                row = db.execute("SELECT * FROM task_leases WHERE task_id=?",
                                 (task_id,)).fetchone()
                if row is None or row["status"] != "review_required":
                    raise LeaseError("only review-required tasks can be closed")
                db.execute("UPDATE task_leases SET status='closed', resolution=? WHERE task_id=?",
                           (reason.strip(), task_id))
                self._event(db, task_id, when, "closed", {"operator_reason": reason.strip()})
                value = db.execute("SELECT * FROM task_leases WHERE task_id=?",
                                   (task_id,)).fetchone()
                db.commit()
                return _row(value)
            except BaseException:
                db.rollback()
                raise

    def cancel(self, task_id: str, *, now: int | None = None) -> dict:
        """Operator may cancel only a not-yet-assigned task."""
        _uuid(task_id)
        when = _clock(now)
        with closing(self._connect()) as db:
            db.execute("BEGIN IMMEDIATE")
            try:
                row = db.execute("SELECT * FROM task_leases WHERE task_id=?",
                                 (task_id,)).fetchone()
                if row is None or row["status"] != "pending":
                    raise LeaseError("only pending tasks may be cancelled")
                db.execute("UPDATE task_leases SET status='cancelled' WHERE task_id=?",
                           (task_id,))
                self._event(db, task_id, when, "cancelled", {})
                value = db.execute("SELECT * FROM task_leases WHERE task_id=?",
                                   (task_id,)).fetchone()
                db.commit()
                return _row(value)
            except BaseException:
                db.rollback()
                raise

    def get(self, task_id: str) -> dict:
        _uuid(task_id)
        with closing(self._connect()) as db:
            row = db.execute("SELECT * FROM task_leases WHERE task_id=?", (task_id,)).fetchone()
        if row is None:
            raise LeaseError("unknown task")
        return _row(row)

    def list(self, limit: int = 100) -> list[dict]:
        if type(limit) is not int or not 1 <= limit <= 250:
            raise LeaseError("limit must be 1..250")
        with closing(self._connect()) as db:
            rows = db.execute("""SELECT * FROM task_leases
                                 ORDER BY created_at DESC, task_id LIMIT ?""",
                              (limit,)).fetchall()
        return [_row(row) for row in rows]

    def events(self, task_id: str) -> list[dict]:
        _uuid(task_id)
        with closing(self._connect()) as db:
            rows = db.execute("""SELECT event_id, at, kind, detail
                    FROM task_lease_events WHERE task_id=? ORDER BY event_id""",
                    (task_id,)).fetchall()
        return [{"event_id": row["event_id"], "at": row["at"],
                 "kind": row["kind"], "detail": json.loads(row["detail"])} for row in rows]


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        description="Offline operator-controlled durable lease metadata; never executes work")
    actions = parser.add_subparsers(dest="command", required=True)
    for name in ("create", "lease", "reconcile", "list", "get", "events",
                 "cancel", "close", "complete", "sign-result"):
        sub = actions.add_parser(name)
        if name not in ("sign-result",):
            sub.add_argument("--db", required=True, type=Path)
        if name in ("get", "events", "lease", "cancel", "close", "sign-result"):
            sub.add_argument("--task-id", required=True)
        if name == "create":
            sub.add_argument("--task-id", default=None)
            sub.add_argument("--mode", required=True, choices=sorted(MODES))
            sub.add_argument("--task-sha256", required=True)
        if name == "lease":
            sub.add_argument("--node-id", required=True)
            sub.add_argument("--seconds", type=int, default=30)
        if name == "close":
            sub.add_argument("--reason", required=True)
        if name in ("complete", "sign-result"):
            sub.add_argument("--manifest", required=True, type=Path)
        if name == "complete":
            sub.add_argument("--packet", required=True, type=Path)
            sub.add_argument("--vault", required=True, type=Path)
        if name == "sign-result":
            sub.add_argument("--lease-id", required=True)
            sub.add_argument("--node-id", required=True)
            sub.add_argument("--private", required=True, type=Path)
            sub.add_argument("--result", required=True, choices=sorted(RESULTS))
            sub.add_argument("--out", required=True, type=Path)
    args = parser.parse_args(argv)
    try:
        if args.command == "sign-result":
            from .mesh import _write_exclusive
            raw = args.manifest.read_bytes()
            if len(raw) > 2 * 1024 * 1024:
                raise LeaseError("manifest is oversized")
            packet = sign_result(args.task_id, args.lease_id, args.node_id,
                                 _read_key(args.private, private=True),
                                 hashlib.sha256(raw).hexdigest(), args.result)
            _write_exclusive(args.out, canonical(packet) + b"\n")
            result = {"packet_written": str(args.out), "execution_verified": False}
        else:
            ledger = TaskLeases(args.db)
            if args.command == "create":
                result = ledger.create(args.task_id or str(uuid4()), args.mode, args.task_sha256)
            elif args.command == "lease":
                result = ledger.lease(args.task_id, args.node_id, args.seconds)
            elif args.command == "complete":
                if args.packet.stat().st_size > MAX_RESULT_PACKET:
                    raise LeaseError("result packet too large")
                packet = json.loads(args.packet.read_text(encoding="utf-8"))
                result = ledger.complete(packet, args.vault, args.manifest)
            elif args.command == "reconcile":
                result = {"review_required_tasks": ledger.reconcile(), "automatic_retry": False}
            elif args.command == "cancel":
                result = ledger.cancel(args.task_id)
            elif args.command == "close":
                result = ledger.close(args.task_id, args.reason)
            elif args.command == "get":
                result = ledger.get(args.task_id)
            elif args.command == "events":
                result = ledger.events(args.task_id)
            else:
                result = ledger.list()
        print(json.dumps(result, indent=2, sort_keys=True))
        return 0
    except (LeaseError, OSError, ValueError, VaultError, json.JSONDecodeError) as exc:
        parser.exit(2, f"refused: {exc}\n")


if __name__ == "__main__":
    raise SystemExit(main())
