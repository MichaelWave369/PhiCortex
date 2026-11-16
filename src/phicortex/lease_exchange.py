"""Authenticated *metadata-only* lease preview and receipt acknowledgment.

No code, URLs, workspace bytes, secrets, permits, task execution or dispatch.
A successful request proves the enrolled node key + pinned TLS identity had
access to a lease summary at that moment, not that the job was performed.
"""
from __future__ import annotations

from contextlib import closing
import json
import re
import sqlite3
import time

from .mesh import (_ed25519, _id, canonical, MAX_SEQUENCE,
                   MAX_AGE_SECONDS, MAX_FUTURE_SECONDS)
from .leases import TaskLeases

SCHEMA = "phicortex.mesh.lease_exchange.v1"
MAX_PACKET_BYTES = 4096
ACTIONS = ("preview", "ack")


class ExchangeError(RuntimeError):
    pass


def _uuid(value: str) -> str:
    try:
        return _id(value)
    except (ValueError, TypeError, AttributeError) as exc:
        raise ExchangeError("invalid node or lease UUID") from exc
    except Exception as exc:
        raise ExchangeError("invalid node or lease UUID") from exc


def sign_exchange(node_id: str, sequence: int, private_key: bytes,
                  action: str, *, lease_id: str | None = None,
                  now: int | None = None) -> dict:
    """Sign one exact action; use the SAME durable node sequence as heartbeats."""
    _uuid(node_id)
    if type(sequence) is not int or not 1 <= sequence <= MAX_SEQUENCE:
        raise ExchangeError("sequence must be positive and monotonic")
    if action not in ACTIONS:
        raise ExchangeError("unknown exchange action")
    if (action == "preview" and lease_id is not None) or (action == "ack" and lease_id is None):
        raise ExchangeError("lease_id must be present only for acknowledgment")
    if lease_id is not None:
        _uuid(lease_id)
    if not isinstance(private_key, bytes) or len(private_key) != 32:
        raise ExchangeError("node signing key must have 32 raw bytes")
    stamp = int(time.time()) if now is None else now
    if type(stamp) is not int or stamp < 0:
        raise ExchangeError("invalid signing time")
    body = {"schema": SCHEMA, "action": action, "node_id": node_id,
            "sequence": sequence, "issued_at": stamp, "lease_id": lease_id}
    _, Private, _ = _ed25519()
    return {"body": body,
            "signature": Private.from_private_bytes(private_key).sign(
                canonical(body)).hex()}


def _validate(packet: dict, action: str, now: int) -> tuple[dict, bytes]:
    if action not in ACTIONS:
        raise ExchangeError("unrecognized exchange endpoint")
    try:
        if not isinstance(packet, dict) or set(packet) != {"body", "signature"}:
            raise ExchangeError("malformed signed request")
        if len(canonical(packet)) > MAX_PACKET_BYTES:
            raise ExchangeError("oversized signed request")
    except (TypeError, ValueError) as exc:
        raise ExchangeError("invalid signed JSON request") from exc
    body, encoded = packet["body"], packet["signature"]
    if not isinstance(body, dict) or set(body) != {
        "schema", "action", "node_id", "lease_id", "sequence", "issued_at"
    }:
        raise ExchangeError("unexpected or missing signed request fields")
    if body["schema"] != SCHEMA or body["action"] != action:
        raise ExchangeError("action or version does not match endpoint")
    _uuid(body["node_id"])
    sequence, stamp = body["sequence"], body["issued_at"]
    if type(sequence) is not int or not 1 <= sequence <= MAX_SEQUENCE:
        raise ExchangeError("invalid request sequence")
    if type(stamp) is not int or not now - MAX_AGE_SECONDS <= stamp <= now + MAX_FUTURE_SECONDS:
        raise ExchangeError("stale or future signed request")
    lease_id = body["lease_id"]
    if (action == "preview" and lease_id is not None) or (action == "ack" and lease_id is None):
        raise ExchangeError("invalid lease_id for request action")
    if lease_id is not None:
        _uuid(lease_id)
    if not isinstance(encoded, str) or not re.fullmatch("[0-9a-f]{128}", encoded):
        raise ExchangeError("malformed Ed25519 signature")
    return body, bytes.fromhex(encoded)


class LeaseExchange:
    """Trusted coordinator-bound node metadata exchange.

    All identity, pin, sequence, lease, receipt checks and updates use one
    SQLite BEGIN IMMEDIATE transaction in the enrolled node/lease database.
    """

    def __init__(self, database):
        self.leases = TaskLeases(database)
        self.database = self.leases.database
        with closing(self.leases._connect()) as db:
            with db:
                db.execute("""CREATE TABLE IF NOT EXISTS lease_receipts (
                    lease_id TEXT PRIMARY KEY,
                    task_id TEXT NOT NULL,
                    node_id TEXT NOT NULL,
                    acknowledged_at INTEGER NOT NULL,
                    request_sequence INTEGER NOT NULL
                )""")

    def apply(self, packet: dict, *, action: str, tls_peer_sha256: str,
              now: int | None = None) -> dict:
        stamp = int(time.time()) if now is None else now
        if type(stamp) is not int or stamp < 0:
            raise ExchangeError("invalid coordinator time")
        body, signature = _validate(packet, action, stamp)
        if (not isinstance(tls_peer_sha256, str) or
                not re.fullmatch("[0-9a-f]{64}", tls_peer_sha256)):
            raise ExchangeError("missing or invalid TLS peer pin")
        node_id, sequence = body["node_id"], body["sequence"]
        Invalid, _, Public = _ed25519()
        with closing(self.leases._connect()) as db:
            db.execute("BEGIN IMMEDIATE")
            try:
                node = db.execute("""SELECT pubkey, revoked, last_sequence, last_seen,
                    last_state, expires_at FROM nodes WHERE id=?""",
                    (node_id,)).fetchone()
                if node is None or node["revoked"]:
                    raise ExchangeError("node not enrolled or revoked")
                pin = db.execute("""SELECT certificate_sha256 FROM node_tls_pins
                    WHERE node_id=?""", (node_id,)).fetchone()
                if pin is None or pin["certificate_sha256"] != tls_peer_sha256:
                    raise ExchangeError("client certificate is not pinned to this node")
                try:
                    Public.from_public_bytes(node["pubkey"]).verify(
                        signature, canonical(body))
                except (Invalid, ValueError, TypeError) as exc:
                    raise ExchangeError("node signature invalid") from exc
                if sequence <= node["last_sequence"]:
                    raise ExchangeError("replayed or out-of-order exchange sequence")
                if (node["last_seen"] is None or node["expires_at"] is None
                        or stamp < node["last_seen"] or stamp >= node["expires_at"]
                        or node["last_state"] != "ready"):
                    raise ExchangeError("node requires a fresh ready heartbeat")
                active = db.execute("""SELECT task_id, lease_id, mode, task_sha256,
                    deadline FROM task_leases WHERE node_id=? AND status='leased'
                    ORDER BY task_id LIMIT 2""", (node_id,)).fetchall()
                if len(active) > 1:
                    raise ExchangeError("multiple concurrent leases detected")
                item = active[0] if active and active[0]["deadline"] > stamp else None
                if action == "ack":
                    if item is None or item["lease_id"] != body["lease_id"]:
                        raise ExchangeError("acknowledgment is not for an active lease")
                acknowledged = False
                if item is not None:
                    receipt = db.execute("SELECT task_id, node_id FROM lease_receipts "
                                         "WHERE lease_id=?", (item["lease_id"],)).fetchone()
                    if receipt is not None:
                        if (receipt["task_id"] != item["task_id"]
                                or receipt["node_id"] != node_id):
                            raise ExchangeError("receipt ownership mismatch")
                        acknowledged = True
                    if action == "ack" and not acknowledged:
                        db.execute("""INSERT INTO lease_receipts
                            (lease_id, task_id, node_id, acknowledged_at, request_sequence)
                            VALUES (?,?,?,?,?)""",
                            (item["lease_id"], item["task_id"], node_id, stamp, sequence))
                        db.execute("""INSERT INTO task_lease_events(task_id,at,kind,detail)
                            VALUES (?,?,?,?)""",
                            (item["task_id"], stamp, "lease_metadata_ack",
                             canonical({"node_id": node_id, "lease_id": item["lease_id"],
                                        "execution_authorized": False}).decode("utf-8")))
                        acknowledged = True
                db.execute("UPDATE nodes SET last_sequence=? WHERE id=?",
                           (sequence, node_id))
                db.commit()
            except BaseException:
                db.rollback()
                raise
        # Deliberately no executable instructions or permitted source paths.
        summary = None
        if item is not None:
            summary = {"task_id": item["task_id"], "lease_id": item["lease_id"],
                       "mode": item["mode"], "task_sha256": item["task_sha256"],
                       "deadline": item["deadline"], "acknowledged": acknowledged}
        return {"schema": SCHEMA, "action": action, "node_id": node_id,
                "sequence": sequence, "lease": summary,
                "execution_authorized": False, "task_dispatched": False,
                "governor_permit_included": False, "task_payload_included": False}
