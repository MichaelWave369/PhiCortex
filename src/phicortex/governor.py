"""Operator-issued, task-bound HMAC grants for an experimental local worker.

This is a *prototype* control, not an independent security process or a
cryptographic proof that Docker/gVisor is isolated. Operator secrets must never
enter the LLM context, a workspace, a container, or a publicly accessible API.
"""
from __future__ import annotations

import argparse
import hashlib
import hmac
import json
import os
from pathlib import Path
import secrets
import sqlite3
import stat
import time
from uuid import uuid4

SCHEMA = "phicortex.governor.permit.v0"
MAX_TTL = 300
MAX_FILE_BYTES = 8 * 1024 * 1024
MAX_TOTAL_BYTES = 64 * 1024 * 1024


class GovernorError(RuntimeError):
    pass


def canonical(value: object) -> bytes:
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False,
                      allow_nan=False).encode("utf-8")


def init_key(path: Path) -> Path:
    """Create a fresh owner-only secret; never overwrite an existing one."""
    path = path.expanduser().absolute()
    path.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
    try:
        fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    except FileExistsError as exc:
        raise GovernorError("key already exists; refusing replacement") from exc
    try:
        with os.fdopen(fd, "wb") as output:
            output.write(secrets.token_bytes(32))
            output.flush()
            os.fsync(output.fileno())
    except BaseException:
        path.unlink(missing_ok=True)
        raise
    return path


def load_key(path: Path) -> bytes:
    path = path.expanduser()
    if path.is_symlink():
        raise GovernorError("symlinked key file refused")
    try:
        meta = path.stat()
    except OSError as exc:
        raise GovernorError("key file unavailable") from exc
    if not stat.S_ISREG(meta.st_mode):
        raise GovernorError("key must be a regular file")
    if os.name == "posix" and (meta.st_mode & 0o077):
        raise GovernorError("key file must not be group/world accessible")
    data = path.read_bytes()
    if len(data) != 32:
        raise GovernorError("key file must contain exactly 32 random bytes")
    return data


def workspace_digest(root: Path) -> str:
    """Bound, symlink-free content digest for the approved workspace snapshot.

    Not a filesystem snapshot or protection against a concurrent hostile writer.
    Source tree must be stable and controlled by the operator.
    """
    root = root.expanduser().resolve(strict=True)
    if not root.is_dir():
        raise GovernorError("workspace not a directory")
    h = hashlib.sha256()
    count, total = 0, 0
    for child in sorted(root.rglob("*")):
        count += 1
        if count > 2000:
            raise GovernorError("too many workspace entries")
        if child.is_symlink():
            raise GovernorError("workspace symlink refused")
        if not child.is_file() and not child.is_dir():
            raise GovernorError("special filesystem entry refused")
        name = child.relative_to(root).as_posix()
        if child.is_dir():
            h.update(canonical(["dir", name]))
            continue
        size = child.stat().st_size
        total += size
        if size > MAX_FILE_BYTES or total > MAX_TOTAL_BYTES:
            raise GovernorError("workspace exceeds digest size limits")
        h.update(canonical(["file", name, size]))
        with child.open("rb") as stream:
            while True:
                chunk = stream.read(1024 * 1024)
                if not chunk:
                    break
                h.update(chunk)
    return h.hexdigest()


def task_fields(job: dict) -> dict:
    return {key: job[key] for key in
            ("mode", "authorized_root", "workspace", "image", "timeout_seconds")}


def issue(job: dict, key: bytes, *, ttl: int = 60, now: int | None = None) -> dict:
    if type(ttl) is not int or not 1 <= ttl <= MAX_TTL:
        raise GovernorError("permit TTL must be 1..300 seconds")
    if len(key) != 32:
        raise GovernorError("invalid operator key")
    issued_at = int(time.time()) if now is None else now
    content = {"schema": SCHEMA, "issued_at": issued_at, "expires_at": issued_at + ttl,
               "nonce": str(uuid4()), "job": task_fields(job),
               "workspace_sha256": workspace_digest(Path(job["workspace"]))}
    content["signature"] = hmac.new(key, canonical(content), hashlib.sha256).hexdigest()
    return content


def _consume_nonce(database: Path, nonce: str, expires: int) -> None:
    database = database.expanduser().absolute()
    if database.is_symlink():
        raise GovernorError("symlinked replay ledger refused")
    database.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
    conn = sqlite3.connect(database, timeout=5)
    try:
        conn.execute("CREATE TABLE IF NOT EXISTS consumed_permits (nonce TEXT PRIMARY KEY, expires INTEGER NOT NULL)")
        try:
            # SQLite PRIMARY KEY is the atomic replay guard, even under concurrency.
            conn.execute("INSERT INTO consumed_permits(nonce, expires) VALUES (?, ?)", (nonce, expires))
            conn.commit()
        except sqlite3.IntegrityError as exc:
            raise GovernorError("permit replay refused") from exc
    finally:
        # A SQLite connection context manager does not close the handle.
        # Explicit close matters on Windows for cleanup, backup, and rotation.
        conn.close()


def verify_and_consume(permit: dict, job: dict, key: bytes, replay_db: Path,
                       *, now: int | None = None) -> None:
    if not isinstance(permit, dict) or set(permit) != {
            "schema", "issued_at", "expires_at", "nonce", "job", "workspace_sha256", "signature"}:
        raise GovernorError("invalid permit schema")
    signature = permit.get("signature")
    if not isinstance(signature, str) or len(signature) != 64:
        raise GovernorError("invalid signature")
    payload = {k: v for k, v in permit.items() if k != "signature"}
    expected = hmac.new(key, canonical(payload), hashlib.sha256).hexdigest()
    if not hmac.compare_digest(signature, expected):
        raise GovernorError("permit signature mismatch")
    issued, expires = permit["issued_at"], permit["expires_at"]
    current = int(time.time()) if now is None else now
    if (permit["schema"] != SCHEMA or type(issued) is not int or type(expires) is not int
            or expires - issued not in range(1, MAX_TTL + 1)
            or issued > current + 5 or current >= expires):
        raise GovernorError("permit invalid, expired or outside time window")
    from uuid import UUID
    try:
        if str(UUID(permit["nonce"])) != permit["nonce"]:
            raise ValueError()
    except (ValueError, AttributeError, TypeError) as exc:
        raise GovernorError("invalid permit nonce") from exc
    if permit["job"] != task_fields(job):
        raise GovernorError("permit does not authorize this task")
    current_digest = workspace_digest(Path(job["workspace"]))
    if not hmac.compare_digest(permit["workspace_sha256"], current_digest):
        raise GovernorError("workspace changed since permit issuance")
    _consume_nonce(replay_db, permit["nonce"], expires)


def write_permit(path: Path, permit: dict) -> None:
    """Exclusive, non-overwriting local permit write."""
    path = path.expanduser().absolute()
    path.parent.mkdir(parents=True, mode=0o700, exist_ok=True)
    try:
        with os.fdopen(os.open(path, os.O_CREAT | os.O_EXCL | os.O_WRONLY, 0o600), "wb") as out:
            out.write(canonical(permit) + b"\n")
    except FileExistsError as exc:
        raise GovernorError("permit exists; refusing overwrite") from exc


def main(argv=None) -> int:
    p = argparse.ArgumentParser(description="Trusted operator CLI to issue short-lived permits")
    commands = p.add_subparsers(dest="action", required=True)
    k = commands.add_parser("init-key")
    k.add_argument("--key-file", required=True, type=Path)
    a = commands.add_parser("approve")
    a.add_argument("--key-file", required=True, type=Path)
    a.add_argument("--workspace-root", required=True, type=Path)
    a.add_argument("--workspace", required=True, type=Path)
    a.add_argument("--image", required=True)
    a.add_argument("--mode", required=True, choices=("build-check", "test"))
    a.add_argument("--seconds", type=int, default=30)
    a.add_argument("--ttl", type=int, default=60)
    a.add_argument("--out", required=True, type=Path)
    args = p.parse_args(argv)
    try:
        if args.action == "init-key":
            init_key(args.key_file)
            print("Operator key initialized; keep it outside workspaces and backups shared with agents.")
        else:
            from .worker import plan
            job = plan(args.mode, args.workspace_root, args.workspace,
                       args.image, args.seconds)
            # Never store the signing secret or permit inside the mounted project.
            target = args.out.expanduser().resolve()
            secret_path = args.key_file.expanduser().resolve(strict=True)
            workspace = Path(job["workspace"])
            if any(path == workspace or workspace in path.parents
                   for path in (target, secret_path)):
                raise GovernorError("operator key and permit must be outside the workspace")
            issued = issue(job, load_key(args.key_file), ttl=args.ttl)
            write_permit(args.out, issued)
            print("Approved a short-lived single-use task permit.")
        return 0
    except (GovernorError, OSError, ValueError) as exc:
        p.exit(2, f"refused: {exc}\n")


if __name__ == "__main__":
    raise SystemExit(main())
