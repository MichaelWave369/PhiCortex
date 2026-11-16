"""Asymmetric operator-issued, single-use permits for copied workspaces.

The signer can be kept on a different OS account or machine; the execution
worker needs only a *public* Ed25519 key. Requires optional 'cryptography'.
"""
from __future__ import annotations

import argparse
from datetime import datetime, timezone
import hashlib
import json
import os
from pathlib import Path
import secrets
import stat
import time
from uuid import uuid4

from .governor import canonical, task_fields, _consume_nonce, MAX_TTL
from .snapshot import create_snapshot, verify_snapshot, SnapshotError

SCHEMA = "phicortex.governor.ed25519.v1"


class ApprovalError(RuntimeError):
    pass


def _crypto():
    try:
        from cryptography.exceptions import InvalidSignature
        from cryptography.hazmat.primitives.asymmetric.ed25519 import (
            Ed25519PrivateKey, Ed25519PublicKey)
    except ImportError as exc:
        raise ApprovalError("install the optional cryptography package") from exc
    return InvalidSignature, Ed25519PrivateKey, Ed25519PublicKey


def _write_new(path: Path, content: bytes, mode: int) -> None:
    path = path.expanduser().absolute()
    path.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
    try:
        fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, mode)
    except FileExistsError as exc:
        raise ApprovalError("key or permit already exists") from exc
    try:
        with os.fdopen(fd, "wb") as output:
            output.write(content)
            output.flush()
            os.fsync(output.fileno())
    except BaseException:
        path.unlink(missing_ok=True)
        raise


def create_keypair(private_path: Path, public_path: Path) -> None:
    if private_path.expanduser().absolute() == public_path.expanduser().absolute():
        raise ApprovalError("public and private key paths must differ")
    if private_path.exists() or public_path.exists():
        raise ApprovalError("key pair exists; refusing overwrite")
    _, Private, _ = _crypto()
    key = Private.generate()
    _write_new(private_path, key.private_bytes_raw(), 0o600)
    try:
        _write_new(public_path, key.public_key().public_bytes_raw(), 0o644)
    except BaseException:
        private_path.unlink(missing_ok=True)
        raise


def _load(path: Path, *, private: bool) -> bytes:
    if path.is_symlink():
        raise ApprovalError("symlinked key refused")
    try:
        meta = path.stat()
        if not stat.S_ISREG(meta.st_mode):
            raise ApprovalError("key must be a regular file")
        if private and os.name == "posix" and (meta.st_mode & 0o077):
            raise ApprovalError("private signing key is accessible to other users")
        data = path.read_bytes()
    except OSError as exc:
        raise ApprovalError("key unavailable") from exc
    if len(data) != 32:
        raise ApprovalError("raw Ed25519 key must contain 32 bytes")
    return data


def issue(job: dict, snapshot_manifest: Path, private_key: bytes,
          *, ttl: int = 60, now: int | None = None) -> dict:
    if type(ttl) is not int or not 1 <= ttl <= MAX_TTL:
        raise ApprovalError("permit validity must be 1..300 seconds")
    if len(private_key) != 32:
        raise ApprovalError("invalid Ed25519 private key")
    manifest = snapshot_manifest.expanduser().resolve(strict=True)
    metadata = verify_snapshot(manifest, expected_workspace=job["workspace"])
    issued_at = int(time.time()) if now is None else now
    payload = {
        "schema": SCHEMA, "issued_at": issued_at, "expires_at": issued_at + ttl,
        "nonce": str(uuid4()), "job": task_fields(job),
        "snapshot_manifest": str(manifest),
        "workspace_sha256": metadata["workspace_sha256"],
        "manifest_sha256": hashlib.sha256(manifest.read_bytes()).hexdigest(),
    }
    _, Private, _ = _crypto()
    payload["signature"] = Private.from_private_bytes(private_key).sign(canonical(payload)).hex()
    return payload


def verify_and_consume(permit: dict, job: dict, public_key: bytes, replay_db: Path,
                       *, now: int | None = None) -> None:
    if not isinstance(permit, dict) or set(permit) != {
        "schema", "issued_at", "expires_at", "nonce", "job",
        "snapshot_manifest", "workspace_sha256", "manifest_sha256", "signature"
    }:
        raise ApprovalError("invalid signed permit schema")
    if not isinstance(public_key, bytes) or len(public_key) != 32:
        raise ApprovalError("worker needs a 32-byte public verification key")
    encoded = permit["signature"]
    if not isinstance(encoded, str) or len(encoded) != 128:
        raise ApprovalError("invalid Ed25519 signature")
    Invalid, _, Public = _crypto()
    try:
        signature = bytes.fromhex(encoded)
        Public.from_public_bytes(public_key).verify(
            signature, canonical({k: v for k, v in permit.items() if k != "signature"}))
    except (Invalid, ValueError, TypeError) as exc:
        raise ApprovalError("permit signature invalid") from exc
    current = int(time.time()) if now is None else now
    issued, expires = permit["issued_at"], permit["expires_at"]
    if (permit["schema"] != SCHEMA or type(issued) is not int or type(expires) is not int
            or not 1 <= expires - issued <= MAX_TTL
            or issued > current + 5 or current >= expires):
        raise ApprovalError("permit expired or invalid")
    try:
        from uuid import UUID
        if str(UUID(permit["nonce"])) != permit["nonce"]:
            raise ValueError()
    except (ValueError, TypeError, AttributeError) as exc:
        raise ApprovalError("invalid nonce") from exc
    if permit["job"] != task_fields(job):
        raise ApprovalError("permit is for a different task")
    try:
        manifest = Path(permit["snapshot_manifest"])
        if (not manifest.is_absolute() or manifest.is_symlink()
                or hashlib.sha256(manifest.read_bytes()).hexdigest() != permit["manifest_sha256"]):
            raise ApprovalError("snapshot manifest differs from approval")
        meta = verify_snapshot(manifest, expected_workspace=job["workspace"])
        if meta["workspace_sha256"] != permit["workspace_sha256"]:
            raise ApprovalError("snapshot bytes differ from approval")
    except (OSError, TypeError, SnapshotError) as exc:
        raise ApprovalError("snapshot is missing or unverified") from exc
    try:
        _consume_nonce(replay_db, permit["nonce"], expires)
    except Exception as exc:
        raise ApprovalError("permit nonce replay or ledger unavailable") from exc


def main(argv=None) -> int:
    cli = argparse.ArgumentParser(description="Ed25519 operator approval tools")
    commands = cli.add_subparsers(dest="action", required=True)
    keys = commands.add_parser("init-keys")
    keys.add_argument("--private", type=Path, required=True)
    keys.add_argument("--public", type=Path, required=True)
    snap = commands.add_parser("snapshot")
    snap.add_argument("--source", type=Path, required=True)
    snap.add_argument("--store", type=Path, required=True)
    approve = commands.add_parser("approve")
    approve.add_argument("--private", type=Path, required=True)
    approve.add_argument("--snapshot-manifest", type=Path, required=True)
    approve.add_argument("--image", required=True)
    approve.add_argument("--mode", required=True, choices=("test", "build-check"))
    approve.add_argument("--seconds", type=int, default=30)
    approve.add_argument("--ttl", type=int, default=60)
    approve.add_argument("--out", type=Path, required=True)
    args = cli.parse_args(argv)
    try:
        if args.action == "init-keys":
            create_keypair(args.private, args.public)
            print("Created a private signing key and a public verification key")
        elif args.action == "snapshot":
            result = create_snapshot(args.source, args.store)
            print(str(result))
        else:
            from .worker import plan
            manifest = args.snapshot_manifest.resolve(strict=True)
            snap_meta = verify_snapshot(manifest)
            workspace = Path(snap_meta["workspace"])
            job = plan(args.mode, workspace.parent, workspace, args.image, args.seconds)
            out = args.out.expanduser().resolve()
            private_path = args.private.expanduser().resolve(strict=True)
            if any(path == workspace or workspace in path.parents
                   for path in (out, private_path)):
                raise ApprovalError("signing keys and permits must stay outside snapshot workspace")
            permit = issue(job, manifest, _load(args.private, private=True), ttl=args.ttl)
            _write_new(args.out, canonical(permit) + b"\n", 0o600)
            print("Signed a task-scoped snapshot approval (single use)")
        return 0
    except (ApprovalError, SnapshotError, OSError, TypeError, ValueError) as exc:
        cli.exit(2, f"refused: {exc}\n")


if __name__ == "__main__":
    raise SystemExit(main())
