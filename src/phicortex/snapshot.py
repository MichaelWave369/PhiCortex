"""Operator-created workspace copies with content verification.

Snapshots are read-only by convention and Docker mount policy, not protected
against a privileged host writer or same-user chmod. Real host isolation and
TOCTOU containment must be validated independently.
"""
from __future__ import annotations

import json
import os
from pathlib import Path
import shutil
import stat
from uuid import uuid4

from .governor import workspace_digest

SCHEMA = "phicortex.snapshot.v1"


class SnapshotError(RuntimeError):
    pass


def _strict_path(path: Path) -> Path:
    if path.is_symlink():
        raise SnapshotError("symlinked root refused")
    try:
        actual = path.expanduser().resolve(strict=True)
    except OSError as exc:
        raise SnapshotError("path not found") from exc
    if not actual.is_dir():
        raise SnapshotError("expected a directory")
    return actual


def create_snapshot(source: Path, store: Path) -> Path:
    """Create an owner-controlled copy and a manifest; return manifest path."""
    source = _strict_path(source)
    store = store.expanduser().absolute()
    if store.is_symlink():
        raise SnapshotError("symlinked snapshot store refused")
    if source == store or source in store.parents:
        raise SnapshotError("snapshot store cannot be inside the source workspace")
    store.mkdir(mode=0o700, parents=True, exist_ok=True)
    store = store.resolve(strict=True)
    if source == store or source in store.parents:
        raise SnapshotError("snapshot store cannot be inside the source workspace")
    first = workspace_digest(source)
    parent = store / uuid4().hex
    parent.mkdir(mode=0o700)
    snapshot = parent / "tree"
    try:
        # Copy symlinks as symlinks, so the digest check refuses them instead
        # of following paths outside the approved tree.
        shutil.copytree(source, snapshot, symlinks=True)
        second = workspace_digest(source)
        copied = workspace_digest(snapshot)
        if first != second or first != copied:
            raise SnapshotError("workspace changed during snapshot creation")
        # Readability inside an unprivileged, read-only mounted container.
        # Host owner can chmod these back: this is not cryptographic immutability.
        for child in sorted(snapshot.rglob("*"), reverse=True):
            if child.is_dir():
                child.chmod(0o555)
            elif child.is_file():
                child.chmod(0o444)
        snapshot.chmod(0o555)
        document = {
            "schema": SCHEMA, "workspace": str(snapshot),
            "workspace_sha256": copied, "source": str(source)
        }
        manifest = parent / "manifest.json"
        with manifest.open("x", encoding="utf-8") as out:
            json.dump(document, out, sort_keys=True, separators=(",", ":"))
            out.write("\n")
        manifest.chmod(0o444)
        return manifest
    except BaseException:
        # Best effort cleanup of partial snapshots, including read-only files.
        shutil.rmtree(parent, ignore_errors=True)
        raise


def verify_snapshot(manifest: Path, expected_workspace: str | None = None) -> dict:
    """Validate path binding and the current content, not host-level immutability."""
    try:
        if manifest.is_symlink():
            raise SnapshotError("symlinked snapshot manifest refused")
        location = manifest.expanduser().resolve(strict=True)
        data = json.loads(location.read_text(encoding="utf-8"))
        if not isinstance(data, dict) or set(data) != {
                "schema", "workspace", "workspace_sha256", "source"}:
            raise SnapshotError("invalid snapshot manifest")
        tree = location.parent / "tree"
        if data["schema"] != SCHEMA or data["workspace"] != str(tree):
            raise SnapshotError("snapshot manifest points outside its tree")
        if expected_workspace is not None and data["workspace"] != expected_workspace:
            raise SnapshotError("snapshot is not approved for this workspace")
        if not isinstance(data["workspace_sha256"], str) or len(data["workspace_sha256"]) != 64:
            raise SnapshotError("invalid snapshot digest")
        current = workspace_digest(tree)
        if current != data["workspace_sha256"]:
            raise SnapshotError("snapshot content has changed")
        return data
    except (OSError, ValueError, TypeError, KeyError) as exc:
        raise SnapshotError("snapshot manifest or content invalid") from exc
