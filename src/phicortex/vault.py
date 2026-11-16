"""Content-addressed evidence vault for worker reports and explicit selected files.

Operator-owned, local-only. Storage integrity is checked by SHA-256, but this
is NOT an authenticated immutable ledger or a trusted remote artifact service.
"""
from __future__ import annotations

from datetime import datetime, timezone
import hashlib
import json
import os
from pathlib import Path, PurePosixPath
import stat
from uuid import uuid4

MAX_BLOB_BYTES = 2 * 1024 * 1024
MAX_ITEMS = 25
SCHEMA = "phicortex.artifacts.v0"


class VaultError(RuntimeError):
    pass


def _canonical(data: object) -> bytes:
    return json.dumps(data, sort_keys=True, ensure_ascii=False,
                      separators=(",", ":"), allow_nan=False).encode("utf-8")


def _safe_store(path: Path, data: bytes) -> None:
    """Create a new file exclusively. A truncated write fails verification."""
    if path.is_symlink():
        raise VaultError("symlinked vault entry refused")
    try:
        fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    except FileExistsError as exc:
        raise VaultError("vault entry already exists") from exc
    try:
        with os.fdopen(fd, "wb") as f:
            f.write(data)
            f.flush()
            os.fsync(f.fileno())
    except BaseException:
        path.unlink(missing_ok=True)
        raise


class Vault:
    def __init__(self, path: Path):
        path = path.expanduser().absolute()
        if path.is_symlink():
            raise VaultError("symlinked vault root refused")
        path.mkdir(parents=True, exist_ok=True, mode=0o700)
        self.root = path.resolve(strict=True)
        self.blobs = self.root / "blobs"
        self.manifests = self.root / "manifests"
        for folder in (self.blobs, self.manifests):
            if folder.is_symlink():
                raise VaultError("symlinked vault folder refused")
            folder.mkdir(mode=0o700, exist_ok=True)

    def put(self, data: bytes) -> dict:
        if not isinstance(data, bytes) or len(data) > MAX_BLOB_BYTES:
            raise VaultError("artifact exceeds 2 MiB limit")
        digest = hashlib.sha256(data).hexdigest()
        dest = self.blobs / digest
        try:
            _safe_store(dest, data)
        except VaultError:
            if not dest.is_file() or dest.is_symlink() or dest.read_bytes() != data:
                raise VaultError("existing content-addressed blob is corrupt")
        return {"sha256": digest, "size": len(data)}

    def _allowed_file(self, workspace: Path, item: str) -> Path:
        if not isinstance(item, str) or not item or "\\" in item or "\x00" in item:
            raise VaultError("invalid artifact path")
        rel = PurePosixPath(item)
        if rel.is_absolute() or any(segment in ("..", ".") for segment in rel.parts):
            raise VaultError("artifact traversal refused")
        target = workspace / item
        if target.is_symlink() or any(parent.is_symlink()
                for parent in target.parents if parent != workspace and workspace in parent.parents):
            raise VaultError("symlinked source path refused")
        try:
            resolved = target.resolve(strict=True)
            resolved.relative_to(workspace)
            meta = resolved.stat()
        except (ValueError, OSError) as exc:
            raise VaultError("artifact escapes the approved workspace") from exc
        if not stat.S_ISREG(meta.st_mode) or meta.st_size > MAX_BLOB_BYTES:
            raise VaultError("artifact must be a regular file <=2 MiB")
        return resolved

    def archive(self, report: dict, *, workspace: Path | None = None,
                include: list[str] | None = None) -> Path:
        if not isinstance(report, dict):
            raise VaultError("report must be a JSON object")
        include = [] if include is None else include
        if not isinstance(include, list) or len(include) > MAX_ITEMS:
            raise VaultError("at most 25 explicit files may be archived")
        report_bytes = _canonical(report)
        report_ref = self.put(report_bytes)
        files = [{"name": "worker-report.json", **report_ref}]
        if include:
            if workspace is None:
                raise VaultError("workspace required for selected artifact files")
            workspace = workspace.expanduser().resolve(strict=True)
            if not workspace.is_dir():
                raise VaultError("workspace missing")
            for relative in include:
                file = self._allowed_file(workspace, relative)
                info = self.put(file.read_bytes())
                files.append({"name": relative, **info})
        manifest = {"schema": SCHEMA, "id": str(uuid4()),
                    "created_at": datetime.now(timezone.utc).isoformat(),
                    "evidence_status": report.get("status", "unknown"),
                    "entries": files, "integrity": "sha256-not-signature"}
        manifest_file = self.manifests / (manifest["id"] + ".json")
        _safe_store(manifest_file, _canonical(manifest) + b"\n")
        return manifest_file

    def verify(self, manifest_file: Path) -> bool:
        manifest_file = manifest_file.expanduser().absolute()
        if (manifest_file.is_symlink() or manifest_file.parent.resolve() != self.manifests
                or manifest_file.suffix != ".json"):
            raise VaultError("invalid manifest path")
        try:
            manifest = json.loads(manifest_file.read_text(encoding="utf-8"))
        except (ValueError, OSError) as exc:
            raise VaultError("manifest missing or malformed") from exc
        if manifest.get("schema") != SCHEMA or not isinstance(manifest.get("entries"), list):
            raise VaultError("invalid manifest schema")
        for entry in manifest["entries"]:
            digest, size = entry.get("sha256"), entry.get("size")
            if (not isinstance(digest, str) or len(digest) != 64
                    or any(ch not in "0123456789abcdef" for ch in digest)
                    or type(size) is not int or not 0 <= size <= MAX_BLOB_BYTES):
                raise VaultError("invalid artifact descriptor")
            path = self.blobs / digest
            if not path.is_file() or path.is_symlink():
                raise VaultError("evidence blob missing or replaced")
            content = path.read_bytes()
            if len(content) != size or hashlib.sha256(content).hexdigest() != digest:
                raise VaultError("evidence blob failed verification")
        return True
