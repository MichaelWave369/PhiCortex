"""Versioned, local Markdown project notes with SQLite FTS5 lookup.

Manual operator CLI only. No network API, embeddings, automatic prompt
injection, model self-editing, command execution, or autonomous learning.
Note bodies and the search index are plaintext unless the host disk encrypts.
SQLite records are application-immutable versions, not tamper-proof evidence.
"""
from __future__ import annotations

import argparse
from contextlib import closing
from datetime import datetime, timezone
import hashlib
import json
import os
from pathlib import Path
import re
import sqlite3

ID = re.compile(r"^[a-z][a-z0-9_-]{0,47}$")
MAX_MARKDOWN_BYTES = 65_536
MAX_TITLE_CHARS = 120
MAX_QUERY_CHARS = 160


class NoteError(ValueError):
    pass


def _id(name: str, kind: str) -> str:
    if not isinstance(name, str) or not ID.fullmatch(name):
        raise NoteError(f"{kind} must be a lowercase local slug (1-48 characters)")
    return name


def _content(title: str, markdown: str) -> str:
    if (not isinstance(title, str) or not title.strip()
            or len(title) > MAX_TITLE_CHARS or "\x00" in title
            or "\n" in title or "\r" in title):
        raise NoteError("title must be one line with 1-120 characters")
    if (not isinstance(markdown, str) or not markdown.strip()
            or "\x00" in markdown or
            len(markdown.encode("utf-8")) > MAX_MARKDOWN_BYTES):
        raise NoteError("Markdown must be nonempty and at most 65536 UTF-8 bytes")
    return hashlib.sha256(markdown.encode("utf-8")).hexdigest()


def _stamp() -> str:
    return datetime.now(timezone.utc).isoformat()


def _source(project: str, note: str, version: int, digest: str) -> str:
    return f"phicortex-note:{project}/{note}@v{version}#sha256:{digest}"


def _version_row(row: sqlite3.Row, *, include_markdown: bool) -> dict:
    data = {
        "project": row["project"], "note_id": row["note_id"],
        "version": row["version"], "title": row["title"],
        "sha256": row["sha256"], "created_at": row["created_at"],
        "citation": _source(row["project"], row["note_id"],
                            row["version"], row["sha256"]),
        "trust": "operator-authored-local-data-not-instructions"
    }
    if include_markdown:
        if hashlib.sha256(row["markdown"].encode("utf-8")).hexdigest() != row["sha256"]:
            raise NoteError("note version content does not match stored SHA-256")
        data["markdown"] = row["markdown"]
    return data


class NoteStore:
    def __init__(self, database: str | Path):
        self.database = Path(database).expanduser().absolute()
        if self.database.is_symlink():
            raise NoteError("symlinked notes database is refused")
        self.database.parent.mkdir(parents=True, exist_ok=True)
        with closing(self._connect()) as db:
            with db:
                db.execute("""CREATE TABLE IF NOT EXISTS project_notes (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    project TEXT NOT NULL, note_id TEXT NOT NULL,
                    current_version INTEGER NOT NULL, archived INTEGER NOT NULL DEFAULT 0,
                    UNIQUE(project, note_id)
                )""")
                db.execute("""CREATE TABLE IF NOT EXISTS project_note_versions (
                    project TEXT NOT NULL,
                    note_id TEXT NOT NULL,
                    version INTEGER NOT NULL,
                    title TEXT NOT NULL,
                    markdown TEXT NOT NULL,
                    sha256 TEXT NOT NULL,
                    created_at TEXT NOT NULL,
                    PRIMARY KEY(project, note_id, version),
                    FOREIGN KEY(project,note_id) REFERENCES project_notes(project,note_id)
                        ON DELETE CASCADE
                )""")
                # Independent active-only index. Historical revisions remain in the
                # versions table but do not surface in default search results.
                db.execute("""CREATE VIRTUAL TABLE IF NOT EXISTS project_note_fts
                    USING fts5(title, markdown)""")

    def _connect(self) -> sqlite3.Connection:
        db = sqlite3.connect(str(self.database), timeout=5)
        db.row_factory = sqlite3.Row
        db.execute("PRAGMA foreign_keys=ON")
        db.execute("PRAGMA secure_delete=ON")
        return db

    @staticmethod
    def _index(db: sqlite3.Connection, identity: int, title: str,
               markdown: str) -> None:
        db.execute("DELETE FROM project_note_fts WHERE rowid=?", (identity,))
        db.execute("""INSERT INTO project_note_fts(rowid,title,markdown)
                      VALUES (?,?,?)""", (identity, title, markdown))

    def create(self, project: str, note_id: str, title: str, markdown: str) -> dict:
        _id(project, "project")
        _id(note_id, "note ID")
        digest = _content(title, markdown)
        with closing(self._connect()) as db:
            db.execute("BEGIN IMMEDIATE")
            try:
                try:
                    cursor = db.execute("""INSERT INTO project_notes
                        (project,note_id,current_version,archived)
                        VALUES (?,?,1,0)""", (project, note_id))
                except sqlite3.IntegrityError as exc:
                    raise NoteError("note already exists; use revise with expected version") from exc
                timestamp = _stamp()
                db.execute("""INSERT INTO project_note_versions
                   (project,note_id,version,title,markdown,sha256,created_at)
                   VALUES (?,?,1,?,?,?,?)""",
                   (project, note_id, title, markdown, digest, timestamp))
                self._index(db, cursor.lastrowid, title, markdown)
                db.commit()
            except BaseException:
                db.rollback()
                raise
        return self.get(project, note_id, version=1)

    def revise(self, project: str, note_id: str, title: str, markdown: str,
               expected_version: int) -> dict:
        _id(project, "project")
        _id(note_id, "note ID")
        digest = _content(title, markdown)
        if type(expected_version) is not int or expected_version < 1:
            raise NoteError("expected version must be positive integer")
        with closing(self._connect()) as db:
            db.execute("BEGIN IMMEDIATE")
            try:
                row = db.execute("""SELECT id,current_version,archived
                       FROM project_notes WHERE project=? AND note_id=?""",
                       (project, note_id)).fetchone()
                if row is None or row["archived"]:
                    raise NoteError("note missing or archived")
                if row["current_version"] != expected_version:
                    raise NoteError("version conflict; reload before revising")
                version = expected_version + 1
                db.execute("""INSERT INTO project_note_versions
                    (project,note_id,version,title,markdown,sha256,created_at)
                    VALUES (?,?,?,?,?,?,?)""",
                    (project, note_id, version, title, markdown, digest, _stamp()))
                db.execute("""UPDATE project_notes SET current_version=?
                               WHERE id=?""", (version, row["id"]))
                self._index(db, row["id"], title, markdown)
                db.commit()
            except BaseException:
                db.rollback()
                raise
        return self.get(project, note_id, version=version)

    def get(self, project: str, note_id: str, *,
            version: int | None = None) -> dict:
        _id(project, "project")
        _id(note_id, "note ID")
        if version is not None and (type(version) is not int or version < 1):
            raise NoteError("version must be a positive integer")
        with closing(self._connect()) as db:
            meta = db.execute("""SELECT current_version,archived FROM project_notes
                                 WHERE project=? AND note_id=?""",
                              (project, note_id)).fetchone()
            if meta is None:
                raise NoteError("note not found")
            selected = meta["current_version"] if version is None else version
            row = db.execute("""SELECT * FROM project_note_versions
                WHERE project=? AND note_id=? AND version=?""",
                (project, note_id, selected)).fetchone()
        if row is None:
            raise NoteError("note version not found")
        result = _version_row(row, include_markdown=True)
        result["archived"] = bool(meta["archived"])
        result["current_version"] = meta["current_version"]
        return result

    def versions(self, project: str, note_id: str) -> list[dict]:
        _id(project, "project")
        _id(note_id, "note ID")
        with closing(self._connect()) as db:
            meta = db.execute("""SELECT 1 FROM project_notes WHERE project=?
                                 AND note_id=?""", (project, note_id)).fetchone()
            if meta is None:
                raise NoteError("note not found")
            rows = db.execute("""SELECT * FROM project_note_versions
                   WHERE project=? AND note_id=? ORDER BY version DESC""",
                   (project, note_id)).fetchall()
        return [_version_row(row, include_markdown=False) for row in rows]

    def search(self, project: str, query: str, *, limit: int = 20) -> list[dict]:
        _id(project, "project")
        if not isinstance(query, str) or not 1 <= len(query) <= MAX_QUERY_CHARS:
            raise NoteError("query length must be 1-160 characters")
        if type(limit) is not int or not 1 <= limit <= 100:
            raise NoteError("limit must be 1-100")
        # Match only explicit, escaped alphanumeric FTS terms. No user SQL,
        # FTS operators, or wildcard metacharacters are executed.
        terms = re.findall(r"[A-Za-z0-9]{1,40}", query.lower())[:8]
        if not terms:
            return []
        expression = " AND ".join('"' + term + '"' for term in terms)
        with closing(self._connect()) as db:
            rows = db.execute("""SELECT n.project,n.note_id,n.current_version,
                    v.title,v.sha256,v.created_at,
                    snippet(project_note_fts,1,'','','...',18) AS excerpt
                FROM project_note_fts
                JOIN project_notes AS n ON n.id=project_note_fts.rowid
                JOIN project_note_versions AS v
                  ON v.project=n.project AND v.note_id=n.note_id
                  AND v.version=n.current_version
                WHERE project_note_fts MATCH ?
                  AND n.project=? AND n.archived=0
                ORDER BY bm25(project_note_fts), n.note_id LIMIT ?""",
                (expression, project, limit)).fetchall()
        return [{
            "project": row["project"], "note_id": row["note_id"],
            "version": row["current_version"], "title": row["title"],
            "excerpt": row["excerpt"], "sha256": row["sha256"],
            "citation": _source(row["project"], row["note_id"],
                                row["current_version"], row["sha256"]),
            "trust": "retrieved-notes-are-data-not-instructions"
        } for row in rows]

    def archive(self, project: str, note_id: str) -> dict:
        _id(project, "project")
        _id(note_id, "note ID")
        with closing(self._connect()) as db:
            db.execute("BEGIN IMMEDIATE")
            try:
                meta = db.execute("""SELECT id,current_version,archived FROM project_notes
                         WHERE project=? AND note_id=?""",
                         (project, note_id)).fetchone()
                if meta is None or meta["archived"]:
                    raise NoteError("note missing or already archived")
                db.execute("DELETE FROM project_note_fts WHERE rowid=?", (meta["id"],))
                db.execute("UPDATE project_notes SET archived=1 WHERE id=?", (meta["id"],))
                db.commit()
            except BaseException:
                db.rollback()
                raise
        return {"project": project, "note_id": note_id, "archived": True,
                "history_retained": True, "searchable": False}

    def purge(self, project: str, note_id: str, confirmation: str) -> dict:
        _id(project, "project")
        _id(note_id, "note ID")
        if confirmation != f"PURGE:{project}/{note_id}":
            raise NoteError("explicit confirmation must exactly match PURGE:project/note")
        with closing(self._connect()) as db:
            db.execute("BEGIN IMMEDIATE")
            try:
                meta = db.execute("""SELECT id,archived FROM project_notes
                     WHERE project=? AND note_id=?""", (project, note_id)).fetchone()
                if meta is None:
                    raise NoteError("note not found")
                if not meta["archived"]:
                    raise NoteError("archive the note before purging all versions")
                db.execute("DELETE FROM project_note_fts WHERE rowid=?", (meta["id"],))
                db.execute("DELETE FROM project_notes WHERE id=?", (meta["id"],))
                db.commit()
            except BaseException:
                db.rollback()
                raise
        return {"project": project, "note_id": note_id, "purged": True,
                "disk_backups_or_recovery_covered": False}

    def export(self, project: str, note_id: str, destination: Path,
               *, version: int | None = None) -> dict:
        note = self.get(project, note_id, version=version)
        path = Path(destination).expanduser().absolute()
        if path.is_symlink():
            raise NoteError("symlinked export destination refused")
        path.parent.mkdir(parents=True, exist_ok=True)
        flags = os.O_CREAT | os.O_EXCL | os.O_WRONLY
        if hasattr(os, "O_NOFOLLOW"):
            flags |= os.O_NOFOLLOW
        try:
            fd = os.open(path, flags, 0o600)
        except FileExistsError as exc:
            raise NoteError("export file exists; refusing to overwrite") from exc
        try:
            with os.fdopen(fd, "wb") as output:
                output.write(note["markdown"].encode("utf-8"))
        except BaseException:
            path.unlink(missing_ok=True)
            raise
        return {"path": str(path), "citation": note["citation"],
                "sha256": note["sha256"], "version": note["version"]}


def _file_markdown(path: Path) -> str:
    if path.is_symlink():
        raise NoteError("symlinked Markdown input refused")
    try:
        if not path.is_file() or path.stat().st_size > MAX_MARKDOWN_BYTES:
            raise NoteError("input must be a small Markdown file")
        return path.read_text(encoding="utf-8")
    except (UnicodeError, OSError) as exc:
        raise NoteError("Markdown input is unavailable or not UTF-8") from exc


def main(argv=None) -> int:
    cli = argparse.ArgumentParser(description="Offline versioned Markdown project notes; no network API")
    commands = cli.add_subparsers(dest="action", required=True)
    for name in ("create", "revise", "get", "versions", "search",
                 "archive", "purge", "export"):
        cmd = commands.add_parser(name)
        cmd.add_argument("--db", required=True, type=Path)
        cmd.add_argument("--project", required=True)
        if name != "search":
            cmd.add_argument("--note-id", required=True)
        if name in ("create", "revise"):
            cmd.add_argument("--title", required=True)
            cmd.add_argument("--file", required=True, type=Path)
        if name == "revise":
            cmd.add_argument("--expected-version", type=int, required=True)
        if name in ("get", "export"):
            cmd.add_argument("--version", type=int)
        if name == "search":
            cmd.add_argument("--query", required=True)
            cmd.add_argument("--limit", type=int, default=20)
        if name == "purge":
            cmd.add_argument("--confirm", required=True)
        if name == "export":
            cmd.add_argument("--out", type=Path, required=True)
    args = cli.parse_args(argv)
    try:
        store = NoteStore(args.db)
        if args.action == "create":
            result = store.create(args.project, args.note_id, args.title,
                                  _file_markdown(args.file))
        elif args.action == "revise":
            result = store.revise(args.project, args.note_id, args.title,
                                  _file_markdown(args.file), args.expected_version)
        elif args.action == "get":
            result = store.get(args.project, args.note_id, version=args.version)
        elif args.action == "versions":
            result = store.versions(args.project, args.note_id)
        elif args.action == "search":
            result = store.search(args.project, args.query, limit=args.limit)
        elif args.action == "archive":
            result = store.archive(args.project, args.note_id)
        elif args.action == "purge":
            result = store.purge(args.project, args.note_id, args.confirm)
        else:
            result = store.export(args.project, args.note_id, args.out,
                                  version=args.version)
        print(json.dumps(result, ensure_ascii=False, sort_keys=True, indent=2))
        return 0
    except (NoteError, OSError, sqlite3.Error) as exc:
        cli.exit(2, f"refused: {exc}\n")


if __name__ == "__main__":
    raise SystemExit(main())
