"""Optional, explicitly enabled local conversation memory.

This implementation is independently authored from the documented API requirements.
It does not import/copy Sovereign Intelligence Mesh source code.
"""
from __future__ import annotations

import re
import sqlite3
import threading
from datetime import datetime, timezone
from pathlib import Path
from uuid import uuid4


class HistoryError(Exception):
    def __init__(self, message: str, status: int):
        super().__init__(message)
        self.status = status


def _now() -> str:
    return datetime.now(timezone.utc).isoformat()


class HistoryStore:
    def __init__(self, db_path: str):
        Path(db_path).parent.mkdir(parents=True, exist_ok=True)
        self.conn = sqlite3.connect(db_path, timeout=5, check_same_thread=False)
        self.conn.row_factory = sqlite3.Row
        self.conn.execute('PRAGMA foreign_keys=ON')
        self.conn.execute('PRAGMA secure_delete=ON')
        self.lock = threading.RLock()
        with self.lock, self.conn:
            self.conn.executescript('''
                CREATE TABLE IF NOT EXISTS conversations (
                    id TEXT PRIMARY KEY, title TEXT NOT NULL,
                    created_at TEXT NOT NULL, updated_at TEXT NOT NULL
                );
                CREATE TABLE IF NOT EXISTS conversation_turns (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    conversation_id TEXT NOT NULL REFERENCES conversations(id) ON DELETE CASCADE,
                    request_id TEXT NOT NULL,
                    user_text TEXT NOT NULL,
                    assistant_text TEXT NOT NULL,
                    model TEXT NOT NULL,
                    elapsed_ms INTEGER NOT NULL,
                    prompt_tokens INTEGER,
                    completion_tokens INTEGER,
                    finish_reason TEXT NOT NULL,
                    context_trimmed INTEGER NOT NULL DEFAULT 0,
                    created_at TEXT NOT NULL,
                    UNIQUE(conversation_id, request_id)
                );
                CREATE INDEX IF NOT EXISTS conversation_turns_order
                    ON conversation_turns(conversation_id, id);
                CREATE VIRTUAL TABLE IF NOT EXISTS conversation_fts USING fts5(
                    user_text, assistant_text, content='conversation_turns', content_rowid='id'
                );
                CREATE TRIGGER IF NOT EXISTS conversation_fts_ai AFTER INSERT ON conversation_turns BEGIN
                    INSERT INTO conversation_fts(rowid,user_text,assistant_text)
                    VALUES(new.id,new.user_text,new.assistant_text);
                END;
                CREATE TRIGGER IF NOT EXISTS conversation_fts_ad AFTER DELETE ON conversation_turns BEGIN
                    INSERT INTO conversation_fts(conversation_fts,rowid,user_text,assistant_text)
                    VALUES('delete',old.id,old.user_text,old.assistant_text);
                END;
                CREATE TRIGGER IF NOT EXISTS conversation_fts_au AFTER UPDATE ON conversation_turns BEGIN
                    INSERT INTO conversation_fts(conversation_fts,rowid,user_text,assistant_text)
                    VALUES('delete',old.id,old.user_text,old.assistant_text);
                    INSERT INTO conversation_fts(rowid,user_text,assistant_text)
                    VALUES(new.id,new.user_text,new.assistant_text);
                END;
            ''')

    def close(self) -> None:
        with self.lock:
            self.conn.close()

    def _existing(self, conv_id: str) -> dict:
        row = self.conn.execute('SELECT * FROM conversations WHERE id=?', (conv_id,)).fetchone()
        if row is None:
            raise HistoryError('conversation not found', 404)
        return dict(row)

    @staticmethod
    def _turn(row: sqlite3.Row) -> dict:
        output = dict(row)
        output['context_trimmed'] = bool(output['context_trimmed'])
        return output

    def create(self) -> dict:
        timestamp = _now()
        value = {'id': str(uuid4()), 'title': 'New chat', 'created_at': timestamp, 'updated_at': timestamp}
        with self.lock, self.conn:
            self.conn.execute('INSERT INTO conversations(id,title,created_at,updated_at) VALUES (:id,:title,:created_at,:updated_at)', value)
        return value

    def list(self, offset: int = 0, limit: int = 40) -> list[dict]:
        with self.lock:
            return [dict(row) for row in self.conn.execute('SELECT * FROM conversations ORDER BY updated_at DESC, id LIMIT ? OFFSET ?', (limit, offset))]

    def page(self, conv_id: str, limit: int = 40, before: int | None = None, through: int | None = None) -> dict:
        if before is not None and through is not None:
            raise HistoryError('before and through cannot be combined', 400)
        with self.lock:
            conv = self._existing(conv_id)
            ceiling = (before - 1) if before is not None else (through if through is not None else 2**63-1)
            if through is not None and not self.conn.execute('SELECT 1 FROM conversation_turns WHERE id=? AND conversation_id=?', (through,conv_id)).fetchone():
                raise HistoryError('turn not found',404)
            rows = self.conn.execute('SELECT * FROM conversation_turns WHERE conversation_id=? AND id<=? ORDER BY id DESC LIMIT ?', (conv_id,ceiling,limit+1)).fetchall()
        shown = rows[:limit]
        return {'conversation': conv,'turns':[self._turn(row) for row in reversed(shown)],
                'older_before': shown[-1]['id'] if len(rows)>limit else None,
                'latest': before is None and through is None}

    def replay(self, conv_id: str, req_id: str, message: str) -> dict | None:
        with self.lock:
            self._existing(conv_id)
            row=self.conn.execute('SELECT * FROM conversation_turns WHERE conversation_id=? AND request_id=?',(conv_id,req_id)).fetchone()
        if row is None:
            return None
        if row['user_text'] != message:
            raise HistoryError('request ID was already used for another message',409)
        return self._turn(row)

    def save(self, conv_id: str, req_id: str, message: str, expected_last: int | None,
             answer: str, model: str, elapsed_ms: int, usage: dict, finish_reason: str, trimmed: bool) -> dict:
        with self.lock, self.conn:
            self.conn.execute('BEGIN IMMEDIATE')
            existing = self.replay(conv_id, req_id, message)
            if existing is not None:
                return existing
            last=self.conn.execute('SELECT MAX(id) FROM conversation_turns WHERE conversation_id=?',(conv_id,)).fetchone()[0]
            if last != expected_last:
                raise HistoryError('conversation changed during inference; retry with latest context',409)
            stamp = _now()
            cursor=self.conn.execute('''INSERT INTO conversation_turns
                (conversation_id,request_id,user_text,assistant_text,model,elapsed_ms,prompt_tokens,completion_tokens,finish_reason,context_trimmed,created_at)
                VALUES (?,?,?,?,?,?,?,?,?,?,?)''',
                (conv_id,req_id,message,answer,model,elapsed_ms,usage.get('prompt_tokens'),usage.get('completion_tokens'),finish_reason,int(trimmed),stamp))
            first= last is None
            title=' '.join(message.split())[:60] if first else None
            if first:
                self.conn.execute('UPDATE conversations SET title=?,updated_at=? WHERE id=?',(title,stamp,conv_id))
            else:
                self.conn.execute('UPDATE conversations SET updated_at=? WHERE id=?',(stamp,conv_id))
            row=self.conn.execute('SELECT * FROM conversation_turns WHERE id=?',(cursor.lastrowid,)).fetchone()
            return self._turn(row)

    def delete(self, conv_id: str) -> None:
        with self.lock, self.conn:
            result = self.conn.execute('DELETE FROM conversations WHERE id=?',(conv_id,))
            if result.rowcount != 1:
                raise HistoryError('conversation not found',404)

    def search(self, query: str, limit: int = 40) -> list[dict]:
        words = re.findall(r'[^\W_]+', query, flags=re.UNICODE)
        if not words:
            return []
        terms=' AND '.join('"'+word+'"' for word in words[:12])
        with self.lock:
            rows=self.conn.execute('''SELECT c.id AS conversation_id,c.title,t.id AS turn_id,t.created_at,
                      snippet(conversation_fts,-1,'','','…',24) AS excerpt
                    FROM conversation_fts JOIN conversation_turns t ON t.id=conversation_fts.rowid
                    JOIN conversations c ON c.id=t.conversation_id
                    WHERE conversation_fts MATCH ? ORDER BY rank,t.id DESC LIMIT ?''',(terms,limit)).fetchall()
            return [dict(row) for row in rows]
