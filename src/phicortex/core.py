"""Minimal CPU-first routing and metadata ledger. No model self-evaluation claims."""
from __future__ import annotations

import json
import os
import sqlite3
import threading
import time
import urllib.error
import urllib.request
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Callable


@dataclass(frozen=True)
class Config:
    chat_model: str = "qwen3:4b"
    code_model: str = "qwen3:4b"
    ollama_url: str = "http://127.0.0.1:11434/v1/chat/completions"
    db_path: str = "phicortex.sqlite3"
    store_transcripts: bool = False

    @classmethod
    def from_env(cls) -> "Config":
        return cls(
            chat_model=os.environ.get("PHICORTEX_CHAT_MODEL", "qwen3:4b"),
            code_model=os.environ.get("PHICORTEX_CODE_MODEL", "qwen3:4b"),
            ollama_url=os.environ.get("PHICORTEX_OLLAMA_URL", "http://127.0.0.1:11434/v1/chat/completions"),
            db_path=os.environ.get("PHICORTEX_DB", "phicortex.sqlite3"),
            store_transcripts=os.environ.get("PHICORTEX_STORE_TRANSCRIPTS", "0") == "1",
        )


class Ledger:
    """Locally persistent event history; no semantic search or memory inference yet."""

    def __init__(self, path: str):
        Path(path).parent.mkdir(parents=True, exist_ok=True)
        self.connection = sqlite3.connect(path, check_same_thread=False)
        self.lock = threading.Lock()
        with self.lock:
            self.connection.execute("CREATE TABLE IF NOT EXISTS events (id INTEGER PRIMARY KEY, at TEXT NOT NULL, kind TEXT NOT NULL, detail TEXT NOT NULL)")
            self.connection.commit()

    def record(self, kind: str, detail: dict) -> None:
        with self.lock:
            self.connection.execute("INSERT INTO events(at, kind, detail) VALUES (?, ?, ?)", (
                datetime.now(timezone.utc).isoformat(), kind, json.dumps(detail, sort_keys=True)
            ))
            self.connection.commit()

    def count(self) -> int:
        with self.lock:
            return int(self.connection.execute("SELECT COUNT(*) FROM events").fetchone()[0])

    def close(self) -> None:
        with self.lock:
            self.connection.close()


class RequestError(Exception):
    def __init__(self, message: str, status: int = 400):
        super().__init__(message)
        self.status = status


def route(messages: list, requested_model: str | None, config: Config) -> tuple[str, str]:
    if not isinstance(messages, list) or not messages:
        raise RequestError("messages must be a non-empty list")
    for item in messages:
        if not isinstance(item, dict) or item.get("role") not in {"system", "user", "assistant", "tool"}:
            raise RequestError("invalid chat message role")
        if not isinstance(item.get("content"), str):
            raise RequestError("phase 1 supports text-only messages")
    user_text = next((m["content"].strip() for m in reversed(messages) if m["role"] == "user"), "")
    if not user_text:
        raise RequestError("a user message is required")
    if user_text.lower().startswith(("/build", "/test", "/dream")):
        raise RequestError("BUILD, TEST, and DREAM are planned but not implemented", 501)
    allowed = {"phicortex-auto", config.chat_model, config.code_model}
    if requested_model is not None and requested_model not in allowed:
        raise RequestError("model is not registered", 400)
    if requested_model and requested_model != "phicortex-auto":
        return requested_model, "explicit-registered-model"
    code_hints = ("python", "javascript", "typescript", "debug", "fix the code", "stack trace", "unit test")
    if any(hint in user_text.lower() for hint in code_hints):
        return config.code_model, "deterministic-code-keyword"
    return config.chat_model, "default-chat"


def ollama_transport(config: Config, payload: dict) -> dict:
    from urllib.parse import urlparse
    parsed = urlparse(config.ollama_url)
    if parsed.scheme != "http" or parsed.hostname not in {"127.0.0.1", "localhost", "::1"}:
        raise RequestError("Ollama backend must use a loopback HTTP endpoint", 400)
    request = urllib.request.Request(config.ollama_url,
        data=json.dumps(payload).encode("utf-8"),
        headers={"Content-Type": "application/json"}, method="POST")
    try:
        with urllib.request.urlopen(request, timeout=90) as response:
            return json.load(response)
    except (urllib.error.URLError, TimeoutError, ValueError) as exc:
        raise RequestError(f"local inference unavailable: {exc}", 502) from exc


class Cortex:
    def __init__(self, config: Config, transport: Callable[[Config, dict], dict] = ollama_transport):
        self.config = config
        self.ledger = Ledger(config.db_path)
        self.transport = transport

    def chat(self, request: dict) -> dict:
        if not isinstance(request, dict):
            raise RequestError("request must be a JSON object")
        if request.get("stream", False):
            raise RequestError("streaming is not implemented in phase 1")
        messages = request.get("messages")
        model, reason = route(messages, request.get("model", "phicortex-auto"), self.config)
        start = time.perf_counter()
        payload = {"model": model, "messages": messages, "stream": False}
        if "temperature" in request:
            payload["temperature"] = request["temperature"]
        try:
            result = self.transport(self.config, payload)
        except RequestError as exc:
            self.ledger.record("inference_failed", {"model": model, "reason": reason, "status": exc.status})
            raise
        if not isinstance(result, dict) or not isinstance(result.get("choices"), list):
            raise RequestError("invalid response from inference backend", 502)
        entry = {"model": model, "route": reason, "latency_ms": round((time.perf_counter() - start) * 1000, 2),
                 "usage": result.get("usage") if isinstance(result.get("usage"), dict) else None}
        if self.config.store_transcripts:
            entry["messages"] = messages
            entry["response"] = result.get("choices")
        self.ledger.record("inference_completed", entry)
        return result
