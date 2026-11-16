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
from uuid import UUID
from .history import HistoryStore, HistoryError
from .colony import choose, classify, registry, RoutingError, POLICY_VERSION


@dataclass(frozen=True)
class Config:
    chat_model: str = "qwen3:4b"
    code_model: str = "qwen3:4b"
    reason_model: str | None = None
    ollama_url: str = "http://127.0.0.1:11434/v1/chat/completions"
    db_path: str = "phicortex.sqlite3"
    store_transcripts: bool = False
    enable_history: bool = False

    @classmethod
    def from_env(cls) -> "Config":
        return cls(
            chat_model=os.environ.get("PHICORTEX_CHAT_MODEL", "qwen3:4b"),
            code_model=os.environ.get("PHICORTEX_CODE_MODEL", "qwen3:4b"),
            reason_model=os.environ.get("PHICORTEX_REASON_MODEL") or None,
            ollama_url=os.environ.get("PHICORTEX_OLLAMA_URL", "http://127.0.0.1:11434/v1/chat/completions"),
            db_path=os.environ.get("PHICORTEX_DB", "phicortex.sqlite3"),
            store_transcripts=os.environ.get("PHICORTEX_STORE_TRANSCRIPTS", "0") == "1",
            enable_history=os.environ.get("PHICORTEX_ENABLE_HISTORY", "0") == "1",
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

    def metrics(self, limit: int = 2000) -> dict:
        """Observed request telemetry only; no fabricated quality ratings."""
        with self.lock:
            rows = self.connection.execute(
                "SELECT kind, detail FROM events ORDER BY id DESC LIMIT ?", (limit,)
            ).fetchall()
        per_model = {}
        per_route = {}
        for kind, raw in rows:
            if kind not in ("inference_completed", "inference_failed"):
                continue
            detail = json.loads(raw)
            reason = detail.get("route")
            if isinstance(reason, str):
                per_route[reason] = per_route.get(reason, 0) + 1
            model = detail.get("model")
            if not isinstance(model, str):
                continue
            metrics = per_model.setdefault(model, {
                "completed": 0, "failed": 0, "latency_samples": 0,
                "average_latency_ms": None, "reported_output_tokens": 0,
            })
            if kind == "inference_failed":
                metrics["failed"] += 1
                continue
            metrics["completed"] += 1
            latency = detail.get("latency_ms")
            if isinstance(latency, (int, float)) and not isinstance(latency, bool) and latency >= 0:
                previous = metrics["average_latency_ms"] or 0
                count = metrics["latency_samples"]
                metrics["average_latency_ms"] = round((previous * count + latency) / (count + 1), 3)
                metrics["latency_samples"] += 1
            usage = detail.get("usage")
            tokens = usage.get("completion_tokens") if isinstance(usage, dict) else None
            if type(tokens) is int and tokens >= 0:
                metrics["reported_output_tokens"] += tokens
        return {"window_events": len(rows), "models": per_model, "routes": per_route,
                "quality_scores": "not_measured", "cpu_only_verified": False}

    def close(self) -> None:
        with self.lock:
            self.connection.close()


class RequestError(Exception):
    def __init__(self, message: str, status: int = 400):
        super().__init__(message)
        self.status = status


def route(messages: list, requested_model: str | None, config: Config,
          *, mode: str | None = None) -> tuple[str, str]:
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
    try:
        decision = choose(messages, requested_model, config, mode=mode)
    except RoutingError as exc:
        raise RequestError(str(exc), 400) from exc
    return decision.model, decision.reason


def ollama_transport(config: Config, payload: dict) -> dict:
    # Phase 1 intentionally only permits a loopback Ollama endpoint.
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
        self.history = HistoryStore(config.db_path) if config.enable_history else None
        self._turn_lock = threading.Lock()

    def chat(self, request: dict) -> dict:
        if not isinstance(request, dict):
            raise RequestError("request must be a JSON object")
        if request.get("stream", False):
            raise RequestError("streaming is not implemented in phase 1")
        messages = request.get("messages")
        if "mode" in request and request["mode"] is None:
            raise RequestError("mode must be chat, dream, build or test")
        specified_mode = request.get("mode") if "mode" in request else None
        model, reason = route(messages, request.get("model", "phicortex-auto"),
                              self.config, mode=specified_mode)
        mode_label = specified_mode if specified_mode is not None else "chat"
        mode_source = "operator-request" if specified_mode is not None else "default"
        start = time.perf_counter()
        payload = {"model": model, "messages": messages, "stream": False}
        if "temperature" in request:
            payload["temperature"] = request["temperature"]
        try:
            result = self.transport(self.config, payload)
        except RequestError as exc:
            self.ledger.record("inference_failed", {"model": model, "reason": reason, "route": reason, "task_class": classify(messages), "mode": mode_label, "mode_source": mode_source, "execution_authorized": False, "policy_version": POLICY_VERSION, "status": exc.status})
            raise
        if not isinstance(result, dict) or not isinstance(result.get("choices"), list):
            raise RequestError("invalid response from inference backend", 502)
        entry = {"model": model, "task_class": classify(messages), "mode": mode_label, "mode_source": mode_source, "execution_authorized": False, "policy_version": POLICY_VERSION, "route": reason, "latency_ms": round((time.perf_counter() - start) * 1000, 2),
                 "usage": result.get("usage") if isinstance(result.get("usage"), dict) else None}
        if self.config.store_transcripts:
            entry["messages"] = messages
            entry["response"] = result.get("choices")
        self.ledger.record("inference_completed", entry)
        return result

    def _history(self) -> HistoryStore:
        if self.history is None:
            raise RequestError("conversation retention is disabled; set PHICORTEX_ENABLE_HISTORY=1", 501)
        return self.history

    def delete_conversation(self, conv_id: str) -> None:
        history = self._history()
        if not self._turn_lock.acquire(blocking=False):
            raise RequestError('cannot delete while a turn is generating', 409)
        try:
            try:
                history.delete(self._uuid(conv_id))
            except HistoryError as exc:
                raise RequestError(str(exc), exc.status) from exc
        finally:
            self._turn_lock.release()

    def close(self) -> None:
        if self.history is not None:
            self.history.close()
        self.ledger.close()

    @staticmethod
    def _uuid(value: str) -> str:
        try:
            return str(UUID(value))
        except (ValueError, AttributeError, TypeError) as exc:
            raise RequestError("invalid UUID", 400) from exc

    def complete_turn(self, conv_id: str, request: dict) -> dict:
        history = self._history()
        conv_id = self._uuid(conv_id)
        if not isinstance(request, dict) or not isinstance(request.get('message'), str):
            raise RequestError('message must be a string')
        message = request['message'].strip()
        if not message or len(message) > 8000 or '\x00' in message:
            raise RequestError('message must have 1-8000 characters and no NUL bytes')
        req_id = self._uuid(request.get('request_id'))
        try:
            existing = history.replay(conv_id, req_id, message)
            if existing is not None:
                return existing
        except HistoryError as exc:
            raise RequestError(str(exc), exc.status) from exc
        if not self._turn_lock.acquire(blocking=False):
            raise RequestError('another turn is generating; retry', 409)
        try:
            # Recheck replay after acquiring the generation lock.
            existing = history.replay(conv_id, req_id, message)
            if existing is not None:
                return existing
            page = history.page(conv_id, limit=13)
            turns = page['turns'][-12:]
            expected_last = page['turns'][-1]['id'] if page['turns'] else None
            trimmed = page['older_before'] is not None or len(page['turns']) > 12
            messages=[{'role':'system','content':'You are a helpful, truthful assistant. State uncertainty clearly.'}]
            for turn in turns:
                messages.extend([{'role':'user','content':turn['user_text']},
                                 {'role':'assistant','content':turn['assistant_text']}])
            messages.append({'role':'user','content':message})
            # Approximate character budget only. True token accounting is a later milestone.
            while sum(len(item['content']) for item in messages) > 6000 and len(messages) > 2:
                del messages[1:3]
                trimmed = True
            if sum(len(item['content']) for item in messages) > 6000:
                raise RequestError('message exceeds provisional context budget', 413)
            started=time.perf_counter()
            result=self.chat({'model':'phicortex-auto','messages':messages})
            try:
                choice=result['choices'][0]
                answer=choice['message']['content']
                finish_reason=choice.get('finish_reason','stop')
                if not isinstance(answer,str) or not answer.strip() or finish_reason not in ('stop','length'):
                    raise ValueError('model did not return a complete text reply')
                usage=result.get('usage') if isinstance(result.get('usage'),dict) else {}
                # Do not store malformed counts.
                usage={k:v for k,v in usage.items() if k in ('prompt_tokens','completion_tokens') and type(v) is int and v>=0}
            except (KeyError, IndexError, TypeError, ValueError) as exc:
                raise RequestError('invalid model reply; turn not saved',502) from exc
            try:
                return history.save(conv_id,req_id,message,expected_last,answer,result.get('model',self.config.chat_model),
                                    int((time.perf_counter()-started)*1000),usage,finish_reason,trimmed)
            except HistoryError as exc:
                raise RequestError(str(exc),exc.status) from exc
        except HistoryError as exc:
            raise RequestError(str(exc),exc.status) from exc
        finally:
            self._turn_lock.release()
