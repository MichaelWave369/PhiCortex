"""Small deterministic model registry and routing decisions.

These are *logical roles*, not separately resident AI processes. No claim of
per-token mixture-of-experts routing or measured model quality is made here.
"""
from __future__ import annotations

from dataclasses import dataclass
import re


MODEL_NAME = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._:/-]{0,127}$")
POLICY_VERSION = "deterministic-v2"
CODE_HINTS = ("python", "javascript", "typescript", "debug", "fix the code",
              "stack trace", "unit test", "write code", "implement function")
REASON_HINTS = ("architecture tradeoff", "compare architectures", "deep reasoning",
                "analyze alternatives", "evaluate tradeoffs", "design a system")


class RoutingError(ValueError):
    pass


@dataclass(frozen=True)
class Decision:
    model: str
    role: str
    task_class: str
    reason: str
    policy_version: str = POLICY_VERSION


def registry(config) -> dict[str, str]:
    """Return configured roles. Unconfigured specialists are not invented."""
    profiles = {"chat": config.chat_model, "code": config.code_model}
    reason_model = getattr(config, "reason_model", None)
    if reason_model:
        profiles["reason"] = reason_model
    for role, name in profiles.items():
        if not isinstance(name, str) or (not MODEL_NAME.fullmatch(name) or "://" in name):
            raise RoutingError(f"invalid configured model name for {role}")
        if name == "phicortex-auto":
            raise RoutingError("phicortex-auto is reserved for the router")
    return profiles


def classify(messages: list) -> str:
    last = next((m["content"].strip() for m in reversed(messages) if m["role"] == "user"), "")
    lower = last.lower()
    if any(h in lower for h in CODE_HINTS):
        return "code"
    if any(h in lower for h in REASON_HINTS):
        return "reason"
    return "chat"


def choose(messages: list, requested_model: str | None, config) -> Decision:
    profiles = registry(config)
    task_class = classify(messages)
    chosen = "phicortex-auto" if requested_model is None else requested_model
    if not isinstance(chosen, str) or chosen not in {"phicortex-auto", *profiles.values()}:
        raise RoutingError("model is not registered")
    if chosen != "phicortex-auto":
        role = next(role for role, model in profiles.items() if model == chosen)
        return Decision(chosen, role, task_class, "explicit-registered-model")
    if task_class == "code":
        return Decision(profiles["code"], "code", task_class, "deterministic-code-keyword")
    if task_class == "reason":
        if "reason" in profiles:
            return Decision(profiles["reason"], "reason", task_class, "deterministic-reason-keyword")
        return Decision(profiles["chat"], "chat", task_class, "reason-role-unconfigured-chat-fallback")
    return Decision(profiles["chat"], "chat", task_class, "default-chat")


def overview(config) -> dict:
    profiles = registry(config)
    return {
        "policy_version": POLICY_VERSION,
        "roles": [{"role": role, "model": model, "quality_evaluated": False}
                  for role, model in sorted(profiles.items())],
        "available_model_names": sorted(set(profiles.values())),
        "backend_readiness": "not_probed",
        "cpu_only_verified": False,
        "adaptive_policy": "not_implemented",
    }
