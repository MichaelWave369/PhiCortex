"""Small deterministic model registry and routing decisions.

These are *logical roles*, not separately resident AI processes. No claim of
per-token mixture-of-experts routing or measured model quality is made here.
"""
from __future__ import annotations

from dataclasses import dataclass
import re


MODEL_NAME = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._:/-]{0,127}$")
POLICY_VERSION = "deterministic-v3-mode-advisory"
MODES = ("chat", "dream", "build", "test")
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
    mode: str = "chat"
    mode_source: str = "default"
    execution_authorized: bool = False


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


def validate_mode(mode: str | None) -> str:
    """Only an explicit, allowlisted request mode may override legacy routing.

    These modes govern *advisory inference selection only*: no chat request
    can launch a worker, consume a Governor permit or change deployment policy.
    """
    if mode is None:
        return "chat"
    if not isinstance(mode, str) or mode not in MODES:
        raise RoutingError("mode must be chat, dream, build or test")
    return mode


def choose(messages: list, requested_model: str | None, config,
           *, mode: str | None = None) -> Decision:
    profiles = registry(config)
    selected_mode = validate_mode(mode)
    source = "operator-request" if mode is not None else "default"
    task_class = classify(messages)
    chosen = "phicortex-auto" if requested_model is None else requested_model
    if not isinstance(chosen, str) or chosen not in {"phicortex-auto", *profiles.values()}:
        raise RoutingError("model is not registered")
    def decision(model: str, role: str, reason: str) -> Decision:
        return Decision(model, role, task_class, reason,
                        mode=selected_mode, mode_source=source)
    if chosen != "phicortex-auto":
        role = next(role for role, model in profiles.items() if model == chosen)
        return decision(chosen, role, "explicit-registered-model")
    if mode is not None:
        if selected_mode in ("build", "test"):
            return decision(profiles["code"], "code",
                            "operator-" + selected_mode + "-advisory-code")
        if selected_mode == "dream":
            if "reason" in profiles:
                return decision(profiles["reason"], "reason",
                                "operator-dream-advisory-reason")
            return decision(profiles["chat"], "chat",
                            "operator-dream-reason-unconfigured-chat-fallback")
        return decision(profiles["chat"], "chat", "operator-chat")
    if task_class == "code":
        return decision(profiles["code"], "code", "deterministic-code-keyword")
    if task_class == "reason":
        if "reason" in profiles:
            return decision(profiles["reason"], "reason", "deterministic-reason-keyword")
        return decision(profiles["chat"], "chat", "reason-role-unconfigured-chat-fallback")
    return decision(profiles["chat"], "chat", "default-chat")


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
        "request_modes": list(MODES),
        "mode_authority": "advisory_inference_only",
        "persistent_mode_state_machine": "not_implemented",
    }
