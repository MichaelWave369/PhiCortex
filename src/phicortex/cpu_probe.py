"""Repeatable, locally managed CPU-first llama.cpp benchmark.

Starts an explicitly CPU-configured llama-server from an installed binary and
local GGUF model, runs a known-answer suite, writes a transparent JSON report,
then stops the child. No download, GPU verification claim, or router promotion.
"""
from __future__ import annotations

import argparse
from dataclasses import replace
from datetime import datetime, timezone
import hashlib
import json
import os
from pathlib import Path
import platform
import secrets
import socket
import subprocess
import sys
import time
from urllib.error import HTTPError, URLError

from .core import RequestError
from urllib.request import ProxyHandler, Request, build_opener

from .core import Config, Cortex
from .evaluate import run_suite, validated_cases

ALIAS = "phicortex-cpu-probe"
MAX_RESP_BYTES = 4 * 1024 * 1024


def sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        for chunk in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def validate_local_assets(server: Path, model: Path) -> None:
    if not server.is_file():
        raise ValueError(f"llama-server binary not found: {server}")
    if not model.is_file() or model.suffix.lower() != ".gguf":
        raise ValueError("model must be an existing local .gguf file")
    if model.stat().st_size < 16:
        raise ValueError("model file is unexpectedly small")


def cpu_command(server: Path, model: Path, port: int, threads: int, context: int,
                key: str, max_tokens: int) -> list[str]:
    if not (1025 <= port <= 65535):
        raise ValueError("port must be 1025 through 65535")
    if not (1 <= threads <= 256 and 256 <= context <= 262144 and 1 <= max_tokens <= context):
        raise ValueError("invalid threads, context, or max tokens")
    if not key:
        raise ValueError("private API key required")
    return [str(server), "--model", str(model), "--alias", ALIAS,
            "--host", "127.0.0.1", "--port", str(port),
            "--threads", str(threads), "--ctx-size", str(context),
            "--parallel", "1", "--n-predict", str(max_tokens),
            "--n-gpu-layers", "0", "--device", "none", "--offline",
            "--no-webui", "--api-key", key]


def clean_server_env() -> dict[str, str]:
    """Prevent LLAMA_ARG_* environment values from defeating explicit CLI flags."""
    env = {k: v for k, v in os.environ.items() if not k.upper().startswith("LLAMA_ARG_")}
    env["CUDA_VISIBLE_DEVICES"] = "-1"
    env["HIP_VISIBLE_DEVICES"] = "-1"
    env["ROCR_VISIBLE_DEVICES"] = "-1"
    return env


def is_port_in_use(port: int) -> bool:
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.settimeout(0.25)
        return s.connect_ex(("127.0.0.1", port)) == 0


def local_opener():
    return build_opener(ProxyHandler({}))


def wait_until_ready(opener, port: int, key: str, process, timeout: float,
                     *, clock=time.monotonic, sleep=time.sleep) -> float:
    start = clock()
    url = f"http://127.0.0.1:{port}/health"
    while clock() - start < timeout:
        if process.poll() is not None:
            raise RuntimeError(f"llama-server exited before ready (exit {process.returncode})")
        try:
            request = Request(url, headers={"Authorization": f"Bearer {key}"})
            with opener.open(request, timeout=2) as response:
                body = response.read(16384)
                if response.status == 200 and json.loads(body).get("status") == "ok":
                    return round((clock() - start) * 1000, 2)
        except (HTTPError, URLError, TimeoutError, ValueError, OSError):
            pass
        sleep(0.25)
    raise TimeoutError("local llama-server did not become ready before deadline")


def transport_for(opener, port: int, key: str, max_tokens: int):
    url = f"http://127.0.0.1:{port}/v1/chat/completions"

    def transport(_config: Config, payload: dict) -> dict:
        data = dict(payload, max_tokens=max_tokens, stream=False)
        request = Request(url, method="POST",
                          data=json.dumps(data).encode("utf-8"),
                          headers={"Authorization": f"Bearer {key}",
                                   "Content-Type": "application/json"})
        try:
            with opener.open(request, timeout=120) as response:
                raw = response.read(MAX_RESP_BYTES + 1)
            if len(raw) > MAX_RESP_BYTES:
                raise ValueError("model response exceeded bounded size")
            parsed = json.loads(raw)
            if not isinstance(parsed, dict):
                raise ValueError("model response is not an object")
            return parsed
        except (HTTPError, URLError, TimeoutError, OSError, ValueError) as exc:
            raise RequestError(f"local model request failed: {type(exc).__name__}", 502) from exc

    return transport


def stop_process(process) -> None:
    if process.poll() is not None:
        return
    process.terminate()
    try:
        process.wait(timeout=7)
    except subprocess.TimeoutExpired:
        process.kill()
        process.wait(timeout=5)


def report_summary(evaluation: dict) -> dict:
    candidate = evaluation["results"][0]
    valid_tokens = sum(case["usage"].get("completion_tokens", 0) for case in candidate["cases"])
    valid_times = sum(case["latency_ms"] for case in candidate["cases"]
                      if "completion_tokens" in case["usage"])
    return {
        "cases_total": candidate["total"],
        "cases_passed": candidate["passed"],
        "median_end_to_end_ms": candidate["median_latency_ms"],
        "reported_completion_tokens": valid_tokens,
        "approx_end_to_end_tokens_per_second": (
            round(valid_tokens * 1000 / valid_times, 3) if valid_times > 0 else None
        ),
        "tokens_per_second_note": "Includes prompt processing and HTTP overhead; not pure decode throughput",
    }


def run_probe(*, server: Path, model: Path, cases: list[dict], output: Path,
              port: int = 18943, threads: int = 4, context: int = 2048,
              max_tokens: int = 64, startup_timeout: float = 120,
              launch=subprocess.Popen, opener=None) -> dict:
    server, model, output = Path(server).resolve(), Path(model).resolve(), Path(output)
    validate_local_assets(server, model)
    validated_cases(cases)
    if startup_timeout <= 0 or startup_timeout > 1800:
        raise ValueError("startup timeout out of range")
    key = secrets.token_urlsafe(36)
    cmd = cpu_command(server, model, port, threads, context, key, max_tokens)
    if is_port_in_use(port):
        raise ValueError(f"loopback port {port} is already in use")
    opener = opener if opener is not None else local_opener()
    config = replace(Config.from_env(), chat_model=ALIAS, code_model=ALIAS,
                     reason_model=None, db_path=":memory:",
                     enable_history=False, store_transcripts=False,
                     ollama_url=f"http://127.0.0.1:{port}/v1/chat/completions")
    start = time.monotonic()
    # No shell, no network URL supplied for the model, no built-in downloader.
    process = launch(cmd, env=clean_server_env(), stdin=subprocess.DEVNULL,
                     stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, shell=False)
    try:
        ready_ms = wait_until_ready(opener, port, key, process, startup_timeout)
        cortex = Cortex(config, transport=transport_for(opener, port, key, max_tokens))
        try:
            evaluated = run_suite(cortex, cases, [ALIAS], dataset_kind="development")
        finally:
            cortex.close()
        report = {
            "schema": "phicortex.cpu-baseline.v1",
            "created_at": datetime.now(timezone.utc).isoformat(),
            "model": {"filename": model.name, "bytes": model.stat().st_size,
                      "sha256": sha256_file(model)},
            "runtime": {"filename": server.name, "sha256": sha256_file(server),
                        "startup_ms": ready_ms, "total_run_ms": round((time.monotonic()-start)*1000,2)},
            "platform": {"system": platform.system(), "machine": platform.machine(),
                         "python": platform.python_version(), "cpu_count": os.cpu_count()},
            "controls": {"loopback_only": True, "no_gpu_layers_configured": True,
                         "device_none_configured": True, "offline_flag_configured": True,
                         "gpu_activity_independently_verified": False,
                         "network_isolation_independently_verified": False,
                         "device_energy_usage_measured": False,
                         "router_policy_promoted": False,
                         "launch_args_without_secret": ["<REDACTED>" if x == key else x for x in cmd[1:]]},
            "summary": report_summary(evaluated),
            "evaluation": evaluated,
        }
        output.parent.mkdir(parents=True, exist_ok=True)
        output.write_text(json.dumps(report, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
        return report
    finally:
        stop_process(process)


def main(argv=None) -> int:
    parser = argparse.ArgumentParser(description="Run an installed local GGUF model with GPU offload disabled")
    parser.add_argument("--server", required=True, type=Path, help="local llama-server[.exe] path")
    parser.add_argument("--model", required=True, type=Path, help="local .gguf model path")
    parser.add_argument("--cases", default="benchmarks/cases.example.json", type=Path)
    parser.add_argument("--out", default="artifacts/cpu-baseline.json", type=Path)
    parser.add_argument("--port", default=18943, type=int)
    parser.add_argument("--threads", default=4, type=int)
    parser.add_argument("--context", default=2048, type=int)
    parser.add_argument("--max-tokens", default=64, type=int)
    parser.add_argument("--startup-timeout", default=120.0, type=float)
    args = parser.parse_args(argv)
    try:
        cases = json.loads(args.cases.read_text(encoding="utf-8"))
        report = run_probe(server=args.server, model=args.model, cases=cases,
                           output=args.out, port=args.port, threads=args.threads,
                           context=args.context, max_tokens=args.max_tokens,
                           startup_timeout=args.startup_timeout)
    except (OSError, ValueError, RuntimeError, TimeoutError) as exc:
        print(f"CPU benchmark failed: {type(exc).__name__}: {exc}", file=sys.stderr)
        return 2
    print(f"Saved CPU-configured baseline to {args.out}")
    print(f"Known-answer cases: {report['summary']['cases_passed']}/{report['summary']['cases_total']}")
    print("GPU inactivity and network isolation have NOT been independently verified.")
    return 0 if all(x["error_type"] is None for x in report["evaluation"]["results"][0]["cases"]) else 2


if __name__ == "__main__":
    raise SystemExit(main())
