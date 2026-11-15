"""Local evaluation CLI with deterministic known-answer checks.

This never self-grades an LLM, changes production routing, or claims CPU-only
verification. The sample suite is public smoke data, NOT a held-out benchmark.
"""
from __future__ import annotations

import argparse
from datetime import datetime, timezone
import hashlib
import json
from pathlib import Path
import statistics
import time

from .colony import registry
from .core import Config, Cortex, RequestError


def validated_cases(cases: object) -> list[dict]:
    if not isinstance(cases, list) or not 1 <= len(cases) <= 200:
        raise ValueError("cases must be a list with 1 to 200 cases")
    seen = set()
    for item in cases:
        if not isinstance(item, dict) or not isinstance(item.get("id"), str):
            raise ValueError("every case needs a string id")
        name = item["id"]
        if not (1 <= len(name) <= 80) or name in seen:
            raise ValueError("duplicate or invalid case id")
        seen.add(name)
        if not isinstance(item.get("prompt"), str) or not 1 <= len(item["prompt"]) <= 8000:
            raise ValueError(f"case {name}: invalid prompt")
        if not isinstance(item.get("expected"), str) or not item["expected"].strip():
            raise ValueError(f"case {name}: nonempty expected answer required")
        if item.get("match", "exact") not in ("exact", "contains"):
            raise ValueError(f"case {name}: invalid match type")
    return cases


def matches(actual: str, expected: str, method: str) -> bool:
    answer = " ".join(actual.strip().split()).casefold()
    target = " ".join(expected.strip().split()).casefold()
    return answer == target if method == "exact" else target in answer


def run_suite(cortex: Cortex, cases: list[dict], model_names: list[str],
              *, dataset_kind: str = "development") -> dict:
    validated_cases(cases)
    if dataset_kind not in ("development", "held-out"):
        raise ValueError("dataset_kind must be development or held-out")
    available = set(registry(cortex.config).values())
    if not model_names or any(not isinstance(m, str) or m not in available for m in model_names):
        raise ValueError("evaluation models must be explicitly registered")
    if len(model_names) != len(set(model_names)):
        raise ValueError("duplicate evaluation models")
    digest = hashlib.sha256(json.dumps(cases, ensure_ascii=False, sort_keys=True,
                                       separators=(",", ":")).encode("utf-8")).hexdigest()
    results = []
    for model in model_names:
        records = []
        for case in cases:
            started = time.perf_counter()
            usage = {}
            passed = False
            failure = None
            try:
                response = cortex.chat({"model": model, "messages": [
                    {"role": "user", "content": case["prompt"]}],
                    "temperature": 0})
                answer = response["choices"][0]["message"]["content"]
                if not isinstance(answer, str):
                    raise ValueError("non-text reply")
                passed = matches(answer, case["expected"], case.get("match", "exact"))
                raw_usage = response.get("usage")
                if isinstance(raw_usage, dict):
                    usage = {key: val for key, val in raw_usage.items()
                             if key in ("prompt_tokens", "completion_tokens", "total_tokens")
                             and type(val) is int and val >= 0}
            except (RequestError, KeyError, IndexError, TypeError, ValueError) as exc:
                failure = type(exc).__name__
            records.append({"id": case["id"], "passed": passed,
                            "latency_ms": round((time.perf_counter() - started) * 1000, 3),
                            "usage": usage, "error_type": failure})
        successes = sum(int(x["passed"]) for x in records)
        results.append({"model": model, "passed": successes, "total": len(records),
                        "pass_rate": round(successes / len(records), 4),
                        "median_latency_ms": round(statistics.median(x["latency_ms"] for x in records), 3),
                        "cases": records})
    return {
        "schema": "phicortex.eval.v1",
        "kind": "deterministic-known-answer-evaluation",
        "dataset_kind": dataset_kind,
        "dataset_sha256": digest,
        "created_at": datetime.now(timezone.utc).isoformat(),
        "cpu_only_verified": False,
        "no_routing_or_weight_changes_applied": True,
        "notes": "Only known-answer matching is graded. No external judge or self-confidence score.",
        "results": results,
    }


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="PhiCortex local registered-model comparison")
    parser.add_argument("--cases", required=True, help="JSON array of known-answer cases")
    parser.add_argument("--models", nargs="*", help="registered model names; default: all distinct roles")
    parser.add_argument("--out", help="optional local JSON report path")
    parser.add_argument("--kind", choices=("development", "held-out"), default="development")
    args = parser.parse_args(argv)
    config = Config.from_env()
    cases = json.loads(Path(args.cases).read_text(encoding="utf-8"))
    models = args.models or sorted(set(registry(config).values()))
    cortex = Cortex(config)
    try:
        report = run_suite(cortex, cases, models, dataset_kind=args.kind)
    finally:
        cortex.close()
    output = json.dumps(report, indent=2, ensure_ascii=False) + "\n"
    if args.out:
        path = Path(args.out)
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(output, encoding="utf-8")
        print(f"Report written to {path}")
    else:
        print(output)
    # A transport error makes an evaluation incomplete even if the code ran.
    return 2 if any(case["error_type"] for r in report["results"] for case in r["cases"]) else 0


if __name__ == "__main__":
    raise SystemExit(main())
