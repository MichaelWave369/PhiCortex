# Measured Brain Colony, v1

The colony now supports configurable **logical** chat, code, and optional reasoning roles.
It still invokes a separately running loopback Ollama-compatible inference endpoint.
These roles are not a new Mixture-of-Experts neural architecture and do not imply
simultaneous resident models or autonomous model training.

## Configuration

- `PHICORTEX_CHAT_MODEL` sets the chat role (default `qwen3:4b`).
- `PHICORTEX_CODE_MODEL` sets the code role (default `qwen3:4b`).
- `PHICORTEX_REASON_MODEL` optionally adds a dedicated reasoning role.
- All models must be available on the **local** inference server. Unknown requested models
  fail closed rather than contacting a remote provider.
- `GET /v1/colony` reports configured roles and explicitly marks model-quality
  and hardware verification as **not evaluated**.
- `GET /v1/telemetry` reports aggregated per-model event observations, not quality.

## Evaluate on actual local models

Set `PYTHONPATH=src` and start the **local** Ollama-compatible server separately.
Run:

~~~bash
python -m phicortex.evaluate --cases benchmarks/cases.example.json --out benchmarks/local-report.json
~~~

The demonstration cases are public and trivial; they are **not held-out** and
must never be used to claim a benchmarked intelligence improvement. Use a private,
independently authored suite with 30+ tasks covering your own chat, coding, grounded
answers and tool-use requirements. Compare models on identical prompts and hardware,
record model revisions, warm/cold timings, context limits and quantization separately.

The evaluator logs deterministic exact/contains checks for known-answer examples, local
latency and backend token usage when provided. Reports omit full prompts and answers;
the report contains case IDs, outcomes and measurements. A failure is recorded as a
failure. No score, self-claimed confidence, or evaluation run automatically changes
routing weights, permissions, model weights, or production configuration.

## Current routing

- Explicit registered model wins.
- Code keywords use the code role.
- Selected architecture/tradeoff phrases use the optional reasoning role.
- Unconfigured reasoning role falls back to chat.
- Everything else defaults to chat.

`deterministic-v2` is explainable, cheap, and intentionally unsophisticated.
It is a baseline for future **independent** held-out comparisons and adaptive policies.
High-stakes or tool use is not auto-authorized.

## Not yet verified

CPU-only execution, RAM/energy benchmarking on the operator's hardware, router accuracy
on real held-out tasks, model quality on real code problems, streaming, adaptive routing,
sandboxed Build/Test execution, an independent Governor, and GPU/NPU scheduling.
