# Φ PhiCortex

> One persistent platform. Many specialized models. Distributed execution. Independently measured progress.

**Status: Phase 1 foundation, not a superintelligence.** This repository is the implementation home for the seven-proposal Council Synthesis (GPT/CortexMesh, Meta/ORION, Kimi/AURORA, Grok/LATTICE, Claude/NEXUS, Gemini/AETHER-CORE, Vessie/DREAMER). These are design influences, not seven required services or live provider integrations.

## What works in this PR

- A Python standard-library HTTP gateway bound only to `127.0.0.1:8765`.
- An OpenAI-shaped **non-streaming**, text-only `/v1/chat/completions` endpoint that delegates to a local Ollama-compatible endpoint.
- Explicit allowlist of configured chat/code models and transparent, deterministic route reasons in the local SQLite event ledger.
- A persistent **metadata** event ledger, with transcript capture **off** by default.
- `/health` and `/v1/models` endpoints, plus offline unit and HTTP integration tests.

This PR does **not** implement real agent sandboxes, distributed task scheduling, external AI consultation, semantic memory, Dream/Build/Test execution, adaptive router training, or GPU/NPU management. Those remain gated milestones.

## Run locally

Requires Python 3.11+ and a separately installed Ollama with a pulled chat model. Zero Python dependencies are required for the gateway.

```bash
# In Bash, PowerShell equivalents below
export PYTHONPATH=src
export PHICORTEX_CHAT_MODEL='qwen3:4b'
export PHICORTEX_CODE_MODEL='qwen3:4b'
python -m phicortex
```

PowerShell:

```powershell
$env:PYTHONPATH = 'src'
$env:PHICORTEX_CHAT_MODEL = 'qwen3:4b'
python -m phicortex
```

In another terminal:

```bash
curl http://127.0.0.1:8765/health
curl -X POST http://127.0.0.1:8765/v1/chat/completions -H 'Content-Type: application/json' -d '{"model":"phicortex-auto","messages":[{"role":"user","content":"Hello"}]}'
```

The backend defaults to `http://127.0.0.1:11434/v1/chat/completions` and is restricted to HTTP loopback for this phase. Set `PHICORTEX_OLLAMA_URL` only to a local compatible endpoint. Ollama must be running separately. CPU-only inference must be configured and measured at the inference backend; this gateway does **not** independently guarantee that the GPU is unused.

### Local memory and privacy

`PHICORTEX_DB` defaults to `phicortex.sqlite3`. By default the event ledger stores route, model, latency, outcome and backend token usage if reported, **not chat text**. Set `PHICORTEX_STORE_TRANSCRIPTS=1` only if you want explicit local transcript retention. Protect and back up the DB appropriately. No cloud sync is included.

## Tests

```bash
PYTHONPATH=src python -m unittest discover -s tests -v
```

PowerShell: set `$env:PYTHONPATH = 'src'` first, then use `python -m unittest discover -s tests -v`.

## Architecture and roadmap

See [Council architecture](docs/ARCHITECTURE.md) and [security boundary](docs/SECURITY.md). The earliest acceptance milestone is: local request → deterministic route → locally loaded model → response → persistent telemetry → real tests. No claim of autonomous learning or generated intelligence is made.

**License:** MIT (see LICENSE).

## Optional Nova-inspired local conversation workspace

**This is a new, independently written implementation of the public API behavior described in the Sovereign Intelligence Mesh Phase 1 proposal, not a copy of Nova's ZIP.** Thanks to Nova and Larrina for the detailed reference implementation and verification plan. Nova's source ZIP did not include a top-level code license, so this PR does not import its source, frontend, or font assets.

Enable plaintext conversation retention **explicitly** before starting PhiCortex:

PowerShell:

```powershell
$env:PHICORTEX_ENABLE_HISTORY = '1'
$env:PYTHONPATH = 'src'
python -m phicortex
```

Linux/macOS shell:

```bash
PHICORTEX_ENABLE_HISTORY=1 PYTHONPATH=src python -m phicortex
```

Open **http://127.0.0.1:8765** in a browser. It uses the existing local model gateway; a separately running Ollama-compatible text model is required to generate responses. The new UI and API have no additional Python or JavaScript dependencies. PhiCortex does **not** download Nova's pinned runtime or model, and it does not verify GPU exclusion.

Conversation endpoints (all loopback-only):

| Endpoint | Action |
| --- | --- |
| `GET /` | PhiCortex local browser workspace |
| `GET /api/v1/status` | Basic configuration (not a model readiness probe) |
| `POST /api/v1/conversations` | Create a conversation |
| `GET /api/v1/conversations` | List conversations |
| `GET /api/v1/conversations/{id}` | Recent turns and cursor pagination |
| `POST /api/v1/conversations/{id}/turns` | Generate and atomically store a turn |
| `GET /api/v1/search?q=Juniper` | Local SQLite FTS5 transcript search |
| `DELETE /api/v1/conversations/{id}` | Delete a conversation and its indexed turns |

Write requests require `X-PhiCortex-Request: 1`; the Nova-style header `X-Mesh-Request: 1` is also accepted for compatibility. A turn POST requires a UUID `request_id` and plaintext `message`. Replaying the same request ID and message returns the same turn without running inference again; a conflicting message returns HTTP 409. A failed generation saves no partial turn. The original `/v1/chat/completions` endpoint still works when history is disabled.

**Privacy:** When `PHICORTEX_ENABLE_HISTORY=1`, messages and model responses are stored as **plaintext** in the configured SQLite database and its FTS5 index. This is independent of `PHICORTEX_STORE_TRANSCRIPTS`, which controls the event ledger. Never enable history on a machine whose local accounts or backups you do not trust. Deleting a conversation removes its database rows and current search hits but is not a secure guarantee about disk recovery, backups, or replicas. The browser renders replies as plain text rather than executable HTML.

**Limitations:** No frontend streaming, real token-aware context selection, encryption at rest, model readiness polling, multi-client authentication, automatic model download, long-term semantic memory, distributed workers, or production Governor yet. Context trimming uses a conservative character budget and keeps only recent turns; it is not equivalent to exact llama.cpp tokenization. Do not expose the listener to the internet or place behind a public reverse proxy.


## Managed CPU baseline (experimental)

After installing a **local** llama.cpp `llama-server` and a compatible GGUF instruct model,
run a temporary CPU-configured local evaluation:

```powershell
$env:PYTHONPATH = 'src'
python -m phicortex.cpu_probe --server 'C:\path\to\llama-server.exe' --model 'C:\path\to\model.gguf' --cases benchmarks/cases.example.json --out artifacts/cpu-baseline.json
```

This does not download models, change router policy, or independently prove GPU inactivity.
It records the explicit CPU/offline launch controls and deterministic evaluation outcomes.
See [CPU baseline guide](docs/CPU_BASELINE.md).


## Guarded local BUILD-check and TEST worker (Phase 3 prototype)

An optional **CLI-only** worker performs Python syntax checks or `unittest` inside a
**local Linux Docker daemon with the gVisor `runsc` runtime**. The default is a
non-executing dry run. Explicit execution requires the operator to enable
`PHICORTEX_ALLOW_ISOLATED_JOBS=1`, use a locally pinned image digest, and pass
runtime checks. There is no fallback to host execution or standard Docker `runc`.

The chat interface still does **not** support autonomous BUILD/TEST, and this is not
an independent Governor or a reviewed microVM. See [guarded worker guide](docs/GUARDED_WORKER.md)
for prerequisites, limitations and the operator-only CLI. The Windows gateway stays
functional, but this specific guarded execution backend requires a Linux worker.
