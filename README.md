# Φ PhiCortex

> One persistent platform. Many specialized models. Distributed execution. Independently measured progress.

**Status: Phase 1 foundation, not a superintelligence.** This repository is the implementation home for the seven-proposal Council Synthesis (GPT/CortexMesh, Meta/ORION, Kimi/AURORA, Grok/LATTICE, Claude/NEXUS, Gemini/AETHER-CORE, Vessie/DREAMER). These are design influences, not seven required services or live provider integrations.

## What works in this PR

- Standard-library HTTP gateway bound only to 127.0.0.1:8765.
- An OpenAI-shaped **non-streaming**, text-only /v1/chat/completions endpoint for a loopback Ollama-compatible endpoint.
- Explicit allowlist for configured chat/code models and deterministic routing reasons in a SQLite event ledger.
- Persistent metadata ledger, with transcript capture off by default.
- /health and /v1/models endpoints, plus offline unit and HTTP integration tests.

This PR does **not** implement sandboxed agents, distributed scheduling, external AIs, semantic memory, Dream/Build/Test execution, adaptive router training, or GPU/NPU management.

## Run locally

Requires Python 3.11+ and a separately installed and running Ollama with a pulled chat model.

Bash:

~~~bash
export PYTHONPATH=src
export PHICORTEX_CHAT_MODEL='qwen3:4b'
export PHICORTEX_CODE_MODEL='qwen3:4b'
python -m phicortex
~~~

PowerShell:

~~~powershell
$env:PYTHONPATH = 'src'
$env:PHICORTEX_CHAT_MODEL = 'qwen3:4b'
python -m phicortex
~~~

From another shell:

~~~bash
curl http://127.0.0.1:8765/health
curl -X POST http://127.0.0.1:8765/v1/chat/completions -H 'Content-Type: application/json' -d '{"model":"phicortex-auto","messages":[{"role":"user","content":"Hello"}]}'
~~~

The backend defaults to http://127.0.0.1:11434/v1/chat/completions; only an HTTP loopback endpoint is accepted. Set PHICORTEX_OLLAMA_URL only for a local compatible endpoint. Ollama must run separately. **Actual CPU-only inference requires separately configuring and measuring the backend:** this gateway itself cannot prove the GPU remained unused.

### Privacy and memory

PHICORTEX_DB defaults to phicortex.sqlite3. Events record model, route, outcome, latency, and backend token usage when available; **not chat text**, unless PHICORTEX_STORE_TRANSCRIPTS=1 is explicitly set. There is no cloud sync or semantic memory yet.

## Tests

~~~bash
PYTHONPATH=src python -m unittest discover -s tests -v
~~~

See docs/ARCHITECTURE.md and docs/SECURITY.md for the planned Governor, worker mesh, Dream mode and measurement gates.

MIT licensed; see LICENSE.
