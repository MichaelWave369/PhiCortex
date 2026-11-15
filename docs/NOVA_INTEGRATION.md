# Nova / Sovereign Intelligence Mesh → PhiCortex integration review

## Provenance and scope

The reference material consists of `Sovereign-Intelligence-Mesh-Feasibility.md` and `Sovereign-Intelligence-Mesh-Phase-1.zip`, supplied for comparative review. Nova/Larrina's work identified a strong executable Phase 1: CPU llama.cpp runtime, searchable local chat history, a React workspace, deterministic tests and a measured Linux smoke run. Those claims are attributed to Nova; they are not PhiCortex benchmarks.

The ZIP contains third-party component license notices but **no top-level license for its own application source**. This integration implements selected interfaces and behavior independently, without importing its Python files, React app, bundled fonts or binary assets. If an appropriate license is confirmed later, we can separately evaluate direct reuse with attribution.

## Implemented now

- Opt-in, SQLite-backed conversations and search (FTS5).
- Commit complete request/reply pairs atomically after successful inference.
- UUID retry replay, conflicting content detection, and basic concurrency protection.
- Pagination, search, deletion, persistent history across restart.
- Same-origin browser workspace with no external dependency or copied frontend.
- Loopback Host/Origin protections and header-gated writes, retaining prior chat API.
- Existing routing / telemetry and new negative-path tests.

## Not yet ported / verified

- Nova's managed llama.cpp binary + Qwen weights download and verification.
- Real CPU-only operation, Windows-native setup, throughput and cold-start measurements.
- Exact chat-template token counting and bounded context as defined in Nova's prototype.
- Nova's React UI and mobile Chromium smoke suite.
- Encryption at rest, remote access and authentication; no external-tool access.
- Long-term semantic memory, Build/Test/Dream workers, distributed mesh, dynamic model routing.

## Decision rationale

PhiCortex's existing model gateway remains intact. The storage/UI compatibility slice is additive and can be disabled without changing prior metadata-only behavior. The language model is still a local, replaceable backend. The next measured step is to add real inference token accounting and a repeatable Windows CPU-only smoke test before claiming feature parity with Nova's reference release.
