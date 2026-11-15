# Φ PhiCortex: seven-brain council synthesis

## Mission
Create a CPU-first, local-first distributed cognitive platform with progressively **verified** capabilities, not a presumed superintelligence.

## Responsibilities

| Contributor | Preserved contribution |
| --- | --- |
| GPT / CortexMesh | Core contracts, local bootstrap, deterministic mathematics and telemetry |
| Meta / ORION | Orchestration, task frames, Git worktrees, worker permissions |
| Kimi / AURORA | Capability chart, measured routing, performance improvement proposals |
| Grok / LATTICE | CHAT/DREAM/BUILD/TEST state machines, swappable model specialists |
| Claude / NEXUS | External Governor, protected evaluations, scoped credentials |
| Gemini / AETHER | Measured CPU/GPU escalation, chaos testing |
| Vessie / DREAMER | Labeled speculation, cross-domain hypotheses, reality bridge |

These are **architectural design influences**, not linked or running external AI providers.

## Desired architecture

~~~mermaid
flowchart TD
 U[Operator / PhiOS / apps] --> G[Gateway + Governor]
 G --> R[Task state machine + model router]
 R --> B[Brain registry / local inference]
 R --> M[Second brain / retrieval]
 R --> X[Sandbox workers]
 B --> E[Telemetry / evidence ledger]
 M --> E
 X --> E
 E --> V[Protected evaluator]
 V -->|candidate changes| A[Human approval / canary / rollback]
 A --> R
~~~

Only gateway, deterministic routing, local Ollama adapter, a metadata ledger and tests are currently implemented. The other blocks are design targets.

## Target task contract (not implemented)
Task request: task_id, actor_id, mode, goal, project_ref, context_budget, allowed_actions, max_tokens, time_limit, resource_requirements, output_schema and correlation_id.

Worker result: task_id, status, artifact paths and SHA256 hashes, independent test evidence, route trace, resource usage, provenance, and unresolved uncertainties.

An untrusted prompt, web page, tool output or model response must never grant its own permissions.

## Engineering phases
1. **Current:** local chat gateway, deterministic routing, metadata persistence and tests.
2. Streaming, measurable CPU-only benchmark, math tools, real state-machine modes and versioned memory.
3. Protected test harness, sandboxed BUILD and TEST, artifact manifests and permission gate.
4. Browser Reader isolation, approved tools, MCP, scoped external operations.
5. Authenticated multi-PC worker fleet, durable task scheduling and retries.
6. Dream consolidation, independently evaluated adaptive router candidates, optional NPU/GPU and A2A/provider adapters.

## Critical conflicts resolved
- Dream mode proposes changes, never deploys directly.
- Start with deterministic routing; train the router only after held-out tests show improvement.
- Models are logical roles; running all of them simultaneously is not a requirement.
- Ledger data and human-reviewed knowledge are canonical; vector and graph indexes are derived views.
- High-risk code runs in a tested isolation backend, never unrestricted on the host.
- No arbitrary confidence thresholds without calibration.

## Acceptance gates
- Verify actual CPU-only inference on target hardware, not just a config claim.
- Demonstrate persistence after restart with transcript retention off by default.
- Reproducibly test routing, invalid models, unimplemented modes, and API behavior.
- Prevent a model from editing Governor policy or protected evaluation data.
- Demonstrate sandbox confinement before enabling generated-code execution.
- Preserve failed evaluations and make changes reversible.
