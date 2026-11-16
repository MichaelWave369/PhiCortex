# Security status and boundaries

**Phase 1 is local development software, not a hardened agent runtime.** No external API, browser control, filesystem editing, SSH, or sandbox execution is exposed. Do not bind the gateway to public networks or expose port 8765 through a reverse proxy. There is no authentication yet.

## Implemented

- Loopback-only HTTP listener on port 8765.
- Loopback-only Ollama backend URL; outbound requests are limited to a configured local backend.
- No execution of generated shell commands or downloaded content.
- Registered-model allowlist and basic text-only request validation.
- 1 MiB HTTP request limit; errors surfaced as JSON; metadata-only event persistence by default.

## Not implemented yet

- Authentication, per-user permissions, rate limits, sandbox governance, hardened egress rules, prompt-injection defenses, secure encrypted audit log, independent immutable evaluation, API-key management.
- Stream responses, distributed workers and real GPU monitoring.

## Required before external actions

A separate Governor process must verify authenticated actor, asset scope, action permission and time budget before any tool call. Treat website content, retrieved documents and model output as untrusted. Use microVM or comparably evaluated execution isolation for untrusted code; the final choice requires environment-specific testing. Live changes demand dry run, backup/rollback and appropriate owner approval. Do not let Dream mode alter deployment policy or benchmark definitions.

## Opt-in saved conversations (integration slice)

`PHICORTEX_ENABLE_HISTORY=1` enables plaintext transcript storage and SQLite FTS5 indexing. This is separate from the metadata event ledger and does not honor `PHICORTEX_STORE_TRANSCRIPTS` as a history switch. Without the history flag, the new conversation endpoints return HTTP 501. Both browser and API are bound to loopback; Host and Origin checks prevent ordinary cross-origin browser use, and conversation writes require a custom request header. These checks do not authenticate local processes. The browser deliberately renders model output using `textContent` rather than HTML. History deletion removes active database/index entries; historical backups and disk-level recovery are outside this guarantee.

Not yet implemented: encrypted storage, token-based local authentication, exact prompt token budgeting, complete per-user isolation, model provenance checks or a protected Governor. Keep the database on a private local disk, review your backup retention, and never expose the API through a public tunnel.


## Local worker prototype

The opt-in CLI `phicortex.worker` can run fixed Python build-check/test tasks
inside a local Linux Docker daemon **only** with the explicitly registered
`runsc` runtime. It refuses native Windows, remote Docker contexts, unpinned
images, non-allowlisted commands, network access, writable source mounts and
execution unless separately opted in. It is not exposed through the HTTP API.
No adversarial host-containment testing has been performed; use a reviewed,
dedicated Linux worker before running truly untrusted code. No secrets in
workspaces. See [guarded worker design](GUARDED_WORKER.md).
