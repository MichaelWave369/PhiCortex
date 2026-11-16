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


## Operator permit + evidence vault prototype

The worker CLI requires an explicit HMAC-signed approval from an operator-owned
32-byte secret file, with at most a 300-second validity window, exact task
scoping and SHA-256 validation of the source workspace. Consumed permit IDs
are recorded in SQLite and cannot be replayed. The key, replay ledger, permit
and vault must remain outside the mounted workspace. No approval endpoint
exists in the local browser or model API.

This is **not** a separately privileged Governor process: the local trusted
worker must possess the verification key, and compromise of that process or
its OS account remains in scope. A SHA-256 workspace digest is not an
immutable filesystem snapshot; concurrent host-side file mutation remains
a threat. The artifact vault provides integrity checks, not signed,
tamper-evident audit records or backup protection. The Docker daemon itself
remains privileged and gVisor was not independently containment-tested here.

Do not use for hostile/unreviewed code or remote API execution. Keep the
signing key protected, the host fully updated, and test gVisor isolation on
a dedicated Linux machine before expanding capabilities.


## Asymmetric permit candidate: Ed25519

The default operator CLI execution pathway now takes a public Ed25519
verification key, not a shared HMAC signing secret. A separate CLI creates
staged, checksum-verified copies of reviewed workspaces and signs their exact
task/snapshot manifest. The private signing key can be kept on a different
OS account or host. The legacy HMAC CLI execution path is disabled, but
low-level explicit migration/tests still exist temporarily.

This is **not** a privileged, always-on independent Governor. The operator
must actually separate and protect the private key. A staged directory with
read-only permissions is not an immutable OS snapshot; a privileged host
writer or owner changing modes can still mutate it. Hashes are checked before
a task launches, but the check-to-mount interval remains a TOCTOU risk.
No real host/gVisor confinement test is claimed. See
[asymmetric approvals](ASYMMETRIC_APPROVALS.md).


## Node enrollment and heartbeat contract

An experimental operator-only local SQLite node registry now accepts signed
Ed25519 heartbeats from manually enrolled public keys and records replay-safe
sequence numbers, last receipt time, draining state, and explicit revocation.
There is NO network listener, node self-enrollment, remote execution, job
queue or distributed scheduling. A heartbeat establishes key possession
only and is **not** evidence of sandbox containment, verified compute
resources or authorization to run a task. Node revocation does not revoke
independent Governor permits; those remain separate trust decisions.
Keep private node keys outside projects, the registry DB under a trusted
OS account, and do not transport signed packets over an untrusted channel.
See [Mesh Enrollment](MESH_ENROLLMENT.md).


## Task Lease Coordination Boundary

The experimental lease ledger is a **trusted-local-operator state machine**,
not a distributed scheduling service and not a new execution grant. It
authenticates signed result claims from enrolled node public keys and checks
local artifact hashes. A successful signature is not a proof of physical
machine identity, correct code execution, or sandbox isolation.

Task deadlines never exceed signed-heartbeat liveness windows; expired
or revoked work becomes `review_required` rather than silently retried.
A node may hold only one active lease at a time. The program does **not**
send commands over the network, enable `/build` or `/test` in chat, or
bind node identity to a Governor approval. The SQLite event stream is not
tamper-proof, and artifact files are not immutable while under a shared
host account. See [Lease Recovery](LEASES.md).


## mTLS Heartbeat Endpoint

The experimental separate mesh listener uses TLS 1.3, client certificate
verification with a configured private CA, and operator-managed cert pins
bound to the existing signed Ed25519 node registry. It exposes exactly one
heartbeat POST endpoint; no server-side tasks, file uploads, shell commands
or model tools are reachable there. LAN binding is opt-in and restricted to
explicit private IPv4 addresses; firewall protections and cert provisioning
are **operator responsibilities**. Enrollment remains local-only.

The TLS heartbeat channel authenticates node communication but does not
authorize a worker to run code, prove the host is uncompromised or prove
gVisor isolation. Do not expose it to the public Internet. See
[Mesh Transport](MESH_TRANSPORT.md).


## Mesh Lease Metadata Exchange Boundary

A successful mTLS, certificate-pinned, Ed25519-authenticated lease preview
is not permission to execute code. The two new endpoints transfer only
manually leased task identifiers, mode, hash, deadline and acknowledgment
state. Worker private keys, Governor permits, source snapshots, shell
commands and code payloads never cross these endpoints. A signed
acknowledgment proves receipt by enrolled key holders, not task execution,
node honesty or gVisor isolation. No new task is allocated by remote calls.
The shared heartbeat/lease sequence counter denies replay, and an expired,
drained or revoked node cannot retrieve a live lease. Manual operator
reconciliation is still required for uncertain expired leases.
See [Mesh Lease Exchange](MESH_LEASE_EXCHANGE.md).


## Signed Envelope Binding (candidate)

A local operator may issue a separate Ed25519-signed envelope that
cross-validates an existing signed Governor permit, snapshot digest,
task/lease UUID, enrolled Ed25519 node identity, pinned TLS client
certificate and acknowledged lease. Its expiry never exceeds the permit,
lease or heartbeat deadline. This check **does not consume** the Governor
permit and cannot grant execution permission or establish exactly-once
execution. It does not change the guarded worker or introduce a remote
command endpoint. The snapshot remains mutable to privileged host
processes, and SQLite is not a secure hardware attestation service.
See [Signed Task Envelopes](SIGNED_TASK_ENVELOPES.md).


## Two-PC validation diagnostic

Local certificate preflight does not prove server identity; the real TLS
handshake checks its trust chain and IP SAN. Operator-recorded public-key
and certificate fingerprints prevent accidentally testing the wrong enrolled
worker. A denial test counts only an explicit HTTP 403; a disconnect or TLS
error is never counted as successful revocation proof. Even an HTTP 403
requires operator-side correlation to establish the cause. Reports exclude
raw secrets and private credential paths but contain operational identifiers.
No auto-retry, job dispatch, Governor permit delivery or code execution is
added. See [Two-PC validation](TWO_PC_MESH_VALIDATION.md).


## Offline lab certificate authority (candidate)

The helper intentionally issues only short-lived, narrow serverAuth or clientAuth
certificates with exact private IP or node UUID identities. Signing a worker
CSR requires a trusted operator to verify the request's origin and node ID;
certificate-signing private keys remain offline from the worker. Certificates
are not production hardened, keys are currently unencrypted PKCS#8 PEMs,
Windows NTFS ACLs require operator inspection and there is no online CRL,
OCSP or automated rotation. Never put the CA private key, node TLS key or
Ed25519 signing key into the repository, the model context or cloud storage.
See [Lab PKI](LAB_PKI.md).


## Advisory modes and operator-managed project notes

Mode is strictly a local model routing hint, not a Governor permission,
worker job, code deployment, filesystem tool or background DREAM
scheduler. Invalid modes are rejected, and legacy slash commands remain
disabled. Explicit model choices still require the configured allowlist.

The separate notes CLI stores UTF-8 Markdown bodies and FTS5 index
in PLAINTEXT on local disk. Retrieved notes are untrusted data and
are never automatically appended to prompts. Historical version hashes
can detect content mismatch, but this SQLite store is not tamper-proof.
Archive removes search hits; explicit confirmed purge deletes current
database rows but cannot ensure backup, journal or SSD secure erasure.
See [LATTICE foundation](LATTICE_MODES_NOTES.md).
