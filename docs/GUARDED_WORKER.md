# PhiCortex guarded BUILD-check / TEST worker v0

This is a **local CLI experiment**, not the automatic agent or independent Governor.
It does not enable `/build` or `/test` in the chat interface, and cannot modify
repositories, produce code patches, reach the Internet, or connect to other PCs.

## Scope

- **BUILD-CHECK**: syntax parse Python files using `ast.parse`; this does not
  compile executables, generate patches, install dependencies, or execute tests.
- **TEST**: run Python's standard-library `unittest discover -s tests -v`.
- Tasks are selected by the trusted human CLI operator, **not by model output**.
- Execution uses a local Linux Docker daemon only when the `runsc` (gVisor)
  runtime is registered. No fallback to Docker's ordinary `runc`, host Python,
  PowerShell or unrestricted shell.
- A pinned, already-installed container image is required; `--pull=never`
  blocks automatic image fetching.

## Security constraints

The runner chooses its command itself and mounts only the explicitly authorized
workspace **read-only**. It runs as UID 65534, with no network, a read-only root
filesystem, a 64 MiB temporary filesystem, all Linux capabilities dropped,
new privileges disabled, 1 CPU, 512 MiB RAM, and 64 allowed processes.
A runtime preflight checks for local `unix:///var/run/docker.sock` and a
registered `runsc` runtime. A timeout stops the Docker client, followed by
forced container deletion by a fixed generated container name.

**Limitations:** Registering gVisor does not cryptographically attest the
daemon. Docker and gVisor can still contain vulnerabilities. Host filesystem
permissions, Docker daemon privileges, memory exhaustion and log buffering
need adversarial testing. This prototype is **not approved for hostile code
or sensitive host systems** without a separate security review. No secrets
should be present in the source workspace. No genuine containment test has
been run on the user's Windows PC or Linux host.

This mode is deliberately unavailable under native Windows. Use a dedicated
Linux worker with the reviewed gVisor runtime when ready. WSL2 and Docker
Desktop compatibility must be verified separately.

## Operator walkthrough (Linux only)

The container image must contain Python 3.12, be locally present, and be
pinned by its full image digest, e.g.
`python:3.12-alpine@sha256:<actual SHA-256 digest>`.
Do not literally use the placeholder digest.

~~~bash
export PYTHONPATH=src
# Dry run: never contacts Docker, never executes code.
python -m phicortex.worker \
  --workspace-root /home/operator/workspaces \
  --workspace /home/operator/workspaces/demo-project \
  --image "python:3.12-alpine@sha256:<actual SHA-256 digest>" \
  --mode test --out /home/operator/reports/demo.json

# Once Docker/gVisor has been independently configured and reviewed:
export PHICORTEX_ALLOW_ISOLATED_JOBS=1
python -m phicortex.worker \
  --workspace-root /home/operator/workspaces \
  --workspace /home/operator/workspaces/demo-project \
  --image "python:3.12-alpine@sha256:<actual SHA-256 digest>" \
  --mode test --out /home/operator/reports/demo-test.json --execute
~~~

The local report records status, exit code, bounded output, duration and a
SHA256 of the job's identifying configuration. It is **not** a cryptographic
proof of gVisor isolation. Never promote the resulting tests without independent
review. Reports can contain sensitive test output, so use private report paths.

## Next milestone

Introduce separately authenticated worker identities and a Governor which signs
specific, immutable task contracts. Use a more strongly isolated runtime when
the threat model demands it, and add a reviewed artifact vault and file-hash
manifest. Only then expose BUILD/TEST tasks through the main API.
