# PhiCortex Ed25519 approvals and staged snapshots v1

**Status:** experimental, operator-driven, Linux gVisor execution only.
These controls do not constitute an independent OS authority or a secure
sandbox against hostile code.

## What this changes

- `approval_v1.py` creates a 32-byte private signing key and distinct
  32-byte **public verification key** using Ed25519. Worker execution uses
  only the public key, never the private key.
- `snapshot.py` copies a reviewed project into an owner-controlled
  staging tree and checks SHA-256 of original and staged content.
  Its files are made read-only for accidental-write prevention.
- Operator signs a permit bound to exact task fields, pinned runtime image,
  snapshot manifest SHA-256 and workspace SHA-256, expiry <=300 seconds,
  and one-time nonce.
- The worker validates the permit with a **public key**, rejects altered
  scope, stale data and replay, then requests existing Linux Docker/gVisor
  isolation before running a fixed build-check or test command.
- The evidence vault still stores explicit result reports and selected
  files with content hashes. The chat API cannot start jobs or issue grants.

Ed25519 signing follows the open-source Python `cryptography` library.
Only this optional execution tooling needs that dependency; PhiCortex's
ordinary local chat remains standard-library-only.

## Preparation

On an operator-controlled account or a separate trusted machine,
install `pip install -r requirements-worker.txt` and initialize keys:

~~~bash
export PYTHONPATH=src
umask 077
python -m phicortex.approval_v1 init-keys \
  --private "$HOME/.phicortex/operator-ed25519.key" \
  --public "$HOME/.phicortex/operator-ed25519.pub"
~~~

Copy **only** the public key to the worker. Never transfer the private key
to the worker or to the model's context, workspace, artifacts, or repository.

The following example assumes a small reviewed Python project, Linux and
a locally installed, digest-pinned Python container image. On Windows,
validation/unit tests work; real execution needs a separately reviewed
Linux Docker/gVisor host.

## Snapshot the source before approval

~~~bash
python -m phicortex.approval_v1 snapshot \
  --source "$HOME/workspaces/reviewed-project" \
  --store "$HOME/.phicortex/snapshots"
~~~

This prints a path like
`~/.phicortex/snapshots/<id>/manifest.json`. The manifest identifies
`~/.phicortex/snapshots/<id>/tree`. The copied snapshot must be accessible
to the signer and the worker, with the same canonical path on each host.

## Issue a one-time approval (operator-side)

~~~bash
python -m phicortex.approval_v1 approve \
  --private "$HOME/.phicortex/operator-ed25519.key" \
  --snapshot-manifest "$HOME/.phicortex/snapshots/<id>/manifest.json" \
  --image "python:3.12-alpine@sha256:<actual-image-digest>" \
  --mode test --seconds 30 --ttl 60 \
  --out "$HOME/.phicortex/permits/run-001.json"
~~~

The signing CLI requires a reviewable, staged source copy. The signer
creates no Docker process and needs no worker Docker socket.

## Execute once (dedicated Linux worker only)

~~~bash
export PHICORTEX_ALLOW_ISOLATED_JOBS=1
python -m phicortex.worker \
  --workspace-root "$HOME/.phicortex/snapshots/<id>" \
  --workspace "$HOME/.phicortex/snapshots/<id>/tree" \
  --image "python:3.12-alpine@sha256:<actual-image-digest>" \
  --mode test --seconds 30 --execute \
  --permit-file "$HOME/.phicortex/permits/run-001.json" \
  --public-key "$HOME/.phicortex/operator-ed25519.pub" \
  --replay-db "$HOME/.phicortex/replay.sqlite3" \
  --vault "$HOME/.phicortex/vault" \
  --out "$HOME/.phicortex/reports/last.json"
~~~

The permit must match the exact snapshot/command. It cannot be reused.
The default CLI still makes a dry run if `--execute` is omitted.

## Unresolved safety requirements

1. The worker is trusted; private-key separation is a **deployment**
   decision, not proven by tests. The operator must protect signer keys
   under a separate principal or on another machine.
2. Read-only filesystem permissions are not immutable snapshots. Another
   privileged process can modify staged content after verification.
3. The gVisor runtime has not been independently exercised on your actual
   Linux/Windows/WSL2 environment; not ready for hostile code.
4. No OS-level network isolation beyond Docker/gVisor configuration was
   independently verified. Protected audit logs and worker identity
   enrollment are still future work.
5. Snapshot copying has size and file-count limits. Use small reviewed
   demo projects and keep secrets outside the source tree.

**Acceptance gate:** demonstrate gVisor confinement, race-resistant snapshot
mounting, resource limits, private-key separation and observable artifact
verification on the target host before extending agent autonomy.
