# Signed Task Envelopes v1

**Status: operator-only, local, read-only authorization cross-check.**
This milestone adds NO execution API, code transfer, automatic job dispatch,
worker daemon, public network listener, model tool permission or Governor
nonce consumption. It is not a claim of real multi-PC isolation.

## Why it exists

PhiCortex has separate but incomplete trust records: an Ed25519 Governor
permit for a reviewed job/snapshot, an operator-assigned durable task lease,
and a verified, enrolled worker identity. This module ties them together
with one separately **operator-signed envelope**.

A valid envelope binds:

- The leased task UUID, lease UUID and fixed allowlisted mode.
- A deterministic task SHA-256 calculated from the approved Governor job
  fields, workspace digest and snapshot-manifest digest.
- The *specific signed* Governor permit SHA-256, not merely its task type.
- The current enrolled worker's UUID, Ed25519 public-key fingerprint and
  operator-pinned TLS client-certificate fingerprint.
- Short-lived timestamps bounded by the permit expiry, lease deadline,
  worker heartbeat expiry and an additional 120-second maximum.
- A unique envelope nonce and Ed25519 signature from the trusted operator.

The envelope carries **no source path, model prompt, code, executable
command, private key, Governor permit body, or workspace contents**.

## Operator workflow (current machine, offline)

Install the optional cryptography dependency and run from the repository
root. The commands below are examples and require *your own local files*;
do not paste real private keys into the chat or put them into a repo.

~~~bash
python -m pip install -r requirements-worker.txt
export PYTHONPATH=src
~~~

1. On a trusted operator workstation, create a small reviewed source
   snapshot and a **signed Ed25519 Governor permit** using the procedures
   in [Asymmetric Approvals](ASYMMETRIC_APPROVALS.md). The permit and
   snapshot must be inspectable at their original local paths. The private
   signing key stays on the trusted operator workstation.

2. Compute the *specific permitted task digest*. Do this **before**
   assigning the task in the node/lease registry:

~~~bash
python -m phicortex.envelope task-digest \
  --permit "$HOME/.phicortex/permits/run-001.json" \
  --public "$HOME/.phicortex/operator-ed25519.pub"
~~~

3. On the coordinator console, create a task with the returned digest and
   manually lease it to a recently authenticated, ready worker. The task
   mode must match the signed Governor permit. Follow
   [Lease Recovery](LEASES.md). The enrolled node must already have a
   manually bound TLS client certificate as described in
   [Mesh Transport](MESH_TRANSPORT.md).

4. The intended worker must acknowledge that lease's **metadata** with
   the existing signed TLS exchange in
   [Mesh Lease Exchange](MESH_LEASE_EXCHANGE.md). That acknowledgment
   does not run the task.

5. Only after the coordinator observes that signed acknowledgment, the
   trusted operator may sign this short-lived *binding record*:

~~~bash
python -m phicortex.envelope sign \
  --db "$HOME/.phicortex/mesh.sqlite3" \
  --task-id "<leased-task-uuid>" \
  --permit "$HOME/.phicortex/permits/run-001.json" \
  --private "$HOME/.phicortex/operator-ed25519.key" \
  --public "$HOME/.phicortex/operator-ed25519.pub" \
  --ttl 45 \
  --out "$HOME/.phicortex/envelopes/task-001.json"
~~~

6. Independently inspect the saved envelope, *without consuming* the
   Governor permit or initiating execution:

~~~bash
python -m phicortex.envelope verify \
  --db "$HOME/.phicortex/mesh.sqlite3" \
  --envelope "$HOME/.phicortex/envelopes/task-001.json" \
  --permit "$HOME/.phicortex/permits/run-001.json" \
  --public "$HOME/.phicortex/operator-ed25519.pub"
~~~

The result is explicitly marked **validated_metadata_only**, with
execution_authorized=false, task_dispatched=false,
permit_consumed=false and worker_isolation_attested=false.

**The existing Governor permit is valid for at most 300 seconds.** The
heartbeat and lease deadlines can be shorter. If the operator workflow
takes too long, the correct response is to issue a new permit and
*new task identity* as needed, rather than extending timestamps or
reassigning uncertain work automatically.

## Fail-closed validations

The verifier checks exact JSON schema and Ed25519 signatures for both
the envelope and its referenced Governor permit, reconstructs the
fixed worker plan, rechecks the snapshot manifest and source digest,
compares the deterministic task hash with the active lease, and checks
the currently enrolled node identity, public-key fingerprint, pinned
TLS certificate, fresh ready heartbeat and signed acknowledgment.
Every comparison is for a *specific* task, lease, node and permit.

Changing the permit, source snapshot, lease owner, task hash, certificate
pin or enrolled key invalidates the binding. Missing receipts, expired
leases, draining/revoked/offline workers or mismatched signing keys are
rejected. There is no automatic lease retry or hidden fallback.

## Critical limitations

- **This is not yet a worker execution authorization mechanism.** The
  existing guarded worker is unchanged and does not accept envelopes.
  It still needs a separate Governor verification-and-consumption step
  plus its gVisor isolation preflight before any operator-driven execution.
- The verifier is **read-only and repeatable** while the envelope is valid;
  the envelope nonce is not consumed. It is therefore unsuitable as an
  exactly-once execution token. Binding execution to one envelope requires
  a separate atomic nonce/lease-consumption protocol.
- The snapshot is an operator-owned directory copy, *not immutable storage*.
  A privileged host writer and check-to-use race remain threats.
- SQLite node registry and certificate pins are trusted operator-controlled
  data. A signed receipt demonstrates possession of the enrolled keys at
  that moment, not a verified physical machine or isolated runtime.
- The envelope stays local. There is **no network envelope-delivery
  endpoint**, remote file transfer or automatic worker execution. The
  existing TLS lease-preview channel remains metadata-only.
- Tests verify cross-platform Python contracts and local cryptographic
  behavior, **not** remote worker safety, trusted hardware, gVisor or
  isolation across two physical PCs.

## Next acceptance gates

First test real two-PC TLS enrollment, revocation, lease acknowledgment,
disconnection and recovery. Then implement a worker-specific, atomic,
single-use execution decision *outside* the model's control, with an
immutable reviewed snapshot, authenticated delivery, signed receipts and
host-level confinement tests. Do not deliver autonomous BUILD/TEST payloads
until these controls are independently verified.
