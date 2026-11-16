# PhiCortex Mesh: Node Enrollment and Heartbeats v1

**Status:** offline contract and identity registry only. This does not launch a
network listener, open a port, schedule tasks, lease work, execute remote code,
or prove sandbox or CPU/GPU capabilities.

## Trust model

- A trusted **local operator** enrolls a node's 32-byte Ed25519 public key in a
  local SQLite registry, assigns a canonical UUID and a limited mode allowlist.
- A worker retains its *own* Ed25519 private key and can sign fresh heartbeats.
  It never receives the operator's Governor private signing key.
- Heartbeat packets have an exact schema: version, node UUID, issued-at timestamp,
  monotonically increasing sequence and ready/draining state. Adding self-claimed
  capabilities or new permission fields causes rejection.
- The coordinator verifies the enrolled public key, signature, time window
  (at most 60 seconds old, 10 seconds into future), and sequence. SQLite
  BEGIN IMMEDIATE serializes replay protection across concurrent imports.
- A successfully imported heartbeat marks a node online for **90 seconds**
  after coordinator receipt, not based on a self-claimed worker clock.
- A draining node is not eligible for future scheduling. Expired nodes are
  reported offline; revoked nodes remain revoked.
- Registered mode labels are an operator's *intent*, NOT verified isolation,
  verified hardware properties, Governor authorization, or a job-execution
  grant. Every response includes execution_authorized=false.

Public key hashes identify registered keys but are not proof of physical PC
identity. Never expose operator-controlled enrollment, revocation or the
registry database to a model or unauthenticated network client.

## Offline, manual smoke test

Requires Python 3.11+ and the optional worker dependency:

~~~bash
python -m pip install -r requirements-worker.txt
export PYTHONPATH=src
~~~

Generate a canonical UUID once (save it, do not generate a new one per message):

~~~bash
python -c "import uuid; print(uuid.uuid4())"
~~~

On the **worker**, generate and protect its distinct signing key:

~~~bash
umask 077
python -m phicortex.mesh new-keys \
  --private "$HOME/.phicortex/node-ed25519.key" \
  --public "$HOME/.phicortex/node-ed25519.pub"
~~~

Transfer *only* the public key and node UUID to the operator over an
authenticated, out-of-band channel. Do not put the private key in project
folders, chat transcripts, GitHub, shared storage or artifact manifests.

On the **coordinator**, enroll that verified key explicitly, replacing
<UUID> and the example paths with real local values:

~~~bash
python -m phicortex.mesh enroll \
  --db "$HOME/.phicortex/mesh.sqlite3" \
  --id "<UUID>" --label "Worker Lab 1" \
  --public "$HOME/.phicortex/node-ed25519.pub" \
  --modes test build-check
~~~

On the worker, create a single signed heartbeat; a SQLite counter outside
the project preserves monotonic sequence numbers across process restarts:

~~~bash
python -m phicortex.mesh heartbeat \
  --id "<UUID>" \
  --private "$HOME/.phicortex/node-ed25519.key" \
  --counter-db "$HOME/.phicortex/node-sequence.sqlite3" \
  --state ready \
  --out "$HOME/.phicortex/heartbeats/hb-001.json"
~~~

Transfer the signed JSON packet to the coordinator (no network transport
is implemented by PhiCortex). On the coordinator:

~~~bash
python -m phicortex.mesh accept \
  --db "$HOME/.phicortex/mesh.sqlite3" \
  --packet "$HOME/.phicortex/heartbeats/hb-001.json"

python -m phicortex.mesh list --db "$HOME/.phicortex/mesh.sqlite3"
~~~

To remove a worker, perform an authenticated local operator action:

~~~bash
python -m phicortex.mesh revoke \
  --db "$HOME/.phicortex/mesh.sqlite3" --id "<UUID>"
~~~

There is no un-revoke operation. To rotate a lost or compromised node key,
revoke the old node, create a new keypair and enroll a new node UUID. Loss of
the node-side sequence database also requires re-enrollment or a separate
operator-approved recovery mechanism; resetting its counter is rejected.

## Security and operational limitations

- **The original enrollment CLI remains offline and does not do discovery or task dispatch.** A separate opt-in heartbeat-only mutual TLS transport is introduced in [Mesh Transport](MESH_TRANSPORT.md).
  Packet import is manual. The coordinator does not automatically send tasks.
- A heartbeat authenticates a registered key, not an independently identified
  physical machine; stolen keys can impersonate a node until revoked.
- Registry enrollment and revocation depend on the local operator account
  protecting its SQLite file. A compromised local host can modify the DB.
- Clocks need approximate synchronization, and 90-second liveness is only
  a heartbeat-derived observation. It does not imply container availability
  or safe compute capacity.
- Heartbeat acceptance does **not** authorize a BUILD or TEST worker; the
  independent Ed25519 Governor permit and sandbox preflight are still required.
  Mesh revocation does not invalidate separately issued Governor permits.
- No execution evidence, lease ownership, artifact transfer, work retries,
  or connection-failure recovery occurs in this milestone. In particular, do
  **not** auto-retry non-idempotent work when a heartbeat expires.
- Python/Linux and Windows test runners exercise signed packet handling,
  concurrency and SQLite persistence, **not actual LAN traffic or hostile
  container isolation**.

## Next acceptance gates

1. Make approved worker transport mutually authenticated and encrypted.
2. Bind worker identity to a *separate* Governor permit and approved snapshot.
3. Implement bounded, durable task leases that expire to **review-required**,
   not automatically replayed side effects.
4. Require signed task results, artifact hashes and independent verification.
5. Test node disconnection, crash, key loss, hostile replay, and actual Linux
   sandbox limits on two real PCs before enabling autonomous dispatch.
