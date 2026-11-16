# Mesh Lease Exchange v1: TLS Preview + Signed Receipt

**Status:** an authenticated **metadata-only** exchange over the opt-in
mutual TLS 1.3 transport introduced in PR #10. This is NOT task dispatch,
remote execution, remote file transfer, Governor authorization, or an
end-to-end distributed worker service.

## Exactly what crosses the wire

Two new POST routes exist on the **separate mesh listener**:

- `POST /mesh/v1/leases/preview` returns the currently leased assignment's
  task UUID, lease UUID, allowlisted mode, task SHA-256, deadline and whether
  the node previously acknowledged that metadata. When there is no active
  unexpired assignment, the response's `lease` is `null`.
- `POST /mesh/v1/leases/ack` records that the worker identity received the
  matching active lease metadata. This is not a claim that a job was started
  or completed. Acknowledgment does not change a task from `leased` to any
  other state; completion remains a **separate** signed evidence process.

Both routes require a **fresh ready heartbeat**, a TLS client certificate
manually pinned to the exact enrolled node, and a **new Ed25519-signed**
request that includes the action, node UUID, strictly increasing shared
sequence number, timestamp and (for an acknowledgment) lease UUID.

The coordinator checks all of this within **one SQLite BEGIN IMMEDIATE
transaction** against the existing node and task registry. It refuses
expired/revoked nodes, drained nodes, replays, stale leases, wrong lease
identifiers and certificate/Ed25519 key mismatches. Receipt records are
durable and idempotent for a correct active lease, with one audit event
for the first acknowledgment.

**There is no task body, code, shell, executable command, workspace path,
Governor permit, key material or artifact available via these routes.**
The response explicitly reports
`execution_authorized=false`, `task_dispatched=false`,
`governor_permit_included=false` and `task_payload_included=false`.

An acknowledgment is only evidence that a holder of the enrolled identity
and TLS credentials acknowledged that metadata, not proof of physical
machine identity, installed software, or valid gVisor isolation.

## Two-PC lab setup

Start with the manual enrollment and certificates in
[Mesh Enrollment](MESH_ENROLLMENT.md) and
[mTLS Transport](MESH_TRANSPORT.md). Ensure both PCs share the same local
coordinator trust chain, distinct operator/worker keys, correctly pinned
client certificate, and an IP SAN matching the coordinator's private IP.
Do **not** expose port 8766 to the Internet; limit it to your lab with an
OS firewall. The coordinator is a trusted network service and requires
manual activation.

Start the mTLS coordinator on a LAN address explicitly:

~~~bash
export PYTHONPATH=src
python -m phicortex.mesh_transport serve \
  --db "$HOME/.phicortex/mesh.sqlite3" \
  --cert "$HOME/.phicortex/credentials/coordinator.crt" \
  --key "$HOME/.phicortex/credentials/coordinator.key" \
  --client-ca "$HOME/.phicortex/credentials/ca.crt" \
  --listen 192.168.1.50 --port 8766 --allow-lan
~~~

Replace the address with your actual coordinator's RFC1918 IPv4 and use
a certificate issued for that **exact** IP. A VPN/tunnel is not assumed.
Never blindly copy a local-private-IP example if it does not match your
machine.

On the worker, send an existing Ed25519-signed heartbeat over mTLS, using
the **same** durable sequence database for all subsequent lease requests:

~~~bash
python -m phicortex.mesh heartbeat \
  --id "<node-uuid>" \
  --private "$HOME/.phicortex/node-ed25519.key" \
  --counter-db "$HOME/.phicortex/node-sequence.sqlite3" \
  --out "$HOME/.phicortex/heartbeats/new-heartbeat.json"

python -m phicortex.mesh_transport send \
  --host 192.168.1.50 --allow-lan \
  --packet "$HOME/.phicortex/heartbeats/new-heartbeat.json" \
  --ca "$HOME/.phicortex/credentials/ca.crt" \
  --cert "$HOME/.phicortex/credentials/node01.crt" \
  --key "$HOME/.phicortex/credentials/node01.key"
~~~

On the **trusted coordinator console**, independently create a reviewed
task intent and manually assign it to this enrolled node, as described in
[Lease Recovery](LEASES.md). The mode and SHA-256 digest are only metadata.
They do not represent executable permission. The task must be pending and
the worker must have a fresh ready heartbeat.

The worker can now retrieve **only** the metadata summary:

~~~bash
python -m phicortex.mesh_transport preview \
  --host 192.168.1.50 --allow-lan \
  --node-id "<node-uuid>" \
  --signing-key "$HOME/.phicortex/node-ed25519.key" \
  --counter-db "$HOME/.phicortex/node-sequence.sqlite3" \
  --ca "$HOME/.phicortex/credentials/ca.crt" \
  --cert "$HOME/.phicortex/credentials/node01.crt" \
  --key "$HOME/.phicortex/credentials/node01.key"
~~~

After inspecting that metadata on the worker, acknowledge the lease UUID
returned by the preview. The acknowledgment also does **not** execute
a task:

~~~bash
python -m phicortex.mesh_transport ack \
  --host 192.168.1.50 --allow-lan \
  --node-id "<node-uuid>" --lease-id "<returned-lease-uuid>" \
  --signing-key "$HOME/.phicortex/node-ed25519.key" \
  --counter-db "$HOME/.phicortex/node-sequence.sqlite3" \
  --ca "$HOME/.phicortex/credentials/ca.crt" \
  --cert "$HOME/.phicortex/credentials/node01.crt" \
  --key "$HOME/.phicortex/credentials/node01.key"
~~~

For a single-PC experiment, omit `--allow-lan` and use
`--host 127.0.0.1` with a loopback-IP SAN on the server certificate.
Use a different certificate/keypair for your real two-PC test.

## Failure and recovery rules

- If TLS cannot connect, the worker gets an error. The local sequence
  counter still advances, so retries must use a **new** signed request.
  Nothing is automatically executed or acknowledged.
- On reconnect, a worker can preview its existing active lease with a new
  signed sequence. Restarting the coordinator does not erase the existing
  SQLite receipt or the lease; the coordinator never auto-reassigns tasks.
- A lease whose deadline has passed returns no active preview. Its
  acknowledgment is refused. The trusted coordinator should call
  `python -m phicortex.leases reconcile` so uncertain work goes into
  **review_required**, never silently requeued.
- Revoked or drained identities cannot use the new routes.
- An arbitrary network client cannot enroll nodes, issue Governor permits,
  request execution, upload evidence or change task ownership.
- The mesh listener still supports signed heartbeats independently and does
  not alter PhiCortex's local chat API.

## Verification boundaries

The new integration suite establishes real **loopback** TLS handshake,
authentication, replay denial, receipt durability, concurrent duplicate
request denial, failed connection/reconnect behavior and lease expiry.
It does not establish that two physical machines can communicate on your
LAN, that a firewall or certificate deployment is correct, or that a
worker can run trustworthy isolated jobs. Those need real operator tests.

**Next gate:** bind a separate worker-specific Governor permit and reviewed
immutable source snapshot to a signed task envelope. Only after
independent real gVisor isolation and two-PC validation should that
envelope carry any executable work. No automatic execution yet.
