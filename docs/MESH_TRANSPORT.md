# PhiCortex Mesh Transport v1: mutual TLS heartbeat channel

**Scope:** working HTTPS/TLS 1.3 heartbeat transport and an optional
metadata-only lease preview/acknowledgment extension, **NOT** a remote worker executor,
job dispatcher, task API, automatic enrollment service or secure distributed AI
deployment. Operator must separately configure a small, private lab PKI.

## What communicates

The coordinator listens on **127.0.0.1:8766 by default**. It supports
signed heartbeats at `POST /mesh/v1/heartbeats` plus the optional,
non-executable lease metadata preview/acknowledgment routes documented in
[Mesh Lease Exchange](MESH_LEASE_EXCHANGE.md). All other paths return 404. The
coordinator never accepts executable commands, files, tasks, scripts, Governor
permits or arbitrary tools over this listener.

A worker initiates the connection using a client certificate trusted by the
coordinator's manually configured CA. The worker also verifies the
coordinator's server certificate and its **IP subject-alternative name** against
the explicitly supplied CA. Both ends require **TLS 1.3**.

The coordinator then verifies all of these:
1. Client TLS certificate chains to the selected CA (TLS handshake).
2. Client certificate SHA-256 fingerprint was **manually bound** to an
   enrolled, non-revoked node UUID in the local registry.
3. Heartbeat body carries the expected node UUID and a valid **Ed25519
   signature** from that enrolled node's existing public key.
4. Fresh timestamp, strictly increasing sequence, and the exact small
   heartbeat schema are all valid.
5. The registry updates the heartbeat and checks the node/certificate binding
   in the **same SQLite BEGIN IMMEDIATE transaction**, preventing races with
   revocation and duplicate sequence claims.

The response includes only node UUID, reported online/draining status, receipt
expiry and sequence plus explicit `execution_authorized=false` and
`task_dispatched=false`.

## Provisioning prerequisites

The operator must control an isolated lab CA and obtain:
- `ca.crt`: public CA certificate that signs coordinator and node TLS certs
- `coordinator.crt` and `coordinator.key`: TLS server identity
- `node01.crt` and `node01.key`: separate TLS client identity
- Existing node **Ed25519** identity keypair from `phicortex.mesh new-keys`

The server certificate must have an `iPAddress` SAN that exactly matches the
coordinator's numeric IPv4 address used by clients, plus serverAuth extended
key usage. The node TLS certificate should carry clientAuth extended key usage.
Use short-lived certs and protect all private keys outside Git repositories,
project workspaces and AI prompts. Do **not** reuse the Ed25519 Governor signer
or the enrolled Ed25519 heartbeat signing key for TLS identity.

CA private key stays offline. The client private key stays on the worker.
The server private key stays on the coordinator. Never push any private key
or `*.key` file to GitHub. A new compromised client certificate requires
revoking the node and enrolling a new UUID/keypair and certificate binding.

The operator must verify cert origin and node identity *out of band*. A cert
fingerprint is an operator-approved binding, not cryptographic hardware
attestation.

## One-time operator enrollment

Install the already-used optional dependency if needed:

~~~bash
python -m pip install -r requirements-worker.txt
export PYTHONPATH=src
~~~

After using [Mesh Enrollment](MESH_ENROLLMENT.md) to enroll the node's Ed25519
public key, bind its **distinct X.509 TLS client certificate**:

~~~bash
python -m phicortex.mesh_transport bind-client-cert \
  --db "$HOME/.phicortex/mesh.sqlite3" \
  --node-id "<enrolled-node-uuid>" \
  --cert "$HOME/.phicortex/credentials/node01.crt"
~~~

Binding is **one-time only**. Unknown, revoked, or already bound nodes are
rejected. The same certificate cannot be assigned to two nodes. The binding
must be performed by the trusted coordinator operator, never by an
unauthenticated remote node.

## Start the coordinator listener

For a safe first loopback experiment:

~~~bash
python -m phicortex.mesh_transport serve \
  --db "$HOME/.phicortex/mesh.sqlite3" \
  --cert "$HOME/.phicortex/credentials/coordinator.crt" \
  --key "$HOME/.phicortex/credentials/coordinator.key" \
  --client-ca "$HOME/.phicortex/credentials/ca.crt"
~~~

A dedicated Linux test coordinator on a local RFC1918 address could explicitly
opt in to LAN binding with e.g. `--listen 192.168.1.50 --allow-lan`.
**Wildcard, public, DNS-name and IPv6 listener addresses are refused.**
Server certificates must include that exact private IP as a SAN. Use an OS
firewall to restrict port 8766 to known worker IPs. Avoid forwarding this port
through a router, Starlink or an internet tunnel. Client packets are no
larger than 4 KiB; this is **not** complete DDoS protection.

## Send an enrolled node heartbeat

On the worker, create a signed heartbeat using its existing Ed25519 private
key and persistent sequence ledger:

~~~bash
python -m phicortex.mesh heartbeat \
  --id "<enrolled-node-uuid>" \
  --private "$HOME/.phicortex/node-ed25519.key" \
  --counter-db "$HOME/.phicortex/node-sequence.sqlite3" \
  --out "$HOME/.phicortex/heartbeats/hb-001.json"
~~~

On the worker, transmit the JSON body through a separate **mTLS** client:

~~~bash
python -m phicortex.mesh_transport send \
  --host 127.0.0.1 --port 8766 \
  --packet "$HOME/.phicortex/heartbeats/hb-001.json" \
  --ca "$HOME/.phicortex/credentials/ca.crt" \
  --cert "$HOME/.phicortex/credentials/node01.crt" \
  --key "$HOME/.phicortex/credentials/node01.key"
~~~

For an approved RFC1918 LAN server, supply its numeric IP in `--host` and
pass `--allow-lan`; the server cert SAN must match. Unlike the old offline
packet import, this **does** make an HTTPS network connection, but it
does not call or modify the model chat gateway and does not transmit tasks.

## What the integration tests prove

Cross-platform Python integration tests start a real TLS 1.3 server on a
random **127.0.0.1** port using short-lived, generated test certificates.
They exercise successful mutual verification, client certificate pinning
on top of the Ed25519 node identity, revocation, invalid signatures,
replays, concurrent duplicate heartbeats, untrusted CAs and missing
certificates. They also ensure the server refuses arbitrary paths and
oversized request bodies.

No CI run verifies connectivity between **two physical PCs** or actual
LAN firewalls, Starlink/NAT behavior, Docker/gVisor, model execution or
the secure delivery of task leases. Do not call this a complete production
zero-trust worker mesh.

## Remaining milestones before task delivery

1. Demonstrate TLS connectivity, certificate expiry/rotation, interruption,
   and revoked-key denial across two real trusted PCs.
2. Create an authenticated, encrypted **task envelope** bound to the worker
   public identity, an independently signed Governor permit and immutable
   execution snapshot.
3. Tie durable lease receipts, worker-side journal and signed evidence to
   explicit exactly-once *recording*. There is no general exactly-once
   execution guarantee across network failure.
4. Validate gVisor confinement and cleanup on real hardware before accepting
   any AI-authored code. An online heartbeat is never permission to execute.

**Ledger Above Ego. Evidence before automatic dispatch.**
