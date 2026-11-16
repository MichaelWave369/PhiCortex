# Two-PC PhiCortex Mesh Validation Kit

**Scope:** operator-driven TLS heartbeat and lease metadata diagnostics. This is
not proof that two physical PCs were tested, a remote execution service, or a
gVisor confinement attestation.

## What is checked

Before network access, mesh_doctor verifies the operator-recorded Ed25519
public-key fingerprint, pinned X.509 client certificate fingerprint, clientAuth
EKU, certificate validity, matching TLS and Ed25519 private keys, symlink-free
credential paths and owner-only Unix key permissions. It also refuses public,
wildcard or non-IP destinations. A private RFC1918 server requires --allow-lan.

When invoked without --preflight-only, the diagnostic sends a fresh
Ed25519-signed heartbeat over **real mTLS 1.3** and another freshly signed
read-only lease preview. Both consume new numbers from the existing durable
node-side sequence database. They do NOT assign tasks, transmit files, deliver
code or issue Governor grants. Lease receipt requires explicit --acknowledge.

The report contains status, sequence numbers, timings and operator-recorded
public fingerprints, not raw keys or private key file paths. It is created
exclusively, not overwritten. Keep reports out of the source repository.

## Prepare the coordinator (PC 1) and worker (PC 2)

Both PCs may be Windows for this *network* exercise. Real worker execution
still requires separately reviewed Linux/gVisor hardware.

1. Install Python 3.12 and requirements-worker.txt on both PCs. From each
   checked-out repository root set PYTHONPATH=src.
2. Give PC 1 an actual private LAN IPv4, and firewall TCP 8766 so only
   your approved worker can reach it. Do not expose a public or Starlink WAN
   address, configure router port-forwarding, or use an Internet tunnel.
3. Provision a private lab CA and a serverAuth certificate for PC 1 with
   its **actual numeric private IP as a SAN**, plus a separate clientAuth
   certificate for PC 2. Keep the CA and server private keys on PC 1.
   See MESH_TRANSPORT.md for prerequisite enrollment and CA configuration.
4. Manually enroll PC 2's Ed25519 public key with phicortex.mesh enroll
   on PC 1. Bind PC 2's X.509 client certificate with
   phicortex.mesh_transport bind-client-cert. Record both returned SHA-256
   fingerprints from the coordinator, not from a worker's self-report.
5. Start the coordinator with phicortex.mesh_transport serve on the
   chosen private IP with --allow-lan. Never open the listener to a public
   interface.

## PC 2 PowerShell: local validation, then a real handshake

Replace all placeholders with actual values and file locations. Never paste
private-key contents into a GitHub issue or AI chat.

~~~powershell
python -m pip install -r requirements-worker.txt
$env:PYTHONPATH = "src"

$base = "$HOME\.phicortex"
$hostIP = "<actual-coordinator-private-ip>"
$nodeId = "<enrolled-node-uuid>"
$nodeHash = "<enrolled-ed25519-public-key-sha256>"
$certHash = "<operator-pinned-x509-client-cert-sha256>"

$common = @(
  "--host", $hostIP, "--port", "8766", "--allow-lan",
  "--server-ca", "$base\credentials\ca.crt",
  "--client-cert", "$base\credentials\node01.crt",
  "--client-key", "$base\credentials\node01.key",
  "--node-id", $nodeId,
  "--node-signing-key", "$base\node-ed25519.key",
  "--counter-db", "$base\node-sequence.sqlite3",
  "--expected-node-sha256", $nodeHash,
  "--expected-cert-sha256", $certHash
)

python -m phicortex.mesh_doctor @common --preflight-only
python -m phicortex.mesh_doctor @common --out "$base\reports\online-first.json"
~~~

An accepted live probe has outcome protocol_passed, a heartbeat and lease
preview with strictly advancing sequences, and
physical_pc_verified=false, execution_authorized=false,
task_dispatched=false.

To explicitly acknowledge **metadata** for an existing manually assigned
lease, use this optional command. It does NOT execute work:

~~~powershell
python -m phicortex.mesh_doctor @common --acknowledge --out "$base\reports\lease-receipt.json"
~~~

## Disconnect, reconnect and revoke

1. Save a successful live report while both PCs are connected.
2. Stop the coordinator's test listener or disconnect its test-only
   network connection. Probe again with a NEW filename. This failure is
   NOT a revocation proof and must not be counted as a success.
3. Restore connectivity, probe again with a different filename and check
   that sequence numbers advanced. The system does not auto-retry any
   execution or task, and the lease state should remain unchanged.
4. On PC 1, revoke only the *test* node UUID with phicortex.mesh revoke.
   Then on PC 2 run:

~~~powershell
python -m phicortex.mesh_doctor @common --expect-denied --out "$base\reports\after-revoke.json"
~~~

Only an explicit HTTP 403 counts as explicit_403_observed. The 403
alone does not prove the cause; correlate it with the operator-side
revocation and registry state. A timeout, bad CA or disconnected network
never passes the negative authorization check.

Revocation is permanent. To restore a worker after this test, enroll
a **new UUID and new keys**, and pin a new TLS client certificate.
Do not reset an old sequence counter.

## What automated CI does and does not prove

Automated Windows/Linux integration tests perform real **loopback** TLS
handshakes, signed heartbeat/preview, operator-pin checks, optional receipt,
certificate mismatch, time validity, failure/reconnect sequencing and
post-revocation denial. That is not a field test across two physical PCs.

The diagnostic cannot independently prove a device's hardware identity,
the correctness of LAN/firewall configuration, secure source isolation,
gVisor containment, actual task execution or autonomous reliability.
Record the two-PC configuration and dated probe results on your own
machines before treating the physical acceptance gate as passed.

**No remote execution, no automatic retry, evidence before autonomy.**


### Optional CSR/CA provisioning helper

The optional, offline [Lab PKI helper](LAB_PKI.md) can generate the CA, role-
specific CSRs on the machine owning each private key, and signed public
client/server certificates without copying the worker's private key to the
coordinator. This is test infrastructure, **not** a hardened production CA.
