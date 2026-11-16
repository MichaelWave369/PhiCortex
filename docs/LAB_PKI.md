# PhiCortex Lab PKI: Two-PC certificate provisioning

**Status:** experimental offline lab helper. It creates an operator-owned X.509 CA and role-specific certificate signing requests (CSRs). It does not start a network CA, enroll workers automatically, deliver executable tasks, attest hardware, or authorize Governor jobs.

## Trust boundaries

The CA private key stays on the trusted operator computer (PC 1). The coordinator creates its own server TLS private key, and the worker PC (PC 2) generates its own **separate** client TLS private key and a CSR. Only the client CSR and resulting signed **public** client certificate cross from one machine to the other. Do not copy the worker key to the coordinator. The CA's **public certificate** can be copied to the worker; the CA's private key must never be copied.

The mesh's Ed25519 node heartbeat identity remains separate from its TLS keypair, and both are separate from the Ed25519 Governor signing identity. The normal operator enrollment and certificate pinning processes are still required.

The helper uses ECDSA P-256 and generates a private CA with 365-day validity, BasicConstraints CA=true and pathlen 0. TLS server/client certificates default to 14 days, have a maximum requested validity of 30 days, and have their respective serverAuth/clientAuth usages. Server CSRs and certificates bind an exact private IPv4 or loopback IP SAN. Client CSRs and certificates bind a canonical enrolled node UUID in the subject and URI SAN. A certificate for a different name, role, or SAN is refused.

## PC 1: create the CA (PowerShell)

Run commands from the PhiCortex repository root. The Python cryptography package is optional for ordinary chat, but required here:

~~~powershell
python -m pip install -r requirements-worker.txt
$env:PYTHONPATH = "src"
python -m phicortex.lab_pki init-ca --ca-key "$HOME/.phicortex/lab-ca/ca.key" --ca-cert "$HOME/.phicortex/lab-ca/ca.crt"
~~~

Store the CA private key under a restricted account, **outside any repository or shared cloud folder**. On Windows, review the NTFS ACLs independently; Unix file modes alone are not a complete Windows access-control system. The current lab private keys are unencrypted PKCS#8 PEMs, not hardware-backed production secrets. Record the printed CA certificate fingerprint out of band.

## PC 1: create the coordinator server identity

Replace the example address with PC 1's **actual** private IPv4. The resulting certificate is valid for only that exact IP. If the address changes, issue a new certificate rather than disabling verification.

~~~powershell
python -m phicortex.lab_pki create-csr --role server --server-ip 192.168.1.50 --key "$HOME/.phicortex/credentials/coordinator.key" --csr "$HOME/.phicortex/credentials/coordinator.csr"
python -m phicortex.lab_pki sign-csr --role server --server-ip 192.168.1.50 --ca-key "$HOME/.phicortex/lab-ca/ca.key" --ca-cert "$HOME/.phicortex/lab-ca/ca.crt" --csr "$HOME/.phicortex/credentials/coordinator.csr" --out "$HOME/.phicortex/credentials/coordinator.crt"
~~~

For a loopback-only first test, use 127.0.0.1 in both commands. The program rejects public IPs, wildcards and arbitrary DNS names.

## PC 2: create its own client key and CSR

First use the existing PhiCortex mesh enrollment procedure to create an Ed25519 node identity. On PC 2, create the separate TLS client key using its enrolled node UUID:

~~~powershell
python -m phicortex.lab_pki create-csr --role client --node-id "<enrolled-node-uuid>" --key "$HOME/.phicortex/credentials/node01.key" --csr "$HOME/.phicortex/credentials/node01.csr"
~~~

Transfer **only node01.csr** to PC 1. Verify its origin and node UUID out of band. On PC 1, issue a short-lived clientAuth certificate from that CSR:

~~~powershell
python -m phicortex.lab_pki sign-csr --role client --node-id "<enrolled-node-uuid>" --ca-key "$HOME/.phicortex/lab-ca/ca.key" --ca-cert "$HOME/.phicortex/lab-ca/ca.crt" --csr "<verified-worker-csr-on-PC1>" --out "<new-public-client-cert-on-PC1>"
~~~

Copy the resulting *public* client certificate and the CA's *public* ca.crt back to PC 2. The worker's TLS private key never leaves PC 2, and the CA private key never leaves PC 1.

## Pin client certificate and test the network

On PC 1, bind the signed client certificate to the existing registered Ed25519 node UUID with the trusted operator-only command:

~~~powershell
python -m phicortex.mesh_transport bind-client-cert --db "$HOME/.phicortex/mesh.sqlite3" --node-id "<enrolled-node-uuid>" --cert "<new-public-client-cert-on-PC1>"
~~~

The output includes certificate_sha256. The existing node enrollment output includes a separate public_key_sha256. Supply **both values from the trusted coordinator** to PC 2's mesh_doctor, following [Two-PC Mesh Validation](TWO_PC_MESH_VALIDATION.md).

The TLS coordinator's actual IP SAN must match its private LAN address. Restrict port 8766 with the OS firewall to the known worker; never expose it through a Starlink WAN, router port-forward, public tunnel or wildcard listener.

## Limitations and warnings

The issuer only signs CSR identities matching the requested role, exact IP or node UUID, and role-appropriate subject alternative names. It rejects arbitrary CSR extensions and existing output filenames. It does not automatically rotate/revoke TLS certificates or remotely distribute private keys. A new cert requires a new pin; the current operator workflow refuses replacing an existing node pin, so revoke and re-enroll a **new node identity** to rotate.

Node revocation prevents authenticated application messages from the node, but is not CA-level certificate revocation; a revoked certificate may still complete TLS authentication if signed by the trusted CA. Local Windows ACL protection, CA custody, physical two-PC behavior, firewall rules and gVisor isolation require hands-on verification. CI only tests cross-platform issuance and loopback TLS interoperability.

**No remote execution, no automatic job dispatch, no private keys in GitHub.**
