# PhiCortex Governor and Evidence Vault v0

**State:** experimental operator-run, Linux-only execution path. Not a
security-certified Governor, not an immutable ledger, not an autonomous
agent and not a browser-exposed service.

## Security model

The trusted operator creates a 32-byte random HMAC secret and issues a
**single-use**, short-lived task permit. The permit authorizes only one
mode (`build-check` or `test`), root, workspace, fully pinned image and
timeout. It also stores a SHA-256 of the current small workspace tree.
The worker verifies the signature, exact requested task, expiration,
content digest, and nonce before launching any Docker process. The nonce
is committed to a durable local SQLite replay ledger before the job starts.
Each execution needs a new permit, including retries.

The worker still requires local Linux Docker, an explicitly registered
gVisor `runsc` runtime, fixed commands, `--network=none`, read-only
mounts, resource quotas, short deadlines and explicit execution opt-in.
No fallback to host execution or ordinary `runc`.

### Trust boundaries that are still missing

- The HMAC verification key is available to the trusted worker process.
  There is **not yet a separate OS account/service boundary** or a remote
  signer with asymmetric verification. Host compromise or misuse of the
  key can defeat the permit system. Protect the secret outside the source
  workspace, backed-up folders and model input.
- Workspace hashing does not freeze the filesystem. Another host process
  could modify content after verification. A future worker must execute
  against an immutable, independently stored snapshot.
- Docker/gVisor is not attested or adversarially evaluated by these unit
  tests. A local Docker daemon can remain highly privileged.
- The evidence vault is a local set of SHA-256 blobs and JSON manifests,
  not a signed immutable audit log, remote backup, or confidential store.
  Reports may include sensitive test output. Only store inside a private
  OS-account directory; do not expose it via the web server.
- Windows runs contract tests only. Linux execution requires actual
  host setup and a separate containment-validation campaign.

## Operator walkthrough: dedicated Linux host only

Use a real locally installed pinned Python image digest. These commands
do not download or trust any model-generated arbitrary shell commands.
The same task details must be supplied to the permit issuer and worker.

1. Generate a key outside your project source (never overwrite an existing key):

~~~bash
export PYTHONPATH=src
umask 077
python -m phicortex.governor init-key --key-file "$HOME/.phicortex/operator.key"
~~~

2. Approve exactly one task after inspecting the source tree:

~~~bash
python -m phicortex.governor approve \
  --key-file "$HOME/.phicortex/operator.key" \
  --workspace-root "$HOME/workspaces" \
  --workspace "$HOME/workspaces/small-demo" \
  --image "python:3.12-alpine@sha256:<actual-digest>" \
  --mode test --seconds 30 --ttl 60 \
  --out "$HOME/.phicortex/grant.json"
~~~

3. Use that permit once, while it is valid:

~~~bash
export PHICORTEX_ALLOW_ISOLATED_JOBS=1
python -m phicortex.worker \
  --workspace-root "$HOME/workspaces" \
  --workspace "$HOME/workspaces/small-demo" \
  --image "python:3.12-alpine@sha256:<actual-digest>" \
  --mode test --seconds 30 --execute \
  --permit-file "$HOME/.phicortex/grant.json" \
  --key-file "$HOME/.phicortex/operator.key" \
  --replay-db "$HOME/.phicortex/replay.sqlite3" \
  --vault "$HOME/.phicortex/vault" \
  --out "$HOME/.phicortex/latest-result.json"
~~~

The default remains a **non-executing dry run**. Generated-code execution
is NOT accessible through CHAT, DREAM, the HTTP API, or any other agent.
`build-check` is only Python syntax checking, not real code generation.
No source writing happens in the container.

Optional `--include relative/path.txt` files are copied to the vault
after execution, at most 25 files of up to 2 MiB each. No directories,
symlinks, absolute paths or parent traversal. Results and source evidence
are not automatically uploaded to GitHub.

The CLI writes the local job report and creates a vault manifest under
`<vault>/manifests/<id>.json`. The manifest points to SHA-256-addressed
blobs under `<vault>/blobs/`. You can verify the manifest using:

~~~python
from pathlib import Path
from phicortex.vault import Vault
vault = Vault(Path.home() / ".phicortex" / "vault")
assert vault.verify(Path.home() / ".phicortex" / "vault" / "manifests" / "<id>.json")
~~~

## Acceptance gates to raise the trust level

1. Separate the signer from the worker's OS account and use independently
   verified asymmetric approval signatures.
2. Copy projects to immutable, content-addressed execution snapshots.
3. Adversarially validate network isolation, filesystem confinement,
   quotas and container cleanup on a real Linux host.
4. Introduce authenticated worker identities, protected event logs and
   denial tests against model-generated instructions.
5. Only then integrate an operator-approved job flow into the API.

**This PR only establishes testable contract and evidence plumbing.**
