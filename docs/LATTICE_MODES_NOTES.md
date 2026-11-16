# LATTICE Foundation: Advisory Modes and Project Notes

**Status:** local, operator-directed primitives. These are not autonomous
DREAM/BUILD/TEST engines, semantic memory, a persistent multi-turn mode
state machine, or a trained routing policy.

## Request-scoped inference modes

The existing loopback-only POST /v1/chat/completions endpoint accepts an
optional top-level mode with values **chat**, **dream**, **build**, **test**.

~~~json
{"model":"phicortex-auto","mode":"build","messages":[{"role":"user","content":"Explain a Python unit test plan"}]}
~~~

| Mode | Registered model role | Actual authority |
| --- | --- | --- |
| chat | chat | Advisory text generation only |
| dream | reason, falling back to chat | Advisory text generation only |
| build | code | Advisory text generation only, no filesystem writes |
| test | code | Advisory text generation only, no test execution |

An explicit registered model selection still takes precedence over the
mode's default role. Unknown models and modes fail closed. If the mode
field is omitted, the original deterministic keyword classifier is used
unchanged. A selected mode is recorded with its source and route reason
in the event ledger, without transcript text by default.

This is **request-scoped routing**, not a persistent state machine:
conversation UI turns still use ordinary chat. Slash commands /build,
/test and /dream remain blocked; nothing in this change contacts the
Governor, runs a sandbox, schedules agents, or proves CPU-only inference.

## Versioned Markdown notes

Manual local CLI: **python -m phicortex.project_notes**. It uses a SQLite
database chosen explicitly with --db. It does not add a network endpoint,
auto-load saved content into prompts, or modify weights.

Each note belongs to a lowercase project slug, has a note ID, a title,
and an exact UTF-8 Markdown body. Each operator edit creates a separate
immutable-by-application version row. The current active version is
indexed in SQLite FTS5; historical versions are available by exact lookup.
Search is project-scoped and returns the precise version, digest,
citation, title and excerpt. Citation format:

~~~text
phicortex-note:phicortex/architecture@v2#sha256:<64-lowercase-hex>
~~~

The SHA-256 digest identifies the exact UTF-8 Markdown content of that
version. A citation is a local logical source reference, not an online
link, digital signature or tamper-proof evidence.

### Operator example (PowerShell)

From the repository root:

~~~powershell
$env:PYTHONPATH = "src"
$notes = "$HOME/.phicortex/project-notes.sqlite3"
New-Item -ItemType Directory -Force "$HOME/.phicortex" | Out-Null
Set-Content -Encoding utf8 "$HOME/.phicortex/architecture-v1.md" "# Architecture"

python -m phicortex.project_notes create --db $notes --project phicortex --note-id architecture --title "Architecture" --file "$HOME/.phicortex/architecture-v1.md"
python -m phicortex.project_notes search --db $notes --project phicortex --query "Architecture"
python -m phicortex.project_notes get --db $notes --project phicortex --note-id architecture --version 1
~~~

To revise, edit a new Markdown source file and supply the last version
you reviewed. Stale versions cannot overwrite newer content:

~~~powershell
python -m phicortex.project_notes revise --db $notes --project phicortex --note-id architecture --title "Architecture v2" --file "$HOME/.phicortex/architecture-v2.md" --expected-version 1
python -m phicortex.project_notes versions --db $notes --project phicortex --note-id architecture
python -m phicortex.project_notes export --db $notes --project phicortex --note-id architecture --version 1 --out "$HOME/.phicortex/export-v1.md"
~~~

Exports are ordinary Markdown and refuse to overwrite an existing file.
Note contents are always untrusted **data**, never executable commands
or priority instructions. No automatic retrieval or prompt injection
is implemented.

### Archive, retention, purge

Archive removes current search hits while retaining past versions:

~~~powershell
python -m phicortex.project_notes archive --db $notes --project phicortex --note-id architecture
~~~

Permanent application-level purge requires archive first plus exact
scoped confirmation:

~~~powershell
python -m phicortex.project_notes purge --db $notes --project phicortex --note-id architecture --confirm "PURGE:phicortex/architecture"
~~~

The Markdown body and FTS5 index are PLAINTEXT on disk. Secure-delete
settings and row deletion do not guarantee erasure from backups, old SSD
blocks, journals or copies. Operator file permissions and retention
practices matter; do not store secrets casually.

## Acceptance and future gates

- Explicit modes choose registered specialist roles and record their
  reasons, without giving chat any new capabilities.
- Legacy no-mode routing behaves the same.
- Note revisions survive restart and old versions retain exact source IDs.
- Active versions search correctly, archived versions disappear from FTS,
  and purge requires an explicit operator confirmation.
- Default transcript retention is unchanged (off).
- Windows/Linux test suites must pass.
- Persistent operator-controlled mode transitions, retrieval consent,
  outcome-measured routing, semantic memory, and real sandbox execution
  remain separate future milestones.
