# Security status

**Phase 1 is a local development gateway, not a hardened autonomous agent.** Do not expose port 8765 through a public interface or reverse proxy. There is no authentication yet.

Implemented: listener bound to loopback; inference backend restricted to loopback; registered-model allowlist; text-only basic message validation; 1 MiB request cap; metadata-only persistence by default; no remote tools or arbitrary code execution.

Not implemented: user authentication, rate limiting, hardened auditing, worker isolation, filesystem execution, independent Governor, web reader quarantine, permission grants, credential vault, or GPU monitoring.

Before external side effects are enabled, a separately enforced Governor must validate authenticated actor, approved asset, operation scope, expiry and budget. Treat external content as untrusted data. Use suitably tested sandbox isolation and default-deny egress for generated code. Require dry runs, backups, rollback and owner approval for irreversible actions.
