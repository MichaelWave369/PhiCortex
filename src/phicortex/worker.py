"""Guarded local Python build-check/test runner. No chat/API integration.

Code executes only via a locally verified Docker daemon with a registered
gVisor runsc runtime. This is a cautious prototype, not a complete Governor.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import os
from pathlib import Path
import platform
import re
import subprocess
import tempfile
import time
from uuid import uuid4
from .governor import verify_and_consume, load_key, GovernorError
from .vault import Vault, VaultError

IMAGE_RE = re.compile(r"^[a-zA-Z0-9][a-zA-Z0-9._/:\-]*@sha256:[0-9a-f]{64}$")
MAX_OUTPUT_BYTES = 64 * 1024
MAX_SECONDS = 120
MAX_WORKSPACE_FILES = 2000

# No shell, user-authored command or host subprocess execution of project code.
BUILD_CHECK = [
    "python", "-B", "-c",
    "import ast; from pathlib import Path; "
    "fs=sorted(p for p in Path('/workspace').rglob('*.py') if p.is_file()); "
    "[ast.parse(p.read_text(encoding='utf-8'),filename=str(p)) for p in fs]; "
    "print('Syntax checked %d Python files' % len(fs))"
]
TEST = ["python", "-B", "-m", "unittest", "discover", "-s", "tests", "-v"]


class WorkerError(RuntimeError):
    pass


def validate_workspace(root: Path, workspace: Path) -> Path:
    root = root.expanduser().resolve(strict=True)
    workspace = workspace.expanduser().resolve(strict=True)
    if not root.is_dir() or not workspace.is_dir():
        raise WorkerError("root and workspace must be directories")
    try:
        workspace.relative_to(root)
    except ValueError as exc:
        raise WorkerError("workspace escapes the explicitly authorized root") from exc
    # A symlink inside a source tree could reach outside the mounted area or
    # obscure the test input. Reject it rather than guessing.
    count = 0
    for entry in workspace.rglob("*"):
        count += 1
        if count > MAX_WORKSPACE_FILES:
            raise WorkerError("workspace contains too many entries")
        if entry.is_symlink():
            raise WorkerError("workspace symlinks are not allowed")
    return workspace


def plan(mode: str, root: Path, workspace: Path, image: str,
         seconds: int = 30, *, platform_name: str | None = None) -> dict:
    if mode not in {"build-check", "test"}:
        raise WorkerError("mode must be build-check or test; arbitrary commands are disabled")
    if type(seconds) is not int or not 1 <= seconds <= MAX_SECONDS:
        raise WorkerError("timeout must be 1-120 seconds")
    if not isinstance(image, str) or not IMAGE_RE.fullmatch(image) or ".." in image:
        raise WorkerError("image must be a fully pinned name@sha256:<64 lowercase hex>")
    workspace = validate_workspace(root, workspace)
    # Docker --mount parses commas as option separators. Never let an
    # operator-controlled path modify the mount contract.
    if any(ch in str(workspace) for ch in (",", chr(10), chr(13))):
        raise WorkerError("workspace path contains Docker mount separators")
    if (platform_name or platform.system()) != "Linux":
        raise WorkerError("execution requires a tested Linux host; Windows may use a dedicated Linux worker")
    name = "phicortex-" + uuid4().hex[:16]
    cmd = [
        "docker", "run", "--rm", "--pull=never", "--name", name,
        "--runtime=runsc", "--network=none", "--read-only",
        "--cap-drop=ALL", "--security-opt=no-new-privileges",
        "--user=65534:65534", "--pids-limit=64", "--memory=512m", "--cpus=1",
        "--tmpfs=/tmp:rw,nosuid,noexec,size=64m",
        "--workdir=/workspace", "--env=PYTHONDONTWRITEBYTECODE=1",
        "--mount=type=bind,source=" + str(workspace) + ",target=/workspace,readonly",
        image,
        *(BUILD_CHECK if mode == "build-check" else TEST),
    ]
    return {"schema": "phicortex.worker.v0", "mode": mode,
            "authorized_root": str(root.expanduser().resolve(strict=True)),
            "workspace": str(workspace), "image": image,
            "timeout_seconds": seconds, "container_name": name,
            "argv": cmd, "isolation": "docker-runsc-required",
            "network": "none", "host_code_execution": False,
            "build_meaning": "syntax-only" if mode == "build-check" else None}


def _docker_env() -> dict:
    # Avoid forwarding operator tokens, SSH agent or cloud credentials to CLI.
    return {k: v for k, v in os.environ.items() if k in ("PATH", "HOME", "SYSTEMROOT", "WINDIR")}


def _docker_capture(argv: list[str]) -> str:
    try:
        value = subprocess.run(argv, capture_output=True, text=True,
                               timeout=8, env=_docker_env(), check=True)
    except (OSError, subprocess.SubprocessError) as exc:
        raise WorkerError("local Docker capability check failed") from exc
    return value.stdout.strip()


def require_runsc() -> None:
    """Default fail-closed guard; not a formal attestation of daemon security."""
    host = _docker_capture(["docker", "context", "inspect", "--format",
                            "{{.Endpoints.docker.Host}}"])
    if host != "unix:///var/run/docker.sock":
        raise WorkerError("only a local Linux Docker socket is accepted")
    if _docker_capture(["docker", "info", "--format", "{{.OSType}}"]) != "linux":
        raise WorkerError("Docker daemon must be Linux")
    try:
        runtimes = json.loads(_docker_capture(["docker", "info", "--format",
                                                "{{json .Runtimes}}"]))
    except ValueError as exc:
        raise WorkerError("cannot parse daemon runtime list") from exc
    if not isinstance(runtimes, dict) or "runsc" not in runtimes:
        raise WorkerError("gVisor runsc is not registered; refusing host execution")


def execute(job: dict, *, permit: dict | None = None, key: bytes | None = None,
            replay_db: Path | None = None, guard=require_runsc,
            launch=subprocess.Popen, cleanup=subprocess.run) -> dict:
    """Run with bounded output and forced cleanup, after runtime verification.

    Never takes commands from a model and does not mount credentials, sockets,
    network adapters, or the host home directory.
    """
    if job.get("schema") != "phicortex.worker.v0" or not isinstance(job.get("argv"), list):
        raise WorkerError("invalid job plan")
    if platform.system() != "Linux":
        raise WorkerError("execution is disabled outside a Linux host")
    name = job.get("container_name")
    if not isinstance(name, str) or not re.fullmatch(r"phicortex-[0-9a-f]{16}", name):
        raise WorkerError("invalid container name")
    try:
        canonical = plan(job["mode"], Path(job["authorized_root"]),
                         Path(job["workspace"]), job["image"],
                         job["timeout_seconds"], platform_name="Linux")
    except (KeyError, TypeError, ValueError) as exc:
        raise WorkerError("invalid job contract") from exc
    canonical["argv"][canonical["argv"].index("--name") + 1] = name
    canonical["container_name"] = name
    if job != canonical:
        raise WorkerError("modified execution contract refused")
    if permit is None or key is None or replay_db is None:
        raise WorkerError("operator permit, key and replay ledger required")
    workspace = Path(job["workspace"])
    for sensitive in (replay_db,):
        selected = Path(sensitive).expanduser().resolve()
        if selected == workspace or workspace in selected.parents:
            raise WorkerError("replay ledger must remain outside the mounted workspace")
    # Preflight before consuming an approval; allow no host execution fallback.
    guard()
    try:
        verify_and_consume(permit, job, key, replay_db)
    except GovernorError as exc:
        raise WorkerError("governor refused job: " + str(exc)) from exc
    cmd = canonical["argv"]
    start = time.monotonic()
    status, code, output = "failed", None, ""
    name = job["container_name"]
    try:
        with tempfile.TemporaryFile(mode="w+b") as log:
            proc = launch(cmd, shell=False, stdout=log, stderr=subprocess.STDOUT,
                          stdin=subprocess.DEVNULL, env=_docker_env())
            try:
                while proc.poll() is None:
                    if time.monotonic() - start > job["timeout_seconds"]:
                        status = "timed_out"
                        proc.kill()
                        break
                    if os.fstat(log.fileno()).st_size > MAX_OUTPUT_BYTES:
                        status = "output_limit"
                        proc.kill()
                        break
                    time.sleep(0.05)
                try:
                    proc.wait(timeout=2)
                except subprocess.TimeoutExpired:
                    proc.kill()
                    proc.wait(timeout=2)
                code = proc.returncode
                if status not in ("timed_out", "output_limit"):
                    status = "passed" if code == 0 else "failed"
            finally:
                log.flush()
                log.seek(0)
                output = log.read(MAX_OUTPUT_BYTES).decode("utf-8", errors="replace")
    finally:
        # Kill a container that might survive a disconnected Docker client.
        # Fixed, validated name only. Never run shell commands.
        try:
            cleanup(["docker", "rm", "-f", name], capture_output=True,
                    text=True, timeout=8, env=_docker_env(), check=False)
        except (OSError, subprocess.SubprocessError):
            # Report cleanup uncertainty rather than claiming containment.
            status = "cleanup_unverified"
    return {"schema": "phicortex.worker.result.v0", "status": status,
            "mode": job["mode"], "exit_code": code,
            "duration_ms": int((time.monotonic() - start) * 1000),
            "output": output, "output_truncated": len(output.encode("utf-8")) >= MAX_OUTPUT_BYTES,
            "task_sha256": hashlib.sha256(json.dumps(
                {k: job[k] for k in ("mode", "workspace", "image", "timeout_seconds")},
                sort_keys=True).encode()).hexdigest(),
            "isolation_requested": job["isolation"],
            "isolation_independently_attested": False,
            "source_modified_by_worker": False}


def main(argv=None) -> int:
    parser = argparse.ArgumentParser(description="Local gVisor-gated build-check/test runner")
    parser.add_argument("--workspace-root", required=True, type=Path)
    parser.add_argument("--workspace", required=True, type=Path)
    parser.add_argument("--image", required=True, help="locally installed image@sha256:digest")
    parser.add_argument("--mode", required=True, choices=("build-check", "test"))
    parser.add_argument("--seconds", type=int, default=30)
    parser.add_argument("--out", type=Path, required=True, help="report path outside workspace")
    parser.add_argument("--execute", action="store_true", help="opt-in execution")
    parser.add_argument("--permit-file", type=Path, help="signed operator approval outside workspace")
    parser.add_argument("--key-file", type=Path, help="owner-only 32-byte governor key")
    parser.add_argument("--replay-db", type=Path, help="durable single-use approval ledger")
    parser.add_argument("--vault", type=Path, help="evidence vault directory outside workspace")
    parser.add_argument("--include", action="append", default=[], help="explicit workspace-relative evidence file")
    args = parser.parse_args(argv)
    try:
        job = plan(args.mode, args.workspace_root, args.workspace, args.image,
                   args.seconds)
        report_path = args.out.expanduser().resolve()
        if report_path == Path(job["workspace"]) or Path(job["workspace"]) in report_path.parents:
            raise WorkerError("report cannot overwrite the mounted workspace")
        if args.execute:
            if os.environ.get("PHICORTEX_ALLOW_ISOLATED_JOBS") != "1":
                raise WorkerError("set PHICORTEX_ALLOW_ISOLATED_JOBS=1 to opt in")
            if not all((args.permit_file, args.key_file, args.replay_db, args.vault)):
                raise WorkerError("--permit-file, --key-file, --replay-db and --vault are required")
            # No approvals, private keys, replay databases or vaults in mounted source.
            for sensitive in (args.permit_file, args.key_file, args.replay_db, args.vault):
                selected = sensitive.expanduser().resolve()
                if selected == Path(job["workspace"]) or Path(job["workspace"]) in selected.parents:
                    raise WorkerError("security credentials and evidence must stay outside workspace")
            try:
                permit = json.loads(args.permit_file.read_text(encoding="utf-8"))
                key = load_key(args.key_file)
            except (OSError, ValueError, GovernorError) as exc:
                raise WorkerError("could not load operator grant") from exc
            report = execute(job, permit=permit, key=key, replay_db=args.replay_db)
        else:
            report = {k: v for k, v in job.items() if k != "argv"}
            report["status"] = "dry_run_only"
            report["isolation_independently_attested"] = False
        report_path.parent.mkdir(parents=True, exist_ok=True)
        report_path.write_text(json.dumps(report, sort_keys=True, indent=2) + "\n",
                               encoding="utf-8")
        if args.execute:
            try:
                vault = Vault(args.vault)
                manifest = vault.archive(report, workspace=Path(job["workspace"]), include=args.include)
                if not vault.verify(manifest):
                    raise VaultError("evidence verification unsuccessful")
                print(f"Evidence manifest: {manifest}")
            except VaultError as exc:
                raise WorkerError("evidence archive failed: " + str(exc)) from exc
        print(f"{report['status']}: {report_path}")
        return 0 if report["status"] in ("passed", "dry_run_only") else 1
    except (WorkerError, OSError, ValueError) as exc:
        parser.exit(2, f"refused: {exc}\n")


if __name__ == "__main__":
    raise SystemExit(main())
