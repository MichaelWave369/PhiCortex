"""Governor permit and content-addressed vault regression tests (no Docker required)."""
import hashlib
import json
import os
import subprocess
from pathlib import Path
import tempfile
import unittest
from unittest import mock

from phicortex.governor import (
    GovernorError, init_key, issue, load_key, verify_and_consume,
    workspace_digest, write_permit,
)
from phicortex.vault import Vault, VaultError
from phicortex.worker import WorkerError, plan, execute

IMAGE = "python:3.12-alpine@sha256:" + "a" * 64


class GovernanceTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.root = Path(self.tmp.name)
        self.workspace = self.root / "project"
        self.workspace.mkdir()
        (self.workspace / "task.py").write_text("print('hello')\n", encoding="utf-8")
        self.job = plan("test", self.root, self.workspace, IMAGE, 30, platform_name="Linux")
        self.key = b"x" * 32
        self.ledger = self.root / "nonce-ledger.sqlite3"

    def test_valid_permit_consumes_once(self):
        grant = issue(self.job, self.key, now=1000, ttl=60)
        verify_and_consume(grant, self.job, self.key, self.ledger, now=1010)
        with self.assertRaisesRegex(GovernorError, "replay"):
            verify_and_consume(grant, self.job, self.key, self.ledger, now=1011)

    def test_tampering_with_signed_scope_refused(self):
        grant = issue(self.job, self.key, now=1000)
        grant["job"]["timeout_seconds"] = 100
        with self.assertRaisesRegex(GovernorError, "signature"):
            verify_and_consume(grant, self.job, self.key, self.ledger, now=1001)

    def test_scope_mismatch_rejected_even_with_valid_signature(self):
        grant = issue(self.job, self.key, now=1000)
        other = plan("build-check", self.root, self.workspace, IMAGE, 30,
                     platform_name="Linux")
        with self.assertRaisesRegex(GovernorError, "does not authorize"):
            verify_and_consume(grant, other, self.key, self.ledger, now=1001)

    def test_expired_future_and_extended_ttls_refused(self):
        with self.assertRaises(GovernorError):
            issue(self.job, self.key, ttl=301, now=1000)
        grant = issue(self.job, self.key, ttl=60, now=1000)
        for current in (900, 1060, 1061):
            with self.assertRaises(GovernorError):
                verify_and_consume(grant, self.job, self.key, self.ledger, now=current)

    def test_workspace_mutation_invalidates_approval(self):
        grant = issue(self.job, self.key, now=1000)
        before = workspace_digest(self.workspace)
        (self.workspace / "task.py").write_text("print('changed')\n", encoding="utf-8")
        self.assertNotEqual(before, workspace_digest(self.workspace))
        with self.assertRaisesRegex(GovernorError, "workspace changed"):
            verify_and_consume(grant, self.job, self.key, self.ledger, now=1001)

    def test_key_file_exclusive_creation_and_permit_serialization(self):
        key_file = self.root / "operator.key"
        init_key(key_file)
        self.assertEqual(len(load_key(key_file)), 32)
        with self.assertRaises(GovernorError):
            init_key(key_file)
        grant = issue(self.job, load_key(key_file), now=1000)
        saved = self.root / "approval.json"
        write_permit(saved, grant)
        self.assertEqual(json.loads(saved.read_text()), grant)
        with self.assertRaises(GovernorError):
            write_permit(saved, grant)
        self.assertNotIn(load_key(key_file).hex(), saved.read_text())

    def test_worker_never_launches_without_permit(self):
        launcher = mock.Mock()
        with mock.patch("phicortex.worker.platform.system", return_value="Linux"):
            with self.assertRaisesRegex(WorkerError, "permit"):
                execute(self.job, guard=lambda: None, launch=launcher)
        launcher.assert_not_called()

    def test_worker_checks_grant_and_replay_before_running(self):
        grant = issue(self.job, self.key)
        fake = mock.Mock()
        fake.poll.return_value = 0
        fake.wait.return_value = 0
        fake.returncode = 0
        launched = mock.Mock(return_value=fake)
        cleaned = mock.Mock(return_value=subprocess.CompletedProcess([], 0, "", ""))
        with mock.patch("phicortex.worker.platform.system", return_value="Linux"):
            result = execute(self.job, permit=grant, key=self.key, replay_db=self.ledger,
                             guard=lambda: None, launch=launched, cleanup=cleaned)
            self.assertEqual(result["status"], "passed")
            self.assertEqual(launched.call_count, 1)
            with self.assertRaisesRegex(WorkerError, "replay"):
                execute(self.job, permit=grant, key=self.key, replay_db=self.ledger,
                        guard=lambda: None, launch=launched, cleanup=cleaned)
        self.assertEqual(launched.call_count, 1)


    def test_cleanup_failure_is_not_misreported_as_pass(self):
        grant = issue(self.job, self.key)
        process = mock.Mock()
        process.poll.return_value = 0
        process.wait.return_value = 0
        process.returncode = 0
        bad_cleanup = mock.Mock(return_value=subprocess.CompletedProcess(
            [], 2, "", "permission denied"))
        with mock.patch("phicortex.worker.platform.system", return_value="Linux"):
            result = execute(self.job, permit=grant, key=self.key, replay_db=self.ledger,
                             guard=lambda: None, launch=lambda *a, **k: process,
                             cleanup=bad_cleanup)
        self.assertEqual(result["status"], "cleanup_unverified")
        self.assertEqual(bad_cleanup.call_count, 1)

    def test_replay_ledger_must_remain_outside_workspace(self):
        grant = issue(self.job, self.key)
        with mock.patch("phicortex.worker.platform.system", return_value="Linux"):
            with self.assertRaisesRegex(WorkerError, "outside"):
                execute(self.job, permit=grant, key=self.key,
                        replay_db=self.workspace / "nonce.db", guard=lambda: None)


class VaultTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.root = Path(self.tmp.name)
        self.workspace = self.root / "workspace"
        self.workspace.mkdir()
        (self.workspace / "result.txt").write_text("artifact bytes", encoding="utf-8")
        self.vault = Vault(self.root / "vault")

    def test_report_and_selected_file_are_content_addressed(self):
        manifest = self.vault.archive({"status": "failed", "detail": "real failure"},
                                      workspace=self.workspace, include=["result.txt"])
        self.assertTrue(self.vault.verify(manifest))
        obj = json.loads(manifest.read_text())
        self.assertEqual(obj["evidence_status"], "failed")
        self.assertEqual(len(obj["entries"]), 2)
        self.assertEqual(obj["entries"][1]["sha256"],
                         hashlib.sha256(b"artifact bytes").hexdigest())
        self.assertEqual(self.vault.put(b"artifact bytes")["sha256"],
                         obj["entries"][1]["sha256"])

    def test_corruption_and_missing_blob_are_detected(self):
        manifest = self.vault.archive({"status": "passed"})
        ref = json.loads(manifest.read_text())["entries"][0]["sha256"]
        (self.vault.blobs / ref).write_bytes(b"corrupt")
        with self.assertRaises(VaultError):
            self.vault.verify(manifest)
        with self.assertRaises(VaultError):
            self.vault.put(b'{"status":"passed"}')

    def test_traversal_and_symlinks_refused(self):
        for name in ("../secret", "/absolute", "sub/../../escape", "C:\\secret"):
            with self.assertRaises(VaultError):
                self.vault.archive({"status": "failed"}, workspace=self.workspace,
                                   include=[name])
        outside = self.root / "outside.txt"
        outside.write_text("not allowed")
        link = self.workspace / "outside-link"
        try:
            link.symlink_to(outside)
        except OSError:
            return
        with self.assertRaises(VaultError):
            self.vault.archive({"status": "failed"}, workspace=self.workspace,
                               include=["outside-link"])

    def test_missing_selected_file_fails_and_large_payload_refused(self):
        with self.assertRaises(VaultError):
            self.vault.archive({"status": "failed"}, workspace=self.workspace,
                               include=["missing.txt"])
        with self.assertRaises(VaultError):
            self.vault.put(b"x" * (2 * 1024 * 1024 + 1))


if __name__ == "__main__":
    unittest.main()
