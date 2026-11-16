"""Ed25519 operator authorization and checked-copy snapshot tests.

These tests mock container execution. They do not attest real gVisor security.
"""
from pathlib import Path
import json
import os
import shutil
import subprocess
import tempfile
import unittest
from unittest import mock

from phicortex.approval_v1 import (
    ApprovalError, create_keypair, issue, verify_and_consume, _load,
)
from phicortex.governor import issue as issue_legacy
from phicortex.snapshot import create_snapshot, verify_snapshot, SnapshotError
from phicortex.worker import plan, execute, WorkerError

IMAGE = "python:3.12-alpine@sha256:" + "a" * 64


class Ed25519SnapshotTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.source = self.root / "original"
        self.source.mkdir()
        (self.source / "main.py").write_text("print('original')\n", encoding="utf-8")
        (self.source / "tests").mkdir()
        (self.source / "tests" / "test_one.py").write_text(
            "import unittest\nclass TestOne(unittest.TestCase):\n"
            "  def test_ok(self): self.assertTrue(True)\n", encoding="utf-8")
        self.manifest = create_snapshot(self.source, self.root / "snapshots")
        self.metadata = verify_snapshot(self.manifest)
        self.snap = Path(self.metadata["workspace"])
        self.job = plan("test", self.snap.parent, self.snap,
                        IMAGE, 30, platform_name="Linux")
        private = self.root / "private.key"
        public = self.root / "public.key"
        create_keypair(private, public)
        self.private = _load(private, private=True)
        self.public = _load(public, private=False)
        self.replay = self.root / "replay.db"

    def test_snapshot_is_independent_of_original_source(self):
        self.assertEqual((self.snap / "main.py").read_text(), "print('original')\n")
        (self.source / "main.py").write_text("print('later')\n")
        self.assertEqual((self.snap / "main.py").read_text(), "print('original')\n")
        self.assertEqual(verify_snapshot(self.manifest)["workspace_sha256"],
                         self.metadata["workspace_sha256"])

    def test_permit_verifies_with_public_key_only_and_refuses_replay(self):
        grant = issue(self.job, self.manifest, self.private, now=1000, ttl=30)
        self.assertNotIn(self.private.hex(), json.dumps(grant))
        verify_and_consume(grant, self.job, self.public, self.replay, now=1010)
        with self.assertRaises(ApprovalError):
            verify_and_consume(grant, self.job, self.public, self.replay, now=1011)

    def test_tampering_scope_or_signature_is_refused(self):
        grant = issue(self.job, self.manifest, self.private, now=1000)
        grant["job"]["timeout_seconds"] = 110
        with self.assertRaisesRegex(ApprovalError, "signature"):
            verify_and_consume(grant, self.job, self.public, self.replay, now=1001)

    def test_another_public_key_cannot_verify(self):
        other_priv = self.root / "other_private"
        other_pub = self.root / "other_public"
        create_keypair(other_priv, other_pub)
        grant = issue(self.job, self.manifest, self.private, now=1000)
        with self.assertRaises(ApprovalError):
            verify_and_consume(grant, self.job, _load(other_pub, private=False),
                               self.replay, now=1001)

    def test_expired_approval_is_refused(self):
        grant = issue(self.job, self.manifest, self.private, now=1000, ttl=5)
        with self.assertRaises(ApprovalError):
            verify_and_consume(grant, self.job, self.public, self.replay, now=1005)

    def test_snapshot_edit_after_signing_is_refused(self):
        grant = issue(self.job, self.manifest, self.private, now=1000)
        (self.snap / "main.py").chmod(0o600)
        (self.snap / "main.py").write_text("changed", encoding="utf-8")
        with self.assertRaises(ApprovalError):
            verify_and_consume(grant, self.job, self.public, self.replay, now=1001)

    def test_missing_or_changed_manifest_refused(self):
        grant = issue(self.job, self.manifest, self.private, now=1000)
        self.manifest.chmod(0o600)
        self.manifest.write_text('{"schema":"invalid"}', encoding="utf-8")
        with self.assertRaises(ApprovalError):
            verify_and_consume(grant, self.job, self.public, self.replay, now=1001)

    def test_rejects_invalid_public_key_file(self):
        public = self.root / "public.key"
        public.write_bytes(b"not-a-valid-ed25519-public-key")
        with self.assertRaises(ApprovalError):
            _load(public, private=False)

    def test_operator_keypair_not_overwritten(self):
        with self.assertRaises(ApprovalError):
            create_keypair(self.root / "private.key", self.root / "public.key")
        self.assertEqual(len(self.public), 32)
        self.assertEqual(len(self.private), 32)

    def test_snapshot_store_inside_source_refused(self):
        with self.assertRaises(SnapshotError):
            create_snapshot(self.source, self.source / "snapshots")

    def test_worker_runs_v1_with_public_key_and_consumes_once(self):
        grant = issue(self.job, self.manifest, self.private)
        process = mock.Mock()
        process.poll.return_value = 0
        process.wait.return_value = 0
        process.returncode = 0
        runner = mock.Mock(return_value=process)
        clean = mock.Mock(return_value=subprocess.CompletedProcess([], 0, "", ""))
        with mock.patch("phicortex.worker.platform.system", return_value="Linux"):
            result = execute(self.job, permit=grant, key=self.public,
                             replay_db=self.replay, guard=lambda: None,
                             launch=runner, cleanup=clean)
            self.assertEqual(result["status"], "passed")
            with self.assertRaisesRegex(WorkerError, "replay"):
                execute(self.job, permit=grant, key=self.public,
                        replay_db=self.replay, guard=lambda: None,
                        launch=runner, cleanup=clean)
        self.assertEqual(runner.call_count, 1)

    def test_legacy_hmac_is_denied_by_default(self):
        legacy = issue_legacy(self.job, b"x" * 32)
        runner = mock.Mock()
        with mock.patch("phicortex.worker.platform.system", return_value="Linux"):
            with self.assertRaisesRegex(WorkerError, "legacy"):
                execute(self.job, permit=legacy, key=b"x" * 32,
                        replay_db=self.replay, guard=lambda: None, launch=runner)
        runner.assert_not_called()


if __name__ == "__main__":
    unittest.main()
