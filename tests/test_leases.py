"""Offline task leasing regression tests; no Docker, LAN, or AI execution."""
from pathlib import Path
import hashlib
import json
import tempfile
import threading
import unittest
from uuid import uuid4

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives.serialization import (
    Encoding, PrivateFormat, PublicFormat, NoEncryption,
)

from phicortex.mesh import NodeRegistry, sign_heartbeat
from phicortex.leases import TaskLeases, LeaseError, sign_result
from phicortex.vault import Vault

D = "a" * 64


def identity():
    key = Ed25519PrivateKey.generate()
    return (key.private_bytes(Encoding.Raw, PrivateFormat.Raw, NoEncryption()),
            key.public_key().public_bytes(Encoding.Raw, PublicFormat.Raw))


class LeaseTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.path = self.root / "shared.sqlite3"
        self.node_db = NodeRegistry(self.path)
        self.leases = TaskLeases(self.path)
        self.node_id = str(uuid4())
        self.secret, pub = identity()
        self.node_db.enroll(self.node_id, "Local Worker", pub,
                            ["test", "build-check"], now=1000)
        self.node_db.accept(sign_heartbeat(self.node_id, 1, self.secret, now=1000),
                            now=1000)
        self.vault = Vault(self.root / "vault")
        self.manifest = self.vault.archive({"status": "passed", "detail": "mock evidence"})
        self.manifest_sha = hashlib.sha256(self.manifest.read_bytes()).hexdigest()
        self.task_id = str(uuid4())

    def create(self, *, tid=None, mode="test", digest=D):
        return self.leases.create(tid or self.task_id, mode, digest, now=1000)

    def lease(self, *, tid=None, node=None, seconds=30, now=1001):
        return self.leases.lease(tid or self.task_id, node or self.node_id, seconds,
                                 now=now)

    def signed(self, leased, *, secret=None, manifest_sha=None, status="passed",
               signed_at=1002):
        return sign_result(leased["task_id"], leased["lease_id"], leased["node_id"],
                           secret if secret is not None else self.secret,
                           manifest_sha or self.manifest_sha, status, now=signed_at)

    def test_create_is_idempotent_and_task_spec_is_immutable(self):
        first = self.create()
        self.assertEqual(first["status"], "pending")
        self.assertEqual(self.leases.create(self.task_id, "test", D, now=1002), first)
        self.assertEqual(len(self.leases.events(self.task_id)), 1)
        with self.assertRaisesRegex(LeaseError, "different immutable"):
            self.create(digest="b" * 64)
        with self.assertRaisesRegex(LeaseError, "allowlist"):
            self.create(tid=str(uuid4()), mode="shell")

    def test_lease_requires_live_enrolled_ready_node_and_approved_mode(self):
        self.create()
        unknown = str(uuid4())
        with self.assertRaises(LeaseError):
            self.lease(node=unknown)
        self.node_db.revoke(self.node_id)
        with self.assertRaisesRegex(LeaseError, "revoked"):
            self.lease()
        self.assertEqual(self.leases.get(self.task_id)["status"], "pending")

    def test_lease_refuses_draining_worker(self):
        self.create()
        self.node_db.accept(sign_heartbeat(self.node_id, 2, self.secret,
                                           state="draining", now=1001), now=1001)
        with self.assertRaisesRegex(LeaseError, "draining"):
            self.lease(now=1002)

    def test_lease_refuses_stale_worker(self):
        self.create()
        with self.assertRaisesRegex(LeaseError, "not fresh"):
            self.lease(now=1090)

    def test_lease_refuses_missing_approved_mode(self):
        self.create(mode="test")
        other = str(uuid4())
        other_secret, other_pub = identity()
        self.node_db.enroll(other, "Only Build", other_pub, ["build-check"], now=1000)
        self.node_db.accept(sign_heartbeat(other, 1, other_secret, now=1000), now=1000)
        with self.assertRaisesRegex(LeaseError, "not enrolled for this task mode"):
            self.lease(node=other)

    def test_lease_is_bounded_by_heartbeat_and_duration(self):
        self.create()
        record = self.lease(seconds=120, now=1002)
        self.assertEqual(record["deadline"], 1090)
        self.assertEqual(record["status"], "leased")
        self.assertFalse(record["execution_authorized"])
        self.assertFalse(record["task_dispatched"])
        self.assertEqual(self.leases.get(self.task_id), record)

    def test_deny_duplicate_lease_and_second_task_on_busy_node(self):
        self.create()
        self.lease()
        with self.assertRaises(LeaseError):
            self.lease()
        other = str(uuid4())
        self.create(tid=other)
        with self.assertRaisesRegex(LeaseError, "already owns"):
            self.lease(tid=other)
        self.assertEqual(self.leases.get(other)["status"], "pending")

    def test_invalid_lease_duration_rejected_without_mutation(self):
        self.create()
        for value in (0, 121, True, 2.5):
            with self.subTest(value=value):
                with self.assertRaises(LeaseError):
                    self.lease(seconds=value)
        self.assertEqual(self.leases.get(self.task_id)["status"], "pending")

    def test_signed_completion_requires_correct_enrolled_identity(self):
        self.create()
        leased = self.lease()
        attacker_key, _ = identity()
        with self.assertRaisesRegex(LeaseError, "signature"):
            self.leases.complete(self.signed(leased, secret=attacker_key),
                                 self.vault.root, self.manifest, now=1002)
        self.assertEqual(self.leases.get(self.task_id)["status"], "leased")

    def test_signed_completion_and_evidence_are_persisted_once(self):
        self.create()
        leased = self.lease()
        signed = self.signed(leased)
        result = self.leases.complete(signed, self.vault.root, self.manifest, now=1002)
        self.assertEqual(result["status"], "completed")
        self.assertEqual(result["result_status"], "passed")
        self.assertEqual(result["evidence_sha256"], self.manifest_sha)
        self.assertFalse(result["execution_authorized"])
        self.assertEqual(self.leases.get(self.task_id), result)
        self.assertEqual([e["kind"] for e in self.leases.events(self.task_id)],
                         ["created", "leased", "completed"])
        with self.assertRaisesRegex(LeaseError, "no matching"):
            self.leases.complete(signed, self.vault.root, self.manifest, now=1003)

    def test_failed_result_is_recorded_without_auto_retry(self):
        self.manifest = self.vault.archive({"status": "failed"})
        self.manifest_sha = hashlib.sha256(self.manifest.read_bytes()).hexdigest()
        self.create()
        leased = self.lease()
        result = self.leases.complete(self.signed(leased, status="failed"),
                                      self.vault.root, self.manifest, now=1002)
        self.assertEqual(result["status"], "completed")
        self.assertEqual(result["result_status"], "failed")
        self.assertIsNone(result["resolution"])

    def test_inconclusive_result_requires_review(self):
        self.manifest = self.vault.archive({"status": "cleanup_unverified"})
        self.manifest_sha = hashlib.sha256(self.manifest.read_bytes()).hexdigest()
        self.create()
        leased = self.lease()
        result = self.leases.complete(self.signed(leased, status="inconclusive"),
                                      self.vault.root, self.manifest, now=1002)
        self.assertEqual(result["status"], "review_required")
        self.assertEqual(result["resolution"], "inconclusive_result")
        with self.assertRaises(LeaseError):
            self.lease()

    def test_expired_completion_cannot_claim_success(self):
        self.create()
        leased = self.lease(seconds=10)
        signed = self.signed(leased, signed_at=1011)
        with self.assertRaisesRegex(LeaseError, "deadline passed"):
            self.leases.complete(signed, self.vault.root, self.manifest, now=1011)
        self.assertEqual(self.leases.reconcile(now=1011), [self.task_id])
        self.assertEqual(self.leases.get(self.task_id)["status"], "review_required")

    def test_reconciliation_does_not_requeue_and_is_idempotent(self):
        self.create()
        self.lease(seconds=10)
        self.assertEqual(self.leases.reconcile(now=1011), [self.task_id])
        self.assertEqual(self.leases.reconcile(now=1012), [])
        self.assertEqual(self.leases.get(self.task_id)["status"], "review_required")
        with self.assertRaises(LeaseError):
            self.lease()
        self.assertEqual([e["kind"] for e in self.leases.events(self.task_id)],
                         ["created", "leased", "review_required"])

    def test_offline_node_does_not_renew_lease(self):
        self.create()
        self.lease(seconds=120, now=1002)
        self.assertEqual(self.leases.reconcile(now=1090), [self.task_id])
        self.assertEqual(self.leases.get(self.task_id)["status"], "review_required")

    def test_revocation_marks_uncertain_lease_for_review(self):
        self.create()
        self.lease()
        self.node_db.revoke(self.node_id)
        self.assertEqual(self.leases.reconcile(now=1003), [self.task_id])
        self.assertIn("revoked", self.leases.get(self.task_id)["resolution"])

    def test_cancel_pending_and_operator_close_review(self):
        self.create()
        self.assertEqual(self.leases.cancel(self.task_id, now=1001)["status"], "cancelled")
        with self.assertRaises(LeaseError):
            self.lease()
        other = str(uuid4())
        self.create(tid=other)
        self.lease(tid=other)
        self.leases.reconcile(now=1032)
        with self.assertRaises(LeaseError):
            self.leases.close(other, "")
        self.assertEqual(self.leases.close(other, "Inspected worker logs", now=1034)["status"], "closed")
        with self.assertRaises(LeaseError):
            self.leases.close(other, "again")

    def test_evidence_hash_mismatch_is_rejected(self):
        self.create()
        leased = self.lease()
        with self.assertRaisesRegex(LeaseError, "evidence digest"):
            self.leases.complete(self.signed(leased, manifest_sha="b" * 64),
                                 self.vault.root, self.manifest, now=1002)

    def test_missing_or_corrupt_evidence_is_rejected(self):
        self.create()
        leased = self.lease()
        body = self.signed(leased)
        (self.vault.blobs / json.loads(self.manifest.read_text())["entries"][0]["sha256"]).write_bytes(b"bad")
        with self.assertRaisesRegex(LeaseError, "missing or corrupt"):
            self.leases.complete(body, self.vault.root, self.manifest, now=1002)

    def test_result_packet_lease_id_tampering_is_rejected(self):
        self.create()
        leased = self.lease()
        bad = self.signed(leased)
        bad["body"]["lease_id"] = str(uuid4())
        with self.assertRaisesRegex(LeaseError, "no matching"):
            self.leases.complete(bad, self.vault.root, self.manifest, now=1002)

    def test_stale_and_future_result_messages_rejected(self):
        self.create()
        leased = self.lease()
        for when in (900, 1013):
            signed = self.signed(leased, signed_at=when)
            with self.assertRaises(LeaseError):
                self.leases.complete(signed, self.vault.root, self.manifest, now=1002)

    def test_concurrent_claims_only_one_lease(self):
        self.create()
        ok, denied = [], []
        def claim():
            try:
                ok.append(self.lease())
            except LeaseError as exc:
                denied.append(str(exc))
        threads = [threading.Thread(target=claim) for _ in range(6)]
        for thread in threads: thread.start()
        for thread in threads: thread.join()
        self.assertEqual(len(ok), 1)
        self.assertEqual(len(denied), 5)

    def test_state_is_durable_across_coordinator_restart(self):
        self.create()
        first = self.lease()
        resumed = TaskLeases(self.path)
        self.assertEqual(resumed.get(self.task_id), first)
        self.assertEqual(resumed.reconcile(now=1031), [self.task_id])
        self.assertEqual(TaskLeases(self.path).get(self.task_id)["status"], "review_required")

    def test_operator_metadata_cannot_execute_code(self):
        self.create()
        details = self.lease()
        self.assertFalse(details["execution_authorized"])
        self.assertFalse(details["task_dispatched"])
        self.assertNotIn("argv", details)
        self.assertNotIn("shell", json.dumps(details))
        self.assertNotIn("private_key", json.dumps(details))
        self.assertEqual(len(self.leases.list()), 1)

    def test_failure_evidence_cannot_be_signed_as_passed(self):
        self.create()
        leased = self.lease()
        failure = self.vault.archive({"status": "failed"})
        digest = hashlib.sha256(failure.read_bytes()).hexdigest()
        with self.assertRaisesRegex(LeaseError, "conflicts"):
            self.leases.complete(self.signed(leased, manifest_sha=digest, status="passed"),
                                 self.vault.root, failure, now=1002)
        self.assertEqual(self.leases.get(self.task_id)["status"], "leased")

    def test_untrusted_result_status_type_is_denied(self):
        self.create()
        leased = self.lease()
        packet = self.signed(leased)
        packet["body"]["result_status"] = []
        with self.assertRaises(LeaseError):
            self.leases.complete(packet, self.vault.root, self.manifest, now=1002)

    def test_signed_result_rejects_unknown_types(self):
        self.create()
        item = self.lease()
        with self.assertRaises(LeaseError):
            sign_result(item["task_id"], item["lease_id"], self.node_id,
                        self.secret, self.manifest_sha, "deploy", now=1002)


if __name__ == "__main__":
    unittest.main()
