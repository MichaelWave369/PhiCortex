import json
import sqlite3
import tempfile
import threading
import unittest
from pathlib import Path
from uuid import uuid4

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives.serialization import Encoding, PrivateFormat, PublicFormat, NoEncryption

from phicortex.mesh import NodeRegistry, MeshError, canonical, sign_heartbeat, MAX_PACKET_BYTES


class MeshRegistryTests(unittest.TestCase):
    def setUp(self):
        self.t = tempfile.TemporaryDirectory()
        self.addCleanup(self.t.cleanup)
        self.path = Path(self.t.name) / "coordinator.sqlite3"
        self.registry = NodeRegistry(self.path)
        self.node = str(uuid4())
        private = Ed25519PrivateKey.generate()
        self.secret = private.private_bytes(Encoding.Raw, PrivateFormat.Raw, NoEncryption())
        self.public = private.public_key().public_bytes(Encoding.Raw, PublicFormat.Raw)
        self.enrolled = self.registry.enroll(self.node, "Worker Lab 1", self.public, ["test"], now=1000)

    def packet(self, seq=1, state="ready", when=1000):
        return sign_heartbeat(self.node, seq, self.secret, state=state, now=when)

    def test_manual_enrollment_and_key_not_exposed(self):
        self.assertEqual(self.enrolled["status"], "enrolled")
        nodes = self.registry.list_nodes(now=1000)
        self.assertEqual(nodes[0]["status"], "enrolled")
        self.assertEqual(nodes[0]["approved_modes"], ["test"])
        self.assertNotIn(self.secret.hex(), json.dumps(nodes))
        self.assertFalse(nodes[0]["hardware_capabilities_verified"])
        self.assertFalse(nodes[0]["execution_authorized"])

    def test_signed_heartbeat_liveness_and_expiry(self):
        result = self.registry.accept(self.packet(), now=1001)
        self.assertEqual(result["status"], "online")
        self.assertEqual(result["expires_at"], 1091)
        self.assertEqual(self.registry.list_nodes(now=1090)[0]["status"], "online")
        self.assertEqual(self.registry.list_nodes(now=1091)[0]["status"], "offline")

    def test_draining_is_not_available_for_work(self):
        self.registry.accept(self.packet(state="draining"), now=1000)
        self.assertEqual(self.registry.list_nodes(now=1020)[0]["status"], "draining")

    def test_signature_tamper_is_denied(self):
        packet = self.packet()
        packet["body"]["state"] = "draining"
        with self.assertRaisesRegex(MeshError, "signature"):
            self.registry.accept(packet, now=1000)
        self.assertEqual(self.registry.list_nodes(now=1000)[0]["status"], "enrolled")

    def test_wrong_key_is_denied(self):
        other = Ed25519PrivateKey.generate().private_bytes(Encoding.Raw, PrivateFormat.Raw, NoEncryption())
        packet = sign_heartbeat(self.node, 1, other, now=1000)
        with self.assertRaisesRegex(MeshError, "signature"):
            self.registry.accept(packet, now=1000)

    def test_sequence_replay_and_out_of_order_are_denied(self):
        self.registry.accept(self.packet(3), now=1001)
        for sequence in (1, 2, 3):
            with self.assertRaisesRegex(MeshError, "replayed"):
                self.registry.accept(self.packet(sequence), now=1002)
        self.registry.accept(self.packet(4), now=1003)

    def test_timestamp_stale_future_and_bool_sequence_denied(self):
        for when in (900, 1011):
            with self.assertRaises(MeshError):
                self.registry.accept(self.packet(1, when=when), now=1000)
        packet = self.packet()
        packet["body"]["sequence"] = True
        with self.assertRaises(MeshError):
            self.registry.accept(packet, now=1000)

    def test_unexpected_claimed_capabilities_denied(self):
        packet = self.packet()
        packet["body"]["gpu"] = "RTX 9999"
        with self.assertRaisesRegex(MeshError, "unexpected"):
            self.registry.accept(packet, now=1000)

    def test_unknown_node_cannot_enroll_itself(self):
        p = sign_heartbeat(str(uuid4()), 1, self.secret, now=1000)
        with self.assertRaisesRegex(MeshError, "not enrolled"):
            self.registry.accept(p, now=1000)

    def test_revoked_worker_denied_and_persisted(self):
        self.registry.revoke(self.node)
        self.assertEqual(NodeRegistry(self.path).list_nodes(now=1000)[0]["status"], "revoked")
        with self.assertRaisesRegex(MeshError, "revoked"):
            self.registry.accept(self.packet(), now=1000)
        with self.assertRaises(MeshError):
            self.registry.revoke(self.node)

    def test_duplicate_node_and_duplicate_key_denied(self):
        with self.assertRaises(MeshError):
            self.registry.enroll(self.node, "Duplicate", self.public, ["test"])
        with self.assertRaises(MeshError):
            self.registry.enroll(str(uuid4()), "Another", self.public, ["test"])

    def test_invalid_operator_scope_denied(self):
        for modes in (["shell"], ["test", "test"], [], ["test", "delete"]):
            with self.assertRaises(MeshError):
                self.registry.enroll(str(uuid4()), "Node 2", bytes([9]) * 32, modes)
        with self.assertRaises(MeshError):
            self.registry.enroll(str(uuid4()), "Bad\nLabel", bytes([9]) * 32, ["test"])

    def test_concurrent_duplicate_heartbeat_only_one_commits(self):
        packet = self.packet()
        successes, failures = [], []
        def call():
            try:
                successes.append(self.registry.accept(packet, now=1000))
            except MeshError as exc:
                failures.append(str(exc))
        threads = [threading.Thread(target=call) for _ in range(5)]
        for t in threads: t.start()
        for t in threads: t.join()
        self.assertEqual(len(successes), 1)
        self.assertEqual(len(failures), 4)
        self.assertEqual(self.registry.list_nodes(now=1000)[0]["last_sequence"], 1)

    def test_no_network_dispatch_or_authority_exposed(self):
        packet = self.packet()
        self.assertEqual(set(packet), {"body", "signature"})
        self.assertLess(len(canonical(packet)), MAX_PACKET_BYTES)
        out = self.registry.accept(packet, now=1000)
        self.assertFalse(out["execution_authorized"])
        self.assertFalse(self.registry.list_nodes(now=1000)[0]["execution_authorized"])


class NodeCounterTests(unittest.TestCase):
    def test_persistent_monotonic_sequence_through_restarts(self):
        from phicortex.mesh import next_sequence
        with tempfile.TemporaryDirectory() as t:
            database = Path(t) / 'counter.db'
            node = str(uuid4())
            self.assertEqual(next_sequence(database, node), 1)
            self.assertEqual(next_sequence(database, node), 2)
            self.assertEqual(next_sequence(database, str(uuid4())), 1)
            self.assertEqual(next_sequence(database, node), 3)

    def test_concurrent_counter_increments_do_not_repeat(self):
        from phicortex.mesh import next_sequence
        with tempfile.TemporaryDirectory() as t:
            database = Path(t) / 'counter.db'
            node = str(uuid4())
            results = []
            threads = [threading.Thread(target=lambda: results.append(next_sequence(database, node))) for _ in range(8)]
            for thread in threads: thread.start()
            for thread in threads: thread.join()
            self.assertEqual(sorted(results), list(range(1, 9)))


if __name__ == "__main__":
    unittest.main()
