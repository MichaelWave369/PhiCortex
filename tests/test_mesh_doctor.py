"""Mesh doctor tests with *real* TLS loopback, not a simulated network.

These verify diagnostic behavior only. They cannot attest two separate PCs,
hardware identity, firewall deployment, or sandbox isolation.
"""
from dataclasses import replace
from datetime import datetime, timedelta, timezone
import hashlib
import json
import os
from pathlib import Path
import socket
import tempfile
import threading
import time
import unittest
from uuid import uuid4

from cryptography import x509
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives.serialization import (
    Encoding, PrivateFormat, PublicFormat, NoEncryption
)

from phicortex.leases import TaskLeases
from phicortex.mesh import NodeRegistry
from phicortex.mesh_doctor import (
    DoctorConfig, DoctorError, preflight, probe,
    _validate_exchange, _validate_heartbeat
)
from phicortex.mesh_transport import (
    TransportPins, server_context, start_server,
)
from test_mesh_transport import PKI


class DoctorIntegrationTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.root = Path(self.tmp.name)
        self.pki = PKI(self.root)
        self.server_cert, self.server_key = self.pki.identity("doctor-server", role="server")
        self.client_cert, self.client_key = self.pki.identity("doctor-client")
        self.other_cert, self.other_key = self.pki.identity("doctor-other")
        self.db = self.root / "mesh.sqlite3"
        self.pins = TransportPins(self.db)
        self.node_id = str(uuid4())
        private = Ed25519PrivateKey.generate()
        self.node_private = private.private_bytes(
            Encoding.Raw, PrivateFormat.Raw, NoEncryption())
        self.node_public = private.public_key().public_bytes(
            Encoding.Raw, PublicFormat.Raw)
        self.node_file = self.root / "node.private"
        self.node_file.write_bytes(self.node_private)
        self.node_file.chmod(0o600)
        self.pins.nodes.enroll(self.node_id, "Lab 1", self.node_public, ["test"])
        cert_hash = self.pins.bind(
            self.node_id, self.client_cert)["certificate_sha256"]
        self.server = start_server(
            self.pins.nodes,
            server_context(self.server_cert, self.server_key, self.pki.ca_path),
            port=0)
        self.thread = threading.Thread(
            target=self.server.serve_forever, daemon=True)
        self.thread.start()
        self.addCleanup(self.stop_server)
        self.conf = DoctorConfig(
            host="127.0.0.1", port=self.server.server_port, allow_lan=False,
            server_ca=self.pki.ca_path, client_cert=self.client_cert,
            client_key=self.client_key,
            node_id=self.node_id, node_signing_key=self.node_file,
            counter_db=self.root / "node-counter.sqlite3",
            expected_node_sha256=hashlib.sha256(self.node_public).hexdigest(),
            expected_cert_sha256=cert_hash)

    def stop_server(self):
        self.server.shutdown()
        self.server.server_close()
        self.thread.join(timeout=5)

    def test_local_preflight_verifies_certificates_and_pins_without_network(self):
        result = preflight(self.conf)
        self.assertIn(result["status"], ("ready", "warning"))
        self.assertFalse(result["network_checked"])
        self.assertFalse(result["execution_authorized"])
        self.assertEqual(result["node_id"], self.node_id)
        self.assertEqual(result["identity"]["client_cert_sha256"],
                         self.conf.expected_cert_sha256)
        self.assertFalse(self.conf.counter_db.exists())

    def test_real_loopback_heartbeat_and_lease_preview(self):
        result = probe(self.conf)
        self.assertEqual(result["outcome"], "protocol_passed")
        self.assertEqual([s["sequence"] for s in result["steps"]], [1, 2])
        self.assertFalse(result["steps"][1]["active_lease"])
        self.assertTrue(result["network_checked"])
        self.assertFalse(result["physical_pc_verified"])
        self.assertFalse(result["execution_authorized"])
        self.assertEqual(self.pins.nodes.list_nodes()[0]["last_sequence"], 2)

    def test_explicit_ack_only_with_existing_operator_leased_task(self):
        first = probe(self.conf)
        self.assertEqual(first["outcome"], "protocol_passed")
        leases = TaskLeases(self.db)
        task_id = str(uuid4())
        leases.create(task_id, "test", "a" * 64)
        leased = leases.lease(task_id, self.node_id, 30)
        second = probe(self.conf)
        self.assertEqual(second["outcome"], "protocol_passed")
        self.assertEqual([s["step"] for s in second["steps"]],
                         ["heartbeat", "lease_preview"])
        self.assertFalse(second["steps"][1]["acknowledged"])
        result = probe(self.conf, acknowledge=True)
        self.assertEqual(result["outcome"], "protocol_passed")
        self.assertEqual([s["step"] for s in result["steps"]],
                         ["heartbeat", "lease_preview", "lease_ack"])
        self.assertEqual([s["kind"] for s in leases.events(task_id)],
                         ["created", "leased", "lease_metadata_ack"])
        self.assertEqual(leases.get(task_id)["lease_id"], leased["lease_id"])
        self.assertEqual(leases.get(task_id)["status"], "leased")
        self.assertFalse(result["task_dispatched"])

    def test_ack_request_without_lease_refuses_without_creating_task(self):
        result = probe(self.conf, acknowledge=True)
        self.assertEqual(result["outcome"], "protocol_refused")
        self.assertEqual(TaskLeases(self.db).list(), [])

    def test_revoked_node_explicit_403_is_observed_but_reason_not_attested(self):
        before = probe(self.conf)
        self.assertEqual(before["outcome"], "protocol_passed")
        self.pins.nodes.revoke(self.node_id)
        result = probe(self.conf, expect_denied=True)
        self.assertEqual(result["outcome"], "explicit_403_observed")
        self.assertFalse(result["denial_reason_attested"])
        self.assertFalse(result["execution_authorized"])

    def test_denial_expectation_never_passes_when_heartbeat_accepted(self):
        result = probe(self.conf, expect_denied=True)
        self.assertEqual(result["outcome"], "protocol_refused")
        self.assertNotIn("denial_reason_attested", result)

    def test_disconnect_is_not_counted_as_authorization_denial(self):
        self.stop_server()
        result = probe(self.conf, expect_denied=True)
        self.assertEqual(result["outcome"], "connectivity_or_tls_failed")
        self.assertFalse(result["execution_authorized"])

    def test_disconnect_and_new_port_recovery_uses_fresh_sequences(self):
        before = probe(self.conf)
        self.assertEqual(before["outcome"], "protocol_passed")
        self.stop_server()
        during = probe(self.conf)
        self.assertEqual(during["outcome"], "connectivity_or_tls_failed")
        # Restart on an ephemeral port; coordinator has the same node registry.
        self.server = start_server(
            self.pins.nodes,
            server_context(self.server_cert, self.server_key, self.pki.ca_path),
            port=0)
        self.thread = threading.Thread(
            target=self.server.serve_forever, daemon=True)
        self.thread.start()
        after = probe(replace(self.conf, port=self.server.server_port))
        self.assertEqual(after["outcome"], "protocol_passed")
        self.assertEqual(before["steps"][0]["sequence"], 1)
        self.assertEqual(during["steps"][0]["sequence"], 3)
        self.assertEqual(after["steps"][0]["sequence"], 4)
        self.assertEqual(after["steps"][1]["sequence"], 5)
        self.assertEqual(self.pins.nodes.list_nodes()[0]["last_sequence"], 5)

    def test_operator_node_pin_mismatch_refuses_before_network(self):
        bad = replace(self.conf, expected_node_sha256="0" * 64)
        with self.assertRaisesRegex(DoctorError, "enrolled public key"):
            preflight(bad)
        self.assertFalse(self.conf.counter_db.exists())

    def test_operator_tls_pin_mismatch_refuses_before_network(self):
        bad = replace(self.conf, expected_cert_sha256="0" * 64)
        with self.assertRaisesRegex(DoctorError, "enrollment pin"):
            preflight(bad)

    def test_tls_private_key_must_match_client_certificate(self):
        bad = replace(self.conf, client_key=self.other_key)
        with self.assertRaisesRegex(DoctorError, "do not match"):
            preflight(bad)

    def test_node_private_key_must_match_enrollment(self):
        rogue = Ed25519PrivateKey.generate().private_bytes(
            Encoding.Raw, PrivateFormat.Raw, NoEncryption())
        self.node_file.write_bytes(rogue)
        with self.assertRaisesRegex(DoctorError, "enrolled public key"):
            preflight(self.conf)

    def test_server_certificate_is_not_accepted_as_client_identity(self):
        fake_cert_der = x509.load_pem_x509_certificate(
            self.server_cert.read_bytes()).public_bytes(Encoding.DER)
        bad = replace(self.conf, client_cert=self.server_cert,
                      client_key=self.server_key,
                      expected_cert_sha256=hashlib.sha256(fake_cert_der).hexdigest())
        with self.assertRaisesRegex(DoctorError, "clientAuth"):
            preflight(bad)

    def test_certificate_expiration_blocks_preflight(self):
        future = datetime.now(timezone.utc) + timedelta(days=4)
        with self.assertRaisesRegex(DoctorError, "outside its validity"):
            preflight(self.conf, now=future)

    def test_untrusted_ca_cannot_be_silently_counted_as_connected(self):
        with tempfile.TemporaryDirectory() as other:
            wrong = PKI(Path(other)).ca_path
            result = probe(replace(self.conf, server_ca=wrong))
            self.assertEqual(result["outcome"], "connectivity_or_tls_failed")

    def test_protocol_validation_refuses_extra_executable_fields(self):
        lease_reply = {
            "schema": "phicortex.mesh.lease_exchange.v1",
            "action": "preview", "node_id": self.node_id, "sequence": 2,
            "lease": None, "execution_authorized": False,
            "task_dispatched": False, "governor_permit_included": False,
            "task_payload_included": False, "command": "shell"
        }
        with self.assertRaisesRegex(DoctorError, "no-execution"):
            _validate_exchange(lease_reply, self.node_id, "preview", 2)
        heartbeat = {"node_id": self.node_id, "sequence": 1,
                     "status": "online", "expires_at": 9999999999,
                     "execution_authorized": False, "task_dispatched": False,
                     "command": "shell"}
        with self.assertRaisesRegex(DoctorError, "no-execution"):
            _validate_heartbeat(heartbeat, self.node_id, 1)

    def test_report_contains_no_credentials_or_private_paths(self):
        result = probe(self.conf)
        rendered = json.dumps(result, sort_keys=True)
        self.assertNotIn(self.node_private.hex(), rendered)
        self.assertNotIn(str(self.client_key), rendered)
        self.assertNotIn(str(self.node_file), rendered)

    @unittest.skipUnless(os.name == "posix", "POSIX key modes only")
    def test_world_readable_private_key_is_rejected(self):
        self.node_file.chmod(0o644)
        with self.assertRaisesRegex(DoctorError, "unsafe Unix"):
            preflight(self.conf)


if __name__ == "__main__":
    unittest.main()
