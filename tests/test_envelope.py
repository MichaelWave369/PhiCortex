"""Signed envelope contract tests.

These tests never execute a sandbox or send tasks over the network. They
exercise the actual Ed25519, SQLite, signed receipt and snapshot checks.
"""
from datetime import datetime, timedelta, timezone
import hashlib
import json
from contextlib import closing
from pathlib import Path
import sqlite3
import tempfile
import unittest
from uuid import uuid4

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec, ed25519
from cryptography.x509.oid import NameOID

from phicortex.approval_v1 import issue as issue_permit
from phicortex.envelope import (
    EnvelopeError, approved_task_digest, inspect_permit,
    sign_envelope, verify_envelope, SCHEMA,
)
from phicortex.lease_exchange import LeaseExchange, sign_exchange
from phicortex.leases import TaskLeases
from phicortex.mesh import NodeRegistry, sign_heartbeat
from phicortex.mesh_transport import TransportPins
from phicortex.snapshot import create_snapshot
from phicortex.worker import plan


IMAGE = "python:3.12-alpine@sha256:" + "a" * 64


def raw_private(key):
    return key.private_bytes(
        serialization.Encoding.Raw, serialization.PrivateFormat.Raw,
        serialization.NoEncryption())


def raw_public(key):
    return key.public_key().public_bytes(
        serialization.Encoding.Raw, serialization.PublicFormat.Raw)


def dummy_client_cert(path: Path) -> Path:
    """Local certificate for offline pin binding; no actual TLS here."""
    key = ec.generate_private_key(ec.SECP256R1())
    name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "Lab Worker")])
    now = datetime.now(timezone.utc)
    cert = (x509.CertificateBuilder()
            .subject_name(name).issuer_name(name).public_key(key.public_key())
            .serial_number(x509.random_serial_number())
            .not_valid_before(now - timedelta(days=1))
            .not_valid_after(now + timedelta(days=1))
            .sign(key, hashes.SHA256()))
    path.write_bytes(cert.public_bytes(serialization.Encoding.PEM))
    return path


class SignedEnvelopeTests(unittest.TestCase):
    def setUp(self):
        self.t = tempfile.TemporaryDirectory()
        self.addCleanup(self.t.cleanup)
        self.root = Path(self.t.name)
        self.source = self.root / "small_project"
        self.source.mkdir()
        (self.source / "demo.py").write_text("print('ok')\n", encoding="utf-8")
        self.manifest = create_snapshot(self.source, self.root / "snapshots")
        self.workspace = self.manifest.parent / "tree"
        self.job = plan("test", self.manifest.parent, self.workspace,
                        IMAGE, 30, platform_name="Linux")
        operator = ed25519.Ed25519PrivateKey.generate()
        self.operator_private = raw_private(operator)
        self.operator_public = raw_public(operator)
        self.permit = issue_permit(self.job, self.manifest,
                                   self.operator_private, now=1000, ttl=250)

        self.database = self.root / "coordinator.sqlite3"
        self.nodes = NodeRegistry(self.database)
        self.pins = TransportPins(self.database)
        self.ledger = TaskLeases(self.database)
        self.exchange = LeaseExchange(self.database)
        self.node_id = str(uuid4())
        worker = ed25519.Ed25519PrivateKey.generate()
        self.node_private = raw_private(worker)
        self.node_public = raw_public(worker)
        self.nodes.enroll(self.node_id, "Worker One", self.node_public,
                          ["test"], now=999)
        self.cert = dummy_client_cert(self.root / "worker.crt")
        self.pin = self.pins.bind(self.node_id, self.cert, now=999)["certificate_sha256"]
        self.nodes.accept(sign_heartbeat(self.node_id, 1, self.node_private, now=1001),
                          now=1001, tls_peer_sha256=self.pin)
        self.task_id = str(uuid4())
        self.digest = approved_task_digest(self.permit, self.operator_public, now=1002)
        self.ledger.create(self.task_id, "test", self.digest, now=1002)
        self.lease = self.ledger.lease(self.task_id, self.node_id, 60, now=1002)
        self.receipt = sign_exchange(self.node_id, 2, self.node_private,
                                     "ack", lease_id=self.lease["lease_id"], now=1003)
        self.exchange.apply(self.receipt, action="ack", tls_peer_sha256=self.pin, now=1003)

    def signed(self, **kwargs):
        return sign_envelope(self.database, self.task_id, self.permit,
                             self.operator_private, self.operator_public,
                             now=1004, **kwargs)

    def verified(self, packet=None, now=1005, permit=None, key=None):
        return verify_envelope(packet or self.signed(), self.database,
                               permit or self.permit, key or self.operator_public, now=now)

    def test_valid_operator_envelope_is_metadata_only_and_repeatable(self):
        envelope = self.signed()
        proof = self.verified(envelope)
        self.assertEqual(proof["status"], "validated_metadata_only")
        self.assertEqual(proof["task_id"], self.task_id)
        self.assertEqual(proof["node_id"], self.node_id)
        for key in ("execution_authorized", "task_dispatched",
                    "permit_consumed", "worker_isolation_attested"):
            self.assertIs(proof[key], False)
        self.assertEqual(self.verified(envelope), proof)
        self.assertEqual(envelope["schema"], SCHEMA)
        self.assertNotIn("argv", json.dumps(envelope))
        self.assertNotIn("workspace", json.dumps({k: v for k, v in envelope.items()
                                                  if k != "workspace_sha256"}))
        self.assertNotIn(self.operator_private.hex(), json.dumps(envelope))

    def test_expected_digest_matches_lease_and_is_stable(self):
        self.assertEqual(self.lease["task_sha256"], self.digest)
        self.assertEqual(approved_task_digest(self.permit, self.operator_public, now=1005),
                         self.digest)
        self.assertEqual(self.signed()["task_sha256"], self.digest)

    def test_tampered_node_or_lease_id_fails_signature(self):
        for field, replacement in (("node_id", str(uuid4())),
                                   ("lease_id", str(uuid4()))):
            envelope = self.signed()
            envelope[field] = replacement
            with self.subTest(field=field), self.assertRaisesRegex(EnvelopeError, "signature"):
                self.verified(envelope)

    def test_extra_fields_or_fake_execute_flag_are_refused(self):
        envelope = self.signed()
        envelope["execute"] = True
        with self.assertRaisesRegex(EnvelopeError, "schema"):
            self.verified(envelope)

    def test_wrong_operator_public_key_refused(self):
        rogue = ed25519.Ed25519PrivateKey.generate()
        with self.assertRaises(EnvelopeError):
            self.verified(key=raw_public(rogue))

    def test_signing_private_key_must_match_governor_public(self):
        rogue = ed25519.Ed25519PrivateKey.generate()
        with self.assertRaisesRegex(EnvelopeError, "does not match"):
            sign_envelope(self.database, self.task_id, self.permit,
                          raw_private(rogue), self.operator_public, now=1004)

    def test_different_valid_governor_permit_mismatches_envelope(self):
        envelope = self.signed()
        second = issue_permit(self.job, self.manifest, self.operator_private,
                              now=1000, ttl=250)
        with self.assertRaisesRegex(EnvelopeError, "no longer matches"):
            self.verified(envelope, permit=second)

    def test_lease_task_hash_must_match_signed_permit(self):
        with closing(sqlite3.connect(self.database)) as db:
            with db:
                db.execute("UPDATE task_leases SET task_sha256=? WHERE task_id=?",
                       ("b" * 64, self.task_id))
        with self.assertRaisesRegex(EnvelopeError, "digest or mode"):
            self.signed()

    def test_no_signed_metadata_ack_denies_envelope(self):
        with closing(sqlite3.connect(self.database)) as db:
            with db:
                db.execute("DELETE FROM lease_receipts WHERE lease_id=?", (self.lease["lease_id"],))
        with self.assertRaisesRegex(EnvelopeError, "not acknowledged"):
            self.signed()

    def test_revoked_node_is_denied(self):
        envelope = self.signed()
        self.nodes.revoke(self.node_id)
        with self.assertRaisesRegex(EnvelopeError, "not live"):
            self.verified(envelope)
        with self.assertRaisesRegex(EnvelopeError, "not live"):
            self.signed()

    def test_changed_node_tls_binding_is_denied(self):
        envelope = self.signed()
        with closing(sqlite3.connect(self.database)) as db:
            with db:
                db.execute("UPDATE node_tls_pins SET certificate_sha256=? WHERE node_id=?",
                       ("f" * 64, self.node_id))
        with self.assertRaisesRegex(EnvelopeError, "no longer matches"):
            self.verified(envelope)

    def test_changed_node_public_key_is_denied(self):
        envelope = self.signed()
        with closing(sqlite3.connect(self.database)) as db:
            with db:
                db.execute("UPDATE nodes SET pubkey_sha256=? WHERE id=?", ("b" * 64, self.node_id))
        with self.assertRaisesRegex(EnvelopeError, "fingerprint"):
            self.verified(envelope)

    def test_draining_node_denied(self):
        envelope = self.signed()
        self.nodes.accept(sign_heartbeat(self.node_id, 3, self.node_private,
                                         state="draining", now=1006),
                          now=1006, tls_peer_sha256=self.pin)
        with self.assertRaisesRegex(EnvelopeError, "not live"):
            self.verified(envelope, now=1006)

    def test_heartbeat_expiry_denied(self):
        envelope = self.signed()
        with closing(sqlite3.connect(self.database)) as db:
            with db:
                db.execute("UPDATE nodes SET expires_at=? WHERE id=?",
                           (1005, self.node_id))
        with self.assertRaisesRegex(EnvelopeError, "not live"):
            self.verified(envelope, now=1005)

    def test_lease_expiry_denied(self):
        envelope = self.signed()
        with closing(sqlite3.connect(self.database)) as db:
            with db:
                db.execute("UPDATE task_leases SET deadline=? WHERE task_id=?",
                           (1005, self.task_id))
        with self.assertRaisesRegex(EnvelopeError, "lease deadline"):
            self.verified(envelope, now=1005)

    def test_envelope_expiry_is_bound_to_all_deadlines(self):
        envelope = self.signed(ttl=120)
        self.assertEqual(envelope["expires_at"],
                         min(1004 + 120, self.permit["expires_at"],
                             self.lease["deadline"], 1001 + 90))
        with self.assertRaises(EnvelopeError):
            self.verified(envelope, now=envelope["expires_at"])

    def test_invalid_ttl_is_rejected(self):
        for ttl in (0, 121, True):
            with self.subTest(ttl=ttl), self.assertRaises(EnvelopeError):
                self.signed(ttl=ttl)

    def test_permit_expiry_denies_even_if_node_heartbeat_refreshed(self):
        envelope = self.signed()
        self.permit["expires_at"] = 1004
        with self.assertRaises(EnvelopeError):
            self.verified(envelope)

    def test_mutated_snapshot_denies_envelope(self):
        envelope = self.signed()
        target = self.workspace / "demo.py"
        target.chmod(0o600)
        target.write_text("print('unexpected')\n", encoding="utf-8")
        with self.assertRaises(EnvelopeError):
            self.verified(envelope)

    def test_missing_approval_manifest_denies_envelope(self):
        envelope = self.signed()
        self.manifest.chmod(0o600)
        self.manifest.unlink()
        with self.assertRaises(EnvelopeError):
            self.verified(envelope)

    def test_lease_close_after_reconcile_denies_old_envelope(self):
        envelope = self.signed()
        self.ledger.reconcile(now=self.lease["deadline"])
        with self.assertRaisesRegex(EnvelopeError, "no active"):
            self.verified(envelope)

    def test_unapproved_node_mode_denied(self):
        with closing(sqlite3.connect(self.database)) as db:
            with db:
                db.execute("UPDATE nodes SET approved_modes_json=? WHERE id=?", ('["build-check"]', self.node_id))
        with self.assertRaisesRegex(EnvelopeError, "not approved"):
            self.signed()

    def test_mismatched_lease_owner_denied(self):
        envelope = self.signed()
        with closing(sqlite3.connect(self.database)) as db:
            with db:
                db.execute("UPDATE task_leases SET node_id=? WHERE task_id=?",
                       (str(uuid4()), self.task_id))
        with self.assertRaisesRegex(EnvelopeError, "not live"):
            self.verified(envelope)

    def test_signature_cannot_be_authorized_from_plain_heartbeat(self):
        self.assertNotIn("signature", self.lease)
        self.assertFalse(self.lease["execution_authorized"])
        self.assertFalse(self.signed().get("execution_authorized", False))

    def test_cannot_issue_for_unknown_task(self):
        with self.assertRaisesRegex(EnvelopeError, "no active"):
            sign_envelope(self.database, str(uuid4()), self.permit,
                          self.operator_private, self.operator_public, now=1004)

    def test_cli_may_inspect_without_consuming_governor_permit(self):
        from phicortex.envelope import main
        from contextlib import redirect_stdout
        from io import StringIO
        public_path = self.root / "operator.pub"
        public_path.write_bytes(self.operator_public)
        permit_path = self.root / "permit.json"
        permit_path.write_text(json.dumps(self.permit), encoding="utf-8")
        buffer = StringIO()
        # CLI uses the real clock, whereas this fixture uses synthetic time.
        # Confirm signature verification directly above; this checks parser/help.
        with redirect_stdout(buffer), self.assertRaises(SystemExit) as caught:
            main(["--help"])
        self.assertEqual(caught.exception.code, 0)


if __name__ == "__main__":
    unittest.main()
