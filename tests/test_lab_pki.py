"""Lab PKI tests: offline issuance, failure gates and real mTLS integration.

Real loopback TLS is tested. No actual separate physical PCs, remote
execution or public-network CA deployment is claimed.
"""
from __future__ import annotations

from dataclasses import replace
from datetime import datetime, timedelta, timezone
import hashlib
import os
from pathlib import Path
import ssl
import tempfile
import threading
import unittest
from uuid import uuid4

from cryptography import x509
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.x509.oid import ExtendedKeyUsageOID

from phicortex.lab_pki import (
    PKIError, init_ca, create_csr, sign_csr, inspect_certificate, _load_file
)
from phicortex.mesh import sign_heartbeat
from phicortex.mesh_transport import (
    TransportPins, server_context, client_context, start_server, send_heartbeat
)
from phicortex.mesh_doctor import preflight, DoctorConfig


class LabPKITests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.root = Path(self.tmp.name)
        self.ca_key = self.root / "operator" / "lab-ca.key"
        self.ca_cert = self.root / "operator" / "lab-ca.crt"
        self.ca = init_ca(self.ca_key, self.ca_cert)
        self.node_id = str(uuid4())

    def server(self, ip="127.0.0.1", prefix="server"):
        key = self.root / prefix / "server.key"
        csr = self.root / prefix / "server.csr"
        cert = self.root / prefix / "server.crt"
        create_csr(key, csr, role="server", server_ip=ip)
        result = sign_csr(self.ca_key, self.ca_cert, csr, cert,
                          role="server", server_ip=ip)
        return key, csr, cert, result

    def worker(self, node_id=None, prefix="worker"):
        node_id = node_id or self.node_id
        key = self.root / prefix / "client.key"
        csr = self.root / prefix / "client.csr"
        cert = self.root / prefix / "client.crt"
        create_csr(key, csr, role="client", node_id=node_id)
        result = sign_csr(self.ca_key, self.ca_cert, csr, cert,
                          role="client", node_id=node_id)
        return key, csr, cert, result

    def test_ca_is_local_p256_constraint_and_owner_only_secret(self):
        ca = x509.load_pem_x509_certificate(self.ca_cert.read_bytes())
        self.assertTrue(ca.extensions.get_extension_for_class(
            x509.BasicConstraints).value.ca)
        self.assertEqual(ca.extensions.get_extension_for_class(
            x509.BasicConstraints).value.path_length, 0)
        self.assertEqual(self.ca["certificate_sha256"],
                         hashlib.sha256(ca.public_bytes(
                             serialization.Encoding.DER)).hexdigest())
        self.assertFalse(self.ca["private_key_exported"])
        if os.name == "posix":
            self.assertEqual(self.ca_key.stat().st_mode & 0o077, 0)

    def test_server_cert_has_matching_ip_san_and_server_eku(self):
        key, csr, path, issued = self.server()
        cert = x509.load_pem_x509_certificate(path.read_bytes())
        san = cert.extensions.get_extension_for_class(
            x509.SubjectAlternativeName).value.get_values_for_type(x509.IPAddress)
        self.assertEqual([str(x) for x in san], ["127.0.0.1"])
        eku = cert.extensions.get_extension_for_class(x509.ExtendedKeyUsage).value
        self.assertIn(ExtendedKeyUsageOID.SERVER_AUTH, eku)
        self.assertNotIn(ExtendedKeyUsageOID.CLIENT_AUTH, eku)
        self.assertFalse(cert.extensions.get_extension_for_class(
            x509.BasicConstraints).value.ca)
        self.assertEqual(inspect_certificate(path)["certificate_sha256"],
                         issued["certificate_sha256"])

    def test_client_cert_binds_canonical_node_uuid_and_role(self):
        key, csr, path, issued = self.worker()
        cert = x509.load_pem_x509_certificate(path.read_bytes())
        eku = cert.extensions.get_extension_for_class(x509.ExtendedKeyUsage).value
        self.assertIn(ExtendedKeyUsageOID.CLIENT_AUTH, eku)
        self.assertNotIn(ExtendedKeyUsageOID.SERVER_AUTH, eku)
        san = cert.extensions.get_extension_for_class(
            x509.SubjectAlternativeName).value.get_values_for_type(
                x509.UniformResourceIdentifier)
        self.assertEqual(san, ["urn:phicortex:node:" + self.node_id])
        self.assertEqual(issued["role"], "client")

    def test_no_overwrite_ca_or_csr_or_signed_cert(self):
        with self.assertRaisesRegex(PKIError, "already exist"):
            init_ca(self.ca_key, self.ca_cert)
        key, csr, path, report = self.worker()
        with self.assertRaises(PKIError):
            create_csr(key, csr, role="client", node_id=self.node_id)
        with self.assertRaises(PKIError):
            sign_csr(self.ca_key, self.ca_cert, csr, path,
                     role="client", node_id=self.node_id)

    def test_public_or_wildcard_server_address_is_refused(self):
        for ip in ("0.0.0.0", "8.8.8.8", "example.com", "169.254.4.2", "::1"):
            with self.subTest(ip=ip), self.assertRaises(PKIError):
                create_csr(self.root / ("no" + uuid4().hex + ".key"),
                           self.root / ("no" + uuid4().hex + ".csr"),
                           role="server", server_ip=ip)

    def test_private_lan_server_ip_is_allowed(self):
        key, csr, cert, result = self.server(ip="192.168.0.9", prefix="lan")
        obj = x509.load_pem_x509_certificate(cert.read_bytes())
        san = obj.extensions.get_extension_for_class(
            x509.SubjectAlternativeName).value.get_values_for_type(x509.IPAddress)
        self.assertEqual([str(s) for s in san], ["192.168.0.9"])

    def test_client_requires_valid_node_uuid_and_no_server_ip(self):
        with self.assertRaises(PKIError):
            create_csr(self.root / "x.key", self.root / "x.csr",
                       role="client", node_id="not-a-uuid")
        with self.assertRaises(PKIError):
            create_csr(self.root / "y.key", self.root / "y.csr",
                       role="client", node_id=self.node_id, server_ip="127.0.0.1")

    def test_operator_refuses_csr_for_different_node(self):
        key, csr, cert, _ = self.worker(prefix="node-one")
        with self.assertRaisesRegex(PKIError, "subject"):
            sign_csr(self.ca_key, self.ca_cert, csr,
                     self.root / "wrong.crt", role="client", node_id=str(uuid4()))

    def test_operator_refuses_csr_for_different_server_ip(self):
        key = self.root / "a.key"
        csr = self.root / "a.csr"
        create_csr(key, csr, role="server", server_ip="127.0.0.1")
        with self.assertRaisesRegex(PKIError, "subject"):
            sign_csr(self.ca_key, self.ca_cert, csr, self.root / "b.crt",
                     role="server", server_ip="192.168.1.10")

    def test_operator_refuses_wrong_role_for_valid_csr(self):
        key, csr, cert, _ = self.worker()
        with self.assertRaises(PKIError):
            sign_csr(self.ca_key, self.ca_cert, csr, self.root / "wrongrole.crt",
                     role="server", server_ip="127.0.0.1")

    def test_ca_key_mismatch_is_refused(self):
        with tempfile.TemporaryDirectory() as other:
            other_ca = Path(other)
            init_ca(other_ca / "ca.key", other_ca / "ca.crt")
            key, csr, cert, _ = self.worker()
            with self.assertRaisesRegex(PKIError, "does not match"):
                sign_csr(other_ca / "ca.key", self.ca_cert, csr,
                         self.root / "wrongca.crt", role="client", node_id=self.node_id)

    def test_validity_bound_14_to_30_days(self):
        key, csr, cert, report = self.worker()
        issued = x509.load_pem_x509_certificate(cert.read_bytes())
        self.assertLessEqual((issued.not_valid_after_utc -
                              issued.not_valid_before_utc).days, 15)
        with self.assertRaises(PKIError):
            sign_csr(self.ca_key, self.ca_cert, csr,
                     self.root / "invalid-days.crt", role="client",
                     node_id=self.node_id, days=31)

    def test_ca_expiration_prevents_signing(self):
        key, csr, cert, _ = self.worker()
        with self.assertRaisesRegex(PKIError, "expired"):
            sign_csr(self.ca_key, self.ca_cert, csr,
                     self.root / "late.crt", role="client",
                     node_id=self.node_id,
                     now=datetime.now(timezone.utc) + timedelta(days=400))

    @unittest.skipUnless(os.name == "posix", "Unix permission enforcement")
    def test_world_readable_ca_key_is_refused(self):
        key = self.root / "private.key"
        csr = self.root / "private.csr"
        create_csr(key, csr, role="client", node_id=self.node_id)
        self.ca_key.chmod(0o644)
        with self.assertRaisesRegex(PKIError, "owner-only"):
            sign_csr(self.ca_key, self.ca_cert, csr,
                     self.root / "unsafe.crt", role="client", node_id=self.node_id)

    def test_rejects_symlinked_ca_path(self):
        link = self.root / "shortcut.key"
        try:
            link.symlink_to(self.ca_key)
        except OSError:
            self.skipTest("cannot create symlink on this host")
        key = self.root / "node.key"
        csr = self.root / "node.csr"
        create_csr(key, csr, role="client", node_id=self.node_id)
        with self.assertRaisesRegex(PKIError, "symlinked"):
            sign_csr(link, self.ca_cert, csr,
                     self.root / "blocked.crt", role="client", node_id=self.node_id)

    def test_signed_x509_cert_is_accepted_by_existing_mesh_doctor(self):
        key, csr, cert, result = self.worker()
        node_key = Ed25519PrivateKey.generate()
        node_path = self.root / "node-signing.key"
        node_path.write_bytes(node_key.private_bytes(
            Encoding.Raw, PrivateFormat.Raw, NoEncryption()))
        node_path.chmod(0o600)
        node_fp = hashlib.sha256(node_key.public_key().public_bytes(
            Encoding.Raw, PublicFormat.Raw)).hexdigest()
        config = DoctorConfig(
            host="127.0.0.1", port=8766, allow_lan=False,
            server_ca=self.ca_cert, client_cert=cert, client_key=key,
            node_id=self.node_id, node_signing_key=node_path,
            counter_db=self.root / "counter.sqlite3",
            expected_node_sha256=node_fp,
            expected_cert_sha256=result["certificate_sha256"])
        status = preflight(config)
        self.assertIn(status["status"], ("ready", "warning"))
        self.assertFalse(status["network_checked"])

    def test_real_mutual_tls_heartbeat_using_new_certificate_workflow(self):
        server_key, server_csr, server_cert, _ = self.server()
        client_key, client_csr, client_cert, report = self.worker()
        pki = TransportPins(self.root / "enrolled.sqlite3")
        node = Ed25519PrivateKey.generate()
        private = node.private_bytes(Encoding.Raw, PrivateFormat.Raw, NoEncryption())
        public = node.public_key().public_bytes(Encoding.Raw, PublicFormat.Raw)
        pki.nodes.enroll(self.node_id, "Lab PKI Worker", public, ["test"])
        pki.bind(self.node_id, client_cert)
        server = start_server(pki.nodes,
                              server_context(server_cert, server_key, self.ca_cert),
                              port=0)
        thread = threading.Thread(target=server.serve_forever, daemon=True)
        thread.start()
        try:
            reply = send_heartbeat("127.0.0.1", server.server_port,
                                   sign_heartbeat(self.node_id, 1, private),
                                   self.ca_cert, client_cert, client_key)
            self.assertEqual(reply["status"], "online")
            self.assertFalse(reply["execution_authorized"])
            self.assertFalse(reply["task_dispatched"])
        finally:
            server.shutdown()
            server.server_close()
            thread.join(timeout=4)

    def test_wrong_signed_certificate_cannot_authenticate_at_other_node(self):
        server_key, server_csr, server_cert, _ = self.server()
        client_key, client_csr, client_cert, report = self.worker()
        other_key, other_csr, other_cert, other_report = self.worker(
            node_id=str(uuid4()), prefix="another")
        pki = TransportPins(self.root / "registry.sqlite3")
        node = Ed25519PrivateKey.generate()
        private = node.private_bytes(Encoding.Raw, PrivateFormat.Raw, NoEncryption())
        public = node.public_key().public_bytes(Encoding.Raw, PublicFormat.Raw)
        pki.nodes.enroll(self.node_id, "Lab PKI Worker", public, ["test"])
        pki.bind(self.node_id, client_cert)
        server = start_server(pki.nodes,
                              server_context(server_cert, server_key, self.ca_cert),
                              port=0)
        thread = threading.Thread(target=server.serve_forever, daemon=True)
        thread.start()
        try:
            from phicortex.mesh_transport import TransportError
            with self.assertRaisesRegex(TransportError, "HTTP 403"):
                send_heartbeat("127.0.0.1", server.server_port,
                               sign_heartbeat(self.node_id, 1, private),
                               self.ca_cert, other_cert, other_key)
        finally:
            server.shutdown()
            server.server_close()
            thread.join(timeout=4)


if __name__ == "__main__":
    unittest.main()
