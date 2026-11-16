"""Offline operator-controlled lab PKI for two-PC PhiCortex mTLS testing.

Produces an ECDSA P-256 lab CA on the trusted operator's computer. Each PC
generates its own ECDSA private key and a role-specific CSR locally. Only a
verified CSR and later a signed public certificate are transferred. This is
NOT a network CA, production PKI, automatic enrollment, or worker authority.
"""
from __future__ import annotations

import argparse
from datetime import datetime, timedelta, timezone
import hashlib
import ipaddress
import json
import os
from pathlib import Path
import re
import stat

from .mesh import _id
from .mesh_transport import validate_endpoint

CA_DAYS = 365
CERT_DAYS_MAX = 30
MAX_INPUT = 64 * 1024
CA_CN = "PhiCortex Private Lab CA v1"
UUID_SAN_PREFIX = "urn:phicortex:node:"


class PKIError(RuntimeError):
    pass


def _modules():
    try:
        from cryptography import x509
        from cryptography.hazmat.primitives import hashes, serialization
        from cryptography.hazmat.primitives.asymmetric import ec
        from cryptography.x509.oid import ExtendedKeyUsageOID, NameOID
    except ImportError as exc:
        raise PKIError("install the optional requirements-worker.txt") from exc
    return x509, hashes, serialization, ec, ExtendedKeyUsageOID, NameOID


def _directory(folder: Path) -> Path:
    folder = folder.expanduser().absolute()
    if folder.is_symlink():
        raise PKIError("symlinked output directory refused")
    folder.mkdir(parents=True, mode=0o700, exist_ok=True)
    if not folder.is_dir():
        raise PKIError("output directory is not a directory")
    return folder


def _load_file(path: Path, *, secret: bool = False) -> bytes:
    if path.is_symlink():
        raise PKIError("symlinked credential input refused")
    try:
        meta = path.stat()
        if not stat.S_ISREG(meta.st_mode) or meta.st_size > MAX_INPUT:
            raise PKIError("invalid or oversized certificate/key/CSR file")
        if secret and os.name == "posix" and (meta.st_mode & 0o077):
            raise PKIError("private key must be owner-only on Unix")
        data = path.read_bytes()
    except OSError as exc:
        raise PKIError("credential input unavailable") from exc
    return data


def _new_file(path: Path, data: bytes, *, secret: bool) -> None:
    path = path.expanduser().absolute()
    _directory(path.parent)
    if path.is_symlink():
        raise PKIError("symlinked credential output refused")
    flags = os.O_CREAT | os.O_EXCL | os.O_WRONLY
    if hasattr(os, "O_NOFOLLOW"):
        flags |= os.O_NOFOLLOW
    try:
        fd = os.open(path, flags, 0o600 if secret else 0o644)
    except FileExistsError as exc:
        raise PKIError("credential already exists; never overwrite") from exc
    try:
        with os.fdopen(fd, "wb") as out:
            out.write(data)
            out.flush()
            os.fsync(out.fileno())
    except BaseException:
        path.unlink(missing_ok=True)
        raise


def _two_files(first: Path, data1: bytes, second: Path, data2: bytes) -> None:
    if first.expanduser().absolute() == second.expanduser().absolute():
        raise PKIError("key and public artifact paths must differ")
    if first.exists() or second.exists() or first.is_symlink() or second.is_symlink():
        raise PKIError("credential paths already exist; no key rotation by overwrite")
    _new_file(first, data1, secret=True)
    try:
        _new_file(second, data2, secret=False)
    except BaseException:
        first.unlink(missing_ok=True)
        raise


def _ec_key_pem(key, serialization) -> bytes:
    return key.private_bytes(
        serialization.Encoding.PEM,
        serialization.PrivateFormat.PKCS8,
        serialization.NoEncryption())


def _cert_pem(cert, serialization) -> bytes:
    return cert.public_bytes(serialization.Encoding.PEM)


def _fingerprint(cert, serialization) -> str:
    return hashlib.sha256(
        cert.public_bytes(serialization.Encoding.DER)).hexdigest()


def _role(role: str, *, ip: str | None = None, node_id: str | None = None):
    x509, hashes, serialization, ec, EKU, NameOID = _modules()
    if role == "server" and ip is not None and node_id is None:
        try:
            address = ipaddress.ip_address(validate_endpoint(ip, 8766, allow_lan=True))
        except Exception as exc:
            raise PKIError("server address must be loopback or private RFC1918 IPv4") from exc
        cn = "phicortex-server-" + str(address)
        san = x509.SubjectAlternativeName([x509.IPAddress(address)])
        return cn, san, EKU.SERVER_AUTH
    if role == "client" and node_id is not None and ip is None:
        try:
            _id(node_id)
        except Exception as exc:
            raise PKIError("client node ID must be canonical UUID") from exc
        cn = "phicortex-node-" + node_id
        san = x509.SubjectAlternativeName([
            x509.UniformResourceIdentifier(UUID_SAN_PREFIX + node_id)])
        return cn, san, EKU.CLIENT_AUTH
    raise PKIError("server requires --server-ip; client requires --node-id")


def _name(cn: str):
    x509, hashes, serialization, ec, EKU, NameOID = _modules()
    return x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, cn)])


def init_ca(key_path: Path, cert_path: Path, *,
            now: datetime | None = None) -> dict:
    """One-time operator action. Store CA private key ONLY on operator PC."""
    x509, hashes, serialization, ec, EKU, NameOID = _modules()
    stamp = now or datetime.now(timezone.utc)
    if stamp.tzinfo is None:
        raise PKIError("signing time must be timezone aware")
    key = ec.generate_private_key(ec.SECP256R1())
    name = _name(CA_CN)
    cert = (x509.CertificateBuilder()
            .subject_name(name).issuer_name(name)
            .public_key(key.public_key())
            .serial_number(x509.random_serial_number())
            .not_valid_before(stamp - timedelta(minutes=2))
            .not_valid_after(stamp + timedelta(days=CA_DAYS))
            .add_extension(x509.BasicConstraints(ca=True, path_length=0), critical=True)
            .add_extension(x509.KeyUsage(
                digital_signature=True, content_commitment=False,
                key_encipherment=False, data_encipherment=False,
                key_agreement=False, key_cert_sign=True, crl_sign=True,
                encipher_only=False, decipher_only=False), critical=True)
            .add_extension(x509.SubjectKeyIdentifier.from_public_key(key.public_key()),
                           critical=False)
            .sign(key, hashes.SHA256()))
    _two_files(key_path, _ec_key_pem(key, serialization),
               cert_path, _cert_pem(cert, serialization))
    return {"role": "lab_ca", "certificate_sha256": _fingerprint(cert, serialization),
            "expires_at": cert.not_valid_after_utc.isoformat(),
            "private_key_exported": False}


def create_csr(key_path: Path, csr_path: Path, *,
               role: str, server_ip: str | None = None,
               node_id: str | None = None) -> dict:
    """Run on the actual machine that will own the new TLS private key."""
    x509, hashes, serialization, ec, EKU, NameOID = _modules()
    cn, san, usage = _role(role, ip=server_ip, node_id=node_id)
    key = ec.generate_private_key(ec.SECP256R1())
    csr = (x509.CertificateSigningRequestBuilder()
           .subject_name(_name(cn))
           .add_extension(san, critical=False)
           .sign(key, hashes.SHA256()))
    _two_files(key_path, _ec_key_pem(key, serialization),
               csr_path, csr.public_bytes(serialization.Encoding.PEM))
    return {"role": role, "subject": cn, "csr_generated": True,
            "private_key_exported": False}


def _ca_credentials(key_path: Path, cert_path: Path, now: datetime):
    x509, hashes, serialization, ec, EKU, NameOID = _modules()
    try:
        key = serialization.load_pem_private_key(
            _load_file(key_path, secret=True), password=None)
        ca = x509.load_pem_x509_certificate(_load_file(cert_path))
    except (ValueError, TypeError) as exc:
        raise PKIError("CA key or certificate invalid") from exc
    if not isinstance(key, ec.EllipticCurvePrivateKey) or not isinstance(
            key.curve, ec.SECP256R1):
        raise PKIError("lab CA must use a P-256 private key")
    if key.public_key().public_numbers() != ca.public_key().public_numbers():
        raise PKIError("CA private key does not match CA certificate")
    if ca.subject != ca.issuer or ca.subject != _name(CA_CN):
        raise PKIError("unrecognized CA identity")
    if not ca.not_valid_before_utc <= now < ca.not_valid_after_utc:
        raise PKIError("CA certificate expired or not yet valid")
    try:
        basic = ca.extensions.get_extension_for_class(x509.BasicConstraints).value
        usage = ca.extensions.get_extension_for_class(x509.KeyUsage).value
    except x509.ExtensionNotFound as exc:
        raise PKIError("CA lacks mandatory constraints") from exc
    if not basic.ca or basic.path_length != 0 or not usage.key_cert_sign:
        raise PKIError("not an authorized signing CA")
    try:
        ca.public_key().verify(ca.signature, ca.tbs_certificate_bytes,
                               ec.ECDSA(ca.signature_hash_algorithm))
    except Exception as exc:
        raise PKIError("CA self-signature invalid") from exc
    return key, ca


def sign_csr(ca_key: Path, ca_cert: Path, csr_path: Path,
             cert_out: Path, *, role: str,
             server_ip: str | None = None, node_id: str | None = None,
             days: int = 14, now: datetime | None = None) -> dict:
    """Operator verifies CSR identity *out of band* before signing."""
    x509, hashes, serialization, ec, EKU, NameOID = _modules()
    stamp = now or datetime.now(timezone.utc)
    if stamp.tzinfo is None:
        raise PKIError("signing time must be timezone aware")
    if type(days) is not int or not 1 <= days <= CERT_DAYS_MAX:
        raise PKIError("leaf validity must be 1..30 days")
    cn, san, role_usage = _role(role, ip=server_ip, node_id=node_id)
    key, ca = _ca_credentials(ca_key, ca_cert, stamp)
    try:
        csr = x509.load_pem_x509_csr(_load_file(csr_path))
    except ValueError as exc:
        raise PKIError("invalid certificate signing request") from exc
    if not csr.is_signature_valid:
        raise PKIError("CSR signature invalid")
    if csr.subject != _name(cn):
        raise PKIError("CSR subject does not match verified server/node identity")
    extensions = list(csr.extensions)
    if (len(extensions) != 1 or extensions[0].oid !=
            x509.ExtensionOID.SUBJECT_ALTERNATIVE_NAME or
            extensions[0].value != san):
        raise PKIError("CSR extensions do not match approved role and exact SAN")
    if not isinstance(csr.public_key(), ec.EllipticCurvePublicKey) or not isinstance(
            csr.public_key().curve, ec.SECP256R1):
        raise PKIError("CSR must use a P-256 public key")
    expiry = min(stamp + timedelta(days=days),
                 ca.not_valid_after_utc - timedelta(minutes=1))
    if expiry <= stamp:
        raise PKIError("CA expires before requested certificate can be issued")
    cert = (x509.CertificateBuilder()
            .subject_name(csr.subject).issuer_name(ca.subject)
            .public_key(csr.public_key())
            .serial_number(x509.random_serial_number())
            .not_valid_before(stamp - timedelta(minutes=2))
            .not_valid_after(expiry)
            .add_extension(x509.BasicConstraints(ca=False, path_length=None), critical=True)
            .add_extension(x509.KeyUsage(
                digital_signature=True, content_commitment=False,
                key_encipherment=False, data_encipherment=False,
                key_agreement=False, key_cert_sign=False, crl_sign=False,
                encipher_only=False, decipher_only=False), critical=True)
            .add_extension(x509.ExtendedKeyUsage([role_usage]), critical=False)
            .add_extension(san, critical=False)
            .add_extension(x509.AuthorityKeyIdentifier.from_issuer_public_key(
                key.public_key()), critical=False)
            .sign(key, hashes.SHA256()))
    _new_file(cert_out, _cert_pem(cert, serialization), secret=False)
    return {"role": role, "subject": cn,
            "certificate_sha256": _fingerprint(cert, serialization),
            "expires_at": cert.not_valid_after_utc.isoformat(),
            "ca_certificate_sha256": _fingerprint(ca, serialization),
            "private_key_exported": False,
            "node_execution_authorized": False}


def inspect_certificate(cert_path: Path) -> dict:
    x509, hashes, serialization, ec, EKU, NameOID = _modules()
    try:
        cert = x509.load_pem_x509_certificate(_load_file(cert_path))
        san = cert.extensions.get_extension_for_class(
            x509.SubjectAlternativeName).value
        values = [str(x) for x in san]
    except (ValueError, x509.ExtensionNotFound) as exc:
        raise PKIError("not a role-specific X.509 leaf certificate") from exc
    try:
        usage = cert.extensions.get_extension_for_class(
            x509.ExtendedKeyUsage).value
        role = ("server" if EKU.SERVER_AUTH in usage else
                "client" if EKU.CLIENT_AUTH in usage else "unknown")
    except x509.ExtensionNotFound:
        role = "unknown"
    now = datetime.now(timezone.utc)
    return {
        "certificate_sha256": _fingerprint(cert, serialization),
        "role": role, "subject": cert.subject.rfc4514_string(),
        "subject_alternative_names": values,
        "expires_at": cert.not_valid_after_utc.isoformat(),
        "currently_valid": cert.not_valid_before_utc <= now < cert.not_valid_after_utc
    }


def main(argv=None) -> int:
    p = argparse.ArgumentParser(
        description="Offline lab X.509 CA and CSR workflow; no network or auto-enrollment")
    commands = p.add_subparsers(dest="action", required=True)
    ca = commands.add_parser("init-ca")
    ca.add_argument("--ca-key", type=Path, required=True)
    ca.add_argument("--ca-cert", type=Path, required=True)
    request = commands.add_parser("create-csr")
    request.add_argument("--key", type=Path, required=True)
    request.add_argument("--csr", type=Path, required=True)
    signed = commands.add_parser("sign-csr")
    signed.add_argument("--ca-key", type=Path, required=True)
    signed.add_argument("--ca-cert", type=Path, required=True)
    signed.add_argument("--csr", type=Path, required=True)
    signed.add_argument("--out", type=Path, required=True)
    signed.add_argument("--days", type=int, default=14)
    for sub in (request, signed):
        sub.add_argument("--role", choices=("server", "client"), required=True)
        specific = sub.add_mutually_exclusive_group(required=True)
        specific.add_argument("--server-ip")
        specific.add_argument("--node-id")
    inspect = commands.add_parser("inspect")
    inspect.add_argument("--cert", type=Path, required=True)
    args = p.parse_args(argv)
    try:
        if args.action == "init-ca":
            result = init_ca(args.ca_key, args.ca_cert)
        elif args.action == "create-csr":
            result = create_csr(args.key, args.csr,
                                role=args.role, server_ip=args.server_ip,
                                node_id=args.node_id)
        elif args.action == "sign-csr":
            result = sign_csr(args.ca_key, args.ca_cert, args.csr, args.out,
                              role=args.role, server_ip=args.server_ip,
                              node_id=args.node_id, days=args.days)
        else:
            result = inspect_certificate(args.cert)
        print(json.dumps(result, indent=2, sort_keys=True))
        return 0
    except (PKIError, OSError, ValueError, TypeError) as exc:
        p.exit(2, f"refused: {exc}\n")


if __name__ == "__main__":
    raise SystemExit(main())
