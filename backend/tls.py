"""Application-private trust material, renewed before any backend listener starts."""

from __future__ import annotations

import ipaddress
import ssl
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from pathlib import Path

from cryptography import x509
from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.x509.oid import ExtendedKeyUsageOID, NameOID

from backend.platform_utils import assert_private_path, atomic_private_write, protect_private_path


@dataclass(frozen=True)
class TLSMaterial:
    ca_cert: Path
    server_cert: Path
    server_key: Path
    fingerprint: str

    def client_context(self) -> ssl.SSLContext:
        context = ssl.create_default_context(cafile=str(self.ca_cert))
        context.minimum_version = ssl.TLSVersion.TLSv1_2
        context.check_hostname = True
        context.verify_mode = ssl.CERT_REQUIRED
        return context


def _private_key_bytes(key: ec.EllipticCurvePrivateKey) -> bytes:
    return key.private_bytes(
        serialization.Encoding.PEM,
        serialization.PrivateFormat.PKCS8,
        serialization.NoEncryption(),
    )


def _load_key(path: Path) -> ec.EllipticCurvePrivateKey:
    assert_private_path(path)
    key = serialization.load_pem_private_key(path.read_bytes(), password=None)
    if not isinstance(key, ec.EllipticCurvePrivateKey):
        raise ValueError("Unexpected private key type.")
    return key


def _public_bytes(key: ec.EllipticCurvePrivateKey) -> bytes:
    return key.public_key().public_bytes(
        serialization.Encoding.DER, serialization.PublicFormat.SubjectPublicKeyInfo
    )


def _matches_key(cert: x509.Certificate, key: ec.EllipticCurvePrivateKey) -> bool:
    return cert.public_key().public_bytes(
        serialization.Encoding.DER, serialization.PublicFormat.SubjectPublicKeyInfo
    ) == _public_bytes(key)


def _valid(cert: x509.Certificate, now: datetime) -> bool:
    expired = cert.not_valid_after_utc <= now
    days_remaining = (cert.not_valid_after_utc - now).total_seconds() / 86400
    return not (expired or days_remaining < 7) and cert.not_valid_before_utc <= now


def ensure_tls(profile: Path, *, now: datetime | None = None) -> TLSMaterial:
    """Repair missing, corrupt, expired or near-expiry CA/leaf before startup."""
    instant = now or datetime.now(UTC)
    if instant.tzinfo is None:
        raise ValueError("Certificate clock must be timezone-aware.")
    tls = profile / "tls"
    tls.mkdir(parents=True, exist_ok=True)
    protect_private_path(tls, directory=True)
    ca_path, ca_key_path = tls / "ca.pem", tls / "ca-key.pem"
    cert_path, key_path = tls / "server.pem", tls / "server-key.pem"
    ca_cert: x509.Certificate | None = None
    ca_key: ec.EllipticCurvePrivateKey | None = None
    try:
        if ca_path.exists() and ca_key_path.exists():
            assert_private_path(ca_path)
            ca_cert = x509.load_pem_x509_certificate(ca_path.read_bytes())
            ca_key = _load_key(ca_key_path)
            ca_cert.verify_directly_issued_by(ca_cert)
            if (
                not _valid(ca_cert, instant)
                or not _matches_key(ca_cert, ca_key)
                or not ca_cert.extensions.get_extension_for_class(x509.BasicConstraints).value.ca
            ):
                ca_cert = None
    except (ValueError, x509.ExtensionNotFound, TypeError, InvalidSignature):
        ca_cert = None
    replaced_ca = ca_cert is None
    if ca_cert is None:
        ca_key = ec.generate_private_key(ec.SECP256R1())
        name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "Toolkit private instance CA")])
        ca_cert = (
            x509.CertificateBuilder()
            .subject_name(name)
            .issuer_name(name)
            .public_key(ca_key.public_key())
            .serial_number(x509.random_serial_number())
            .not_valid_before(instant - timedelta(minutes=5))
            .not_valid_after(instant + timedelta(days=365))
            .add_extension(x509.BasicConstraints(ca=True, path_length=0), critical=True)
            .add_extension(
                x509.KeyUsage(False, False, False, False, False, True, True, False, False),
                critical=True,
            )
            .sign(ca_key, hashes.SHA256())
        )
        atomic_private_write(ca_key_path, _private_key_bytes(ca_key))
        atomic_private_write(ca_path, ca_cert.public_bytes(serialization.Encoding.PEM))
    assert ca_key is not None
    server_cert: x509.Certificate | None = None
    try:
        if not replaced_ca and cert_path.exists() and key_path.exists():
            assert_private_path(cert_path)
            server_cert = x509.load_pem_x509_certificate(cert_path.read_bytes())
            key = _load_key(key_path)
            server_cert.verify_directly_issued_by(ca_cert)
            sans = server_cert.extensions.get_extension_for_class(x509.SubjectAlternativeName).value
            if (
                not _valid(server_cert, instant)
                or not _matches_key(server_cert, key)
                or ipaddress.IPv4Address("127.0.0.1")
                not in sans.get_values_for_type(x509.IPAddress)
                or "localhost" not in sans.get_values_for_type(x509.DNSName)
            ):
                server_cert = None
    except (ValueError, x509.ExtensionNotFound, TypeError, InvalidSignature):
        server_cert = None
    if server_cert is None:
        key = ec.generate_private_key(ec.SECP256R1())
        server_cert = (
            x509.CertificateBuilder()
            .subject_name(x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "localhost")]))
            .issuer_name(ca_cert.subject)
            .public_key(key.public_key())
            .serial_number(x509.random_serial_number())
            .not_valid_before(instant - timedelta(minutes=5))
            .not_valid_after(min(instant + timedelta(days=90), ca_cert.not_valid_after_utc))
            .add_extension(x509.BasicConstraints(ca=False, path_length=None), critical=True)
            .add_extension(
                x509.SubjectAlternativeName(
                    [x509.IPAddress(ipaddress.IPv4Address("127.0.0.1")), x509.DNSName("localhost")]
                ),
                critical=False,
            )
            .add_extension(x509.ExtendedKeyUsage([ExtendedKeyUsageOID.SERVER_AUTH]), critical=False)
            .sign(ca_key, hashes.SHA256())
        )
        atomic_private_write(key_path, _private_key_bytes(key))
        atomic_private_write(cert_path, server_cert.public_bytes(serialization.Encoding.PEM))
    return TLSMaterial(ca_path, cert_path, key_path, server_cert.fingerprint(hashes.SHA256()).hex())
