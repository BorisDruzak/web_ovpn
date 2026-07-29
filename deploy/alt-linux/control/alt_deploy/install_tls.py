from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
import ipaddress
import os
from pathlib import Path
import ssl
import stat

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.x509.oid import NameOID

from .config import Settings


@dataclass(frozen=True)
class TLSMaterial:
    ca_certificate: Path
    server_certificate: Path
    server_private_key: Path


def _is_root() -> bool:
    return os.name != "nt" and getattr(os, "geteuid", lambda: -1)() == 0


def _validate_path(path: Path, *, mode: int, description: str) -> None:
    try:
        metadata = path.lstat()
    except OSError as exc:
        raise ValueError(f"Execution TLS {description} cannot be inspected") from exc
    if not stat.S_ISREG(metadata.st_mode) or stat.S_ISLNK(metadata.st_mode):
        raise ValueError(f"Execution TLS {description} is not a regular file")
    if os.name != "nt" and stat.S_IMODE(metadata.st_mode) != mode:
        raise ValueError(f"Execution TLS {description} permissions are invalid")
    if _is_root() and (metadata.st_uid != 0 or metadata.st_gid != 0):
        raise ValueError(f"Execution TLS {description} ownership is invalid")


def _ensure_directory(path: Path, *, mode: int) -> None:
    if path.exists():
        metadata = path.lstat()
        if stat.S_ISLNK(metadata.st_mode) or not stat.S_ISDIR(metadata.st_mode):
            raise ValueError("Execution TLS directory is unsafe")
    else:
        path.mkdir(parents=True, mode=mode)
    if _is_root():
        os.chown(path, 0, 0)
    os.chmod(path, mode)


def _write_new(path: Path, data: bytes, *, mode: int, description: str) -> None:
    flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL
    if hasattr(os, "O_BINARY"):
        flags |= os.O_BINARY
    if hasattr(os, "O_NOFOLLOW"):
        flags |= os.O_NOFOLLOW
    try:
        descriptor = os.open(path, flags, mode)
    except FileExistsError as exc:
        raise ValueError(f"Execution TLS {description} already exists") from exc
    try:
        if _is_root():
            os.fchown(descriptor, 0, 0)
        os.fchmod(descriptor, mode)
        offset = 0
        while offset < len(data):
            offset += os.write(descriptor, data[offset:])
        os.fsync(descriptor)
    finally:
        os.close(descriptor)


def _private_pem(key: rsa.RSAPrivateKey) -> bytes:
    return key.private_bytes(
        serialization.Encoding.PEM,
        serialization.PrivateFormat.PKCS8,
        serialization.NoEncryption(),
    )


def _certificate_pem(certificate: x509.Certificate) -> bytes:
    return certificate.public_bytes(serialization.Encoding.PEM)


def _build_material(address: str) -> tuple[bytes, bytes, bytes, bytes]:
    try:
        listener_ip = ipaddress.ip_address(address)
    except ValueError as exc:
        raise ValueError("Execution TLS listener address must be an IP address") from exc
    now = datetime.now(timezone.utc)
    ca_key = rsa.generate_private_key(public_exponent=65537, key_size=3072)
    ca_name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "ALT install execution CA")])
    ca_certificate = (
        x509.CertificateBuilder()
        .subject_name(ca_name)
        .issuer_name(ca_name)
        .public_key(ca_key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - timedelta(minutes=1))
        .not_valid_after(now + timedelta(days=3650))
        .add_extension(x509.BasicConstraints(ca=True, path_length=0), critical=True)
        .add_extension(
            x509.SubjectKeyIdentifier.from_public_key(ca_key.public_key()),
            critical=False,
        )
        .add_extension(
            x509.KeyUsage(
                digital_signature=True,
                content_commitment=False,
                key_encipherment=False,
                data_encipherment=False,
                key_agreement=False,
                key_cert_sign=True,
                crl_sign=True,
                encipher_only=False,
                decipher_only=False,
            ),
            critical=True,
        )
        .sign(ca_key, hashes.SHA256())
    )
    server_key = rsa.generate_private_key(public_exponent=65537, key_size=3072)
    server_name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, address)])
    server_certificate = (
        x509.CertificateBuilder()
        .subject_name(server_name)
        .issuer_name(ca_certificate.subject)
        .public_key(server_key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - timedelta(minutes=1))
        .not_valid_after(now + timedelta(days=825))
        .add_extension(x509.BasicConstraints(ca=False, path_length=None), critical=True)
        .add_extension(x509.SubjectAlternativeName([x509.IPAddress(listener_ip)]), critical=False)
        .add_extension(
            x509.SubjectKeyIdentifier.from_public_key(server_key.public_key()),
            critical=False,
        )
        .add_extension(
            x509.AuthorityKeyIdentifier.from_issuer_public_key(ca_key.public_key()),
            critical=False,
        )
        .sign(ca_key, hashes.SHA256())
    )
    return (
        _private_pem(ca_key),
        _certificate_pem(ca_certificate),
        _private_pem(server_key),
        _certificate_pem(server_certificate),
    )


def _validate_material(material: TLSMaterial, address: str) -> None:
    _validate_path(material.ca_certificate, mode=0o644, description="CA certificate")
    _validate_path(material.server_certificate, mode=0o644, description="server certificate")
    _validate_path(material.server_private_key, mode=0o600, description="server private key")
    try:
        ca = x509.load_pem_x509_certificate(material.ca_certificate.read_bytes())
        server = x509.load_pem_x509_certificate(material.server_certificate.read_bytes())
        key = serialization.load_pem_private_key(material.server_private_key.read_bytes(), password=None)
        names = server.extensions.get_extension_for_class(x509.SubjectAlternativeName).value
    except (OSError, ValueError, x509.ExtensionNotFound) as exc:
        raise ValueError("Execution TLS material is invalid") from exc
    if ca.subject != ca.issuer or server.issuer != ca.subject:
        raise ValueError("Execution TLS certificate chain is invalid")
    if address not in {str(item.value) for item in names if isinstance(item, x509.IPAddress)}:
        raise ValueError("Execution TLS certificate listener identity is invalid")
    if key.public_key().public_numbers() != server.public_key().public_numbers():
        raise ValueError("Execution TLS private key does not match certificate")


def ensure_execution_tls_material(settings: Settings) -> TLSMaterial:
    material = TLSMaterial(
        ca_certificate=settings.install_execution_ca_certificate,
        server_certificate=settings.install_execution_server_certificate,
        server_private_key=settings.install_execution_server_private_key,
    )
    paths = (
        settings.install_execution_ca_private_key,
        material.ca_certificate,
        material.server_private_key,
        material.server_certificate,
    )
    exists = [path.exists() for path in paths]
    if any(exists) and not all(exists):
        raise ValueError("Execution TLS material is incomplete")
    if not any(exists):
        _ensure_directory(settings.install_execution_tls_root, mode=0o700)
        _ensure_directory(material.ca_certificate.parent, mode=0o755)
        ca_key, ca_cert, server_key, server_cert = _build_material(
            settings.install_execution_listen_address
        )
        _write_new(settings.install_execution_ca_private_key, ca_key, mode=0o600, description="CA private key")
        _write_new(material.ca_certificate, ca_cert, mode=0o644, description="CA certificate")
        _write_new(material.server_private_key, server_key, mode=0o600, description="server private key")
        _write_new(material.server_certificate, server_cert, mode=0o644, description="server certificate")
    _validate_path(settings.install_execution_ca_private_key, mode=0o600, description="CA private key")
    _validate_material(material, settings.install_execution_listen_address)
    return material


def create_execution_server_context(material: TLSMaterial, *, key_path: Path | None = None) -> ssl.SSLContext:
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    context.minimum_version = ssl.TLSVersion.TLSv1_3
    context.load_cert_chain(
        certfile=str(material.server_certificate),
        keyfile=str(key_path or material.server_private_key),
    )
    return context
