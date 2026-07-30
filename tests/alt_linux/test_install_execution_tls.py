from __future__ import annotations

import json
import os
from pathlib import Path
import socket
import ssl
import sys
import threading
from datetime import datetime, timedelta, timezone
import ipaddress

import pytest
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.x509.oid import NameOID


REPO_ROOT = Path(__file__).resolve().parents[2]
CONTROL_ROOT = REPO_ROOT / "deploy" / "alt-linux" / "control"
API_ROOT = REPO_ROOT / "deploy" / "alt-linux" / "api"
for path in (CONTROL_ROOT, API_ROOT):
    if str(path) not in sys.path:
        sys.path.insert(0, str(path))

from alt_deploy.config import Settings
from alt_deploy import install_tls
from alt_deploy.install_tls import ensure_execution_tls_material
import install_execution_server
from install_execution_server import create_execution_tls_server


def _has_root_authority() -> bool:
    return os.name != "nt" and os.geteuid() == 0


def _settings(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> Settings:
    monkeypatch.setenv("ALT_DEPLOY_INSTALL_EXECUTION_TLS_ROOT", str(tmp_path / "tls"))
    monkeypatch.setenv("ALT_DEPLOY_INSTALL_EXECUTION_CA_CERTIFICATE", str(tmp_path / "etc" / "ca.pem"))
    monkeypatch.setenv("ALT_DEPLOY_INSTALL_EXECUTION_SERVER_CERTIFICATE", str(tmp_path / "etc" / "server.pem"))
    monkeypatch.setenv("ALT_DEPLOY_INSTALL_EXECUTION_LISTEN_ADDRESS", "127.0.0.1")
    return Settings.from_env()


def _health(port: int, cafile: Path, *, tls12_only: bool = False) -> dict[str, object]:
    context = ssl.create_default_context(cafile=str(cafile))
    if tls12_only:
        context.minimum_version = ssl.TLSVersion.TLSv1_2
        context.maximum_version = ssl.TLSVersion.TLSv1_2
    with socket.create_connection(("127.0.0.1", port), timeout=3) as raw:
        with context.wrap_socket(raw, server_hostname="127.0.0.1") as secure:
            secure.sendall(b"GET /health HTTP/1.1\r\nHost: 127.0.0.1\r\nConnection: close\r\n\r\n")
            response = b"".join(iter(lambda: secure.recv(4096), b""))
    _head, body = response.split(b"\r\n\r\n", 1)
    return json.loads(body)


@pytest.mark.skipif(not _has_root_authority(), reason="TLS authority material requires Linux root")
def test_tls_material_has_expected_modes_and_is_idempotent(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    material = ensure_execution_tls_material(_settings(tmp_path, monkeypatch))

    assert ensure_execution_tls_material(_settings(tmp_path, monkeypatch)) == material
    if os.name != "nt":
        assert material.server_private_key.stat().st_mode & 0o777 == 0o600
        assert material.server_certificate.stat().st_mode & 0o777 == 0o644
        assert material.ca_certificate.stat().st_mode & 0o777 == 0o644


def test_tls_material_refuses_creation_without_root_authority(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(install_tls, "_is_root", lambda: False)

    with pytest.raises(PermissionError, match="root"):
        ensure_execution_tls_material(_settings(tmp_path, monkeypatch))


@pytest.mark.skipif(not _has_root_authority(), reason="root ownership is a Linux root contract")
def test_tls_material_is_owned_by_root_when_created_as_root(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    material = ensure_execution_tls_material(_settings(tmp_path, monkeypatch))

    assert material.server_private_key.stat().st_uid == 0
    assert material.server_private_key.stat().st_gid == 0
    assert material.server_private_key.stat().st_mode & 0o777 == 0o600


@pytest.mark.skipif(not _has_root_authority(), reason="TLS authority material requires Linux root")
def test_tls_listener_accepts_only_trusted_tls13_clients(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    settings = _settings(tmp_path, monkeypatch)
    material = ensure_execution_tls_material(settings)
    server = create_execution_tls_server(settings, material, listen_port=0)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        port = int(server.server_address[1])
        assert _health(port, material.ca_certificate) == {"schema_version": 1, "service": "alt-install-execution", "status": "ok"}
        wrong_ca = ensure_execution_tls_material(_settings(tmp_path / "wrong", monkeypatch)).ca_certificate
        with pytest.raises(ssl.SSLCertVerificationError):
            _health(port, wrong_ca)
        with pytest.raises(ssl.SSLError):
            _health(port, material.ca_certificate, tls12_only=True)
        with socket.create_connection(("127.0.0.1", port), timeout=3) as plain:
            plain.sendall(b"GET /health HTTP/1.1\r\nHost: 127.0.0.1\r\n\r\n")
            try:
                assert plain.recv(4096) == b""
            except ConnectionResetError:
                pass
    finally:
        server.shutdown()
        server.server_close()
        thread.join(timeout=3)


@pytest.mark.skipif(not _has_root_authority(), reason="TLS authority material requires Linux root")
def test_tls_listener_rejects_an_expired_server_certificate(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    settings = _settings(tmp_path, monkeypatch)
    material = ensure_execution_tls_material(settings)
    ca_key = serialization.load_pem_private_key(
        settings.install_execution_ca_private_key.read_bytes(), password=None
    )
    server_key = serialization.load_pem_private_key(material.server_private_key.read_bytes(), password=None)
    ca = x509.load_pem_x509_certificate(material.ca_certificate.read_bytes())
    now = datetime.now(timezone.utc)
    expired = (
        x509.CertificateBuilder()
        .subject_name(x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "127.0.0.1")]))
        .issuer_name(ca.subject)
        .public_key(server_key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - timedelta(days=2))
        .not_valid_after(now - timedelta(days=1))
        .add_extension(x509.BasicConstraints(ca=False, path_length=None), critical=True)
        .add_extension(x509.SubjectAlternativeName([x509.IPAddress(ipaddress.ip_address("127.0.0.1"))]), critical=False)
        .sign(ca_key, hashes.SHA256())
    )
    material.server_certificate.write_bytes(expired.public_bytes(serialization.Encoding.PEM))
    server = create_execution_tls_server(settings, material, listen_port=0)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        with pytest.raises(ssl.SSLCertVerificationError):
            _health(int(server.server_address[1]), material.ca_certificate)
    finally:
        server.shutdown()
        server.server_close()
        thread.join(timeout=3)


@pytest.mark.skipif(not _has_root_authority(), reason="TLS authority material requires Linux root")
def test_runtime_uses_credential_copy_without_reading_root_key(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    settings = _settings(tmp_path, monkeypatch)
    material = ensure_execution_tls_material(settings)

    class _Server:
        def serve_forever(self) -> None:
            return

        def server_close(self) -> None:
            return

    monkeypatch.setattr(
        install_execution_server,
        "ensure_execution_tls_material",
        lambda _settings: pytest.fail("runtime read the root-only key"),
        raising=False,
    )
    monkeypatch.setattr(
        install_execution_server,
        "load_execution_tls_material",
        lambda _settings: material,
        raising=False,
    )
    monkeypatch.setattr(
        install_execution_server,
        "create_execution_tls_server",
        lambda *_args, **_kwargs: _Server(),
    )

    monkeypatch.setenv("ALT_DEPLOY_INSTALL_EXECUTION_LISTEN_ADDRESS", "192.168.100.17")
    assert install_execution_server.main([
        "--listen-address", "192.168.100.17", "--listen-port", "18092",
        "--credential-key", str(material.server_private_key),
    ]) == 0


@pytest.mark.parametrize(
    ("address", "port"),
    (("127.0.0.1", "18092"), ("192.168.100.17", "18492")),
)
def test_runtime_rejects_any_listener_other_than_fixed_v2_endpoint(
    address: str, port: str,
) -> None:
    with pytest.raises(SystemExit) as exc_info:
        install_execution_server.main([
            "--listen-address", address, "--listen-port", port,
            "--credential-key", "/run/credentials/execution-tls-key",
        ])

    assert exc_info.value.code == 2
