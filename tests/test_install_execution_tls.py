from __future__ import annotations

import json
import os
from pathlib import Path
import socket
import ssl
import sys
import threading

import pytest


REPO_ROOT = Path(__file__).resolve().parents[1]
CONTROL_ROOT = REPO_ROOT / "deploy" / "alt-linux" / "control"
API_ROOT = REPO_ROOT / "deploy" / "alt-linux" / "api"
UNIT = REPO_ROOT / "deploy" / "alt-linux" / "systemd" / "alt-install-execution.service"
for path in (CONTROL_ROOT, API_ROOT):
    if str(path) not in sys.path:
        sys.path.insert(0, str(path))

from alt_deploy.config import Settings
from alt_deploy.install_tls import ensure_execution_tls_material
from install_execution_server import create_execution_tls_server


def _settings(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> Settings:
    monkeypatch.setenv("ALT_DEPLOY_INSTALL_EXECUTION_TLS_ROOT", str(tmp_path / "tls"))
    monkeypatch.setenv(
        "ALT_DEPLOY_INSTALL_EXECUTION_CA_CERTIFICATE",
        str(tmp_path / "certificates" / "execution-ca.pem"),
    )
    monkeypatch.setenv(
        "ALT_DEPLOY_INSTALL_EXECUTION_SERVER_CERTIFICATE",
        str(tmp_path / "certificates" / "execution-server.pem"),
    )
    monkeypatch.setenv("ALT_DEPLOY_INSTALL_EXECUTION_LISTEN_ADDRESS", "127.0.0.1")
    monkeypatch.setenv("ALT_DEPLOY_INSTALL_EXECUTION_LISTEN_PORT", "18492")
    return Settings.from_env()


def _https_health(port: int, cafile: Path) -> dict[str, object]:
    context = ssl.create_default_context(cafile=str(cafile))
    with socket.create_connection(("127.0.0.1", port), timeout=3) as raw:
        with context.wrap_socket(raw, server_hostname="127.0.0.1") as secure:
            secure.sendall(
                b"GET /health HTTP/1.1\r\nHost: 127.0.0.1\r\nConnection: close\r\n\r\n"
            )
            response = bytearray()
            while block := secure.recv(4096):
                response.extend(block)
    head, body = bytes(response).split(b"\r\n\r\n", 1)
    assert head.startswith(b"HTTP/1.0 200")
    return json.loads(body.decode("utf-8"))


def test_tls_material_is_idempotent_and_server_certificate_covers_listener(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    settings = _settings(tmp_path, monkeypatch)

    first = ensure_execution_tls_material(settings)
    second = ensure_execution_tls_material(settings)

    assert first == second
    assert first.ca_certificate.is_file()
    assert first.server_certificate.is_file()
    assert first.server_private_key.is_file()
    if os.name != "nt":
        assert first.server_private_key.stat().st_mode & 0o777 == 0o600


def test_tls_listener_serves_health_only_with_trusted_ca(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    settings = _settings(tmp_path, monkeypatch)
    material = ensure_execution_tls_material(settings)
    server = create_execution_tls_server(settings, material, listen_port=0)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        port = int(server.server_address[1])
        assert _https_health(port, material.ca_certificate) == {
            "schema_version": 1,
            "service": "alt-install-execution",
            "status": "ok",
        }
        wrong_ca = ensure_execution_tls_material(
            _settings(tmp_path / "other", monkeypatch)
        ).ca_certificate
        with pytest.raises(ssl.SSLCertVerificationError):
            _https_health(port, wrong_ca)
    finally:
        server.shutdown()
        server.server_close()
        thread.join(timeout=3)


def test_execution_unit_uses_systemd_credential_without_root_handler() -> None:
    text = UNIT.read_text(encoding="utf-8")

    assert "User=altserver" in text
    assert "Group=altserver" in text
    assert "--listen-address 192.168.100.17 --listen-port 18092" in text
    assert (
        "LoadCredential=execution-tls-key:"
        "/var/lib/alt-deploy-secrets/install-execution-server.pem" in text
    )
    assert "--credential-key %d/execution-tls-key" in text
    for setting in (
        "NoNewPrivileges=true",
        "PrivateTmp=true",
        "PrivateDevices=true",
        "ProtectSystem=strict",
        "ProtectHome=read-only",
        "RestrictAddressFamilies=AF_INET AF_INET6",
        "CapabilityBoundingSet=",
    ):
        assert setting in text
