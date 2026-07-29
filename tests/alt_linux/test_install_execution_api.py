from __future__ import annotations

import hashlib
import http.client
import ipaddress
import json
import socket
import ssl
import sys
import threading
from contextlib import contextmanager
from datetime import datetime, timedelta, timezone
from pathlib import Path

import pytest
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.x509.oid import NameOID


REPO_ROOT = Path(__file__).resolve().parents[2]
CONTROL_ROOT = REPO_ROOT / "deploy" / "alt-linux" / "control"
API_ROOT = REPO_ROOT / "deploy" / "alt-linux" / "api"
for path in (CONTROL_ROOT, API_ROOT):
    if str(path) not in sys.path:
        sys.path.insert(0, str(path))

from alt_deploy.config import Settings
from alt_deploy.errors import ControlError
from alt_deploy.install_session_repository import InstallSessionRepository
from alt_deploy.install_tls import TLSMaterial
import install_execution_server
from install_execution_server import create_execution_tls_server


SESSION_ID = "install-20260729T120000Z-a1b2c3d4"
CREDENTIAL = "E" * 43
ARTIFACTS = {
    "autoinstall.scm": b"(define execution-secret \"opaque\")\n",
    "vm-profile.scm": b"(define target \"/dev/vda\")\n",
    "pkg-groups.tar": b"pkg-groups-fixture",
    "install-scripts.tar": b"install-scripts-fixture",
}
MANIFEST = b'{"schema_version":1,"session_id":"' + SESSION_ID.encode("ascii") + b'"}\n'


class _ClaimService:
    def __init__(self) -> None:
        self.claimed: list[str] = []

    def claim(self, session_id: str) -> dict[str, object]:
        if self.claimed:
            raise ControlError(
                "execution_claim_conflict",
                "Install execution cannot be claimed",
                4,
            )
        self.claimed.append(session_id)
        return {"execution": {"state": "claimed"}}


def _settings_in(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> Settings:
    monkeypatch.setenv(
        "ALT_DEPLOY_INSTALL_SESSIONS", str(tmp_path / "sessions")
    )
    monkeypatch.setenv(
        "ALT_DEPLOY_INSTALL_SESSIONS_LOCK",
        str(tmp_path / "sessions.lock"),
    )
    monkeypatch.setenv(
        "ALT_DEPLOY_INSTALL_EXECUTION_LISTEN_ADDRESS", "127.0.0.1"
    )
    return Settings.from_env()


def _tls_material(tmp_path: Path) -> TLSMaterial:
    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    subject = x509.Name(
        [x509.NameAttribute(NameOID.COMMON_NAME, "127.0.0.1")]
    )
    now = datetime.now(timezone.utc)
    certificate = (
        x509.CertificateBuilder()
        .subject_name(subject)
        .issuer_name(subject)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - timedelta(minutes=1))
        .not_valid_after(now + timedelta(hours=1))
        .add_extension(
            x509.BasicConstraints(ca=True, path_length=None),
            critical=True,
        )
        .add_extension(
            x509.SubjectAlternativeName(
                [x509.IPAddress(ipaddress.ip_address("127.0.0.1"))]
            ),
            critical=False,
        )
        .sign(key, hashes.SHA256())
    )
    certificate_path = tmp_path / "server.pem"
    key_path = tmp_path / "server-key.pem"
    certificate_path.write_bytes(
        certificate.public_bytes(serialization.Encoding.PEM)
    )
    key_path.write_bytes(
        key.private_bytes(
            serialization.Encoding.PEM,
            serialization.PrivateFormat.PKCS8,
            serialization.NoEncryption(),
        )
    )
    return TLSMaterial(
        ca_certificate=certificate_path,
        server_certificate=certificate_path,
        server_private_key=key_path,
    )


def _authorized_repository(settings: Settings) -> InstallSessionRepository:
    repository = InstallSessionRepository(settings)
    repository.create(
        session_id=SESSION_ID,
        inventory_bytes=b'{"schema_version":1}\n',
        credential_sha256=hashlib.sha256(
            CREDENTIAL.encode("ascii")
        ).hexdigest(),
        create_nonce_sha256="a" * 64,
        status={
            "schema_version": 1,
            "session_id": SESSION_ID,
            "state": "plan_published",
            "execution": {
                "schema_version": 1,
                "revision": 1,
                "state": "authorized",
                "authorized_at": "2026-07-29T12:02:00+00:00",
                "expires_at": "2099-01-01T00:00:00+00:00",
                "plan_sha256": "b" * 64,
                "inventory_sha256": "c" * 64,
                "disk_fingerprint": "sha256:" + "d" * 64,
                "target_disk": "/dev/vda",
                "reason": "Authorize disposable test target",
                "profile_id": "alt-kworkstation-11.4",
                "profile_version": 1,
                "iso_id": "alt-kworkstation-11.4-x86_64",
                "iso_sha256": "e" * 64,
                "manifest_sha256": hashlib.sha256(MANIFEST).hexdigest(),
                "claimed_at": None,
                "handoff_started_at": None,
                "installer_started_at": None,
                "installed_at": None,
                "failed_at": None,
                "failure_code": None,
                "cancelled_at": None,
                "cancel_reason": None,
                "expired_at": None,
            },
        },
    )
    repository.publish_execution(
        SESSION_ID,
        files={
            "execution-manifest.json": MANIFEST,
            "execution-manifest-signature.json": b'{"signature":"opaque"}\n',
            **ARTIFACTS,
        },
    )
    return repository


@contextmanager
def _running(server: object):
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        yield
    finally:
        server.shutdown()
        server.server_close()
        thread.join(timeout=3)


def _request(
    server: object,
    material: TLSMaterial,
    method: str,
    path: str,
    *,
    bearer: str | None = None,
    body: bytes | None = None,
) -> tuple[int, dict[str, str], bytes]:
    context = ssl.create_default_context(
        cafile=str(material.ca_certificate)
    )
    host, port = server.server_address
    connection = http.client.HTTPSConnection(
        host, port, timeout=3, context=context
    )
    headers = {}
    if bearer is not None:
        headers["Authorization"] = f"Bearer {bearer}"
    connection.request(method, path, body=body, headers=headers)
    response = connection.getresponse()
    payload = response.read()
    response_headers = dict(response.getheaders())
    connection.close()
    return response.status, response_headers, payload


@pytest.fixture
def tls_server(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> tuple[object, TLSMaterial, _ClaimService, Settings]:
    settings = _settings_in(tmp_path, monkeypatch)
    _authorized_repository(settings)
    material = _tls_material(tmp_path)
    claims = _ClaimService()
    monkeypatch.setattr(
        install_execution_server,
        "ExecutionAuthorizationService",
        lambda *args, **kwargs: claims,
        raising=False,
    )
    server = create_execution_tls_server(
        settings,
        material,
        listen_port=0,
    )
    return server, material, claims, settings


def test_manifest_route_requires_the_session_bearer_and_is_no_store(
    tls_server: tuple[object, TLSMaterial, _ClaimService, Settings],
) -> None:
    server, material, _claims, settings = tls_server
    path = f"/v2/install-sessions/{SESSION_ID}/execution/manifest"
    status_path = settings.install_sessions_dir / SESSION_ID / "status.json"
    status_before = status_path.read_bytes()

    with _running(server):
        missing = _request(server, material, "GET", path)
        invalid = _request(
            server, material, "GET", path, bearer="F" * 43
        )
        status, headers, body = _request(
            server, material, "GET", path, bearer=CREDENTIAL
        )

    assert missing[0] == 401
    assert invalid[0] == 403
    assert (status, body) == (200, MANIFEST)
    assert headers["Cache-Control"] == "no-store"
    assert headers["Content-Length"] == str(len(MANIFEST))
    assert "Location" not in headers
    assert status_path.read_bytes() == status_before


def test_artifact_route_accepts_only_four_literal_expected_names(
    tls_server: tuple[object, TLSMaterial, _ClaimService, Settings],
) -> None:
    server, material, _claims, _settings = tls_server
    root = f"/v2/install-sessions/{SESSION_ID}/execution/artifacts"

    with _running(server):
        accepted = {
            name: _request(
                server,
                material,
                "GET",
                f"{root}/{name}",
                bearer=CREDENTIAL,
            )
            for name in ARTIFACTS
        }
        rejected = [
            _request(
                server,
                material,
                "GET",
                path,
                bearer=CREDENTIAL,
            )
            for path in (
                f"{root}/../status.json",
                f"{root}/%2e%2e%2fstatus.json",
                f"{root}/autoinstall.scm?download=1",
                f"{root}/execution-manifest-signature.json",
                f"{root}/AUTOINSTALL.SCM",
                f"{root}/autoinstall.scm/",
                f"/v1/install-sessions/{SESSION_ID}/status",
            )
        ]

    assert {
        name: (status, body)
        for name, (status, _headers, body) in accepted.items()
    } == {name: (200, content) for name, content in ARTIFACTS.items()}
    assert all(
        headers["Cache-Control"] == "no-store"
        and headers["Content-Length"] == str(len(ARTIFACTS[name]))
        and "Location" not in headers
        for name, (_status, headers, _body) in accepted.items()
    )
    assert [response[0] for response in rejected] == [404] * len(rejected)
    assert all("Location" not in response[1] for response in rejected)


def test_claim_route_is_single_use_and_rejects_request_bodies(
    tls_server: tuple[object, TLSMaterial, _ClaimService, Settings],
) -> None:
    server, material, claims, _settings = tls_server
    path = f"/v2/install-sessions/{SESSION_ID}/execution/claim"

    with _running(server):
        missing = _request(server, material, "POST", path)
        invalid = _request(
            server,
            material,
            "POST",
            path,
            bearer="F" * 43,
        )
        with_body = _request(
            server,
            material,
            "POST",
            path,
            bearer=CREDENTIAL,
            body=b"{}",
        )
        first = _request(
            server, material, "POST", path, bearer=CREDENTIAL
        )
        second = _request(
            server, material, "POST", path, bearer=CREDENTIAL
        )

    assert missing[0] == 401
    assert invalid[0] == 403
    assert with_body[0] == 400
    assert first[0] == 200
    assert json.loads(first[2]) == {
        "execution": {"state": "claimed"},
        "status": "ok",
    }
    assert second[0] == 409
    assert claims.claimed == [SESSION_ID]
    assert all(
        response[1]["Cache-Control"] == "no-store"
        and "Location" not in response[1]
        for response in (with_body, first, second)
    )


def test_reads_require_a_current_execution_authorization(
    tls_server: tuple[object, TLSMaterial, _ClaimService, Settings],
) -> None:
    server, material, _claims, settings = tls_server
    path = f"/v2/install-sessions/{SESSION_ID}/execution/manifest"
    status_path = settings.install_sessions_dir / SESSION_ID / "status.json"
    status = json.loads(status_path.read_text(encoding="utf-8"))
    execution = status.pop("execution")
    status_path.write_text(json.dumps(status), encoding="utf-8")

    with _running(server):
        not_authorized = _request(
            server, material, "GET", path, bearer=CREDENTIAL
        )
        execution["authorized_at"] = "2020-01-01T00:00:00+00:00"
        execution["expires_at"] = "2020-01-01T00:05:00+00:00"
        status["execution"] = execution
        status_path.write_text(json.dumps(status), encoding="utf-8")
        expired = _request(
            server, material, "GET", path, bearer=CREDENTIAL
        )

    assert not_authorized[0] == 409
    assert expired[0] == 410
    assert all(
        response[1]["Cache-Control"] == "no-store"
        and "Location" not in response[1]
        for response in (not_authorized, expired)
    )


def test_v2_listener_rejects_plain_http_without_a_response(
    tls_server: tuple[object, TLSMaterial, _ClaimService, Settings],
) -> None:
    server, _material, _claims, _settings = tls_server

    with _running(server):
        host, port = server.server_address
        with socket.create_connection((host, port), timeout=3) as plain:
            plain.sendall(
                b"GET /health HTTP/1.1\r\n"
                b"Host: 127.0.0.1\r\nConnection: close\r\n\r\n"
            )
            try:
                assert plain.recv(4096) == b""
            except ConnectionResetError:
                pass
