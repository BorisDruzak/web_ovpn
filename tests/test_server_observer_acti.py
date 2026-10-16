"""ACTI checks use the existing observer and never accept runtime commands or URLs."""

import json
import base64
import shutil
import subprocess
import sys
import ssl
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from datetime import datetime, timezone, timedelta

import pytest

from app import server_observer as observer


SERVICES = ("frontend", "api", "postgres", "redis", "worker", "keycloak")
FLAGS = (
    "worker_heartbeat",
    "mounts_verified",
    "storage_capacity",
    "outbox_healthy",
    "backup_fresh",
    "backup_check_fresh",
)


def acti_payload():
    return {
        "format": "acti-observer-v1",
        "services": dict.fromkeys(SERVICES, True),
        **dict.fromkeys(FLAGS, True),
    }


def config():
    return {
        "ssh_key": observer.OBSERVER_KEY_PATH,
        "tunnel_source": "192.0.2.50",
        "targets": [
            {
                "role": "acti",
                "host": "acti.example.invalid",
                "user": "observer",
                "checks": [{"name": "acti", "source": "target"}],
            }
        ],
    }


def test_acti_remote_contract_requires_exact_format_services_and_boolean_fields(
    monkeypatch,
):
    monkeypatch.setattr(observer, "_acti_https_checks", lambda host: [])
    snapshot = observer.collect(
        config(),
        lambda *args, **kwargs: subprocess.CompletedProcess(
            args, 0, json.dumps(acti_payload()), ""
        ),
        observer.parse_utc("2026-10-16T10:00:00Z"),
    )
    target = snapshot["targets"][0]
    assert target["role"] == "acti" and target["status"] == "ok"
    assert len(target["checks"]) == 12
    assert {check["name"] for check in target["checks"]} == {
        s + "_active" for s in SERVICES
    } | set(FLAGS)
    assert all(check["status"] == "ok" for check in target["checks"])


@pytest.mark.parametrize(
    "mutation",
    [
        "missing",
        "extra",
        "service_missing",
        "service_extra",
        "integer",
        "null",
        "format",
        "duplicate",
    ],
)
def test_acti_remote_invalid_contract_fails_closed_without_payload_leakage(
    monkeypatch, mutation
):
    data = acti_payload()
    if mutation == "missing":
        del data["backup_fresh"]
    elif mutation == "extra":
        data["private_path"] = "PRIVATE-MUST-NOT-LEAK"
    elif mutation == "service_missing":
        del data["services"]["redis"]
    elif mutation == "service_extra":
        data["services"]["extra"] = True
    elif mutation == "integer":
        data["worker_heartbeat"] = 1
    elif mutation == "null":
        data["worker_heartbeat"] = None
    elif mutation == "format":
        data["format"] = "other-v1"
    encoded = json.dumps(data)
    if mutation == "duplicate":
        encoded = encoded[:-1] + ',"backup_fresh":false}'
    monkeypatch.setattr(observer, "_acti_https_checks", lambda host: [])
    snapshot = observer.collect(
        config(),
        lambda *args, **kwargs: subprocess.CompletedProcess(args, 0, encoded, ""),
        observer.parse_utc("2026-10-16T10:00:00Z"),
    )
    assert len(snapshot["targets"][0]["checks"]) == 12
    assert {check["status"] for check in snapshot["targets"][0]["checks"]} == {"error"}
    assert "PRIVATE-MUST-NOT-LEAK" not in json.dumps(snapshot)


def test_acti_external_checks_run_after_ssh_transport_failure_and_fixed_command(
    monkeypatch,
):
    seen = []

    def https(host):
        seen.append(host)
        return [{"name": "https_live", "source": "gateway", "status": "ok"}]

    monkeypatch.setattr(observer, "_acti_https_checks", https)

    def runner(command, **kwargs):
        assert command[-1] == "/usr/bin/sudo -n /usr/local/sbin/acti-v3-observe"
        assert kwargs["timeout"] == 20 and kwargs["shell"] is False
        raise subprocess.TimeoutExpired(command, 20)

    target = observer.collect(
        config(), runner, observer.parse_utc("2026-10-16T10:00:00Z")
    )["targets"][0]
    assert seen == ["acti.example.invalid"]
    assert len(target["checks"]) == 13 and target["checks"][-1]["status"] == "ok"
    assert {check["error"] for check in target["checks"][:-1]} == {"timeout"}


def test_acti_false_flags_and_services_produce_critical_not_transport_error(
    monkeypatch,
):
    data = acti_payload()
    data["services"]["worker"] = False
    data["backup_fresh"] = False
    monkeypatch.setattr(observer, "_acti_https_checks", lambda host: [])
    target = observer.collect(
        config(),
        lambda *args, **kwargs: subprocess.CompletedProcess(
            args, 0, json.dumps(data), ""
        ),
        observer.parse_utc("2026-10-16T10:00:00Z"),
    )["targets"][0]
    assert {
        check["name"] for check in target["checks"] if check["status"] == "critical"
    } == {"worker_active", "backup_fresh"}


def test_acti_https_uses_only_fixed_paths_ca_and_deadline(monkeypatch):
    host = "acti.example.invalid"
    issuer = "https://" + host + "/idp/realms/acti"
    payloads = [
        {"status": "live"},
        {
            "status": "ready",
            "checks": {"database": True, "redis": True, "storage": True},
        },
        {
            "issuer": issuer,
            "authorization_endpoint": issuer + "/protocol/openid-connect/auth",
            "token_endpoint": issuer + "/protocol/openid-connect/token",
            "jwks_uri": issuer + "/protocol/openid-connect/certs",
        },
    ]
    calls = []

    def runner(command, **kwargs):
        calls.append((command, kwargs))
        return subprocess.CompletedProcess(
            command, 0, json.dumps(payloads[len(calls) - 1]).encode(), b""
        )

    monkeypatch.setattr(observer.subprocess, "run", runner)
    checks = observer._acti_https_checks(host)
    assert [x["name"] for x in checks] == [
        "https_live",
        "https_ready",
        "oidc_discovery",
    ]
    assert all(x["source"] == "gateway" and x["status"] == "ok" for x in checks)
    assert [call[0][-2] for call in calls] == [
        "/api/v1/health/live",
        "/api/v1/health/ready",
        "/idp/realms/acti/.well-known/openid-configuration",
    ]
    for command, options in calls:
        assert (
            command[-1] == "/etc/openvpn-web/acti-ca.crt"
            and command[-4] == host
            and command[-3] == "443"
        )
        assert 0 < options["timeout"] <= 3 and options["shell"] is False


@pytest.mark.parametrize(
    "failure",
    [
        "duplicate",
        "oversize",
        "bad_json",
        "not_object",
        "live_bool",
        "ready_false",
        "ready_integer",
        "issuer",
        "endpoint",
        "timeout",
        "transport",
        "redirect",
    ],
)
def test_acti_https_contract_errors_are_redacted_and_do_not_skip_later_checks(
    monkeypatch, failure
):
    live = b'{"status":"live"}'
    ready = {
        "status": "ready",
        "checks": {"database": True, "redis": True, "storage": True},
    }
    realm = "https://acti.example.invalid/idp/realms/acti"
    discovery = {
        "issuer": realm,
        "authorization_endpoint": realm + "/auth",
        "token_endpoint": realm + "/token",
        "jwks_uri": realm + "/certs",
    }
    values = [live, json.dumps(ready).encode(), json.dumps(discovery).encode()]
    broken = 0
    if failure == "duplicate":
        values[0] = b'{"status":"other","status":"live"}'
    elif failure == "oversize":
        values[0] = b"x" * 16385
    elif failure == "bad_json":
        values[0] = b"PRIVATE-NOT-JSON"
    elif failure == "not_object":
        values[0] = b"[]"
    elif failure == "live_bool":
        values[0] = b'{"status":true}'
    elif failure in {"ready_false", "ready_integer"}:
        broken = 1
        ready["checks"]["database"] = False if failure == "ready_false" else 1
        values[1] = json.dumps(ready).encode()
    elif failure in {"issuer", "endpoint"}:
        broken = 2
        discovery["issuer" if failure == "issuer" else "jwks_uri"] = (
            "https://foreign.example.invalid/private"
        )
        values[2] = json.dumps(discovery).encode()
    calls = []

    def runner(command, **kwargs):
        index = len(calls)
        calls.append(command)
        if index == broken and failure == "timeout":
            raise subprocess.TimeoutExpired(command, 3)
        return subprocess.CompletedProcess(
            command,
            4
            if index == broken and failure == "transport"
            else 3
            if index == broken and failure == "redirect"
            else 0,
            values[index],
            b"PRIVATE-NOT-EXPOSED",
        )

    monkeypatch.setattr(observer.subprocess, "run", runner)
    checks = observer._acti_https_checks("acti.example.invalid")
    assert len(calls) == 3 and checks[broken]["status"] == "error"
    assert "PRIVATE" not in json.dumps(checks)
    assert all(
        check["status"] == "ok" for index, check in enumerate(checks) if index != broken
    )


def test_backup_probe_is_fixed_read_only_bounded_windows_command():
    command = observer._ROLE_PROBES["acti_backup"]
    assert len(command) <= 7000
    body = base64.b64decode(command.split("-EncodedCommand ")[1]).decode("utf-16le")
    assert "Get-EventLog -LogName Application -Source ACTIBackup -Newest 1" in body
    for forbidden in (
        "Set-",
        "Start-",
        "Stop-",
        "Remove-",
        "Write-EventLog",
        "Get-Content",
        "Get-ChildItem",
        "Invoke-",
    ):
        assert forbidden not in body


@pytest.mark.parametrize(
    "mutation", ["missing", "extra", "number", "service", "format"]
)
def test_backup_return_contract_rejects_partial_or_ambiguous_fields(mutation):
    data = {
        "format": "acti-backup-observer-v1",
        "services": {},
        "watchdog_fresh": True,
        "backup_snapshot_fresh": True,
        "repository_capacity": True,
    }
    if mutation == "missing":
        del data["watchdog_fresh"]
    elif mutation == "extra":
        data["private"] = "PRIVATE"
    elif mutation == "number":
        data["repository_capacity"] = 1
    elif mutation == "service":
        data["services"]["smb"] = True
    else:
        data["format"] = "other"
    with pytest.raises(observer._ProbeFailure):
        observer._checks_from_payload("acti_backup", "gateway", data, 1)


@pytest.mark.skipif(
    not shutil.which("powershell.exe"),
    reason="Real PowerShell parser and fixture execution on Windows",
)
@pytest.mark.parametrize(
    "mutation",
    [
        "healthy",
        "stale",
        "future",
        "event_time",
        "capacity",
        "missing",
        "extra",
        "boolean_number",
        "unavailable",
        "unknown_format",
        "unknown_issue",
        "fractional_bytes",
        "bad_timestamp",
        "snapshot_old_now",
        "duplicate",
    ],
)
def test_backup_eventlog_program_validates_owned_report_without_writes(mutation):
    now = datetime.now(timezone.utc)

    def stamp(value):
        return value.isoformat().replace("+00:00", "Z")

    payload = {
        "format": "acti-backup-watchdog-v1",
        "checked_utc": stamp(now),
        "check_only": False,
        "status": "healthy",
        "event_id": 1000,
        "snapshot_count": 2,
        "newest_snapshot_utc": stamp(now - timedelta(hours=1)),
        "snapshot_age_hours": 1.0,
        "repository_bytes": 1000,
        "repository_entries": 20,
        "free_gib": 1000,
        "maximum_age_hours": 30,
        "minimum_free_gib": 100,
        "maximum_repository_gib": 300,
        "issues": [],
    }
    event_time = now
    if mutation == "stale":
        payload["checked_utc"] = stamp(now - timedelta(hours=31))
        event_time = now - timedelta(hours=31)
    elif mutation == "future":
        payload["checked_utc"] = stamp(now + timedelta(minutes=10))
        event_time = now + timedelta(minutes=10)
    elif mutation == "event_time":
        event_time = now - timedelta(hours=1)
    elif mutation == "capacity":
        payload.update(
            status="unhealthy", event_id=1003, free_gib=1, issues=["free_space_limit"]
        )
    elif mutation == "missing":
        del payload["snapshot_count"]
    elif mutation == "extra":
        payload["private"] = "PRIVATE"
    elif mutation == "boolean_number":
        payload["free_gib"] = True
    elif mutation == "unknown_format":
        payload["format"] = "other"
    elif mutation == "unknown_issue":
        payload.update(status="unhealthy", event_id=1003, issues=["PRIVATE_unknown"])
    elif mutation == "fractional_bytes":
        payload["repository_bytes"] = 0.5
    elif mutation == "bad_timestamp":
        payload["checked_utc"] = "not-an-iso-dateZ"
    elif mutation == "snapshot_old_now":
        payload["checked_utc"] = stamp(now - timedelta(hours=29))
        event_time = now - timedelta(hours=29)
        payload["newest_snapshot_utc"] = stamp(now - timedelta(hours=31))
        payload["snapshot_age_hours"] = 2
    body = base64.b64decode(
        observer._ROLE_PROBES["acti_backup"].split("-EncodedCommand ")[1]
    ).decode("utf-16le")
    if mutation == "unavailable":
        prefix = "function Get-EventLog {throw 'PRIVATE provider failure'};"
    else:
        encoded = json.dumps(payload)
        if mutation == "duplicate":
            encoded = encoded[:-1] + ',"status":"healthy"}'
        encoded = encoded.replace("'", "''")
        prefix = (
            "function Get-EventLog {[pscustomobject]@{Message='"
            + encoded
            + "';EventID="
            + str(payload["event_id"])
            + ";TimeGenerated=[datetime]::Parse('"
            + stamp(event_time)
            + "')}};"
        )
    result = subprocess.run(
        [
            "powershell.exe",
            "-NoProfile",
            "-NonInteractive",
            "-EncodedCommand",
            base64.b64encode((prefix + body).encode("utf-16le")).decode(),
        ],
        capture_output=True,
        timeout=15,
    )
    if mutation == "unavailable":
        assert result.returncode != 0
        return
    assert result.returncode == 0
    data = json.loads(result.stdout.decode("utf-8-sig"))
    assert set(data) == {
        "format",
        "services",
        "watchdog_fresh",
        "backup_snapshot_fresh",
        "repository_capacity",
    }
    if mutation == "healthy":
        assert all(
            data[k] is True
            for k in ("watchdog_fresh", "backup_snapshot_fresh", "repository_capacity")
        )
    elif mutation == "capacity":
        assert (
            data["watchdog_fresh"] is True
            and data["backup_snapshot_fresh"] is True
            and data["repository_capacity"] is False
        )
    elif mutation == "snapshot_old_now":
        assert data["backup_snapshot_fresh"] is False
    else:
        assert data["watchdog_fresh"] is False or data["repository_capacity"] is False
    assert "PRIVATE" not in json.dumps(data)


@pytest.fixture(scope="module")
def tls_fixture(tmp_path_factory):
    from cryptography import x509
    from cryptography.hazmat.primitives import hashes, serialization
    from cryptography.hazmat.primitives.asymmetric import ec
    from cryptography.x509.oid import NameOID, ExtendedKeyUsageOID

    folder = tmp_path_factory.mktemp("acti-test-tls")
    now = datetime.now(timezone.utc)

    def certificate(name, key, issuer_name, issuer_key, ca):
        builder = (
            x509.CertificateBuilder()
            .subject_name(name)
            .issuer_name(issuer_name)
            .public_key(key.public_key())
            .serial_number(x509.random_serial_number())
            .not_valid_before(now - timedelta(hours=1))
            .not_valid_after(now + timedelta(days=1))
            .add_extension(
                x509.BasicConstraints(ca=ca, path_length=None), critical=True
            )
            .add_extension(
                x509.KeyUsage(
                    digital_signature=True,
                    content_commitment=False,
                    key_encipherment=False,
                    data_encipherment=False,
                    key_agreement=False,
                    key_cert_sign=ca,
                    crl_sign=ca,
                    encipher_only=None,
                    decipher_only=None,
                ),
                critical=True,
            )
            .add_extension(
                x509.SubjectKeyIdentifier.from_public_key(key.public_key()),
                critical=False,
            )
            .add_extension(
                x509.AuthorityKeyIdentifier.from_issuer_public_key(
                    issuer_key.public_key()
                ),
                critical=False,
            )
        )
        if not ca:
            builder = builder.add_extension(
                x509.SubjectAlternativeName([x509.DNSName("localhost")]), critical=False
            ).add_extension(
                x509.ExtendedKeyUsage([ExtendedKeyUsageOID.SERVER_AUTH]), critical=False
            )
        return builder.sign(issuer_key, hashes.SHA256())

    ca_key = ec.generate_private_key(ec.SECP256R1())
    ca_name = x509.Name(
        [x509.NameAttribute(NameOID.COMMON_NAME, "ACTI disposable test CA")]
    )
    ca = certificate(ca_name, ca_key, ca_name, ca_key, True)
    key = ec.generate_private_key(ec.SECP256R1())
    leaf_name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "localhost")])
    leaf = certificate(leaf_name, key, ca_name, ca_key, False)
    ca_path = folder / "ca.pem"
    cert_path = folder / "server.pem"
    key_path = folder / "key.pem"
    ca_path.write_bytes(ca.public_bytes(serialization.Encoding.PEM))
    cert_path.write_bytes(leaf.public_bytes(serialization.Encoding.PEM))
    key_path.write_bytes(
        key.private_bytes(
            serialization.Encoding.PEM,
            serialization.PrivateFormat.PKCS8,
            serialization.NoEncryption(),
        )
    )
    bad_key = ec.generate_private_key(ec.SECP256R1())
    bad_ca = certificate(ca_name, bad_key, ca_name, bad_key, True)
    bad_path = folder / "wrong-ca.pem"
    bad_path.write_bytes(bad_ca.public_bytes(serialization.Encoding.PEM))
    requests = []

    class Handler(BaseHTTPRequestHandler):
        def log_message(self, *args):
            pass

        def do_GET(self):
            requests.append((self.path, dict(self.headers)))
            if self.path == "/slow":
                threading.Event().wait(1)
                return
            self.send_response(302 if self.path == "/redirect" else 200)
            self.send_header(
                "Content-Type",
                "text/plain" if self.path == "/wrong-type" else "application/json",
            )
            if self.path == "/redirect":
                self.send_header("Location", "/ok")
            self.end_headers()
            try:
                self.wfile.write(
                    b"x" * 16385 if self.path == "/large" else b'{"status":"live"}'
                )
            except OSError:
                pass

    server = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
    server.daemon_threads = True
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    context.load_cert_chain(cert_path, key_path)
    server.socket = context.wrap_socket(server.socket, server_side=True)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    yield server.server_port, ca_path, bad_path, requests
    server.shutdown()
    server.server_close()
    thread.join(timeout=2)


@pytest.mark.parametrize(
    "case,expected",
    [
        ("trusted", 0),
        ("hostname", 4),
        ("untrusted", 4),
        ("redirect", 3),
        ("large", 3),
        ("wrong-type", 3),
    ],
)
def test_real_tls_probe_requires_chain_hostname_json_and_never_redirects(
    tls_fixture, monkeypatch, case, expected
):
    port, ca, bad_ca, requests = tls_fixture
    monkeypatch.setenv("HTTPS_PROXY", "http://127.0.0.1:1")
    path = "/" + case if case in {"redirect", "large", "wrong-type"} else "/ok"
    before = len(requests)
    result = subprocess.run(
        [
            sys.executable,
            "-I",
            "-c",
            observer._ACTI_HTTPS_PROBE,
            "127.0.0.1" if case == "hostname" else "localhost",
            str(port),
            path,
            str(bad_ca if case == "untrusted" else ca),
        ],
        capture_output=True,
        timeout=3,
    )
    assert result.returncode == expected
    assert result.stderr == b""
    if expected == 0:
        assert json.loads(result.stdout) == {"status": "live"}
    if case == "redirect":
        assert [x[0] for x in requests[before:]] == ["/redirect"]
    assert all(
        "Cookie" not in headers and "Authorization" not in headers
        for _, headers in requests
    )


def test_real_tls_probe_is_killed_at_wall_deadline_during_slow_response(tls_fixture):
    port, ca, _, _ = tls_fixture
    with pytest.raises(subprocess.TimeoutExpired):
        subprocess.run(
            [
                sys.executable,
                "-I",
                "-c",
                observer._ACTI_HTTPS_PROBE,
                "localhost",
                str(port),
                "/slow",
                str(ca),
            ],
            capture_output=True,
            timeout=0.2,
        )


@pytest.mark.parametrize(
    "field,value",
    [
        ("userinfo_endpoint", "http://acti.example.invalid/idp/realms/acti/userinfo"),
        ("check_session_iframe", "https://foreign.example.invalid/frame"),
        (
            "mtls_endpoint_aliases",
            {"token_endpoint": "https://foreign.example.invalid/token"},
        ),
        ("mtls_endpoint_aliases", "not-an-object"),
        ("jwks_uri", "https://acti.example.invalid/idp/realms/acti/../foreign/certs"),
        (
            "jwks_uri",
            "https://acti.example.invalid/idp/realms/acti/%2e%2e/foreign/certs",
        ),
    ],
)
def test_discovery_optional_endpoints_cannot_escape_verified_origin_and_realm(
    field, value
):
    realm = "https://acti.example.invalid/idp/realms/acti"
    data = {
        "issuer": realm,
        "authorization_endpoint": realm + "/auth",
        "token_endpoint": realm + "/token",
        "jwks_uri": realm + "/certs",
        field: value,
    }
    with pytest.raises(observer._ProbeFailure):
        observer._validate_acti_https("oidc_discovery", data, "acti.example.invalid")


def test_acti_https_overall_budget_exhaustion_never_spawns_more_processes(monkeypatch):
    moments = iter([0.0, 0.0, 10.1, 10.2])
    monkeypatch.setattr(observer, "perf_counter", lambda: next(moments))
    calls = []

    def runner(command, **kwargs):
        calls.append(kwargs["timeout"])
        raise subprocess.TimeoutExpired(command, kwargs["timeout"])

    monkeypatch.setattr(observer.subprocess, "run", runner)
    checks = observer._acti_https_checks("acti.example.invalid")
    assert calls == [3]
    assert len(checks) == 3 and all(check["error"] == "timeout" for check in checks)
