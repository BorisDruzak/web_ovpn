from __future__ import annotations

from dataclasses import replace
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import subprocess
import sys
from types import SimpleNamespace
from uuid import UUID
import zipfile

import pytest

ROOT = Path(__file__).resolve().parents[1]
DEVICE = UUID("11111111-1111-4111-8111-111111111111")


@pytest.fixture
def verifier(monkeypatch):
    monkeypatch.setattr(os, "environ", os.environ.copy())
    path = ROOT / "deploy/verify_endpoint_platform.py"
    assert path.exists(), "deployment smoke verifier is required"
    spec = importlib.util.spec_from_file_location("endpoint_deploy_verifier", path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    yield module
    from app.config import get_settings
    get_settings.cache_clear()


@pytest.fixture
def artifact(tmp_path):
    directory = tmp_path / "deploy"
    directory.mkdir()
    wheels = directory / "wheels"
    wheels.mkdir()
    wheel = wheels / "endpoint_platform_client-1.2.3-py3-none-any.whl"
    with zipfile.ZipFile(wheel, "w") as archive:
        archive.writestr("endpoint_platform_client-1.2.3.dist-info/METADATA", "Name: endpoint-platform-client\nVersion: 1.2.3\n")
    lock = directory / "endpoint-platform-client.lock"
    manifest = {"distribution": "endpoint-platform-client", "version": "1.2.3", "wheel": wheel.name, "sha256": hashlib.sha256(wheel.read_bytes()).hexdigest()}
    lock.write_text(json.dumps(manifest))
    return lock, wheel, manifest


def test_artifact_accepts_only_exact_digest_and_wheel_metadata(verifier, artifact):
    lock, wheel, manifest = artifact
    assert verifier.verify_artifact(lock) == (wheel, manifest)
    wheel.write_bytes(wheel.read_bytes() + b"changed")
    with pytest.raises(verifier.VerificationError, match="sdk_artifact_invalid"):
        verifier.verify_artifact(lock)


@pytest.mark.parametrize("field,value", [("version", None), ("sha256", "bad"), ("wheel", "../../evil.whl"), ("version", "9.0.0"), ("distribution", "other-client")])
def test_artifact_rejects_unconfigured_or_mismatched_lock(verifier, artifact, field, value):
    lock, _, manifest = artifact
    manifest[field] = value
    lock.write_text(json.dumps(manifest))
    with pytest.raises(verifier.VerificationError):
        verifier.verify_artifact(lock)


@pytest.mark.parametrize("version,hash_value,editable", [("9.0", None, False), ("1.2.3", "bad", False), ("1.2.3", None, True)])
def test_installed_sdk_rejects_version_hash_or_editable(verifier, artifact, monkeypatch, version, hash_value, editable):
    _, wheel, manifest = artifact
    direct = {"url": wheel.as_uri(), "archive_info": {"hashes": {"sha256": hash_value or manifest["sha256"]}}}
    if editable:
        direct = {"url": wheel.parent.as_uri(), "dir_info": {"editable": True}}
    dist = SimpleNamespace(version=version, read_text=lambda _: json.dumps(direct))
    monkeypatch.setattr(verifier.metadata, "distribution", lambda _: dist)
    with pytest.raises(verifier.VerificationError, match="sdk_installed_invalid"):
        verifier.verify_installed(manifest)


def test_installed_sdk_requires_import(verifier, artifact, monkeypatch):
    _, wheel, manifest = artifact
    direct = {"url": wheel.as_uri(), "archive_info": {"hashes": {"sha256": manifest["sha256"]}}}
    monkeypatch.setattr(verifier.metadata, "distribution", lambda _: SimpleNamespace(version="1.2.3", read_text=lambda _: json.dumps(direct)))
    monkeypatch.setattr(verifier.importlib, "import_module", lambda _: (_ for _ in ()).throw(ImportError("secret")))
    with pytest.raises(verifier.VerificationError, match="sdk_installed_invalid"):
        verifier.verify_installed(manifest)


@pytest.mark.parametrize("uid,gid,mode,secret,allowed", [(0, 123, 0o100640, True, True), (1, 123, 0o100640, True, False), (0, 99, 0o100640, True, False), (0, 123, 0o100644, True, False), (0, 123, 0o100660, True, False), (0, 123, 0o100644, False, True), (0, 123, 0o100664, False, False), (0, 123, 0o120640, True, False)])
def test_secret_and_ca_permissions_are_root_managed(verifier, uid, gid, mode, secret, allowed):
    info = SimpleNamespace(st_uid=uid, st_gid=gid, st_mode=mode)
    if allowed:
        verifier.validate_file_metadata(info, 123, secret=secret)
    else:
        with pytest.raises(verifier.VerificationError, match="file_permissions_invalid"):
            verifier.validate_file_metadata(info, 123, secret=secret)


@pytest.fixture
def sdk(monkeypatch):
    calls = []
    class Client:
        failure = None
        def __init__(self, base_url, **kwargs):
            assert base_url == "https://endpoint.example.test"
            assert kwargs["timeout_seconds"] == 5
        def invoke(self, operation, value):
            calls.append(operation)
            if self.failure == operation:
                raise PermissionError("sensitive-token")
            return value
        def list_devices(self):
            return self.invoke("devices.read", [{"id": str(DEVICE)}])
        def list_agent_network_identities(self):
            return self.invoke("identities", [])
        def get_latest_context(self, device_id, profile):
            assert device_id == DEVICE
            return self.invoke("context.read", None)
        def request_collection(self, device_id, profile, key):
            assert device_id == DEVICE and profile == "baseline_v1"
            assert key.startswith("web-ovpn-smoke:")
            return self.invoke("context.collect", {"id": str(DEVICE), "device_id": str(DEVICE), "profile": profile, "status": "queued"})
        def close(self):
            calls.append("closed")
    monkeypatch.setitem(sys.modules, "endpoint_platform_client", SimpleNamespace(EndpointPlatformClient=Client))
    return Client, calls


def settings():
    from app.config import get_settings
    return replace(get_settings(), endpoint_platform_enabled=False, endpoint_platform_base_url="https://endpoint.example.test", endpoint_platform_smoke_device_id=DEVICE, endpoint_platform_token_file=Path(__file__).resolve(), endpoint_platform_ca_file=Path(__file__).resolve(), endpoint_platform_timeout_seconds=5)


def test_smoke_uses_three_required_operations_before_enable(verifier, sdk):
    _, calls = sdk
    verifier.verify_api(settings(), "abc123")
    assert calls == [
        "devices.read", "identities",
        "context.read", "context.read", "context.read", "context.read", "context.read",
        "context.collect", "closed",
    ]
    assert settings().endpoint_platform_enabled is False


def test_smoke_accepts_newly_requested_collection(verifier, sdk):
    client, calls = sdk

    def requested_collection(self, device_id, profile, key):
        assert device_id == DEVICE and profile == "baseline_v1"
        assert key.startswith("web-ovpn-smoke:")
        return self.invoke("context.collect", {
            "id": str(DEVICE), "device_id": str(DEVICE), "profile": profile,
            "status": "requested",
        })

    client.request_collection = requested_collection
    verifier.verify_api(settings(), "abc123")
    assert calls[-2:] == ["context.collect", "closed"]


@pytest.mark.parametrize("scope", ["devices.read", "context.read", "context.collect"])
def test_smoke_scope_denial_is_redacted_and_closes_client(verifier, sdk, scope):
    client, calls = sdk
    client.failure = scope
    with pytest.raises(verifier.VerificationError, match="endpoint_platform_scope_denied") as error:
        verifier.verify_api(settings(), "abc123")
    assert "sensitive" not in str(error.value)
    assert calls[-1] == "closed"


@pytest.mark.parametrize("failure", ["TLS validation failed", "redirect rejected"])
def test_smoke_transport_failure_never_passes_or_leaks(verifier, sdk, failure):
    client, calls = sdk
    client.list_devices = lambda self: (_ for _ in ()).throw(RuntimeError(failure + " sensitive-token"))
    with pytest.raises(verifier.VerificationError, match="endpoint_platform_unavailable"):
        verifier.verify_api(settings(), "abc123")
    assert calls[-1] == "closed"


def test_config_refuses_non_https_and_missing_smoke_device(verifier):
    for current in [replace(settings(), endpoint_platform_base_url="http://example.test"), replace(settings(), endpoint_platform_smoke_device_id=None), replace(settings(), endpoint_platform_timeout_seconds=float("nan"))]:
        with pytest.raises(verifier.VerificationError, match="config_invalid"):
            verifier.validate_settings(current)


def test_cli_verifies_the_committed_locked_wheel(verifier):
    result = subprocess.run([sys.executable, str(ROOT / "deploy/verify_endpoint_platform.py"), "--app-dir", str(ROOT), "--artifact-only"], capture_output=True, text=True)
    assert result.returncode == 0
    assert result.stdout.strip() == "endpoint_platform_artifact_verified"
    assert result.stderr == ""


@pytest.mark.parametrize("content", ["", "not-a-certificate-sensitive-value"])
def test_main_refuses_unreadable_or_invalid_ca_without_secret_output(verifier, artifact, sdk, monkeypatch, tmp_path, capsys, content):
    lock, wheel, manifest = artifact
    token, ca, env = (tmp_path / name for name in ("service.token", "ca.pem", "environment"))
    token.write_text("sensitive-token")
    ca.write_text(content)
    env.write_text(f"ENDPOINT_PLATFORM_BASE_URL=https://endpoint.example.test\nENDPOINT_PLATFORM_TOKEN_FILE={token.as_posix()}\nENDPOINT_PLATFORM_CA_FILE={ca.as_posix()}\nENDPOINT_PLATFORM_SMOKE_DEVICE_ID={DEVICE}\n")
    direct = {"url": wheel.as_uri(), "archive_info": {"hashes": {"sha256": manifest["sha256"]}}}
    monkeypatch.setattr(verifier.metadata, "distribution", lambda _: SimpleNamespace(version="1.2.3", read_text=lambda _: json.dumps(direct)))
    # Windows cannot model POSIX owners; permission rules are covered separately.
    monkeypatch.setattr(verifier, "service_group", lambda: 123)
    monkeypatch.setattr(verifier, "validate_file_metadata", lambda *args, **kwargs: None)
    assert verifier.main(["--app-dir", str(lock.parent.parent), "--env-file", str(env)]) == 1
    output = capsys.readouterr()
    assert output.out.strip() in {"endpoint_platform_file_unreadable", "endpoint_platform_ca_invalid"}
    assert output.err == ""
    assert sdk[1] == []


def test_disabled_install_does_not_require_artifact_or_contact_sdk(verifier, monkeypatch, tmp_path, sdk, capsys):
    env = tmp_path / "environment"
    env.write_text("ENDPOINT_PLATFORM_ENABLED=0\n")
    monkeypatch.setattr(verifier, "service_group", lambda: 123)
    monkeypatch.setattr(verifier, "validate_file_metadata", lambda *args, **kwargs: None)
    assert verifier.main(["--app-dir", str(tmp_path), "--env-file", str(env), "--if-enabled", "--install"]) == 77
    assert capsys.readouterr().out.strip() == "endpoint_platform_disabled"
    assert sdk[1] == []


@pytest.mark.parametrize("line,value", [
    ("  ENDPOINT_PLATFORM_ENABLED = 1  ", "1"),
    ("ENDPOINT_PLATFORM_TOKEN_FILE=/etc/token#blue", "/etc/token#blue"),
    ("ENDPOINT_PLATFORM_TOKEN_FILE=/etc/token #blue", "/etc/token #blue"),
    ('ENDPOINT_PLATFORM_TOKEN_FILE="/etc/token #blue"', "/etc/token #blue"),
])
def test_environment_matches_systemd_whitespace_and_literal_hash(verifier, monkeypatch, tmp_path, line, value):
    env = tmp_path / "environment"
    env.write_text(line + "\n")
    monkeypatch.setattr(verifier, "validate_file_metadata", lambda *args, **kwargs: None)
    verifier.load_environment(env, 123)
    key = "ENDPOINT_PLATFORM_ENABLED" if "ENABLED" in line else "ENDPOINT_PLATFORM_TOKEN_FILE"
    assert os.environ[key] == value


@pytest.mark.parametrize("line", [
    'APP_SECRET_KEY="unterminated\nENDPOINT_PLATFORM_ENABLED=1',
    "APP_SECRET_KEY=value\\\nENDPOINT_PLATFORM_ENABLED=1",
    'ENDPOINT_PLATFORM_TOKEN_FILE="/etc/token" trailing',
])
def test_environment_rejects_ambiguous_multiline_or_quoting(verifier, monkeypatch, tmp_path, line):
    env = tmp_path / "environment"
    env.write_text(line + "\n")
    monkeypatch.setattr(verifier, "validate_file_metadata", lambda *args, **kwargs: None)
    with pytest.raises(verifier.VerificationError, match="config_invalid"):
        verifier.load_environment(env, 123)


@pytest.mark.parametrize("separator", ["\u0085", "\u2028", "\u2029", "\u00a0", "\x0b", "\u200b"])
def test_environment_rejects_unicode_controls_and_non_lf_separators(verifier, monkeypatch, tmp_path, separator):
    env = tmp_path / "environment"
    env.write_text(f"APP_SECRET_KEY=value{separator}ENDPOINT_PLATFORM_ENABLED=1\n", encoding="utf-8")
    monkeypatch.setattr(verifier, "validate_file_metadata", lambda *args, **kwargs: None)
    with pytest.raises(verifier.VerificationError, match="config_invalid"):
        verifier.load_environment(env, 123)


@pytest.mark.parametrize("state,status,success", [("not-found", 4, True), ("loaded", 0, True), ("", 1, False)])
def test_quiesce_handles_missing_units_but_refuses_unknown_manager_state(state, status, success):
    source = (ROOT / "deploy/install-openvpn-web.sh").read_text()
    start = source.index("endpoint_platform_quiesce() {")
    function = source[start:source.index("\n}\n", start) + 3]
    harness = f'''set -eu
sudo_cmd() {{
  if [[ "$*" == *ActiveState* ]]; then printf '%s\\n' inactive; return 0; fi
  if [[ "$*" == *show* ]]; then printf '%s\\n' '{state}'; return {status}; fi
  printf '%s\\n' "$*"
}}
{function}
endpoint_platform_quiesce
'''
    result = subprocess.run(["bash", "-c", harness], capture_output=True, text=True)
    assert (result.returncode == 0) == success
    if state == "not-found":
        assert "disable" not in result.stdout
    if state == "loaded":
        assert "disable --now inventory-endpoint-sync.timer" in result.stdout
        assert "stop inventory-endpoint-sync.service" in result.stdout


@pytest.mark.parametrize("initial,after_stop,success", [("active", "inactive", True), ("activating", "inactive", True), ("active", "active", False)])
def test_quiesce_stops_running_units_even_when_unit_files_missing(initial, after_stop, success):
    source = (ROOT / "deploy/install-openvpn-web.sh").read_text()
    start = source.index("endpoint_platform_quiesce() {")
    function = source[start:source.index("\n}\n", start) + 3]
    harness = f'''set -eu
declare -A current_state=([inventory-endpoint-sync.timer]={initial} [inventory-endpoint-sync.service]={initial})
sudo_cmd() {{
  local unit="${{@: -1}}"
  if [[ "$*" == *LoadState* ]]; then printf '%s\\n' not-found; return 0; fi
  if [[ "$*" == *ActiveState* ]]; then printf '%s\\n' "${{current_state[$unit]}}"; return 0; fi
  if [[ "$*" == *stop* ]]; then current_state[$unit]={after_stop}; fi
  printf '%s\\n' "$*"
}}
{function}
endpoint_platform_quiesce
printf '%s\\n' quiesced
[[ "${{current_state[inventory-endpoint-sync.timer]}}" == inactive ]]
[[ "${{current_state[inventory-endpoint-sync.service]}}" == inactive ]]
'''
    result = subprocess.run(["bash", "-c", harness], capture_output=True, text=True)
    assert (result.returncode == 0) == success
    assert ("quiesced" in result.stdout) == success
    assert "stop inventory-endpoint-sync.timer" in result.stdout
    if success:
        assert "stop inventory-endpoint-sync.service" in result.stdout


@pytest.mark.parametrize("status,analyzer_status,enabled", [(0, 0, True), (1, 0, False), (77, 0, False), (0, 9, False)])
def test_installer_gate_disables_previous_timer_and_enables_only_verified(tmp_path, status, analyzer_status, enabled):
    source = (ROOT / "deploy/install-openvpn-web.sh").read_text()
    start = source.find("endpoint_platform_gate() {")
    assert start >= 0, "installer requires a verification gate"
    function = source[start:source.index("\n}\n", start) + 3]
    harness = f'''set -eu
APP=/opt/openvpn-web
ENV_PATH=/etc/openvpn-web/openvpn-web.env
sudo_cmd() {{
  if [[ "$*" == *systemd-analyze* ]]; then return {analyzer_status}; fi
  if [[ "$*" == *verify-endpoint-platform* ]]; then return {status}; fi
  printf '%s\\n' "$*"
}}
{function}
endpoint_platform_gate
'''
    result = subprocess.run(["bash", "-c", harness], capture_output=True, text=True)
    assert result.returncode == 0, result.stderr
    assert "disable --now inventory-endpoint-sync.timer" in result.stdout
    assert ("enable --now inventory-endpoint-sync.timer" in result.stdout) == enabled
    if status == 1:
        assert "ENDPOINT_PLATFORM_ENABLED=0" in result.stdout
