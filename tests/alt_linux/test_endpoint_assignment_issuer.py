"""Verify the private controller-side enrollment assignment boundary."""

from datetime import datetime, timedelta, timezone
import io
import json
from pathlib import Path
from types import SimpleNamespace

import pytest
import yaml

from alt_deploy import endpoint_assignment_issuer as issuer


NOW = datetime(2026, 11, 12, 1, 0, tzinfo=timezone.utc)
ASSET = "11111111-1111-4111-8111-111111111111"
MACHINE = "22222222-2222-4222-8222-222222222222"
INSTALLATION = f"inventory-{ASSET}-{MACHINE}-" + "a" * 32
FINGERPRINT = "sha256:" + "b" * 64
PAYLOAD = {"installation_id": INSTALLATION, "machine_uuid": MACHINE, "hardware_fingerprint": FINGERPRINT}


class Client:
    def __init__(self, calls, expires_at, *args, **kwargs):
        calls.append((args, kwargs))
        self.calls = calls
        self.expires_at = expires_at

    def __enter__(self):
        return self

    def __exit__(self, *args):
        self.calls.append("closed")

    def issue_inventory_installation(self, installation_id, hardware_fingerprint, platform):
        self.calls.append((installation_id, hardware_fingerprint, platform))
        return SimpleNamespace(expires_at=self.expires_at)


def run(payload, *, expires_at=NOW + timedelta(minutes=30)):
    calls = []
    data = json.dumps(payload).encode()
    result = issuer.main(
        stdin=io.BytesIO(data), clock=lambda: NOW,
        client_factory=lambda *args, **kwargs: Client(calls, expires_at, *args, **kwargs),
    )
    return result, calls


def test_controller_issues_with_the_staging_scope_and_expires_safely(monkeypatch, capsys):
    paths = []
    monkeypatch.setattr(issuer, "_require_file", lambda path, *, secret: paths.append((path, secret)))
    result, calls = run(PAYLOAD)
    assert result == 0
    assert paths == [(issuer.TOKEN_FILE, True), (issuer.CA_FILE, False)]
    assert calls == [
        (("https://endpoint-staging.sosnadmin.local",), {
            "token_file": issuer.TOKEN_FILE, "ca_file": issuer.CA_FILE, "timeout_seconds": 10,
        }),
        (INSTALLATION, FINGERPRINT, "linux"),
        "closed",
    ]
    result, calls = run(PAYLOAD, expires_at=NOW)
    assert result != 0 and calls[-1] == "closed"
    result, calls = run(PAYLOAD, expires_at=NOW + timedelta(seconds=119))
    assert result != 0 and calls[-1] == "closed"
    assert capsys.readouterr().out == "endpoint_native_assignment_unavailable\n" * 2


@pytest.mark.parametrize("change", [
    {"machine_uuid": ASSET}, {"installation_id": "ordinary-install"},
    {"hardware_fingerprint": "sha256:wrong"}, {"origin": "https://elsewhere.invalid"},
])
def test_controller_rejects_untrusted_or_mismatched_proof_before_sdk(change, monkeypatch, capsys):
    monkeypatch.setattr(issuer, "_require_file", lambda *a, **k: pytest.fail("credentials were read"))
    result, calls = run({**PAYLOAD, **change})
    assert result != 0 and calls == []
    visible = capsys.readouterr().out
    assert INSTALLATION not in visible and FINGERPRINT not in visible


def test_signed_probe_and_issuer_precede_local_configuration_and_coordinator():
    role = Path(__file__).resolve().parents[2] / "deploy/alt-linux/ansible/roles/software_endpoint_agent_native/tasks/main.yml"
    tasks = yaml.safe_load(role.read_text(encoding="utf-8"))
    block = next(section["block"] for section in tasks if "block" in section)
    names = [item["name"] for item in block]
    probe = names.index("Read the fingerprint with the signed runtime")
    issue = names.index("Issue the installation assignment on the staging controller")
    accepted = names.index("Require a live Endpoint installation assignment")
    assert names.index("Require the exact signed archive bytes before extraction") < probe < issue < accepted
    assert accepted < names.index("Prepare native configuration only in a fresh slot")
    assert accepted < names.index("Run the existing Endpoint native coordinator")
    assert block[probe]["no_log"] is True
    assert block[issue]["delegate_to"] == "localhost" and block[issue]["become"] is False
    assert block[issue]["no_log"] is True
    assert "stdin" in block[issue]["ansible.builtin.command"]
    assert not any("token" in value.lower() for value in block[issue]["ansible.builtin.command"]["argv"])
    coordinator = block[names.index("Run the existing Endpoint native coordinator")]
    assert coordinator["environment"] == {
        "ENDPOINT_AGENT_DEPLOYMENT_ENVIRONMENT": "staging",
        "CANARY_ENVIRONMENT": "staging",
        "CANARY_APPROVED": "true",
        "ENDPOINT_AGENT_ORIGIN": "https://endpoint-staging.sosnadmin.local",
    }


def test_controller_redacts_upstream_error(monkeypatch, capsys):
    monkeypatch.setattr(issuer, "_require_file", lambda *args, **kwargs: None)

    def fail(*args, **kwargs):
        raise RuntimeError(f"private upstream diagnostic {INSTALLATION} {FINGERPRINT}")

    assert issuer.main(stdin=io.BytesIO(json.dumps(PAYLOAD).encode()), client_factory=fail) != 0
    assert capsys.readouterr().out == "endpoint_native_assignment_unavailable\n"


@pytest.mark.parametrize(("mode", "gid", "allowed"), [
    (0o100640, 42, True), (0o100644, 42, False), (0o100640, 99, False), (0o120640, 42, False),
])
def test_issuer_requires_root_managed_group_readable_secret(mode, gid, allowed, monkeypatch):
    monkeypatch.setattr(issuer.os, "getegid", lambda: 42, raising=False)
    path = SimpleNamespace(
        parents=[SimpleNamespace(lstat=lambda: SimpleNamespace(st_mode=0o40755, st_uid=0))],
        lstat=lambda: SimpleNamespace(st_mode=mode, st_uid=0, st_gid=gid, st_size=100, st_nlink=1),
    )
    if allowed:
        issuer._require_file(path, secret=True)
    else:
        with pytest.raises(ValueError):
            issuer._require_file(path, secret=True)


def test_local_issuer_preflight_loads_tls_client_without_calling_endpoint(monkeypatch):
    monkeypatch.setattr(issuer, "_require_file", lambda *args, **kwargs: None)
    calls = []
    assert issuer.main(
        preflight=True, client_factory=lambda *args, **kwargs: Client(calls, NOW, *args, **kwargs),
    ) == 0
    assert len(calls) == 2 and calls[-1] == "closed"


def test_planning_preflight_has_fixed_command_and_bounded_runtime():
    calls = []

    def runner(command, **kwargs):
        calls.append((command, kwargs))
        return SimpleNamespace(returncode=0)

    assert issuer.assignment_issuer_available(runner=runner)
    command, kwargs = calls[0]
    assert command == [str(issuer.ISSUER_PYTHON), "-I", str(Path(issuer.__file__).resolve()), "--preflight"]
    assert kwargs["timeout"] == 15
