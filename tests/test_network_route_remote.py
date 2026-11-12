import hashlib
import json
import os
import subprocess
import sys
from types import SimpleNamespace

import pytest

from app import network_route_remote as remote
from app.network_probe_profiles import ProbeProfiles


ARGUMENTS = {"target": "192.0.2.4", "protocol": "icmp"}
DIGEST = hashlib.sha256(b'{"protocol":"icmp","target":"192.0.2.4"}').hexdigest()


@pytest.fixture
def origin_files(tmp_path, monkeypatch):
    config = tmp_path / "origins.json"
    credentials = tmp_path / "credentials"
    credentials.mkdir()
    (credentials / "test-origin.key").write_bytes(b"private key placeholder")
    (credentials / "test-origin.key").chmod(0o640)
    (credentials / "known_hosts").write_bytes(b"host key placeholder")
    config.write_text(
        '{"origins":{"test-origin":{"host":"192.0.2.3","user":"route-probe","port":2201}}}'
    )
    monkeypatch.setattr(remote, "ORIGINS_PATH", config)
    monkeypatch.setattr(remote, "CREDENTIALS_DIR", credentials)
    monkeypatch.setattr(remote, "_root_owned", lambda info: True)
    return config, credentials


def test_controller_uses_pinned_ssh_and_filters_response(monkeypatch, origin_files):
    _, credentials = origin_files

    def run(argv):
        assert argv[:6] == ["/usr/bin/ssh", "-F", "/dev/null", "-4", "-nT", "-i"]
        assert argv[6:11] == [
            str(credentials / "test-origin.key"),
            "-p",
            "2201",
            "-l",
            "route-probe",
        ]
        for option in (
            "StrictHostKeyChecking=yes",
            f"UserKnownHostsFile={credentials / 'known_hosts'}",
            "GlobalKnownHostsFile=/dev/null",
            "UpdateHostKeys=no",
            "IdentityAgent=none",
            "BatchMode=yes",
            "IdentitiesOnly=yes",
            "ClearAllForwardings=yes",
            "PreferredAuthentications=publickey",
        ):
            assert argv[argv.index(option) - 1] == "-o"
        assert argv[-3:] == [
            "--",
            "192.0.2.3",
            f"route-probe test-profile test-probe {DIGEST}",
        ]
        result = {
            "status": "reachable",
            "evidence": {
                "duration_ms": 5.5,
                "round_trip_ms": 0.5,
                "raw": "private output",
            },
            "kernel_route": {
                "status": "route_found",
                "result": {"dst": "192.0.2.4", "dev": "eth0", "raw": "secret"},
            },
            "observed_path": ["unverified"],
        }
        return 0, json.dumps({"digest": DIGEST, "result": result}).encode()

    monkeypatch.setattr(remote, "_run_ssh", run)

    assert remote.probe_remote_route(
        "test-origin", "test-profile", "test-probe", ARGUMENTS
    ) == {
        "status": "reachable",
        "evidence": {"duration_ms": 5.5, "round_trip_ms": 0.5},
        "kernel_route": {
            "status": "route_found",
            "result": {"dst": "192.0.2.4", "dev": "eth0"},
        },
    }


@pytest.mark.parametrize(
    "origin, profile, probe",
    [
        ("unlisted", "profile", "probe"),
        ("../test-origin", "profile", "probe"),
        ("test-origin", "profile;id", "probe"),
        ("test-origin", "profile", "probe\n"),
    ],
)
def test_controller_rejects_unknown_or_unsafe_identifiers_before_ssh(
    monkeypatch, origin_files, origin, profile, probe
):
    monkeypatch.setattr(remote, "_run_ssh", lambda *args: pytest.fail("unexpected SSH"))

    assert (
        remote.probe_remote_route(origin, profile, probe, ARGUMENTS)["status"]
        == "unavailable"
    )


@pytest.mark.parametrize(
    "host, user",
    [
        ("router.test", "route-probe"),
        ("224.0.0.1", "route-probe"),
        ("192.0.2.3", "root"),
        ("192.0.2.3", "probe -v"),
        ("192.0.2.3", "foo@other"),
    ],
)
def test_controller_requires_numeric_host_and_unprivileged_account(
    monkeypatch, origin_files, host, user
):
    config, _ = origin_files
    config.write_text(
        json.dumps({"origins": {"test-origin": {"host": host, "user": user}}})
    )
    monkeypatch.setattr(remote, "_run_ssh", lambda *args: pytest.fail("unexpected SSH"))

    assert (
        remote.probe_remote_route(
            "test-origin", "test-profile", "test-probe", ARGUMENTS
        )["status"]
        == "unavailable"
    )


@pytest.mark.parametrize(
    "response, status, reason",
    [
        ((255, b"raw SSH output"), "unavailable", "origin_ssh_failed"),
        ((2, b"raw command output"), "failed", "origin_command_failed"),
        ((0, b'{"digest":"bad", "result":{}}'), "failed", "invalid_origin_response"),
        ((0, b"raw response"), "failed", "invalid_origin_response"),
        (subprocess.TimeoutExpired("internal argv", 10), "timeout", "origin_timeout"),
    ],
)
def test_controller_returns_sanitized_failure(
    monkeypatch, origin_files, response, status, reason
):
    def run(argv):
        if isinstance(response, Exception):
            raise response
        return response

    monkeypatch.setattr(remote, "_run_ssh", run)
    result = remote.probe_remote_route(
        "test-origin", "test-profile", "test-probe", ARGUMENTS
    )

    assert result["status"] == status
    assert result["evidence"]["reason"] == reason
    assert "raw" not in str(result)
    assert "internal" not in str(result)


def test_ssh_reader_caps_stdout_and_runtime(monkeypatch):
    assert remote._run_ssh(
        [sys.executable, "-c", "import sys; sys.stdout.buffer.write(b'reply\\n')"]
    ) == (0, b"reply\n")
    with pytest.raises(ValueError):
        remote._run_ssh([sys.executable, "-c", "print('x' * 16384)"])
    monkeypatch.setattr(remote, "SSH_TIMEOUT", 0.75)
    with pytest.raises(subprocess.TimeoutExpired):
        remote._run_ssh([sys.executable, "-c", "import time; time.sleep(10)"])


def _configured_origin(
    monkeypatch, *, router_source=None, agent_origin=None, arguments=ARGUMENTS
):
    probe = SimpleNamespace(
        id="test-probe",
        router_source=router_source,
        agent_origin=agent_origin,
        local_arguments=lambda: arguments,
    )
    profiles = SimpleNamespace(routes={"test-profile": SimpleNamespace(probes=[probe])})
    monkeypatch.setattr(remote, "load_probe_profiles", lambda: profiles)


def test_forced_command_runs_exact_root_configured_probe(monkeypatch, capsys):
    _configured_origin(monkeypatch)
    result = {
        "status": "reachable",
        "evidence": {"duration_ms": 1.0},
        "kernel_route": {"status": "route_found", "result": {}},
    }

    def probe(**kwargs):
        assert kwargs == ARGUMENTS
        return result

    monkeypatch.setenv(
        "SSH_ORIGINAL_COMMAND", f"route-probe test-profile test-probe {DIGEST}"
    )
    monkeypatch.setattr(remote, "probe_local_route", probe)

    assert remote.main() == 0
    assert json.loads(capsys.readouterr().out) == {"digest": DIGEST, "result": result}


@pytest.mark.parametrize(
    "command",
    [
        "",
        "sh",
        "route-probe test-profile test-probe",
        f"route-probe test-profile test-probe {DIGEST}; id",
        f"route-probe test-profile test-probe {DIGEST}\n",
        f"route-probe test-profile test-probe {DIGEST} 192.0.2.5",
    ],
)
def test_forced_command_rejects_other_commands_before_loading_config(
    monkeypatch, capsys, command
):
    monkeypatch.setenv("SSH_ORIGINAL_COMMAND", command)
    monkeypatch.setattr(
        remote, "load_probe_profiles", lambda: pytest.fail("unexpected profile load")
    )

    assert remote.main() == 2
    assert capsys.readouterr().out == ""


@pytest.mark.parametrize(
    "config, reason",
    [
        ({"router_source": "router"}, "origin_probe_not_configured"),
        ({"agent_origin": "other"}, "origin_probe_not_configured"),
        (
            {"arguments": {"target": "192.0.2.5", "protocol": "icmp"}},
            "profile_mismatch",
        ),
    ],
)
def test_forced_command_refuses_recursion_and_profile_mismatch(
    monkeypatch, capsys, config, reason
):
    _configured_origin(monkeypatch, **config)
    monkeypatch.setenv(
        "SSH_ORIGINAL_COMMAND", f"route-probe test-profile test-probe {DIGEST}"
    )
    monkeypatch.setattr(
        remote, "probe_local_route", lambda **kw: pytest.fail("unexpected active probe")
    )

    assert remote.main() == 0
    result = json.loads(capsys.readouterr().out)["result"]
    assert result["status"] == "unavailable"
    assert result["evidence"]["reason"] == reason


def test_origin_and_controller_hash_normalized_profile_defaults(monkeypatch, capsys):
    probe = {
        "id": "test-probe",
        "target": "192.0.2.4",
        "protocol": "dns",
        "expected_path": "test",
        "dns_name": "a.test",
    }
    profiles = ProbeProfiles.model_validate(
        {"routes": {"test-profile": {"label": "DNS", "probes": [probe]}}}
    )
    controller = ProbeProfiles.model_validate(
        {
            "routes": {
                "test-profile": {
                    "label": "DNS",
                    "probes": [
                        dict(probe, port=53, dns_type="A", agent_origin="test-origin"),
                    ],
                }
            }
        }
    )
    arguments = controller.routes["test-profile"].probes[0].local_arguments()
    digest = remote._digest(arguments)
    result = {
        "status": "reachable",
        "evidence": {"duration_ms": 1.0},
        "kernel_route": {"status": "no_route", "result": {}},
    }

    def run(**kwargs):
        assert kwargs == arguments
        return result

    monkeypatch.setattr(remote, "load_probe_profiles", lambda: profiles)
    monkeypatch.setattr(remote, "probe_local_route", run)
    monkeypatch.setenv(
        "SSH_ORIGINAL_COMMAND", f"route-probe test-profile test-probe {digest}"
    )

    assert remote.main() == 0
    assert json.loads(capsys.readouterr().out)["result"] == result


def test_controller_rejects_symlink_identity(monkeypatch, origin_files):
    _, credentials = origin_files
    identity = credentials / "test-origin.key"
    other = credentials / "other-key"
    identity.rename(other)
    try:
        identity.symlink_to(other)
    except OSError:
        pytest.skip("Creating symlinks requires additional privileges on this host")
    monkeypatch.setattr(remote, "_run_ssh", lambda *args: pytest.fail("unexpected SSH"))

    result = remote.probe_remote_route(
        "test-origin", "test-profile", "test-probe", ARGUMENTS
    )

    assert result["status"] == "unavailable"


@pytest.mark.skipif(os.name == "nt", reason="Linux file permissions")
@pytest.mark.parametrize("mode", [0o644, 0o660])
def test_controller_rejects_broad_identity_permissions(monkeypatch, origin_files, mode):
    _, credentials = origin_files
    (credentials / "test-origin.key").chmod(mode)
    monkeypatch.setattr(remote, "_run_ssh", lambda *args: pytest.fail("unexpected SSH"))

    result = remote.probe_remote_route(
        "test-origin", "test-profile", "test-probe", ARGUMENTS
    )

    assert result["status"] == "unavailable"
