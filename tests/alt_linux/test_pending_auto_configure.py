from __future__ import annotations

import importlib.util
import json
import subprocess
from pathlib import Path
from types import ModuleType

import pytest

from alt_deploy.config import Settings


MACHINE_UUID = "53b03180-5d78-11f0-bd95-f027db877a00"

PROCESS_PENDING_PATH = (
    Path(__file__).resolve().parents[2]
    / "deploy"
    / "alt-linux"
    / "api"
    / "process_pending.py"
)


def _load_module() -> ModuleType:
    spec = importlib.util.spec_from_file_location(
        "process_pending_auto_configure_under_test",
        PROCESS_PENDING_PATH,
    )
    assert spec is not None
    assert spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def _prepare(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> tuple[ModuleType, Path, Path, Path]:
    module = _load_module()
    registration = tmp_path / "registration"
    pending = registration / "pending"
    ready = registration / "ready"
    failed = registration / "failed"
    for directory in (pending, ready, failed):
        directory.mkdir(parents=True)

    requests = tmp_path / "configure-requests"
    requests.mkdir(mode=0o700)
    known_hosts = tmp_path / "known_hosts"
    known_hosts.touch()
    private_key = tmp_path / "id_ed25519"
    private_key.write_text("private-key-fixture", encoding="utf-8")

    state = tmp_path / "state"
    settings = Settings(
        registration_root=registration,
        state_root=state,
        jobs_dir=state / "jobs",
        assignments_dir=state / "assignments",
        lock_file=state / "workstationctl.lock",
        ansible_project_dir=tmp_path / "ansible",
        known_hosts_file=known_hosts,
        private_key_file=private_key,
        ansible_playbook_path=Path("/usr/bin/ansible-playbook"),
        systemd_run_path=Path("/usr/bin/systemd-run"),
        worker_path=Path("/usr/local/libexec/alt-provision-worker"),
        job_stage_helper_path=tmp_path / "alt-job-stage",
        workstationctl_path=Path("/usr/local/sbin/workstationctl"),
    )
    (settings.ansible_project_dir / "playbooks").mkdir(parents=True)
    (
        settings.ansible_project_dir
        / "playbooks"
        / "00-validate-assigned-domain-user.yml"
    ).write_text("---\n", encoding="utf-8")
    monkeypatch.setattr(module, "SETTINGS", settings, raising=False)
    monkeypatch.setattr(module, "PENDING_DIR", pending)
    monkeypatch.setattr(module, "READY_DIR", ready)
    monkeypatch.setattr(module, "FAILED_DIR", failed)
    monkeypatch.setattr(module, "CONFIGURE_REQUESTS_DIR", requests, raising=False)
    monkeypatch.setattr(module, "KNOWN_HOSTS", known_hosts)
    monkeypatch.setattr(module, "PRIVATE_KEY", private_key)
    monkeypatch.setattr(module, "wait_for_ssh", lambda ip: True)
    return module, pending, ready, requests


def _write_registration(pending: Path) -> Path:
    path = pending / f"{MACHINE_UUID}.json"
    path.write_text(
        json.dumps(
            {
                "machine_key": MACHINE_UUID,
                "uuid": MACHINE_UUID,
                "hostname": "alt-a1-pc2",
                "ip": "192.168.101.56",
                "mac": "c0:9b:f4:62:54:e5",
                "registration_id": "reg-11111111111111111111111111111111",
                "registered_at": "2026-08-12T08:00:00+00:00",
                "status": "pending",
            }
        )
        + "\n",
        encoding="utf-8",
    )
    return path


def _write_request(requests: Path, uuid: str) -> Path:
    path = requests / f"{uuid}.json"
    path.write_text(
        json.dumps(
            {
                "machine_uuid": uuid,
                "final_hostname": "alt-a1-pc2",
                "hostname_mode": "verify",
                "profile": "standard-domain",
                "domain": "sosnadmin.local",
                "realm": "SOSNADMIN.LOCAL",
                "workgroup": "SOSNADM",
                "computer_ou": "OU=Pilot,OU=Linux,OU=Устройства,DC=sosnadmin,DC=local",
                "domain_test_user": "alt-test-2@sosnadmin.local",
                "software_profile": "base",
                "remote_access_profile": "none",
                "assigned_domain_user": None,
            }
        )
        + "\n",
        encoding="utf-8",
    )
    return path


def test_uuid_bound_request_runs_preview_then_configure(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    module, pending, ready, requests = _prepare(tmp_path, monkeypatch)
    pending_record = _write_registration(pending)
    request_path = _write_request(requests, MACHINE_UUID)
    configure_commands: list[list[str]] = []

    def run(
        command: list[str],
        *,
        timeout: int = 60,
    ) -> subprocess.CompletedProcess[str]:
        if command[0] == module.SSH_KEYGEN:
            return subprocess.CompletedProcess(command, 0, "", "")
        if command[0] == module.SSH_KEYSCAN:
            return subprocess.CompletedProcess(
                command, 0, "192.168.101.56 ssh-ed25519 AAAATEST\n", ""
            )
        if command[0] == module.ANSIBLE:
            return subprocess.CompletedProcess(
                command, 0, '192.168.101.56 | SUCCESS => {"ping":"pong"}\n', ""
            )
        if command[0] != module.WORKSTATIONCTL:
            raise AssertionError(f"Unexpected command: {command}")
        if "preflight" in command:
            return subprocess.CompletedProcess(
                command,
                0,
                json.dumps(
                    {
                        "status": "ok",
                        "machine_uuid": MACHINE_UUID,
                        "preflight": {"status": "ok", "checks": {"uuid": True}},
                    }
                ),
                "",
            )
        configure_commands.append(command)
        if "preview" in command:
            assert command[-1] == str(request_path)
            return subprocess.CompletedProcess(
                command,
                0,
                json.dumps(
                    {
                        "status": "ok",
                        "machine_uuid": MACHINE_UUID,
                        "target_ip": "192.168.101.56",
                    }
                ),
                "",
            )
        if "start" in command:
            return subprocess.CompletedProcess(
                command,
                0,
                json.dumps(
                    {
                        "machine_uuid": MACHINE_UUID,
                        "run_id": "configure-run-123",
                        "verification": {"domain_join": True},
                    }
                ),
                "",
            )
        raise AssertionError(f"Unexpected workstationctl command: {command}")

    monkeypatch.setattr(module, "run_command", run)

    module.process_record(pending_record)

    record = json.loads(
        (ready / pending_record.name).read_text(encoding="utf-8")
    )
    assert record["status"] == "configured"
    assert record["configure_result"]["run_id"] == "configure-run-123"
    assert len(configure_commands) == 2
    assert "preview" in configure_commands[0]
    assert "start" in configure_commands[1]


def test_request_for_another_uuid_does_not_start_configuration(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    module, pending, ready, requests = _prepare(tmp_path, monkeypatch)
    pending_record = _write_registration(pending)
    _write_request(
        requests,
        "aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa",
    )

    def run(
        command: list[str],
        *,
        timeout: int = 60,
    ) -> subprocess.CompletedProcess[str]:
        if command[0] == module.SSH_KEYGEN:
            return subprocess.CompletedProcess(command, 0, "", "")
        if command[0] == module.SSH_KEYSCAN:
            return subprocess.CompletedProcess(
                command, 0, "192.168.101.56 ssh-ed25519 AAAATEST\n", ""
            )
        if command[0] == module.ANSIBLE:
            return subprocess.CompletedProcess(
                command, 0, '192.168.101.56 | SUCCESS => {"ping":"pong"}\n', ""
            )
        if command[0] == module.WORKSTATIONCTL and "preflight" in command:
            return subprocess.CompletedProcess(
                command,
                0,
                json.dumps(
                    {
                        "status": "ok",
                        "machine_uuid": MACHINE_UUID,
                        "preflight": {"status": "ok", "checks": {"uuid": True}},
                    }
                ),
                "",
            )
        raise AssertionError(f"Configuration must not start: {command}")

    monkeypatch.setattr(module, "run_command", run)

    module.process_record(pending_record)

    record = json.loads(
        (ready / pending_record.name).read_text(encoding="utf-8")
    )
    assert record["status"] == "awaiting_assignment"


def test_assigned_user_is_validated_before_configure_start(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    module, pending, ready, requests = _prepare(tmp_path, monkeypatch)
    pending_record = _write_registration(pending)
    registration = json.loads(pending_record.read_text(encoding="utf-8"))
    registration["assigned_domain_user"] = "alt-test-2@sosnadmin.local"
    pending_record.write_text(json.dumps(registration), encoding="utf-8")
    request_path = _write_request(requests, MACHINE_UUID)
    command_order: list[str] = []

    def run(
        command: list[str],
        *,
        timeout: int = 60,
    ) -> subprocess.CompletedProcess[str]:
        if command[0] == module.SSH_KEYGEN:
            return subprocess.CompletedProcess(command, 0, "", "")
        if command[0] == module.SSH_KEYSCAN:
            return subprocess.CompletedProcess(
                command, 0, "192.168.101.56 ssh-ed25519 AAAATEST\n", ""
            )
        if command[0] == module.ANSIBLE:
            return subprocess.CompletedProcess(command, 0, "pong\n", "")
        if command[0] == module.ANSIBLE_PLAYBOOK:
            assert command[-1].endswith(
                "00-validate-assigned-domain-user.yml"
            )
            assert "assigned_domain_user=alt-test-2@sosnadmin.local" in command
            command_order.append("validate")
            return subprocess.CompletedProcess(command, 0, "", "")
        if command[0] == module.WORKSTATIONCTL and "preflight" in command:
            command_order.append("preflight")
            return subprocess.CompletedProcess(
                command,
                0,
                json.dumps({
                    "status": "ok",
                    "machine_uuid": MACHINE_UUID,
                    "preflight": {"status": "ok", "checks": {}},
                }),
                "",
            )
        if command[0] == module.WORKSTATIONCTL:
            command_order.append("configure")
            return subprocess.CompletedProcess(
                command,
                0,
                json.dumps({
                    "status": "ok",
                    "machine_uuid": MACHINE_UUID,
                    "target_ip": "192.168.101.56",
                    "run_id": "configure-run-123",
                }),
                "",
            )
        raise AssertionError(f"Unexpected command: {command}")

    monkeypatch.setattr(module, "run_command", run)
    module.process_record(pending_record)

    record = json.loads((ready / pending_record.name).read_text(encoding="utf-8"))
    assert record["status"] == "configured"
    assert command_order[:2] == ["preflight", "validate"]
    assert command_order.count("configure") == 2
    assert str(request_path) in [item for item in []] or request_path.exists()


def test_unknown_assigned_user_stops_before_domain_configure(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    module, pending, _, requests = _prepare(tmp_path, monkeypatch)
    pending_record = _write_registration(pending)
    registration = json.loads(pending_record.read_text(encoding="utf-8"))
    registration["assigned_domain_user"] = "missing@sosnadmin.local"
    pending_record.write_text(json.dumps(registration), encoding="utf-8")
    _write_request(requests, MACHINE_UUID)

    def run(
        command: list[str],
        *,
        timeout: int = 60,
    ) -> subprocess.CompletedProcess[str]:
        if command[0] == module.SSH_KEYGEN:
            return subprocess.CompletedProcess(command, 0, "", "")
        if command[0] == module.SSH_KEYSCAN:
            return subprocess.CompletedProcess(
                command, 0, "192.168.101.56 ssh-ed25519 AAAATEST\n", ""
            )
        if command[0] == module.ANSIBLE:
            return subprocess.CompletedProcess(command, 0, "pong\n", "")
        if command[0] == module.WORKSTATIONCTL and "preflight" in command:
            return subprocess.CompletedProcess(
                command,
                0,
                json.dumps({
                    "status": "ok",
                    "machine_uuid": MACHINE_UUID,
                    "preflight": {"status": "ok", "checks": {}},
                }),
                "",
            )
        if command[0] == module.ANSIBLE_PLAYBOOK:
            return subprocess.CompletedProcess(
                command,
                2,
                "ALT_PREFLIGHT_FAILURE:assigned_domain_user_not_found\n",
                "",
            )
        raise AssertionError(f"Domain configure must not start: {command}")

    monkeypatch.setattr(module, "run_command", run)
    module.process_record(pending_record)

    failed = pending.parent / "failed" / pending_record.name
    record = json.loads(failed.read_text(encoding="utf-8"))
    assert record["status"] == "failed"
    assert record["error"] == "assigned_domain_user_not_found"
