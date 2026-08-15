from __future__ import annotations

import json
import subprocess
from pathlib import Path
from types import SimpleNamespace

import pytest

from alt_deploy.config import Settings
from alt_deploy.configure import ConfigurePlanner, ConfigureRequest
from alt_deploy.errors import ControlError


MACHINE_UUID = "53b03180-5d78-11f0-bd95-f027db877a00"


class MachineFixture:
    def get(self, machine_uuid: str) -> SimpleNamespace:
        assert machine_uuid == MACHINE_UUID
        return SimpleNamespace(
            uuid=MACHINE_UUID,
            ip="192.168.101.56",
        )


def prepare_settings(tmp_path: Path) -> Settings:
    project = tmp_path / "ansible"
    project.mkdir()
    (project / "ansible.cfg").write_text(
        "[defaults]\n",
        encoding="utf-8",
    )
    (project / "playbooks").mkdir()
    (
        project
        / "playbooks"
        / "03-configure-domain-workstation.yml"
    ).write_text("---\n", encoding="utf-8")
    known_hosts = tmp_path / "known_hosts"
    known_hosts.touch()
    private_key = tmp_path / "id_ed25519"
    private_key.write_text("fixture", encoding="utf-8")
    ansible_playbook = tmp_path / "ansible-playbook"
    ansible_playbook.write_text("#!/bin/sh\n", encoding="utf-8")

    return Settings(
        registration_root=tmp_path / "registration",
        state_root=tmp_path / "state",
        jobs_dir=tmp_path / "state" / "jobs",
        assignments_dir=tmp_path / "state" / "assignments",
        lock_file=tmp_path / "state" / "workstationctl.lock",
        ansible_project_dir=project,
        known_hosts_file=known_hosts,
        private_key_file=private_key,
        ansible_playbook_path=ansible_playbook,
        systemd_run_path=Path("/usr/bin/systemd-run"),
        worker_path=Path("/usr/local/libexec/alt-provision-worker"),
        job_stage_helper_path=tmp_path / "alt-job-stage",
        workstationctl_path=Path("/usr/local/sbin/workstationctl"),
    )


def request() -> ConfigureRequest:
    return ConfigureRequest.from_mapping(
        {
            "machine_uuid": MACHINE_UUID,
            "final_hostname": "alt-a1-pc2",
            "hostname_mode": "verify",
            "profile": "standard-domain",
            "domain": "sosnadmin.local",
            "realm": "SOSNADMIN.LOCAL",
            "workgroup": "SOSNADM",
            "computer_ou": (
                "OU=Pilot,OU=Linux,OU=Devices,"
                "DC=sosnadmin,DC=local"
            ),
            "domain_test_user": "alt-test-2@sosnadmin.local",
            "software_profile": "base",
            "remote_access_profile": "none",
            "assigned_domain_user": None,
        },
        expected_uuid=MACHINE_UUID,
    )


def result_path_from_command(command: list[str]) -> Path:
    result_argument = next(
        value
        for value in command
        if value.startswith("configure_result_file=")
    )
    return Path(result_argument.removeprefix("configure_result_file="))


def test_nonzero_ansible_uses_valid_structured_failure_result(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    settings = prepare_settings(tmp_path)
    monkeypatch.setattr(
        "alt_deploy.configure.VaultHealthChecker.check_ad_join",
        lambda self: {"status": "ok"},
    )

    def fake_run(
        command: list[str],
        **_: object,
    ) -> subprocess.CompletedProcess[str]:
        result_path = result_path_from_command(command)
        result_path.write_text(
            json.dumps(
                {
                    "schema_version": 1,
                    "machine_uuid": MACHINE_UUID,
                    "hostname": "alt-a1-pc2",
                    "profile": "standard-domain",
                    "status": "failed",
                    "phase": "network",
                    "retryable": True,
                    "recovered": False,
                    "reboot_required": False,
                    "error": {
                        "code": "domain_dns_unhealthy",
                        "class": "retryable_transient",
                        "safe_message": "AD DNS is unavailable",
                    },
                    "components": {},
                    "verification": {},
                }
            ),
            encoding="utf-8",
        )
        return subprocess.CompletedProcess(command, 2, "", "")

    monkeypatch.setattr(
        "alt_deploy.configure.subprocess.run",
        fake_run,
    )

    with pytest.raises(ControlError) as exc:
        ConfigurePlanner(
            settings,
            machines=MachineFixture(),
        ).start(MACHINE_UUID, request())

    assert exc.value.code == "domain_dns_unhealthy"
    assert exc.value.details["phase"] == "network"
    assert exc.value.details["retryable"] is True
    assert exc.value.details["run_id"]


def test_first_domain_configure_allows_long_full_upgrade(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    settings = prepare_settings(tmp_path)
    monkeypatch.setattr(
        "alt_deploy.configure.VaultHealthChecker.check_ad_join",
        lambda self: {"status": "ok"},
    )
    captured: dict[str, object] = {}

    def fake_run(
        command: list[str],
        **kwargs: object,
    ) -> subprocess.CompletedProcess[str]:
        captured.update(kwargs)
        result_path = result_path_from_command(command)
        result_path.write_text(
            json.dumps(
                {
                    "schema_version": 1,
                    "machine_uuid": MACHINE_UUID,
                    "hostname": "alt-a1-pc2",
                    "profile": "standard-domain",
                    "status": "successful",
                    "phase": "finalize",
                    "retryable": False,
                    "recovered": False,
                    "reboot_required": False,
                    "error": {},
                    "components": {},
                    "verification": {},
                }
            ),
            encoding="utf-8",
        )
        return subprocess.CompletedProcess(command, 0, "", "")

    monkeypatch.setattr(
        "alt_deploy.configure.subprocess.run",
        fake_run,
    )

    ConfigurePlanner(settings, machines=MachineFixture()).start(
        MACHINE_UUID,
        request(),
    )

    assert captured["timeout"] == 5400


def test_launch_error_persists_synthetic_safe_failure_result(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    settings = prepare_settings(tmp_path)
    monkeypatch.setattr(
        "alt_deploy.configure.VaultHealthChecker.check_ad_join",
        lambda self: {"status": "ok"},
    )
    monkeypatch.setattr(
        "alt_deploy.configure.subprocess.run",
        lambda *args, **kwargs: (_ for _ in ()).throw(
            OSError("ansible executable unavailable")
        ),
    )

    with pytest.raises(ControlError) as exc:
        ConfigurePlanner(
            settings,
            machines=MachineFixture(),
        ).start(MACHINE_UUID, request())

    assert exc.value.code == "configure_execution_unavailable"
    run_id = exc.value.details["run_id"]
    result_path = settings.state_root / "configure-runs" / run_id / "result.json"
    result = json.loads(result_path.read_text(encoding="utf-8"))
    assert result["status"] == "failed"
    assert result["phase"] == "finalize"
    assert result["error"]["code"] == "configure_execution_unavailable"
    assert "ansible executable unavailable" not in json.dumps(result)
