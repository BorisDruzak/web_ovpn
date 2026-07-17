from __future__ import annotations

import io
import json
import subprocess
from dataclasses import replace
from pathlib import Path

from alt_deploy.ansible import AnsibleController
from alt_deploy.cli import main
from alt_deploy.jsonio import atomic_write_json, read_json
from alt_deploy.registry import MachineRepository

from test_registry_cli import (
    MACHINE_UUID,
    make_settings,
    write_machine,
)


def prepare_controller_files(
    tmp_path: Path,
):
    settings = make_settings(tmp_path)

    fake_ansible = tmp_path / "ansible-playbook"
    fake_ansible.write_text("#!/bin/sh\n", encoding="utf-8")
    fake_ansible.chmod(0o755)

    settings = replace(
        settings,
        ansible_playbook_path=fake_ansible,
    )

    settings.private_key_file.write_text(
        "private",
        encoding="utf-8",
    )
    settings.known_hosts_file.write_text(
        "host key",
        encoding="utf-8",
    )

    playbook = (
        settings.ansible_project_dir
        / "playbooks"
        / "01-preflight.yml"
    )
    playbook.parent.mkdir(parents=True)
    playbook.write_text("---\n", encoding="utf-8")

    return settings


def test_preflight_uses_inline_inventory_and_strict_known_hosts(
    tmp_path: Path,
) -> None:
    settings = prepare_controller_files(tmp_path)
    captured: list[list[str]] = []

    def fake_run(
        command: list[str],
        timeout: int,
    ) -> subprocess.CompletedProcess[str]:
        captured.append(command)

        result_arg = next(
            value
            for value in command
            if value.startswith("preflight_result_file=")
        )
        result_path = Path(
            result_arg.split("=", 1)[1]
        )

        atomic_write_json(
            result_path,
            {
                "status": "ok",
                "checks": {
                    "alt_release": True,
                },
            },
        )

        return subprocess.CompletedProcess(
            command,
            0,
            "PLAY RECAP ok=10",
            "",
        )

    write_machine(
        settings,
        "ready",
        "2026-07-16T08:00:00+00:00",
    )
    machine = MachineRepository(settings).list()[0]

    result = AnsibleController(
        settings,
        runner=fake_run,
    ).run_preflight(machine)

    command = captured[0]

    assert command[0] == str(
        settings.ansible_playbook_path
    )
    assert f"{machine.ip}," in command
    assert (
        f"--private-key={settings.private_key_file}"
        in command
    )
    assert any(
        "StrictHostKeyChecking=yes" in value
        for value in command
    )
    assert any(
        "ProxyCommand=none" in value
        for value in command
    )
    assert result["status"] == "ok"


def test_preflight_cli_persists_success(
    tmp_path: Path,
    monkeypatch,
) -> None:
    settings = make_settings(tmp_path)

    write_machine(
        settings,
        "ready",
        "2026-07-16T08:00:00+00:00",
    )

    monkeypatch.setattr(
        "alt_deploy.cli.AnsibleController.run_preflight",
        lambda self, machine, employee_login="": {
            "status": "ok",
            "checks": {
                "uuid": True,
            },
        },
    )

    stdout = io.StringIO()

    rc = main(
        [
            "--json",
            "preflight",
            MACHINE_UUID,
        ],
        settings=settings,
        stdout=stdout,
        stderr=io.StringIO(),
    )

    assert rc == 0

    record = read_json(
        settings.registration_root
        / "ready"
        / f"{MACHINE_UUID}.json"
    )

    assert record["status"] == "awaiting_assignment"
    assert record["preflight"]["status"] == "ok"

    response = json.loads(stdout.getvalue())

    assert response["preflight"]["checks"]["uuid"] is True


def test_default_preflight_runner_uses_project_config(
    tmp_path: Path,
    monkeypatch,
) -> None:
    settings = prepare_controller_files(tmp_path)

    ansible_config = (
        settings.ansible_project_dir
        / "ansible.cfg"
    )
    ansible_config.write_text(
        "[defaults]\nroles_path = ./roles\n",
        encoding="utf-8",
    )

    captured: dict[str, object] = {}

    def fake_run(
        command: list[str],
        **kwargs,
    ) -> subprocess.CompletedProcess[str]:
        captured.update(kwargs)

        result_arg = next(
            value
            for value in command
            if value.startswith(
                "preflight_result_file="
            )
        )
        result_path = Path(
            result_arg.split("=", 1)[1]
        )

        atomic_write_json(
            result_path,
            {
                "status": "ok",
                "checks": {
                    "alt_release": True,
                },
            },
        )

        return subprocess.CompletedProcess(
            command,
            0,
            "PLAY RECAP",
            "",
        )

    monkeypatch.setattr(
        "alt_deploy.ansible.subprocess.run",
        fake_run,
    )

    write_machine(
        settings,
        "ready",
        "2026-07-16T08:00:00+00:00",
    )
    machine = MachineRepository(settings).list()[0]

    result = AnsibleController(
        settings
    ).run_preflight(machine)

    assert result["status"] == "ok"
    assert captured["cwd"] == (
        settings.ansible_project_dir
    )
    assert captured["env"]["ANSIBLE_CONFIG"] == str(
        ansible_config
    )
