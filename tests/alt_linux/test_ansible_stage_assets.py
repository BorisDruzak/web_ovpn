from __future__ import annotations

from pathlib import Path
from typing import Any

import yaml


REPO_ROOT = Path(__file__).resolve().parents[2]
PROVISION_PLAYBOOK = (
    REPO_ROOT
    / "deploy"
    / "alt-linux"
    / "ansible"
    / "playbooks"
    / "02-provision-account.yml"
)


def load_playbook() -> dict[str, Any]:
    payload = yaml.safe_load(
        PROVISION_PLAYBOOK.read_text(encoding="utf-8")
    )
    assert isinstance(payload, list)
    assert len(payload) == 1
    play = payload[0]
    assert isinstance(play, dict)
    return play


def test_provision_playbook_records_ordered_stages() -> None:
    play = load_playbook()
    workflow = next(
        task
        for task in play["tasks"]
        if task["name"] == "Run provision phases and persist failure outcome"
    )
    tasks = workflow["block"]

    expected = [
        ("Record identity provision stage", "identity"),
        ("Run workstation identity role", "workstation_identity"),
        ("Record employee provision stage", "employee"),
        ("Run local employee role", "local_employee"),
        ("Record login screen provision stage", "login_screen"),
        ("Run LightDM accounts role", "lightdm_accounts"),
        ("Record verification provision stage", "verifying"),
        ("Run provision verification role", "provision_verify"),
    ]

    observed: list[tuple[str, str]] = []

    for task in tasks:
        if "ansible.builtin.include_tasks" in task:
            observed.append(
                (
                    task["name"],
                    task["vars"]["provision_stage_name"],
                )
            )
            assert task["ansible.builtin.include_tasks"] == (
                "tasks/record_provision_stage.yml"
            )
        elif "ansible.builtin.include_role" in task:
            observed.append(
                (
                    task["name"],
                    task["ansible.builtin.include_role"]["name"],
                )
            )

    assert observed == expected
    assert "roles" not in play
