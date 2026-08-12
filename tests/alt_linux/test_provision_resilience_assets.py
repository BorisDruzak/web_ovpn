from __future__ import annotations

from pathlib import Path
from typing import Any

import yaml


REPO_ROOT = Path(__file__).resolve().parents[2]
PLAYBOOK = (
    REPO_ROOT
    / "deploy"
    / "alt-linux"
    / "ansible"
    / "playbooks"
    / "02-provision-account.yml"
)


def _playbook() -> dict[str, Any]:
    payload = yaml.safe_load(PLAYBOOK.read_text(encoding="utf-8"))
    assert isinstance(payload, list) and len(payload) == 1
    assert isinstance(payload[0], dict)
    return payload[0]


def test_provision_failure_has_an_always_terminal_result() -> None:
    """A role failure must write a typed result before the play fails."""
    tasks = _playbook()["tasks"]
    workflow = next(
        task
        for task in tasks
        if task["name"] == "Run provision phases and persist failure outcome"
    )

    assert "block" in workflow
    assert "rescue" in workflow
    assert "always" in workflow
    assert [task["name"] for task in workflow["always"]] == [
        "Write structured provision failure result",
    ]
    finalizer = workflow["always"][0]["ansible.builtin.include_tasks"]
    assert finalizer == "tasks/provision_failure_result.yml"
    assert workflow["always"][0]["when"] == (
        "provision_outcome.status == 'failed'"
    )

    terminal_failure = tasks[-1]
    assert terminal_failure["name"] == (
        "Return a non-zero status after terminal failure persistence"
    )
    assert terminal_failure["when"] == (
        "provision_outcome.status == 'failed'"
    )


def test_provision_failure_result_uses_only_safe_contract_fields() -> None:
    """The Ansible finalizer must match the controller's failure parser."""
    finalizer = (
        PLAYBOOK.parent
        / "tasks"
        / "provision_failure_result.yml"
    )
    payload = yaml.safe_load(finalizer.read_text(encoding="utf-8"))
    assert isinstance(payload, list)
    result_task = next(
        task
        for task in payload
        if task["name"] == "Write provision failure result on controller"
    )
    content = result_task["ansible.builtin.copy"]["content"]
    for field in (
        "schema_version",
        "status",
        "machine_uuid",
        "final_hostname",
        "employee_login",
        "profile",
        "job_id",
        "phase",
        "retryable",
        "error",
        "safe_message",
    ):
        assert field in content
    for forbidden in (
        "ansible_failed_result",
        "stdout",
        "stderr",
        "password",
        "secret",
        "token",
    ):
        assert forbidden not in content
