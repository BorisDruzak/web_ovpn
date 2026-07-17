from __future__ import annotations

from pathlib import Path
from typing import Any

import yaml


REPO_ROOT = Path(__file__).resolve().parents[2]

ANSIBLE_ROOT = (
    REPO_ROOT
    / "deploy"
    / "alt-linux"
    / "ansible"
)

PREFLIGHT_PLAYBOOK = (
    ANSIBLE_ROOT
    / "playbooks"
    / "01-preflight.yml"
)

PROVISION_PLAYBOOK = (
    ANSIBLE_ROOT
    / "playbooks"
    / "02-provision-account.yml"
)

LOCAL_EMPLOYEE_TASKS = (
    ANSIBLE_ROOT
    / "roles"
    / "local_employee"
    / "tasks"
    / "main.yml"
)

SDDM_TASKS = (
    ANSIBLE_ROOT
    / "roles"
    / "sddm_accounts"
    / "tasks"
    / "main.yml"
)

ASSIGNMENT_TEMPLATE = (
    ANSIBLE_ROOT
    / "roles"
    / "provision_verify"
    / "templates"
    / "assignment.json.j2"
)

VAULT_EXAMPLE = (
    ANSIBLE_ROOT
    / "group_vars"
    / "vault.yml.example"
)


def load_yaml(path: Path) -> list[Any]:
    return list(
        yaml.safe_load_all(
            path.read_text(encoding="utf-8")
        )
    )


def find_module_task(
    tasks: list[dict[str, Any]],
    module_name: str,
) -> dict[str, Any]:
    for task in tasks:
        if module_name in task:
            return task

        for block_name in (
            "block",
            "rescue",
            "always",
        ):
            nested = task.get(block_name)

            if isinstance(nested, list):
                try:
                    return find_module_task(
                        nested,
                        module_name,
                    )
                except AssertionError:
                    pass

    raise AssertionError(
        f"Module task not found: {module_name}"
    )


def test_both_playbooks_are_valid_yaml() -> None:
    assert load_yaml(PREFLIGHT_PLAYBOOK)
    assert load_yaml(PROVISION_PLAYBOOK)


def test_provision_role_order_is_fixed() -> None:
    documents = load_yaml(PROVISION_PLAYBOOK)
    play = documents[0][0]

    role_names = [
        role["role"]
        if isinstance(role, dict)
        else role
        for role in play["roles"]
    ]

    assert role_names == [
        "workstation_identity",
        "local_employee",
        "sddm_accounts",
        "provision_verify",
    ]


def test_local_employee_uses_vault_hash_without_admin_groups() -> None:
    tasks = load_yaml(LOCAL_EMPLOYEE_TASKS)[0]
    user_task = find_module_task(
        tasks,
        "ansible.builtin.user",
    )

    arguments = user_task["ansible.builtin.user"]

    assert arguments["password"] == (
        "{{ vault_employee_password_hash }}"
    )
    assert arguments["update_password"] == "always"
    assert arguments["groups"] == ""
    assert user_task["no_log"] is True


def test_sddm_configuration_hides_only_ansible() -> None:
    content = SDDM_TASKS.read_text(
        encoding="utf-8"
    )

    assert "HideUsers=ansible" in content
    assert "User=" in content
    assert "Session=" in content
    assert "Relogin=false" in content


def test_assignment_template_contains_no_secret_fields() -> None:
    content = ASSIGNMENT_TEMPLATE.read_text(
        encoding="utf-8"
    ).lower()

    for forbidden in (
        "password",
        "secret",
        "token",
        "private_key",
        "vault",
    ):
        assert forbidden not in content


def test_vault_example_contains_no_secret_value() -> None:
    payload = load_yaml(VAULT_EXAMPLE)[0]

    assert payload == {
        "vault_employee_password_hash": "",
    }


def test_roles_contain_no_unsafe_ansible_patterns() -> None:
    tracked_files = [
        *ANSIBLE_ROOT.rglob("*.yml"),
        *ANSIBLE_ROOT.rglob("*.j2"),
        *ANSIBLE_ROOT.rglob("*.cfg"),
    ]

    combined = "\n".join(
        path.read_text(encoding="utf-8")
        for path in tracked_files
    )

    assert "ansible.builtin.shell" not in combined
    assert "ignore_errors:" not in combined
    assert "StrictHostKeyChecking=no" not in combined


def test_local_employee_validates_existing_account_before_mutation() -> None:
    tasks = load_yaml(LOCAL_EMPLOYEE_TASKS)[0]

    task_names = [
        str(task.get("name") or "")
        for task in tasks
    ]

    inspect_index = task_names.index(
        "Inspect existing local employee"
    )
    normalize_index = task_names.index(
        "Normalize existing local employee"
    )
    validate_index = task_names.index(
        "Validate existing local employee"
    )
    create_index = task_names.index(
        "Create or reconcile local employee"
    )

    assert (
        inspect_index
        < normalize_index
        < validate_index
        < create_index
    )

    inspect_task = tasks[inspect_index]

    assert inspect_task["ansible.builtin.command"]["argv"] == [
        "getent",
        "passwd",
        "{{ employee_login }}",
    ]
    assert inspect_task["register"] == "employee_existing"
    assert inspect_task["changed_when"] is False
    assert inspect_task["failed_when"] is False

    validation = tasks[validate_index][
        "ansible.builtin.assert"
    ]["that"]

    rendered = "\n".join(
        str(condition)
        for condition in validation
    )

    assert (
        "employee_existing_fields | length == 0 "
        "or employee_existing_fields[2] | int >= 1000"
        in rendered
    )
    assert (
        "employee_existing_fields | length == 0 "
        "or employee_existing_fields[5] == "
        "'/home/' + employee_login"
        in rendered
    )
    assert (
        "employee_login not in "
        "['root', 'ansible', 'osn-admin']"
        in rendered
    )
