from __future__ import annotations

from pathlib import Path
from typing import Any

import yaml


REPO_ROOT = Path(__file__).resolve().parents[2]
ANSIBLE_ROOT = REPO_ROOT / "deploy" / "alt-linux" / "ansible"
PREFLIGHT_PLAYBOOK = ANSIBLE_ROOT / "playbooks" / "01-preflight.yml"
PREFLIGHT_TASKS = ANSIBLE_ROOT / "roles" / "preflight" / "tasks" / "main.yml"
PROVISION_PLAYBOOK = ANSIBLE_ROOT / "playbooks" / "02-provision-account.yml"
LOCAL_EMPLOYEE_TASKS = (
    ANSIBLE_ROOT / "roles" / "local_employee" / "tasks" / "main.yml"
)
LIGHTDM_TASKS = (
    ANSIBLE_ROOT / "roles" / "lightdm_accounts" / "tasks" / "main.yml"
)
ASSIGNMENT_TEMPLATE = (
    ANSIBLE_ROOT
    / "roles"
    / "provision_verify"
    / "templates"
    / "assignment.json.j2"
)
VAULT_EXAMPLE = ANSIBLE_ROOT / "group_vars" / "vault.yml.example"


def load_yaml(path: Path) -> list[Any]:
    return list(yaml.safe_load_all(path.read_text(encoding="utf-8")))


def find_module_task(
    tasks: list[dict[str, Any]],
    module_name: str,
) -> dict[str, Any]:
    for task in tasks:
        if module_name in task:
            return task

        for block_name in ("block", "rescue", "always"):
            nested = task.get(block_name)
            if isinstance(nested, list):
                try:
                    return find_module_task(nested, module_name)
                except AssertionError:
                    pass

    raise AssertionError(f"Module task not found: {module_name}")


def test_both_playbooks_are_valid_yaml() -> None:
    assert load_yaml(PREFLIGHT_PLAYBOOK)
    assert load_yaml(PROVISION_PLAYBOOK)


def test_provision_role_order_is_fixed() -> None:
    play = load_yaml(PROVISION_PLAYBOOK)[0][0]

    assert "roles" not in play
    role_names = [
        task["ansible.builtin.include_role"]["name"]
        for task in play["tasks"]
        if "ansible.builtin.include_role" in task
    ]

    assert role_names == [
        "workstation_identity",
        "local_employee",
        "lightdm_accounts",
        "provision_verify",
    ]


def test_local_employee_uses_vault_hash_without_admin_groups() -> None:
    tasks = load_yaml(LOCAL_EMPLOYEE_TASKS)[0]
    user_task = find_module_task(tasks, "ansible.builtin.user")
    arguments = user_task["ansible.builtin.user"]

    assert arguments["password"] == "{{ vault_employee_password_hash }}"
    assert arguments["update_password"] == "always"
    assert arguments["groups"] == ""
    assert user_task["no_log"] is True


def test_lightdm_configuration_hides_only_ansible_and_disables_autologin() -> None:
    content = LIGHTDM_TASKS.read_text(encoding="utf-8")

    assert "/var/lib/AccountsService/users/ansible" in content
    assert "SystemAccount=true" in content
    assert (
        "/var/lib/AccountsService/users/{{ employee_login }}"
        in content
    )
    assert "SystemAccount=false" in content
    assert (
        "/etc/lightdm/lightdm.conf.d/90-alt-workstation.conf"
        in content
    )
    assert "autologin-user=" in content
    assert "autologin-user-timeout=0" in content
    assert "osn-admin" not in content
    assert "sddm" not in content.lower()


def test_assignment_template_contains_no_secret_fields() -> None:
    content = ASSIGNMENT_TEMPLATE.read_text(encoding="utf-8").lower()

    for forbidden in (
        "password",
        "secret",
        "token",
        "private_key",
        "vault",
    ):
        assert forbidden not in content


def test_vault_example_contains_no_secret_value() -> None:
    assert load_yaml(VAULT_EXAMPLE)[0] == {
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
    task_names = [str(task.get("name") or "") for task in tasks]

    inspect_index = task_names.index("Inspect existing local employee")
    normalize_index = task_names.index("Normalize existing local employee")
    validate_index = task_names.index("Validate existing local employee")
    create_index = task_names.index("Create or reconcile local employee")

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

    validation = tasks[validate_index]["ansible.builtin.assert"]["that"]
    rendered = "\n".join(str(condition) for condition in validation)

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
        "employee_login not in ['root', 'ansible', 'osn-admin']"
        in rendered
    )


def test_preflight_validates_lightdm_accountsservice_stack() -> None:
    tasks = load_yaml(PREFLIGHT_TASKS)[0]
    by_name = {
        str(task.get("name") or ""): task
        for task in tasks
    }

    assert by_name["Check LightDM package"][
        "ansible.builtin.command"
    ]["argv"] == ["rpm", "-q", "lightdm"]
    assert by_name["Check AccountsService package"][
        "ansible.builtin.command"
    ]["argv"] == ["rpm", "-q", "accountsservice"]
    assert by_name["Check AccountsService daemon"][
        "ansible.builtin.command"
    ]["argv"] == [
        "systemctl",
        "is-active",
        "accounts-daemon",
    ]
    assert by_name["Read active display manager"][
        "ansible.builtin.command"
    ]["argv"] == [
        "readlink",
        "-f",
        "/etc/systemd/system/display-manager.service",
    ]

    validation = by_name[
        "Validate LightDM and AccountsService"
    ]["ansible.builtin.assert"]["that"]
    rendered = "\n".join(str(condition) for condition in validation)

    assert "preflight_lightdm.rc == 0" in rendered
    assert "preflight_accountsservice.rc == 0" in rendered
    assert (
        "preflight_accounts_daemon.stdout | trim == 'active'"
        in rendered
    )
    assert (
        "'lightdm.service' in preflight_display_manager.stdout"
        in rendered
    )
    assert "sddm" not in PREFLIGHT_TASKS.read_text(
        encoding="utf-8"
    ).lower()


def test_provision_verifies_lightdm_accountsservice_state() -> None:
    tasks_path = (
        ANSIBLE_ROOT
        / "roles"
        / "provision_verify"
        / "tasks"
        / "main.yml"
    )
    content = tasks_path.read_text(encoding="utf-8")

    assert "/var/lib/AccountsService/users/ansible" in content
    assert (
        "/var/lib/AccountsService/users/{{ employee_login }}"
        in content
    )
    assert (
        "/etc/lightdm/lightdm.conf.d/90-alt-workstation.conf"
        in content
    )
    assert "SystemAccount=true" in content
    assert "SystemAccount=false" in content
    assert "autologin-user=" in content
    assert "autologin-user-timeout=0" in content
    assert "lightdm_hides_ansible" in content
    assert "lightdm_shows_employee" in content
    assert "lightdm_autologin_disabled" in content
    assert "sddm" not in content.lower()


def test_provision_playbook_explicitly_loads_vault() -> None:
    play = load_yaml(PROVISION_PLAYBOOK)[0][0]
    assert play["vars_files"] == ["../group_vars/vault.yml"]


def test_employee_sudo_checks_use_c_locale_and_accept_denial() -> None:
    local_employee = (
        ANSIBLE_ROOT
        / "roles"
        / "local_employee"
        / "tasks"
        / "main.yml"
    ).read_text(encoding="utf-8")
    provision_verify = (
        ANSIBLE_ROOT
        / "roles"
        / "provision_verify"
        / "tasks"
        / "main.yml"
    ).read_text(encoding="utf-8")

    for content in (local_employee, provision_verify):
        assert "LC_ALL: C" in content
        assert "is not allowed to run sudo" in content

    assert "local_employee_sudo.rc != 0" not in local_employee
    assert (
        "provision_verify_employee_sudo.rc != 0"
        not in provision_verify
    )


def test_provision_completion_timestamp_is_collected_immediately_before_assignment() -> None:
    tasks_path = (
        ANSIBLE_ROOT
        / "roles"
        / "provision_verify"
        / "tasks"
        / "main.yml"
    )
    tasks = load_yaml(tasks_path)[0]
    by_name = {
        str(task.get("name") or ""): task
        for task in tasks
    }

    assert "Read provision completion time" in by_name

    read_time = by_name["Read provision completion time"]
    assert read_time["ansible.builtin.command"]["argv"] == [
        "date",
        "-u",
        "+%Y-%m-%dT%H:%M:%SZ",
    ]
    assert read_time["register"] == "provision_completed_at_command"
    assert read_time["changed_when"] is False

    set_time = by_name["Set provision completion time"]
    assert set_time["ansible.builtin.set_fact"][
        "provision_completed_at"
    ] == "{{ provision_completed_at_command.stdout | trim }}"

    content = tasks_path.read_text(encoding="utf-8")
    assert "ansible_date_time.iso8601" not in content
