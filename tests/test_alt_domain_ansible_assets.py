from __future__ import annotations

from pathlib import Path

import yaml


ANSIBLE_ROOT = (
    Path(__file__).resolve().parents[1] / "deploy" / "alt-linux" / "ansible"
)


def test_domain_playbook_uses_only_the_manual_domain_roles() -> None:
    playbook_path = ANSIBLE_ROOT / "playbooks" / "03-configure-domain-workstation.yml"
    playbook = yaml.safe_load(playbook_path.read_text(encoding="utf-8"))

    assert playbook[0]["roles"] == [
        "manual_preflight",
        "workstation_identity",
        "workstation_base",
        "workstation_network",
        "domain_join",
        "standard_software",
        "domain_verify",
    ]
    assert playbook[0]["vars_files"] == [
        "../group_vars/all.yml",
        "../group_vars/vault.yml",
    ]


def test_domain_join_uses_kerberos_stdin_and_never_password_arguments() -> None:
    role_path = ANSIBLE_ROOT / "roles" / "domain_join" / "tasks" / "main.yml"
    tasks = yaml.safe_load(role_path.read_text(encoding="utf-8"))
    rendered = role_path.read_text(encoding="utf-8")

    credential_tasks = [
        task
        for task in tasks
        if "kinit" in task["name"].lower()
        or "Join" in task["name"]
    ]
    assert credential_tasks
    assert all(task.get("no_log") is True for task in credential_tasks)
    assert "vault_ad_join_password" in rendered
    assert 'stdin: "{{ vault_ad_join_password }}"' in rendered
    assert 'argv: [kinit, -C, "{{ vault_ad_join_user }}"]' in rendered
    assert "system-auth" in rendered
    assert "kdestroy" in rendered


def test_domain_group_vars_use_confirmed_alt_package_and_domain_dns() -> None:
    variables = yaml.safe_load(
        (ANSIBLE_ROOT / "group_vars" / "all.yml").read_text(encoding="utf-8")
    )

    assert variables["domain_prerequisite_packages"] == ["task-auth-ad-sssd"]
    assert variables["ad_dns_servers"] == ["192.168.100.11"]
    assert variables["ad_domain"] == "sosnadmin.local"


def test_domain_verify_accepts_short_name_or_upn() -> None:
    content = (
        ANSIBLE_ROOT / "roles" / "domain_verify" / "tasks" / "main.yml"
    ).read_text(encoding="utf-8")

    assert "domain_test_user if '@' in domain_test_user" in content
