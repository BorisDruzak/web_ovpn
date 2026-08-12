from __future__ import annotations

from pathlib import Path
from typing import Any

import yaml


REPO_ROOT = Path(__file__).resolve().parents[2]
ANSIBLE_ROOT = REPO_ROOT / "deploy" / "alt-linux" / "ansible"
CONFIGURE_PLAYBOOK = (
    ANSIBLE_ROOT / "playbooks" / "03-configure-domain-workstation.yml"
)
PREJOIN_UPGRADE = (
    ANSIBLE_ROOT / "roles" / "prejoin_upgrade" / "tasks" / "main.yml"
)
NETWORK_TASKS = (
    ANSIBLE_ROOT / "roles" / "workstation_network" / "tasks" / "main.yml"
)
DOMAIN_JOIN_TASKS = (
    ANSIBLE_ROOT / "roles" / "domain_join" / "tasks" / "main.yml"
)
MANUAL_PREFLIGHT_TASKS = (
    ANSIBLE_ROOT / "roles" / "manual_preflight" / "tasks" / "main.yml"
)
GROUP_POLICY_TASKS = (
    ANSIBLE_ROOT / "roles" / "alt_group_policy_client" / "tasks" / "main.yml"
)
DOMAIN_VERIFY_TASKS = (
    ANSIBLE_ROOT / "roles" / "domain_verify" / "tasks" / "main.yml"
)
COMMON_VARS = ANSIBLE_ROOT / "group_vars" / "all.yml"


def load_tasks(path: Path) -> list[dict[str, Any]]:
    return yaml.safe_load(path.read_text(encoding="utf-8"))


def test_configure_playbook_uses_explicit_phase_orchestration() -> None:
    play = load_tasks(CONFIGURE_PLAYBOOK)[0]

    assert "roles" not in play
    assert "tasks" in play


def test_configure_playbook_has_terminal_result_finalizer() -> None:
    content = CONFIGURE_PLAYBOOK.read_text(encoding="utf-8")

    assert "configure_finalize.yml" in content
    assert "always:" in content


def test_retry_policy_is_declared_and_bounded() -> None:
    variables = yaml.safe_load(COMMON_VARS.read_text(encoding="utf-8"))

    for field in (
        "alt_transient_attempts",
        "alt_package_lock_attempts",
        "alt_service_attempts",
        "alt_ntp_attempts",
        "alt_domain_join_max_attempts",
    ):
        assert isinstance(variables.get(field), int)
        assert 1 <= variables[field] <= 30


def test_prejoin_upgrade_does_not_force_changed_or_reboot() -> None:
    content = PREJOIN_UPGRADE.read_text(encoding="utf-8")

    assert "changed_when: true" not in content
    assert "Determine whether a full ALT upgrade is pending" in content


def test_network_resolver_change_has_verification_and_rollback() -> None:
    content = NETWORK_TASKS.read_text(encoding="utf-8")

    assert "backup: true" in content
    assert "Validate domain DNS after resolver change" in content
    assert "rescue:" in content


def test_domain_join_reconciles_trust_after_mutation() -> None:
    content = DOMAIN_JOIN_TASKS.read_text(encoding="utf-8")

    assert "Reconcile domain trust after ambiguous join failure" in content
    assert "domain_join_outcome_unknown" in content
    assert "Join workstation and prove resulting domain trust" in content


def test_domain_convergence_probes_have_bounded_retries() -> None:
    for path in (
        MANUAL_PREFLIGHT_TASKS,
        GROUP_POLICY_TASKS,
        DOMAIN_VERIFY_TASKS,
    ):
        content = path.read_text(encoding="utf-8")
        assert 'retries: "{{ alt_' in content
        assert 'delay: "{{ alt_' in content

    preflight = MANUAL_PREFLIGHT_TASKS.read_text(encoding="utf-8")
    assert "until: manual_preflight_ntp.stdout | trim == 'yes'" in preflight
    assert "until: >-" in preflight

    group_policy = GROUP_POLICY_TASKS.read_text(encoding="utf-8")
    assert "until: alt_group_policy_machine_update.rc == 0" in group_policy

    verification = DOMAIN_VERIFY_TASKS.read_text(encoding="utf-8")
    assert "until: domain_verify_sssd.stdout | trim == 'active'" in verification
    assert "until: domain_verify_user.rc == 0" in verification
