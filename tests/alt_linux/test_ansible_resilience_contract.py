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


def test_prejoin_upgrade_retries_only_recognized_transient_apt_failures() -> None:
    content = PREJOIN_UPGRADE.read_text(encoding="utf-8")
    variables = yaml.safe_load(COMMON_VARS.read_text(encoding="utf-8"))

    assert variables["alt_apt_transient_error_pattern"]
    assert content.count("failed_when: >-") >= 3
    assert content.count("alt_apt_transient_error_pattern") >= 3


def test_fixed_package_roles_use_verified_bounded_package_helper() -> None:
    helper = (
        ANSIBLE_ROOT / "roles" / "alt_resilience" / "tasks" / "install_packages.yml"
    ).read_text(encoding="utf-8")

    assert "Validate fixed package names" in helper
    assert "Determine missing fixed packages" in helper
    assert "Verify installed fixed packages" in helper
    assert "alt_apt_transient_error_pattern" in helper
    assert 'retries: "{{ alt_package_lock_attempts }}"' in helper
    assert "until: alt_resilience_package_install.rc == 0" in helper

    for role in (
        "workstation_base",
        "alt_group_policy_prerequisites",
        "standard_software",
    ):
        content = (
            ANSIBLE_ROOT / "roles" / role / "tasks" / "main.yml"
        ).read_text(encoding="utf-8")
        assert "ansible.builtin.include_role" in content
        assert "alt_resilience" in content
        assert "ansible.builtin.package" not in content


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


def test_gpo_and_browser_are_fixed_isolated_configure_components() -> None:
    play = load_tasks(CONFIGURE_PLAYBOOK)[0]
    critical_roles = [item["role"] for item in play["vars"]["configure_critical_phases"]]
    components = play["vars"]["configure_components"]

    assert critical_roles.index("prejoin_upgrade") < critical_roles.index("domain_join")
    assert critical_roles.index("alt_group_policy_prerequisites") < critical_roles.index(
        "domain_join"
    )
    assert critical_roles.index("domain_join") < critical_roles.index(
        "alt_group_policy_client"
    )
    assert components == [
        {"name": "standard_software", "role": "standard_software", "required": True},
        {"name": "browser", "role": "software_browser", "required": True},
    ]


def test_browser_artifact_is_validated_and_is_not_hidden_in_standard_software() -> None:
    browser_tasks = (
        ANSIBLE_ROOT / "roles" / "software_browser" / "tasks" / "main.yml"
    ).read_text(encoding="utf-8")
    standard_tasks = (
        ANSIBLE_ROOT / "roles" / "standard_software" / "tasks" / "main.yml"
    ).read_text(encoding="utf-8")

    assert "Validate approved Yandex Browser artifact" in browser_tasks
    assert "software_browser_catalog.sha256" in browser_tasks
    assert "name: software_browser" not in standard_tasks


def test_browser_install_retries_only_recognized_transient_apt_failures() -> None:
    browser_tasks = (
        ANSIBLE_ROOT / "roles" / "software_browser" / "tasks" / "main.yml"
    ).read_text(encoding="utf-8")

    assert 'retries: "{{ alt_package_lock_attempts }}"' in browser_tasks
    assert 'delay: "{{ alt_package_lock_delay_seconds }}"' in browser_tasks
    assert "until: software_browser_install.rc == 0" in browser_tasks
    assert "software_browser_install.stderr" in browser_tasks
    assert "alt_apt_transient_error_pattern" in browser_tasks
    assert "signature" in browser_tasks.lower()
    assert "checksum" in browser_tasks.lower()


def test_workstation_profile_keeps_wayland_and_client_dns_entrypoint() -> None:
    variables = yaml.safe_load(COMMON_VARS.read_text(encoding="utf-8"))

    assert variables["workstation_desktop_session"] == "wayland"
    assert variables["ad_dns_servers"] == ["192.168.100.1"]
    assert variables["alt_group_policy_prerequisite_packages"] == [
        "gpupdate",
        "alterator-gpupdate",
    ]


def test_domain_join_enables_gpo_and_identity_accepts_short_or_fqdn_name() -> None:
    domain_join = DOMAIN_JOIN_TASKS.read_text(encoding="utf-8")
    identity = (
        ANSIBLE_ROOT / "roles" / "workstation_identity" / "tasks" / "main.yml"
    ).read_text(encoding="utf-8")

    assert '"--gpo"' in domain_join
    assert "workstation_identity_accepted_static_hostnames" in identity
    assert '"{{ final_hostname | lower }}.{{ ad_domain | lower }}"' in identity
