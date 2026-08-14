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
ALT_CI_WORKFLOW = REPO_ROOT / ".github" / "workflows" / "verify-alt-ansible.yml"
ANSIBLE_LINT_CONFIG = REPO_ROOT / ".ansible-lint"
YAMLLINT_CONFIG = REPO_ROOT / ".yamllint"


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
    assert "Inspect the planned full ALT upgrade for diagnostics" in content


def test_prejoin_upgrade_retries_only_recognized_transient_apt_failures() -> None:
    content = PREJOIN_UPGRADE.read_text(encoding="utf-8")
    variables = yaml.safe_load(COMMON_VARS.read_text(encoding="utf-8"))

    assert variables["alt_apt_transient_error_pattern"]
    assert content.count("failed_when: false") >= 3
    assert content.count("alt_apt_transient_error_pattern") >= 3
    assert content.count("is not search(alt_apt_transient_error_pattern)") >= 3


def test_prejoin_upgrade_treats_simulation_conflict_as_diagnostic_only() -> None:
    content = PREJOIN_UPGRADE.read_text(encoding="utf-8")
    configure_playbook = CONFIGURE_PLAYBOOK.read_text(encoding="utf-8")

    assert "is not search(alt_apt_transient_error_pattern)" in content
    assert "prejoin_upgrade_simulation.rc != 0 or" in content
    assert "upgrade_dependency_conflict" not in content
    assert "upgrade_execution_failed" in content
    assert "configure_phase_failure | default" in configure_playbook


def test_fixed_package_roles_use_verified_bounded_package_helper() -> None:
    helper = (
        ANSIBLE_ROOT / "roles" / "alt_resilience" / "tasks" / "install_packages.yml"
    ).read_text(encoding="utf-8")

    assert "Validate fixed package names" in helper
    assert "Determine missing fixed packages" in helper
    assert "Verify installed fixed packages" in helper
    assert "alt_apt_transient_error_pattern" in helper
    assert 'retries: "{{ alt_package_lock_attempts }}"' in helper
    assert "is not search(alt_apt_transient_error_pattern)" in helper
    assert "package_install_nontransient_failed" in helper

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


def test_network_rollback_removes_only_a_newly_created_persistent_resolver() -> None:
    content = NETWORK_TASKS.read_text(encoding="utf-8")

    assert "Inspect persistent resolver without following links" in content
    assert "Remove newly created persistent resolver after failed validation" in content
    assert "not workstation_network_persistent_resolver_before.stat.exists" in content


def test_domain_join_reconciles_trust_after_mutation() -> None:
    content = DOMAIN_JOIN_TASKS.read_text(encoding="utf-8")

    assert "Reconcile domain trust after ambiguous join failure" in content
    assert "domain_join_outcome_unknown" in content
    assert "Join workstation and prove resulting domain trust" in content


def test_domain_join_retries_only_transient_kdc_and_ldap_failures() -> None:
    content = DOMAIN_JOIN_TASKS.read_text(encoding="utf-8")
    variables = yaml.safe_load(COMMON_VARS.read_text(encoding="utf-8"))

    assert variables["alt_domain_transient_error_pattern"]
    assert content.count("alt_domain_transient_error_pattern") >= 2
    assert content.count('retries: "{{ alt_transient_attempts }}"') >= 2
    assert "Acquire temporary Kerberos ticket" in content
    assert "Search target OU for requested computer account" in content


def test_ambiguous_domain_join_retries_once_only_when_account_is_absent() -> None:
    content = DOMAIN_JOIN_TASKS.read_text(encoding="utf-8")

    assert "Search target OU after ambiguous join failure" in content
    assert "Reject untrusted computer account after ambiguous join failure" in content
    assert "Retry join only when mutation is proven absent" in content
    assert "domain_join_recovery_command" in content
    assert "Verify trust after safe join retry" in content


def test_terminal_result_marks_reconciled_domain_join_as_recovered() -> None:
    domain_join = DOMAIN_JOIN_TASKS.read_text(encoding="utf-8")
    finalizer = (
        ANSIBLE_ROOT / "playbooks" / "tasks" / "configure_finalize.yml"
    ).read_text(encoding="utf-8")

    assert "domain_join_recovered" in domain_join
    assert "domain_join_recovered" in finalizer


def test_configure_finalizer_does_not_embed_yaml_folding_inside_jinja() -> None:
    finalizer = (
        ANSIBLE_ROOT / "playbooks" / "tasks" / "configure_finalize.yml"
    ).read_text(encoding="utf-8")

    assert "'recovered': >-" not in finalizer


def test_local_employee_rejects_conflicting_primary_group_before_mutation() -> None:
    employee_tasks = (
        ANSIBLE_ROOT / "roles" / "local_employee" / "tasks" / "main.yml"
    ).read_text(encoding="utf-8")

    assert "Inspect existing employee primary group" in employee_tasks
    assert "Validate existing employee primary group" in employee_tasks
    assert "ALT_PREFLIGHT_FAILURE:employee_group_conflict" in employee_tasks
    assert employee_tasks.index("Inspect existing employee primary group") < employee_tasks.index(
        "Ensure employee primary group exists"
    )


def test_alt_resilience_ci_checks_contract_and_all_playbook_syntax() -> None:
    workflow = ALT_CI_WORKFLOW.read_text(encoding="utf-8")

    assert "tests/alt_linux/test_ansible_assets.py" in workflow
    assert "tests/alt_linux/test_ansible_resilience_contract.py" in workflow
    assert "ansible-playbook --syntax-check" in workflow
    assert "for play in deploy/alt-linux/ansible/playbooks/*.yml" in workflow
    assert "ansible-lint deploy/alt-linux/ansible" in workflow
    assert "yamllint deploy/alt-linux/ansible" in workflow


def test_alt_resilience_lint_configuration_keeps_safety_rules_enabled() -> None:
    ansible_lint = ANSIBLE_LINT_CONFIG.read_text(encoding="utf-8")
    yaml_lint = YAMLLINT_CONFIG.read_text(encoding="utf-8")

    assert "run-once[task]" in ansible_lint
    assert "no-changed-when" not in ansible_lint
    assert "syntax-check" not in ansible_lint
    assert "max: 120" in yaml_lint


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
        {"name": "plasma_baseline", "role": "plasma_baseline", "required": True},
        {"name": "standard_software", "role": "standard_software", "required": True},
        {"name": "browser", "role": "software_browser", "required": True},
        {
            "name": "onlyoffice",
            "role": "software_onlyoffice",
            "required": True,
            "enabled": "{{ software_profile == 'core-apps' }}",
        },
        {
            "name": "nextcloud_desktop",
            "role": "software_nextcloud_desktop",
            "required": True,
            "enabled": "{{ software_profile == 'core-apps' }}",
        },
        {
            "name": "desktop_shortcuts",
            "role": "desktop_shortcuts",
            "required": True,
            "enabled": "{{ software_profile == 'core-apps' }}",
        },
        {
            "name": "remote_access_krfb",
            "role": "remote_access_krfb",
            "required": True,
            "enabled": "{{ remote_access_profile == 'krfb' }}",
        },
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


def test_terminal_result_publishes_boolean_browser_verification() -> None:
    finalizer = (
        ANSIBLE_ROOT / "playbooks" / "tasks" / "configure_finalize.yml"
    ).read_text(encoding="utf-8")

    assert "'browser': software_browser_verified | default(false)" in finalizer


def test_browser_install_retries_only_recognized_transient_apt_failures() -> None:
    browser_tasks = (
        ANSIBLE_ROOT / "roles" / "software_browser" / "tasks" / "main.yml"
    ).read_text(encoding="utf-8")

    assert 'retries: "{{ alt_package_lock_attempts }}"' in browser_tasks
    assert 'delay: "{{ alt_package_lock_delay_seconds }}"' in browser_tasks
    assert "is not search(alt_apt_transient_error_pattern)" in browser_tasks
    assert "browser_install_nontransient_failed" in browser_tasks
    assert "software_browser_install.stderr" in browser_tasks
    assert "alt_apt_transient_error_pattern" in browser_tasks
    assert "signature" in browser_tasks.lower()
    assert "checksum" in browser_tasks.lower()


def test_browser_cleanup_requires_an_allocated_tempfile_path() -> None:
    browser_tasks = (
        ANSIBLE_ROOT / "roles" / "software_browser" / "tasks" / "main.yml"
    ).read_text(encoding="utf-8")

    assert "software_browser_temp_rpm.path is defined" in browser_tasks


def test_core_apps_roles_are_isolated_and_use_resilient_package_paths() -> None:
    variables = yaml.safe_load(COMMON_VARS.read_text(encoding="utf-8"))
    onlyoffice = (
        ANSIBLE_ROOT / "roles" / "software_onlyoffice" / "tasks" / "main.yml"
    ).read_text(encoding="utf-8")
    nextcloud = (
        ANSIBLE_ROOT / "roles" / "software_nextcloud_desktop" / "tasks" / "main.yml"
    ).read_text(encoding="utf-8")
    shortcuts = (
        ANSIBLE_ROOT / "roles" / "desktop_shortcuts" / "tasks" / "main.yml"
    ).read_text(encoding="utf-8")
    shortcut_defaults = yaml.safe_load(
        (
            ANSIBLE_ROOT / "roles" / "desktop_shortcuts" / "defaults" / "main.yml"
        ).read_text(encoding="utf-8")
    )

    assert 'retries: "{{ alt_package_lock_attempts }}"' in onlyoffice
    assert "onlyoffice_install_nontransient_failed" in onlyoffice
    assert "software_onlyoffice_temp_rpm.path is defined" in onlyoffice
    assert "ansible.builtin.include_role" in nextcloud
    assert "alt_resilience_package_names" in nextcloud
    assert variables["software_catalog"]["nextcloud_desktop"]["packages"] == [
        "nextcloud-client",
        "nextcloud-client-kde",
    ]
    assert "assigned_domain_user" in shortcuts
    assert "getent, passwd" in shortcuts
    assert shortcut_defaults["desktop_shortcuts_nextcloud_entry"] == "nextcloud-client.desktop"
    assert "loop: lookup('ansible.builtin.fileglob'" not in shortcuts


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
