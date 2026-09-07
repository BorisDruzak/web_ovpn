from __future__ import annotations

from pathlib import Path

import yaml


ANSIBLE_ROOT = (
    Path(__file__).resolve().parents[1] / "deploy" / "alt-linux" / "ansible"
)
CRITICAL_ROLES = [
    "manual_preflight",
    "workstation_identity",
    "prejoin_upgrade",
    "workstation_base",
    "alt_group_policy_prerequisites",
    "workstation_network",
    "domain_join",
    "alt_group_policy_client",
    "domain_login_baseline",
    "domain_verify",
]


def test_domain_playbook_delegates_to_the_critical_phase_contract() -> None:
    playbook_path = ANSIBLE_ROOT / "playbooks" / "03-configure-domain-workstation.yml"
    playbook = yaml.safe_load(playbook_path.read_text(encoding="utf-8"))

    assert "roles" not in playbook[0]
    assert playbook[0]["tasks"] == [
        {
            "name": "Configure critical manual workstation phase",
            "ansible.builtin.import_tasks": "tasks/configure_critical_phase.yml",
        }
    ]
    assert playbook[0]["vars_files"] == [
        "../group_vars/all.yml",
        "../group_vars/vault.yml",
        "../group_vars/software_catalog.yml",
    ]


def test_critical_phase_runs_only_the_base_roles_in_controller_order() -> None:
    phase_path = ANSIBLE_ROOT / "playbooks" / "tasks" / "configure_critical_phase.yml"
    rendered = phase_path.read_text(encoding="utf-8")

    expected_includes = [
        f"name: {role}" for role in CRITICAL_ROLES
    ]
    positions = [rendered.index(include) for include in expected_includes]

    assert positions == sorted(positions)
    assert rendered.count("ansible.builtin.include_role:") == len(CRITICAL_ROLES)
    assert "standard_software" not in rendered
    assert "loop:" not in rendered


def test_selected_components_are_preflighted_before_component_roles() -> None:
    text = (ANSIBLE_ROOT / "playbooks" / "tasks" / "configure_critical_phase.yml").read_text(
        encoding="utf-8"
    )

    assert "configure_component_preflight.yml" in text
    assert text.index("configure_component_preflight.yml") < text.index("Run manual preflight")


def test_stage03_loads_the_nonsecret_component_catalog() -> None:
    text = (ANSIBLE_ROOT / "playbooks" / "03-configure-domain-workstation.yml").read_text(
        encoding="utf-8"
    )

    assert "../group_vars/software_catalog.yml" in text


def test_component_preflight_rejects_disabled_catalog_entries() -> None:
    text = (
        ANSIBLE_ROOT / "playbooks" / "tasks" / "configure_component_preflight.yml"
    ).read_text(encoding="utf-8")

    assert "software_component_catalog_invalid" in text
    assert "checksum_algorithm: sha256" in text
    assert "delegate_to: localhost" in text


def test_critical_phase_writes_exact_structured_success_result() -> None:
    phase_path = ANSIBLE_ROOT / "playbooks" / "tasks" / "configure_critical_phase.yml"
    finalizer_path = ANSIBLE_ROOT / "playbooks" / "tasks" / "write_configure_result.yml"
    phase = yaml.safe_load(phase_path.read_text(encoding="utf-8"))
    finalizer = yaml.safe_load(finalizer_path.read_text(encoding="utf-8"))
    result = phase[0]["ansible.builtin.set_fact"]["configure_result"]

    assert set(result) == {
        "schema_version",
        "machine_uuid",
        "hostname",
        "profile",
        "status",
        "phase",
        "retryable",
        "recovered",
        "reboot_required",
        "error",
        "components",
        "verification",
    }
    assert result["schema_version"] == 1
    assert result["status"] == "successful"
    assert result["phase"] == "finalize"
    assert result["error"] is None
    assert finalizer[0]["ansible.builtin.copy"]["content"] == (
        "{{ configure_result | to_nice_json }}"
    )
    assert finalizer[0]["delegate_to"] == "localhost"
    assert finalizer[0]["become"] is False
    assert finalizer[0]["run_once"] is True


def test_critical_phase_persists_safe_failed_result_before_terminal_failure() -> None:
    phase_path = ANSIBLE_ROOT / "playbooks" / "tasks" / "configure_critical_phase.yml"
    rendered = phase_path.read_text(encoding="utf-8")

    finalizer_index = rendered.index("write_configure_result.yml")
    fail_index = rendered.index("ansible.builtin.fail:")

    assert finalizer_index < fail_index
    assert "'status': 'failed'" in rendered
    assert "'configure_critical_phase_failed'" in rendered
    assert "'fatal-invariant'" in rendered
    assert "'error':" in rendered


def test_critical_phase_rescue_persists_before_terminal_failure() -> None:
    phase_path = ANSIBLE_ROOT / "playbooks" / "tasks" / "configure_critical_phase.yml"
    phase = yaml.safe_load(phase_path.read_text(encoding="utf-8"))
    rescue_tasks = phase[1]["rescue"]

    persistence_indexes = [
        index
        for index, task in enumerate(rescue_tasks)
        if task.get("ansible.builtin.include_tasks") == "write_configure_result.yml"
    ]
    failure_indexes = [
        index
        for index, task in enumerate(rescue_tasks)
        if "ansible.builtin.fail" in task
    ]

    assert persistence_indexes == [1]
    assert failure_indexes == [2]
    assert persistence_indexes[0] < failure_indexes[0]


def test_domain_verify_does_not_write_a_legacy_configure_result() -> None:
    content = (
        ANSIBLE_ROOT / "roles" / "domain_verify" / "tasks" / "main.yml"
    ).read_text(encoding="utf-8")

    assert "Write public configure result on controller" not in content
    assert "configure_result_file" not in content


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


def test_domain_join_converts_ad_dn_to_alt_parent_first_ou_path() -> None:
    role_path = ANSIBLE_ROOT / "roles" / "domain_join" / "tasks" / "main.yml"
    rendered = role_path.read_text(encoding="utf-8")

    assert "alt_createcomputer_path" in rendered
    assert "regex_findall('OU=([^,]+)') | reverse | join('/')" in rendered
    assert '"--createcomputer={{ alt_createcomputer_path }}"' in rendered
    assert '"--gpo"' in rendered


def test_prejoin_upgrade_runs_only_before_domain_join_and_defers_reboot() -> None:
    content = (
        ANSIBLE_ROOT / "roles" / "prejoin_upgrade" / "tasks" / "main.yml"
    ).read_text(encoding="utf-8")

    assert "system-auth, status" in content
    assert "apt-get, update" in content
    assert "apt-get, -y, dist-upgrade" in content
    assert "ansible.builtin.reboot" not in content
    assert "prejoin_upgrade_reboot_required" in content
    assert content.count("not prejoin_upgrade_already_joined") >= 3
    assert "prejoin_upgrade_dist_upgrade is defined" in content


def test_group_policy_installation_precedes_join_and_enablement_follows_it() -> None:
    variables = yaml.safe_load(
        (ANSIBLE_ROOT / "group_vars" / "all.yml").read_text(encoding="utf-8")
    )
    prerequisites = (
        ANSIBLE_ROOT / "roles" / "alt_group_policy_prerequisites" / "tasks" / "main.yml"
    ).read_text(encoding="utf-8")
    client = (
        ANSIBLE_ROOT / "roles" / "alt_group_policy_client" / "tasks" / "main.yml"
    ).read_text(encoding="utf-8")

    assert variables["alt_group_policy_prerequisite_packages"] == [
        "gpupdate", "alterator-gpupdate"
    ]
    assert "alt_group_policy_prerequisite_packages" in prerequisites
    assert "gpupdate-setup, enable" in client
    assert "gpupdate, --target, Computer, --system, --force" in client


def test_domain_join_requires_a_valid_samba_trust_before_skipping_join() -> None:
    role_path = ANSIBLE_ROOT / "roles" / "domain_join" / "tasks" / "main.yml"
    rendered = role_path.read_text(encoding="utf-8")

    assert "argv: [net, ads, testjoin]" in rendered
    assert "domain_join_testjoin.rc == 0" in rendered
    assert 'domain_join_already_joined: "{{ domain_join_testjoin.rc == 0 }}"' in rendered


def test_domain_group_vars_use_confirmed_alt_package_and_domain_dns() -> None:
    variables = yaml.safe_load(
        (ANSIBLE_ROOT / "group_vars" / "all.yml").read_text(encoding="utf-8")
    )

    assert variables["domain_prerequisite_packages"] == [
        "task-auth-ad-sssd",
        "openldap-clients",
    ]
    assert variables["ad_dns_servers"] == ["192.168.100.11"]
    assert variables["ad_domain"] == "sosnadmin.local"


def test_domain_verify_accepts_short_name_or_upn() -> None:
    content = (
        ANSIBLE_ROOT / "roles" / "domain_verify" / "tasks" / "main.yml"
    ).read_text(encoding="utf-8")

    assert "domain_test_user if '@' in domain_test_user" in content


def test_domain_login_baseline_enables_sssd_home_creation_and_verify_checks_it() -> None:
    baseline_path = ANSIBLE_ROOT / "roles" / "domain_login_baseline" / "tasks" / "main.yml"
    assert baseline_path.exists()
    baseline = baseline_path.read_text(encoding="utf-8")
    content = (
        ANSIBLE_ROOT / "roles" / "domain_verify" / "tasks" / "main.yml"
    ).read_text(encoding="utf-8")

    assert "/etc/pam.d/system-auth-sss-only" in content
    assert "pam_mkhomedir.so" in content
    assert "skel=/etc/skel umask=0077" in content
    assert "grep" in content
    assert "ansible.builtin.lineinfile" in baseline
    assert "ansible.builtin.lineinfile" not in content


def test_workstation_base_manages_desktop_session_with_x11_default() -> None:
    variables = yaml.safe_load(
        (ANSIBLE_ROOT / "group_vars" / "all.yml").read_text(encoding="utf-8")
    )
    content = (
        ANSIBLE_ROOT / "roles" / "workstation_base" / "tasks" / "main.yml"
    ).read_text(encoding="utf-8")

    assert variables["workstation_desktop_session"] == "x11"
    assert "workstation_desktop_session" in content
    assert "/usr/bin/startplasma-x11" in content
    assert "/usr/bin/startplasma-wayland" in content
    assert "/etc/lightdm/lightdm.conf.d" in content
    assert "90-alt-workstation-session.conf" in content
    assert "90-alt-workstation-x11.conf" in content
    assert "lightdm_session: plasmax11" in content
    assert "user-session={{ workstation_base_desktop_sessions" in content


def test_manual_preflight_accepts_alt_workstation_k_11_x_from_os_release() -> None:
    content = (
        ANSIBLE_ROOT / "roles" / "manual_preflight" / "tasks" / "main.yml"
    ).read_text(encoding="utf-8")

    assert "/etc/os-release" in content
    assert '"$ID"' in content
    assert '"$VARIANT_ID"' in content
    assert "altlinux" in content
    assert "kworkstation" in content
    assert "VERSION_ID" in content
    assert "^11\\." in content
    assert "/etc/altlinux-release" not in content


def test_workstation_identity_requires_explicit_hostname_mode_for_rename() -> None:
    content = (
        ANSIBLE_ROOT / "roles" / "workstation_identity" / "tasks" / "main.yml"
    ).read_text(encoding="utf-8")

    assert "hostname_mode" in content
    assert "change_confirmed" in content
    assert "when: hostname_mode == 'change_confirmed'" in content
    assert "ALT_PREFLIGHT_FAILURE:hostname_mismatch" in content


def test_domain_join_rejects_untrusted_existing_computer_before_join_write() -> None:
    role_path = ANSIBLE_ROOT / "roles" / "domain_join" / "tasks" / "main.yml"
    content = role_path.read_text(encoding="utf-8")

    assert "ldapsearch" in content
    assert "-Y" in content
    assert "GSSAPI" in content
    assert "alt_createcomputer_path" in content
    assert "(sAMAccountName={{ final_hostname }}$)" in content
    assert "ALT_PREFLIGHT_FAILURE:domain_computer_conflict" in content
    assert content.index("kinit") < content.index("ldapsearch")
    assert content.index("ldapsearch") < content.index("- system-auth\n          - write")
    for forbidden in ("Remove-ADComputer", "net ads leave", "adcli delete-computer", "reset-computer"):
        assert forbidden not in content
