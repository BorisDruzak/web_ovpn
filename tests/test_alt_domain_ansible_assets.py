from __future__ import annotations

from pathlib import Path

import pytest
import yaml
from jinja2 import StrictUndefined
from jinja2.nativetypes import NativeEnvironment


ANSIBLE_ROOT = (
    Path(__file__).resolve().parents[1] / "deploy" / "alt-linux" / "ansible"
)
ROLES = ANSIBLE_ROOT / "roles"
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
    "standard_software",
    "remote_access_krfb",
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


def test_critical_phase_runs_components_between_login_baseline_and_verification() -> None:
    phase_path = ANSIBLE_ROOT / "playbooks" / "tasks" / "configure_critical_phase.yml"
    rendered = phase_path.read_text(encoding="utf-8")

    expected_includes = [
        f"name: {role}" for role in CRITICAL_ROLES
    ]
    positions = [rendered.index(include) for include in expected_includes]

    assert positions == sorted(positions)
    assert rendered.count("ansible.builtin.include_role:") == len(CRITICAL_ROLES)
    assert "loop:" not in rendered


def test_standard_software_uses_a_fixed_role_map() -> None:
    text = (ANSIBLE_ROOT / "roles/standard_software/tasks/main.yml").read_text()
    tasks = yaml.safe_load(text)
    include = next(task for task in tasks if "ansible.builtin.include_role" in task)
    assert include["vars"]["software_component_role_map"] == {
        "browser": "software_browser",
        "onlyoffice": "software_onlyoffice",
        "nextcloud_desktop": "software_nextcloud_desktop",
    }
    assert include["ansible.builtin.include_role"]["name"] == (
        "{{ software_component_role_map[software_component] }}"
    )
    assert include["loop"] == "{{ selected_software_components }}"
    assert "{{ item }}" not in text
    assert "standard_packages" not in text
    assert "organization_packages" not in text


@pytest.mark.parametrize("component", ["browser", "onlyoffice"])
def test_component_rpm_roles_recheck_private_payload_and_always_remove_it(component: str) -> None:
    path = ANSIBLE_ROOT / f"roles/software_{component}/tasks/main.yml"
    assert path.exists(), "selected RPM component role must exist"
    tasks = yaml.safe_load(path.read_text())
    protected = next(task for task in tasks if "always" in task)
    assert protected["no_log"] is True
    block = protected["block"]
    checks = [task for task in block if "ansible.builtin.stat" in task]
    assert len([task for task in checks if task["ansible.builtin.stat"].get("checksum_algorithm") == "sha256"]) == 2
    controller_check = next(task for task in checks if task.get("delegate_to") == "localhost")
    assert controller_check["become"] is False
    copy = next(task for task in block if "ansible.builtin.copy" in task)
    assert copy["ansible.builtin.copy"]["mode"] == "0600"
    argv = [task["ansible.builtin.command"]["argv"] for task in block if "ansible.builtin.command" in task]
    install = next(command for command in argv if command[:3] == ["apt-get", "-y", "install"])
    assert install[3:] == [f"{{{{ software_{component}_temporary.path }}}}"]
    assert len([command for command in argv if command[:2] == ["rpm", "-qp"]]) == 2
    assert any(command[:2] == ["rpm", "-q"] and "%{EPOCH}" in command[3] for command in argv)
    cleanup = protected["always"][0]
    assert cleanup["ansible.builtin.file"] == {
        "path": f"{{{{ software_{component}_temporary.path }}}}", "state": "absent"
    }
    assert cleanup["when"] == f"software_{component}_temporary.path is defined"
    assert "rescue" not in protected
    assert tasks[-1]["ansible.builtin.set_fact"][f"software_{component}_verified"] is True
    assert "/policies/managed/" not in path.read_text()


@pytest.mark.parametrize("component", ["browser", "onlyoffice"])
@pytest.mark.parametrize("field,value,allowed", [
    ("epoch", "(none)", True), ("epoch", "0", True), ("epoch", "1", False),
    ("package_name", "other-package", False), ("package_evr", "0.0-1", False),
    ("architecture", "aarch64", False),
])
def test_rpm_metadata_gate_rejects_an_unapproved_package_identity(component, field, value, allowed):
    catalog = yaml.safe_load((ANSIBLE_ROOT / "group_vars/software_catalog.yml").read_text())["software_catalog"]
    actual = catalog[component] | {"epoch": "(none)", field: value}
    metadata = "|".join(actual[key] for key in ["package_name", "package_evr", "architecture", "epoch"])
    tasks = yaml.safe_load((ANSIBLE_ROOT / f"roles/software_{component}/tasks/main.yml").read_text())
    assertion = next(task for task in tasks[1]["block"] if task["name"] == f"Require the exact controller {component} RPM identity")
    environment = NativeEnvironment(undefined=StrictUndefined)
    assert environment.compile_expression(assertion["ansible.builtin.assert"]["that"][0])(**{
        "software_catalog": catalog, f"software_{component}_controller_metadata": {"stdout": metadata}
    }) is allowed


@pytest.mark.parametrize("component", ["browser", "onlyoffice"])
@pytest.mark.parametrize("field,value,allowed", [
    ("mode", "0600", True), ("mode", "0644", False),
    ("checksum", "wrong-digest", False), ("isreg", False, False),
])
def test_rpm_transfer_gate_rejects_changed_or_public_payload(component, field, value, allowed):
    catalog = yaml.safe_load((ANSIBLE_ROOT / "group_vars/software_catalog.yml").read_text())["software_catalog"]
    stat = {"exists": True, "isreg": True, "mode": "0600", "checksum": catalog[component]["sha256"]} | {field: value}
    tasks = yaml.safe_load((ANSIBLE_ROOT / f"roles/software_{component}/tasks/main.yml").read_text())
    assertion = next(task for task in tasks[1]["block"] if task["name"] == f"Require the exact transferred {component} RPM bytes")
    environment = NativeEnvironment(undefined=StrictUndefined)
    context = {"software_catalog": catalog, f"software_{component}_target_artifact": {"stat": stat}}
    assert all(environment.compile_expression(expression)(**context)
               for expression in assertion["ansible.builtin.assert"]["that"]) is allowed


def test_nextcloud_installs_and_queries_only_the_approved_repository_packages() -> None:
    path = ANSIBLE_ROOT / "roles/software_nextcloud_desktop/tasks/main.yml"
    assert path.exists(), "selected repository component role must exist"
    tasks = yaml.safe_load(path.read_text())
    commands = [task["ansible.builtin.command"]["argv"] for task in tasks if "ansible.builtin.command" in task]
    assert ["apt-get", "-y", "install", "nextcloud-client", "nextcloud-client-kde"] in commands
    query = next(task for task in tasks if task.get("ansible.builtin.command", {}).get("argv", [])[:2] == ["rpm", "-q"])
    assert query["loop"] == ["nextcloud-client", "nextcloud-client-kde"]
    assert tasks[-1]["ansible.builtin.set_fact"]["software_nextcloud_desktop_verified"] is True


@pytest.mark.parametrize("component", ["browser", "onlyoffice", "nextcloud_desktop"])
def test_component_result_is_pessimistic_until_role_verification(component: str) -> None:
    path = ANSIBLE_ROOT / f"roles/software_{component}/tasks/main.yml"
    assert path.exists(), "component role must record safe failure and verified success"
    tasks = yaml.safe_load(path.read_text())
    initial = tasks[0]["ansible.builtin.set_fact"]
    assert initial[f"software_{component}_verified"] is False
    assert "'status': 'failed'" in initial["configure_result"]
    assert "'verified': false" in initial["configure_result"]
    success = tasks[-1]["ansible.builtin.set_fact"]
    assert "'status': 'ok'" in success["configure_result"]
    assert "'verified': true" in success["configure_result"]
    assert "configure_result.components | combine" in success["configure_result"]
    assert "ansible_failed_result" not in path.read_text()


def test_finalizer_preserves_component_records_and_verification() -> None:
    tasks = yaml.safe_load((ANSIBLE_ROOT / "playbooks/tasks/configure_critical_phase.yml").read_text())
    critical = tasks[1]
    success = next(task for task in critical["block"] if task["name"] == "Finalize successful configure result")
    text = success["ansible.builtin.set_fact"]["configure_result"]
    assert "configure_result.components | combine" in text
    assert "configure_result.verification | combine" in text
    assert "'error': none" in text
    failed = critical["rescue"][0]["ansible.builtin.set_fact"]["configure_result"]
    assert "'components':" not in failed
    assert "configure_result.verification | combine" in failed


def test_software_phase_is_restored_before_domain_verification() -> None:
    tasks = yaml.safe_load((ANSIBLE_ROOT / "roles/standard_software/tasks/main.yml").read_text())
    assert tasks[1]["ansible.builtin.set_fact"]["configure_result"] == (
        "{{ configure_result | combine({'phase': 'components'}) }}"
    )
    assert tasks[-1].get("ansible.builtin.set_fact", {}).get("configure_result") == (
        "{{ configure_result | combine({'phase': 'domain_core_verify'}) }}"
    )
    assert tasks[-1]["when"] == "selected_software_components | length > 0"


def test_krfb_role_targets_one_explicit_user_and_never_starts_a_process() -> None:
    text = (ROLES / "remote_access_krfb/tasks/main.yml").read_text()

    assert "assigned_domain_user" in text and "getent" in text
    assert "no_log: true" in text
    assert "systemctl --user" not in text and "loginctl" not in text
    assert all(
        forbidden not in text
        for forbidden in ("pkill", "killall", "firewalld", "iptables", "nftables")
    )


def test_krfb_template_has_vault_placeholders_not_password_literals() -> None:
    text = (ROLES / "remote_access_krfb/templates/krfbrc.j2").read_text()

    assert "{{ vault_krfb_desktop_password_obscured }}" in text
    assert "{{ vault_krfb_unattended_password_obscured }}" in text


def test_krfb_role_requires_exact_user_home_and_network_confirmation() -> None:
    tasks = yaml.safe_load((ROLES / "remote_access_krfb/tasks/main.yml").read_text())
    rendered = (ROLES / "remote_access_krfb/tasks/main.yml").read_text()

    network_gate = next(
        task for task in tasks if task["name"] == "Require confirmed restricted KRFB access"
    )
    network_checks = network_gate["ansible.builtin.assert"]["that"]
    assert any("alt_deploy_krfb_tcp_5900_restricted_confirmed is boolean" in check for check in network_checks)
    assert any("alt_deploy_krfb_tcp_5900_restricted_confirmed" == check for check in network_checks)

    lookup = next(task for task in tasks if task["name"] == "Resolve the assigned domain user")
    assert lookup["ansible.builtin.command"]["argv"] == [
        "getent",
        "-s",
        "sss",
        "passwd",
        "{{ krfb_assigned_upn }}",
    ]
    assert lookup["changed_when"] is False
    assert lookup["failed_when"] is False

    home_check = next(task for task in tasks if task["name"] == "Inspect the assigned user home")
    assert home_check["ansible.builtin.stat"]["follow"] is False
    home_gate = next(task for task in tasks if task["name"] == "Require the existing assigned user home")
    home_checks = home_gate["ansible.builtin.assert"]["that"]
    assert any("isdir" in check for check in home_checks)
    assert any(".stat.uid" in check for check in home_checks)
    assert any(".stat.gid" in check for check in home_checks)
    assert "state: directory\n    path: \"{{ krfb_config_home }}\"" not in rendered

    existing_path_check = next(
        task for task in tasks if task["name"] == "Inspect existing assigned-user KRFB paths"
    )
    assert existing_path_check["ansible.builtin.stat"]["follow"] is False
    unsafe_path_gate = next(
        task for task in tasks if task["name"] == "Reject unsafe existing assigned-user KRFB paths"
    )
    unsafe_path_checks = unsafe_path_gate["ansible.builtin.assert"]["that"]
    assert any("isdir" in check for check in unsafe_path_checks)
    assert any("islnk" in check for check in unsafe_path_checks)
    assert any(".stat.uid" in check for check in unsafe_path_checks)
    assert any(".stat.gid" in check for check in unsafe_path_checks)

    unsafe_gate_index = tasks.index(unsafe_path_gate)
    root_mutation_index = min(
        index
        for index, task in enumerate(tasks)
        if "ansible.builtin.package" in task
        or "ansible.builtin.file" in task
        or "ansible.builtin.template" in task
    )
    assert unsafe_gate_index < root_mutation_index

    directory_create = next(
        task for task in tasks if task["name"] == "Create absent assigned-user KRFB directories"
    )
    assert directory_create["ansible.builtin.file"]["follow"] is False
    assert directory_create["when"] == "not krfb_existing_path.stat.exists"
    assert unsafe_gate_index < tasks.index(directory_create)


def test_krfb_role_uses_fixed_package_and_protected_outputs() -> None:
    tasks = yaml.safe_load((ROLES / "remote_access_krfb/tasks/main.yml").read_text())

    package = next(task for task in tasks if task["name"] == "Install the fixed KRFB package")
    assert package["ansible.builtin.package"] == {"name": "krfb", "state": "present"}

    templates = [task for task in tasks if "ansible.builtin.template" in task]
    assert {
        task["ansible.builtin.template"]["dest"]: (
            task["ansible.builtin.template"]["mode"], task.get("no_log")
        )
        for task in templates
    } == {
        "{{ krfb_config_home }}/.config/krfbrc": ("0600", True),
        "{{ krfb_config_home }}/.config/autostart/org.sosn.krfb.desktop": ("0644", True),
    }

    success = tasks[-1]["ansible.builtin.set_fact"]
    assert success["krfb_configured"] is True
    assert "configure_result.components | combine" in success["configure_result"]
    assert "configure_result.verification | combine" in success["configure_result"]
    assert "krfb_configured" in success["configure_result"]


def test_krfb_runs_after_selected_software_and_only_when_requested() -> None:
    tasks = yaml.safe_load(
        (ANSIBLE_ROOT / "playbooks/tasks/configure_critical_phase.yml").read_text()
    )
    block = tasks[1]["block"]
    software_index = next(
        index for index, task in enumerate(block) if task["name"] == "Run selected standard software"
    )
    krfb_index = next(
        index for index, task in enumerate(block) if task["name"] == "Run requested KRFB profile"
    )
    verify_index = next(
        index for index, task in enumerate(block) if task["name"] == "Run domain verification"
    )

    assert software_index < krfb_index < verify_index
    assert block[krfb_index]["ansible.builtin.include_role"] == {"name": "remote_access_krfb"}
    assert block[krfb_index]["when"] == "remote_access_profile == 'krfb'"


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
