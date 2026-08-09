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
        "prejoin_upgrade",
        "workstation_base",
        "alt_group_policy_prerequisites",
        "workstation_network",
        "domain_join",
        "alt_group_policy_client",
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


def test_domain_join_converts_ad_dn_to_alt_parent_first_ou_path() -> None:
    role_path = ANSIBLE_ROOT / "roles" / "domain_join" / "tasks" / "main.yml"
    rendered = role_path.read_text(encoding="utf-8")

    assert "alt_createcomputer_path" in rendered
    assert "regex_findall('OU=([^,]+)') | reverse | join('/')" in rendered
    assert '"--createcomputer={{ alt_createcomputer_path }}"' in rendered
    assert '"--gpo"' in rendered


def test_prejoin_upgrade_runs_only_before_domain_join_and_reboots() -> None:
    content = (
        ANSIBLE_ROOT / "roles" / "prejoin_upgrade" / "tasks" / "main.yml"
    ).read_text(encoding="utf-8")

    assert "system-auth, status" in content
    assert "argv: [net, ads, testjoin]" in content
    assert "prejoin_upgrade_testjoin.rc == 0" in content
    assert "apt-get, update" in content
    assert "apt-get, -y, dist-upgrade" in content
    assert "ansible.builtin.reboot" in content
    assert content.count("not prejoin_upgrade_already_joined") == 3
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
        "gpupdate",
        "alterator-gpupdate",
    ]
    assert "alt_group_policy_prerequisite_packages" in prerequisites
    assert "Check ALT Group Policy setup command" in client
    assert "path: /usr/bin/gpupdate-setup" in client
    assert client.index("Check ALT Group Policy setup command") < client.index(
        "Enable the ALT Group Policy workstation profile after domain join"
    )
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


def test_browser_catalog_declares_the_approved_vendor_rpm() -> None:
    variables = yaml.safe_load(
        (ANSIBLE_ROOT / "group_vars" / "all.yml").read_text(encoding="utf-8")
    )

    assert variables["approved_software_components"] == ["browser"]
    assert variables["software_catalog"]["browser"] == {
        "artifact_path": (
            "/opt/alt-deploy-control/artifacts/yandex-browser/Yandex.rpm"
        ),
        "sha256": (
            "7fbce78e9799ae36ebfcf750d5880f27d829d5546e9ac77f1868afb9657d9a89"
        ),
        "package_name": "yandex-browser-stable",
        "package_evr": "26.4.4.968-1",
        "architecture": "x86_64",
    }


def test_standard_software_dispatches_only_the_approved_browser_role() -> None:
    content = (
        ANSIBLE_ROOT / "roles" / "standard_software" / "tasks" / "main.yml"
    ).read_text(encoding="utf-8")

    assert "browser: software_browser" in content
    assert "approved_software_components" in content
    assert "ALT_PREFLIGHT_FAILURE:software_component_unsupported" in content
    assert "ansible.builtin.include_role" in content


def test_browser_role_validates_then_installs_and_cleans_up_without_policy_files() -> None:
    content = (
        ANSIBLE_ROOT / "roles" / "software_browser" / "tasks" / "main.yml"
    ).read_text(encoding="utf-8")

    assert "delegate_to: localhost" in content
    assert "get_checksum: true" in content
    assert "software_browser_catalog.sha256" in content
    assert content.index("Validate approved Yandex Browser artifact") < content.index(
        "Install approved Yandex Browser RPM"
    )
    assert "apt-get, -y, install" in content
    assert "rpm, -q" in content
    assert "state: absent" in content
    assert "software_browser_verified: true" in content
    assert "/etc/opt/yandex/browser/policies" not in content


def test_domain_verify_publishes_only_a_boolean_browser_result() -> None:
    content = (
        ANSIBLE_ROOT / "roles" / "domain_verify" / "tasks" / "main.yml"
    ).read_text(encoding="utf-8")

    assert "'browser': software_browser_verified | default(false)" in content
    assert "Yandex.rpm" not in content
    assert "/opt/alt-deploy-control/artifacts" not in content


def test_domain_verify_accepts_short_name_or_upn() -> None:
    content = (
        ANSIBLE_ROOT / "roles" / "domain_verify" / "tasks" / "main.yml"
    ).read_text(encoding="utf-8")

    assert "domain_test_user if '@' in domain_test_user" in content


def test_domain_verify_enables_and_checks_sssd_home_creation() -> None:
    content = (
        ANSIBLE_ROOT / "roles" / "domain_verify" / "tasks" / "main.yml"
    ).read_text(encoding="utf-8")

    assert "/etc/pam.d/system-auth-sss-only" in content
    assert "pam_mkhomedir.so" in content
    assert "skel=/etc/skel umask=0077" in content
    assert "grep" in content


def test_workstation_base_manages_desktop_session_with_wayland_default() -> None:
    variables = yaml.safe_load(
        (ANSIBLE_ROOT / "group_vars" / "all.yml").read_text(encoding="utf-8")
    )
    content = (
        ANSIBLE_ROOT / "roles" / "workstation_base" / "tasks" / "main.yml"
    ).read_text(encoding="utf-8")

    assert variables["workstation_desktop_session"] == "wayland"
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
    assert "{{ computer_ou }}" in content
    assert "(sAMAccountName={{ final_hostname }}$)" in content
    assert "ALT_PREFLIGHT_FAILURE:domain_computer_conflict" in content
    assert content.index("kinit") < content.index("ldapsearch")
    assert content.index("ldapsearch") < content.index("- system-auth\n          - write")
    for forbidden in ("Remove-ADComputer", "net ads leave", "adcli delete-computer", "reset-computer"):
        assert forbidden not in content
