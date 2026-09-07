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
        "plasma_baseline",
        "organization_ca",
        "software_endpoint_agent",
        "software_cryptopro",
        "software_cryptopro_cades",
        "software_gosuslugi_plugin",
        "software_onlyoffice",
        "software_nextcloud_desktop",
        "standard_software",
        "desktop_shortcuts",
        {"role": "remote_access_krfb", "when": "remote_access_profile == 'krfb'"},
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
    assert "path: /usr/sbin/gpupdate-setup" in client
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
    assert variables["ad_dns_servers"] == ["192.168.100.1"]
    assert variables["ad_domain"] == "sosnadmin.local"


def test_workstation_network_keeps_active_and_persistent_resolvers_identical() -> None:
    content = (
        ANSIBLE_ROOT / "roles" / "workstation_network" / "tasks" / "main.yml"
    ).read_text(encoding="utf-8")

    assert 'dest: "/etc/net/ifaces/{{ workstation_network_interface }}/resolv.conf"' in content
    assert 'dest: /etc/resolv.conf' in content
    assert content.count("{% for server in ad_dns_servers %}") == 1
    assert content.count('content: "{{ workstation_network_resolver_content }}"') == 2


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


def test_endpoint_agent_role_uses_a_verified_first_installation_claim_flow() -> None:
    variables = yaml.safe_load(
        (ANSIBLE_ROOT / "group_vars" / "all.yml").read_text(encoding="utf-8")
    )
    role_path = ANSIBLE_ROOT / "roles" / "software_endpoint_agent" / "tasks" / "main.yml"

    assert variables["endpoint_enrollment_campaign_id"] is None
    assert variables["software_catalog"]["endpoint_agent"] == {
        "artifact_path": (
            "/opt/alt-deploy-control/artifacts/endpoint-agent/"
            "endpoint-agent-0.1.0-6.x86_64.rpm"
        ),
        "sha256": "c7e3a1476ae831611cfb593f34ac4b7c43ff6c6602a6d7717c2032049cb752ac",
        "package_name": "endpoint-agent",
        "package_evr": "0.1.0-6",
        "architecture": "x86_64",
    }
    assert role_path.is_file()

    content = role_path.read_text(encoding="utf-8")
    assert "endpoint_agent_recovery_required" in content
    assert "endpoint_agent_fingerprint_tools_missing" in content
    assert "getent, hosts, endpoint.sosnadmin.local" in content
    assert "rpm2cpio" in content
    assert "provisioning/install-claims" in content
    assert "vault_endpoint_provisioning_token" in content
    assert "no_log: true" in content
    assert "endpoint-agent-finalize.path" in content
    assert "endpoint_agent_verified: true" in content


def test_cryptopro_and_gosuslugi_use_fixed_verified_controller_artifacts() -> None:
    variables = yaml.safe_load(
        (ANSIBLE_ROOT / "group_vars" / "all.yml").read_text(encoding="utf-8")
    )

    assert {
        key: variables["software_catalog"]["cryptopro"][key]
        for key in ("artifact_path", "sha256", "package_evr")
    } == {
        "artifact_path": "/opt/alt-deploy-control/artifacts/cryptopro/linux-amd64.tgz",
        "sha256": "dcab1fb326397c1993bf52e55732096793037caeec9f374586fc4e6ff0d739d4",
        "package_evr": "5.0.13600-7",
    }
    assert variables["software_catalog"]["cryptopro_cades"] == {
        "artifact_path": (
            "/opt/alt-deploy-control/artifacts/cryptopro-cades/"
            "cades-linux-amd64.tar.gz"
        ),
        "sha256": "9559cff6c818c6031fb7f182493830e9e138bda85616848d0f54620bf523c137",
        "package_evr": "2.0.15700-1",
        "packages": [
            {
                "filename": "cprocsp-pki-cades-64-2.0.15700-1.amd64.rpm",
                "package_name": "cprocsp-pki-cades-64",
                "package_evr": "2.0.15700-1",
                "architecture": "x86_64",
            },
            {
                "filename": "cprocsp-pki-plugin-64-2.0.15700-1.amd64.rpm",
                "package_name": "cprocsp-pki-plugin-64",
                "package_evr": "2.0.15700-1",
                "architecture": "x86_64",
            },
        ],
    }
    assert variables["software_catalog"]["gosuslugi_plugin"] == {
        "artifact_path": (
            "/opt/alt-deploy-control/artifacts/gosuslugi/"
            "Gosplugin_Alt-RedOS_Installer.rpm.zip"
        ),
        "sha256": "2160e85de15830462eeb49a965e5f99bea371fa90379a0956ac3a65ccaa7c085",
        "package_name": "gosuslugi-plugin",
        "package_evr": "1.3.42.0-1",
        "architecture": "x86_64",
        "installer_filename": "Gosplugin_Alt-RedOS_Installer.rpm.sh",
        "payload_filename": "gosuslugi-plugin-1.3.42.0-1.x86_64.rpm",
    }


def test_onlyoffice_and_nextcloud_catalogs_declare_approved_sources() -> None:
    variables = yaml.safe_load(
        (ANSIBLE_ROOT / "group_vars" / "all.yml").read_text(encoding="utf-8")
    )

    assert variables["software_catalog"]["onlyoffice"] == {
        "artifact_path": (
            "/opt/alt-deploy-control/artifacts/onlyoffice/"
            "onlyoffice-desktopeditors-9.4.0-epm1.repacked.130.x86_64.rpm"
        ),
        "sha256": "b8dd26405b5cd79da8a80afc7089007de608a53e7e90ea6a247379bebfe54c9f",
        "package_name": "onlyoffice-desktopeditors",
        "package_evr": "9.4.0-epm1.repacked.130",
        "architecture": "x86_64",
        "executable": "/usr/bin/desktopeditors",
    }
    assert variables["software_catalog"]["nextcloud_desktop"] == {
        "package_name": "nextcloud-client",
        "executable": "/usr/bin/nextcloud",
    }


def test_onlyoffice_and_nextcloud_roles_use_safe_idempotent_installation() -> None:
    onlyoffice = ANSIBLE_ROOT / "roles" / "software_onlyoffice" / "tasks" / "main.yml"
    nextcloud = (
        ANSIBLE_ROOT / "roles" / "software_nextcloud_desktop" / "tasks" / "main.yml"
    )

    assert onlyoffice.is_file()
    assert nextcloud.is_file()

    onlyoffice_text = onlyoffice.read_text(encoding="utf-8")
    nextcloud_text = nextcloud.read_text(encoding="utf-8")
    assert "delegate_to: localhost" in onlyoffice_text
    assert "onlyoffice_artifact_invalid" in onlyoffice_text
    assert "onlyoffice_rpm_metadata_invalid" in onlyoffice_text
    assert "onlyoffice_install_verification_failed" in onlyoffice_text
    assert "follow: true" in onlyoffice_text
    assert "no_log: true" in onlyoffice_text
    assert "state: absent" in onlyoffice_text
    assert "apt-get, -y, install" in onlyoffice_text
    assert "software_nextcloud_desktop_catalog" in nextcloud_text
    assert "apt-get, update" in nextcloud_text
    assert "nextcloud_desktop_install_verification_failed" in nextcloud_text
    assert "/etc/xdg/autostart" not in nextcloud_text
    assert "overrideserverurl" not in nextcloud_text


def test_organization_ca_cryptopro_and_gosuslugi_roles_verify_runtime_without_ifcplugin() -> None:
    ca = ANSIBLE_ROOT / "roles" / "organization_ca" / "tasks" / "main.yml"
    cryptopro = ANSIBLE_ROOT / "roles" / "software_cryptopro" / "tasks" / "main.yml"
    cryptopro_cades = (
        ANSIBLE_ROOT / "roles" / "software_cryptopro_cades" / "tasks" / "main.yml"
    )
    gosuslugi = (
        ANSIBLE_ROOT / "roles" / "software_gosuslugi_plugin" / "tasks" / "main.yml"
    )

    assert ca.is_file()
    assert cryptopro.is_file()
    assert cryptopro_cades.is_file()
    assert gosuslugi.is_file()

    ca_defaults = (
        ANSIBLE_ROOT / "roles" / "organization_ca" / "defaults" / "main.yml"
    ).read_text(encoding="utf-8")
    ca_handlers = (
        ANSIBLE_ROOT / "roles" / "organization_ca" / "handlers" / "main.yml"
    ).read_text(encoding="utf-8")
    assert "organization_ca_anchor_path" in ca.read_text(encoding="utf-8")
    assert (
        'src: "{{ playbook_dir }}/../files/organization_ca/sosnadmin-local-ca.crt"'
        in ca.read_text(encoding="utf-8")
    )
    assert "/etc/pki/ca-trust/source/anchors/sosnadmin-local-ca.crt" in ca_defaults
    assert "/bin/update-ca-trust" in ca_handlers
    cryptopro_text = cryptopro.read_text(encoding="utf-8")
    cryptopro_defaults = (
        ANSIBLE_ROOT / "roles" / "software_cryptopro" / "defaults" / "main.yml"
    ).read_text(encoding="utf-8")
    assert "delegate_to: localhost" in cryptopro_text
    assert "vault_cryptopro_license" in cryptopro_text
    assert "no_log: true" in cryptopro_text
    assert "software_cryptopro_rpm_paths" in cryptopro_text
    assert "Install approved CryptoPro RPMs in one transaction" in cryptopro_text
    assert "Set permissions for temporary CryptoPro directory" in cryptopro_text
    assert "Determine whether CryptoPro installation is required" in cryptopro_text
    assert "when: software_cryptopro_install_required" in cryptopro_text
    assert "Enable PCSC socket activation after CryptoPro installation" in cryptopro_text
    assert "Verify PCSC socket activation" in cryptopro_text
    assert "cryptopro_native_host_missing" not in cryptopro_text
    assert "cryptopro_native_host_ok" not in cryptopro_text
    assert "/opt/cprocsp/bin/amd64/nmcades" not in cryptopro_defaults
    assert "IFCPlugin" not in cryptopro_text
    cades_text = cryptopro_cades.read_text(encoding="utf-8")
    assert "software_cryptopro_cades_catalog" in cades_text
    assert "2.0.15700-1" not in cades_text
    assert "cryptopro_cades_native_host_missing" in cades_text
    gosuslugi_text = gosuslugi.read_text(encoding="utf-8")
    gosuslugi_defaults = (
        ANSIBLE_ROOT / "roles" / "software_gosuslugi_plugin" / "defaults" / "main.yml"
    ).read_text(encoding="utf-8")
    assert "delegate_to: localhost" in gosuslugi_text
    assert "jabjbhgjaidecageckilhonbggakppme" in gosuslugi_text
    assert "Determine whether ГосПлагин installation is required" in gosuslugi_text
    assert "when: software_gosuslugi_plugin_install_required" in gosuslugi_text
    assert "PAYLOAD:" in gosuslugi_text
    assert "rpm --force" not in gosuslugi_text
    assert "/opt/iitrust/gosuslugi_plugin/bin/gosuslugi_plugin" in gosuslugi_defaults


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


def test_domain_verify_publishes_only_safe_cryptopro_gosuslugi_and_ca_results() -> None:
    content = (
        ANSIBLE_ROOT / "roles" / "domain_verify" / "tasks" / "main.yml"
    ).read_text(encoding="utf-8")

    for result_key in (
        "organization_ca_ok",
        "cryptopro_ok",
        "cryptopro_native_host_ok",
        "cryptopro_cades_ok",
        "gosuslugi_plugin_ok",
        "gosuslugi_plugin_native_host_ok",
        "onlyoffice_ok",
        "nextcloud_desktop_ok",
    ):
        assert result_key in content
    assert "vault_cryptopro_license" not in content


def test_domain_verify_publishes_only_nonsecret_endpoint_agent_result() -> None:
    content = (
        ANSIBLE_ROOT / "roles" / "domain_verify" / "tasks" / "main.yml"
    ).read_text(encoding="utf-8")

    assert "endpoint_agent_ok" in content
    assert "endpoint_agent_version" in content
    assert "vault_endpoint_provisioning_token" not in content
    assert "provisioning-claim" not in content


def test_domain_verify_publishes_only_nonsecret_remote_access_result() -> None:
    content = (
        ANSIBLE_ROOT / "roles" / "domain_verify" / "tasks" / "main.yml"
    ).read_text(encoding="utf-8")

    assert "'remote_access': {'profile': remote_access_profile" in content
    assert "krfb_configured | default(false)" in content
    assert "vault_krfb_" not in content


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


def test_plasma_baseline_prepares_only_new_domain_homes_from_etc_skel() -> None:
    role_path = ANSIBLE_ROOT / "roles" / "plasma_baseline" / "tasks" / "main.yml"
    assert role_path.is_file()
    content = role_path.read_text(encoding="utf-8")

    assert "/etc/skel/.config" in content
    assert "/etc/skel/.config/powerdevilrc" in content
    assert "/etc/skel/.config/kxkbrc" in content
    assert "/home/" not in content
    assert "krfb" not in content.lower()


def test_plasma_baseline_templates_capture_the_approved_power_and_layout_defaults() -> None:
    power = (
        ANSIBLE_ROOT / "roles" / "plasma_baseline" / "templates" / "powerdevilrc.j2"
    )
    keyboard = (
        ANSIBLE_ROOT / "roles" / "plasma_baseline" / "templates" / "kxkbrc.j2"
    )

    assert power.is_file()
    assert keyboard.is_file()

    assert "DimDisplayWhenIdle=false" in power.read_text(encoding="utf-8")
    assert "TurnOffDisplayWhenIdle=false" in power.read_text(encoding="utf-8")
    assert "AutoSuspendAction=0" in power.read_text(encoding="utf-8")
    assert "PowerProfile=performance" in power.read_text(encoding="utf-8")
    assert keyboard.read_text(encoding="utf-8").strip() == "[Layout]\nSwitchMode=Global"


def test_desktop_shortcuts_provision_skel_and_existing_domain_test_profile() -> None:
    role_path = ANSIBLE_ROOT / "roles" / "desktop_shortcuts" / "tasks" / "main.yml"
    defaults_path = (
        ANSIBLE_ROOT / "roles" / "desktop_shortcuts" / "defaults" / "main.yml"
    )

    assert role_path.is_file()
    assert defaults_path.is_file()

    content = role_path.read_text(encoding="utf-8")
    defaults = yaml.safe_load(defaults_path.read_text(encoding="utf-8"))
    assert defaults["desktop_shortcuts_skel_dir"] == "/etc/skel/Рабочий стол"
    assert defaults["desktop_shortcuts_application_entries"] == [
        "cptools.desktop",
        "yandex-browser.desktop",
        "onlyoffice-desktopeditors.desktop",
        "nextcloud-client.desktop",
    ]
    assert defaults["desktop_shortcuts_applications_dir"] == "/usr/share/applications"
    assert defaults["desktop_shortcuts_nextcloud_autostart_dir"] == "/etc/skel/.config/autostart"
    assert defaults["desktop_shortcuts_nextcloud_entry"] == "nextcloud-client.desktop"
    assert defaults["desktop_shortcuts_relative_links"] == [
        {"name": "Сетевая папка", "src": "../net.drives/Public"},
        {"name": "Домашняя папка", "src": ".."},
    ]
    assert "domain_test_user" in content
    assert "getent, passwd" in content
    assert "desktop_shortcuts_skel_dir" in content
    assert "desktop_shortcuts_applications_dir" in content
    assert "desktop_shortcuts_relative_links" in content
    assert "desktop_shortcuts_nextcloud_autostart_dir" in content
    assert ".config/autostart" in content
    assert "state: link" in content
    assert "Create missing assigned domain user home" not in content


def test_krfb_role_targets_only_the_explicit_user_without_starting_a_process() -> None:
    content = (
        ANSIBLE_ROOT / "roles" / "remote_access_krfb" / "tasks" / "main.yml"
    )
    assert content.is_file()
    content = content.read_text(encoding="utf-8")

    assert "assigned_domain_user" in content
    assert "argv: [getent, passwd" in content
    assert "failed_when: false" in content
    assert "krfb_config_home" in content
    assert "no_log: true" in content
    assert "Inspect assigned domain user home before KRFB preconfiguration" in content
    assert "when: not krfb_config_home_stat.stat.exists" in content
    for forbidden in ("systemctl --user", "pkill", "killall", "loginctl", "command: krfb"):
        assert forbidden not in content


def test_krfb_template_uses_only_vault_password_values_and_plasma_autostart() -> None:
    config = (
        ANSIBLE_ROOT / "roles" / "remote_access_krfb" / "templates" / "krfbrc.j2"
    )
    autostart = (
        ANSIBLE_ROOT
        / "roles"
        / "remote_access_krfb"
        / "templates"
        / "org.sosn.krfb.desktop.j2"
    )

    assert config.is_file()
    assert autostart.is_file()
    config = config.read_text(encoding="utf-8")
    autostart = autostart.read_text(encoding="utf-8")

    assert "{{ vault_krfb_desktop_password_obscured }}" in config
    assert "{{ vault_krfb_unattended_password_obscured }}" in config
    assert "allowDesktopControl=true" in config
    assert "allowUnattendedAccess=true" in config
    assert "noWallet=true" in config
    assert "Exec=/usr/bin/krfb" in autostart
    assert "OnlyShowIn=KDE;" in autostart


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


def test_workstation_identity_accepts_approved_short_name_or_domain_fqdn() -> None:
    content = (
        ANSIBLE_ROOT / "roles" / "workstation_identity" / "tasks" / "main.yml"
    ).read_text(encoding="utf-8")

    assert "workstation_identity_accepted_static_hostnames" in content
    assert '"{{ final_hostname | lower }}.{{ ad_domain | lower }}"' in content
    assert "in workstation_identity_accepted_static_hostnames" in content


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
