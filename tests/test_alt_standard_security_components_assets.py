from __future__ import annotations

from pathlib import Path

import yaml


ANSIBLE_ROOT = Path(__file__).resolve().parents[1] / "deploy" / "alt-linux" / "ansible"


def test_standard_domain_requires_security_components_after_domain_join() -> None:
    playbook = yaml.safe_load(
        (ANSIBLE_ROOT / "playbooks" / "03-configure-domain-workstation.yml").read_text(
            encoding="utf-8"
        )
    )
    components = playbook[0]["vars"]["configure_components"]

    assert [component["name"] for component in components] == [
        "plasma_baseline",
        "standard_software",
        "browser",
        "onlyoffice",
        "nextcloud_desktop",
        "organization_ca",
        "cryptopro",
        "cryptopro_cades",
        "gosuslugi_plugin",
        "endpoint_agent",
        "desktop_shortcuts",
    ]
    assert all(component["required"] is True for component in components)


def test_security_roles_use_reviewed_artifacts_and_safe_endpoint_contract() -> None:
    variables = yaml.safe_load(
        (ANSIBLE_ROOT / "group_vars" / "all.yml").read_text(encoding="utf-8")
    )
    endpoint = (
        ANSIBLE_ROOT / "roles" / "endpoint_agent_alt" / "tasks" / "main.yml"
    ).read_text(encoding="utf-8")

    assert variables["software_catalog"]["gosuslugi_plugin"]["package_evr"] == "1.3.19.0-1"
    assert variables["endpoint_agent_rpm_sha256"] == (
        "44ef9157f6f88049b715e957d4c0cc8e1b5f5e1ae109e9a0442045de91580d05"
    )
    assert "/usr/lib/endpoint-agent/endpoint-agent-fingerprint" in endpoint
    assert "https://endpoint.sosnadmin.local" in endpoint
    assert "validate_certs: true" in endpoint
    assert "endpoint-enrollment-claim" in endpoint
    assert "Revoke per-host rollout campaign" in endpoint
    assert "Inspect one-time Endpoint claim" in endpoint
    assert "Create protected Endpoint credential directory" in endpoint
    assert "Restart Endpoint Agent without one-time claim" in endpoint
    assert "no_log: true" in endpoint

    gosuslugi = (
        ANSIBLE_ROOT / "roles" / "software_gosuslugi_plugin" / "tasks" / "main.yml"
    ).read_text(encoding="utf-8")
    assert "Copy approved ГосПлагин RPM to workstation" in gosuslugi
    assert "argv: [apt-get, -y, install, /var/tmp/gosuslugi-plugin.rpm]" in gosuslugi


def test_user_profile_includes_cryptopro_home_and_public_launchers() -> None:
    shortcuts = (
        ANSIBLE_ROOT / "roles" / "desktop_shortcuts_user" / "tasks" / "main.yml"
    ).read_text(encoding="utf-8")
    templates = ANSIBLE_ROOT / "roles" / "desktop_shortcuts" / "templates"

    assert "desktop_shortcuts_custom_entries" in shortcuts
    variables = yaml.safe_load(
        (ANSIBLE_ROOT / "group_vars" / "all.yml").read_text(encoding="utf-8")
    )
    assert variables["desktop_shortcuts_skel_dir"] == "/etc/skel/Рабочий стол"
    assert (templates / "sosn-cryptopro.desktop.j2").is_file()
    assert (templates / "sosn-home.desktop.j2").is_file()
    assert (templates / "sosn-public.desktop.j2").is_file()


def test_managed_desktop_launchers_have_executable_commands_and_icons() -> None:
    templates = ANSIBLE_ROOT / "roles" / "desktop_shortcuts" / "templates"
    cryptopro = (templates / "sosn-cryptopro.desktop.j2").read_text(encoding="utf-8")
    home = (templates / "sosn-home.desktop.j2").read_text(encoding="utf-8")
    public = (templates / "sosn-public.desktop.j2").read_text(encoding="utf-8")

    assert "Icon=/opt/cprocsp/share/icons/cptools.png" in cryptopro
    assert "Exec=dolphin --new-window" in home
    assert "Icon=folder-home" in home
    assert "Exec=dolphin --new-window smb://antares/Public" in public
    assert "Icon=folder-network" in public
    assert "sh -c" not in home


def test_identity_accepts_domain_fqdn_after_hostname_verification() -> None:
    identity = (
        ANSIBLE_ROOT / "roles" / "workstation_identity" / "tasks" / "main.yml"
    ).read_text(encoding="utf-8")

    assert "workstation_identity_after.stdout | trim | lower" in identity
    assert "in workstation_identity_accepted_static_hostnames" in identity
