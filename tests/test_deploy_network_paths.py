from pathlib import Path


def test_installer_only_installs_role_only_path_sample_when_absent():
    installer = Path("deploy/install-openvpn-web.sh").read_text(encoding="utf-8")
    sample = Path("deploy/network-paths.json.sample").read_text(encoding="utf-8")
    assert "network-paths.json.sample" in installer
    assert "192.168." not in sample


def test_installer_does_not_enable_network_collection_timer():
    installer = Path("deploy/install-openvpn-web.sh").read_text(encoding="utf-8")
    assert "enable --now netctl-collect.timer" not in installer


def test_installer_does_not_create_or_enable_routeros_sources():
    installer = Path("deploy/install-openvpn-web.sh").read_text(encoding="utf-8")
    assert "192.168." not in installer
    assert "mikrotik-main.yaml" not in installer
    assert "mikrotik-hex.yaml" not in installer
    assert "enabled: true" not in installer


def test_default_deployment_verification_does_not_require_collection_timer():
    deployment = Path("docs/DEPLOYMENT.md").read_text(encoding="utf-8")
    default_verification = deployment.split("After deployment:", 1)[1].split("```", 2)[1]
    assert "systemctl is-active netctl-collect.timer" not in default_verification
    assert "separately approved timer activation" in deployment


def test_deployment_docs_require_operator_to_provision_routeros_source():
    deployment = Path("docs/DEPLOYMENT.md").read_text(encoding="utf-8")
    assert "The installer creates `/etc/netctl/sources.d/mikrotik-hex.yaml`" not in deployment
    assert "approved operator must provision `/etc/netctl/sources.d/mikrotik-hex.yaml`" in deployment
