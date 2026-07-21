from pathlib import Path


def test_installer_only_installs_role_only_path_sample_when_absent():
    installer = Path("deploy/install-openvpn-web.sh").read_text(encoding="utf-8")
    sample = Path("deploy/network-paths.json.sample").read_text(encoding="utf-8")
    assert "network-paths.json.sample" in installer
    assert "192.168." not in sample


def test_installer_does_not_enable_network_collection_timer():
    installer = Path("deploy/install-openvpn-web.sh").read_text(encoding="utf-8")
    assert "enable --now netctl-collect.timer" not in installer
