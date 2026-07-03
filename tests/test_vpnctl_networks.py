import json
import os
import stat
import subprocess
import sys
from pathlib import Path


VPNCTL = Path(__file__).resolve().parents[1] / "deploy" / "vpnctl"


def run_vpnctl(tmp_path: Path, *args: str) -> dict:
    out_dir = tmp_path / "out"
    ccd_dir = tmp_path / "ccd"
    pki_dir = tmp_path / "pki"
    easy_rsa = tmp_path / "easy-rsa"
    for path in [out_dir, ccd_dir, pki_dir / "issued", pki_dir / "private", pki_dir / "reqs", easy_rsa]:
        path.mkdir(parents=True, exist_ok=True)
    vipnet = tmp_path / "vipnet-nets.conf"
    if not vipnet.exists():
        vipnet.write_text("10.83.1.0/24\n", encoding="utf-8")
    env = {
        **os.environ,
        "OUT_DIR": str(out_dir),
        "CCD_DIR": str(ccd_dir),
        "PKI_DIR": str(pki_dir),
        "EASYRSA_DIR": str(easy_rsa),
        "OPENVPN_DIR": str(tmp_path / "openvpn"),
        "SHARE_OUT_DIR": str(tmp_path / "share"),
        "ARCHIVE_DIR": str(tmp_path / "archive"),
        "REGISTRY_DB": str(tmp_path / "registry.sqlite"),
        "NETWORKS_DB": str(tmp_path / "networks.json"),
        "NETWORK_TEMPLATES_DB": str(tmp_path / "network-templates.json"),
        "OPERATION_LOG": str(tmp_path / "vpnctl.log"),
        "LOCK_FILE": str(tmp_path / "vpnctl.lock"),
        "VIPNET_NETS_FILE": str(vipnet),
        "STATUS_LOG": str(tmp_path / "status.log"),
    }
    proc = subprocess.run(
        [sys.executable, str(VPNCTL), "--json", *args],
        env=env,
        text=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        check=True,
    )
    return json.loads(proc.stdout)


def test_networks_import_legacy_vipnet_file_with_tags_and_nat(tmp_path):
    data = run_vpnctl(tmp_path, "networks", "list")

    rows = {row["cidr"]: row for row in data["networks"]}
    assert rows["10.83.1.0/24"]["tag"] == "vipnet"
    assert rows["10.83.1.0/24"]["nat"] is True
    assert rows["192.168.100.10/32"]["tag"] == "directum"
    assert rows["192.168.100.10/32"]["nat"] is False


def test_network_add_updates_nat_file_only_for_nat_networks(tmp_path):
    data = run_vpnctl(tmp_path, "networks", "add", "10.44.0.0/24", "--tag", "branch", "--no-nat")
    assert data["network"]["nat"] is False
    assert "10.44.0.0/24" not in (tmp_path / "vipnet-nets.conf").read_text(encoding="utf-8")

    data = run_vpnctl(tmp_path, "networks", "update", "10.44.0.0/24", "--tag", "branch", "--nat")
    assert data["network"]["nat"] is True
    assert "10.44.0.0/24" in (tmp_path / "vipnet-nets.conf").read_text(encoding="utf-8")


def test_network_templates_include_existing_profiles_and_custom_templates(tmp_path):
    data = run_vpnctl(tmp_path, "network-templates", "list")
    names = {row["name"] for row in data["templates"]}
    assert "directum17" in names
    assert "vipnet" in names

    created = run_vpnctl(
        tmp_path,
        "network-templates",
        "add",
        "branch_directum",
        "--description",
        "Branch + Directum",
        "--cidr",
        "192.168.100.10/32",
        "--cidr",
        "10.83.1.0/24",
        "--dns",
    )
    assert created["template"]["name"] == "branch_directum"
    assert created["template"]["dns"] is True

    listed = run_vpnctl(tmp_path, "network-templates", "list")
    assert "branch_directum" in {row["name"] for row in listed["templates"]}


def test_client_template_apply_writes_ccd_from_selected_networks(tmp_path):
    run_vpnctl(
        tmp_path,
        "network-templates",
        "add",
        "branch_directum",
        "--cidr",
        "192.168.100.10/32",
        "--cidr",
        "10.83.1.0/24",
        "--dns",
    )

    data = run_vpnctl(
        tmp_path,
        "client-template-apply",
        "alpha",
        "branch_directum",
        "10.8.0.44",
        "--reason",
        "access change",
    )

    text = (tmp_path / "ccd" / "alpha").read_text(encoding="utf-8")
    assert data["status"] == "ok"
    assert data["template"] == "branch_directum"
    assert "ifconfig-push 10.8.0.44 255.255.255.0" in text
    assert 'push "route 192.168.100.10 255.255.255.255"' in text
    assert 'push "route 10.83.1.0 255.255.255.0"' in text
    assert 'push "dhcp-option DNS 192.168.100.1"' in text


def test_client_networks_apply_writes_ccd_without_manual_content(tmp_path):
    data = run_vpnctl(
        tmp_path,
        "client-networks-apply",
        "alpha",
        "--cidr",
        "192.168.100.10/32",
        "--cidr",
        "10.83.1.0/24",
        "--reason",
        "selected networks",
    )

    text = (tmp_path / "ccd" / "alpha").read_text(encoding="utf-8")
    assert data["status"] == "ok"
    assert data["networks"] == ["192.168.100.10/32", "10.83.1.0/24"]
    assert "10.83.1.0" in text
    if os.name != "nt":
        assert stat.S_IMODE((tmp_path / "ccd" / "alpha").stat().st_mode) == 0o644


def test_reconnect_client_reports_not_configured_without_management(tmp_path):
    data = run_vpnctl(tmp_path, "reconnect-client", "alpha", "--reason", "route refresh")

    assert data["status"] == "not_configured"
    assert data["client"] == "alpha"
