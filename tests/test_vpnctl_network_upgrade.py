import json
import os
import subprocess
import sys
from pathlib import Path


VPNCTL = Path(__file__).resolve().parents[1] / "deploy" / "vpnctl"


def run_vpnctl(tmp_path: Path, *args: str, check: bool = True) -> dict:
    out_dir = tmp_path / "out"
    ccd_dir = tmp_path / "ccd"
    pki_dir = tmp_path / "pki"
    easy_rsa = tmp_path / "easy-rsa"
    openvpn_dir = tmp_path / "openvpn"
    for path in [out_dir, ccd_dir, pki_dir / "issued", pki_dir / "private", pki_dir / "reqs", easy_rsa, openvpn_dir]:
        path.mkdir(parents=True, exist_ok=True)
    vipnet = tmp_path / "vipnet-nets.conf"
    if not vipnet.exists():
        vipnet.write_text("172.153.159.0/24\n", encoding="utf-8")
    server_conf = tmp_path / "server.conf"
    if not server_conf.exists():
        server_conf.write_text(
            "server 192.168.50.0 255.255.255.0\n"
            "status /var/log/openvpn/status.log 10\n"
            "status-version 2\n",
            encoding="utf-8",
        )
    env = {
        **os.environ,
        "OUT_DIR": str(out_dir),
        "CCD_DIR": str(ccd_dir),
        "PKI_DIR": str(pki_dir),
        "EASYRSA_DIR": str(easy_rsa),
        "OPENVPN_DIR": str(openvpn_dir),
        "SHARE_OUT_DIR": str(tmp_path / "share"),
        "ARCHIVE_DIR": str(tmp_path / "archive"),
        "REGISTRY_DB": str(tmp_path / "registry.sqlite"),
        "NETWORKS_DB": str(tmp_path / "networks.json"),
        "NETWORK_TEMPLATES_DB": str(tmp_path / "network-templates.json"),
        "OPERATION_LOG": str(tmp_path / "vpnctl.log"),
        "LOCK_FILE": str(tmp_path / "vpnctl.lock"),
        "VIPNET_NETS_FILE": str(vipnet),
        "STATUS_LOG": str(tmp_path / "status.log"),
        "SERVER_CONF": str(server_conf),
        "OPENVPN_TUNNEL_CIDR": "192.168.50.0/24",
        "OPENVPN_SERVER_TUNNEL_IP": "192.168.50.1",
        "OPENVPN_USER_POOL_START": "192.168.50.2",
        "OPENVPN_USER_POOL_END": "192.168.50.199",
        "OPENVPN_ROUTER_POOL_START": "192.168.50.200",
        "OPENVPN_ROUTER_POOL_END": "192.168.50.249",
        "REMOTE_SITE_CIDRS": "192.168.51.0/24,192.168.52.0/24",
        "CENTRAL_LAN_CIDRS": "192.168.100.0/23,10.10.10.0/23,10.83.1.0/24",
        "VIPNET_TARGET_CIDRS": "172.153.153.0/24,172.153.155.0/24,172.153.159.0/24",
    }
    proc = subprocess.run(
        [sys.executable, str(VPNCTL), "--json", *args],
        env=env,
        text=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        check=check,
    )
    if not check and proc.returncode != 0:
        return {"returncode": proc.returncode, "stdout": proc.stdout, "stderr": proc.stderr}
    return json.loads(proc.stdout)


def test_router_site_to_site_preview_renders_iroute_and_server_route_plan(tmp_path):
    data = run_vpnctl(
        tmp_path,
        "preview",
        "router_site_001",
        "router_vipnet",
        "192.168.50.201",
        "--client-type",
        "router_site_to_site",
        "--remote-lan",
        "192.168.51.0/24",
        "--create-server-route",
    )

    ccd = "\n".join(data["ccd_preview"])
    routes = "\n".join(data["server_routes_preview"])
    assert data["client_type"] == "router_site_to_site"
    assert data["remote_lan_cidr"] == "192.168.51.0/24"
    assert "ifconfig-push 192.168.50.201 255.255.255.0" in ccd
    assert "iroute 192.168.51.0 255.255.255.0" in ccd
    assert "route 192.168.51.0 255.255.255.0" in routes
    assert "10.8." not in ccd


def test_site_routes_managed_block_is_idempotent(tmp_path):
    server_conf = tmp_path / "server.conf"

    first = run_vpnctl(tmp_path, "site-routes", "add", "192.168.51.0/24", "--client", "router_site_001")
    second = run_vpnctl(tmp_path, "site-routes", "add", "192.168.51.0/24", "--client", "router_site_001")
    run_vpnctl(tmp_path, "site-routes", "add", "192.168.52.0/24", "--client", "router_site_002")
    listed = run_vpnctl(tmp_path, "site-routes", "list")
    removed = run_vpnctl(tmp_path, "site-routes", "remove", "192.168.51.0/24")

    text = server_conf.read_text(encoding="utf-8")
    assert first["changed"] is True
    assert second["changed"] is False
    assert text.count("route 192.168.51.0 255.255.255.0") == 0
    assert "route 192.168.52.0 255.255.255.0" in text
    assert listed["site_routes"][0]["cidr"] == "192.168.51.0/24"
    assert removed["changed"] is True


def test_validate_network_plan_detects_legacy_ccd_and_overlapping_remote_lan(tmp_path):
    ccd_dir = tmp_path / "ccd"
    ccd_dir.mkdir(parents=True, exist_ok=True)
    (ccd_dir / "legacy").write_text("ifconfig-push 10.8.0.10 255.255.255.0\n", encoding="utf-8")
    bad = run_vpnctl(
        tmp_path,
        "preview",
        "router_bad",
        "router_vipnet",
        "192.168.50.201",
        "--client-type",
        "router_site_to_site",
        "--remote-lan",
        "192.168.100.0/24",
        "--create-server-route",
        check=False,
    )
    validation = run_vpnctl(tmp_path, "validate-network-plan")

    messages = "\n".join(validation["warnings"] + validation["errors"])
    assert bad["returncode"] != 0
    assert "overlap" in bad["stderr"].lower() or "перес" in bad["stderr"].lower()
    assert validation["status"] == "warning"
    assert "10.8.0.10" in messages


def test_nat_status_reports_disabled_expected_shape(tmp_path):
    data = run_vpnctl(tmp_path, "nat-status")

    assert data["status"] == "ok"
    assert data["mode"] == "disabled_expected"
    assert data["legacy_nat_service"]["name"] == "vipnet-openvpn-nat.service"
    assert data["legacy_nat_service"]["active"] is False
    assert data["legacy_chain"]["name"] == "VIPNET_OPENVPN_SNAT"
    assert data["legacy_chain"]["exists"] is False
