import json
import os
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


def seed_client_files(tmp_path: Path, client: str = "alpha") -> tuple[Path, Path]:
    out_dir = tmp_path / "out"
    ccd_dir = tmp_path / "ccd"
    out_dir.mkdir(parents=True, exist_ok=True)
    ccd_dir.mkdir(parents=True, exist_ok=True)
    ovpn = out_dir / f"{client}.ovpn"
    ccd = ccd_dir / client
    ovpn.write_text(
        "client\nremote vpn.example 1194\n<key>\nprivate-key\n</key>\n",
        encoding="utf-8",
    )
    ccd.write_text('ifconfig-push 10.8.0.10 255.255.255.0\npush "route 192.168.100.10 255.255.255.255"\n', encoding="utf-8")
    return ovpn, ccd


def seed_cert_material(tmp_path: Path, client: str = "alpha") -> tuple[Path, Path]:
    out_dir = tmp_path / "out"
    ccd_dir = tmp_path / "ccd"
    pki_dir = tmp_path / "pki"
    for path in [out_dir, ccd_dir, pki_dir / "issued", pki_dir / "private"]:
        path.mkdir(parents=True, exist_ok=True)
    cert = "-----BEGIN CERTIFICATE-----\nclient-cert\n-----END CERTIFICATE-----\n"
    key = "-----BEGIN PRIVATE KEY-----\nclient-key\n-----END PRIVATE KEY-----\n"
    (pki_dir / "ca.crt").write_text("-----BEGIN CERTIFICATE-----\nca-cert\n-----END CERTIFICATE-----\n", encoding="utf-8")
    (pki_dir / "issued" / f"{client}.crt").write_text(cert, encoding="utf-8")
    (pki_dir / "private" / f"{client}.key").write_text(key, encoding="utf-8")
    (pki_dir / "index.txt").write_text(f"V\t260101000000Z\t\tunknown\t/CN={client}\n", encoding="utf-8")
    tlscrypt = out_dir / f"{client}.tls-crypt-v2.key"
    tlscrypt.write_text("tls-crypt-v2-client-key\n", encoding="utf-8")
    ccd = ccd_dir / client
    ccd.write_text('push "route 10.83.1.0 255.255.255.0"\n', encoding="utf-8")
    return out_dir / f"{client}.ovpn", ccd


def test_config_view_returns_ovpn_and_ccd_content(tmp_path):
    seed_client_files(tmp_path)

    data = run_vpnctl(tmp_path, "config-view", "alpha")

    assert data["status"] == "ok"
    assert data["client"] == "alpha"
    assert "private-key" in data["ovpn"]["content"]
    assert "ifconfig-push 10.8.0.10" in data["ccd"]["content"]


def test_ccd_update_writes_backup_and_updates_registry(tmp_path):
    _, ccd = seed_client_files(tmp_path)

    data = run_vpnctl(tmp_path, "ccd-update", "alpha", "--content", 'push "route 10.10.10.0 255.255.254.0"', "--reason", "test")

    assert data["status"] == "ok"
    assert data["backup_path"]
    assert Path(data["backup_path"]).exists()
    assert ccd.read_text(encoding="utf-8").endswith("\n")
    assert "10.10.10.0" in ccd.read_text(encoding="utf-8")


def test_profile_apply_rewrites_ccd_from_template(tmp_path):
    _, ccd = seed_client_files(tmp_path)

    data = run_vpnctl(tmp_path, "profile-apply", "alpha", "directum17", "10.8.0.55", "--reason", "profile change")

    text = ccd.read_text(encoding="utf-8")
    assert data["status"] == "ok"
    assert data["profile"] == "directum17"
    assert "ifconfig-push 10.8.0.55 255.255.255.0" in text
    assert "192.168.100.10" in text
    assert "192.168.100.17" in text


def test_ovpn_update_writes_backup_without_leaking_content_to_result(tmp_path):
    ovpn, _ = seed_client_files(tmp_path)

    data = run_vpnctl(tmp_path, "ovpn-update", "alpha", "--content", "client\nremote changed.example 1194\n", "--reason", "endpoint")

    assert data["status"] == "ok"
    assert data["backup_path"]
    assert Path(data["backup_path"]).exists()
    assert "content" not in data
    assert "changed.example" in ovpn.read_text(encoding="utf-8")


def test_repair_artifacts_rebuilds_missing_ovpn_without_touching_ccd(tmp_path):
    ovpn, ccd = seed_cert_material(tmp_path)
    before_ccd = ccd.read_text(encoding="utf-8")

    data = run_vpnctl(tmp_path, "repair-artifacts", "alpha", "--reason", "download-link")

    assert data["status"] == "ok"
    assert "ovpn_written" in data["actions"]
    assert ovpn.exists()
    text = ovpn.read_text(encoding="utf-8")
    assert "client-cert" in text
    assert "client-key" in text
    assert "tls-crypt-v2-client-key" in text
    assert ccd.read_text(encoding="utf-8") == before_ccd
