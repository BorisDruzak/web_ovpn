import json
import os
import subprocess
import sys
from pathlib import Path


VPNCTL = Path(__file__).resolve().parents[1] / "deploy" / "vpnctl"


def run_vpnctl(tmp_path: Path, *args: str, check: bool = True) -> subprocess.CompletedProcess[str]:
    env = {
        **os.environ,
        "OUT_DIR": str(tmp_path / "out"),
        "CCD_DIR": str(tmp_path / "ccd"),
        "PKI_DIR": str(tmp_path / "pki"),
        "EASYRSA_DIR": str(tmp_path / "easy-rsa"),
        "OPENVPN_DIR": str(tmp_path / "openvpn"),
        "SHARE_OUT_DIR": str(tmp_path / "share"),
        "ARCHIVE_DIR": str(tmp_path / "archive"),
        "REGISTRY_DB": str(tmp_path / "registry.sqlite"),
        "NETWORKS_DB": str(tmp_path / "networks.json"),
        "NETWORK_TEMPLATES_DB": str(tmp_path / "network-templates.json"),
        "OPERATION_LOG": str(tmp_path / "vpnctl.log"),
        "LOCK_FILE": str(tmp_path / "vpnctl.lock"),
        "VIPNET_NETS_FILE": str(tmp_path / "vipnet-nets.conf"),
    }
    for directory in ("out", "ccd", "pki/issued", "pki/private", "pki/reqs", "easy-rsa", "openvpn"):
        (tmp_path / directory).mkdir(parents=True, exist_ok=True)
    (tmp_path / "openvpn" / "tls-crypt-v2.key").write_text("server-key\n", encoding="utf-8")
    return subprocess.run(
        [sys.executable, str(VPNCTL), "--json", *args],
        env=env,
        text=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        check=check,
    )


def test_batch_preview_lists_five_unique_clients(tmp_path):
    completed = run_vpnctl(
        tmp_path,
        "generate-batch",
        "--client", "user_1",
        "--client", "user_2",
        "--client", "user_3",
        "--client", "user_4",
        "--client", "user_5",
        "--template", "directum",
        "--dry-run",
    )

    result = json.loads(completed.stdout)
    assert result["status"] == "preview"
    assert result["requested_count"] == 5
    assert [row["client"] for row in result["clients"]] == ["user_1", "user_2", "user_3", "user_4", "user_5"]


def test_batch_preview_rejects_duplicate_names_before_creating_files(tmp_path):
    completed = run_vpnctl(
        tmp_path,
        "generate-batch",
        "--client", "person",
        "--client", "person",
        "--template", "directum",
        "--dry-run",
        check=False,
    )

    assert completed.returncode != 0
    assert "unique" in completed.stderr
    assert not list((tmp_path / "out").glob("*.ovpn"))
