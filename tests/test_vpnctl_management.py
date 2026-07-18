import json
import os
import socket
import subprocess
import sys
import threading
import time
from pathlib import Path

import pytest


VPNCTL = Path(__file__).resolve().parents[1] / "deploy" / "vpnctl"


def vpnctl_env(tmp_path: Path) -> dict[str, str]:
    out_dir = tmp_path / "out"
    ccd_dir = tmp_path / "ccd"
    pki_dir = tmp_path / "pki"
    easy_rsa = tmp_path / "easy-rsa"
    openvpn_dir = tmp_path / "openvpn"
    for path in [
        out_dir,
        ccd_dir,
        pki_dir / "issued",
        pki_dir / "private",
        pki_dir / "reqs",
        easy_rsa,
        openvpn_dir,
    ]:
        path.mkdir(parents=True, exist_ok=True)
    (tmp_path / "vipnet-nets.conf").write_text("10.83.1.0/24\n", encoding="utf-8")
    return {
        **os.environ,
        "OUT_DIR": str(out_dir),
        "CCD_DIR": str(ccd_dir),
        "PKI_DIR": str(pki_dir),
        "EASYRSA_DIR": str(easy_rsa),
        "OPENVPN_DIR": str(openvpn_dir),
        "SERVER_CONF": str(openvpn_dir / "server.conf"),
        "SHARE_OUT_DIR": str(tmp_path / "share"),
        "ARCHIVE_DIR": str(tmp_path / "archive"),
        "REGISTRY_DB": str(tmp_path / "registry.sqlite"),
        "NETWORKS_DB": str(tmp_path / "networks.json"),
        "NETWORK_TEMPLATES_DB": str(tmp_path / "network-templates.json"),
        "OPERATION_LOG": str(tmp_path / "vpnctl.log"),
        "LOCK_FILE": str(tmp_path / "vpnctl.lock"),
        "VIPNET_NETS_FILE": str(tmp_path / "vipnet-nets.conf"),
        "STATUS_LOG": str(tmp_path / "status.log"),
        "MANAGEMENT_SOCKET": str(tmp_path / "openvpn" / "server.sock"),
    }


def run_vpnctl(tmp_path: Path, *args: str, check: bool = True) -> subprocess.CompletedProcess:
    proc = subprocess.run(
        [sys.executable, str(VPNCTL), "--json", *args],
        env=vpnctl_env(tmp_path),
        text=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        check=False,
    )
    if check and proc.returncode:
        raise AssertionError(f"vpnctl failed: stdout={proc.stdout}\nstderr={proc.stderr}")
    return proc


def json_out(proc: subprocess.CompletedProcess) -> dict:
    return json.loads(proc.stdout)


def test_server_config_patch_idempotent(tmp_path):
    server_conf = tmp_path / "openvpn" / "server.conf"
    server_conf.parent.mkdir(parents=True, exist_ok=True)
    server_conf.write_text(
        "port 1194\nstatus /tmp/old-status.log 60\nmanagement 127.0.0.1 7505\n",
        encoding="utf-8",
    )

    first = json_out(
        run_vpnctl(
            tmp_path,
            "server-config",
            "apply",
            "--status-interval",
            "10",
            "--status-version",
            "2",
            "--enable-management",
            "--management-socket",
            str(tmp_path / "openvpn" / "server.sock"),
            "--management-client-group",
            "openvpn-web",
            "--management-log-cache",
            "300",
        )
    )
    second = json_out(
        run_vpnctl(
            tmp_path,
            "server-config",
            "apply",
            "--status-interval",
            "10",
            "--status-version",
            "2",
            "--enable-management",
            "--management-socket",
            str(tmp_path / "openvpn" / "server.sock"),
            "--management-client-group",
            "openvpn-web",
            "--management-log-cache",
            "300",
        )
    )

    text = server_conf.read_text(encoding="utf-8")
    assert first["changed"] is True
    assert second["changed"] is False
    assert text.count("status ") == 1
    assert text.count("status-version ") == 1
    assert text.count("management ") == 1
    assert text.count("management-client-group ") == 1
    assert text.count("management-log-cache ") == 1


def test_status_interval_validation(tmp_path):
    bad_low = run_vpnctl(tmp_path, "server-config", "apply", "--status-interval", "4", check=False)
    ok = run_vpnctl(tmp_path, "server-config", "apply", "--status-interval", "10")
    bad_high = run_vpnctl(tmp_path, "server-config", "apply", "--status-interval", "301", check=False)

    assert bad_low.returncode != 0
    assert json_out(ok)["settings"]["status_interval"] == 10
    assert bad_high.returncode != 0


def test_default_status_log_matches_systemd_openvpn_server_unit(tmp_path, monkeypatch):
    env = vpnctl_env(tmp_path)
    env.pop("STATUS_LOG", None)
    monkeypatch.delenv("STATUS_LOG", raising=False)
    server_conf = tmp_path / "server.conf"
    server_conf.write_text("server 192.168.50.0 255.255.255.0\n", encoding="utf-8")
    env["SERVER_CONF"] = str(server_conf)

    proc = subprocess.run(
        [sys.executable, str(VPNCTL), "--json", "server-config", "inspect"],
        env=env,
        text=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        check=True,
    )

    assert json_out(proc)["settings"]["status_path"] == "/run/openvpn-server/status-server.log"


def test_management_socket_path_validation(tmp_path):
    tcp = run_vpnctl(
        tmp_path,
        "server-config",
        "apply",
        "--enable-management",
        "--management-socket",
        "127.0.0.1:7505",
        check=False,
    )
    relative = run_vpnctl(
        tmp_path,
        "server-config",
        "apply",
        "--enable-management",
        "--management-socket",
        "server.sock",
        check=False,
    )
    ok = run_vpnctl(
        tmp_path,
        "server-config",
        "apply",
        "--enable-management",
        "--management-socket",
        str(tmp_path / "openvpn" / "server.sock"),
    )

    assert tcp.returncode != 0
    assert relative.returncode != 0
    assert json_out(ok)["settings"]["management_socket"].endswith("server.sock")


def test_management_status_parser(tmp_path):
    sample = "\n".join(
        [
            "OpenVPN CLIENT LIST",
            "Updated,Thu Jul  2 12:00:00 2026",
            "Common Name,Real Address,Bytes Received,Bytes Sent,Connected Since",
            "alpha,1.2.3.4:50000,123,456,Thu Jul  2 11:59:00 2026",
            "ROUTING TABLE",
            "Virtual Address,Common Name,Real Address,Last Ref",
            "192.168.50.10,alpha,1.2.3.4:50000,Thu Jul  2 12:00:00 2026",
            "GLOBAL STATS",
            "END",
        ]
    )
    proc = run_vpnctl(tmp_path, "management", "parse-status-sample", "--content", sample)

    clients = json_out(proc)["clients"]
    assert clients == [
        {
            "common_name": "alpha",
            "real_address": "1.2.3.4:50000",
            "virtual_address": "192.168.50.10",
            "bytes_received": 123,
            "bytes_sent": 456,
            "connected_since": "Thu Jul  2 11:59:00 2026",
        }
    ]


def test_management_status_parser_handles_openvpn_26_csv_sections(tmp_path):
    sample = "\n".join(
        [
            "TITLE,OpenVPN 2.6.19",
            "TIME,2026-07-02 15:33:02,1783006382",
            "HEADER,CLIENT_LIST,Common Name,Real Address,Virtual Address,Virtual IPv6 Address,Bytes Received,Bytes Sent,Connected Since,Connected Since (time_t),Username,Client ID,Peer ID,Data Channel Cipher",
            "CLIENT_LIST,alpha,1.2.3.4:50000,192.168.50.10,,123,456,2026-07-02 15:32:10,1783006330,UNDEF,3,2,AES-128-GCM",
            "HEADER,ROUTING_TABLE,Virtual Address,Common Name,Real Address,Last Ref,Last Ref (time_t)",
            "ROUTING_TABLE,192.168.50.10,alpha,1.2.3.4:50000,2026-07-02 15:33:01,1783006381",
            "GLOBAL_STATS,Max bcast/mcast queue length,6",
            "GLOBAL_STATS,dco_enabled,0",
            "END",
        ]
    )
    proc = run_vpnctl(tmp_path, "management", "parse-status-sample", "--content", sample)

    clients = json_out(proc)["clients"]
    assert clients == [
        {
            "common_name": "alpha",
            "real_address": "1.2.3.4:50000",
            "virtual_address": "192.168.50.10",
            "bytes_received": 123,
            "bytes_sent": 456,
            "connected_since": "2026-07-02 15:32:10",
        }
    ]


def test_connected_fallback_when_management_unavailable(tmp_path):
    status_log = tmp_path / "status.log"
    status_log.write_text(
        "CLIENT_LIST,alpha,1.2.3.4:50000,192.168.50.10,123,456,Thu Jul 2 12:00:00 2026,,,,,,\n",
        encoding="utf-8",
    )

    data = json_out(run_vpnctl(tmp_path, "connected", "--source", "auto"))

    assert data["source"] == "status_log"
    assert data["connected"][0]["common_name"] == "alpha"


def test_management_kill_command(tmp_path):
    if not hasattr(socket, "AF_UNIX"):
        pytest.skip("Unix domain sockets are not available on this Python build")
    socket_path = tmp_path / "openvpn" / "server.sock"
    socket_path.parent.mkdir(parents=True, exist_ok=True)
    commands: list[str] = []
    ready = threading.Event()

    def server() -> None:
        if socket_path.exists():
            socket_path.unlink()
        with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as srv:
            srv.bind(str(socket_path))
            srv.listen(1)
            ready.set()
            with srv.accept()[0] as conn:
                conn.sendall(b"INFO:OpenVPN Management Interface\n")
                buffer = b""
                while True:
                    chunk = conn.recv(1024)
                    if not chunk:
                        break
                    buffer += chunk
                    while b"\n" in buffer:
                        raw, buffer = buffer.split(b"\n", 1)
                        command = raw.decode("utf-8").strip()
                        commands.append(command)
                        if command == "status":
                            conn.sendall(
                                b"OpenVPN CLIENT LIST\n"
                                b"Common Name,Real Address,Bytes Received,Bytes Sent,Connected Since\n"
                                b"alpha,1.2.3.4:50000,1,2,now\n"
                                b"ROUTING TABLE\n"
                                b"Virtual Address,Common Name,Real Address,Last Ref\n"
                                b"192.168.50.10,alpha,1.2.3.4:50000,now\n"
                                b"END\n"
                            )
                        elif command == "kill alpha":
                            conn.sendall(b"SUCCESS: common name 'alpha' found, 1 client killed\n")
                        elif command == "quit":
                            return

    thread = threading.Thread(target=server, daemon=True)
    thread.start()
    assert ready.wait(2)

    started_at = time.monotonic()
    data = json_out(run_vpnctl(tmp_path, "management", "kill", "alpha"))
    elapsed = time.monotonic() - started_at
    bad = run_vpnctl(tmp_path, "management", "kill", "bad;name", check=False)

    thread.join(timeout=2)
    assert data["killed"] is True
    assert elapsed < 2.5
    assert "status" in commands
    assert "kill alpha" in commands
    assert bad.returncode != 0
