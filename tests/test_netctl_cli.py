import json
from pathlib import Path

import pytest


def run_cli(args, capsys):
    from netctl.cli import main

    rc = main(args)
    captured = capsys.readouterr()
    assert captured.err == ""
    return rc, json.loads(captured.out)


def write_mock_source(config_path: Path) -> None:
    sources_dir = config_path.parent / "sources.d"
    sources_dir.mkdir(parents=True, exist_ok=True)
    (sources_dir / "mock-main.yaml").write_text(
        "\n".join(
            [
                "name: mock-main",
                "driver: mock",
                "host: 192.168.100.250",
                "port: 8729",
                "username: netobserver",
                "secret_ref: mikrotik-main",
                "tls: true",
                "verify_tls: false",
                "site: main",
                "role: core-router",
                "enabled: true",
            ]
        )
        + "\n",
        encoding="utf-8",
    )


def test_mikrotik_api_driver_parses_arp_and_dhcp_rows():
    from netctl.drivers.mikrotik_api import MikroTikApiDriver

    arp = MikroTikApiDriver.normalize_arp_rows(
        [
            {
                "address": "192.168.100.55",
                "mac-address": "aa:bb:cc:dd:ee:ff",
                "interface": "bridge-lan",
                "complete": "true",
                "dynamic": "false",
                "comment": "printer",
            }
        ]
    )
    dhcp = MikroTikApiDriver.normalize_dhcp_rows(
        [
            {
                "address": "192.168.100.55",
                "active-address": "192.168.100.55",
                "mac-address": "AA:BB:CC:DD:EE:FF",
                "host-name": "pc-buh-01",
                "server": "dhcp-main",
                "status": "bound",
                "dynamic": "true",
            }
        ]
    )

    assert arp == [
        {
            "ip": "192.168.100.55",
            "mac": "AA:BB:CC:DD:EE:FF",
            "interface": "bridge-lan",
            "complete": True,
            "dynamic": False,
            "comment": "printer",
        }
    ]
    assert dhcp[0]["ip"] == "192.168.100.55"
    assert dhcp[0]["mac"] == "AA:BB:CC:DD:EE:FF"
    assert dhcp[0]["hostname"] == "pc-buh-01"
    assert dhcp[0]["status"] == "bound"


def test_normalizer_merges_dhcp_and_arp_and_assigns_categories():
    from netctl.normalizer import normalize_hosts

    source = {"name": "mock-main", "host": "192.168.100.250", "site": "main", "role": "core-router"}
    snapshot = {
        "dhcp_leases": [
            {"ip": "192.168.100.55", "mac": "AA:BB:CC:DD:EE:FF", "hostname": "pc-buh-01", "status": "bound"},
            {"ip": "192.168.51.10", "mac": "AA:BB:CC:DD:EE:10", "hostname": "branch-pc", "status": "bound"},
        ],
        "arp": [
            {"ip": "192.168.100.55", "mac": "AA:BB:CC:DD:EE:FF", "interface": "bridge-lan", "complete": True},
            {"ip": "192.168.100.88", "mac": "AA:BB:CC:DD:EE:88", "interface": "bridge-lan", "complete": True},
            {"ip": "192.168.100.250", "mac": "D4:01:C3:9C:83:5F", "interface": "bridge-lan", "complete": True},
        ],
        "neighbors": [
            {"address": "192.168.100.70", "mac": "AA:BB:CC:DD:EE:70", "identity": "switch-core"},
        ],
        "bridge_hosts": [{"mac": "AA:BB:CC:DD:EE:FF", "interface": "ether2"}],
    }

    hosts = {host["ip"]: host for host in normalize_hosts(source, snapshot, "2026-07-03T12:00:00Z")}

    assert hosts["192.168.100.55"]["hostname"] == "pc-buh-01"
    assert hosts["192.168.100.55"]["category"] == "local_device"
    assert sorted(hosts["192.168.100.55"]["sources"]) == ["mikrotik_arp", "mikrotik_dhcp"]
    assert hosts["192.168.51.10"]["category"] == "site_device"
    assert hosts["192.168.100.250"]["category"] == "router"
    assert hosts["192.168.100.70"]["display_name"] == "switch-core"
    assert hosts["192.168.100.88"]["category"] == "unknown"


def test_normalizer_creates_source_router_without_self_arp():
    from netctl.normalizer import normalize_hosts

    source = {"name": "mikrotik-main", "host": "192.168.100.250", "site": "main", "role": "core-router"}
    snapshot = {
        "identity": [{"name": "sosn"}],
        "arp": [{"ip": "192.168.100.55", "mac": "AA:BB:CC:DD:EE:FF", "complete": True}],
        "dhcp_leases": [],
        "neighbors": [],
        "bridge_hosts": [],
    }

    hosts = {host["ip"]: host for host in normalize_hosts(source, snapshot, "2026-07-03T12:00:00Z")}

    assert hosts["192.168.100.250"]["category"] == "router"
    assert hosts["192.168.100.250"]["display_name"] == "sosn"
    assert hosts["192.168.100.250"]["sources"] == ["mikrotik_identity"]


def test_normalizer_classifies_service_networks_and_ignores_incomplete_arp_noise():
    from netctl.normalizer import normalize_hosts

    source = {"name": "mikrotik-main", "host": "192.168.100.250", "site": "main", "role": "core-router"}
    snapshot = {
        "identity": [{"name": "sosn"}],
        "dhcp_leases": [
            {"ip": "10.83.1.11", "mac": "E0:1C:FC:AE:82:9B", "hostname": "", "status": "waiting", "comment": "PVE1 MGMT"},
            {"ip": "10.254.254.2", "mac": "00:58:3F:21:C6:2A", "hostname": "", "status": "bound"},
        ],
        "arp": [
            {"ip": "192.168.0.12", "mac": "84:D8:1B:EF:3C:6F", "interface": "bridge-lan", "complete": True},
            {"ip": "192.168.0.20", "mac": None, "interface": "bridge-lan", "complete": False},
            {"ip": "192.168.1.251", "mac": "A4:DC:BE:AF:CB:FB", "interface": "ether9_wan_RTK", "complete": True},
            {"ip": "78.29.0.1", "mac": "88:90:09:7B:90:34", "interface": "ether10_wan_IS74", "complete": True},
        ],
        "neighbors": [
            {"address": "192.168.100.18", "mac": "2C:C8:1B:9C:33:D8", "identity": "MT-b2-k4", "platform": "MikroTik"},
        ],
        "bridge_hosts": [],
    }

    hosts = {host["ip"]: host for host in normalize_hosts(source, snapshot, "2026-07-03T12:00:00Z")}

    assert hosts["192.168.0.12"]["category"] == "telephony"
    assert hosts["10.83.1.11"]["category"] == "mgmt"
    assert "mgmt" in hosts["10.83.1.11"]["tags"]
    assert hosts["10.254.254.2"]["category"] == "vipnet_transit"
    assert hosts["192.168.1.251"]["category"] == "wan"
    assert hosts["78.29.0.1"]["category"] == "wan"
    assert hosts["192.168.100.18"]["category"] == "network_infra"
    assert "192.168.0.20" not in hosts


def test_normalizer_guesses_device_type_with_evidence():
    from netctl.normalizer import normalize_hosts

    source = {"name": "mikrotik-main", "host": "192.168.100.250", "site": "main", "role": "core-router"}
    snapshot = {
        "identity": [{"name": "sosn"}],
        "dhcp_leases": [
            {"ip": "192.168.0.221", "mac": "C0:74:AD:01:02:03", "hostname": "", "status": "bound", "comment": "ATC Grandstream"},
            {"ip": "10.83.1.12", "mac": "E0:1C:FC:AE:82:9C", "hostname": "", "status": "bound", "comment": "PVE2 IPMI"},
            {"ip": "192.168.100.55", "mac": "AA:BB:CC:DD:EE:FF", "hostname": "pc-buh-01", "status": "bound"},
        ],
        "arp": [
            {"ip": "192.168.100.80", "mac": "AA:BB:CC:DD:EE:80", "interface": "bridge-lan", "complete": True, "comment": "printer hp"},
        ],
        "neighbors": [
            {"address": "192.168.100.18", "mac": "2C:C8:1B:9C:33:D8", "identity": "MT-b2-k4", "platform": "MikroTik"},
        ],
    }

    hosts = {host["ip"]: host for host in normalize_hosts(source, snapshot, "2026-07-03T12:00:00Z")}

    assert hosts["192.168.0.221"]["device_type"] == "phone"
    assert hosts["192.168.0.221"]["device_confidence"] >= 80
    assert any("telephony" in item for item in hosts["192.168.0.221"]["device_evidence"])
    assert hosts["10.83.1.12"]["device_type"] == "server"
    assert hosts["192.168.100.55"]["device_type"] == "pc"
    assert hosts["192.168.100.80"]["device_type"] == "printer"
    assert hosts["192.168.100.18"]["device_type"] == "network"


def test_manual_tag_follows_mac_when_ip_changes(tmp_path, capsys):
    config_path = tmp_path / "netctl.yaml"
    db_url = f"sqlite:///{(tmp_path / 'netctl.sqlite').as_posix()}"
    write_mock_source(config_path)

    rc, _ = run_cli(["--json", "--config", str(config_path), "--db", db_url, "collect", "mock-main"], capsys)
    assert rc == 0

    rc, tag_result = run_cli(
        ["--json", "--config", str(config_path), "--db", db_url, "tags", "add", "192.168.100.55", "accounting"],
        capsys,
    )
    assert rc == 0
    assert tag_result["device_key"] == "mac:AA:BB:CC:DD:EE:FF"
    assert tag_result["tags"] == ["accounting"]

    from netctl.db import connect, get_source, sync_config_sources
    from netctl.store import save_collection

    conn = connect(db_url)
    try:
        sync_config_sources(conn, config_path)
        source = get_source(conn, "mock-main")
        assert source is not None
        save_collection(
            conn,
            source,
            {
                "identity": [{"name": "mock-router"}],
                "dhcp_leases": [
                    {"ip": "192.168.100.77", "mac": "AA:BB:CC:DD:EE:FF", "hostname": "pc-buh-01", "status": "bound"},
                ],
                "arp": [],
                "neighbors": [],
                "bridge_hosts": [],
            },
            "2026-07-03T12:05:00Z",
        )
    finally:
        conn.close()

    rc, data = run_cli(["--json", "--config", str(config_path), "--db", db_url, "hosts", "inspect", "192.168.100.77"], capsys)
    assert rc == 0
    assert data["host"]["device_key"] == "mac:AA:BB:CC:DD:EE:FF"
    assert "accounting" in data["host"]["manual_tags"]
    assert "accounting" in data["host"]["tags"]


def test_legacy_hosts_without_device_columns_get_defaults(tmp_path):
    from netctl.db import connect
    from netctl.store import query_hosts

    db_url = f"sqlite:///{(tmp_path / 'netctl.sqlite').as_posix()}"
    conn = connect(db_url)
    try:
        conn.execute(
            """
            INSERT INTO network_hosts
              (ip, mac, hostname, display_name, category, status, site, first_seen_at, last_seen_at, last_source, tags_json, comment)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (
                "192.168.100.99",
                "aa-bb-cc-dd-ee-99",
                "",
                "",
                "unknown",
                "seen",
                "main",
                "2026-07-03T12:00:00Z",
                "2026-07-03T12:00:00Z",
                "mikrotik-main",
                '{"sources":["mikrotik_arp"],"tags":[]}',
                "",
            ),
        )
        conn.commit()

        host = query_hosts(conn)[0]

        assert host["device_key"] == "mac:AA:BB:CC:DD:EE:99"
        assert host["device_type"] == "unknown"
        assert host["device_confidence"] == 0
        assert host["device_evidence"] == []
    finally:
        conn.close()


def test_sources_validate_name_and_hide_secret(tmp_path, capsys):
    config_path = tmp_path / "netctl.yaml"
    db_url = f"sqlite:///{(tmp_path / 'netctl.sqlite').as_posix()}"

    bad_rc, bad = run_cli(
        [
            "--json",
            "--config",
            str(config_path),
            "--db",
            db_url,
            "sources",
            "add-mikrotik",
            "bad name",
            "--host",
            "192.168.100.250",
            "--username",
            "netobserver",
            "--secret-ref",
            "mikrotik-main",
        ],
        capsys,
    )
    assert bad_rc == 2
    assert bad["status"] == "error"

    ok_rc, ok = run_cli(
        [
            "--json",
            "--config",
            str(config_path),
            "--db",
            db_url,
            "sources",
            "add-mikrotik",
            "mikrotik-main",
            "--host",
            "192.168.100.250",
            "--port",
            "8729",
            "--username",
            "netobserver",
            "--secret-ref",
            "mikrotik-main",
            "--tls",
            "--site",
            "main",
            "--role",
            "core-router",
        ],
        capsys,
    )
    assert ok_rc == 0
    assert ok["source"]["name"] == "mikrotik-main"

    _, inspected = run_cli(
        ["--json", "--config", str(config_path), "--db", db_url, "sources", "inspect", "mikrotik-main"],
        capsys,
    )
    assert inspected["source"]["secret_ref"] == "mikrotik-main"
    assert "password" not in json.dumps(inspected).lower()


def test_sources_test_returns_json_error_on_driver_failure(tmp_path, capsys, monkeypatch):
    import netctl.cli as cli

    config_path = tmp_path / "netctl.yaml"
    db_url = f"sqlite:///{(tmp_path / 'netctl.sqlite').as_posix()}"
    write_mock_source(config_path)

    def fail_driver(_source, _secrets):
        raise RuntimeError("tls handshake failed")

    monkeypatch.setattr(cli, "driver_for", fail_driver)

    rc, data = run_cli(["--json", "--config", str(config_path), "--db", db_url, "sources", "test", "mock-main"], capsys)

    assert rc == 1
    assert data == {"status": "error", "message": "tls handshake failed", "source": "mock-main"}
    assert capsys.readouterr().err == ""


def test_load_secrets_ignores_unreadable_path(tmp_path, monkeypatch):
    from netctl.config import load_secrets

    monkeypatch.setenv("NETCTL_SECRETS_PATH", str(tmp_path))
    monkeypatch.setenv("NETCTL_SECRET_FROM_ENV_PASSWORD", "env-secret")

    secrets = load_secrets()

    assert secrets["NETCTL_SECRET_FROM_ENV_PASSWORD"] == "env-secret"


def test_collect_creates_run_and_hosts_filters(tmp_path, capsys):
    config_path = tmp_path / "netctl.yaml"
    db_url = f"sqlite:///{(tmp_path / 'netctl.sqlite').as_posix()}"
    write_mock_source(config_path)

    rc, data = run_cli(["--json", "--config", str(config_path), "--db", db_url, "collect", "mock-main"], capsys)

    assert rc == 0
    assert data["status"] == "ok"
    assert data["summary"]["arp"] >= 1

    _, local_hosts = run_cli(
        ["--json", "--config", str(config_path), "--db", db_url, "hosts", "list", "--category", "local_device"],
        capsys,
    )
    assert "192.168.100.55" in [host["ip"] for host in local_hosts["hosts"]]

    _, search = run_cli(
        ["--json", "--config", str(config_path), "--db", db_url, "hosts", "list", "--q", "buh"],
        capsys,
    )
    assert search["hosts"][0]["display_name"] == "pc-buh-01"

    _, dashboard = run_cli(["--json", "--config", str(config_path), "--db", db_url, "dashboard"], capsys)
    assert dashboard["summary"]["total_hosts"] >= 3
    assert dashboard["sources"][0]["name"] == "mock-main"


def test_collect_lock_prevents_parallel_run(tmp_path, capsys):
    from netctl.collect_lock import collect_lock_path

    config_path = tmp_path / "netctl.yaml"
    db_url = f"sqlite:///{(tmp_path / 'netctl.sqlite').as_posix()}"
    write_mock_source(config_path)
    lock_path = collect_lock_path(db_url)
    lock_path.parent.mkdir(parents=True, exist_ok=True)
    lock_path.write_text("busy", encoding="utf-8")

    rc, data = run_cli(["--json", "--config", str(config_path), "--db", db_url, "collect", "mock-main"], capsys)

    assert rc == 1
    assert data["status"] == "error"
    assert "already running" in data["message"]
