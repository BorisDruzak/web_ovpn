import json
import os
import subprocess
import sys
from pathlib import Path

import pytest


@pytest.fixture(autouse=True)
def mock_collect_lock_process_evidence(request, monkeypatch):
    if request.node.name not in {
        "test_process_start_time_parses_after_final_comm_parenthesis",
        "test_collect_lock_rejects_owner_when_proc_stat_is_missing_but_pid_exists",
        "test_collect_lock_reclaims_pid_outside_safe_range",
    }:
        monkeypatch.setattr("netctl.collect_lock._process_start_time", lambda pid: "100")


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


def write_mock_ipsec_pair_sources(config_path: Path) -> None:
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
    (sources_dir / "mock-hex.yaml").write_text(
        "\n".join(
            [
                "name: mock-hex",
                "driver: mock",
                "host: 192.168.99.1",
                "port: 22",
                "username: asmr_admin",
                "secret_ref: mikrotik-hex",
                "tls: false",
                "verify_tls: false",
                "site: m-arhiv",
                "role: edge-router",
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


def test_mikrotik_snapshot_persists_address_lists_rules_and_update_posture(tmp_path, capsys, monkeypatch):
    from netctl.db import connect, get_source, sync_config_sources
    from netctl.store import save_collection
    import netctl.cli as cli

    config_path = tmp_path / "netctl.yaml"
    db_url = f"sqlite:///{(tmp_path / 'netctl.sqlite').as_posix()}"
    write_mock_source(config_path)
    monkeypatch.setattr(
        cli,
        "collector_status",
        lambda: (0, {"status": "ok", "enabled": True, "active": True, "next_run": ""}),
        raising=False,
    )
    snapshot = {
        "firewall_address_lists": [{"list": "vpn", "address": "198.51.100.9", "disabled": False}],
        "firewall_filter_rules": [
            {
                "id": "*1",
                "table": "filter",
                "chain": "forward",
                "action": "accept",
                "disabled": False,
                "src_address": "198.51.100.9",
                "dst_address_list": "vpn",
                "protocol": "tcp",
                "comment": "VPN access",
                "packets": 7,
                "bytes": 700,
            }
        ],
        "firewall_nat_rules": [
            {"id": "*2", "table": "nat", "chain": "srcnat", "action": "masquerade", "disabled": False}
        ],
        "firewall_mangle_rules": [
            {"id": "*3", "table": "mangle", "chain": "prerouting", "action": "mark-connection", "disabled": True}
        ],
        "update_posture": {
            "channel": "stable",
            "installed_version": "7.19.4",
            "latest_version": "",
            "routerboot_current_version": "7.19.4",
            "routerboot_upgrade_version": "7.20.1",
            "schedulers": [{"name": "backup", "disabled": False, "next_run": "jul/22/2026 01:00:00", "on_event": "secret script"}],
        },
    }

    conn = connect(db_url)
    try:
        sync_config_sources(conn, config_path)
        source = get_source(conn, "mock-main")
        assert source is not None
        save_collection(conn, source, snapshot, "2026-07-03T12:00:00Z")
    finally:
        conn.close()

    _, address_lists = run_cli(["--json", "--config", str(config_path), "--db", db_url, "address-lists", "list"], capsys)
    assert address_lists["address_lists"][0]["list"] == "vpn"
    assert address_lists["address_lists"][0]["address"] == "198.51.100.9"
    _, rules = run_cli(
        ["--json", "--config", str(config_path), "--db", db_url, "firewall-rules", "list", "--table", "filter"], capsys
    )
    assert len(rules["firewall_rules"]) == 1
    assert {key: rules["firewall_rules"][0][key] for key in ("identity", "table", "chain", "action", "disabled", "src_address", "dst_address_list", "protocol", "comment", "packets", "bytes", "source")} == {
        "identity": "*1",
        "table": "filter",
        "chain": "forward",
        "action": "accept",
        "disabled": 0,
        "src_address": "198.51.100.9",
        "dst_address_list": "vpn",
        "protocol": "tcp",
        "comment": "VPN access",
        "packets": 7,
        "bytes": 700,
        "source": "mock-main",
    }
    _, posture = run_cli(["--json", "--config", str(config_path), "--db", db_url, "update-posture", "list"], capsys)
    assert posture["update_posture"][0]["last_seen_at"]
    posture["update_posture"][0].pop("last_seen_at")
    assert posture["update_posture"] == [
        {
            "source": "mock-main",
            "channel": "stable",
            "installed_version": "7.19.4",
            "latest_version": "",
            "routerboot_current_version": "7.19.4",
            "routerboot_upgrade_version": "7.20.1",
            "schedulers": [{"name": "backup", "disabled": False, "next_run": "jul/22/2026 01:00:00"}],
        }
    ]
    assert "on_event" not in json.dumps(posture)


def test_persisted_router_booleans_are_evaluated_as_booleans_end_to_end(tmp_path, capsys, monkeypatch):
    import netctl.cli as cli
    import netctl.store as store
    from app.network_paths import evaluate_paths
    from app.server_observer import parse_utc
    from netctl.db import connect, get_source, sync_config_sources

    config_path = tmp_path / "netctl.yaml"
    db_url = f"sqlite:///{(tmp_path / 'netctl.sqlite').as_posix()}"
    write_mock_source(config_path)
    monkeypatch.setattr(store, "utc_now", lambda: "2026-07-21T17:55:00Z")
    monkeypatch.setattr(cli, "utc_now", lambda: "2026-07-21T18:00:00Z")
    monkeypatch.setattr(
        cli,
        "collector_status",
        lambda: (0, {"status": "ok", "enabled": True, "active": True, "next_run": ""}),
    )

    conn = connect(db_url)
    try:
        sync_config_sources(conn, config_path)
        source = get_source(conn, "mock-main")
        assert source is not None
        store.save_collection(
            conn,
            source,
            {
                "routes": [
                    {
                        "dst_address": "198.51.100.0/24",
                        "gateway": "198.51.100.1",
                        "active": True,
                        "disabled": False,
                    }
                ],
                "firewall_address_lists": [
                    {"list": "vpn-targets", "address": "203.0.113.0/24", "disabled": True}
                ],
                "firewall_filter_rules": [
                    {
                        "id": "*1",
                        "chain": "forward",
                        "action": "accept",
                        "disabled": True,
                        "src_address": "198.51.100.0/24",
                        "dst_address": "203.0.113.0/24",
                        "packets": 8,
                        "bytes": 800,
                    }
                ],
            },
            "2026-07-21T17:55:00Z",
        )
    finally:
        conn.close()

    _, routes = run_cli(
        ["--json", "--config", str(config_path), "--db", db_url, "routes", "list", "--source", "mock-main"],
        capsys,
    )
    _, address_lists = run_cli(
        ["--json", "--config", str(config_path), "--db", db_url, "address-lists", "list", "--source", "mock-main"],
        capsys,
    )
    _, rules = run_cli(
        [
            "--json", "--config", str(config_path), "--db", db_url,
            "firewall-rules", "list", "--table", "filter", "--source", "mock-main",
        ],
        capsys,
    )
    definition = __import__("app.network_paths", fromlist=["PathDefinition"]).PathDefinition(
        role="directum",
        router_source="mock-main",
        openvpn_pool="198.51.100.0/24",
        target_cidr="203.0.113.0/24",
        return_route={"dst_address": "198.51.100.0/24", "gateway": "198.51.100.1"},
        address_lists=({"list": "vpn-targets", "address": "203.0.113.0/24"},),
        policy_matchers=(
            {
                "table": "filter",
                "chain": "forward",
                "action": "accept",
                "src_address": "198.51.100.0/24",
                "dst_address": "203.0.113.0/24",
            },
        ),
    )
    result = evaluate_paths(
        definitions={"directum": definition},
        runtime={"sections": {"openvpn": {"service_active": True, "server_network": "198.51.100.0/24"}}},
        collector={"enabled": True, "active": True},
        router_rows={
            "sources": address_lists["sources"],
            "routes": routes["routes"],
            "address_lists": address_lists["address_lists"],
            "firewall_rules": rules["firewall_rules"],
        },
        server_health={
            "collected_at": "2026-07-21T17:55:00Z",
            "targets": [{"role": "directum", "status": "ok"}],
        },
        now=parse_utc("2026-07-21T18:00:00Z"),
    )[0]
    checks = {item["name"]: item for item in result["checks"]}

    assert routes["routes"][0]["active"] == 1
    assert address_lists["address_lists"][0]["disabled"] == 1
    assert rules["firewall_rules"][0]["disabled"] == 1
    assert checks["return_route"]["status"] == "ok"
    assert checks["address_list:1"]["status"] == "critical"
    assert checks["policy:1"]["status"] == "critical"


def test_router_evidence_lists_report_error_when_collector_is_inactive(tmp_path, capsys, monkeypatch):
    import netctl.cli as cli

    config_path = tmp_path / "netctl.yaml"
    db_url = f"sqlite:///{(tmp_path / 'netctl.sqlite').as_posix()}"
    write_mock_source(config_path)
    monkeypatch.setattr(
        cli,
        "collector_status",
        lambda: (1, {"status": "error", "enabled": True, "active": False, "next_run": ""}),
        raising=False,
    )

    commands = [
        ["address-lists", "list"],
        ["firewall-rules", "list", "--table", "filter"],
        ["update-posture", "list"],
    ]
    for command in commands:
        rc, data = run_cli(["--json", "--config", str(config_path), "--db", db_url, *command], capsys)
        assert rc == 1
        assert data["status"] == "error"
        assert data["collector"]["active"] is False


def test_router_evidence_lists_report_stale_and_preserve_update_timestamp(tmp_path, capsys, monkeypatch):
    from netctl.db import connect, get_source, sync_config_sources
    from netctl.store import save_collection
    import netctl.cli as cli

    config_path = tmp_path / "netctl.yaml"
    db_url = f"sqlite:///{(tmp_path / 'netctl.sqlite').as_posix()}"
    write_mock_source(config_path)
    monkeypatch.setattr(
        cli,
        "collector_status",
        lambda: (0, {"status": "ok", "enabled": True, "active": True, "next_run": ""}),
        raising=False,
    )
    monkeypatch.setattr(cli, "utc_now", lambda: "2026-07-21T18:16:00Z")

    conn = connect(db_url)
    try:
        sync_config_sources(conn, config_path)
        source = get_source(conn, "mock-main")
        assert source is not None
        save_collection(
            conn,
            source,
            {
                "firewall_address_lists": [{"list": "vpn", "address": "198.51.100.9"}],
                "firewall_filter_rules": [{"id": "*1", "table": "filter", "chain": "forward", "action": "accept"}],
                "update_posture": {"channel": "stable", "installed_version": "7.19.4", "latest_version": ""},
            },
            "2026-07-21T18:00:00Z",
        )
        conn.execute("UPDATE network_sources SET last_collect_at = ? WHERE id = ?", ("2026-07-21T18:00:00Z", source["id"]))
        conn.execute("UPDATE update_posture SET last_seen_at = ? WHERE source_id = ?", ("2026-07-21T18:00:00Z", source["id"]))
        conn.commit()
    finally:
        conn.close()

    commands = [
        ["address-lists", "list"],
        ["firewall-rules", "list", "--table", "filter"],
        ["update-posture", "list"],
    ]
    for command in commands:
        rc, data = run_cli(["--json", "--config", str(config_path), "--db", db_url, *command], capsys)
        assert rc == 1
        assert data["status"] == "stale"
    assert data["update_posture"][0]["last_seen_at"] == "2026-07-21T18:00:00Z"


def test_router_evidence_cli_rejects_materially_future_collection_time(tmp_path, capsys, monkeypatch):
    import netctl.cli as cli
    import netctl.store as store
    from netctl.db import connect, get_source, sync_config_sources

    config_path = tmp_path / "netctl.yaml"
    db_url = f"sqlite:///{(tmp_path / 'netctl.sqlite').as_posix()}"
    write_mock_source(config_path)
    monkeypatch.setattr(store, "utc_now", lambda: "2026-07-21T18:10:00Z")
    monkeypatch.setattr(cli, "utc_now", lambda: "2026-07-21T18:00:00Z")
    monkeypatch.setattr(
        cli,
        "collector_status",
        lambda: (0, {"status": "ok", "enabled": True, "active": True, "next_run": ""}),
    )
    conn = connect(db_url)
    try:
        sync_config_sources(conn, config_path)
        source = get_source(conn, "mock-main")
        assert source is not None
        store.save_collection(conn, source, {"firewall_address_lists": []}, "2026-07-21T18:10:00Z")
    finally:
        conn.close()

    rc, data = run_cli(
        ["--json", "--config", str(config_path), "--db", db_url, "address-lists", "list", "--source", "mock-main"],
        capsys,
    )

    assert rc == 1
    assert data["status"] == "stale"
    assert data["sources"][0]["status"] == "stale"


def test_firewall_rules_use_snapshot_table_not_item_value(tmp_path, capsys, monkeypatch):
    from netctl.db import connect, get_source, sync_config_sources
    from netctl.store import save_collection
    import netctl.cli as cli

    config_path = tmp_path / "netctl.yaml"
    db_url = f"sqlite:///{(tmp_path / 'netctl.sqlite').as_posix()}"
    write_mock_source(config_path)
    monkeypatch.setattr(
        cli,
        "collector_status",
        lambda: (0, {"status": "ok", "enabled": True, "active": True, "next_run": ""}),
        raising=False,
    )
    conn = connect(db_url)
    try:
        sync_config_sources(conn, config_path)
        source = get_source(conn, "mock-main")
        assert source is not None
        save_collection(
            conn,
            source,
            {"firewall_nat_rules": [{"id": "*2", "table": "filter", "chain": "srcnat", "action": "masquerade"}]},
            "2026-07-21T18:00:00Z",
        )
    finally:
        conn.close()

    _, data = run_cli(
        ["--json", "--config", str(config_path), "--db", db_url, "firewall-rules", "list", "--table", "nat"], capsys
    )
    assert data["firewall_rules"][0]["table"] == "nat"


def test_collector_status_uses_fixed_timer_show_command(tmp_path, capsys, monkeypatch):
    import subprocess

    import netctl.cli as cli

    command: list[str] = []

    def fake_run(args, **kwargs):
        command.extend(args)
        assert kwargs["shell"] is False
        return subprocess.CompletedProcess(
            args,
            0,
            stdout="UnitFileState=enabled\nActiveState=active\nNextElapseUSecRealtime=Tue 2026-07-22 01:00:00 UTC\n",
            stderr="",
        )

    monkeypatch.setattr(cli.subprocess, "run", fake_run)
    db_url = f"sqlite:///{(tmp_path / 'netctl.sqlite').as_posix()}"

    rc, status = run_cli(["--json", "--db", db_url, "collector-status"], capsys)

    assert rc == 0
    assert command == ["systemctl", "show", "netctl-collect.timer"]
    assert status == {
        "status": "ok",
        "enabled": True,
        "active": True,
        "next_run": "2026-07-22T01:00:00Z",
    }


def test_collector_status_reports_error_for_disabled_or_inactive_timer(tmp_path, capsys, monkeypatch):
    import subprocess

    import netctl.cli as cli

    def fake_run(args, **kwargs):
        return subprocess.CompletedProcess(
            args,
            0,
            stdout="UnitFileState=disabled\nActiveState=inactive\nNextElapseUSecRealtime=n/a\n",
            stderr="",
        )

    monkeypatch.setattr(cli.subprocess, "run", fake_run)
    db_url = f"sqlite:///{(tmp_path / 'netctl.sqlite').as_posix()}"

    rc, status = run_cli(["--json", "--db", db_url, "collector-status"], capsys)

    assert rc == 1
    assert status == {"status": "error", "enabled": False, "active": False, "next_run": ""}


def test_mikrotik_ssh_driver_does_not_collect_scheduler_event_text(monkeypatch):
    import subprocess

    from netctl.drivers.mikrotik_ssh import MikroTikSshDriver

    calls = []

    def fake_run(command, **kwargs):
        calls.append(command)
        assert "/system scheduler" not in command[-1]
        return subprocess.CompletedProcess(command, 0, stdout="", stderr="")

    monkeypatch.setattr(subprocess, "run", fake_run)
    driver = MikroTikSshDriver(
        {"name": "mikrotik-hex", "host": "192.168.99.1", "port": 22, "username": "netobserver"},
        {},
    )

    snapshot = driver.collect()

    assert snapshot["update_posture"]["schedulers"] == []
    assert calls


def test_mikrotik_update_posture_includes_routerboot_versions():
    from netctl.drivers.mikrotik_api import MikroTikApiDriver

    posture = MikroTikApiDriver.normalize_update_posture(
        [{"version": "7.19.4"}],
        [{"channel": "stable", "installed-version": "7.19.4", "latest-version": ""}],
        [],
        [{"current-firmware": "7.19.4", "upgrade-firmware": "7.20.1"}],
    )

    assert posture["routerboot_current_version"] == "7.19.4"
    assert posture["routerboot_upgrade_version"] == "7.20.1"
    assert MikroTikApiDriver.COLLECT_PATHS["routerboard"] == (
        "/system/routerboard/print",
        ["current-firmware", "upgrade-firmware"],
    )


def test_normalizer_merges_dhcp_and_arp_and_assigns_categories():
    from netctl.context_classifier import legacy_segment_rules
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

    hosts = {host["ip"]: host for host in normalize_hosts(source, snapshot, "2026-07-03T12:00:00Z", segment_rules=legacy_segment_rules())}

    assert hosts["192.168.100.55"]["hostname"] == "pc-buh-01"
    assert hosts["192.168.100.55"]["category"] == "local_device"
    assert sorted(hosts["192.168.100.55"]["sources"]) == ["mikrotik_arp", "mikrotik_dhcp"]
    assert hosts["192.168.51.10"]["category"] == "site_device"
    assert hosts["192.168.100.250"]["category"] == "router"
    assert hosts["192.168.100.70"]["display_name"] == "switch-core"
    assert hosts["192.168.100.88"]["category"] == "unknown"


def test_normalizer_creates_source_router_without_self_arp():
    from netctl.context_classifier import legacy_segment_rules
    from netctl.normalizer import normalize_hosts

    source = {"name": "mikrotik-main", "host": "192.168.100.250", "site": "main", "role": "core-router"}
    snapshot = {
        "identity": [{"name": "sosn"}],
        "arp": [{"ip": "192.168.100.55", "mac": "AA:BB:CC:DD:EE:FF", "complete": True}],
        "dhcp_leases": [],
        "neighbors": [],
        "bridge_hosts": [],
    }

    hosts = {host["ip"]: host for host in normalize_hosts(source, snapshot, "2026-07-03T12:00:00Z", segment_rules=legacy_segment_rules())}

    assert hosts["192.168.100.250"]["category"] == "router"
    assert hosts["192.168.100.250"]["display_name"] == "sosn"
    assert hosts["192.168.100.250"]["sources"] == ["mikrotik_identity"]


def test_normalizer_classifies_service_networks_and_ignores_incomplete_arp_noise():
    from netctl.context_classifier import legacy_segment_rules
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

    hosts = {host["ip"]: host for host in normalize_hosts(source, snapshot, "2026-07-03T12:00:00Z", segment_rules=legacy_segment_rules())}

    assert hosts["192.168.0.12"]["category"] == "telephony"
    assert hosts["10.83.1.11"]["category"] == "mgmt"
    assert "mgmt" in hosts["10.83.1.11"]["tags"]
    assert hosts["10.254.254.2"]["category"] == "vipnet_transit"
    assert hosts["192.168.1.251"]["category"] == "wan"
    assert hosts["78.29.0.1"]["category"] == "wan"
    assert hosts["192.168.100.18"]["category"] == "network_infra"
    assert "192.168.0.20" not in hosts


def test_normalizer_guesses_device_type_with_evidence():
    from netctl.context_classifier import legacy_segment_rules
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

    hosts = {host["ip"]: host for host in normalize_hosts(source, snapshot, "2026-07-03T12:00:00Z", segment_rules=legacy_segment_rules())}

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

    rc, remove_result = run_cli(
        ["--json", "--config", str(config_path), "--db", db_url, "tags", "remove", "192.168.100.77", "accounting"],
        capsys,
    )
    assert rc == 0
    assert remove_result["tags"] == []
    _, tags_result = run_cli(["--json", "--config", str(config_path), "--db", db_url, "tags", "list"], capsys)
    assert tags_result["tags"] == []


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


def test_demoted_stale_noise_hosts_get_noise_device_type(tmp_path):
    from netctl.db import connect, get_source, sync_config_sources
    from netctl.store import inspect_host, save_collection

    config_path = tmp_path / "netctl.yaml"
    db_url = f"sqlite:///{(tmp_path / 'netctl.sqlite').as_posix()}"
    write_mock_source(config_path)
    conn = connect(db_url)
    try:
        sync_config_sources(conn, config_path)
        source = get_source(conn, "mock-main")
        assert source is not None
        conn.execute(
            """
            INSERT INTO network_hosts
              (ip, mac, hostname, display_name, category, status, site, first_seen_at, last_seen_at, last_source, tags_json, comment)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (
                "192.168.0.20",
                None,
                None,
                None,
                "telephony",
                "online",
                "main",
                "2026-07-03T12:00:00Z",
                "2026-07-03T12:00:00Z",
                "mock-main",
                '{"sources":["mikrotik_arp"],"tags":["telephony"]}',
                "",
            ),
        )
        conn.execute(
            """
            INSERT INTO network_hosts
              (ip, mac, hostname, display_name, category, status, site, first_seen_at, last_seen_at, last_source, tags_json, comment)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (
                "192.168.0.21",
                None,
                None,
                None,
                "noise",
                "seen",
                "main",
                "2026-07-03T12:00:00Z",
                "2026-07-03T12:00:00Z",
                "mock-main",
                '{"sources":[],"tags":["noise","stale_arp"]}',
                "",
            ),
        )
        conn.commit()

        save_collection(
            conn,
            source,
            {"identity": [], "dhcp_leases": [], "arp": [], "neighbors": [], "bridge_hosts": []},
            "2026-07-03T12:05:00Z",
        )
        host = inspect_host(conn, "192.168.0.20")

        assert host is not None
        assert host["category"] == "noise"
        assert host["device_type"] == "noise"
        assert host["device_key"] == "ip:192.168.0.20"
        assert "stale_arp" in host["tags"]
        old_noise = inspect_host(conn, "192.168.0.21")
        assert old_noise is not None
        assert old_noise["device_type"] == "noise"
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
    assert {
        "arp",
        "dhcp_leases",
        "interfaces",
        "routes",
        "neighbors",
        "bridge_hosts",
        "firewall_address_lists",
    } <= data["summary"].keys()
    assert data["summary"]["runtime_assets_touched"] >= 1
    assert data["summary"]["runtime_ips_current"] >= 1
    assert data["summary"]["runtime_hostnames_current"] >= 1
    assert data["summary"]["runtime_findings_open"] >= 0
    assert data["summary"]["context_classifier_fallback"] is True

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


def test_runtime_assets_status_reports_identity_operational_summary(tmp_path, capsys):
    config_path = tmp_path / "netctl.yaml"
    db_url = f"sqlite:///{(tmp_path / 'netctl.sqlite').as_posix()}"
    write_mock_source(config_path)

    rc, _ = run_cli(
        ["--json", "--config", str(config_path), "--db", db_url, "collect", "mock-main"],
        capsys,
    )
    assert rc == 0

    rc, data = run_cli(
        ["--json", "--config", str(config_path), "--db", db_url, "runtime-assets", "status"],
        capsys,
    )

    assert rc == 0
    assert data["status"] == "ok"
    summary = data["runtime_identity"]
    assert summary["schema_migration_versions"] == [1, 2, 3, 4, 5, 6, 7, 8, 9]
    assert summary["counts"]["assets"] >= 1
    assert summary["counts"]["interfaces"] >= 1
    assert summary["counts"]["current_ip_observations"] >= 1
    assert summary["counts"]["current_hostname_observations"] >= 1
    collection = summary["last_successful_collections"]
    assert len(collection) == 1
    assert collection[0]["source_id"] == 1
    assert collection[0]["source"] == "mock-main"
    assert collection[0]["started_at"]
    assert collection[0]["finished_at"]
    assert summary["open_findings"]["by_type"] == []
    assert summary["open_findings"]["by_severity"] == []
    assert summary["migration_2_report_summary"]["migration_version"] == 2
    assert summary["migration_only_current"]["ip_observations"] == 0
    assert summary["migration_only_current"]["hostname_observations"] == 0
    assert summary["migration_only_current"]["total"] == 0


def test_runtime_assets_inspect_and_findings_commands_are_read_only(tmp_path, capsys):
    from netctl.db import connect

    config_path = tmp_path / "netctl.yaml"
    db_url = f"sqlite:///{(tmp_path / 'netctl.sqlite').as_posix()}"
    write_mock_source(config_path)
    rc, _ = run_cli(
        ["--json", "--config", str(config_path), "--db", db_url, "collect", "mock-main"],
        capsys,
    )
    assert rc == 0

    conn = connect(db_url)
    try:
        asset = conn.execute("SELECT id FROM assets WHERE asset_key = ?", ("mac:AA:BB:CC:DD:EE:FF",)).fetchone()
        assert asset is not None
        conn.execute(
            """
            INSERT INTO runtime_identity_findings (
                finding_key, finding_type, severity, status, asset_id,
                first_seen_at, last_seen_at, details_json
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (
                "test-runtime-finding",
                "duplicate_current_ip",
                "warning",
                "open",
                asset["id"],
                "2026-07-18T00:00:00Z",
                "2026-07-18T00:00:00Z",
                '{"ip":"192.168.100.55"}',
            ),
        )
        conn.commit()
    finally:
        conn.close()

    rc, inspected = run_cli(
        [
            "--json", "--config", str(config_path), "--db", db_url,
            "runtime-assets", "inspect", "--asset-key", "mac:AA:BB:CC:DD:EE:FF",
        ],
        capsys,
    )
    assert rc == 0
    assert inspected["runtime_asset"]["asset"]["asset_key"] == "mac:AA:BB:CC:DD:EE:FF"
    assert inspected["runtime_asset"]["interfaces"]
    assert inspected["runtime_asset"]["current_ip_observations"]
    assert inspected["runtime_asset"]["current_hostname_observations"]
    assert inspected["runtime_asset"]["findings"][0]["finding_key"] == "test-runtime-finding"

    rc, findings = run_cli(
        ["--json", "--config", str(config_path), "--db", db_url, "runtime-assets", "findings", "--status", "open"],
        capsys,
    )
    assert rc == 0
    assert findings["findings"][0]["details"] == {"ip": "192.168.100.55"}
    assert findings["findings"][0]["asset_key"] == "mac:AA:BB:CC:DD:EE:FF"

    rc, missing = run_cli(
        [
            "--json", "--config", str(config_path), "--db", db_url,
            "runtime-assets", "inspect", "--asset-key", "mac:00:00:00:00:00:00",
        ],
        capsys,
    )
    assert rc == 1
    assert missing == {
        "status": "error",
        "message": "runtime asset not found",
        "asset_key": "mac:00:00:00:00:00:00",
    }

    rc, invalid = run_cli(
        ["--json", "--config", str(config_path), "--db", db_url, "runtime-assets", "findings", "--status", "invalid"],
        capsys,
    )
    assert rc == 2
    assert invalid == {
        "status": "error",
        "message": "invalid finding status",
        "finding_status": "invalid",
    }


def test_runtime_assets_findings_acknowledged_legacy_findings(tmp_path, capsys):
    from netctl.db import connect

    config_path = tmp_path / "netctl.yaml"
    db_url = f"sqlite:///{(tmp_path / 'netctl.sqlite').as_posix()}"
    conn = connect(db_url)
    try:
        conn.executemany(
            """
            INSERT INTO runtime_identity_findings (
                finding_key, finding_type, severity, status,
                first_seen_at, last_seen_at, details_json
            ) VALUES (?, ?, 'warning', ?, '2026-07-17T00:00:00Z', '2026-07-17T01:00:00Z', ?)
            """,
            [
                ("legacy-identity-conflict:1", "historical_identity_conflict", "open", '{"origin":"migration"}'),
                ("ip-moved:1:192.0.2.10:1:2", "historical_identity_conflict", "open", '{"origin":"live"}'),
                ("mac-site-collision:1:00:11:22:33:44:55", "mac_identity_collision", "open", "{}"),
                ("unresolved-ip-only:1:192.0.2.11", "unresolved_ip_only_runtime", "open", "{}"),
                ("legacy-identity-conflict:2", "historical_identity_conflict", "resolved", "{}"),
            ],
        )
        conn.execute("DELETE FROM schema_migrations WHERE version = 4")
        conn.commit()
    finally:
        conn.close()

    migrated = connect(db_url)
    migrated.close()

    code, payload = run_cli(
        ["--json", "--config", str(config_path), "--db", db_url, "runtime-assets", "findings"],
        capsys,
    )
    assert code == 0
    assert {item["finding_type"] for item in payload["findings"]} == {
        "historical_identity_conflict", "mac_identity_collision",
        "unresolved_ip_only_runtime",
    }

    code, payload = run_cli(
        [
            "--json", "--config", str(config_path), "--db", db_url,
            "runtime-assets", "findings", "--status", "acknowledged",
        ],
        capsys,
    )
    assert code == 0
    assert [item["finding_key"] for item in payload["findings"]] == [
        "legacy-identity-conflict:1"
    ]
    assert payload["findings"][0]["details"] == {"origin": "migration"}


def test_runtime_assets_commands_do_not_modify_database_or_sync_sources(tmp_path, capsys):
    from netctl.db import connect

    config_path = tmp_path / "netctl.yaml"
    db_url = f"sqlite:///{(tmp_path / 'netctl.sqlite').as_posix()}"
    write_mock_source(config_path)
    rc, _ = run_cli(
        ["--json", "--config", str(config_path), "--db", db_url, "collect", "mock-main"],
        capsys,
    )
    assert rc == 0

    conn = connect(db_url)
    try:
        conn.execute(
            "UPDATE network_sources SET updated_at = ? WHERE name = ?",
            ("2000-01-01T00:00:00Z", "mock-main"),
        )
        conn.commit()
        before = "\n".join(conn.iterdump())
    finally:
        conn.close()

    for args in (
        ["runtime-assets", "status"],
        ["runtime-assets", "inspect", "--asset-key", "mac:AA:BB:CC:DD:EE:FF"],
        ["runtime-assets", "findings", "--status", "open"],
    ):
        rc, data = run_cli(
            ["--json", "--config", str(config_path), "--db", db_url, *args],
            capsys,
        )
        assert rc == 0
        assert data["status"] == "ok"

    conn = connect(db_url)
    try:
        assert conn.execute(
            "SELECT updated_at FROM network_sources WHERE name = ?",
            ("mock-main",),
        ).fetchone()["updated_at"] == "2000-01-01T00:00:00Z"
        assert "\n".join(conn.iterdump()) == before
    finally:
        conn.close()


def test_collect_lock_prevents_parallel_run(tmp_path, capsys, monkeypatch):
    from netctl.collect_lock import collect_lock_path

    config_path = tmp_path / "netctl.yaml"
    db_url = f"sqlite:///{(tmp_path / 'netctl.sqlite').as_posix()}"
    write_mock_source(config_path)
    lock_path = collect_lock_path(db_url)
    lock_path.parent.mkdir(parents=True, exist_ok=True)
    lock_path.write_text("123 10", encoding="ascii")
    monkeypatch.setattr("netctl.collect_lock._process_start_time", lambda pid: "10")

    rc, data = run_cli(["--json", "--config", str(config_path), "--db", db_url, "collect", "mock-main"], capsys)

    assert rc == 1
    assert data["status"] == "error"
    assert "already running" in data["message"]


def test_collect_lock_reclaims_absent_owner(tmp_path, monkeypatch):
    from netctl.collect_lock import CollectLock, collect_lock_path

    db_url = f"sqlite:///{tmp_path / 'netctl.sqlite'}"
    lock_path = collect_lock_path(db_url)
    lock_path.parent.mkdir(parents=True, exist_ok=True)
    lock_path.write_text("123 10", encoding="ascii")
    monkeypatch.setattr(
        "netctl.collect_lock._process_start_time",
        lambda pid: None if pid == 123 else "200",
    )

    with CollectLock(db_url):
        assert lock_path.read_text(encoding="ascii") == f"{os.getpid()} 200\n"


def test_collect_lock_uses_windows_start_time_when_proc_is_unavailable(monkeypatch):
    import importlib
    import netctl.collect_lock as collect_lock

    collect_lock = importlib.reload(collect_lock)

    def missing_proc_stat(*_args, **_kwargs):
        raise FileNotFoundError

    monkeypatch.setattr(collect_lock.Path, "read_text", missing_proc_stat)
    monkeypatch.setattr(collect_lock.os, "name", "nt")
    monkeypatch.setattr(collect_lock.os, "kill", lambda *_args: None)
    monkeypatch.setattr(
        collect_lock,
        "_windows_process_start_time",
        lambda pid: "windows-start" if pid == 2468 else None,
        raising=False,
    )

    assert collect_lock._process_start_time(2468) == "windows-start"


def test_collect_lock_rejects_owner_when_proc_stat_is_missing_but_pid_exists(tmp_path, monkeypatch):
    from netctl.collect_lock import CollectLock, collect_lock_path

    db_url = f"sqlite:///{tmp_path / 'netctl.sqlite'}"
    lock_path = collect_lock_path(db_url)
    lock_path.parent.mkdir(parents=True, exist_ok=True)
    lock_path.write_text("123 10", encoding="ascii")
    original_read_text = Path.read_text
    stat = "456 (collector) " + " ".join(["S", *(["1"] * 18), "200"])

    def missing_owner_stat(path, *args, **kwargs):
        normalized = str(path).replace("\\", "/")
        if normalized.endswith("/proc/123/stat"):
            raise FileNotFoundError
        if normalized.endswith("/stat") and "/proc/" in normalized:
            return stat
        return original_read_text(path, *args, **kwargs)

    monkeypatch.setattr(Path, "read_text", missing_owner_stat)
    monkeypatch.setattr("netctl.collect_lock.os.kill", lambda pid, signal: None)

    with pytest.raises(RuntimeError, match="collection already running"):
        CollectLock(db_url).__enter__()
    assert lock_path.read_text(encoding="ascii") == "123 10"


def test_collect_lock_reclaims_oversized_pid_record(tmp_path, monkeypatch):
    from netctl.collect_lock import CollectLock, collect_lock_path

    db_url = f"sqlite:///{tmp_path / 'netctl.sqlite'}"
    lock_path = collect_lock_path(db_url)
    lock_path.parent.mkdir(parents=True, exist_ok=True)
    lock_path.write_text("9" * 5000, encoding="ascii")
    monkeypatch.setattr("netctl.collect_lock._process_start_time", lambda pid: "200")

    with CollectLock(db_url):
        assert lock_path.read_text(encoding="ascii") == f"{os.getpid()} 200\n"


def test_collect_lock_reclaims_pid_outside_safe_range(tmp_path, monkeypatch):
    from netctl.collect_lock import CollectLock, collect_lock_path

    oversized_pid = "99999999999999999999"
    db_url = f"sqlite:///{tmp_path / 'netctl.sqlite'}"
    lock_path = collect_lock_path(db_url)
    lock_path.parent.mkdir(parents=True, exist_ok=True)
    lock_path.write_text(f"{oversized_pid} 10", encoding="ascii")
    original_read_text = Path.read_text
    stat = "456 (collector) " + " ".join(["S", *(["1"] * 18), "200"])

    def missing_oversized_owner_stat(path, *args, **kwargs):
        normalized = str(path).replace("\\", "/")
        if normalized.endswith(f"/proc/{oversized_pid}/stat"):
            raise FileNotFoundError
        if normalized.endswith("/stat") and "/proc/" in normalized:
            return stat
        return original_read_text(path, *args, **kwargs)

    monkeypatch.setattr(Path, "read_text", missing_oversized_owner_stat)
    monkeypatch.setattr(
        "netctl.collect_lock.os.kill",
        lambda pid, signal: (_ for _ in ()).throw(OverflowError("out of range")),
    )

    with CollectLock(db_url):
        assert lock_path.read_text(encoding="ascii") == f"{os.getpid()} 200\n"


def test_collect_lock_fails_closed_without_local_start_time(tmp_path, monkeypatch):
    from netctl.collect_lock import CollectLock, collect_lock_path

    db_url = f"sqlite:///{tmp_path / 'netctl.sqlite'}"
    lock_path = collect_lock_path(db_url)
    monkeypatch.setattr("netctl.collect_lock._process_start_time", lambda pid: None)

    with pytest.raises(RuntimeError, match="collection already running"):
        CollectLock(db_url).__enter__()
    assert not lock_path.exists()


def test_collect_lock_fails_closed_with_unknown_local_process_evidence(tmp_path, monkeypatch):
    from netctl.collect_lock import CollectLock, collect_lock_path

    db_url = f"sqlite:///{tmp_path / 'netctl.sqlite'}"
    lock_path = collect_lock_path(db_url)
    monkeypatch.setattr(
        "netctl.collect_lock._process_start_time",
        lambda pid: (_ for _ in ()).throw(PermissionError("denied")),
    )

    with pytest.raises(RuntimeError, match="collection already running"):
        CollectLock(db_url).__enter__()
    assert not lock_path.exists()


def test_collect_lock_rejects_matching_live_owner(tmp_path, monkeypatch):
    from netctl.collect_lock import CollectLock, collect_lock_path

    db_url = f"sqlite:///{tmp_path / 'netctl.sqlite'}"
    lock_path = collect_lock_path(db_url)
    lock_path.parent.mkdir(parents=True, exist_ok=True)
    lock_path.write_text("123 10", encoding="ascii")
    monkeypatch.setattr("netctl.collect_lock._process_start_time", lambda pid: "10")

    with pytest.raises(RuntimeError, match="collection already running"):
        CollectLock(db_url).__enter__()


def test_collect_lock_reclaims_pid_reused_owner(tmp_path, monkeypatch):
    from netctl.collect_lock import CollectLock, collect_lock_path

    db_url = f"sqlite:///{tmp_path / 'netctl.sqlite'}"
    lock_path = collect_lock_path(db_url)
    lock_path.parent.mkdir(parents=True, exist_ok=True)
    lock_path.write_text("123 10", encoding="ascii")
    monkeypatch.setattr(
        "netctl.collect_lock._process_start_time",
        lambda pid: "11" if pid == 123 else "200",
    )

    with CollectLock(db_url):
        assert lock_path.read_text(encoding="ascii") == f"{os.getpid()} 200\n"


def test_collect_lock_rejects_live_legacy_owner(tmp_path, monkeypatch):
    from netctl.collect_lock import CollectLock, collect_lock_path

    db_url = f"sqlite:///{tmp_path / 'netctl.sqlite'}"
    lock_path = collect_lock_path(db_url)
    lock_path.parent.mkdir(parents=True, exist_ok=True)
    lock_path.write_text("123", encoding="ascii")
    monkeypatch.setattr("netctl.collect_lock._process_start_time", lambda pid: "10")

    with pytest.raises(RuntimeError, match="collection already running"):
        CollectLock(db_url).__enter__()


def test_collect_lock_reclaims_absent_legacy_owner(tmp_path, monkeypatch):
    from netctl.collect_lock import CollectLock, collect_lock_path

    db_url = f"sqlite:///{tmp_path / 'netctl.sqlite'}"
    lock_path = collect_lock_path(db_url)
    lock_path.parent.mkdir(parents=True, exist_ok=True)
    lock_path.write_text("123", encoding="ascii")
    monkeypatch.setattr(
        "netctl.collect_lock._process_start_time",
        lambda pid: None if pid == 123 else "200",
    )

    with CollectLock(db_url):
        assert lock_path.read_text(encoding="ascii") == f"{os.getpid()} 200\n"


def test_collect_lock_reclaims_malformed_record(tmp_path, monkeypatch):
    from netctl.collect_lock import CollectLock, collect_lock_path

    db_url = f"sqlite:///{tmp_path / 'netctl.sqlite'}"
    lock_path = collect_lock_path(db_url)
    lock_path.parent.mkdir(parents=True, exist_ok=True)
    lock_path.write_text("not a lock record", encoding="ascii")
    monkeypatch.setattr("netctl.collect_lock._process_start_time", lambda pid: "200")

    with CollectLock(db_url):
        assert lock_path.read_text(encoding="ascii") == f"{os.getpid()} 200\n"


def test_collect_lock_writes_numeric_owner_record(tmp_path, monkeypatch):
    from netctl.collect_lock import CollectLock, collect_lock_path

    db_url = f"sqlite:///{tmp_path / 'netctl.sqlite'}"
    lock_path = collect_lock_path(db_url)
    monkeypatch.setattr("netctl.collect_lock._process_start_time", lambda pid: "987654")

    with CollectLock(db_url):
        assert lock_path.read_text(encoding="ascii") == f"{os.getpid()} 987654\n"


def test_process_start_time_parses_after_final_comm_parenthesis(monkeypatch):
    from netctl.collect_lock import _process_start_time

    stat = "123 (worker name (nested)) " + " ".join(["S", *(["1"] * 18), "987654"])
    monkeypatch.setattr(Path, "read_text", lambda self, encoding: stat)

    assert _process_start_time(123) == "987654"


def test_collect_lock_rejects_unknown_owner_process_evidence(tmp_path, monkeypatch):
    from netctl.collect_lock import CollectLock, collect_lock_path

    db_url = f"sqlite:///{tmp_path / 'netctl.sqlite'}"
    lock_path = collect_lock_path(db_url)
    lock_path.parent.mkdir(parents=True, exist_ok=True)
    lock_path.write_text("123 10", encoding="ascii")

    def process_evidence(pid):
        if pid == 123:
            raise PermissionError("denied")
        return "200"

    monkeypatch.setattr("netctl.collect_lock._process_start_time", process_evidence)

    with pytest.raises(RuntimeError, match="collection already running"):
        CollectLock(db_url).__enter__()
    assert lock_path.read_text(encoding="ascii") == "123 10"


def test_collect_lock_rejects_unreadable_owner_record(tmp_path, monkeypatch):
    from netctl.collect_lock import CollectLock, collect_lock_path

    db_url = f"sqlite:///{tmp_path / 'netctl.sqlite'}"
    lock_path = collect_lock_path(db_url)
    lock_path.parent.mkdir(parents=True, exist_ok=True)
    lock_path.write_text("123 10", encoding="ascii")
    original_read_text = Path.read_text

    def unreadable_owner(path, *args, **kwargs):
        if path == lock_path:
            raise PermissionError("denied")
        return original_read_text(path, *args, **kwargs)

    monkeypatch.setattr(Path, "read_text", unreadable_owner)

    with pytest.raises(RuntimeError, match="collection already running"):
        CollectLock(db_url).__enter__()


def test_collect_lock_rejects_contender_during_lock_publication(tmp_path, monkeypatch):
    from netctl.collect_lock import CollectLock
    from netctl import collect_lock

    db_url = f"sqlite:///{tmp_path / 'netctl.sqlite'}"
    monkeypatch.setattr("netctl.collect_lock._process_start_time", lambda pid: "200")
    original_write = collect_lock.os.write
    attempted_contender = False

    def attempt_contender_before_publish(fd, data):
        nonlocal attempted_contender
        if not attempted_contender:
            attempted_contender = True
            with pytest.raises(RuntimeError, match="collection already running"):
                CollectLock(db_url).__enter__()
        return original_write(fd, data)

    monkeypatch.setattr("netctl.collect_lock.os.write", attempt_contender_before_publish)

    with CollectLock(db_url):
        assert attempted_contender


def test_collect_lock_rejects_contender_during_partial_write(tmp_path, monkeypatch):
    from netctl.collect_lock import CollectLock, collect_lock_path
    from netctl import collect_lock

    db_url = f"sqlite:///{tmp_path / 'netctl.sqlite'}"
    lock_path = collect_lock_path(db_url)
    monkeypatch.setattr("netctl.collect_lock._process_start_time", lambda pid: "200")
    original_write = collect_lock.os.write
    attempted_contender = False

    def partial_write(fd, data):
        nonlocal attempted_contender
        original_write(fd, data[:1])
        if not attempted_contender:
            attempted_contender = True
            with pytest.raises(RuntimeError, match="collection already running"):
                CollectLock(db_url).__enter__()
        return len(data) - 1

    monkeypatch.setattr("netctl.collect_lock.os.write", partial_write)
    lock = CollectLock(db_url)

    with pytest.raises(OSError, match="write collection lock"):
        lock.__enter__()
    assert attempted_contender
    assert lock.fd is None
    assert not lock_path.exists()


def test_collect_lock_cleans_up_after_write_failure(tmp_path, monkeypatch):
    from netctl.collect_lock import CollectLock, collect_lock_path
    from netctl import collect_lock

    db_url = f"sqlite:///{tmp_path / 'netctl.sqlite'}"
    lock_path = collect_lock_path(db_url)
    monkeypatch.setattr("netctl.collect_lock._process_start_time", lambda pid: "200")
    original_write = collect_lock.os.write
    monkeypatch.setattr(
        "netctl.collect_lock.os.write",
        lambda fd, data: (_ for _ in ()).throw(OSError("disk full")),
    )
    lock = CollectLock(db_url)

    with pytest.raises(OSError, match="disk full"):
        lock.__enter__()
    assert lock.fd is None
    assert not lock_path.exists()

    monkeypatch.setattr("netctl.collect_lock.os.write", original_write)
    with CollectLock(db_url):
        assert lock_path.exists()


def test_collect_lock_guard_rejects_separate_linux_process(tmp_path):
    from netctl import collect_lock
    from netctl.collect_lock import _acquire_recovery_guard, _release_recovery_guard, collect_lock_path

    if collect_lock.fcntl is None:
        pytest.skip("requires Linux fcntl.flock")

    db_url = f"sqlite:///{tmp_path / 'netctl.sqlite'}"
    lock_path = collect_lock_path(db_url)
    lock_path.parent.mkdir(parents=True, exist_ok=True)
    guard_fd = _acquire_recovery_guard(lock_path.with_name(f"{lock_path.name}.recovery"))
    child = "\n".join(
        [
            "from netctl.collect_lock import CollectLock",
            "import sys",
            "try:",
            "    CollectLock(sys.argv[1]).__enter__()",
            "except RuntimeError:",
            "    raise SystemExit(0)",
            "raise SystemExit(1)",
        ]
    )
    try:
        result = subprocess.run(
            [sys.executable, "-c", child, db_url],
            cwd=Path(__file__).resolve().parents[1],
            check=False,
        )
    finally:
        _release_recovery_guard(guard_fd)

    assert result.returncode == 0


def test_collect_lock_recovery_guards_are_isolated_by_path(tmp_path):
    from netctl.collect_lock import _acquire_recovery_guard, _release_recovery_guard

    first_path = tmp_path / "first.lock.recovery"
    second_path = tmp_path / "second.lock.recovery"
    first_fd = _acquire_recovery_guard(first_path)
    try:
        second_fd = _acquire_recovery_guard(second_path)
        try:
            assert second_fd >= 0
        finally:
            _release_recovery_guard(second_fd)
    finally:
        _release_recovery_guard(first_fd)


def test_collect_lock_rejects_retry_collision(tmp_path, monkeypatch):
    from netctl.collect_lock import CollectLock, collect_lock_path
    from netctl import collect_lock

    db_url = f"sqlite:///{tmp_path / 'netctl.sqlite'}"
    lock_path = collect_lock_path(db_url)
    lock_path.parent.mkdir(parents=True, exist_ok=True)
    lock_path.write_text("123 10", encoding="ascii")
    monkeypatch.setattr(
        "netctl.collect_lock._process_start_time",
        lambda pid: None if pid == 123 else "200",
    )
    original_open = collect_lock.os.open
    calls = 0

    def collision_on_retry(path, flags):
        nonlocal calls
        if path == lock_path:
            calls += 1
            if calls == 2:
                raise FileExistsError
        return original_open(path, flags)

    monkeypatch.setattr("netctl.collect_lock.os.open", collision_on_retry)

    with pytest.raises(RuntimeError, match="collection already running"):
        CollectLock(db_url).__enter__()
    assert calls == 2


def test_ipsec_status_reports_source_health(tmp_path, capsys):
    config_path = tmp_path / "netctl.yaml"
    db_url = f"sqlite:///{(tmp_path / 'netctl.sqlite').as_posix()}"
    write_mock_source(config_path)

    rc, data = run_cli(["--json", "--config", str(config_path), "--db", db_url, "ipsec", "status"], capsys)

    assert rc == 0
    assert data["status"] == "ok"
    assert data["summary"] == {"sources": 1, "ok": 1, "warn": 0, "error": 0, "site_checks_ok": 0, "site_checks_warn": 1}
    assert data["sources"][0]["source"] == "mock-main"
    assert data["sources"][0]["status"] == "ok"
    assert data["sources"][0]["summary"]["policies_total"] == 1
    assert data["sources"][0]["summary"]["policies_established"] == 1
    assert data["sources"][0]["policies"][0]["src_address"] == "192.168.100.0/23"
    assert data["sources"][0]["policies"][0]["dst_address"] == "192.168.99.0/24"


def test_ipsec_status_reports_bidirectional_site_checks(tmp_path, capsys):
    config_path = tmp_path / "netctl.yaml"
    db_url = f"sqlite:///{(tmp_path / 'netctl.sqlite').as_posix()}"
    write_mock_ipsec_pair_sources(config_path)

    rc, data = run_cli(["--json", "--config", str(config_path), "--db", db_url, "ipsec", "status"], capsys)

    assert rc == 0
    assert data["summary"]["sources"] == 2
    assert data["summary"]["site_checks_ok"] == 1
    assert data["summary"]["site_checks_warn"] == 0
    assert data["site_checks"] == [
        {
            "status": "ok",
            "network_a": "192.168.100.0/23",
            "network_b": "192.168.99.0/24",
            "directions": [
                {"source": "mock-main", "src_address": "192.168.100.0/23", "dst_address": "192.168.99.0/24", "ph2_count": 1},
                {"source": "mock-hex", "src_address": "192.168.99.0/24", "dst_address": "192.168.100.0/23", "ph2_count": 1},
            ],
        }
    ]


def test_mikrotik_ssh_driver_parses_routeros6_ipsec_without_sensitive_sa(monkeypatch):
    import subprocess

    from netctl.drivers.mikrotik_ssh import MikroTikSshDriver

    calls = []

    def fake_run(command, shell, text, stdout, stderr, timeout, check):
        calls.append(command)
        assert shell is False
        assert "BatchMode=yes" in command
        joined = " ".join(command)
        if "active-peers" in joined:
            out = " 0    local-address=62.148.235.108 port=4500 remote-address=78.29.35.68 port=4500 state=established side=initiator uptime=2h ph2-total=2\\n"
        elif "policy" in joined:
            out = (
                " 0 T  * group=default src-address=::/0 dst-address=::/0 protocol=all proposal=default template=yes\\n"
                " 1   A  peer=ics-asmr-tunnel tunnel=yes src-address=192.168.99.0/24 src-port=any dst-address=192.168.100.0/23 dst-port=any protocol=all action=encrypt level=require ipsec-protocols=esp sa-src-address=62.148.235.108 sa-dst-address=78.29.35.68 proposal=default ph2-count=1 ph2-state=established\\n"
            )
        else:
            out = ""
        return subprocess.CompletedProcess(command, 0, stdout=out, stderr="")

    monkeypatch.setattr(subprocess, "run", fake_run)
    driver = MikroTikSshDriver(
        {
            "name": "mikrotik-hex",
            "host": "192.168.99.1",
            "port": 22,
            "username": "asmr_admin",
            "ssh_identity_file": "/var/lib/netctl/.ssh/m_arhiv_hex_rsa",
            "ssh_proxy_jump": "a2-it-n@192.168.99.176",
        },
        {},
    )

    data = driver.ipsec_status()

    assert data["errors"] == []
    assert data["installed_sas"] == []
    assert data["active_peers"][0]["state"] == "established"
    assert data["policies"][0]["src_address"] == "192.168.99.0/24"
    assert data["policies"][0]["dst_address"] == "192.168.100.0/23"
    assert data["policies"][0]["established"] is True
    assert not any("installed-sa" in " ".join(command) for command in calls)


def test_mikrotik_ssh_driver_tests_routeros6_scalar_sections(monkeypatch):
    import subprocess

    from netctl.drivers.mikrotik_ssh import MikroTikSshDriver

    calls = []

    def fake_run(command, shell, text, stdout, stderr, timeout, check):
        calls.append(command)
        joined = " ".join(command)
        if "/system identity print" in joined:
            out = "  name: m-arhiv\n"
        elif "/system resource print" in joined:
            out = "  version: 6.49.7 (stable)\n  board-name: hEX\n"
        else:
            out = ""
        return subprocess.CompletedProcess(command, 0, stdout=out, stderr="")

    monkeypatch.setattr(subprocess, "run", fake_run)
    driver = MikroTikSshDriver(
        {
            "name": "mikrotik-hex",
            "host": "192.168.99.1",
            "port": 22,
            "username": "asmr_admin",
            "ssh_identity_file": "/var/lib/netctl/.ssh/m_arhiv_hex_rsa",
        },
        {},
    )

    result = driver.test()

    assert result["status"] == "ok"
    assert result["identity"] == "m-arhiv"
    assert result["resource"]["version"] == "6.49.7 (stable)"
    assert result["resource"]["board-name"] == "hEX"
    assert not any("print terse" in " ".join(command) for command in calls)


def test_mikrotik_ssh_collection_uses_scalar_routerboard_print_for_routeros6(monkeypatch):
    import subprocess

    from netctl.drivers.mikrotik_ssh import MikroTikSshDriver

    calls = []

    def fake_run(command, **kwargs):
        calls.append(command)
        return subprocess.CompletedProcess(command, 0, stdout="", stderr="")

    monkeypatch.setattr(subprocess, "run", fake_run)
    driver = MikroTikSshDriver(
        {"name": "mikrotik-hex", "host": "192.168.99.1", "port": 22, "username": "netobserver"},
        {},
    )

    driver.collect()

    routerboard_commands = [command[-1] for command in calls if "/system routerboard print" in command[-1]]
    assert routerboard_commands == ["/system routerboard print"]
