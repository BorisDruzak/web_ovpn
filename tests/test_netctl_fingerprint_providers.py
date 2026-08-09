from __future__ import annotations

import json
import sqlite3
from pathlib import Path

import pytest


OUI_FIXTURE = Path(__file__).parent / "fixtures" / "nmap-mac-prefixes"


def _db(tmp_path: Path) -> sqlite3.Connection:
    from netctl.db import connect

    return connect(f"sqlite:///{(tmp_path / 'fingerprint.sqlite').as_posix()}")


def _asset(
    conn: sqlite3.Connection,
    *,
    mac: str = "00:11:22:AA:BB:CC",
    hostname: str = "",
    kind: str = "unknown",
) -> int:
    now = "2026-08-09T08:00:00Z"
    asset_id = int(
        conn.execute(
            """INSERT INTO assets
               (asset_key, identity_method, kind, identity_confidence, provisional,
                first_seen_at, last_seen_at, created_at, updated_at)
               VALUES (?, 'manual', ?, 100, 0, ?, ?, ?, ?)""",
            (f"mac:{mac}", kind, now, now, now, now),
        ).lastrowid
    )
    conn.execute(
        """INSERT INTO asset_interfaces
           (asset_id, interface_key, mac, first_seen_at, last_seen_at)
           VALUES (?, 'eth0', ?, ?, ?)""",
        (asset_id, mac, now, now),
    )
    conn.execute(
        """INSERT INTO ip_observations
           (asset_id, source_key, ip, first_seen_at, last_seen_at,
            is_current, observation_source)
           VALUES (?, 'dhcp', '192.0.2.55', ?, ?, 1, 'collector_host')""",
        (asset_id, now, now),
    )
    if hostname:
        conn.execute(
            """INSERT INTO hostname_observations
               (asset_id, hostname, source_key, source_type, first_seen_at,
                last_seen_at, is_current)
               VALUES (?, ?, 'dhcp', 'mikrotik_dhcp', ?, ?, 1)""",
            (asset_id, hostname, now, now),
        )
    conn.commit()
    return asset_id


def _nmap_success(
    conn: sqlite3.Connection,
    asset_id: int,
    *,
    service_name: str = "",
    product: str = "",
    os_type: str = "",
    osfamily: str = "",
    service_confidence: int = 10,
    service_method: str = "probed",
    os_accuracy: int = 95,
) -> None:
    run_id = int(
        conn.execute(
            """INSERT INTO nmap_fingerprint_runs
               (asset_id, target_ip, profile, status, started_at, finished_at)
               VALUES (?, '192.0.2.55', 'asset-fingerprint-v1', 'success', ?, ?)""",
            (asset_id, "2026-08-09T08:00:00Z", "2026-08-09T08:00:01Z"),
        ).lastrowid
    )
    if service_name or product:
        conn.execute(
            """INSERT INTO nmap_fingerprint_ports
               (run_id, protocol, port, state, service_name, product, method,
                confidence)
               VALUES (?, 'tcp', 554, 'open', ?, ?, ?, ?)""",
            (run_id, service_name, product, service_method, service_confidence),
        )
    if os_type or osfamily:
        classes = [{
            "type": os_type,
            "vendor": "Microsoft" if osfamily == "Windows" else "",
            "osfamily": osfamily,
            "osgen": "11" if osfamily == "Windows" else "",
            "accuracy": os_accuracy,
            "cpes": [],
        }]
        conn.execute(
            """INSERT INTO nmap_fingerprint_os_matches
               (run_id, position, name, accuracy, classes_json)
               VALUES (?, 0, 'fixture os', ?, ?)""",
            (run_id, os_accuracy, json.dumps(classes)),
        )
    conn.commit()


def _switch_source(conn: sqlite3.Connection, source_id: int = 10) -> int:
    now = "2026-08-09T08:00:00Z"
    conn.execute(
        """INSERT INTO network_sources
           (id, name, driver, host, port, username, secret_ref, tls, verify_tls,
            enabled, created_at, updated_at)
           VALUES (?, ?, 'snmp_switch', '192.0.2.10', 161, '', 'env:TEST',
                   0, 0, 1, ?, ?)""",
        (source_id, f"switch-{source_id}", now, now),
    )
    return source_id


def test_oui_database_is_local_cached_and_missing_file_is_graceful(
    tmp_path: Path,
) -> None:
    """A card lookup must neither require the file twice nor use a network fallback."""
    from netctl.fingerprint.oui import OUIDatabase

    fixture = tmp_path / "nmap-mac-prefixes"
    fixture.write_text("AABBCC Fixture Vendor\n", encoding="utf-8")
    database = OUIDatabase(fixture)

    assert database.lookup("AA:BB:CC:00:00:01") == "Fixture Vendor"
    fixture.unlink()
    assert database.lookup("AA:BB:CC:00:00:02") == "Fixture Vendor"
    assert OUIDatabase(tmp_path / "missing").lookup("AA:BB:CC:00:00:01") == ""


def test_hikvision_oui_and_nmap_rtsp_product_classify_camera(tmp_path: Path) -> None:
    """Dropping either DB provider would leave this normal camera below high confidence."""
    from netctl.fingerprint.engine import classify_evidence
    from netctl.fingerprint.providers import collect_asset_evidence

    conn = _db(tmp_path)
    try:
        asset_id = _asset(conn)
        _nmap_success(conn, asset_id, service_name="rtsp", product="Hikvision camera")

        result = classify_evidence(
            collect_asset_evidence(conn, asset_id, oui_path=OUI_FIXTURE)
        )
    finally:
        conn.close()

    assert result.device_type == "camera"
    assert result.confidence == 100
    assert {(item.provider, item.signal, item.weight) for item in result.evidence} >= {
        ("oui", "hikvision", 50),
        ("nmap_service", "camera_product", 60),
    }


def test_grandstream_oui_and_matching_lldp_telephone_classify_phone(
    tmp_path: Path,
) -> None:
    """LLDP must be joined to the asset MAC before its strong capability is used."""
    from netctl.fingerprint.engine import classify_evidence
    from netctl.fingerprint.providers import collect_asset_evidence

    conn = _db(tmp_path)
    try:
        asset_id = _asset(conn, mac="10:20:30:AA:BB:CC")
        source_id = _switch_source(conn)
        run_id = int(
            conn.execute(
                """INSERT INTO switch_collection_runs
                   (source_id, started_at, finished_at, status)
                   VALUES (?, ?, ?, 'success')""",
                (source_id, "2026-08-09T08:00:00Z", "2026-08-09T08:00:01Z"),
            ).lastrowid
        )
        conn.execute(
            """INSERT INTO current_switch_lldp_neighbors
               (source_id, local_port_key, chassis_id, port_id, system_name,
                observed_at, collector_run_id, chassis_id_subtype,
                system_capabilities_json, enabled_capabilities_json)
               VALUES (?, 'physical:7', '10:20:30:AA:BB:CC', 'eth0', 'desk-phone',
                       ?, ?, 'mac_address', '[\"telephone\"]', '[\"telephone\"]')""",
            (source_id, "2026-08-09T08:00:01Z", run_id),
        )
        conn.commit()

        result = classify_evidence(
            collect_asset_evidence(conn, asset_id, oui_path=OUI_FIXTURE)
        )
    finally:
        conn.close()

    assert result.device_type == "phone"
    assert result.confidence == 100


def test_known_snmp_switch_identity_beats_conflicting_weak_raw_kind(
    tmp_path: Path,
) -> None:
    """The raw assets.kind column must remain evidence, never the final authority."""
    from netctl.fingerprint.engine import classify_evidence
    from netctl.fingerprint.providers import collect_asset_evidence

    conn = _db(tmp_path)
    try:
        asset_id = _asset(conn, kind="phone")
        source_id = _switch_source(conn)
        conn.execute(
            """INSERT INTO switch_devices
               (source_id, runtime_asset_id, updated_at)
               VALUES (?, ?, '2026-08-09T08:00:00Z')""",
            (source_id, asset_id),
        )
        conn.commit()

        result = classify_evidence(
            collect_asset_evidence(conn, asset_id, oui_path=OUI_FIXTURE)
        )
    finally:
        conn.close()

    assert result.device_type == "network"
    assert result.confidence == 100


def test_known_snmp_switch_and_nmap_network_class_are_both_explainable(
    tmp_path: Path,
) -> None:
    """Nmap must contribute medium evidence without replacing SNMP authority."""
    from netctl.fingerprint.engine import classify_evidence
    from netctl.fingerprint.providers import collect_asset_evidence

    conn = _db(tmp_path)
    try:
        asset_id = _asset(conn, mac="AA:BB:CC:DD:EE:01")
        source_id = _switch_source(conn)
        conn.execute(
            """INSERT INTO switch_devices
               (source_id, runtime_asset_id, updated_at)
               VALUES (?, ?, '2026-08-09T08:00:00Z')""",
            (source_id, asset_id),
        )
        _nmap_success(
            conn,
            asset_id,
            os_type="network device",
            osfamily="Cisco IOS",
        )

        result = classify_evidence(
            collect_asset_evidence(conn, asset_id, oui_path=OUI_FIXTURE)
        )
    finally:
        conn.close()

    assert result.device_type == "network"
    assert result.confidence == 100
    assert {(item.provider, item.weight) for item in result.evidence} >= {
        ("snmp", 100),
        ("nmap_os", 70),
    }


def test_windows_nmap_os_and_pc_hostname_choose_pc_over_server(tmp_path: Path) -> None:
    """Windows general-purpose evidence needs a weak endpoint hint to resolve PC/server."""
    from netctl.fingerprint.engine import classify_evidence
    from netctl.fingerprint.providers import collect_asset_evidence

    conn = _db(tmp_path)
    try:
        asset_id = _asset(conn, mac="AA:BB:CC:DD:EE:01", hostname="pc-finance-01")
        _nmap_success(conn, asset_id, os_type="general purpose", osfamily="Windows")

        result = classify_evidence(
            collect_asset_evidence(conn, asset_id, oui_path=OUI_FIXTURE)
        )
    finally:
        conn.close()

    assert result.device_type == "pc"
    assert result.confidence == 60
    assert {item.candidate_type for item in result.evidence if item.provider == "nmap_os"} == {
        "pc",
        "server",
    }


def test_generic_hp_oui_alone_does_not_force_printer(tmp_path: Path) -> None:
    """A multi-product vendor must not be treated as a device classification shortcut."""
    from netctl.fingerprint.engine import classify_evidence
    from netctl.fingerprint.providers import collect_asset_evidence

    conn = _db(tmp_path)
    try:
        asset_id = _asset(conn, mac="20:30:40:AA:BB:CC")
        result = classify_evidence(
            collect_asset_evidence(conn, asset_id, oui_path=OUI_FIXTURE)
        )
    finally:
        conn.close()

    assert result.device_type == "unknown"
    assert not any(item.provider == "oui" for item in result.evidence)


def test_port_role_is_modest_and_downstream_bridge_is_not_switch_identity() -> None:
    """Topology attachment role must not be promoted into authoritative identity."""
    from netctl.fingerprint.providers import port_role_evidence

    endpoint = port_role_evidence("endpoint")

    assert {item.candidate_type for item in endpoint} == {
        "pc",
        "phone",
        "camera",
        "printer",
        "server",
    }
    assert max(item.weight for item in endpoint) <= 10
    assert port_role_evidence("downstream_bridge") == ()


def test_confirmed_endpoint_agent_device_type_is_strong_typed_evidence() -> None:
    """Losing the confirmation gate could let ambiguous agent records classify assets."""
    from netctl.fingerprint.providers import endpoint_agent_evidence

    assert endpoint_agent_evidence({"state": "ambiguous", "device_type": "pc"}) == ()
    [item] = endpoint_agent_evidence({"state": "confirmed", "device_type": "pc"})
    assert (item.provider, item.signal, item.candidate_type, item.weight) == (
        "endpoint_agent",
        "device_type",
        "pc",
        100,
    )


@pytest.mark.parametrize("os_family", ["Cisco IOS", "Cisco IOS XE", "NX-OS"])
def test_endpoint_agent_network_operating_systems_are_not_apple_phones(
    os_family: str,
) -> None:
    """The IOS token is ambiguous; Cisco network families must win explicitly."""
    from netctl.fingerprint.providers import endpoint_agent_evidence

    [item] = endpoint_agent_evidence(
        {"state": "confirmed", "os_family": os_family}
    )

    assert (item.candidate_type, item.weight) == ("network", 90)


@pytest.mark.parametrize("os_family", ["Apple iOS", "iOS", "iPadOS"])
def test_endpoint_agent_apple_mobile_operating_systems_are_phones(
    os_family: str,
) -> None:
    from netctl.fingerprint.providers import endpoint_agent_evidence

    [item] = endpoint_agent_evidence(
        {"state": "confirmed", "os_family": os_family}
    )

    assert (item.candidate_type, item.weight) == ("phone", 90)


def test_confirmed_endpoint_agent_evidence_round_trips_through_db_recompute(
    tmp_path: Path,
) -> None:
    """A standalone converter is insufficient if reconciliation cannot read the evidence."""
    from netctl.fingerprint.providers import (
        current_asset_fingerprint,
        recompute_asset_fingerprint,
        store_endpoint_agent_evidence,
    )

    conn = _db(tmp_path)
    try:
        asset_id = _asset(conn, mac="AA:BB:CC:DD:EE:01", kind="network")
        store_endpoint_agent_evidence(
            conn,
            asset_id,
            {"state": "confirmed", "device_type": "pc", "os_family": "Windows"},
            observed_at="2026-08-09T08:00:00Z",
        )
        recompute_asset_fingerprint(
            conn, asset_id, computed_at="2026-08-09T08:00:01Z", oui_path=OUI_FIXTURE
        )
        conn.commit()
        confirmed = current_asset_fingerprint(conn, asset_id)

        store_endpoint_agent_evidence(
            conn,
            asset_id,
            {"state": "ambiguous", "device_type": "pc"},
            observed_at="2026-08-09T08:01:00Z",
        )
        recompute_asset_fingerprint(
            conn, asset_id, computed_at="2026-08-09T08:01:01Z", oui_path=OUI_FIXTURE
        )
        conn.commit()
        ambiguous = current_asset_fingerprint(conn, asset_id)
    finally:
        conn.close()

    assert confirmed is not None
    assert confirmed["device_type"] == "pc"
    assert confirmed["confidence"] == 100
    assert ambiguous is not None
    assert ambiguous["device_type"] == "unknown"
    assert not any(
        item["provider"] == "endpoint_agent" for item in ambiguous["evidence"]
    )


def test_endpoint_agent_sync_atomically_replaces_evidence_and_recomputes(
    tmp_path: Path,
) -> None:
    """The ingestion boundary must clear stale links and leave V2 current."""
    from netctl.fingerprint.providers import (
        current_asset_fingerprint,
        replace_endpoint_agent_evidence,
    )

    conn = _db(tmp_path)
    try:
        pc_id = _asset(conn, mac="AA:BB:CC:DD:EE:01")
        stale_id = _asset(conn, mac="AA:BB:CC:DD:EE:02")
        conn.execute(
            """INSERT INTO asset_endpoint_agent_evidence_current
               (asset_id, device_type, os_family, observed_at)
               VALUES (?, 'phone', '', '2026-08-09T07:00:00Z')""",
            (stale_id,),
        )
        conn.commit()

        result = replace_endpoint_agent_evidence(
            conn,
            [
                {
                    "asset_key": "mac:AA:BB:CC:DD:EE:01",
                    "state": "confirmed",
                    "device_type": "pc",
                    "os_family": "Windows",
                },
                {
                    "asset_key": "mac:AA:BB:CC:DD:EE:02",
                    "state": "no_agent",
                },
            ],
            observed_at="2026-08-09T08:02:00Z",
            oui_path=OUI_FIXTURE,
        )
        stored_rows = conn.execute(
            """SELECT asset_id, device_type FROM asset_endpoint_agent_evidence_current
               ORDER BY asset_id"""
        ).fetchall()
        pc = current_asset_fingerprint(conn, pc_id)
        stale = current_asset_fingerprint(conn, stale_id)
    finally:
        conn.close()

    assert result == {"assets": 2, "confirmed": 1, "fingerprints": 2}
    assert [(row["asset_id"], row["device_type"]) for row in stored_rows] == [
        (pc_id, "pc")
    ]
    assert pc is not None and pc["device_type"] == "pc"
    assert stale is not None and stale["device_type"] == "unknown"


def test_low_quality_nmap_matches_do_not_receive_full_medium_weights(
    tmp_path: Path,
) -> None:
    """One-percent Nmap guesses must not decide a device type at weight 60/70."""
    from netctl.fingerprint.providers import collect_asset_evidence

    conn = _db(tmp_path)
    try:
        asset_id = _asset(conn, mac="AA:BB:CC:DD:EE:01")
        _nmap_success(
            conn,
            asset_id,
            service_name="rtsp",
            product="Hikvision camera",
            os_type="network device",
            osfamily="Cisco IOS",
            service_confidence=1,
            os_accuracy=1,
        )

        evidence = collect_asset_evidence(conn, asset_id, oui_path=OUI_FIXTURE)
    finally:
        conn.close()

    assert not any(item.provider in {"nmap_service", "nmap_os"} for item in evidence)


def test_nmap_table_service_hint_is_weaker_than_a_probed_product(tmp_path: Path) -> None:
    """A port-table service name must not receive the probed-product weight."""
    from netctl.fingerprint.providers import collect_asset_evidence

    conn = _db(tmp_path)
    try:
        asset_id = _asset(conn, mac="AA:BB:CC:DD:EE:01")
        _nmap_success(
            conn,
            asset_id,
            service_name="rtsp",
            service_confidence=10,
            service_method="table",
        )

        evidence = collect_asset_evidence(conn, asset_id, oui_path=OUI_FIXTURE)
    finally:
        conn.close()

    [hint] = [item for item in evidence if item.provider == "nmap_service"]
    assert hint.weight == 40


def test_recompute_persists_v2_without_overwriting_raw_asset_kind(tmp_path: Path) -> None:
    """Derived classification must remain separate from the raw runtime identity."""
    from netctl.fingerprint.providers import (
        current_asset_fingerprint,
        recompute_asset_fingerprint,
    )

    conn = _db(tmp_path)
    try:
        asset_id = _asset(conn, mac="AA:BB:CC:DD:EE:01", kind="printer")
        _nmap_success(conn, asset_id, service_name="routeros", product="MikroTik RouterOS")

        result = recompute_asset_fingerprint(
            conn,
            asset_id,
            computed_at="2026-08-09T08:00:02Z",
            oui_path=OUI_FIXTURE,
        )
        conn.commit()
        stored = current_asset_fingerprint(conn, asset_id)
        raw_kind = conn.execute(
            "SELECT kind FROM assets WHERE id = ?", (asset_id,)
        ).fetchone()[0]
    finally:
        conn.close()

    assert result.device_type == "network"
    assert raw_kind == "printer"
    assert stored is not None
    assert stored["device_type"] == "network"
    assert stored["confidence"] == 60
    assert stored["fingerprint_version"] == "fingerprint-v2"
    assert stored["computed_at"] == "2026-08-09T08:00:02Z"
    assert stored["evidence"][0].keys() == {
        "provider", "signal", "candidate_type", "weight", "summary"
    }


def test_successful_nmap_finalization_recomputes_v2_for_only_that_asset(
    tmp_path: Path,
) -> None:
    """Committing normalized Nmap rows without refreshing V2 would leave stale cards."""
    from netctl.fingerprint.providers import current_asset_fingerprint
    from netctl.nmap.models import NmapFingerprint, NmapPort
    from netctl.nmap.store import ensure_fingerprint

    conn = _db(tmp_path)
    try:
        asset_id = _asset(conn, kind="unknown")
        other_id = _asset(conn, mac="AA:BB:CC:DD:EE:02", kind="unknown")
        result = ensure_fingerprint(
            conn,
            "mac:00:11:22:AA:BB:CC",
            executor=lambda _ip: NmapFingerprint(
                nmap_version="7.95",
                ports=(
                    NmapPort(
                        protocol="tcp",
                        port=554,
                        state="open",
                        service_name="rtsp",
                        product="Hikvision camera",
                        version="",
                        extra_info="",
                        tunnel="",
                        method="probed",
                        confidence=10,
                        cpes=(),
                    ),
                ),
                os_matches=(),
            ),
            now="2026-08-09T08:00:01Z",
        )
        current = current_asset_fingerprint(conn, asset_id)
        other = current_asset_fingerprint(conn, other_id)
    finally:
        conn.close()

    assert result["status"] == "success"
    assert current is not None
    assert current["device_type"] == "camera"
    assert current["fingerprint_version"] == "fingerprint-v2"
    assert other is None
