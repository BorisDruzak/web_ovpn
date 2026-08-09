from __future__ import annotations

import json
import threading
from dataclasses import replace
from pathlib import Path
from unittest.mock import Mock


ASSET_KEY = "mac:AA:BB:CC:DD:EE:01"
TARGET_IP = "192.168.100.55"


def _db_url(tmp_path: Path, name: str = "nmap-store.sqlite") -> str:
    return f"sqlite:///{(tmp_path / name).as_posix()}"


def _seed_asset(db_url: str, ip: str = TARGET_IP) -> None:
    from netctl.db import connect

    conn = connect(db_url)
    now = "2026-08-09T08:00:00Z"
    try:
        asset_id = conn.execute(
            """INSERT INTO assets
               (asset_key, identity_method, identity_confidence, provisional,
                first_seen_at, last_seen_at, created_at, updated_at)
               VALUES (?, 'manual', 100, 0, ?, ?, ?, ?)""",
            (ASSET_KEY, now, now, now, now),
        ).lastrowid
        conn.execute(
            """INSERT INTO ip_observations
               (asset_id, source_key, ip, first_seen_at, last_seen_at,
                is_current, observation_source)
               VALUES (?, 'source-a', ?, ?, ?, 1, 'collector_host')""",
            (asset_id, ip, now, now),
        )
        conn.commit()
    finally:
        conn.close()


def _fingerprint(version: str = "7.95"):
    from netctl.nmap.models import NmapFingerprint, NmapOSClass, NmapOSMatch, NmapPort

    return NmapFingerprint(
        nmap_version=version,
        ports=(
            NmapPort(
                protocol="tcp",
                port=22,
                state="open",
                service_name="ssh",
                product="OpenSSH",
                version="9.2p1",
                extra_info="Ubuntu",
                tunnel="",
                method="probed",
                confidence=10,
                cpes=("cpe:/a:openbsd:openssh:9.2p1",),
            ),
        ),
        os_matches=(
            NmapOSMatch(
                name="Linux 6.X",
                accuracy=96,
                classes=(
                    NmapOSClass(
                        type="general purpose",
                        vendor="Linux",
                        osfamily="Linux",
                        osgen="6.X",
                        accuracy=95,
                        cpes=("cpe:/o:linux:linux_kernel:6",),
                    ),
                ),
            ),
        ),
    )


def test_migration_23_creates_bounded_fingerprint_schema(tmp_path: Path) -> None:
    """Without the partial unique index, concurrent ensures can both own a scan."""
    from netctl.db import connect

    conn = connect(_db_url(tmp_path))
    try:
        versions = [int(row[0]) for row in conn.execute(
            "SELECT version FROM schema_migrations ORDER BY version"
        )]
        tables = {str(row[0]) for row in conn.execute(
            "SELECT name FROM sqlite_master WHERE type = 'table'"
        )}
        index_sql = str(conn.execute(
            "SELECT sql FROM sqlite_master WHERE type = 'index' "
            "AND name = 'nmap_fingerprint_runs_one_running_idx'"
        ).fetchone()[0])
        run_columns = {str(row[1]) for row in conn.execute(
            "PRAGMA table_info(nmap_fingerprint_runs)"
        )}
    finally:
        conn.close()

    assert 23 in versions
    assert {
        "nmap_fingerprint_runs",
        "nmap_fingerprint_ports",
        "nmap_fingerprint_os_matches",
    } <= tables
    assert "WHERE status = 'running'" in index_sql
    assert {
        "id",
        "asset_id",
        "target_ip",
        "profile",
        "status",
        "started_at",
        "finished_at",
        "nmap_version",
        "error_class",
        "error_message",
    } <= run_columns
    assert "raw_xml" not in run_columns
    assert "stderr" not in run_columns


def test_ensure_persists_only_normalized_fingerprint_fields(tmp_path: Path) -> None:
    """The database must contain normalized projections, never raw XML or stderr."""
    from netctl.db import connect
    from netctl.nmap.store import ensure_fingerprint

    db_url = _db_url(tmp_path)
    _seed_asset(db_url)
    conn = connect(db_url)
    try:
        result = ensure_fingerprint(
            conn,
            ASSET_KEY,
            executor=lambda ip: _fingerprint(),
            now="2026-08-09T08:00:00Z",
        )
        stored_port = dict(conn.execute("SELECT * FROM nmap_fingerprint_ports").fetchone())
        stored_os = dict(conn.execute("SELECT * FROM nmap_fingerprint_os_matches").fetchone())
    finally:
        conn.close()

    assert result["status"] == "success"
    assert result["fresh"] is True
    assert result["target_ip"] == TARGET_IP
    assert result["ports"][0]["cpes"] == ["cpe:/a:openbsd:openssh:9.2p1"]
    assert result["os_matches"][0]["classes"][0]["osfamily"] == "Linux"
    assert json.loads(stored_port["cpe_json"]) == ["cpe:/a:openbsd:openssh:9.2p1"]
    assert json.loads(stored_os["classes_json"])[0]["osgen"] == "6.X"
    assert not any("xml" in key or "stderr" in key for key in stored_port | stored_os)


def test_ensure_reuses_success_until_ttl_expires_at_the_exact_boundary(
    tmp_path: Path,
) -> None:
    """Repeated card opens inside TTL must not start another Nmap process."""
    from netctl.db import connect
    from netctl.nmap.policy import ASSET_FINGERPRINT_PROFILE
    from netctl.nmap.store import ensure_fingerprint

    db_url = _db_url(tmp_path)
    _seed_asset(db_url)
    conn = connect(db_url)
    executor = Mock(return_value=_fingerprint())
    try:
        first = ensure_fingerprint(
            conn, ASSET_KEY, executor=executor, now="2026-08-09T08:00:00Z"
        )
        fresh = ensure_fingerprint(
            conn, ASSET_KEY, executor=executor, now="2026-08-09T08:59:59Z"
        )
        expired = ensure_fingerprint(
            conn,
            ASSET_KEY,
            executor=executor,
            now="2026-08-09T09:00:00Z",
            profile=replace(ASSET_FINGERPRINT_PROFILE, ttl_seconds=3600),
        )
    finally:
        conn.close()

    assert first["id"] == fresh["id"]
    assert expired["id"] != first["id"]
    assert executor.call_count == 2


def test_ensure_returns_a_nonstale_running_scan_without_executing(tmp_path: Path) -> None:
    """A second web process must join the existing single flight."""
    from netctl.db import connect
    from netctl.nmap.store import ensure_fingerprint

    db_url = _db_url(tmp_path)
    _seed_asset(db_url)
    conn = connect(db_url)
    executor = Mock(side_effect=AssertionError("must not execute"))
    try:
        run_id = conn.execute(
            """INSERT INTO nmap_fingerprint_runs
               (asset_id, target_ip, profile, status, started_at)
               VALUES (1, ?, 'asset-fingerprint-v1', 'running', ?)""",
            (TARGET_IP, "2026-08-09T08:00:00Z"),
        ).lastrowid
        conn.commit()
        result = ensure_fingerprint(
            conn, ASSET_KEY, executor=executor, now="2026-08-09T08:00:59Z"
        )
    finally:
        conn.close()

    assert result["id"] == run_id
    assert result["status"] == "running"
    executor.assert_not_called()


def test_ensure_reclaims_a_stale_running_scan_after_process_crash(tmp_path: Path) -> None:
    """A crashed web process must not leave the asset permanently locked."""
    from netctl.db import connect
    from netctl.nmap.store import ensure_fingerprint

    db_url = _db_url(tmp_path)
    _seed_asset(db_url)
    conn = connect(db_url)
    try:
        old_id = conn.execute(
            """INSERT INTO nmap_fingerprint_runs
               (asset_id, target_ip, profile, status, started_at)
               VALUES (1, ?, 'asset-fingerprint-v1', 'running', ?)""",
            (TARGET_IP, "2026-08-09T08:00:00Z"),
        ).lastrowid
        conn.commit()
        result = ensure_fingerprint(
            conn,
            ASSET_KEY,
            executor=lambda _ip: _fingerprint(),
            now="2026-08-09T08:01:00Z",
        )
        old = dict(conn.execute(
            "SELECT * FROM nmap_fingerprint_runs WHERE id = ?", (old_id,)
        ).fetchone())
    finally:
        conn.close()

    assert result["status"] == "success"
    assert result["id"] != old_id
    assert old["status"] == "failed"
    assert old["error_class"] == "stale_running"
    assert old["error_message"] == "fingerprint run exceeded stale timeout"


def test_current_ip_change_does_not_start_a_second_nonstale_process(
    tmp_path: Path,
) -> None:
    """Target churn must not break the per-asset single-flight guarantee."""
    from netctl.db import connect
    from netctl.nmap.store import ensure_fingerprint

    db_url = _db_url(tmp_path)
    _seed_asset(db_url)
    conn = connect(db_url)
    executor = Mock(side_effect=AssertionError("second scan started"))
    try:
        old_id = conn.execute(
            """INSERT INTO nmap_fingerprint_runs
               (asset_id, target_ip, profile, status, started_at)
               VALUES (1, ?, 'asset-fingerprint-v1', 'running', ?)""",
            (TARGET_IP, "2026-08-09T08:00:00Z"),
        ).lastrowid
        conn.execute("UPDATE ip_observations SET is_current = 0")
        conn.execute(
            """INSERT INTO ip_observations
               (asset_id, source_key, ip, first_seen_at, last_seen_at,
                is_current, observation_source)
               VALUES (1, 'source-b', '192.168.100.56', ?, ?, 1, 'collector_host')""",
            ("2026-08-09T08:00:01Z", "2026-08-09T08:00:01Z"),
        )
        conn.commit()

        result = ensure_fingerprint(
            conn,
            ASSET_KEY,
            executor=executor,
            now="2026-08-09T08:00:01Z",
        )
    finally:
        conn.close()

    assert result["id"] == old_id
    assert result["status"] == "running"
    assert result["target_ip"] == TARGET_IP
    executor.assert_not_called()


def test_two_connections_start_exactly_one_fingerprint_process(tmp_path: Path) -> None:
    """Separate web processes racing on one asset must still be single-flight."""
    from netctl.db import connect
    from netctl.nmap.store import ensure_fingerprint

    db_url = _db_url(tmp_path)
    _seed_asset(db_url)
    started = threading.Event()
    release = threading.Event()
    first_result: list[dict[str, object]] = []
    calls: list[str] = []

    def blocking_executor(ip: str):
        calls.append(ip)
        started.set()
        assert release.wait(5)
        return _fingerprint()

    def first_worker() -> None:
        conn = connect(db_url)
        try:
            first_result.append(
                ensure_fingerprint(
                    conn,
                    ASSET_KEY,
                    executor=blocking_executor,
                    now="2026-08-09T08:00:00Z",
                )
            )
        finally:
            conn.close()

    thread = threading.Thread(target=first_worker)
    thread.start()
    assert started.wait(5)
    second_conn = connect(db_url)
    try:
        second = ensure_fingerprint(
            second_conn,
            ASSET_KEY,
            executor=Mock(side_effect=AssertionError("second scan started")),
            now="2026-08-09T08:00:01Z",
        )
    finally:
        second_conn.close()
        release.set()
        thread.join(5)

    assert not thread.is_alive()
    assert second["status"] == "running"
    assert first_result[0]["status"] == "success"
    assert second["id"] == first_result[0]["id"]
    assert calls == [TARGET_IP]


def test_ensure_does_not_reuse_a_fresh_result_after_current_ip_changes(
    tmp_path: Path,
) -> None:
    """A fresh fingerprint for an old address must not describe the asset's new address."""
    from netctl.db import connect
    from netctl.nmap.store import ensure_fingerprint

    db_url = _db_url(tmp_path)
    _seed_asset(db_url)
    conn = connect(db_url)
    calls: list[str] = []
    try:
        first = ensure_fingerprint(
            conn,
            ASSET_KEY,
            executor=lambda ip: calls.append(ip) or _fingerprint(),
            now="2026-08-09T08:00:00Z",
        )
        conn.execute("UPDATE ip_observations SET is_current = 0")
        conn.execute(
            """INSERT INTO ip_observations
               (asset_id, source_key, ip, first_seen_at, last_seen_at,
                is_current, observation_source)
               VALUES (1, 'source-b', '192.168.100.56', ?, ?, 1, 'collector_host')""",
            ("2026-08-09T08:01:00Z", "2026-08-09T08:01:00Z"),
        )
        conn.commit()
        second = ensure_fingerprint(
            conn,
            ASSET_KEY,
            executor=lambda ip: calls.append(ip) or _fingerprint(),
            now="2026-08-09T08:01:00Z",
        )
    finally:
        conn.close()

    assert first["id"] != second["id"]
    assert calls == ["192.168.100.55", "192.168.100.56"]


def test_ensure_sanitizes_unexpected_executor_errors(tmp_path: Path) -> None:
    """Unexpected exception text must not be persisted or exposed."""
    from netctl.db import connect
    from netctl.nmap.store import ensure_fingerprint

    db_url = _db_url(tmp_path)
    _seed_asset(db_url)
    conn = connect(db_url)
    try:
        result = ensure_fingerprint(
            conn,
            ASSET_KEY,
            executor=lambda _ip: (_ for _ in ()).throw(
                RuntimeError("secret raw stderr and command")
            ),
            now="2026-08-09T08:00:00Z",
        )
        stored = dict(conn.execute(
            "SELECT error_class, error_message FROM nmap_fingerprint_runs"
        ).fetchone())
    finally:
        conn.close()

    assert result["status"] == "failed"
    assert stored == {
        "error_class": "internal_error",
        "error_message": "fingerprint execution failed",
    }
    assert "secret" not in repr(result)
