import json
import re
import sqlite3

import pytest

from netctl.db import connect


NOW = "2026-09-07T10:00:00Z"
LATER = "2026-09-07T10:01:00Z"


@pytest.fixture
def conn(tmp_path):
    connection = connect(f"sqlite:///{(tmp_path / 'snapshot.sqlite').as_posix()}")
    yield connection
    connection.close()


def add_host(conn, ip, *, hostname="", sources=("arp",)):
    conn.execute(
        """INSERT INTO network_hosts
           (ip, hostname, category, status, last_seen_at, tags_json)
           VALUES (?, ?, 'unknown', 'seen', ?, ?)""",
        (ip, hostname, NOW, json.dumps({"sources": sources})),
    )
    conn.commit()


def test_snapshot_sql_filters_match_public_fields_before_decode(conn):
    from netctl.host_snapshot import list_host_snapshot, refresh_host_snapshot

    add_host(conn, "203.0.113.2", sources=("dhcp",))
    add_host(conn, "203.0.113.10", sources=("arp",))
    add_host(conn, "203.0.114.1", sources=("arp",))
    conn.execute("UPDATE network_hosts SET display_name='Named printer', device_type='printer', last_source='router-a', tags_json=? WHERE ip='203.0.113.2'", (json.dumps({"sources": ["dhcp"], "tags": ["office-blue"]}),))
    conn.execute("UPDATE network_hosts SET category='noise' WHERE ip='203.0.113.10'")
    conn.commit()
    refresh_host_snapshot(conn, now=NOW)
    # Poison irrelevant JSON: any post-decode filtering fails immediately.
    conn.execute("UPDATE network_host_current_state SET payload_json='invalid-json' WHERE ip != '203.0.113.2'")
    conn.commit()
    for extra in [
        {"q": " PRINTER "}, {"q": "office-blue"}, {"has_hostname": "yes"},
        {"source": "router-a"}, {"source": "dhcp"}, {"network": "203.0.113.0/25"},
    ]:
        result = list_host_snapshot(conn, {"status": "all", "category": "all", **extra}, 1, 100)
        assert [host["ip"] for host in result["hosts"]] == ["203.0.113.2"]
        assert result["total"] == 1


def test_snapshot_pagination_clamps_page_and_limit(conn):
    from netctl.host_snapshot import list_host_snapshot

    assert list_host_snapshot(conn, {}, -10, 999)["limit"] == 250
    assert list_host_snapshot(conn, {}, 0, 0)["page"] == 1
    assert list_host_snapshot(conn, {}, 0, 0)["limit"] == 1


def test_hosts_cli_pagination_without_writable_prepare(tmp_path, monkeypatch):
    import netctl.cli as cli
    from netctl.host_snapshot import refresh_host_snapshot

    db_url = f"sqlite:///{(tmp_path / 'cli.sqlite').as_posix()}"
    conn = connect(db_url)
    add_host(conn, "203.0.113.10")
    add_host(conn, "203.0.113.2")
    refresh_host_snapshot(conn, now=NOW)
    conn.close()
    monkeypatch.setattr(cli, "prepare_conn", lambda *a: pytest.fail("list opened writable connection"))
    args = cli.build_parser().parse_args(["--db", db_url, "hosts", "list", "--status", "all", "--page", "2", "--limit", "1", "--network", "203.0.113.0/25"])
    rc, data = cli.dispatch(args)
    assert rc == 0
    assert [host["ip"] for host in data["hosts"]] == ["203.0.113.10"]
    assert data["pagination"] == {"page": 2, "limit": 1, "total": 2, "pages": 2}


@pytest.mark.parametrize("command", ["list", "snapshot-status"])
def test_hosts_missing_database_is_pending_without_creating_files(tmp_path, command):
    import netctl.cli as cli

    path = tmp_path / "missing.sqlite"
    args = cli.build_parser().parse_args(["--db", f"sqlite:///{path.as_posix()}", "hosts", command])
    rc, data = cli.dispatch(args)
    assert rc == 0
    assert data["snapshot"] == {"snapshot_id": 0, "generated_at": None, "total_hosts": 0, "duration_ms": 0}
    assert not path.exists()


def test_snapshot_current_status_and_mac_filters_apply_before_decode(conn):
    from netctl.host_snapshot import list_host_snapshot, refresh_host_snapshot

    for number in range(1, 6):
        add_host(conn, f"203.0.113.{number}")
    conn.execute("UPDATE network_hosts SET mac='AA:BB:CC:DD:EE:01' WHERE ip='203.0.113.1'")
    conn.commit()
    refresh_host_snapshot(conn, now=NOW)
    for number, status in enumerate(["online", "seen", "connected", "offline", "stale"], 1):
        conn.execute("UPDATE network_host_current_state SET status=?, payload_json=json_set(payload_json, '$.status', ?) WHERE ip=?", (status, status, f"203.0.113.{number}"))
    conn.execute("UPDATE network_host_current_state SET payload_json='invalid-json' WHERE status IN ('offline', 'stale')")
    conn.commit()
    assert [host["status"] for host in list_host_snapshot(conn, {"status": "current"}, 1, 100)["hosts"]] == ["online", "seen", "connected"]
    assert [host["ip"] for host in list_host_snapshot(conn, {"has_mac": "yes"}, 1, 100)["hosts"]] == ["203.0.113.1"]
    assert list_host_snapshot(conn, {}, 10**100, 100)["hosts"] == []


def test_snapshot_seen_within_and_arbitrary_ipv6_network_filter(conn):
    from datetime import datetime, timezone
    from netctl.host_snapshot import list_host_snapshot, refresh_host_snapshot

    for address in ["2001:db8::2", "2001:db8::10", "2001:db8:1::1"]:
        add_host(conn, address)
    now = datetime.now(timezone.utc).isoformat()
    conn.execute("UPDATE network_hosts SET last_seen_at='2000-01-01T00:00:00Z'")
    conn.execute("UPDATE network_hosts SET last_seen_at=? WHERE ip='2001:db8::2'", (now,))
    conn.commit()
    refresh_host_snapshot(conn, now=now)
    assert [host["ip"] for host in list_host_snapshot(conn, {"status": "all", "network": "2001:db8::/80"}, 1, 100)["hosts"]] == ["2001:db8::2", "2001:db8::10"]
    assert [host["ip"] for host in list_host_snapshot(conn, {"status": "all", "seen_within": "1h"}, 1, 100)["hosts"]] == ["2001:db8::2"]


def test_refresh_publishes_complete_replacement_snapshot(conn):
    from netctl.host_snapshot import refresh_host_snapshot, list_host_snapshot

    add_host(conn, "203.0.113.10")
    first = refresh_host_snapshot(conn, now=NOW)
    conn.execute("DELETE FROM network_hosts")
    conn.commit()
    add_host(conn, "203.0.113.2", hostname="new-host", sources=("dhcp", "arp"))
    second = refresh_host_snapshot(conn, now=LATER)
    page = list_host_snapshot(conn, {"status": "all"}, 1, 50)
    assert second.snapshot_id == first.snapshot_id + 1
    assert second.generated_at == LATER
    assert second.total_hosts == 1
    assert [host["ip"] for host in page["hosts"]] == ["203.0.113.2"]
    assert page["hosts"][0]["hostname"] == "new-host"
    assert {row[0] for row in conn.execute("SELECT source FROM network_host_current_sources")} == {"dhcp", "arp"}


@pytest.mark.parametrize("failure_point", ["_insert_snapshot_rows", "_replace_snapshot_metadata", "build_host_snapshot"])
def test_failed_snapshot_publication_preserves_previous_rows(conn, monkeypatch, failure_point):
    import netctl.host_snapshot as snapshot

    add_host(conn, "203.0.113.10")
    previous = snapshot.refresh_host_snapshot(conn, now=NOW)
    original = snapshot.list_host_snapshot(conn, {"status": "all"}, 1, 50)
    add_host(conn, "203.0.113.2")

    def fail(*args, **kwargs):
        raise sqlite3.OperationalError("private payload must not leak")

    monkeypatch.setattr(snapshot, failure_point, fail)
    with pytest.raises(sqlite3.Error):
        snapshot.refresh_host_snapshot(conn, now=LATER)
    assert snapshot.snapshot_status(conn) == previous
    assert snapshot.list_host_snapshot(conn, {"status": "all"}, 1, 50) == original


def test_snapshot_list_filters_before_numeric_pagination_without_projection(conn, monkeypatch):
    import netctl.host_snapshot as snapshot

    add_host(conn, "203.0.113.10", hostname="ten", sources=("dhcp",))
    add_host(conn, "203.0.113.2", hostname="two", sources=("dhcp",))
    add_host(conn, "203.0.113.1", sources=("arp",))
    snapshot.refresh_host_snapshot(conn, now=NOW)
    conn.execute("PRAGMA query_only = ON")

    def forbidden(*args, **kwargs):
        pytest.fail("listing must only decode the selected stored page")

    monkeypatch.setattr(snapshot, "bulk_project_host_availability", forbidden)
    page = snapshot.list_host_snapshot(conn, {"status": "all", "source": "dhcp", "has_hostname": True}, 1, 1)
    assert page["total"] == 2
    assert page["pages"] == 2
    assert [host["ip"] for host in page["hosts"]] == ["203.0.113.2"]
    assert snapshot.list_host_snapshot(conn, {"status": "all", "q": "TEN"}, 1, 50)["total"] == 1


def test_empty_snapshot_has_metadata_and_can_replace_nonempty_snapshot(conn):
    from netctl.host_snapshot import refresh_host_snapshot, snapshot_status, list_host_snapshot

    assert snapshot_status(conn).snapshot_id == 0
    add_host(conn, "203.0.113.1")
    refresh_host_snapshot(conn, now=NOW)
    conn.execute("DELETE FROM network_hosts")
    conn.commit()
    published = refresh_host_snapshot(conn, now=LATER)
    assert published.snapshot_id == 2
    assert published.total_hosts == 0
    assert list_host_snapshot(conn, {}, 1, 50)["hosts"] == []


def test_refresh_log_does_not_include_failed_payload(conn, monkeypatch, caplog):
    import netctl.host_snapshot as snapshot

    def fail(*args, **kwargs):
        raise ValueError("PRIVATE-CREDENTIAL")

    monkeypatch.setattr(snapshot, "build_host_snapshot", fail)
    with caplog.at_level("INFO"), pytest.raises(ValueError):
        snapshot.refresh_host_snapshot(conn, now=NOW)
    assert "host_snapshot.refresh.start" in caplog.text
    assert "host_snapshot.refresh.error" in caplog.text
    assert "PRIVATE-CREDENTIAL" not in caplog.text


@pytest.mark.parametrize("page, expected_count", [(1, 1), (2, 0)])
def test_snapshot_logs_include_non_sensitive_measurements(conn, caplog, page, expected_count):
    from netctl.host_snapshot import list_host_snapshot, refresh_host_snapshot

    add_host(conn, "203.0.113.1", hostname="private-host", sources=("private-source",))
    with caplog.at_level("INFO", logger="netctl.host_snapshot"):
        refresh_host_snapshot(conn, now=NOW)
        result = list_host_snapshot(conn, {"status": "all", "q": "private-host", "source": "private-source"}, page, 1)

    messages = [record.getMessage() for record in caplog.records if record.name == "netctl.host_snapshot"]
    assert len(result["hosts"]) == expected_count
    assert any(re.fullmatch(r"host_snapshot.refresh.finish id=1 count=1 duration_ms=\d+", message) for message in messages)
    assert any(re.fullmatch(
        rf"host_snapshot.list.finish id=1 count={expected_count} total=1 page={page} limit=1 duration_ms=\d+",
        message,
    ) for message in messages)
    # Only numeric measurements may accompany event names, including raw log arguments.
    for record in caplog.records:
        if record.name == "netctl.host_snapshot":
            assert re.fullmatch(r"host_snapshot\.[a-z.]+(?: (?:id|count|total|page|limit|duration_ms)=\d+)+", record.getMessage())
            assert all(isinstance(value, int) for value in record.args)


def test_partial_insert_failure_restores_both_state_and_sources(conn):
    from netctl.host_snapshot import refresh_host_snapshot, list_host_snapshot

    add_host(conn, "203.0.113.1", sources=("old-source",))
    refresh_host_snapshot(conn, now=NOW)
    previous = list_host_snapshot(conn, {"status": "all"}, 1, 50)
    add_host(conn, "203.0.113.2")
    conn.execute("""CREATE TEMP TRIGGER reject_second_snapshot_host
                    BEFORE INSERT ON network_host_current_state WHEN NEW.ip = '203.0.113.2'
                    BEGIN SELECT RAISE(ABORT, 'insertion rejected'); END""")
    with pytest.raises(sqlite3.IntegrityError):
        refresh_host_snapshot(conn, now=LATER)
    assert list_host_snapshot(conn, {"status": "all"}, 1, 50) == previous
    assert [tuple(row) for row in conn.execute("SELECT snapshot_id, ip, source FROM network_host_current_sources")] == [(1, "203.0.113.1", "old-source")]


@pytest.mark.parametrize("pending_write", [False, True])
def test_refresh_rejects_callers_transaction_without_altering_it(conn, monkeypatch, pending_write):
    import netctl.host_snapshot as snapshot

    add_host(conn, "203.0.113.1")
    snapshot.refresh_host_snapshot(conn, now=NOW)
    conn.execute("BEGIN")
    if pending_write:
        conn.execute("UPDATE network_hosts SET hostname = 'pending-name'")
    else:
        conn.execute("SELECT hostname FROM network_hosts").fetchall()

    def fail(*args, **kwargs):
        pytest.fail("refresh must reject caller transaction before building")

    monkeypatch.setattr(snapshot, "build_host_snapshot", fail)
    with pytest.raises(sqlite3.ProgrammingError, match="requires no active transaction"):
        snapshot.refresh_host_snapshot(conn, now=LATER)
    assert conn.in_transaction
    assert conn.execute("SELECT hostname FROM network_hosts").fetchone()[0] == ("pending-name" if pending_write else "")
    assert snapshot.snapshot_status(conn).snapshot_id == 1
    conn.rollback()


def test_competing_host_comment_write_during_projection_does_not_block_publication(conn, monkeypatch):
    import netctl.host_snapshot as snapshot

    add_host(conn, "203.0.113.1")
    first = snapshot.refresh_host_snapshot(conn, now=NOW)
    path = conn.execute("PRAGMA database_list").fetchone()[2]
    writer = sqlite3.connect(path)
    project = snapshot.bulk_project_host_availability

    def project_with_competing_writer(*args, **kwargs):
        writer.execute("UPDATE network_hosts SET comment = 'concurrent-comment'")
        writer.commit()
        return project(*args, **kwargs)

    monkeypatch.setattr(snapshot, "bulk_project_host_availability", project_with_competing_writer)
    try:
        second = snapshot.refresh_host_snapshot(conn, now=LATER)
        assert second.snapshot_id == first.snapshot_id + 1
        assert not conn.in_transaction
        assert conn.execute("SELECT comment FROM network_hosts").fetchone()[0] == "concurrent-comment"
        page = snapshot.list_host_snapshot(conn, {"status": "all"}, 1, 50)
        assert page["total"] == 1
        # The built payload remains a consistent source snapshot from before the write.
        assert page["hosts"][0]["comment"] is None
    finally:
        writer.close()


def test_separate_reader_sees_old_complete_snapshot_until_publication(conn, monkeypatch):
    import netctl.host_snapshot as snapshot

    add_host(conn, "203.0.113.1")
    snapshot.refresh_host_snapshot(conn, now=NOW)
    path = conn.execute("PRAGMA database_list").fetchone()[2]
    reader = sqlite3.connect(path)
    add_host(conn, "203.0.113.2")
    insert = snapshot._insert_snapshot_rows

    def inspect_during_publication(*args):
        old = snapshot.list_host_snapshot(reader, {"status": "all"}, 1, 50)
        assert old["snapshot"]["snapshot_id"] == 1
        assert old["total"] == 1
        assert [host["ip"] for host in old["hosts"]] == ["203.0.113.1"]
        insert(*args)

    monkeypatch.setattr(snapshot, "_insert_snapshot_rows", inspect_during_publication)
    try:
        snapshot.refresh_host_snapshot(conn, now=LATER)
        assert snapshot.list_host_snapshot(reader, {"status": "all"}, 1, 50)["total"] == 2
    finally:
        reader.close()


def test_migration_upgrades_existing_host_data_and_is_repeatable(conn):
    from netctl.migrations import apply_migrations

    add_host(conn, "203.0.113.1")
    for table in ("network_host_current_sources", "network_host_current_state", "network_host_snapshot_meta"):
        conn.execute(f"DROP TABLE {table}")
    conn.execute("DELETE FROM schema_migrations WHERE version = 26")
    conn.commit()
    apply_migrations(conn)
    apply_migrations(conn)
    assert conn.execute("SELECT ip FROM network_hosts").fetchone()[0] == "203.0.113.1"
    assert conn.execute("SELECT count(*) FROM schema_migrations WHERE version = 26").fetchone()[0] == 1


def test_unpublished_legacy_database_lists_empty_without_migrations():
    from netctl.host_snapshot import list_host_snapshot

    conn = sqlite3.connect(":memory:")
    conn.execute("PRAGMA query_only = ON")
    try:
        page = list_host_snapshot(conn, {}, 1, 50)
        assert page["snapshot"]["snapshot_id"] == 0
        assert page["snapshot"]["generated_at"] is None
        assert page["hosts"] == []
    finally:
        conn.close()


def test_all_source_filter_does_not_hide_hosts(conn):
    from netctl.host_snapshot import refresh_host_snapshot, list_host_snapshot

    add_host(conn, "203.0.113.1")
    refresh_host_snapshot(conn, now=NOW)
    assert list_host_snapshot(conn, {"status": "all", "source": "all"}, 1, 50)["total"] == 1


def test_numeric_sort_handles_ipv6_and_invalid_legacy_ips(conn):
    from netctl.host_snapshot import refresh_host_snapshot, list_host_snapshot

    for ip in ("invalid-z", "2001:db8::10", "203.0.113.10", "invalid-a", "2001:db8::2", "203.0.113.2"):
        add_host(conn, ip)
    refresh_host_snapshot(conn, now=NOW)
    page = list_host_snapshot(conn, {"status": "all"}, 1, 50)
    assert [host["ip"] for host in page["hosts"]] == [
        "203.0.113.2", "203.0.113.10", "2001:db8::2", "2001:db8::10", "invalid-a", "invalid-z",
    ]
