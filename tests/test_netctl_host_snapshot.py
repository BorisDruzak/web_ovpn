import json
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
