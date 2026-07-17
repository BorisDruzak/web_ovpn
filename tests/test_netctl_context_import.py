from __future__ import annotations

from copy import deepcopy
import hashlib
import json
from pathlib import Path
import sqlite3
from typing import Any

import pytest
import yaml


def import_document() -> dict[str, object]:
    return {
        "schema_version": "2.2.0",
        "metadata": {"context_id": "test-network"},
        "sites": [{"id": "central"}],
        "locations": [{"id": "central-rack"}],
        "segments": [{"id": "central-lan"}],
        "devices": [{"id": "router"}, {"id": "switch"}],
        "services": [{"id": "web"}],
        "links": [
            {
                "id": "router-switch",
                "relation": "CONNECTED_TO",
                "confidence": 100,
                "endpoint_a": {"device": "router", "interface": "ether1"},
                "endpoint_b": {"device": "switch", "interface": "ether1"},
            },
            {
                "id": "switch-router",
                "relation": "CONNECTED_TO",
                "confidence": 100,
                "endpoint_a": {"device": "switch", "interface": "ether2"},
                "endpoint_b": {"device": "router", "interface": "ether2"},
            },
        ],
    }


RUNTIME_TABLES = (
    "network_sources",
    "collection_runs",
    "network_hosts",
    "network_device_tags",
    "host_observations",
    "network_interfaces",
    "network_routes",
    "dhcp_leases",
    "arp_entries",
    "bridge_hosts",
    "network_neighbors",
    "network_events",
)

REPRESENTATIVE_RUNTIME_TABLES = (
    "network_hosts",
    "host_observations",
)


def raw_document(document: dict[str, object]) -> bytes:
    return json.dumps(document, ensure_ascii=False, sort_keys=True).encode("utf-8")


def run_cli(args: list[str], capsys: pytest.CaptureFixture[str]) -> tuple[int, dict[str, Any]]:
    from netctl.cli import main

    rc = main(args)
    captured = capsys.readouterr()
    assert captured.err == ""
    return rc, json.loads(captured.out)


def connect_import_db(tmp_path: Path) -> sqlite3.Connection:
    from netctl.db import connect

    return connect(f"sqlite:///{(tmp_path / 'netctl.sqlite').as_posix()}")


def runtime_counts(conn: sqlite3.Connection) -> dict[str, int]:
    return {
        table: int(conn.execute(f"SELECT COUNT(*) FROM {table}").fetchone()[0])
        for table in RUNTIME_TABLES
    }


def representative_runtime_rows(conn: sqlite3.Connection) -> dict[str, list[tuple[object, ...]]]:
    return {
        table: [tuple(row) for row in conn.execute(f"SELECT * FROM {table} ORDER BY id")]
        for table in REPRESENTATIVE_RUNTIME_TABLES
    }


def seed_representative_runtime_rows(conn: sqlite3.Connection) -> None:
    host = conn.execute(
        """
        INSERT INTO network_hosts
            (ip, mac, hostname, display_name, category, device_key, device_type,
             device_confidence, device_evidence_json, status, site, first_seen_at,
             last_seen_at, last_source, tags_json, comment)
        VALUES
            (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        """,
        (
            "192.0.2.10",
            "00:11:22:33:44:55",
            "observed-router",
            "Observed Router",
            "network",
            "router-192-0-2-10",
            "router",
            87,
            '{"source":"test"}',
            "up",
            "central",
            "2026-07-17T00:00:00Z",
            "2026-07-17T00:01:00Z",
            "test-source",
            '["managed","observed"]',
            "seeded runtime row",
        ),
    )
    conn.execute(
        """
        INSERT INTO host_observations
            (host_id, source_id, observed_at, observation_type, ip, mac, hostname,
             interface, data_json)
        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
        """,
        (
            host.lastrowid,
            None,
            "2026-07-17T00:02:00Z",
            "arp",
            "192.0.2.10",
            "00:11:22:33:44:55",
            "observed-router",
            "ether1",
            '{"vlan":10,"source":"test"}',
        ),
    )
    conn.commit()


def intent_count(conn: sqlite3.Connection) -> int:
    from netctl.context import IMPORT_COLLECTIONS

    return sum(
        int(conn.execute(f"SELECT COUNT(*) FROM {table}").fetchone()[0])
        for table, _entity_type in IMPORT_COLLECTIONS.values()
    )


def intent_rows_by_table(conn: sqlite3.Connection) -> dict[str, list[tuple[object, ...]]]:
    from netctl.context import IMPORT_COLLECTIONS

    return {
        table: [tuple(row) for row in conn.execute(f"SELECT * FROM {table} ORDER BY id")]
        for table, _entity_type in IMPORT_COLLECTIONS.values()
    }


@pytest.mark.parametrize(
    ("mutate", "expected"),
    [
        (lambda document: document["devices"].append({"id": "router"}), ("devices.2.id", "duplicate id 'router'")),
        (lambda document: document["links"][0].update(relation="UNKNOWN"), ("links.0.relation", "unsupported relation 'UNKNOWN'")),
        (lambda document: document["links"][0].update(relation=[]), ("links.0.relation", "unsupported relation []")),
        (lambda document: document["links"][0].update(confidence=True), ("links.0.confidence", "confidence must be an integer from 0 to 100")),
        (lambda document: document["links"][0].update(confidence=-1), ("links.0.confidence", "confidence must be an integer from 0 to 100")),
        (lambda document: document["links"][0].update(confidence=101), ("links.0.confidence", "confidence must be an integer from 0 to 100")),
        (lambda document: document["links"][0].update(endpoint_a="router"), ("links.0.endpoint_a", "endpoint must be an object")),
        (lambda document: document["links"][0]["endpoint_a"].update(device="  "), ("links.0.endpoint_a.device", "device must be a non-blank string")),
        (lambda document: document["links"][0]["endpoint_a"].update(interface="  "), ("links.0.endpoint_a.interface", "interface must be a non-blank string when present")),
        (lambda document: document["links"][0]["endpoint_a"].update(device="missing"), ("links.0.endpoint_a.device", "unknown device 'missing'")),
    ],
    ids=[
        "duplicate-imported-id",
        "unsupported-relation",
        "non-string-relation",
        "boolean-confidence",
        "negative-confidence",
        "confidence-above-100",
        "non-object-endpoint",
        "blank-endpoint-device",
        "blank-endpoint-interface",
        "unknown-endpoint-device",
    ],
)
def test_validate_import_semantics_rejects_invalid_import_entities(mutate: object, expected: tuple[str, str]) -> None:
    from netctl.context import validate_import_semantics

    document = import_document()
    mutate(document)  # type: ignore[operator]

    assert expected in {(error["path"], error["message"]) for error in validate_import_semantics(document)}


def test_validate_import_semantics_allows_ids_reused_in_different_collections() -> None:
    from netctl.context import validate_import_semantics

    document = import_document()
    document["devices"] = [{"id": "central"}]
    document["links"] = []

    assert validate_import_semantics(document) == []


def test_canonical_entity_hash_ignores_mapping_key_order() -> None:
    from netctl.context import canonical_entity_hash, canonical_entity_json

    first = {"id": "router", "metadata": {"role": "edge", "site": "central"}}
    second = {"metadata": {"site": "central", "role": "edge"}, "id": "router"}

    assert canonical_entity_json(first) == canonical_entity_json(second)
    assert canonical_entity_hash(first) == canonical_entity_hash(second)


def test_normalise_import_entities_ignores_top_level_import_collection_order() -> None:
    from netctl.context import normalise_import_entities

    first = import_document()
    second = deepcopy(first)
    second["devices"] = list(reversed(second["devices"]))
    second["links"] = list(reversed(second["links"]))

    assert normalise_import_entities(first) == normalise_import_entities(second)


def test_import_runs_are_distinct_attempts_for_one_immutable_revision(tmp_path: Path) -> None:
    from netctl.db import (
        connect,
        create_context_import_run,
        finish_context_import_run,
        record_context_revision,
    )

    conn = connect(f"sqlite:///{(tmp_path / 'netctl.sqlite').as_posix()}")
    try:
        revision = record_context_revision(
            conn,
            {"context_id": "test-network", "schema_version": "2.2.0", "sha256": "a" * 64, "counts": {}},
            tmp_path / "network.yaml",
            "validation-git-sha",
        )
        first = create_context_import_run(
            conn,
            context_id="test-network",
            context_revision_id=revision["id"],
            base_context_revision_id=None,
            input_sha256="a" * 64,
            git_sha="first-import-git-sha",
            source_path=tmp_path / "network.yaml",
        )
        second = create_context_import_run(
            conn,
            context_id="test-network",
            context_revision_id=revision["id"],
            base_context_revision_id=None,
            input_sha256="a" * 64,
            git_sha="second-import-git-sha",
            source_path=tmp_path / "network.yaml",
        )
        finished = finish_context_import_run(conn, second["id"], "success_noop_same_content", [])

        assert first["id"] != second["id"]
        assert first["git_sha"] == "first-import-git-sha"
        assert finished["git_sha"] == "second-import-git-sha"
        assert finished["status"] == "success_noop_same_content"
        assert conn.execute("SELECT COUNT(*) FROM context_import_runs").fetchone()[0] == 2
        assert conn.in_transaction
        conn.commit()
    finally:
        conn.close()


def test_context_head_is_only_persisted_through_head_helpers(tmp_path: Path) -> None:
    from netctl.db import connect, create_context_import_run, get_context_head, record_context_revision, set_context_head

    conn = connect(f"sqlite:///{(tmp_path / 'netctl.sqlite').as_posix()}")
    try:
        revision = record_context_revision(
            conn,
            {"context_id": "test-network", "schema_version": "2.2.0", "sha256": "a" * 64, "counts": {}},
            tmp_path / "network.yaml",
            "validation-git-sha",
        )
        run = create_context_import_run(
            conn,
            context_id="test-network",
            context_revision_id=revision["id"],
            base_context_revision_id=None,
            input_sha256="a" * 64,
            git_sha="import-git-sha",
            source_path=tmp_path / "network.yaml",
        )

        assert get_context_head(conn, "test-network") is None
        head = set_context_head(conn, "test-network", revision["id"], run["id"])

        assert head["context_id"] == "test-network"
        assert head["context_revision_id"] == revision["id"]
        assert head["activated_by_import_run_id"] == run["id"]
        conn.commit()
    finally:
        conn.close()


def test_context_import_run_can_only_finish_once(tmp_path: Path) -> None:
    from netctl.db import connect, create_context_import_run, finish_context_import_run

    conn = connect(f"sqlite:///{(tmp_path / 'netctl.sqlite').as_posix()}")
    try:
        run = create_context_import_run(
            conn,
            context_id="test-network",
            context_revision_id=None,
            base_context_revision_id=None,
            input_sha256="a" * 64,
            git_sha="import-git-sha",
            source_path=tmp_path / "network.yaml",
        )
        finish_context_import_run(conn, run["id"], "validation_error", [{"path": "metadata", "message": "invalid"}])
        before = conn.execute(
            "SELECT status, errors_json, finished_at FROM context_import_runs WHERE id = ?", (run["id"],)
        ).fetchone()

        with pytest.raises(ValueError, match="not running"):
            finish_context_import_run(conn, run["id"], "db_error", [{"path": "database", "message": "overwritten"}])

        after = conn.execute(
            "SELECT status, errors_json, finished_at FROM context_import_runs WHERE id = ?", (run["id"],)
        ).fetchone()
        assert tuple(after) == tuple(before)
    finally:
        conn.close()


def test_context_import_run_rejects_blank_git_sha(tmp_path: Path) -> None:
    from netctl.db import connect, create_context_import_run

    conn = connect(f"sqlite:///{(tmp_path / 'netctl.sqlite').as_posix()}")
    try:
        with pytest.raises(ValueError, match="git_sha is required"):
            create_context_import_run(
                conn,
                context_id="test-network",
                context_revision_id=None,
                base_context_revision_id=None,
                input_sha256="a" * 64,
                git_sha="   ",
                source_path=tmp_path / "network.yaml",
            )
    finally:
        conn.close()


def test_first_import_materialises_active_snapshot_without_touching_runtime_tables(tmp_path: Path) -> None:
    from netctl.context import normalise_import_entities
    from netctl.context_import import import_context, load_active_snapshot

    conn = connect_import_db(tmp_path)
    document = import_document()
    source_path = tmp_path / "network-context.yaml"
    try:
        conn.execute(
            "INSERT INTO network_hosts (ip, hostname) VALUES (?, ?)",
            ("192.0.2.10", "observed-router"),
        )
        conn.execute(
            """
            INSERT INTO host_observations
                (host_id, observed_at, observation_type, ip)
            VALUES (1, '2026-07-17T00:00:00Z', 'arp', '192.0.2.10')
            """
        )
        conn.execute(
            "INSERT INTO dhcp_leases (ip, hostname) VALUES (?, ?)",
            ("192.0.2.10", "observed-router"),
        )
        conn.commit()
        before_runtime = runtime_counts(conn)

        result = import_context(
            conn,
            document,
            raw_document(document),
            source_path,
            "first-import-git-sha",
        )

        assert result["result"] == "success_imported"
        assert result["run"]["status"] == "success_imported"
        assert result["context"]["context_id"] == "test-network"
        assert result["head"]["context_revision_id"] == result["context"]["id"]
        assert runtime_counts(conn) == before_runtime
        assert conn.execute("SELECT COUNT(*) FROM intent_assets WHERE lifecycle = 'active'").fetchone()[0] == 2
        assert conn.execute("SELECT COUNT(*) FROM network_hosts").fetchone()[0] == 1
        assert conn.execute(
            "SELECT COUNT(*) FROM intent_assets WHERE stable_id = 'router'"
        ).fetchone()[0] == 1
        assert conn.execute(
            "SELECT COUNT(*) FROM intent_links WHERE relation = 'CONNECTED_TO'"
        ).fetchone()[0] == 2
        assert load_active_snapshot(conn, "test-network") == normalise_import_entities(document)
        assert load_active_snapshot(conn, "missing-context") is None
    finally:
        conn.close()


def test_removal_creates_retired_copy_and_preserves_original_snapshot(tmp_path: Path) -> None:
    from netctl.context_import import import_context

    conn = connect_import_db(tmp_path)
    original = import_document()
    removed = deepcopy(original)
    removed["devices"] = [{"id": "router"}]
    removed["links"] = []
    source_path = tmp_path / "network-context.yaml"
    try:
        first = import_context(conn, original, raw_document(original), source_path, "first-git-sha")
        original_rows = [
            tuple(row)
            for row in conn.execute(
                """
                SELECT stable_id, lifecycle, canonical_json, canonical_hash, origin_context_revision_id
                FROM intent_assets
                WHERE context_revision_id = ?
                ORDER BY stable_id
                """,
                (first["context"]["id"],),
            )
        ]

        second = import_context(conn, removed, raw_document(removed), source_path, "second-git-sha")

        retired_switch = conn.execute(
            """
            SELECT lifecycle, canonical_json, canonical_hash, origin_context_revision_id
            FROM intent_assets
            WHERE context_revision_id = ? AND stable_id = 'switch'
            """,
            (second["context"]["id"],),
        ).fetchone()
        original_switch = conn.execute(
            """
            SELECT lifecycle, canonical_json, canonical_hash, origin_context_revision_id
            FROM intent_assets
            WHERE context_revision_id = ? AND stable_id = 'switch'
            """,
            (first["context"]["id"],),
        ).fetchone()
        carried_router = conn.execute(
            """
            SELECT lifecycle, origin_context_revision_id
            FROM intent_assets
            WHERE context_revision_id = ? AND stable_id = 'router'
            """,
            (second["context"]["id"],),
        ).fetchone()
        current_original_rows = [
            tuple(row)
            for row in conn.execute(
                """
                SELECT stable_id, lifecycle, canonical_json, canonical_hash, origin_context_revision_id
                FROM intent_assets
                WHERE context_revision_id = ?
                ORDER BY stable_id
                """,
                (first["context"]["id"],),
            )
        ]

        assert second["result"] == "success_imported"
        assert tuple(retired_switch) == (
            "retired",
            original_switch["canonical_json"],
            original_switch["canonical_hash"],
            first["context"]["id"],
        )
        assert tuple(carried_router) == ("active", first["context"]["id"])
        assert current_original_rows == original_rows
        assert all(row[1] == "active" for row in current_original_rows)
    finally:
        conn.close()


def test_same_content_creates_new_noop_run_without_duplicate_snapshot(tmp_path: Path) -> None:
    from netctl.context_import import import_context

    conn = connect_import_db(tmp_path)
    document = import_document()
    raw_bytes = raw_document(document)
    source_path = tmp_path / "network-context.yaml"
    try:
        first = import_context(conn, document, raw_bytes, source_path, "first-git-sha")
        before_intent_count = intent_count(conn)
        first_head = dict(conn.execute("SELECT * FROM context_heads").fetchone())

        second = import_context(conn, document, raw_bytes, source_path, "second-git-sha")

        assert second["result"] == "success_noop_same_content"
        assert second["run"]["id"] != first["run"]["id"]
        assert second["run"]["git_sha"] == "second-git-sha"
        assert second["context"]["id"] == first["context"]["id"]
        assert intent_count(conn) == before_intent_count
        assert conn.execute("SELECT COUNT(*) FROM context_revisions").fetchone()[0] == 1
        assert conn.execute("SELECT COUNT(*) FROM context_import_runs").fetchone()[0] == 2
        assert dict(conn.execute("SELECT * FROM context_heads").fetchone()) == first_head
    finally:
        conn.close()


def test_inactive_imported_revision_reactivates_without_new_intent_rows(tmp_path: Path) -> None:
    from netctl.context_import import import_context

    conn = connect_import_db(tmp_path)
    first_document = import_document()
    second_document = deepcopy(first_document)
    second_document["services"] = []
    source_path = tmp_path / "network-context.yaml"
    try:
        first = import_context(
            conn,
            first_document,
            raw_document(first_document),
            source_path,
            "first-git-sha",
        )
        second = import_context(
            conn,
            second_document,
            raw_document(second_document),
            source_path,
            "second-git-sha",
        )
        before_intent_count = intent_count(conn)

        reactivated = import_context(
            conn,
            first_document,
            raw_document(first_document),
            source_path,
            "reactivation-git-sha",
        )

        assert second["context"]["id"] != first["context"]["id"]
        assert reactivated["result"] == "success_activated_existing_content"
        assert reactivated["context"]["id"] == first["context"]["id"]
        assert reactivated["head"]["context_revision_id"] == first["context"]["id"]
        assert reactivated["head"]["activated_by_import_run_id"] == reactivated["run"]["id"]
        assert intent_count(conn) == before_intent_count
    finally:
        conn.close()


def test_entity_origins_do_not_cross_context_boundaries(tmp_path: Path) -> None:
    from netctl.context_import import import_context

    conn = connect_import_db(tmp_path)
    first_document = import_document()
    second_document = deepcopy(first_document)
    second_document["metadata"] = {"context_id": "other-network"}
    source_path = tmp_path / "network-context.yaml"
    try:
        first = import_context(
            conn,
            first_document,
            raw_document(first_document),
            source_path,
            "first-git-sha",
        )
        second = import_context(
            conn,
            second_document,
            raw_document(second_document),
            source_path,
            "second-git-sha",
        )

        second_origin = conn.execute(
            """
            SELECT origin_context_revision_id
            FROM intent_assets
            WHERE context_revision_id = ? AND stable_id = 'router'
            """,
            (second["context"]["id"],),
        ).fetchone()[0]
        assert second["context"]["id"] != first["context"]["id"]
        assert second_origin == second["context"]["id"]
    finally:
        conn.close()


def test_semantic_validation_error_preserves_prior_head_and_active_snapshot(tmp_path: Path) -> None:
    from netctl.context_import import import_context

    conn = connect_import_db(tmp_path)
    original = import_document()
    document = deepcopy(original)
    document["links"][0]["relation"] = "UNKNOWN"
    source_path = tmp_path / "network-context.yaml"
    try:
        seed_representative_runtime_rows(conn)
        first = import_context(conn, original, raw_document(original), source_path, "first-git-sha")
        before_head = dict(conn.execute("SELECT * FROM context_heads WHERE context_id = 'test-network'").fetchone())
        before_intent_rows = intent_rows_by_table(conn)
        before_runtime = runtime_counts(conn)
        before_runtime_rows = representative_runtime_rows(conn)

        result = import_context(
            conn,
            document,
            raw_document(document),
            source_path,
            "invalid-git-sha",
        )

        persisted = conn.execute(
            "SELECT * FROM context_import_runs WHERE id = ?", (result["run"]["id"],)
        ).fetchone()
        assert result["result"] == "validation_error"
        assert result["context"] is None
        assert result["head"] == before_head
        assert persisted["status"] == "validation_error"
        assert persisted["finished_at"] is not None
        assert persisted["context_revision_id"] is None
        assert persisted["base_context_revision_id"] == first["context"]["id"]
        assert json.loads(persisted["errors_json"]) == result["errors"]
        assert conn.execute("SELECT COUNT(*) FROM context_revisions").fetchone()[0] == 1
        assert dict(conn.execute("SELECT * FROM context_heads WHERE context_id = 'test-network'").fetchone()) == before_head
        assert intent_rows_by_table(conn) == before_intent_rows
        assert runtime_counts(conn) == before_runtime
        assert representative_runtime_rows(conn) == before_runtime_rows
    finally:
        conn.close()


def test_second_entity_table_failure_rolls_back_candidate_and_preserves_prior_head(tmp_path: Path) -> None:
    from netctl.context_import import import_context
    from netctl.context import IMPORT_COLLECTIONS

    conn = connect_import_db(tmp_path)
    original = import_document()
    broken = deepcopy(original)
    broken["locations"] = [{"id": "candidate-location"}]
    source_path = tmp_path / "network-context.yaml"
    try:
        seed_representative_runtime_rows(conn)
        first = import_context(conn, original, raw_document(original), source_path, "first-git-sha")
        before_head = dict(conn.execute("SELECT * FROM context_heads WHERE context_id = 'test-network'").fetchone())
        before_intent_rows = intent_rows_by_table(conn)
        before_runtime = runtime_counts(conn)
        before_runtime_rows = representative_runtime_rows(conn)
        conn.execute(
            """
            CREATE TRIGGER fail_candidate_location
            BEFORE INSERT ON intent_locations
            WHEN NEW.stable_id = 'candidate-location'
            BEGIN
                SELECT RAISE(ABORT, 'forced materialisation failure');
            END
            """
        )
        conn.commit()

        result = import_context(conn, broken, raw_document(broken), source_path, "broken-git-sha")

        conn.close()
        conn = connect_import_db(tmp_path)

        assert result["result"] == "db_error"
        assert result["run"]["status"] == "db_error"
        assert result["head"] == before_head
        assert dict(conn.execute("SELECT * FROM context_heads WHERE context_id = 'test-network'").fetchone()) == before_head
        assert intent_rows_by_table(conn) == before_intent_rows
        assert runtime_counts(conn) == before_runtime
        assert representative_runtime_rows(conn) == before_runtime_rows
        assert all(
            conn.execute(
                f"SELECT COUNT(*) FROM {table} WHERE context_revision_id = ?",
                (result["context"]["id"],),
            ).fetchone()[0]
            == 0
            for table, _entity_type in IMPORT_COLLECTIONS.values()
        )
        persisted_run = conn.execute(
            "SELECT * FROM context_import_runs WHERE id = ?", (result["run"]["id"],)
        ).fetchone()
        assert persisted_run["status"] == "db_error"
        assert persisted_run["finished_at"] is not None
        assert persisted_run["base_context_revision_id"] == first["context"]["id"]
        persisted_errors = json.loads(persisted_run["errors_json"])
        assert persisted_errors == [
            {"path": "database", "message": "forced materialisation failure"}
        ]
    finally:
        conn.close()


def test_diff_snapshots_reports_canonical_entity_changes_in_stable_order() -> None:
    from netctl.context_diff import diff_snapshots

    base = {
        "asset": {
            "changed": {"id": "changed", "role": "before"},
            "removed": {"id": "removed"},
            "same": {"id": "same", "nested": {"a": 1, "b": 2}},
            "retired": {"id": "retired", "lifecycle": "retired"},
        }
    }
    candidate = {
        "asset": {
            "added": {"id": "added"},
            "changed": {"role": "after", "id": "changed"},
            "same": {"nested": {"b": 2, "a": 1}, "id": "same"},
            "retired": {"id": "retired", "lifecycle": "retired"},
        }
    }

    assert [(item["stable_id"], item["change"]) for item in diff_snapshots(base, candidate)] == [
        ("added", "added"),
        ("changed", "changed"),
        ("removed", "removed"),
        ("retired", "unchanged"),
        ("same", "unchanged"),
    ]


def test_context_cli_diff_treats_payload_lifecycle_as_active_intent(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    database_url = f"sqlite:///{(tmp_path / 'netctl.sqlite').as_posix()}"
    context_path = tmp_path / "network-context.yaml"
    schema_path = tmp_path / "network-context.schema.json"
    context_path.write_text(
        yaml.safe_dump(
            {
                "schema_version": "2.2.0",
                "metadata": {"context_id": "test-network"},
                "devices": [{"id": "old-router", "lifecycle": "retired"}],
            }
        ),
        encoding="utf-8",
    )
    schema_path.write_text(json.dumps({"type": "object"}), encoding="utf-8")

    diff_rc, diff = run_cli(
        [
            "--json", "--db", database_url, "context", "diff", "--path", str(context_path),
            "--schema", str(schema_path),
        ],
        capsys,
    )

    assert diff_rc == 0
    assert diff["base_revision"] is None
    assert diff["summary"] == {"added": 1, "changed": 0, "removed": 0, "unchanged": 0}
    assert [(item["stable_id"], item["change"]) for item in diff["changes"]] == [
        ("old-router", "added")
    ]


@pytest.mark.parametrize(
    ("yaml_payload", "schema_payload", "expected_path", "expected_context_id"),
    [
        ("metadata: [unterminated", '{"type":"object"}', "document", ""),
        (yaml.safe_dump(import_document()), '{"type":', "schema", "test-network"),
    ],
    ids=["malformed-yaml", "malformed-schema"],
)
def test_context_cli_import_parse_failures_record_one_validation_error_run_without_snapshot_writes(
    tmp_path: Path,
    capsys: pytest.CaptureFixture[str],
    yaml_payload: str,
    schema_payload: str,
    expected_path: str,
    expected_context_id: str,
) -> None:
    database_url = f"sqlite:///{(tmp_path / 'netctl.sqlite').as_posix()}"
    context_path = tmp_path / "network-context.yaml"
    schema_path = tmp_path / "network-context.schema.json"
    context_path.write_text(yaml_payload, encoding="utf-8")
    schema_path.write_text(schema_payload, encoding="utf-8")

    import_rc, result = run_cli(
        [
            "--json", "--db", database_url, "context", "import", "--path", str(context_path),
            "--schema", str(schema_path), "--git-sha", "invalid-input-git-sha",
        ],
        capsys,
    )

    assert import_rc == 1
    assert result["status"] == "error"
    assert result["result"] == "validation_error"
    assert result["context"] is None
    assert result["head"] is None
    assert result["errors"][0]["path"] == expected_path
    conn = connect_import_db(tmp_path)
    try:
        runs = conn.execute("SELECT * FROM context_import_runs").fetchall()
        assert len(runs) == 1
        assert runs[0]["status"] == "validation_error"
        assert runs[0]["finished_at"] is not None
        assert runs[0]["context_id"] == expected_context_id
        assert runs[0]["context_revision_id"] is None
        assert runs[0]["base_context_revision_id"] is None
        assert runs[0]["git_sha"] == "invalid-input-git-sha"
        assert runs[0]["input_sha256"] == hashlib.sha256(context_path.read_bytes()).hexdigest()
        assert json.loads(runs[0]["errors_json"]) == result["errors"]
        assert conn.execute("SELECT COUNT(*) FROM context_revisions").fetchone()[0] == 0
        assert conn.execute("SELECT COUNT(*) FROM context_heads").fetchone()[0] == 0
        assert intent_count(conn) == 0
    finally:
        conn.close()


def test_context_cli_import_nan_canonicalisation_records_one_validation_error_run_without_snapshot_writes(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    database_url = f"sqlite:///{(tmp_path / 'netctl.sqlite').as_posix()}"
    context_path = tmp_path / "network-context.yaml"
    schema_path = tmp_path / "network-context.schema.json"
    document = import_document()
    document["devices"][0]["metric"] = float("nan")
    context_path.write_text(yaml.safe_dump(document), encoding="utf-8")
    schema_path.write_text(json.dumps({"type": "object"}), encoding="utf-8")

    import_rc, result = run_cli(
        [
            "--json", "--db", database_url, "context", "import", "--path", str(context_path),
            "--schema", str(schema_path), "--git-sha", "nan-git-sha",
        ],
        capsys,
    )

    assert import_rc == 1
    assert result["status"] == "error"
    assert result["result"] == "validation_error"
    assert result["context"] is None
    assert result["head"] is None
    assert result["errors"][0]["path"] == "canonicalization"
    assert "Out of range float values are not JSON compliant" in result["errors"][0]["message"]
    conn = connect_import_db(tmp_path)
    try:
        runs = conn.execute("SELECT * FROM context_import_runs").fetchall()
        assert len(runs) == 1
        assert runs[0]["status"] == "validation_error"
        assert runs[0]["context_id"] == "test-network"
        assert runs[0]["context_revision_id"] is None
        assert runs[0]["base_context_revision_id"] is None
        assert json.loads(runs[0]["errors_json"]) == result["errors"]
        assert conn.execute("SELECT COUNT(*) FROM context_revisions").fetchone()[0] == 0
        assert conn.execute("SELECT COUNT(*) FROM context_heads").fetchone()[0] == 0
        assert intent_count(conn) == 0
    finally:
        conn.close()


def test_context_cli_import_diff_and_status_are_structural_and_read_only(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    database_url = f"sqlite:///{(tmp_path / 'netctl.sqlite').as_posix()}"
    context_path = tmp_path / "network-context.yaml"
    schema_path = tmp_path / "network-context.schema.json"
    document = import_document()
    context_path.write_text(yaml.safe_dump(document), encoding="utf-8")
    schema_path.write_text(json.dumps({"type": "object"}), encoding="utf-8")

    missing_sha_rc, missing_sha = run_cli(
        ["--json", "--db", database_url, "context", "import", "--path", str(context_path), "--schema", str(schema_path)],
        capsys,
    )
    assert missing_sha_rc == 1
    assert missing_sha == {"status": "error", "message": "context git SHA is required", "errors": []}

    validate_rc, _validate = run_cli(
        ["--json", "--db", database_url, "context", "validate", "--path", str(context_path), "--schema", str(schema_path)],
        capsys,
    )
    status_rc, before_import_status = run_cli(["--json", "--db", database_url, "context", "status"], capsys)
    assert validate_rc == status_rc == 0
    assert before_import_status["context"] == before_import_status["latest_validated_revision"]
    assert before_import_status["active_head"] is None

    first_rc, first = run_cli(
        [
            "--json", "--db", database_url, "context", "import", "--path", str(context_path), "--schema", str(schema_path),
            "--git-sha", "first-git-sha",
        ],
        capsys,
    )
    assert first_rc == 0
    assert first["status"] == "ok"
    assert first["result"] == "success_imported"
    assert first["run"]["git_sha"] == "first-git-sha"
    assert first["head"]["context_revision_id"] == first["context"]["id"]

    second_rc, second = run_cli(
        [
            "--json", "--db", database_url, "context", "import", "--path", str(context_path), "--schema", str(schema_path),
            "--git-sha", "second-git-sha",
        ],
        capsys,
    )
    assert second_rc == 0
    assert second["result"] == "success_noop_same_content"
    assert second["run"]["id"] != first["run"]["id"]
    assert second["context"]["id"] == first["context"]["id"]

    candidate = deepcopy(document)
    candidate["devices"] = [
        {"id": "firewall"},
        {"id": "switch"},
        {"id": "router", "role": "changed"},
    ]
    candidate["services"] = []
    candidate["sites"] = list(reversed(candidate["sites"]))
    candidate["links"] = list(reversed(candidate["links"]))
    candidate_path = tmp_path / "candidate.yaml"
    candidate_path.write_text(yaml.safe_dump(candidate), encoding="utf-8")

    conn = connect_import_db(tmp_path)
    try:
        tables = ("context_revisions", "context_import_runs", "context_heads", *[table for table, _kind in __import__("netctl.context", fromlist=["IMPORT_COLLECTIONS"]).IMPORT_COLLECTIONS.values()])
        before_counts = {table: int(conn.execute(f"SELECT COUNT(*) FROM {table}").fetchone()[0]) for table in tables}
    finally:
        conn.close()
    diff_rc, diff = run_cli(
        ["--json", "--db", database_url, "context", "diff", "--path", str(candidate_path), "--schema", str(schema_path)],
        capsys,
    )
    assert diff_rc == 0
    assert diff["base_revision"]["id"] == first["context"]["id"]
    assert diff["summary"] == {"added": 1, "changed": 1, "removed": 1, "unchanged": 6}
    assert {(item["stable_id"], item["change"]) for item in diff["changes"]} >= {
        ("firewall", "added"), ("router", "changed"), ("web", "removed"), ("switch", "unchanged"),
    }
    conn = connect_import_db(tmp_path)
    try:
        assert {table: int(conn.execute(f"SELECT COUNT(*) FROM {table}").fetchone()[0]) for table in tables} == before_counts
    finally:
        conn.close()

    invalid = deepcopy(document)
    invalid["links"][0]["relation"] = "UNKNOWN"
    context_path.write_text(yaml.safe_dump(invalid), encoding="utf-8")
    invalid_rc, invalid_result = run_cli(
        [
            "--json", "--db", database_url, "context", "import", "--path", str(context_path), "--schema", str(schema_path),
            "--git-sha", "invalid-git-sha",
        ],
        capsys,
    )
    assert invalid_rc == 1
    assert invalid_result["status"] == "error"
    assert invalid_result["result"] == "validation_error"
    assert invalid_result["head"]["context_revision_id"] == first["context"]["id"]


def test_schema_invalid_context_import_records_one_validation_error_run_and_preserves_active_snapshot(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    from netctl.context_import import load_active_snapshot

    database_url = f"sqlite:///{(tmp_path / 'netctl.sqlite').as_posix()}"
    context_path = tmp_path / "network-context.yaml"
    schema_path = tmp_path / "network-context.schema.json"
    document = import_document()
    schema = {
        "type": "object",
        "required": ["schema_version"],
        "properties": {"schema_version": {"const": "2.2.0"}},
    }
    context_path.write_text(yaml.safe_dump(document), encoding="utf-8")
    schema_path.write_text(json.dumps(schema), encoding="utf-8")

    initial_rc, initial = run_cli(
        [
            "--json", "--db", database_url, "context", "import", "--path", str(context_path), "--schema", str(schema_path),
            "--git-sha", "initial-git-sha",
        ],
        capsys,
    )
    assert initial_rc == 0

    conn = connect_import_db(tmp_path)
    try:
        before_snapshot = load_active_snapshot(conn, "test-network")
        before_head = conn.execute(
            "SELECT context_revision_id FROM context_heads WHERE context_id = 'test-network'"
        ).fetchone()[0]
        before_intent_count = intent_count(conn)
    finally:
        conn.close()

    invalid = deepcopy(document)
    invalid["schema_version"] = "invalid"
    context_path.write_text(yaml.safe_dump(invalid), encoding="utf-8")
    invalid_rc, invalid_result = run_cli(
        [
            "--json", "--db", database_url, "context", "import", "--path", str(context_path), "--schema", str(schema_path),
            "--git-sha", "schema-invalid-git-sha",
        ],
        capsys,
    )

    assert invalid_rc == 1
    assert invalid_result["status"] == "error"
    assert invalid_result["result"] == "validation_error"
    conn = connect_import_db(tmp_path)
    try:
        validation_runs = conn.execute(
            "SELECT * FROM context_import_runs WHERE status = 'validation_error'"
        ).fetchall()
        assert len(validation_runs) == 1
        assert validation_runs[0]["context_revision_id"] is None
        assert validation_runs[0]["git_sha"] == "schema-invalid-git-sha"
        assert conn.execute("SELECT COUNT(*) FROM context_revisions").fetchone()[0] == 1
        assert intent_count(conn) == before_intent_count
        assert load_active_snapshot(conn, "test-network") == before_snapshot
        assert conn.execute(
            "SELECT context_revision_id FROM context_heads WHERE context_id = 'test-network'"
        ).fetchone()[0] == before_head
    finally:
        conn.close()
