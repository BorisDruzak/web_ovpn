from __future__ import annotations

import ast
import hashlib
import json
import sqlite3
from pathlib import Path

import pytest


LEGACY_MIGRATION_HASHES = {
    "_migration_1": "f10c9fbef340cb2fa115e59678ffbe65916f2bceba427a1b2d2b01283c66637f",
    "_migration_2": "3be17db8a897bc88f67950ec820af0dce4551174902c1f4a063cc634ad112a20",
    "_migration_3": "6e37bcbf67c75ec2ff9e1a4e34cc23ac0577baca4a02459c8a1ed734b970818d",
    "_migration_4": "46dfb6aeaf386e9cef40ee7461065aed906c7d32b75c4032ad9ff6b12e3bcf53",
}

SWITCH_TABLES = {
    "switch_devices",
    "switch_collection_runs",
    "switch_capabilities",
    "switch_ports",
    "current_switch_fdb",
    "switch_fdb_events",
}


def _db_url(path: Path) -> str:
    return f"sqlite:///{path.as_posix()}"


def _table_names(conn) -> set[str]:
    return {
        str(row[0])
        for row in conn.execute("SELECT name FROM sqlite_master WHERE type = 'table'")
    }


def _snmp_source(**overrides: object) -> dict[str, object]:
    source: dict[str, object] = {
        "name": "switch-docs-example",
        "driver": "snmp_switch",
        "host": "192.0.2.16",
        "port": 161,
        "username": "",
        "secret_ref": "switch_docs_example_snmp",
        "site": "documentation",
        "role": "access-switch",
        "enabled": False,
        "snmp_version": "2c",
        "snmp_timeout_seconds": 2,
        "snmp_retries": 1,
        "snmp_max_repetitions": 25,
        "snmp_profile_hint": "dgs",
        "snmp_capability_ttl_hours": 168,
        "snmp_raw_capture": False,
        "snmp_raw_retention_hours": 24,
        "snmp_counter_retention_days": 14,
        "snmp_event_retention_days": 180,
        "snmp_access_port_mac_threshold": 10,
        "snmp_low_speed_threshold_bps": 100_000_000,
        "runtime_asset_key": "mac:02:00:00:00:00:16",
        "intent_context_id": "documentation-context",
        "intent_stable_id": "documentation-switch",
    }
    source.update(overrides)
    return source


def test_legacy_migrations_are_immutable() -> None:
    import netctl.migrations as migrations

    path = Path(migrations.__file__)
    source = path.read_text(encoding="utf-8")
    tree = ast.parse(source)
    actual = {
        node.name: hashlib.sha256(
            ast.get_source_segment(source, node).encode("utf-8")
        ).hexdigest()
        for node in tree.body
        if isinstance(node, ast.FunctionDef) and node.name in LEGACY_MIGRATION_HASHES
    }

    assert actual == LEGACY_MIGRATION_HASHES


def test_migration_5_creates_switch_schema_once(tmp_path: Path) -> None:
    from netctl.db import connect

    db_url = _db_url(tmp_path / "netctl.sqlite")
    conn = connect(db_url)
    try:
        assert [
            row[0]
            for row in conn.execute(
                "SELECT version FROM schema_migrations ORDER BY version"
            )
        ] == [1, 2, 3, 4, 5]
        assert SWITCH_TABLES <= _table_names(conn)
        assert "driver_options_json" in {
            row[1] for row in conn.execute("PRAGMA table_info(network_sources)")
        }
    finally:
        conn.close()

    reopened = connect(db_url)
    try:
        assert reopened.execute(
            "SELECT COUNT(*) FROM schema_migrations WHERE version = 5"
        ).fetchone()[0] == 1
    finally:
        reopened.close()


def test_migration_5_failure_rolls_back_schema_and_ledger(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    from netctl import migrations
    from netctl.db import connect

    with monkeypatch.context() as migration_patch:
        migration_patch.setattr(migrations, "MIGRATIONS", migrations.MIGRATIONS[:4])
        conn = connect(_db_url(tmp_path / "rollback.sqlite"))

    original_migration_5 = migrations._migration_5

    def fail_after_migration_5(connection) -> None:
        original_migration_5(connection)
        raise RuntimeError("injected migration 5 failure")

    monkeypatch.setattr(
        migrations,
        "MIGRATIONS",
        (*migrations.MIGRATIONS[:4], (5, fail_after_migration_5)),
    )
    try:
        with pytest.raises(RuntimeError, match="injected migration 5 failure"):
            migrations.apply_migrations(conn)

        assert SWITCH_TABLES.isdisjoint(_table_names(conn))
        assert "driver_options_json" not in {
            row[1] for row in conn.execute("PRAGMA table_info(network_sources)")
        }
        assert conn.execute(
            "SELECT COUNT(*) FROM schema_migrations WHERE version = 5"
        ).fetchone()[0] == 0
    finally:
        conn.close()


def test_migration_5_does_not_escape_outer_savepoint(tmp_path: Path) -> None:
    from netctl import migrations
    from netctl.db import connect

    with pytest.MonkeyPatch.context() as migration_patch:
        migration_patch.setattr(migrations, "MIGRATIONS", migrations.MIGRATIONS[:4])
        conn = connect(_db_url(tmp_path / "savepoint.sqlite"))

    try:
        conn.execute("SAVEPOINT migration_5_outer")
        migrations._migration_5(conn)
        assert SWITCH_TABLES <= _table_names(conn)
        conn.execute("ROLLBACK TO SAVEPOINT migration_5_outer")
        conn.execute("RELEASE SAVEPOINT migration_5_outer")

        assert SWITCH_TABLES.isdisjoint(_table_names(conn))
        assert "driver_options_json" not in {
            row[1] for row in conn.execute("PRAGMA table_info(network_sources)")
        }
    finally:
        conn.close()


def test_driver_options_column_defaults_to_empty_json(tmp_path: Path) -> None:
    from netctl.db import connect
    from netctl.util import utc_now

    conn = connect(_db_url(tmp_path / "default.sqlite"))
    try:
        now = utc_now()
        conn.execute(
            """
            INSERT INTO network_sources
                (name, driver, host, port, username, secret_ref, created_at, updated_at)
            VALUES ('docs-source', 'mock', '192.0.2.10', 1, '', 'docs-source', ?, ?)
            """,
            (now, now),
        )
        assert conn.execute(
            "SELECT driver_options_json FROM network_sources WHERE name = 'docs-source'"
        ).fetchone()[0] == "{}"
    finally:
        conn.close()


def test_snmp_scalar_yaml_round_trips_as_driver_options(tmp_path: Path) -> None:
    from netctl.config import load_config_sources, normalize_source, write_source_yaml

    config_path = tmp_path / "netctl.yaml"
    expected = normalize_source(_snmp_source())
    output_path = write_source_yaml(config_path, expected)

    assert "community:" not in output_path.read_text(encoding="utf-8")
    assert load_config_sources(config_path) == [expected]
    assert expected["driver_options"] == {
        "snmp_version": "2c",
        "timeout_seconds": 2,
        "retries": 1,
        "max_repetitions": 25,
        "profile_hint": "dgs",
        "capability_ttl_hours": 168,
        "raw_capture": False,
        "raw_retention_hours": 24,
        "counter_retention_days": 14,
        "event_retention_days": 180,
        "access_port_mac_threshold": 10,
        "low_speed_threshold_bps": 100_000_000,
        "runtime_asset_key": "mac:02:00:00:00:00:16",
        "intent_context_id": "documentation-context",
        "intent_stable_id": "documentation-switch",
    }


def test_snmp_options_persist_as_sorted_json_and_decode(tmp_path: Path) -> None:
    from netctl.config import normalize_source
    from netctl.db import connect, get_source, upsert_source

    conn = connect(_db_url(tmp_path / "options.sqlite"))
    try:
        normalized = normalize_source(_snmp_source())
        upsert_source(conn, normalized)
        stored = conn.execute(
            "SELECT driver_options_json FROM network_sources WHERE name = ?",
            (normalized["name"],),
        ).fetchone()[0]
        loaded = get_source(conn, str(normalized["name"]))

        assert stored == json.dumps(
            normalized["driver_options"],
            ensure_ascii=False,
            sort_keys=True,
            separators=(",", ":"),
        )
        assert loaded is not None
        assert loaded["driver_options"] == normalized["driver_options"]
        assert "driver_options_json" not in loaded
    finally:
        conn.close()


def test_snmp_database_boundary_rejects_unknown_option_alias(tmp_path: Path) -> None:
    from netctl.config import normalize_source
    from netctl.db import connect, upsert_source

    conn = connect(_db_url(tmp_path / "unknown-option.sqlite"))
    try:
        normalized = normalize_source(_snmp_source())
        normalized["driver_options"] = {
            **normalized["driver_options"],
            "community_string": None,
        }

        with pytest.raises(ValueError) as error:
            upsert_source(conn, normalized)

        assert error.value.args == ("SNMP driver_options are invalid",)
        assert conn.execute(
            "SELECT COUNT(*) FROM network_sources WHERE name = ?",
            (normalized["name"],),
        ).fetchone()[0] == 0
    finally:
        conn.close()


@pytest.mark.parametrize(
    "driver_options_json",
    [
        '{"community_string":null}',
        '{"profile_hint":"dgs","unknown_option":null}',
        "not-json",
    ],
)
def test_source_reads_fail_closed_for_direct_invalid_snmp_json(
    tmp_path: Path, driver_options_json: str
) -> None:
    from netctl.db import connect, get_source, list_sources
    from netctl.util import utc_now

    conn = connect(_db_url(tmp_path / "invalid-read.sqlite"))
    try:
        now = utc_now()
        conn.execute(
            """
            INSERT INTO network_sources
                (name, driver, host, port, username, secret_ref, created_at, updated_at,
                 driver_options_json)
            VALUES ('switch-invalid-docs', 'snmp_switch', '192.0.2.22', 161, '',
                    'switch-invalid-docs', ?, ?, ?)
            """,
            (now, now, driver_options_json),
        )

        with pytest.raises(ValueError) as get_error:
            get_source(conn, "switch-invalid-docs")
        with pytest.raises(ValueError) as list_error:
            list_sources(conn)

        assert get_error.value.args == ("stored SNMP driver_options are invalid",)
        assert list_error.value.args == ("stored SNMP driver_options are invalid",)
    finally:
        conn.close()


def test_source_reads_fail_closed_for_direct_private_legacy_options(
    tmp_path: Path,
) -> None:
    from netctl.db import connect, get_source, list_sources
    from netctl.util import utc_now

    conn = connect(_db_url(tmp_path / "invalid-legacy-read.sqlite"))
    try:
        now = utc_now()
        conn.execute(
            """
            INSERT INTO network_sources
                (name, driver, host, port, username, secret_ref, created_at, updated_at,
                 driver_options_json)
            VALUES ('legacy-invalid-docs', 'mock', '192.0.2.23', 1, '',
                    'legacy-invalid-docs', ?, ?, '{"resolved_token":null}')
            """,
            (now, now),
        )

        with pytest.raises(ValueError) as get_error:
            get_source(conn, "legacy-invalid-docs")
        with pytest.raises(ValueError) as list_error:
            list_sources(conn)

        assert get_error.value.args == ("stored driver_options are invalid",)
        assert list_error.value.args == ("stored driver_options are invalid",)
    finally:
        conn.close()


@pytest.mark.parametrize(
    ("override", "message"),
    [
        ({"snmp_version": "3"}, "snmp_version"),
        ({"snmp_profile_hint": "unsupported"}, "snmp_profile_hint"),
        ({"snmp_raw_retention_hours": 25}, "snmp_raw_retention_hours"),
        ({"snmp_counter_retention_days": 0}, "snmp_counter_retention_days"),
        ({"snmp_event_retention_days": 0}, "snmp_event_retention_days"),
    ],
)
def test_snmp_rejects_unsupported_version_profile_and_retention(
    override: dict[str, object], message: str
) -> None:
    from netctl.config import normalize_source

    with pytest.raises(ValueError, match=message):
        normalize_source(_snmp_source(**override))


@pytest.mark.parametrize("value", [True, 2.5, "2.5"])
def test_snmp_integer_options_reject_bool_and_nonintegral_values(value: object) -> None:
    from netctl.config import normalize_source

    with pytest.raises(ValueError) as error:
        normalize_source(_snmp_source(snmp_timeout_seconds=value))

    assert error.value.args == ("snmp_timeout_seconds must be an integer",)


@pytest.mark.parametrize(
    ("override", "message"),
    [
        ({"snmp_raw_capture": "sometimes"}, "snmp_raw_capture must be a boolean"),
        ({"runtime_asset_key": {"nested": None}}, "runtime_asset_key must be a string"),
        ({"driver_options": []}, "SNMP driver_options must be a mapping"),
    ],
)
def test_snmp_options_reject_noncanonical_types(
    override: dict[str, object], message: str
) -> None:
    from netctl.config import normalize_source

    with pytest.raises(ValueError) as error:
        normalize_source(_snmp_source(**override))

    assert error.value.args == (message,)


def test_snmp_rejects_yaml_community_key_without_echoing_material() -> None:
    from netctl.config import normalize_source

    with pytest.raises(ValueError) as error:
        normalize_source(_snmp_source(community=None))

    assert "community" in str(error.value).lower()
    assert error.value.args == ("SNMP community must be configured through secret_ref",)


def test_snmp_rejects_community_alias_key() -> None:
    from netctl.config import normalize_source

    with pytest.raises(ValueError) as error:
        normalize_source(_snmp_source(community_string=None))

    assert error.value.args == ("unsupported SNMP source option",)


def test_snmp_secret_env_name_is_distinct_from_password_env_name() -> None:
    from netctl.config import secret_env_name, snmp_community_env_name

    secret_ref = "switch_docs_example"
    assert snmp_community_env_name(secret_ref) == (
        "NETCTL_SECRET_SWITCH_DOCS_EXAMPLE_COMMUNITY"
    )
    assert snmp_community_env_name(secret_ref) != secret_env_name(secret_ref)


@pytest.mark.parametrize("secret_ref", ["switch-docs", "switch docs", "switch__docs", "1switch"])
def test_snmp_community_env_name_rejects_ambiguous_secret_references(secret_ref: str) -> None:
    from netctl.config import snmp_community_env_name

    with pytest.raises(ValueError) as error:
        snmp_community_env_name(secret_ref)

    assert error.value.args == ("SNMP secret_ref is invalid",)


def test_source_public_removes_resolved_secret_material_recursively() -> None:
    from netctl.db import source_public

    resolved_material = object()
    public = source_public(
        {
            "name": "switch-docs-example",
            "community": resolved_material,
            "community_string": resolved_material,
            "password": resolved_material,
            "resolved_secret": resolved_material,
            "driver_options": {
                "community": resolved_material,
                "resolved_community": resolved_material,
                "profile_hint": "dgs",
            },
        }
    )

    assert public == {
        "name": "switch-docs-example",
        "driver_options": {"profile_hint": "dgs"},
    }
    assert resolved_material not in public.values()


def test_source_public_fails_closed_for_invalid_snmp_options() -> None:
    from netctl.db import source_public

    with pytest.raises(ValueError) as error:
        source_public(
            {
                "name": "switch-invalid-docs",
                "driver": "snmp_switch",
                "driver_options": {"community_string": None},
            }
        )

    assert error.value.args == ("SNMP driver_options are invalid",)


def test_existing_mikrotik_normalization_is_unchanged() -> None:
    from netctl.config import normalize_source

    assert normalize_source(
        {
            "name": "mikrotik-docs",
            "driver": "mikrotik_api",
            "host": "192.0.2.1",
            "port": 8729,
            "username": "observer",
            "secret_ref": "mikrotik-docs",
            "tls": True,
            "verify_tls": False,
            "site": "documentation",
            "role": "router",
            "ssh_identity_file": "",
            "ssh_proxy_jump": "",
            "ssh_connect_timeout": 8,
            "enabled": True,
        }
    ) == {
        "name": "mikrotik-docs",
        "driver": "mikrotik_api",
        "host": "192.0.2.1",
        "port": 8729,
        "username": "observer",
        "secret_ref": "mikrotik-docs",
        "tls": True,
        "verify_tls": False,
        "site": "documentation",
        "role": "router",
        "ssh_identity_file": "",
        "ssh_proxy_jump": "",
        "ssh_connect_timeout": 8,
        "enabled": True,
    }


def test_mikrotik_source_reads_omit_empty_driver_options(tmp_path: Path) -> None:
    from netctl.config import normalize_source
    from netctl.db import connect, get_source, list_sources, source_public, upsert_source

    conn = connect(_db_url(tmp_path / "mikrotik-shape.sqlite"))
    try:
        normalized = normalize_source(
            {
                "name": "mikrotik-docs",
                "driver": "mikrotik_api",
                "host": "192.0.2.1",
            }
        )
        upsert_source(conn, normalized)

        loaded = get_source(conn, "mikrotik-docs")
        listed = list_sources(conn)

        assert loaded is not None
        assert "driver_options" not in loaded
        assert "driver_options" not in source_public(loaded)
        assert len(listed) == 1
        assert "driver_options" not in listed[0]
    finally:
        conn.close()


@pytest.mark.parametrize(
    ("table", "columns", "values"),
    [
        (
            "switch_ports",
            "source_id, port_key, last_seen_at, collector_run_id",
            "?, 'port:1', ?, ?",
        ),
        (
            "current_switch_fdb",
            (
                "source_id, vlan_key, mac, port_key, first_seen_at, last_seen_at, "
                "collector_run_id"
            ),
            "?, 'vid:1', '02:00:00:00:00:22', 'port:1', ?, ?, ?",
        ),
        (
            "switch_fdb_events",
            (
                "source_id, vlan_key, mac, event_type, observed_at, "
                "collector_run_id"
            ),
            "?, 'vid:1', '02:00:00:00:00:22', 'appeared', ?, ?",
        ),
    ],
)
def test_switch_children_reject_collection_run_from_another_source(
    tmp_path: Path, table: str, columns: str, values: str
) -> None:
    from netctl.db import connect
    from netctl.util import utc_now

    conn = connect(_db_url(tmp_path / f"cross-source-{table}.sqlite"))
    try:
        now = utc_now()
        for name in ("switch-docs-a", "switch-docs-b"):
            conn.execute(
                """
                INSERT INTO network_sources
                    (name, driver, host, port, username, secret_ref, created_at, updated_at)
                VALUES (?, 'snmp_switch', '192.0.2.30', 161, '', ?, ?, ?)
                """,
                (name, name, now, now),
            )
        source_a, source_b = [
            row[0]
            for row in conn.execute(
                "SELECT id FROM network_sources ORDER BY name"
            ).fetchall()
        ]
        run_id = conn.execute(
            """
            INSERT INTO switch_collection_runs (source_id, started_at, status)
            VALUES (?, ?, 'running')
            """,
            (source_a, now),
        ).lastrowid

        parameters = (
            (source_b, now, run_id)
            if table != "current_switch_fdb"
            else (source_b, now, now, run_id)
        )
        with pytest.raises(sqlite3.IntegrityError):
            conn.execute(
                f"INSERT INTO {table} ({columns}) VALUES ({values})",
                parameters,
            )
    finally:
        conn.close()
