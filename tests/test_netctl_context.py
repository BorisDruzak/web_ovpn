import json
from pathlib import Path
from typing import Any

import pytest
import yaml


def write_context_files(tmp_path: Path) -> tuple[Path, Path, dict[str, Any]]:
    document = {
        "schema_version": "2.2.0",
        "metadata": {"context_id": "test-network"},
        "sites": [{"id": "central"}],
        "segments": [{"id": "central-lan"}],
        "devices": [{"id": "router"}],
        "services": [{"id": "web"}],
        "features": [{"id": "vpn"}],
        "risks": [{"id": "flat-lan"}],
    }
    schema = {
        "type": "object",
        "required": ["schema_version", "metadata", "sites"],
        "properties": {
            "schema_version": {"const": "2.2.0"},
            "metadata": {"type": "object", "required": ["context_id"]},
            "sites": {"type": "array"},
        },
    }
    context_path = tmp_path / "context.yaml"
    schema_path = tmp_path / "network-context.schema.json"
    context_path.write_text(yaml.safe_dump(document), encoding="utf-8")
    schema_path.write_text(json.dumps(schema), encoding="utf-8")
    return context_path, schema_path, document


def test_context_summary_reports_stable_sha_and_collection_counts(tmp_path: Path) -> None:
    from netctl.context import context_summary, load_context

    context_path, _schema_path, document = write_context_files(tmp_path)

    assert context_summary(
        load_context(context_path), context_path.read_bytes()
    ) == context_summary(document, context_path.read_bytes())
    assert context_summary(document, context_path.read_bytes())["counts"] == {
        "sites": 1,
        "locations": 0,
        "segments": 1,
        "devices": 1,
        "services": 1,
        "links": 0,
        "features": 1,
        "risks": 1,
    }


def test_load_schema_reads_json_object(tmp_path: Path) -> None:
    from netctl.context import load_schema

    schema_path = tmp_path / "network-context.schema.json"
    schema = {"type": "object"}
    schema_path.write_text(json.dumps(schema), encoding="utf-8")

    assert load_schema(schema_path) == schema


def test_load_context_rejects_non_object_yaml(tmp_path: Path) -> None:
    from netctl.context import load_context

    context_path = tmp_path / "context.yaml"
    context_path.write_text("- central\n", encoding="utf-8")

    with pytest.raises(ValueError, match="context YAML must contain an object"):
        load_context(context_path)


def test_load_schema_rejects_non_object_json(tmp_path: Path) -> None:
    from netctl.context import load_schema

    schema_path = tmp_path / "network-context.schema.json"
    schema_path.write_text("[]", encoding="utf-8")

    with pytest.raises(ValueError, match="context schema must contain an object"):
        load_schema(schema_path)


def test_validate_context_reports_schema_and_duplicate_id_errors(tmp_path: Path) -> None:
    from netctl.context import load_context, load_schema, validate_context

    context_path, schema_path, document = write_context_files(tmp_path)
    document["sites"].append({"id": "central"})
    document.pop("schema_version")
    context_path.write_text(yaml.safe_dump(document), encoding="utf-8")

    errors = validate_context(load_context(context_path), load_schema(schema_path))

    assert {error["path"] for error in errors} >= {"schema_version", "sites.1.id"}
    assert any(error["message"] == "duplicate id 'central'" for error in errors)


def test_validate_context_scopes_duplicate_ids_to_their_collection(tmp_path: Path) -> None:
    from netctl.context import load_context, load_schema, validate_context

    context_path, schema_path, document = write_context_files(tmp_path)
    document["segments"].append({"id": "central"})
    context_path.write_text(yaml.safe_dump(document), encoding="utf-8")

    assert validate_context(load_context(context_path), load_schema(schema_path)) == []


def test_load_context_and_schema_report_missing_files(tmp_path: Path) -> None:
    from netctl.context import load_context, load_schema

    with pytest.raises(FileNotFoundError):
        load_context(tmp_path / "missing.yaml")
    with pytest.raises(FileNotFoundError):
        load_schema(tmp_path / "missing.schema.json")


def test_context_revision_is_idempotent_and_status_returns_latest(tmp_path: Path) -> None:
    from netctl.db import connect, latest_context_revision, record_context_revision

    conn = connect(f"sqlite:///{(tmp_path / 'netctl.sqlite').as_posix()}")
    context = {
        "context_id": "test-network",
        "schema_version": "2.2.0",
        "sha256": "a" * 64,
        "counts": {},
    }
    try:
        first = record_context_revision(conn, context, tmp_path / "context.yaml", "abc123")
        second = record_context_revision(conn, context, tmp_path / "context.yaml", "abc123")

        assert first["id"] == second["id"]
        assert conn.execute("SELECT COUNT(*) FROM context_revisions").fetchone()[0] == 1
        assert latest_context_revision(conn)["sha256"] == "a" * 64
    finally:
        conn.close()
