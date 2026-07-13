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
