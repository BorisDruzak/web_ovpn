from __future__ import annotations

from pathlib import Path
from copy import deepcopy

import pytest


def import_document() -> dict[str, object]:
    return {
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
