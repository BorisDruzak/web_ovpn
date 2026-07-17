from __future__ import annotations

from pathlib import Path

import pytest


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
