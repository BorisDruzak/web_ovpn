import json
import sqlite3
from hashlib import sha256
from pathlib import Path
from typing import Any

import pytest
import yaml


def run_cli(args: list[str], capsys: pytest.CaptureFixture[str]) -> tuple[int, dict[str, Any]]:
    from netctl.cli import main

    rc = main(args)
    captured = capsys.readouterr()
    assert captured.err == ""
    return rc, json.loads(captured.out)


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


def test_revalidating_a_revision_refreshes_latest_status_without_duplicate_rows(
    tmp_path: Path, capsys: pytest.CaptureFixture[str], monkeypatch: pytest.MonkeyPatch
) -> None:
    import netctl.db as db

    db_url = f"sqlite:///{(tmp_path / 'netctl.sqlite').as_posix()}"
    timestamps = iter(["2026-07-13T00:00:00Z", "2026-07-13T00:00:00Z", "2026-07-13T00:00:00Z"])
    monkeypatch.setattr(db, "utc_now", lambda: next(timestamps))
    conn = db.connect(db_url)
    context_a = {"context_id": "test-network", "schema_version": "2.2.0", "sha256": "a" * 64, "counts": {"sites": 1}}
    context_b = {"context_id": "test-network", "schema_version": "2.2.0", "sha256": "b" * 64, "counts": {"sites": 2}}
    try:
        first_a = db.record_context_revision(conn, context_a, tmp_path / "a.yaml", "a")
        db.record_context_revision(conn, context_b, tmp_path / "b.yaml", "b")
        refreshed_a = db.record_context_revision(conn, {**context_a, "counts": {"sites": 3}}, tmp_path / "a.yaml", "a")

        latest = db.latest_context_revision(conn)
        assert refreshed_a["id"] == first_a["id"]
        assert conn.execute("SELECT COUNT(*) FROM context_revisions").fetchone()[0] == 2
        assert latest["sha256"] == context_a["sha256"]
        assert latest["counts"] == {"sites": 3}
        assert latest["validated_at"] == "2026-07-13T00:00:00Z"
    finally:
        conn.close()

    status_rc, status = run_cli(["--json", "--db", db_url, "context", "status"], capsys)
    assert status_rc == 0
    assert status["context"]["sha256"] == context_a["sha256"]
    assert status["context"]["counts"] == {"sites": 3}


def test_context_validate_then_status_returns_recorded_revision(tmp_path: Path, capsys: pytest.CaptureFixture[str]) -> None:
    context_path, schema_path, _document = write_context_files(tmp_path)
    db_url = f"sqlite:///{(tmp_path / 'netctl.sqlite').as_posix()}"

    rc, valid = run_cli(
        [
            "--json",
            "--db",
            db_url,
            "context",
            "validate",
            "--path",
            str(context_path),
            "--schema",
            str(schema_path),
            "--git-sha",
            "abc123",
        ],
        capsys,
    )
    status_rc, status = run_cli(["--json", "--db", db_url, "context", "status"], capsys)

    assert rc == status_rc == 0
    assert valid["context"]["git_sha"] == status["context"]["git_sha"] == "abc123"
    assert status["context"]["counts"] == valid["context"]["counts"]


def test_context_validate_invalid_document_keeps_last_successful_revision(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    context_path, schema_path, document = write_context_files(tmp_path)
    db_url = f"sqlite:///{(tmp_path / 'netctl.sqlite').as_posix()}"

    assert run_cli(
        ["--json", "--db", db_url, "context", "validate", "--path", str(context_path), "--schema", str(schema_path)], capsys
    )[0] == 0
    document.pop("schema_version")
    context_path.write_text(yaml.safe_dump(document), encoding="utf-8")

    invalid_rc, invalid = run_cli(
        ["--json", "--db", db_url, "context", "validate", "--path", str(context_path), "--schema", str(schema_path)],
        capsys,
    )
    status_rc, status = run_cli(["--json", "--db", db_url, "context", "status"], capsys)

    assert invalid_rc != 0 and invalid["status"] == "error"
    assert status_rc == 0 and status["context"]["schema_version"] == "2.2.0"


def test_context_validate_without_path_returns_json_error(tmp_path: Path, capsys: pytest.CaptureFixture[str]) -> None:
    db_url = f"sqlite:///{(tmp_path / 'netctl.sqlite').as_posix()}"

    rc, data = run_cli(["--json", "--db", db_url, "context", "validate"], capsys)

    assert rc == 1
    assert data == {"status": "error", "message": "context path is required", "errors": []}


@pytest.mark.parametrize(
    ("context_contents", "schema_contents"),
    [
        (None, json.dumps({"type": "object"})),
        ("sites: [", json.dumps({"type": "object"})),
        ("metadata: {}\n", "[]"),
    ],
    ids=["missing-context", "invalid-yaml", "invalid-schema"],
)
def test_context_validate_file_and_parse_errors_return_json(
    tmp_path: Path, capsys: pytest.CaptureFixture[str], context_contents: str | None, schema_contents: str
) -> None:
    context_path = tmp_path / "context.yaml"
    schema_path = tmp_path / "network-context.schema.json"
    if context_contents is not None:
        context_path.write_text(context_contents, encoding="utf-8")
    schema_path.write_text(schema_contents, encoding="utf-8")
    db_url = f"sqlite:///{(tmp_path / 'netctl.sqlite').as_posix()}"

    rc, data = run_cli(
        ["--json", "--db", db_url, "context", "validate", "--path", str(context_path), "--schema", str(schema_path)], capsys
    )

    assert rc == 1
    assert data["status"] == "error"
    assert data["errors"] == []
    assert data["message"]


def test_context_validate_unreadable_file_returns_json_error(
    tmp_path: Path, capsys: pytest.CaptureFixture[str], monkeypatch: pytest.MonkeyPatch
) -> None:
    context_path, schema_path, _document = write_context_files(tmp_path)
    db_url = f"sqlite:///{(tmp_path / 'netctl.sqlite').as_posix()}"
    original_read_bytes = Path.read_bytes

    def fail_context_read(path: Path) -> bytes:
        if path == context_path:
            raise PermissionError("context is unreadable")
        return original_read_bytes(path)

    monkeypatch.setattr(Path, "read_bytes", fail_context_read)

    rc, data = run_cli(
        ["--json", "--db", db_url, "context", "validate", "--path", str(context_path), "--schema", str(schema_path)], capsys
    )

    assert rc == 1
    assert data == {"status": "error", "message": "context is unreadable", "errors": []}


def test_context_status_without_successful_revision_returns_json_error(tmp_path: Path, capsys: pytest.CaptureFixture[str]) -> None:
    db_url = f"sqlite:///{(tmp_path / 'netctl.sqlite').as_posix()}"

    rc, data = run_cli(["--json", "--db", db_url, "context", "status"], capsys)

    assert rc == 1
    assert data == {"status": "error", "message": "no successful context validation found", "errors": []}


def test_resolve_context_schema_precedence(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    from netctl.cli import resolve_context_schema

    context_path = tmp_path / "repo" / "contexts" / "network.yaml"
    context_path.parent.mkdir(parents=True)
    context_path.write_text("metadata: {}\n", encoding="utf-8")
    explicit_schema = tmp_path / "explicit.json"
    sibling_schema = context_path.parent.parent / "schemas" / "network-context.schema.json"
    environment_schema = tmp_path / "environment.json"
    for path in (explicit_schema, sibling_schema, environment_schema):
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text("{}", encoding="utf-8")
    monkeypatch.setenv("NETCTL_CONTEXT_SCHEMA", str(environment_schema))

    assert resolve_context_schema(context_path, str(explicit_schema)) == explicit_schema
    explicit_schema.unlink()
    assert resolve_context_schema(context_path, "") == sibling_schema
    sibling_schema.unlink()
    assert resolve_context_schema(context_path, "") == environment_schema


def test_context_validate_uses_the_hashed_raw_bytes_for_parsing(
    tmp_path: Path, capsys: pytest.CaptureFixture[str], monkeypatch: pytest.MonkeyPatch
) -> None:
    context_path, schema_path, _document = write_context_files(tmp_path)
    raw_bytes = context_path.read_bytes()
    changed_bytes = raw_bytes.replace(b"test-network", b"other-network")
    original_read_bytes = Path.read_bytes
    context_reads = 0

    def alternating_context_reads(path: Path) -> bytes:
        nonlocal context_reads
        if path == context_path:
            context_reads += 1
            return raw_bytes if context_reads == 1 else changed_bytes
        return original_read_bytes(path)

    monkeypatch.setattr(Path, "read_bytes", alternating_context_reads)
    db_url = f"sqlite:///{(tmp_path / 'netctl.sqlite').as_posix()}"

    rc, data = run_cli(
        ["--json", "--db", db_url, "context", "validate", "--path", str(context_path), "--schema", str(schema_path)], capsys
    )

    assert rc == 0
    assert context_reads == 1
    assert data["context"]["context_id"] == "test-network"
    assert data["context"]["sha256"] == sha256(raw_bytes).hexdigest()


def test_legacy_context_revision_gets_empty_decoded_counts(tmp_path: Path) -> None:
    from netctl.db import connect, latest_context_revision

    db_path = tmp_path / "netctl.sqlite"
    legacy = sqlite3.connect(db_path)
    try:
        legacy.execute(
            """
            CREATE TABLE context_revisions (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                context_id TEXT NOT NULL,
                schema_version TEXT NOT NULL,
                sha256 TEXT NOT NULL,
                source_path TEXT NOT NULL,
                validated_at TEXT NOT NULL,
                git_sha TEXT NOT NULL DEFAULT '',
                status TEXT NOT NULL,
                error_json TEXT NOT NULL DEFAULT '[]',
                UNIQUE(context_id, sha256)
            )
            """
        )
        legacy.execute(
            """
            INSERT INTO context_revisions
                (context_id, schema_version, sha256, source_path, validated_at, git_sha, status, error_json)
            VALUES ('legacy', '2.2.0', 'a', 'legacy.yaml', '2026-07-13T00:00:00Z', '', 'ok', '[]')
            """
        )
        legacy.commit()
    finally:
        legacy.close()

    conn = connect(f"sqlite:///{db_path.as_posix()}")
    try:
        assert latest_context_revision(conn)["counts"] == {}
        conn.execute("UPDATE context_revisions SET counts_json = 'not-json'")
        conn.commit()
        assert latest_context_revision(conn)["counts"] == {}
    finally:
        conn.close()
