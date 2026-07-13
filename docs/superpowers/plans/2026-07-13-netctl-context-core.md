# Netctl Context Core Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox syntax for tracking.

**Goal:** Add read-only validation and revision status for canonical network-context YAML files to netctl.

**Architecture:** A focused netctl.context module owns local YAML/schema loading, validation, duplicate-ID detection, and summary creation. The existing CLI calls it and persists successful results with SQLite helpers; it never contacts network devices.

**Tech Stack:** Python 3.14, PyYAML 6.0.2, jsonschema 4.23.0, SQLite, pytest 8.3.4.

## Global Constraints

- Read only explicitly supplied local YAML and local JSON Schema; never fetch a schema.
- Do not contact or change any production-network component.
- Do not add API routes, UI pages, device/link imports, or host/IP-model changes.
- Resolve schemas: --schema; then <repo-root>/schemas/network-context.schema.json; then NETCTL_CONTEXT_SCHEMA.
- Invalid input returns non-zero and never replaces the latest success.
- Repeated validation of one context ID/SHA-256 pair is idempotent.

---

## File Structure

- Create: netctl/context.py — pure local loading, validation, duplicate-ID checks, summary.
- Modify: netctl/db.py:27-154 — revision-table DDL and persistence helpers.
- Modify: netctl/cli.py:17-453 — context command parser and handlers.
- Modify: requirements.txt:1-10 — pinned dependencies.
- Create: tests/test_netctl_context.py — unit and CLI tests using only temporary files/databases.

### Task 1: Define and implement the pure context contract

**Files:**
- Modify: requirements.txt:1-10
- Create: tests/test_netctl_context.py
- Create: netctl/context.py

**Interfaces:**
- Produces load_context(path: Path) -> dict[str, Any].
- Produces load_schema(path: Path) -> dict[str, Any].
- Produces validate_context(document: dict[str, Any], schema: dict[str, Any]) -> list[dict[str, str]].
- Produces context_summary(document: dict[str, Any], raw_bytes: bytes) -> dict[str, Any].

- [ ] **Step 1: Write the failing fixture and summary test**

~~~
def write_context_files(tmp_path: Path) -> tuple[Path, Path, dict[str, Any]]:
    document = {
        "schema_version": "2.2.0",
        "metadata": {"context_id": "test-network"},
        "sites": [{"id": "central"}], "segments": [{"id": "central-lan"}],
        "devices": [{"id": "router"}], "services": [{"id": "web"}],
        "features": [{"id": "vpn"}], "risks": [{"id": "flat-lan"}],
    }
    schema = {"type": "object", "required": ["schema_version", "metadata", "sites"],
              "properties": {"schema_version": {"const": "2.2.0"},
                             "metadata": {"type": "object", "required": ["context_id"]},
                             "sites": {"type": "array"}}}
    context_path, schema_path = tmp_path / "context.yaml", tmp_path / "network-context.schema.json"
    context_path.write_text(yaml.safe_dump(document), encoding="utf-8")
    schema_path.write_text(json.dumps(schema), encoding="utf-8")
    return context_path, schema_path, document

def test_context_summary_reports_stable_sha_and_collection_counts(tmp_path):
    from netctl.context import context_summary, load_context
    context_path, _schema_path, document = write_context_files(tmp_path)
    assert context_summary(load_context(context_path), context_path.read_bytes()) == context_summary(document, context_path.read_bytes())
    assert context_summary(document, context_path.read_bytes())["counts"] == {
        "sites": 1, "locations": 0, "segments": 1, "devices": 1,
        "services": 1, "links": 0, "features": 1, "risks": 1,
    }
~~~

- [ ] **Step 2: Run the test and verify RED**

Run: python -m pytest tests/test_netctl_context.py::test_context_summary_reports_stable_sha_and_collection_counts -q

Expected: FAIL because netctl.context does not exist.

- [ ] **Step 3: Add dependencies and minimal implementation**

Append these lines to requirements.txt:

~~~
PyYAML==6.0.2
jsonschema==4.23.0
~~~

In netctl/context.py define:

~~~
COUNT_FIELDS = ("sites", "locations", "segments", "devices", "services", "links", "features", "risks")

def context_summary(document: dict[str, Any], raw_bytes: bytes) -> dict[str, Any]:
    metadata = document.get("metadata") if isinstance(document.get("metadata"), dict) else {}
    return {
        "context_id": str(metadata.get("context_id") or ""),
        "schema_version": str(document.get("schema_version") or ""),
        "sha256": hashlib.sha256(raw_bytes).hexdigest(),
        "counts": {name: len(document.get(name, [])) if isinstance(document.get(name), list) else 0 for name in COUNT_FIELDS},
    }
~~~

load_context reads bytes with Path.read_bytes and yaml.safe_load; it raises ValueError("context YAML must contain an object") when the result is not a dict. load_schema reads UTF-8 JSON and raises ValueError("context schema must contain an object") when the result is not a dict.

- [ ] **Step 4: Verify GREEN and commit**

Run: python -m pytest tests/test_netctl_context.py::test_context_summary_reports_stable_sha_and_collection_counts -q

Expected: PASS.

~~~
git add requirements.txt tests/test_netctl_context.py netctl/context.py
git commit -m "feat: add network context loader"
~~~

### Task 2: Validate JSON Schema and duplicate IDs

**Files:**
- Modify: netctl/context.py
- Modify: tests/test_netctl_context.py

**Interfaces:**
- Consumes a decoded document and Draft 2020-12 JSON Schema.
- Produces sorted dictionaries with path and message keys.

- [ ] **Step 1: Write failing validation tests**

~~~
def test_validate_context_reports_schema_and_duplicate_id_errors(tmp_path):
    from netctl.context import load_context, load_schema, validate_context
    context_path, schema_path, document = write_context_files(tmp_path)
    document["sites"].append({"id": "central"})
    document.pop("schema_version")
    context_path.write_text(yaml.safe_dump(document), encoding="utf-8")
    errors = validate_context(load_context(context_path), load_schema(schema_path))
    assert {error["path"] for error in errors} >= {"schema_version", "sites.1.id"}
    assert any(error["message"] == "duplicate id 'central'" for error in errors)

def test_load_context_and_schema_report_missing_files(tmp_path):
    from netctl.context import load_context, load_schema
    with pytest.raises(FileNotFoundError):
        load_context(tmp_path / "missing.yaml")
    with pytest.raises(FileNotFoundError):
        load_schema(tmp_path / "missing.schema.json")
~~~

- [ ] **Step 2: Run and verify RED**

Run: python -m pytest tests/test_netctl_context.py -q

Expected: FAIL because validate_context is absent.

- [ ] **Step 3: Implement deterministic validation**

Use Draft202012Validator(schema).iter_errors(document), sort by tuple(error.absolute_path), and map schema violations to:

~~~
{"path": ".".join(str(part) for part in error.absolute_path), "message": error.message}
~~~

For every top-level list, track string ID values inside that list only. For every duplicate append:

~~~
{"path": f"{collection}.{index}.id", "message": f"duplicate id '{item_id}'"}
~~~

Sort the combined errors by (path, message). IDs in distinct collections remain independent.

- [ ] **Step 4: Verify GREEN and commit**

Run: python -m pytest tests/test_netctl_context.py -q

Expected: PASS.

~~~
git add netctl/context.py tests/test_netctl_context.py
git commit -m "feat: validate network context identifiers"
~~~

### Task 3: Store successful revisions idempotently

**Files:**
- Modify: netctl/db.py:27-154
- Modify: tests/test_netctl_context.py

**Interfaces:**
- Produces record_context_revision(conn, context, source_path, git_sha) -> dict[str, Any].
- Produces latest_context_revision(conn) -> dict[str, Any] | None.

- [ ] **Step 1: Write the failing persistence test**

~~~
def test_context_revision_is_idempotent_and_status_returns_latest(tmp_path):
    from netctl.db import connect, latest_context_revision, record_context_revision
    conn = connect(f"sqlite:///{(tmp_path / 'netctl.sqlite').as_posix()}")
    context = {"context_id": "test-network", "schema_version": "2.2.0", "sha256": "a" * 64, "counts": {}}
    try:
        first = record_context_revision(conn, context, tmp_path / "context.yaml", "abc123")
        second = record_context_revision(conn, context, tmp_path / "context.yaml", "abc123")
        assert first["id"] == second["id"]
        assert conn.execute("SELECT COUNT(*) FROM context_revisions").fetchone()[0] == 1
        assert latest_context_revision(conn)["sha256"] == "a" * 64
    finally:
        conn.close()
~~~

- [ ] **Step 2: Run and verify RED**

Run: python -m pytest tests/test_netctl_context.py::test_context_revision_is_idempotent_and_status_returns_latest -q

Expected: FAIL because the table/helper is absent.

- [ ] **Step 3: Add DDL and helpers**

Add this DDL inside ensure_schema:

~~~
CREATE TABLE IF NOT EXISTS context_revisions (
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
);
~~~

record_context_revision uses INSERT OR IGNORE with status "ok", error_json "[]", commits, then selects by context_id and sha256. latest_context_revision selects status = "ok" ordered by validated_at DESC, id DESC.

- [ ] **Step 4: Verify GREEN and commit**

Run: python -m pytest tests/test_netctl_context.py tests/test_netctl_cli.py -q

Expected: PASS.

~~~
git add netctl/db.py tests/test_netctl_context.py
git commit -m "feat: store validated context revisions"
~~~

### Task 4: Add JSON CLI validation and status

**Files:**
- Modify: netctl/cli.py:17-453
- Modify: tests/test_netctl_context.py

**Interfaces:**
- Produces netctl --json --db URL context validate --path PATH [--schema PATH] [--git-sha SHA].
- Produces netctl --json --db URL context status [--path PATH] [--schema PATH] [--git-sha SHA].

- [ ] **Step 1: Write failing CLI tests**

~~~
def test_context_validate_then_status_returns_recorded_revision(tmp_path, capsys):
    context_path, schema_path, _document = write_context_files(tmp_path)
    db_url = f"sqlite:///{(tmp_path / 'netctl.sqlite').as_posix()}"
    rc, valid = run_cli(["--json", "--db", db_url, "context", "validate", "--path", str(context_path),
                         "--schema", str(schema_path), "--git-sha", "abc123"], capsys)
    status_rc, status = run_cli(["--json", "--db", db_url, "context", "status"], capsys)
    assert rc == status_rc == 0
    assert valid["context"]["git_sha"] == status["context"]["git_sha"] == "abc123"

def test_context_validate_invalid_document_keeps_last_successful_revision(tmp_path, capsys):
    context_path, schema_path, document = write_context_files(tmp_path)
    db_url = f"sqlite:///{(tmp_path / 'netctl.sqlite').as_posix()}"
    assert run_cli(["--json", "--db", db_url, "context", "validate", "--path", str(context_path),
                    "--schema", str(schema_path)], capsys)[0] == 0
    document.pop("schema_version")
    context_path.write_text(yaml.safe_dump(document), encoding="utf-8")
    invalid_rc, invalid = run_cli(["--json", "--db", db_url, "context", "validate", "--path", str(context_path),
                                   "--schema", str(schema_path)], capsys)
    status_rc, status = run_cli(["--json", "--db", db_url, "context", "status"], capsys)
    assert invalid_rc != 0 and invalid["status"] == "error"
    assert status_rc == 0 and status["context"]["schema_version"] == "2.2.0"
~~~

- [ ] **Step 2: Run and verify RED**

Run: python -m pytest tests/test_netctl_context.py -q

Expected: FAIL because context is not an accepted CLI command.

- [ ] **Step 3: Implement the parser, resolver, and handlers**

Both children accept --path, --schema, and --git-sha; require --path only for validate. Use this resolver:

~~~
def resolve_context_schema(path: Path, explicit_schema: str) -> Path:
    candidates = [Path(explicit_schema)] if explicit_schema else []
    candidates.append(path.parent.parent / "schemas" / "network-context.schema.json")
    if os.environ.get("NETCTL_CONTEXT_SCHEMA"):
        candidates.append(Path(os.environ["NETCTL_CONTEXT_SCHEMA"]))
    for candidate in candidates:
        if candidate.is_file():
            return candidate
    raise FileNotFoundError("network context schema not found; use --schema or NETCTL_CONTEXT_SCHEMA")
~~~

Validate reads raw YAML bytes, calls pure helpers, returns err("network context validation failed", errors=errors) with code 1 for validation errors, otherwise records and returns ok(context=revision, errors=[]). File/parse errors return err(str(exc), errors=[]) with code 1. Status returns err("no successful context validation found", errors=[]) with code 1 if no revision, otherwise ok(context=revision, errors=[]).

- [ ] **Step 4: Verify GREEN, full regression, and commit**

Run: python -m pytest tests/test_netctl_context.py -q

Expected: PASS.

Run: python -m pytest -q

Expected: all existing tests and the new tests pass.

~~~
git add netctl/cli.py tests/test_netctl_context.py
git commit -m "feat: add netctl context commands"
~~~

### Task 5: Run canonical acceptance without network access

**Files:**
- Modify: none
- Test input: C:\Temp\network_configuration-plan-019f5ab8\config\network-context.yaml
- Test schema: C:\Temp\network_configuration-plan-019f5ab8\schemas\network-context.schema.json

- [ ] **Step 1: Run regression and diff checks**

Run: git diff --check main...HEAD

Expected: no output.

Run: python -m pytest -q

Expected: all tests pass.

- [ ] **Step 2: Validate the canonical file and show status**

~~~
$dbPath = Join-Path $env:TEMP 'netctl-context-test.sqlite3'
Remove-Item -LiteralPath $dbPath -Force -ErrorAction SilentlyContinue
$db = "sqlite:///$($dbPath.Replace('\', '/'))"
$contextRoot = 'C:\Temp\network_configuration-plan-019f5ab8'
$gitSha = git -C $contextRoot rev-parse HEAD
python -m netctl.cli --json --db $db context validate --path "$contextRoot\config\network-context.yaml" --schema "$contextRoot\schemas\network-context.schema.json" --git-sha $gitSha
python -m netctl.cli --json --db $db context status
~~~

Expected: both results have status "ok" and include schema version, SHA-256, Git SHA, source path, and counts.

- [ ] **Step 3: Reject an invalid disposable copy while preserving status**

~~~
$invalid = Join-Path $env:TEMP 'network-context-invalid.yaml'
(Get-Content -Raw "$contextRoot\config\network-context.yaml").Replace('schema_version: 2.2.0', 'schema_version: invalid') | Set-Content -NoNewline $invalid
python -m netctl.cli --json --db $db context validate --path $invalid --schema "$contextRoot\schemas\network-context.schema.json"
if ($LASTEXITCODE -eq 0) { throw 'invalid context unexpectedly succeeded' }
python -m netctl.cli --json --db $db context status
Remove-Item -LiteralPath $invalid -Force
~~~

Expected: validation returns status "error" and non-zero; status remains the original successful revision.
