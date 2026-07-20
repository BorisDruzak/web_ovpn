# Netctl Context Import and Diff Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use `superpowers:subagent-driven-development` (recommended) or `superpowers:executing-plans` to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Implement PR 1B: atomically import a semantically valid canonical network-context snapshot into versioned intent tables and compare it structurally with the active snapshot, without modifying runtime observations or the production network.

**Architecture:** A validated YAML document identifies immutable, content-addressed `context_revisions` by `(context_id, sha256)`. Each `context import` invocation is separately recorded in `context_import_runs`; only `context_heads` selects the active revision. Canonical entities are stored as revision-scoped intent snapshots, while `network_hosts` and all collector observation tables remain outside the import path.

**Tech Stack:** Python 3, SQLite, `sqlite3`, PyYAML, jsonschema Draft 2020-12, pytest.

## Global Constraints

- PR 1A is complete; retain its `context validate` and validation-revision behaviour.
- The canonical source is an explicitly supplied local YAML file and an explicitly supplied or locally resolved JSON Schema; never fetch either at runtime.
- The import must not contact or modify MikroTik, OpenVPN, DNS, DHCP, switches, firewall rules, or any production-network configuration.
- `context_revisions` are content-addressed by exactly `(context_id, sha256)` and are not an import-attempt log.
- Every import attempt gets one `context_import_runs` row. A new Git SHA for identical content creates a new run, not a new revision or intent rows.
- `context_heads` is the sole authority for the active revision of a `context_id`; validation alone never activates content.
- YAML `devices` are imported only to `intent_assets`; do not insert into `network_hosts`, runtime `assets`, or observation tables.
- Every `intent_*` row belongs to one `context_revision_id`. No import code may physically delete an intent row.
- Entity IDs are namespaced by entity type. The same `stable_id` is legal in different collections and is compared as `(entity_type, stable_id)`.
- Run schema and semantic validation before materialising intent rows or activating a head.
- YAML key order and top-level collection order must not affect entity hashes or diff results.
- Preserve the previous active head on semantic-validation, transactional, or database failures.
- Add a migration test from the current PR 1A SQLite schema, backup/rollback runbook, rollback tests, and the full pytest regression.

---

## 1. Scope and explicit non-goals

This PR imports the following canonical collections:

| YAML collection | Intent table | Entity type |
| --- | --- | --- |
| `sites` | `intent_sites` | `site` |
| `locations` | `intent_locations` | `location` |
| `segments` | `intent_segments` | `segment` |
| `devices` | `intent_assets` | `asset` |
| `services` | `intent_services` | `service` |
| `links` | `intent_links` | `link` |

`features`, `risks`, `routing_intent`, `wan`, `dhcp`, and `dns` continue to be validated by the existing schema but are not materialised in PR 1B. They must not be silently copied into a different intent table. A later PR may add a separately versioned table for each collection.

This PR does not create a runtime `assets` model, `asset_interfaces`, SNMP sources, FDB rows, UI pages, reconciliation findings, or device-write operations. In particular, it must not alter `network_hosts`, `host_observations`, `dhcp_leases`, `arp_entries`, `bridge_hosts`, or any other observation/collector table.

## 2. Fixed data model

### 2.1 `context_revisions`: immutable content identity

Keep the existing PR 1A table and its unique `(context_id, sha256)` constraint. From PR 1B onward, `record_context_revision()` must use `INSERT ... ON CONFLICT(context_id, sha256) DO NOTHING`, then select the existing row. It must never update a row's schema version, SHA, counts, source path, Git SHA, or timestamp.

The existing `source_path`, `git_sha`, `validated_at`, `status`, `error_json`, `counts_json`, and `validation_order` columns remain for migration compatibility. They are legacy validation metadata, not import provenance. New PR 1B logic does not mutate them and does not use `git_sha` to distinguish revisions. The authoritative source path and Git SHA for an import are stored in `context_import_runs`.

An already existing PR 1A row is a valid content revision even if it has no imported snapshot yet. Its first successful PR 1B import creates its intent rows exactly once.

### 2.2 `context_import_runs`: one durable audit record per attempt

Create the following table. `context_revision_id` is nullable because a schema or semantic failure has no importable content revision. `input_sha256` is recorded even for such failures.

```sql
CREATE TABLE context_import_runs (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    context_id TEXT NOT NULL DEFAULT '',
    context_revision_id INTEGER REFERENCES context_revisions(id) ON DELETE RESTRICT,
    base_context_revision_id INTEGER REFERENCES context_revisions(id) ON DELETE RESTRICT,
    input_sha256 TEXT NOT NULL DEFAULT '',
    git_sha TEXT NOT NULL,
    source_path TEXT NOT NULL,
    started_at TEXT NOT NULL,
    finished_at TEXT,
    status TEXT NOT NULL CHECK (status IN (
        'running',
        'success_imported',
        'success_noop_same_content',
        'success_activated_existing_content',
        'validation_error',
        'db_error'
    )),
    errors_json TEXT NOT NULL DEFAULT '[]'
);
CREATE INDEX context_import_runs_context_started_idx
    ON context_import_runs(context_id, started_at DESC, id DESC);
```

`git_sha` is required for `context import`; an empty provenance value is not acceptable for an activation attempt. `source_path` records the supplied file path, not a copied YAML payload. `errors_json` contains the deterministic structured validation errors or the database error string wrapped as one error object.

### 2.3 `context_heads`: only active-revision selector

```sql
CREATE TABLE context_heads (
    context_id TEXT PRIMARY KEY,
    context_revision_id INTEGER NOT NULL
        REFERENCES context_revisions(id) ON DELETE RESTRICT,
    activated_by_import_run_id INTEGER NOT NULL
        REFERENCES context_import_runs(id) ON DELETE RESTRICT,
    activated_at TEXT NOT NULL
);
```

There is at most one head per `context_id`. There is no `active` flag in `context_revisions` or any `intent_*` table. A revision becomes active only through an insert/update of this table in the same transaction as the materialised snapshot and successful run update.

### 2.4 Versioned intent snapshot tables

Each entity table has a separate ID namespace and the following common columns:

```sql
id INTEGER PRIMARY KEY AUTOINCREMENT,
context_revision_id INTEGER NOT NULL REFERENCES context_revisions(id) ON DELETE RESTRICT,
stable_id TEXT NOT NULL,
lifecycle TEXT NOT NULL CHECK (lifecycle IN ('active', 'retired')),
canonical_json TEXT NOT NULL,
canonical_hash TEXT NOT NULL,
origin_context_revision_id INTEGER NOT NULL REFERENCES context_revisions(id) ON DELETE RESTRICT,
UNIQUE(context_revision_id, stable_id)
```

Create `intent_sites`, `intent_locations`, `intent_segments`, `intent_assets`, and `intent_services` with exactly those common columns. `intent_links` adds queryable link fields while retaining its complete canonical payload:

```sql
relation TEXT NOT NULL CHECK (relation IN (
    'CONNECTED_TO', 'MEMBER_OF', 'ROUTED_VIA', 'RUNS_ON', 'USED_BY',
    'LOCATED_AT', 'CAN_ACCESS', 'AFFECTED_BY', 'RESOLVED_BY'
)),
endpoint_a_json TEXT NOT NULL,
endpoint_b_json TEXT NOT NULL
```

Add an index named `<table>_revision_lifecycle_idx` on `(context_revision_id, lifecycle)` to every intent table, and an index named `<table>_revision_hash_idx` on `(context_revision_id, canonical_hash)` to `intent_links` and the five generic entity tables.

For a new snapshot, the entities present in the YAML are inserted with `lifecycle = 'active'`. For each entity in the prior head that is absent from the new YAML, copy its `stable_id`, `canonical_json`, `canonical_hash`, and `origin_context_revision_id` into the corresponding new-revision table with `lifecycle = 'retired'`. Thus removal is represented in the new snapshot and history is never deleted. `origin_context_revision_id` is the first revision in which that exact intent entity payload was materialised; it remains unchanged when an entity is carried forward or retired.

The canonical-YAML count is the number of active entities supplied by the YAML. The total rows in an intent snapshot can be larger because it includes retired entities; acceptance checks must compare canonical counts only with active rows.

## 3. Canonicalisation, semantic validation, and diff

### 3.1 Canonical entity representation

Add these public functions to `netctl/context.py`:

```python
IMPORT_COLLECTIONS: dict[str, tuple[str, str]]
RELATION_TYPES: frozenset[str]

def validate_import_semantics(document: dict[str, Any]) -> list[dict[str, str]]: ...
def canonical_entity_json(entity: dict[str, Any]) -> str: ...
def canonical_entity_hash(entity: dict[str, Any]) -> str: ...
def normalise_import_entities(document: dict[str, Any]) -> dict[str, dict[str, dict[str, Any]]]: ...
```

`canonical_entity_json()` must use:

```python
json.dumps(entity, ensure_ascii=False, sort_keys=True, separators=(",", ":"), allow_nan=False)
```

and `canonical_entity_hash()` must return the SHA-256 hex digest of that UTF-8 JSON string. The normalised collection shape is `{entity_type: {stable_id: entity}}`; its construction sorts collection members by `id` before comparing them. That makes top-level list ordering and mapping-key ordering irrelevant. List ordering *inside an entity* remains part of the entity payload and therefore remains semantically meaningful in this PR.

### 3.2 Semantic-validation contract

Run existing JSON-Schema and duplicate-ID validation first, then run `validate_import_semantics()` in memory. It must return sorted `{path, message}` errors and reject all of the following before any intent snapshot write:

1. Duplicate IDs within each imported collection (`sites`, `locations`, `segments`, `devices`, `services`, `links`).
2. A missing, non-string, or blank `id` in any imported entity.
3. A link `relation` not in `RELATION_TYPES`.
4. A link `confidence` where `type(value) is not int` or `value < 0` or `value > 100`. Boolean values are invalid even though Python treats them as integers.
5. A missing or non-object `endpoint_a` or `endpoint_b`.
6. An endpoint whose `device` is missing, non-string, or blank; an optional `interface`, when present, must be a non-blank string.
7. An endpoint device reference that is not the `id` of an active YAML `devices` member.

The permitted link relations are fixed in this PR to:

```text
CONNECTED_TO, MEMBER_OF, ROUTED_VIA, RUNS_ON, USED_BY,
LOCATED_AT, CAN_ACCESS, AFFECTED_BY, RESOLVED_BY
```

Same textual IDs in different collections are deliberately valid. For example, a `site` and a `device` may both have `id: central`; only two `devices` named `central` are invalid. Link endpoint references always resolve in the `devices` namespace, which imports as `intent_assets`.

### 3.3 Structural diff contract

Add a pure function in a new `netctl/context_diff.py`:

```python
def diff_snapshots(
    base: dict[str, dict[str, dict[str, Any]]],
    candidate: dict[str, dict[str, dict[str, Any]]],
) -> list[dict[str, str]]: ...
```

It compares the union of `(entity_type, stable_id)` keys and returns one sorted record for every entity:

```json
{
  "entity_type": "asset",
  "stable_id": "core-router",
  "change": "added|changed|removed|unchanged",
  "before_hash": "... or null",
  "after_hash": "... or null"
}
```

`changed` means both entities exist and their canonical JSON hashes differ. A retired item in the base snapshot is treated as absent intent for comparison: it is `added` if active in the candidate and `unchanged` if it remains retired in a materialised-to-materialised comparison. The CLI candidate is always a raw YAML document, so `context diff` compares active candidate entities with the active portion of the current head. It does not insert a revision, a run, or intent rows.

## 4. Import state machine and atomicity

The required states and write boundaries are:

```text
read YAML/schema -> schema validation -> semantic validation
    -> validation_error run (only when invalid; no revision, intent, or head write)
    -> create/reuse immutable revision + running import run
    -> BEGIN IMMEDIATE: materialise/reuse snapshot + update head + mark run success
    -> COMMIT
```

Detailed behaviour:

1. Read the YAML bytes once. Parse, schema-validate, calculate raw SHA-256, and semantically validate entirely in memory.
2. On schema or semantic errors, insert one finished `context_import_runs` row with `status = 'validation_error'`, `context_revision_id = NULL`, and the sorted errors. Do not create intent rows or modify `context_heads`.
3. For valid input, create or reuse the immutable content revision and insert a committed `running` run. This short transaction makes a DB failure attributable to the attempt without making the revision active.
4. Begin a new `BEGIN IMMEDIATE` transaction. Read the existing head for the same `context_id`.
5. If the candidate revision is already that head, create no intent rows, update the run to `success_noop_same_content`, and commit. This is the required result for **same YAML + new Git SHA**. The new run is preserved with its distinct Git SHA; no revision or objects are duplicated.
6. If the candidate revision already has a complete intent snapshot but is not the head, create no duplicate rows; atomically update the head and finish the run as `success_activated_existing_content`.
7. Otherwise materialise all active candidate entities and inherited retired entities, update/insert `context_heads`, mark the run `success_imported`, and commit all three effects together.
8. If the materialisation transaction fails, roll it back. Attempt a separate short transaction that sets the already-created run to `db_error` and stores the error. The CLI must still report failure if that best-effort audit update also cannot be persisted (for example, a completely unavailable or full database). At no point may the prior head change.

SQLite permits only one writer. Use `BEGIN IMMEDIATE` for the materialise/activate transaction and keep it free of file I/O, YAML parsing, schema validation, and network calls. `connect()` must enable `PRAGMA foreign_keys = ON`, preserve the existing WAL/busy-timeout settings if present, and never involve the collector lock as a substitute for a database transaction.

## 5. CLI contract

Extend `netctl/cli.py` with these commands, retaining the existing argument style:

```bash
netctl --json --db <sqlite-url> context import \
  --path <network-context.yaml> --schema <schema.json> --git-sha <commit>

netctl --json --db <sqlite-url> context diff \
  --path <network-context.yaml> --schema <schema.json>
```

`context import` requires a non-empty `--git-sha`, returns a non-zero code for validation/database failure, and emits at least:

```json
{
  "status": "ok",
  "result": "success_imported",
  "run": {"id": 17, "git_sha": "abc123", "status": "success_imported"},
  "context": {"id": 5, "context_id": "sosn-admin-network", "sha256": "..."},
  "head": {"context_id": "sosn-admin-network", "context_revision_id": 5}
}
```

The identical-content case returns `"result": "success_noop_same_content"`, a new run ID, the same `context_revision_id`, and the unchanged head. `context diff` is read-only and returns its base revision (or `null`), per-change records, and a count summary for `added`, `changed`, `removed`, and `unchanged`.

Keep `context validate` as the PR 1A-compatible content-validation command. It creates/reuses a content revision but never activates it or creates an import run. Preserve the current `context` member of `context status` as a compatibility alias for `latest_validated_revision`, and add explicit fields:

```json
{
  "status": "ok",
  "context": {"...": "latest validated revision compatibility alias"},
  "latest_validated_revision": {"...": "..."},
  "active_head": {"context_id": "...", "context_revision_id": 5, "git_sha": "..."}
}
```

`active_head` is `null` until the first successful import. No output may imply that a validation-only revision is active.

## 6. Files and implementation order

### Task 1: Add the versioned context-import migration

**Files:**

- Create: `netctl/migrations.py`
- Modify: `netctl/db.py`
- Test: `tests/test_netctl_context_migrations.py`

**Interfaces:**

- Produces: `apply_migrations(conn: sqlite3.Connection) -> None`
- Produces: `MIGRATIONS: tuple[tuple[int, Callable[[sqlite3.Connection], None]], ...]`
- Consumes: existing PR 1A `context_revisions` schema and `connect()`.

- [ ] **Step 1: Write the migration regression fixture and failing tests.**

Create a SQLite file with the exact pre-PR-1B `context_revisions` definition used by PR 1A, one persisted revision, and representative rows in `network_hosts`, `host_observations`, and `dhcp_leases`. Assert that migration creates `schema_migrations`, `context_import_runs`, `context_heads`, and all six `intent_*` tables; preserves every legacy row and its primary key; and leaves `context_heads` empty.

- [ ] **Step 2: Run the focused migration test and confirm failure.**

Run: `python -m pytest tests/test_netctl_context_migrations.py -q`

Expected: FAIL because `schema_migrations` and PR 1B tables do not exist.

- [ ] **Step 3: Implement the migration runner and migration 1.**

Implement a `schema_migrations(version INTEGER PRIMARY KEY, applied_at TEXT NOT NULL)` ledger. `apply_migrations()` must run each unapplied migration in ascending version order in one transaction and record the version only after its DDL succeeds. Migration 1 creates exactly the tables, checks, foreign keys, and indexes from section 2. It must not rebuild, drop, or alter existing runtime tables or physically delete any row.

- [ ] **Step 4: Call migrations from `ensure_schema()` and enable foreign keys.**

Call `conn.execute("PRAGMA foreign_keys = ON")` immediately after opening every SQLite connection. Preserve the current base-schema bootstrap for new databases, then call `apply_migrations(conn)` before committing. Do not use `_ensure_column` for new PR 1B tables.

- [ ] **Step 5: Run focused tests.**

Run: `python -m pytest tests/test_netctl_context_migrations.py tests/test_netctl_context.py -q`

Expected: PASS, including the existing PR 1A legacy-schema test.

### Task 2: Make content revisions immutable and add import-run persistence

**Files:**

- Modify: `netctl/db.py`
- Test: `tests/test_netctl_context.py`
- Test: `tests/test_netctl_context_import.py`

**Interfaces:**

- Produces: `create_context_import_run(...) -> dict[str, Any]`
- Produces: `finish_context_import_run(conn, run_id: int, status: str, errors: list[dict[str, str]]) -> dict[str, Any]`
- Produces: `get_context_head(conn, context_id: str) -> dict[str, Any] | None`
- Produces: `set_context_head(conn, context_id: str, revision_id: int, run_id: int) -> dict[str, Any]`

- [ ] **Step 1: Write failing immutability and run tests.**

Test that validating the same `(context_id, sha256)` through a new path/Git SHA returns the same revision row and leaves its stored PR 1A metadata unchanged. Test that two import attempts create two run rows with their distinct Git SHAs even when they point to the same revision.

- [ ] **Step 2: Run the tests to confirm the current mutable upsert fails.**

Run: `python -m pytest tests/test_netctl_context.py -q`

Expected: the new immutability assertions FAIL because `record_context_revision()` currently updates conflict fields.

- [ ] **Step 3: Implement immutable revision and run helpers.**

Change `record_context_revision()` to `DO NOTHING` on its unique conflict. Implement run creation/finish helpers with only the statuses in section 2.2 and head helpers that exclusively read/write `context_heads`. All functions must accept the caller's connection and must not call `commit()`; the caller owns the transaction boundary. In the same task, update the existing `context validate` branch in `netctl/cli.py` to commit after a successful `record_context_revision()` call, so the PR 1A CLI contract remains green before the later CLI-command task.

- [ ] **Step 4: Run focused tests.**

Run: `python -m pytest tests/test_netctl_context.py tests/test_netctl_context_import.py -q`

Expected: PASS.

### Task 3: Implement canonicalisation and semantic validation

**Files:**

- Modify: `netctl/context.py`
- Test: `tests/test_netctl_context_import.py`

**Interfaces:**

- Produces the four functions from section 3.1.
- Consumes: the existing `validate_context(document, schema)` result.

- [ ] **Step 1: Write parameterised failing tests.**

Add one case each for duplicate imported IDs, unsupported relation, boolean confidence, confidence `-1`, confidence `101`, non-object endpoint, blank endpoint device, blank endpoint interface, and a device reference absent from `devices`. Add positive tests showing a site and device sharing the same ID are accepted. Add hash-equality tests for reordered mapping keys and reordered top-level `devices`/`links` lists.

- [ ] **Step 2: Run semantic tests and confirm failure.**

Run: `python -m pytest tests/test_netctl_context_import.py -q`

Expected: FAIL because semantic validation and canonicalisation are absent.

- [ ] **Step 3: Implement deterministic validation and normalisation.**

Use the collection mapping and relation set from this plan. Return sorted structured errors using paths such as `links.0.endpoint_a.device`. Construct the entity map by type and stable ID; never use a global `seen_ids` set.

- [ ] **Step 4: Run focused tests.**

Run: `python -m pytest tests/test_netctl_context_import.py -q`

Expected: PASS.

### Task 4: Materialise immutable intent snapshots and heads

**Files:**

- Create: `netctl/context_import.py`
- Modify: `netctl/db.py`
- Test: `tests/test_netctl_context_import.py`

**Interfaces:**

- Produces: `import_context(conn, document: dict[str, Any], raw_bytes: bytes, source_path: Path, git_sha: str) -> dict[str, Any]`
- Produces: `load_active_snapshot(conn, context_id: str) -> dict[str, dict[str, dict[str, Any]]] | None`
- Consumes: semantic validation and the run/head helpers from tasks 2 and 3.

- [ ] **Step 1: Write failing import tests.**

Cover: first import creates active intent rows and a head; `devices` appears only in `intent_assets`; a removal produces a copied `retired` row in the next revision; the original snapshot remains unchanged; the same content with a new Git SHA creates a second run with `success_noop_same_content`; a previously imported inactive revision reactivates without extra intent rows; and runtime-table row counts remain unchanged.

- [ ] **Step 2: Run import tests and confirm failure.**

Run: `python -m pytest tests/test_netctl_context_import.py -q`

Expected: FAIL because no importer or intent tables are used.

- [ ] **Step 3: Implement the state machine from section 4.**

Perform file/schema/semantic work before opening the materialisation transaction. Persist a finished validation-error run only after validation has completed. For valid input, create/reuse the revision and a `running` run, then use `BEGIN IMMEDIATE` to insert active and inherited-retired entities, upsert `context_heads`, and finish the run. Roll back that transaction on every exception and best-effort mark the run `db_error` afterwards.

- [ ] **Step 4: Run import tests.**

Run: `python -m pytest tests/test_netctl_context_import.py -q`

Expected: PASS.

### Task 5: Implement pure structural diff and CLI commands

**Files:**

- Create: `netctl/context_diff.py`
- Modify: `netctl/cli.py`
- Test: `tests/test_netctl_context_import.py`

**Interfaces:**

- Produces: `diff_snapshots(...) -> list[dict[str, str]]`
- Extends: `netctl context import`, `netctl context diff`, and `netctl context status`.

- [ ] **Step 1: Write failing CLI tests.**

Test `context diff` against an active head for add/change/remove/unchanged results, including reordered YAML collections. Assert it creates no revision, run, head, or intent row. Test import's required Git SHA, successful JSON response, identical-content JSON response, validation-error JSON response, and status output with `latest_validated_revision` plus a nullable `active_head`.

- [ ] **Step 2: Run CLI tests and confirm failure.**

Run: `python -m pytest tests/test_netctl_context_import.py -q`

Expected: FAIL because `import` and `diff` parsers/dispatch paths do not exist.

- [ ] **Step 3: Add parser and dispatch branches.**

Register `import` and `diff` under `context`; require `--path` for both and a non-empty `--git-sha` for import. Reuse the current schema-resolution order. `diff` calls no database write helper. `status` obtains active state only through `get_context_head()` and preserves the documented compatibility alias.

- [ ] **Step 4: Run focused CLI tests.**

Run: `python -m pytest tests/test_netctl_context_import.py tests/test_netctl_context.py -q`

Expected: PASS.

### Task 6: Prove rollback and prior-head preservation

**Files:**

- Test: `tests/test_netctl_context_import.py`

**Interfaces:**

- Consumes: the importer transaction contract from task 4.

- [ ] **Step 1: Write failing rollback tests.**

After a successful baseline import, inject a failure during the second entity-table insert and assert: the previous head revision ID is unchanged; the prior active intent rows are byte-for-byte unchanged; no partial rows exist for the failed candidate revision; runtime table counts are unchanged; and the associated run is `db_error` when the recovery update can execute. Add a semantic-failure test asserting the same head preservation and a `validation_error` run with no candidate intent rows.

- [ ] **Step 2: Run rollback tests and confirm failure.**

Run: `python -m pytest tests/test_netctl_context_import.py -q`

Expected: FAIL until all importer writes share the required transaction.

- [ ] **Step 3: Make transaction ownership explicit.**

Remove internal commits from any helper participating in import materialisation. Use `conn.execute("BEGIN IMMEDIATE")`, `conn.commit()`, and `conn.rollback()` only in the orchestrator. Keep recovery-run updating outside the rolled-back transaction.

- [ ] **Step 4: Run rollback tests.**

Run: `python -m pytest tests/test_netctl_context_import.py -q`

Expected: PASS.

### Task 7: Write the database backup and rollback runbook

**Files:**

- Create: `docs/runbooks/netctl-context-import-backup-rollback.md`
- Modify: `README.md`

**Interfaces:**

- Documents: production deployment before migration and a tested rollback procedure.

- [ ] **Step 1: Document the pre-upgrade backup.**

Use the deployed database path `/var/lib/netctl/netctl.sqlite` unless deployment configuration specifies another `--db` URL. Stop collection before copying, create an SQLite online backup, verify it, and retain its timestamped filename:

```bash
sudo systemctl stop netctl-collect.timer netctl-collect.service
sudo install -d -m 0750 /var/backups/netctl
backup="/var/backups/netctl/netctl-before-context-import-$(date -u +%Y%m%dT%H%M%SZ).sqlite"
sudo sqlite3 /var/lib/netctl/netctl.sqlite ".backup '$backup'"
sudo sqlite3 "$backup" 'PRAGMA integrity_check;'
sudo sha256sum "$backup"
```

Require `ok` from `PRAGMA integrity_check` before proceeding.

- [ ] **Step 2: Document deploy verification.**

Run migration/startup, then execute `netctl --json context status`, one known-good `context diff`, one known-good `context import`, and a query confirming that `context_heads` has one row for the context. Record the successful import run ID and Git SHA in the deployment ticket/log.

- [ ] **Step 3: Document rollback.**

On failed migration or failed post-deploy verification, stop the service and timer, preserve the failed database under a timestamped diagnostic name, restore the verified backup, run `PRAGMA integrity_check`, restart only after success, and verify `context status` again:

```bash
sudo systemctl stop netctl-collect.timer netctl-collect.service
failed="/var/lib/netctl/netctl.failed-$(date -u +%Y%m%dT%H%M%SZ).sqlite"
sudo mv /var/lib/netctl/netctl.sqlite "$failed"
sudo install -m 0640 -o netctl -g netctl "$backup" /var/lib/netctl/netctl.sqlite
sudo sqlite3 /var/lib/netctl/netctl.sqlite 'PRAGMA integrity_check;'
sudo systemctl start netctl-collect.timer
sudo /usr/local/sbin/netctl --json context status
```

- [ ] **Step 4: Add a concise README pointer and review the runbook.**

Link to the runbook from the Network Observer section; do not add credentials, YAML production contents, API tokens, SNMP communities, or private keys.

### Task 8: Full regression and acceptance evidence

**Files:**

- Modify only if a test or documentation correction is required by the evidence.

- [ ] **Step 1: Run focused context tests.**

Run: `python -m pytest tests/test_netctl_context.py tests/test_netctl_context_migrations.py tests/test_netctl_context_import.py -q`

Expected: PASS.

- [ ] **Step 2: Run the complete regression suite.**

Run: `python -m pytest -q`

Expected: PASS with no skipped context-import failure hidden by test selection.

- [ ] **Step 3: Run command-level acceptance checks with disposable files/database.**

Run validate, import, status, diff, an identical-content import with a different Git SHA, and an invalid-link import against a temporary SQLite database. Confirm result statuses respectively include `success_imported`, active head data, add/change/remove/unchanged diff counts, `success_noop_same_content`, and non-zero validation failure with the previous head unchanged.

- [ ] **Step 4: Review migration/rollback evidence.**

Confirm the migration fixture preserves the pre-PR-1B runtime rows and that rollback tests verify no partial candidate intent rows or head changes. Save the full pytest output and command JSON with secrets redacted.

## 7. Requirement-to-test matrix

| Requirement | Primary test evidence |
| --- | --- |
| Content-addressed revisions | Same `(context_id, sha256)` never creates or mutates a second revision row. |
| One run per attempt | Two identical imports with different Git SHA yield two run IDs. |
| Single active pointer | Only `context_heads` changes active revision; validate creates no head. |
| Devices are intent only | `intent_assets` receives devices; runtime table counts do not change. |
| Versioned retention | Removed object is a `retired` row in the next revision; prior row remains. |
| Semantic validation | Invalid endpoints, relations, confidence, and references fail before intent materialisation. |
| Namespaced IDs | Same site/device ID succeeds; duplicate IDs in one collection fail. |
| Structural diff | Key/list ordering is unchanged; payload change changes canonical hash. |
| Same content/new Git SHA | New run, same revision/head, no intent inserts, `success_noop_same_content`. |
| Atomic activation | Injected semantic/DB failure preserves prior head and snapshot. |
| Runtime isolation | `network_hosts` and observation-table counts are unchanged after every import case. |
| Migration, backup, rollback | Current-schema fixture migrates; runbook commands and transaction rollback tests are reviewed. |

## 8. Acceptance criteria

PR 1B is complete only when all of the following are demonstrated:

- `context_revisions` is immutable and unique by `(context_id, sha256)`; its rows are not used as attempt history.
- Every import invocation records a `context_import_runs` result, subject only to unavoidable total-database unavailability documented by the CLI error.
- `context_heads` is the only active-revision mechanism and changes atomically with a completed snapshot.
- Every imported entity row is revision-scoped, namespaced by table/entity type, and never physically deleted.
- Canonical `devices` exist in `intent_assets` only; no runtime observations change.
- All specified semantic validation cases fail before intent/head materialisation.
- `context diff` is deterministic for YAML mapping/key order and top-level collection order, and reports add/change/remove/unchanged by `(entity_type, stable_id)` plus canonical hashes.
- Same content with a new Git SHA produces one new run with `success_noop_same_content`, the existing revision/head, and zero duplicated intent rows.
- A schema, semantic, or injected database failure leaves the prior active revision and all its snapshot rows intact.
- Migration tests start from the current PR 1A SQLite schema, backup/rollback documentation is present, rollback tests pass, and `python -m pytest -q` passes.
