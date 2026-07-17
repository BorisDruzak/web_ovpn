# Netctl Runtime Asset Identity Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use `superpowers:subagent-driven-development` (recommended) or `superpowers:executing-plans` to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Implement Phase W1 / PR 2A: a migration-safe runtime asset, interface, IP, hostname, intent-binding, and tag foundation that removes IP uniqueness from *new runtime identity* without deleting or replacing the existing Network Observer model.

**Architecture:** Migration 2 adds a new, additive runtime model alongside `network_hosts`; it never removes or relaxes the legacy table's `UNIQUE(ip)` constraint. Deterministic migration maps MAC-backed legacy hosts to stable runtime assets and converts IP-only hosts to provisional assets, then materialises observations independently from Git-imported `intent_assets`. Existing commands continue using their current legacy queries; new read helpers define the explicit dual-read boundary for the next PR.

**Tech Stack:** Python 3, SQLite, existing `netctl.migrations.MIGRATIONS` runner, PyYAML/jsonschema, pytest.

## Global Constraints

- PR 1B is complete in `main` at merge `337f68812332d365d52bc6433c4aeb7ffed6aa86`; retain its intent import/diff semantics and tests.
- Extend the existing `netctl/migrations.py` registry with migration version `2`; do not add a second migration mechanism.
- `intent_assets` is Git-imported desired context. Runtime `assets` are observed or manually confirmed real devices; neither side overwrites the other.
- Keep `network_hosts`, `host_observations`, DHCP, ARP, bridge, neighbor, and legacy tag tables intact. Do not drop, rename, or remove their IP uniqueness in this PR.
- An IP address is an observation, never a globally unique asset key. New tables must have no `UNIQUE(ip)` or equivalent global unique IP index.
- A runtime asset may have multiple interfaces and multiple MAC addresses.
- A matching runtime/intent string ID must not automatically create a confirmed `asset_intent_bindings` row.
- No live device, OpenVPN, DNS, DHCP, firewall, or other production-network configuration may be contacted or changed.
- Enable SQLite `WAL` and a bounded `busy_timeout`; test both settings.
- Preserve legacy tags, comments, evidence, category/status, source, and first/last-seen values deterministically.
- Add deployment/rollback instructions before production migration and run the full pytest suite.

---

## 1. Runtime data model and identity rules

### 1.1 New version-2 DDL

Migration 2 creates these additive tables. All `created_at`, `updated_at`, `first_seen_at`, and `last_seen_at` values use existing `utc_now()` ISO-UTC output.

```sql
CREATE TABLE assets (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    asset_key TEXT NOT NULL UNIQUE,
    kind TEXT NOT NULL DEFAULT 'unknown',
    status TEXT NOT NULL DEFAULT 'unknown',
    site TEXT NOT NULL DEFAULT '',
    location TEXT NOT NULL DEFAULT '',
    display_name TEXT NOT NULL DEFAULT '',
    identity_confidence INTEGER NOT NULL CHECK (identity_confidence BETWEEN 0 AND 100),
    provisional INTEGER NOT NULL CHECK (provisional IN (0, 1)),
    legacy_comment TEXT NOT NULL DEFAULT '',
    legacy_evidence_json TEXT NOT NULL DEFAULT '[]',
    first_seen_at TEXT NOT NULL,
    last_seen_at TEXT NOT NULL,
    created_at TEXT NOT NULL,
    updated_at TEXT NOT NULL
);

CREATE TABLE asset_interfaces (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    asset_id INTEGER NOT NULL REFERENCES assets(id) ON DELETE RESTRICT,
    interface_key TEXT NOT NULL,
    mac TEXT,
    interface_type TEXT NOT NULL DEFAULT '',
    interface_name TEXT NOT NULL DEFAULT '',
    first_seen_at TEXT NOT NULL,
    last_seen_at TEXT NOT NULL,
    UNIQUE(asset_id, interface_key)
);

CREATE TABLE ip_observations (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    asset_id INTEGER NOT NULL REFERENCES assets(id) ON DELETE RESTRICT,
    asset_interface_id INTEGER REFERENCES asset_interfaces(id) ON DELETE RESTRICT,
    site TEXT NOT NULL DEFAULT '',
    source_id INTEGER REFERENCES network_sources(id) ON DELETE RESTRICT,
    ip TEXT NOT NULL,
    first_seen_at TEXT NOT NULL,
    last_seen_at TEXT NOT NULL,
    is_current INTEGER NOT NULL CHECK (is_current IN (0, 1)),
    observation_source TEXT NOT NULL,
    UNIQUE(asset_id, ip, source_id, observation_source)
);

CREATE TABLE hostname_observations (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    asset_id INTEGER NOT NULL REFERENCES assets(id) ON DELETE RESTRICT,
    hostname TEXT NOT NULL,
    source_id INTEGER REFERENCES network_sources(id) ON DELETE RESTRICT,
    source_type TEXT NOT NULL,
    first_seen_at TEXT NOT NULL,
    last_seen_at TEXT NOT NULL,
    is_current INTEGER NOT NULL CHECK (is_current IN (0, 1)),
    UNIQUE(asset_id, hostname, source_id, source_type)
);

CREATE TABLE asset_intent_bindings (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    asset_id INTEGER NOT NULL REFERENCES assets(id) ON DELETE RESTRICT,
    intent_asset_id INTEGER NOT NULL REFERENCES intent_assets(id) ON DELETE RESTRICT,
    binding_source TEXT NOT NULL,
    confidence INTEGER NOT NULL CHECK (confidence BETWEEN 0 AND 100),
    status TEXT NOT NULL CHECK (status IN ('candidate', 'confirmed', 'rejected', 'retired')),
    first_seen_at TEXT NOT NULL,
    last_seen_at TEXT NOT NULL,
    UNIQUE(asset_id, intent_asset_id, binding_source)
);

CREATE TABLE asset_tag_bindings (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    asset_id INTEGER NOT NULL REFERENCES assets(id) ON DELETE RESTRICT,
    tag TEXT NOT NULL,
    binding_source TEXT NOT NULL,
    first_seen_at TEXT NOT NULL,
    last_seen_at TEXT NOT NULL,
    UNIQUE(asset_id, tag, binding_source)
);

CREATE TABLE legacy_host_asset_mappings (
    legacy_network_host_id INTEGER PRIMARY KEY REFERENCES network_hosts(id) ON DELETE RESTRICT,
    asset_id INTEGER NOT NULL REFERENCES assets(id) ON DELETE RESTRICT,
    mapping_kind TEXT NOT NULL CHECK (mapping_kind IN ('mac', 'provisional')),
    migrated_at TEXT NOT NULL
);
```

Add these indexes. None makes `ip` unique.

```sql
CREATE INDEX assets_site_last_seen_idx ON assets(site, last_seen_at DESC);
CREATE INDEX asset_interfaces_mac_idx ON asset_interfaces(mac) WHERE mac IS NOT NULL;
CREATE INDEX ip_observations_current_ip_idx ON ip_observations(ip, is_current, last_seen_at DESC);
CREATE INDEX ip_observations_asset_current_idx ON ip_observations(asset_id, is_current, last_seen_at DESC);
CREATE INDEX hostname_observations_current_hostname_idx ON hostname_observations(hostname, is_current, last_seen_at DESC);
CREATE INDEX asset_intent_bindings_asset_idx ON asset_intent_bindings(asset_id, status);
CREATE INDEX asset_tag_bindings_tag_idx ON asset_tag_bindings(tag, asset_id);
```

### 1.2 Deterministic legacy mapping

Use `normalize_mac()` from `netctl.normalizer`; only a non-empty normalized result is a MAC identity.

| Legacy condition | `assets.asset_key` | Provisional | Confidence | Interface key |
| --- | --- | --- | --- | --- |
| `network_hosts.mac` normalizes | `mac:<NORMALIZED_MAC>` | `0` | `100` | `mac:<NORMALIZED_MAC>` |
| no valid MAC | `legacy-host:<network_hosts.id>` | `1` | `20` | `legacy-host:<network_hosts.id>:unknown` |

`legacy_host_asset_mappings` records every migrated source row and guarantees the migration does not create a second provisional asset when re-run. For a MAC-backed host, reuse an existing `assets.asset_key = mac:<MAC>` asset and insert one mapping per `network_hosts.id`; this supports multiple legacy IP rows mapping to the same device. For an IP-only host, its mapping points to its one `legacy-host:<id>` asset. A pre-existing mapping to a different asset is an unresolved deterministic migration error and is recorded in the report.

Map legacy columns as follows:

| Legacy value | Runtime destination |
| --- | --- |
| `category` | `assets.kind` |
| `status` | `assets.status` |
| `site` | `assets.site` |
| `display_name`, falling back to `hostname` | `assets.display_name` |
| `comment` | `assets.legacy_comment` |
| `device_evidence_json` | `assets.legacy_evidence_json` |
| `first_seen_at`, `last_seen_at` | `assets` and current observations timestamps |
| `ip` | one current `ip_observations` row |
| `hostname` when non-blank | one current `hostname_observations` row with `source_type = 'legacy_network_host'` |
| `host_observations.ip` / `.hostname` | non-current historical `ip_observations` / `hostname_observations` with `source_type = observation_type` |
| `network_device_tags.tags_json` | one `asset_tag_bindings` row per normalized tag with `binding_source = 'legacy_manual_tag'` |

Resolve `source_id` by matching legacy `last_source` to `network_sources.name`; use `NULL` when no source exists. Parse malformed legacy JSON as an empty evidence/tag list; preserve the original unparseable evidence string in a one-element JSON list rather than discarding it.

### 1.3 Migration report

Create `runtime_asset_migration_reports`:

```sql
CREATE TABLE runtime_asset_migration_reports (
    migration_version INTEGER PRIMARY KEY,
    completed_at TEXT NOT NULL,
    legacy_host_count INTEGER NOT NULL,
    mac_asset_count INTEGER NOT NULL,
    provisional_asset_count INTEGER NOT NULL,
    interface_count INTEGER NOT NULL,
    ip_observation_count INTEGER NOT NULL,
    hostname_observation_count INTEGER NOT NULL,
    tag_binding_count INTEGER NOT NULL,
    unresolved_legacy_host_ids_json TEXT NOT NULL DEFAULT '[]'
);
```

Migration 2 writes one report only after the copy succeeds. It is the deterministic accounting surface: `legacy_host_count = COUNT(legacy_host_asset_mappings) + len(unresolved_legacy_host_ids_json)`. An empty unresolved list is required for a successful normal migration. Reapplying version 2 does not write a second report because `schema_migrations` prevents it.

## 2. Compatibility and transaction boundary

1. `network_hosts` and its `UNIQUE(ip)` constraint remain legacy-only. Existing `netctl hosts`, web pages, MCP network-host reads, tags, and collector writes continue to use it unchanged in PR 2A.
2. Add read-only helpers in `netctl/runtime_assets.py`: `get_runtime_asset_by_key`, `list_asset_interfaces`, `list_current_ip_observations`, `list_current_hostname_observations`, and `runtime_identity_report`. Do not redirect existing UI/CLI queries to them yet.
3. Expose no automatic intent binding. `asset_intent_bindings` starts empty after migration. A later PR may create candidate/confirmed bindings through an explicit operator workflow.
4. Migration 2 executes under the existing `apply_migrations()` savepoint. Any exception rolls back all version-2 tables, copied data, indexes, report row, and migration-ledger insertion.
5. `connect()` sets `PRAGMA foreign_keys = ON`, `PRAGMA journal_mode = WAL`, and `PRAGMA busy_timeout = 5000` before schema use. Tests must assert `foreign_keys = 1`, journal mode `wal`, and busy timeout `5000`.
6. Adding `network_routes.routing_table` is deliberately excluded from PR 2A. File a separate GitHub issue if no existing issue tracks it; do not add an `_ensure_column` change in this branch.

## 3. File map

| File | Change |
| --- | --- |
| `netctl/migrations.py` | Add migration 2 DDL, deterministic legacy copy, and migration report creation. |
| `netctl/db.py` | Configure WAL/busy timeout in `connect()` without changing legacy table schemas. |
| `netctl/runtime_assets.py` | New read-only helpers and report decoder for the new runtime model. |
| `tests/test_netctl_runtime_assets.py` | Migration, mapping, idempotency, rollback, pragmas, and read-helper tests. |
| `tests/test_netctl_cli.py` | Preserve legacy hosts/tags command compatibility after migration. |
| `docs/runbooks/netctl-runtime-asset-identity-backup-rollback.md` | Production backup, preflight, migration verification, and rollback runbook. |
| `README.md` | Link the new runtime-identity migration runbook from Network Observer documentation. |

## 4. Task plan

### Task 1: Write production-compatible migration fixtures and WAL tests

**Files:**

- Create: `tests/test_netctl_runtime_assets.py`
- Modify: `netctl/db.py`

**Interfaces:**

- Produces test helpers `create_pr1b_database(path: Path) -> None` and `seed_legacy_host(...) -> int`.
- Consumes `netctl.db.connect()`.

- [ ] **Step 1: Write failing schema/pragmas tests.**

Add tests that construct the current PR 1B schema with `network_hosts`, `network_device_tags`, `host_observations`, `context_revisions`, and migration-1 tables; then assert opening through `connect()` applies version 2 and returns `foreign_keys == 1`, `journal_mode == 'wal'`, and `busy_timeout == 5000`.

```python
def test_connect_enables_runtime_identity_pragmas_and_migration_2(tmp_path: Path) -> None:
    db_path = tmp_path / "legacy.sqlite"
    create_pr1b_database(db_path)
    conn = connect(f"sqlite:///{db_path.as_posix()}")
    try:
        assert conn.execute("PRAGMA foreign_keys").fetchone()[0] == 1
        assert str(conn.execute("PRAGMA journal_mode").fetchone()[0]).lower() == "wal"
        assert conn.execute("PRAGMA busy_timeout").fetchone()[0] == 5000
        assert conn.execute("SELECT version FROM schema_migrations WHERE version = 2").fetchone()[0] == 2
    finally:
        conn.close()
```

- [ ] **Step 2: Verify RED.**

Run: `python -m pytest tests/test_netctl_runtime_assets.py::test_connect_enables_runtime_identity_pragmas_and_migration_2 -q`

Expected: FAIL because migration 2 and WAL/busy-timeout setup do not exist.

- [ ] **Step 3: Configure connection pragmas.**

In `netctl/db.py`, execute `PRAGMA foreign_keys = ON`, `PRAGMA journal_mode = WAL`, and `PRAGMA busy_timeout = 5000` after opening the connection and before `ensure_schema(conn)`. Do not alter `network_hosts` DDL or the behavior of `db_path_from_url()`.

- [ ] **Step 4: Run the focused RED/GREEN boundary.**

Run: `python -m pytest tests/test_netctl_runtime_assets.py::test_connect_enables_runtime_identity_pragmas_and_migration_2 -q`

Expected: remains FAIL only because migration 2 is absent; WAL/foreign-key assertions pass once migration implementation begins.

- [ ] **Step 5: Commit.**

```bash
git add netctl/db.py tests/test_netctl_runtime_assets.py
git commit -m "test: define runtime identity migration baseline"
```

### Task 2: Add migration 2 schema and deterministic MAC/IP-only mapping

**Files:**

- Modify: `netctl/migrations.py`
- Modify: `tests/test_netctl_runtime_assets.py`

**Interfaces:**

- Produces: `_migration_2(conn: sqlite3.Connection) -> None`
- Produces: `MIGRATIONS = ((1, _migration_1), (2, _migration_2))`

- [ ] **Step 1: Write failing mapping tests.**

Seed three legacy hosts: two rows sharing a normalized MAC with different IPs, one IP-only row, plus historic `host_observations`. Assert one MAC asset with two current IP observations, one provisional asset with key `legacy-host:<id>`, no unique index on `ip_observations.ip`, and an accurate migration report.

```python
assert asset_rows == [("mac:AA:BB:CC:DD:EE:FF", 0), (f"legacy-host:{ip_only_id}", 1)]
assert current_ips_for_mac_asset == {"192.168.100.10", "192.168.100.77"}
assert conn.execute("SELECT COUNT(*) FROM ip_observations WHERE ip = '192.168.100.10'").fetchone()[0] >= 1
```

- [ ] **Step 2: Verify RED.**

Run: `python -m pytest tests/test_netctl_runtime_assets.py -k "mac or provisional or report" -q`

Expected: FAIL because `assets`, observations, and migration report do not exist.

- [ ] **Step 3: Implement the version-2 DDL exactly as section 1.1.**

Add each table and index through `_migration_2()`; use `normalize_mac()` and `utc_now()` only. Do not call `commit()` inside a migration. Include the report table and create its row only after all legacy rows have been copied.

- [ ] **Step 4: Implement legacy-row conversion.**

Iterate `network_hosts` by `id ASC`. Use the mapping table in section 1.2. Insert/reuse assets and interfaces with `INSERT ... ON CONFLICT` only on the declared asset/interface uniqueness keys. Copy each current host IP, historical observation IP/hostname, current hostname, decoded evidence, comments, and legacy manual tags. Never delete or update a legacy row.

- [ ] **Step 5: Verify GREEN.**

Run: `python -m pytest tests/test_netctl_runtime_assets.py -k "mac or provisional or report" -q`

Expected: PASS.

- [ ] **Step 6: Commit.**

```bash
git add netctl/migrations.py tests/test_netctl_runtime_assets.py
git commit -m "feat: add runtime asset identity migration"
```

### Task 3: Preserve tags, comments, evidence, reused IPs, and multiple interfaces

**Files:**

- Modify: `netctl/migrations.py`
- Modify: `tests/test_netctl_runtime_assets.py`

**Interfaces:**

- Consumes migration-2 assets, interfaces, observations, and tag bindings.
- Produces deterministic `runtime_asset_migration_reports` values.

- [ ] **Step 1: Write failing preservation tests.**

Seed a MAC asset with two distinct MAC-bearing legacy rows, a manual tag keyed by the first MAC, comments/evidence, and two different assets that use the same IP at different times. Assert two interfaces for the one asset, retained tag/comment/evidence, and two `ip_observations` records for the reused IP without a uniqueness error.

```python
assert interface_macs == ["AA:BB:CC:DD:EE:01", "AA:BB:CC:DD:EE:02"]
assert set(tags_for_asset) == {"accounting"}
assert asset["legacy_comment"] == "preserve me"
assert json.loads(asset["legacy_evidence_json"]) == ["dhcp", "arp"]
assert reused_ip_asset_ids == {first_asset_id, second_asset_id}
```

- [ ] **Step 2: Verify RED.**

Run: `python -m pytest tests/test_netctl_runtime_assets.py -k "tags or evidence or reused_ip or multiple_interfaces" -q`

Expected: FAIL until copy and deduplication preserve all values.

- [ ] **Step 3: Implement deterministic preservation.**

Decode `network_device_tags.tags_json` using the existing list semantics; bind each tag once with `binding_source = 'legacy_manual_tag'`. Merge asset timestamps with `min(first_seen_at)` and `max(last_seen_at)`. Preserve evidence as JSON lists and store unparseable original evidence as one string entry. Keep observations distinct by the DDL uniqueness tuple; never collapse records merely because their IP matches.

- [ ] **Step 4: Verify GREEN.**

Run: `python -m pytest tests/test_netctl_runtime_assets.py -k "tags or evidence or reused_ip or multiple_interfaces" -q`

Expected: PASS.

- [ ] **Step 5: Commit.**

```bash
git add netctl/migrations.py tests/test_netctl_runtime_assets.py
git commit -m "test: preserve legacy runtime identity evidence"
```

### Task 4: Prove migration rollback and idempotence

**Files:**

- Modify: `netctl/migrations.py`
- Modify: `tests/test_netctl_runtime_assets.py`

**Interfaces:**

- Consumes the existing `apply_migrations()` savepoint.
- Produces no additional transaction mechanism.

- [ ] **Step 1: Write failing transaction tests.**

Use a SQLite trigger that raises on the second legacy asset insert. Assert no version-2 table exists, no `schema_migrations` version 2 row exists, and every legacy table row remains byte-for-byte unchanged after reopening the database. Add a second test that opens a successfully migrated database twice and asserts each new-table count and report row remains unchanged.

- [ ] **Step 2: Verify RED.**

Run: `python -m pytest tests/test_netctl_runtime_assets.py -k "rollback or idempotent" -q`

Expected: FAIL until migration-2 work remains wholly inside the existing savepoint.

- [ ] **Step 3: Keep all migration-2 writes transaction-owned by `apply_migrations()`.**

Do not add any helper `commit()`. If migration helpers are extracted, accept `conn` and return counts only. Ensure the report row and version-2 ledger insert are part of the same savepoint.

- [ ] **Step 4: Verify GREEN.**

Run: `python -m pytest tests/test_netctl_runtime_assets.py -k "rollback or idempotent" -q`

Expected: PASS.

- [ ] **Step 5: Commit.**

```bash
git add netctl/migrations.py tests/test_netctl_runtime_assets.py
git commit -m "test: verify runtime identity migration rollback"
```

### Task 5: Add read-only runtime asset helpers and legacy compatibility checks

**Files:**

- Create: `netctl/runtime_assets.py`
- Modify: `tests/test_netctl_runtime_assets.py`
- Modify: `tests/test_netctl_cli.py`

**Interfaces:**

```python
def get_runtime_asset_by_key(conn: sqlite3.Connection, asset_key: str) -> dict[str, Any] | None: ...
def list_asset_interfaces(conn: sqlite3.Connection, asset_id: int) -> list[dict[str, Any]]: ...
def list_current_ip_observations(conn: sqlite3.Connection, asset_id: int) -> list[dict[str, Any]]: ...
def list_current_hostname_observations(conn: sqlite3.Connection, asset_id: int) -> list[dict[str, Any]]: ...
def runtime_identity_report(conn: sqlite3.Connection) -> dict[str, Any] | None: ...
```

- [ ] **Step 1: Write failing helper/compatibility tests.**

After migrating a fixture, assert helpers return interfaces and current observations sorted deterministically. Run existing `netctl hosts list`, `hosts inspect`, and tags commands against the same database; assert they still return the legacy host records and manual tags.

- [ ] **Step 2: Verify RED.**

Run: `python -m pytest tests/test_netctl_runtime_assets.py -k "read_helper" tests/test_netctl_cli.py -q`

Expected: FAIL because `netctl.runtime_assets` is absent; legacy tests remain green before any code change.

- [ ] **Step 3: Implement read-only helpers.**

Use parameterized SQL and return `dict(row)` values. Order interfaces by `id`, current IPs by `ip, last_seen_at DESC`, current hostnames by `hostname, last_seen_at DESC`; decode the migration report JSON. Do not modify `netctl.store`, `query_hosts`, web routes, MCP tools, or CLI parser in this task.

- [ ] **Step 4: Verify GREEN.**

Run: `python -m pytest tests/test_netctl_runtime_assets.py -k "read_helper" tests/test_netctl_cli.py -q`

Expected: PASS.

- [ ] **Step 5: Commit.**

```bash
git add netctl/runtime_assets.py tests/test_netctl_runtime_assets.py tests/test_netctl_cli.py
git commit -m "feat: add runtime asset identity read helpers"
```

### Task 6: Add production backup/rollback guidance and final verification

**Files:**

- Create: `docs/runbooks/netctl-runtime-asset-identity-backup-rollback.md`
- Modify: `README.md`

- [ ] **Step 1: Write the deployment runbook.**

Require the existing context-import rollback set, a fresh SQLite `.backup`, `PRAGMA integrity_check`, a copy of the deployed application tree/wrapper, and a `schema_migrations` query before/after deployment. Include verification queries for: version 2 present once, legacy table counts unchanged, migration report counts, no unique IP index, foreign keys/WAL/busy timeout, and current observer commands.

- [ ] **Step 2: Document rollback.**

Stop `openvpn-web.service`, `netctl-collect.timer`, and `netctl-collect.service`; restore the previous application/wrapper before the backed-up database; verify integrity; start services; then check `netctl --json hosts list` and `netctl --json context status`. Do not include credentials, tokens, private keys, production YAML contents, or SNMP communities.

- [ ] **Step 3: Link the runbook from README.**

Add one Network Observer sentence pointing to the new runbook and stating that PR 2A retains legacy host reads during the compatibility period.

- [ ] **Step 4: Run focused and full verification.**

Run:

```bash
python -m pytest tests/test_netctl_runtime_assets.py tests/test_netctl_context_import.py tests/test_netctl_context_migrations.py tests/test_netctl_cli.py -q
python -m pytest -q
git diff --check
```

Expected: all tests pass, no diff whitespace errors, and no live network/device access occurs.

- [ ] **Step 5: Commit.**

```bash
git add docs/runbooks/netctl-runtime-asset-identity-backup-rollback.md README.md
git commit -m "docs: add runtime identity migration runbook"
```

## 5. Acceptance matrix

| Issue requirement | Evidence |
| --- | --- |
| No global unique runtime IP | DDL inspection plus reused-IP migration test. |
| MAC IP change is one asset | Two legacy IPs map to one `mac:<MAC>` asset. |
| Multiple asset interfaces | Two MACs map to two interface rows for the same asset. |
| IP-only is provisional | `legacy-host:<id>`, provisional `1`, confidence `20`. |
| Tags/comments/evidence survive | Dedicated migration preservation test. |
| Runtime remains separate from intent | `asset_intent_bindings` empty; `intent_assets` count/payload unchanged. |
| Failed migration rolls back | Trigger-injected migration test and reopened legacy DB assertion. |
| Idempotence | Second open has unchanged new-table/report counts. |
| Foreign keys/WAL/busy timeout | PRAGMA assertions in a fresh connection. |
| Existing observer commands work | Existing CLI hosts/tags tests on migrated fixture. |
| Production recovery | Version-2 backup/rollback runbook and README link. |

## 6. Explicitly deferred work

This plan does not implement SNMP/FDB collection, user ownership automation, captive portal, employee authentication, automatic intent binding confirmation, deletion of legacy tables, a web UI rewrite, PostgreSQL, or RouterOS `routing_table` persistence. If route-table persistence is still desired, create a separate issue before implementation rather than extending migration 2.
