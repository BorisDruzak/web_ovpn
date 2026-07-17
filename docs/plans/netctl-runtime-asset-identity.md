# Netctl Runtime Asset Identity Implementation Plan

> **For agentic workers:** implement this plan with test-driven development. Complete tasks in order and do not start SNMP/FDB ingestion in this PR.

**Status:** approved after architecture review

**Approved identity decision:** during automatic legacy migration, different MAC addresses always create different runtime assets unless separate reliable evidence proves that they are interfaces of one device. IP, hostname, display name, location, and observation timing are not sufficient by themselves to merge assets.

**Goal:** implement Phase W1 / PR 2A: an additive, migration-safe runtime asset, interface, IP, hostname, intent-binding, and tag foundation that removes IP uniqueness from the new runtime identity model while preserving the existing Network Observer model and PR 1B intent snapshots.

**Architecture:** migration version 2 adds runtime identity tables alongside `network_hosts`. Legacy reads and collectors remain unchanged. Runtime assets are seeded conservatively from normalized MAC addresses or provisional legacy-host IDs. Git-imported `intent_assets` remain separate. A later correlation phase may propose merge candidates, but only explicit strong evidence or an operator decision may merge assets.

**Tech stack:** Python 3, SQLite, existing `netctl.migrations.MIGRATIONS`, pytest.

---

## 1. Approved identity contract

### 1.1 Meaning of an asset

A runtime asset is an independently managed device or component with its own lifecycle and state.

```text
workstation                 -> one asset
workstation Ethernet/Wi-Fi -> interfaces of that asset, when ownership is proven
physical server             -> one asset
IPMI/BMC                    -> separate component asset
virtual machine             -> separate asset
hypervisor                  -> separate asset
switch                      -> one asset; switch ports are interfaces
```

### 1.2 Conservative migration policy

```text
same normalized MAC, different IPs -> one asset
same IP, different MACs            -> different assets
different MACs                     -> different assets
no valid MAC                       -> one provisional asset per legacy host row
```

The legacy `network_hosts` table keeps `UNIQUE(ip)`, so the “same IP, different MACs” case is represented and tested as reuse across time through historical observations or sequential states, not as two simultaneous legacy host rows.

Migration must never merge different MACs using only:

```text
IP
hostname
display_name
site/location
observation time
```

These fields may later contribute to a `candidate merge` finding, but not to an automatic merge.

### 1.3 Multiple interfaces

The schema must support multiple interfaces per asset. Migration version 2 does not infer that two different legacy MACs belong to one asset.

Multi-interface support is proven by explicit runtime inserts/read helpers in tests. Future correlation may attach another interface only when supported by strong evidence:

```text
agent device UUID
SMBIOS UUID
serial number
inventory number
explicit operator confirmation
```

### 1.4 NIC replacement

A replacement NIC initially creates a separate MAC-seeded asset. A later confirmed merge may:

```text
keep one surviving asset ID;
attach the new interface;
mark the old interface retired;
preserve both MAC histories;
store merge provenance.
```

Merge/alias history is not implemented in PR 2A.

### 1.5 MAC-derived asset keys

`mac:<MAC>` is a deterministic migration seed, not a permanent organizational identity. NIC replacement and explicit asset merge require future alias/merge semantics.

### 1.6 IP addresses

IP is always an observation with time and source. It is never a globally unique asset key. Reused IPs and duplicate-IP findings must remain representable.

---

## 2. Global constraints

- PR 1B remains intact at merge `337f68812332d365d52bc6433c4aeb7ffed6aa86`.
- Extend the existing `MIGRATIONS` registry with migration version `2`; do not add another migration system.
- `intent_assets` is Git intent; runtime `assets` is observed/manual identity. Neither overwrites the other.
- Keep `network_hosts`, `host_observations`, DHCP, ARP, bridge, neighbor, and legacy tag tables intact.
- Do not remove the legacy `network_hosts.ip UNIQUE` constraint in this PR.
- New runtime IP tables must have no global unique constraint on `ip`.
- Do not automatically confirm runtime-to-intent bindings.
- Do not contact or change network devices, OpenVPN, DNS, DHCP, firewalls, or switches.
- Enable SQLite foreign keys, WAL, and bounded `busy_timeout` with tests.
- Preserve legacy tags, comments, evidence, timestamps, source information, category/status, and unresolved records deterministically.
- Add deployment/rollback documentation before production migration.
- Run focused and full regression tests.

---

## 3. Migration version 2 data model

### 3.1 `assets`

```sql
CREATE TABLE assets (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    asset_key TEXT NOT NULL UNIQUE,
    identity_method TEXT NOT NULL CHECK (identity_method IN ('mac_seed', 'provisional_legacy', 'manual')),
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
```

### 3.2 `asset_interfaces`

```sql
CREATE TABLE asset_interfaces (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    asset_id INTEGER NOT NULL REFERENCES assets(id) ON DELETE RESTRICT,
    interface_key TEXT NOT NULL,
    mac TEXT,
    interface_type TEXT NOT NULL DEFAULT '',
    interface_name TEXT NOT NULL DEFAULT '',
    lifecycle TEXT NOT NULL DEFAULT 'active' CHECK (lifecycle IN ('active', 'retired')),
    first_seen_at TEXT NOT NULL,
    last_seen_at TEXT NOT NULL,
    UNIQUE(asset_id, interface_key)
);
```

Do not add a global unique constraint on `mac`. Duplicate/cloned MAC observations must be representable and investigated rather than causing migration failure.

### 3.3 `ip_observations`

`source_id` is optional provenance. `source_key` is mandatory deterministic identity and participates in deduplication because SQLite treats `NULL` values as distinct in unique constraints.

```sql
CREATE TABLE ip_observations (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    asset_id INTEGER NOT NULL REFERENCES assets(id) ON DELETE RESTRICT,
    asset_interface_id INTEGER REFERENCES asset_interfaces(id) ON DELETE RESTRICT,
    site TEXT NOT NULL DEFAULT '',
    source_id INTEGER REFERENCES network_sources(id) ON DELETE RESTRICT,
    source_key TEXT NOT NULL,
    ip TEXT NOT NULL,
    first_seen_at TEXT NOT NULL,
    last_seen_at TEXT NOT NULL,
    is_current INTEGER NOT NULL CHECK (is_current IN (0, 1)),
    observation_source TEXT NOT NULL,
    UNIQUE(asset_id, ip, source_key, observation_source)
);
```

### 3.4 `hostname_observations`

```sql
CREATE TABLE hostname_observations (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    asset_id INTEGER NOT NULL REFERENCES assets(id) ON DELETE RESTRICT,
    hostname TEXT NOT NULL,
    source_id INTEGER REFERENCES network_sources(id) ON DELETE RESTRICT,
    source_key TEXT NOT NULL,
    source_type TEXT NOT NULL,
    first_seen_at TEXT NOT NULL,
    last_seen_at TEXT NOT NULL,
    is_current INTEGER NOT NULL CHECK (is_current IN (0, 1)),
    UNIQUE(asset_id, hostname, source_key, source_type)
);
```

### 3.5 Stable runtime-to-intent bindings

Do not reference `intent_assets.id` directly because that row belongs to one context revision. Bind to stable intent identity and optionally record the last revision in which the binding was verified.

```sql
CREATE TABLE asset_intent_bindings (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    asset_id INTEGER NOT NULL REFERENCES assets(id) ON DELETE RESTRICT,
    context_id TEXT NOT NULL,
    intent_stable_id TEXT NOT NULL,
    last_verified_context_revision_id INTEGER REFERENCES context_revisions(id) ON DELETE RESTRICT,
    binding_source TEXT NOT NULL,
    confidence INTEGER NOT NULL CHECK (confidence BETWEEN 0 AND 100),
    status TEXT NOT NULL CHECK (status IN ('candidate', 'confirmed', 'rejected', 'retired')),
    first_seen_at TEXT NOT NULL,
    last_seen_at TEXT NOT NULL,
    UNIQUE(asset_id, context_id, intent_stable_id, binding_source)
);
```

Migration version 2 leaves this table empty. Equal string IDs never create an automatic confirmed binding.

### 3.6 Tags and legacy mappings

```sql
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

### 3.7 Migration report

```sql
CREATE TABLE runtime_asset_migration_reports (
    migration_version INTEGER PRIMARY KEY,
    completed_at TEXT NOT NULL,
    legacy_host_count INTEGER NOT NULL,
    mapped_legacy_host_count INTEGER NOT NULL,
    mac_asset_count INTEGER NOT NULL,
    provisional_asset_count INTEGER NOT NULL,
    interface_count INTEGER NOT NULL,
    ip_observation_count INTEGER NOT NULL,
    hostname_observation_count INTEGER NOT NULL,
    tag_binding_count INTEGER NOT NULL,
    unresolved_legacy_host_ids_json TEXT NOT NULL DEFAULT '[]',
    unresolved_observation_ids_json TEXT NOT NULL DEFAULT '[]',
    unresolved_tag_records_json TEXT NOT NULL DEFAULT '[]',
    aggregation_conflicts_json TEXT NOT NULL DEFAULT '[]'
);
```

Successful normal migration requires all legacy hosts to be mapped. Unresolved observations or tag records are allowed only when preserved in the report with reason and original key/ID; they must not be silently discarded.

### 3.8 Indexes

```sql
CREATE INDEX assets_site_last_seen_idx ON assets(site, last_seen_at DESC);
CREATE INDEX asset_interfaces_mac_idx ON asset_interfaces(mac) WHERE mac IS NOT NULL;
CREATE INDEX ip_observations_current_ip_idx ON ip_observations(ip, is_current, last_seen_at DESC);
CREATE INDEX ip_observations_asset_current_idx ON ip_observations(asset_id, is_current, last_seen_at DESC);
CREATE INDEX hostname_observations_current_hostname_idx ON hostname_observations(hostname, is_current, last_seen_at DESC);
CREATE INDEX asset_intent_bindings_asset_idx ON asset_intent_bindings(asset_id, status);
CREATE INDEX asset_tag_bindings_tag_idx ON asset_tag_bindings(tag, asset_id);
```

None of these indexes makes `ip` or `mac` globally unique.

---

## 4. Deterministic legacy mapping

### 4.1 MAC resolution order

For each `network_hosts` row:

1. Normalize `network_hosts.mac`.
2. When the MAC column is absent/invalid, normalize `device_key` only when it starts with `mac:`.
3. If both are valid and differ, use the MAC column, preserve the disagreement in `aggregation_conflicts_json`, and do not merge the two MAC identities.
4. If neither yields a MAC, create a provisional asset.

### 4.2 Asset keys

| Legacy condition | Asset key | Provisional | Confidence | Interface key |
|---|---|---:|---:|---|
| valid normalized MAC | `mac:<MAC>` | 0 | 100 | `mac:<MAC>` |
| no valid MAC | `legacy-host:<network_hosts.id>` | 1 | 20 | `legacy-host:<id>:unknown` |

Different normalized MACs always produce different assets.

### 4.3 Same-MAC aggregation policy

Several legacy rows may map to one MAC asset. Aggregate them deterministically:

```text
first_seen_at = minimum effective first timestamp
last_seen_at  = maximum effective last timestamp
representative row = greatest (effective_last_seen, legacy_host_id)
kind/status/site/display_name/comment = representative row with documented fallbacks
evidence = sorted normalized union from all mapped rows
```

Timestamp fallbacks:

```text
effective_first = first_seen_at or last_seen_at or migration_time
effective_last  = last_seen_at or first_seen_at or migration_time
```

When representative values conflict, keep the selected value and record the alternatives plus source host IDs in `aggregation_conflicts_json`. Iteration order must never determine the result.

### 4.4 Current observations

For each mapped `network_hosts` row:

```text
IP -> current ip_observation
hostname -> current hostname_observation when non-blank
source_key -> legacy-network-host:<host-id>
source_id -> matching network_sources.id when last_source exists; otherwise NULL
```

### 4.5 Historical host observations

Resolve an observation asset in this order:

1. `host_observations.host_id` through `legacy_host_asset_mappings`.
2. Normalized observation MAC when it maps to exactly one MAC-seeded asset.
3. Observation IP when it maps to exactly one legacy host mapping.
4. Otherwise record the observation ID and reason in `unresolved_observation_ids_json`.

For each copied observation:

```text
source_key = legacy-host-observation:<observation-id>
source_id = original source_id only when that network_sources row exists; otherwise NULL
is_current = 0
source_type/observation_source = legacy observation_type
```

An orphaned `source_id` must not break migration.

### 4.6 Manual tag migration

Legacy tag keys are handled explicitly:

```text
mac:<MAC> -> matching MAC-seeded asset
ip:<IP>   -> asset mapped from network_hosts row with that IP
other/unmatched key -> unresolved_tag_records_json
```

Each unresolved record contains at least:

```json
{"device_key":"...","reason":"...","raw_tags_json":"..."}
```

Malformed tag JSON is preserved in the unresolved report. Valid tags are normalized and inserted once with `binding_source = 'legacy_manual_tag'`.

### 4.7 Evidence and comments

- Valid evidence JSON lists are normalized and unioned.
- Invalid evidence JSON is preserved as a literal string element in `legacy_evidence_json`.
- The representative comment is stored in `legacy_comment`.
- Other conflicting non-empty comments remain recoverable in `aggregation_conflicts_json` and in untouched legacy tables.

---

## 5. Compatibility and transaction boundary

1. Existing `netctl hosts`, web pages, MCP host reads, tags, and collectors continue to use legacy tables during PR 2A.
2. Add read-only helpers in `netctl/runtime_assets.py`; do not redirect existing UI/CLI queries yet.
3. `asset_intent_bindings` remains empty after migration.
4. Migration 2 runs inside the existing `apply_migrations()` savepoint. No migration helper may call `commit()`.
5. `connect()` configures before schema use:

```sql
PRAGMA foreign_keys = ON;
PRAGMA journal_mode = WAL;
PRAGMA busy_timeout = 5000;
```

6. `network_routes.routing_table` is outside PR 2A and is tracked in Issue #8.
7. Candidate merge generation and operator merge workflow are deferred. PR 2A only preserves the data model needed for them.

---

## 6. Read-only runtime helpers

Create `netctl/runtime_assets.py`:

```python
def get_runtime_asset_by_key(conn, asset_key): ...
def list_asset_interfaces(conn, asset_id): ...
def list_current_ip_observations(conn, asset_id): ...
def list_current_hostname_observations(conn, asset_id): ...
def runtime_identity_report(conn): ...
```

Requirements:

- parameterized SQL;
- deterministic ordering;
- report JSON fields decoded to arrays;
- no writes;
- no automatic intent binding;
- no existing CLI/UI query replacement.

---

## 7. TDD task sequence

### Task 1 — production-compatible fixture and SQLite pragmas

Create `tests/test_netctl_runtime_assets.py` with a PR 1B production-like schema fixture.

RED tests:

```text
foreign_keys = 1
journal_mode = wal
busy_timeout = 5000
migration version 2 is applied
```

Commands:

```bash
python -m pytest tests/test_netctl_runtime_assets.py::test_connect_enables_runtime_identity_pragmas_and_migration_2 -q
```

Implement only connection pragmas and migration-2 registration required to turn the focused test green.

### Task 2 — migration DDL and conservative mapping

RED tests:

```text
same MAC + changed IP -> one asset, one MAC interface, multiple current IP observations
different MACs -> separate assets even when hostname/display_name overlap
IP-only host -> provisional legacy-host:<id> asset
no global unique IP index
migration report accounts for every legacy host
```

The reused-IP scenario is tested separately as historical/temporal reuse because simultaneous duplicate IP rows are not representable in legacy `network_hosts`.

Commands:

```bash
python -m pytest tests/test_netctl_runtime_assets.py -k "same_mac or different_macs or provisional or report" -q
```

### Task 3 — source keys and observation history

RED tests:

```text
NULL source_id cannot produce duplicate observation rows
orphan host_observations.source_id becomes NULL with deterministic source_key
historical observation resolves through host mapping/MAC/IP precedence
unresolved historical observations are reported
reused IP can belong to different assets at different times
```

Commands:

```bash
python -m pytest tests/test_netctl_runtime_assets.py -k "source_key or orphan_source or history or reused_ip" -q
```

### Task 4 — deterministic aggregation and tags

RED tests:

```text
conflicting same-MAC rows select representative deterministically
first/last timestamps aggregate with documented fallbacks
evidence union is deterministic
mac: tags migrate
ip: tags migrate
unmatched/malformed tag records are reported
```

Commands:

```bash
python -m pytest tests/test_netctl_runtime_assets.py -k "aggregate or evidence or tags" -q
```

### Task 5 — stable intent binding schema and multi-interface capability

RED tests:

```text
asset_intent_bindings stores context_id + intent_stable_id, not intent_assets row identity
binding remains meaningful when context head changes
migration creates no automatic binding
one explicitly created asset can own multiple interfaces
migration never joins different MACs automatically
```

Commands:

```bash
python -m pytest tests/test_netctl_runtime_assets.py -k "intent_binding or multiple_interfaces or no_auto_merge" -q
```

### Task 6 — migration rollback and idempotence

Inject a deterministic failure after partial version-2 work using a test wrapper/hook around the migration copy helper. Do not add a production-only failure flag.

Verify after reopening:

```text
no schema_migrations version 2 row
no partial version-2 data/tables left by the savepoint
legacy rows unchanged
successful second open does not duplicate rows or report
```

Commands:

```bash
python -m pytest tests/test_netctl_runtime_assets.py -k "rollback or idempotent" -q
```

### Task 7 — read helpers and legacy compatibility

Implement `netctl/runtime_assets.py` after RED tests.

Verify:

```text
helpers return deterministic runtime data
legacy hosts list/inspect still works
legacy tags commands still work
PR 1B context import/diff tests remain green
```

Commands:

```bash
python -m pytest tests/test_netctl_runtime_assets.py -k "read_helper" tests/test_netctl_cli.py tests/test_netctl_context_import.py -q
```

### Task 8 — production backup/rollback runbook

Create:

```text
docs/runbooks/netctl-runtime-asset-identity-backup-rollback.md
```

The runbook must include:

```text
stop web/timer/collector
SQLite .backup and integrity_check
application tree and wrapper backup
schema_migrations pre/post query
legacy table count comparison
migration report inspection
check no unique IP index exists
foreign_keys/WAL/busy_timeout verification
legacy observer command verification
restore old application/wrapper before old DB
```

Link it from `README.md`.

### Task 9 — final verification

```bash
python -m pytest tests/test_netctl_runtime_assets.py tests/test_netctl_context_import.py tests/test_netctl_context_migrations.py tests/test_netctl_cli.py -q
python -m pytest -q
git diff --check
```

No live device or production-network access is permitted in tests.

---

## 8. Acceptance matrix

| Requirement | Required evidence |
|---|---|
| Same MAC and changed IP remains one asset | migration test with multiple current IP observations |
| Different MACs are not auto-merged | matching hostname/display_name fixture produces separate assets |
| Reused IP remains historical, not identity | temporal observation fixture maps one IP to different assets at different times |
| Multiple interfaces are supported | explicit runtime insert/read-helper test |
| IP-only host is provisional | `legacy-host:<id>`, provisional=1, confidence=20 |
| IP is not globally unique | DDL/index inspection and reused-IP test |
| NULL source cannot duplicate observations | mandatory `source_key` uniqueness test |
| Intent binding survives context revisions | stable `(context_id, intent_stable_id)` test |
| Tags/comments/evidence survive | deterministic aggregation/tag tests and report |
| Orphan data is not lost | unresolved observation/tag report tests |
| Migration rollback is atomic | failure injection and reopened DB assertions |
| Migration is idempotent | second open has unchanged counts/report |
| Existing observer remains operational | legacy CLI tests on migrated fixture |
| SQLite settings are correct | PRAGMA tests |
| Production recovery is documented | backup/rollback runbook |
| Candidate merge is conservative | no auto-merge test; future work documented |

---

## 9. Explicitly deferred

```text
SNMP/FDB ingestion
candidate-merge generation
operator asset merge/alias workflow
agent UUID/SMBIOS correlation
user ownership and captive portal
automatic intent-binding confirmation
deleting legacy tables
full UI dual-read migration
PostgreSQL
RouterOS routing_table persistence
```

PR 2A establishes a safe additive identity foundation only.
