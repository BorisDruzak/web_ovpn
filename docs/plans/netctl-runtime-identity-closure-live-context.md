# Netctl Runtime Identity Closure and Live Context Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Close Phase W1 / PR 2A with reproducible CI and production evidence, then implement PR 2B live runtime observation writes and PR 2C context-driven network classification before starting SNMP/FDB ingestion.

**Architecture:** Keep migration `2` and the legacy observer compatibility boundary intact. Add migration `3` only for integrity guards, current-state semantics, and runtime identity findings; add a transactional runtime writer called from the existing collection path; then replace production CIDR classification constants with metadata imported from the canonical context. Git intent, runtime observations, and legacy compatibility remain separate.

**Tech Stack:** Python 3.12, SQLite, existing `netctl.migrations.MIGRATIONS`, pytest, GitHub Actions, systemd deployment runbooks, `network_configuration` JSON Schema/YAML.

## Global Constraints

- Implementation baseline is `web_ovpn/main` commit `7427e08f0ce7bdb3957cf407d2d9db1e8c0e36a9`.
- Do not edit migration `2` after publication; all database corrections use migration `3` or later.
- Keep `network_hosts`, `host_observations`, DHCP, ARP, bridge, neighbor, route, tag, and current UI/CLI legacy reads intact until an explicit later cutover.
- IP addresses remain observations and must never have a global unique constraint in runtime tables.
- Different MAC addresses are never merged automatically.
- Do not create automatic confirmed runtime-to-intent bindings.
- Do not contact or change network devices in unit or migration tests.
- A failed or partial collection must preserve the last successful runtime current state.
- SNMP/FDB ingestion does not start until PR 2B and PR 2C are merged, deployed, and verified.
- Production CIDRs, sites, and endpoint categories must ultimately come from imported context, not Python constants.
- Every production migration requires SQLite `.backup`, integrity verification, application/wrapper backup, post-migration checks, and rollback evidence.

---

## 1. Scope and delivery order

This work is intentionally split into three independently reviewable deliveries.

### Delivery A — close PR 2A

```text
CI-verified merged main
production backup and migration 2 deployment
reviewed runtime_asset_migration_reports row
legacy command and service verification
Issue #7 closed only after evidence exists
```

### Delivery B — PR 2B live runtime observations

```text
migration 3 integrity guards and findings table
runtime writer for successful normalized host snapshots
per-source current/stale transitions
atomic legacy + runtime collection transaction
identity-conflict and duplicate-IP findings
read helpers and deployment runbook
```

### Delivery C — PR 2C remove architecture-specific classification

```text
observer_category in canonical segment intent
active-context network classifier
normalizer no longer depends on production CIDR constants
safe compatibility fallback with visible warning
zero fallback use required before SNMP ingestion
```

---

## 2. Current gaps this plan closes

| Gap | Current consequence | Delivery |
|---|---|---|
| No CI evidence on merge commit `7427e08` | tests exist but merged-main result is not independently recorded | A |
| Issue #7 remains open and production migration is unverified | PR 2A cannot be called operationally complete | A |
| Migration `2` is a one-time copy | runtime assets become stale after later collections | B |
| `ip_observations.asset_id` and `asset_interface_id` can disagree | future writers can create internally inconsistent rows | B |
| migrated legacy rows are marked `is_current=1` without fresh collector confirmation | old IP/hostname values may look current | B |
| failed collection semantics are not connected to runtime current state | a naive writer could emit false disappearances | B |
| same-MAC cross-site use and current duplicate IP are not findings | identity collisions can be silently hidden | B |
| historical host/MAC/IP disagreement is not recorded when `host_id` wins | migration provenance is incomplete | B |
| host classification uses hard-coded production networks | subnet/site changes can misclassify devices | C |
| source/collector model still contains vendor-specific assumptions | SNMP must remain gated until generic context/classification is ready | later SNMP PR |

---

# Delivery A — close PR 2A

### Task 1: Add mandatory runtime-identity CI on pull requests and main

**Files:**
- Create: `.github/workflows/verify-netctl-runtime.yml`
- Test: `tests/test_netctl_runtime_assets.py`
- Test: `tests/test_netctl_context_import.py`
- Test: `tests/test_netctl_context_migrations.py`
- Test: `tests/test_netctl_cli.py`

**Interfaces:**
- Consumes: project `requirements.txt` and Python 3.12.
- Produces: one focused runtime-identity job and one full-regression job on PRs, pushes to `main`, and manual dispatch.

- [ ] **Step 1: Add the workflow**

```yaml
name: Verify netctl runtime identity

on:
  push:
    branches: [main]
    paths:
      - "netctl/**"
      - "tests/**"
      - "requirements.txt"
      - ".github/workflows/verify-netctl-runtime.yml"
  pull_request:
    paths:
      - "netctl/**"
      - "tests/**"
      - "requirements.txt"
      - ".github/workflows/verify-netctl-runtime.yml"
  workflow_dispatch:

permissions:
  contents: read

jobs:
  focused-runtime-identity:
    runs-on: ubuntu-24.04
    timeout-minutes: 20
    steps:
      - uses: actions/checkout@v4
      - uses: actions/setup-python@v5
        with:
          python-version: "3.12"
          cache: pip
      - run: python -m pip install --quiet --upgrade pip
      - run: python -m pip install --quiet -r requirements.txt
      - run: >-
          python -m pytest -q
          tests/test_netctl_runtime_assets.py
          tests/test_netctl_context_import.py
          tests/test_netctl_context_migrations.py
          tests/test_netctl_cli.py

  full-regression:
    runs-on: ubuntu-24.04
    timeout-minutes: 30
    steps:
      - uses: actions/checkout@v4
      - uses: actions/setup-python@v5
        with:
          python-version: "3.12"
          cache: pip
      - run: python -m pip install --quiet --upgrade pip
      - run: python -m pip install --quiet -r requirements.txt
      - name: Run and retain full pytest output
        shell: bash
        run: |
          set +e
          python -m pytest -q > pytest-full.log 2>&1
          rc=$?
          echo "$rc" > pytest-full.exit-code
          cat pytest-full.log
          exit "$rc"
      - if: always()
        uses: actions/upload-artifact@v4
        with:
          name: pytest-full-runtime-identity
          path: |
            pytest-full.log
            pytest-full.exit-code
          if-no-files-found: error
          retention-days: 14
```

- [ ] **Step 2: Run the same commands locally**

```bash
python -m pytest -q \
  tests/test_netctl_runtime_assets.py \
  tests/test_netctl_context_import.py \
  tests/test_netctl_context_migrations.py \
  tests/test_netctl_cli.py
python -m pytest -q
git diff --check
```

Expected: all commands exit `0`.

- [ ] **Step 3: Commit**

```bash
git add .github/workflows/verify-netctl-runtime.yml
git commit -m "ci: verify runtime identity on main"
```

- [ ] **Step 4: Repository setting outside code**

Configure branch protection for `main` so `focused-runtime-identity` and `full-regression` are required before merge. Record the setting change in the deployment/change ticket; do not store tokens or screenshots containing sensitive repository details.

---

### Task 2: Produce merged-main and production closure evidence

**Files:**
- Create: `docs/verification/netctl-runtime-asset-identity-production.md`
- Modify: `docs/runbooks/netctl-runtime-asset-identity-backup-rollback.md`
- Modify: `README.md`

**Interfaces:**
- Consumes: the existing migration-2 backup/rollback runbook and exact release commit.
- Produces: a sanitized evidence document sufficient to close Issue #7.

- [ ] **Step 1: Extend the runbook with exact release verification**

Add checks that record:

```bash
release_sha="$(git -C /path/to/reviewed/checkout rev-parse HEAD)"
test "$release_sha" = "<approved-main-sha>"
sha256sum netctl/migrations.py netctl/runtime_assets.py tests/test_netctl_runtime_assets.py
```

The production copy must be compared against the approved release by checksum before migration starts.

- [ ] **Step 2: Execute the existing production runbook**

Required retained evidence:

```text
backup directory
SHA256SUMS
PRAGMA integrity_check=ok
schema_migrations before/after
legacy table counts before/after
runtime_asset_migration_reports row
manual decision for each unresolved/conflict record
foreign_keys=1
journal_mode=wal
busy_timeout=5000
legacy read-command outputs
openvpn-web.service active
netctl-collect.timer active
netctl-collect.service inactive outside its scheduled run
```

- [ ] **Step 3: Write the sanitized verification document**

Use this structure:

```markdown
# Runtime asset identity production verification

- release_commit: `<full SHA>`
- deployed_at_utc: `<ISO timestamp>`
- backup_manifest: `<path without secrets>`
- integrity_check: `ok`
- schema_migration_2_count: `1`
- legacy_counts_diff: `empty`
- migrated_hosts: `<count>`
- unresolved_hosts: `0`
- unresolved_observations: `<count and disposition>`
- unresolved_tags: `<count and disposition>`
- aggregation_conflicts: `<count and disposition>`
- focused_tests: `<passed/skipped>`
- full_tests: `<passed/skipped>`
- services: `verified`
- rollback_required: `false`
```

Do not include raw host lists, credentials, communities, tokens, private keys, or complete database dumps.

- [ ] **Step 4: Close Issue #7 only after all evidence is present**

The closure comment must reference the release SHA, test result, verification document, migration report disposition, and service status.

- [ ] **Step 5: Synchronize `network_configuration`**

Create a documentation PR that marks PR 2A operationally complete and sets PR 2B as current. Do not mark SNMP ingestion current yet.

- [ ] **Step 6: Commit**

```bash
git add \
  docs/verification/netctl-runtime-asset-identity-production.md \
  docs/runbooks/netctl-runtime-asset-identity-backup-rollback.md \
  README.md
git commit -m "docs: verify runtime identity production migration"
```

---

# Delivery B — PR 2B live runtime observations

### Task 3: Add migration 3 integrity guards and finding storage

**Files:**
- Modify: `netctl/migrations.py`
- Modify: `tests/test_netctl_runtime_assets.py`

**Interfaces:**
- Produces: `_migration_3(conn: sqlite3.Connection) -> None` and migration ledger version `3`.
- Consumes: migration-2 tables without modifying their original DDL.

- [ ] **Step 1: Write failing migration-3 tests**

Add tests that assert:

```text
migration version 3 exists exactly once
legacy migration-created current flags become historical
cross-asset interface references fail on INSERT
cross-asset interface references fail on UPDATE
runtime_identity_findings exists with required indexes
reopening the database is idempotent
failure in migration 3 rolls back version 3 completely
```

- [ ] **Step 2: Verify RED**

```bash
python -m pytest tests/test_netctl_runtime_assets.py -k "migration_3 or interface_guard or finding_table" -q
```

Expected: FAIL because migration 3 does not exist.

- [ ] **Step 3: Add migration 3**

```python
def _migration_3(conn: sqlite3.Connection) -> None:
    conn.executescript(
        """
        CREATE TABLE runtime_identity_findings (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            finding_key TEXT NOT NULL UNIQUE,
            finding_type TEXT NOT NULL,
            severity TEXT NOT NULL CHECK (severity IN ('info', 'warning', 'error', 'critical')),
            status TEXT NOT NULL CHECK (status IN ('open', 'acknowledged', 'resolved')),
            asset_id INTEGER REFERENCES assets(id) ON DELETE RESTRICT,
            source_id INTEGER REFERENCES network_sources(id) ON DELETE RESTRICT,
            first_seen_at TEXT NOT NULL,
            last_seen_at TEXT NOT NULL,
            details_json TEXT NOT NULL DEFAULT '{}'
        );
        CREATE INDEX runtime_identity_findings_status_type_idx
            ON runtime_identity_findings(status, finding_type, last_seen_at DESC);

        CREATE TRIGGER ip_observations_interface_asset_insert_guard
        BEFORE INSERT ON ip_observations
        WHEN NEW.asset_interface_id IS NOT NULL
         AND NOT EXISTS (
             SELECT 1 FROM asset_interfaces
             WHERE id = NEW.asset_interface_id AND asset_id = NEW.asset_id
         )
        BEGIN
            SELECT RAISE(ABORT, 'asset_interface_id does not belong to asset_id');
        END;

        CREATE TRIGGER ip_observations_interface_asset_update_guard
        BEFORE UPDATE OF asset_id, asset_interface_id ON ip_observations
        WHEN NEW.asset_interface_id IS NOT NULL
         AND NOT EXISTS (
             SELECT 1 FROM asset_interfaces
             WHERE id = NEW.asset_interface_id AND asset_id = NEW.asset_id
         )
        BEGIN
            SELECT RAISE(ABORT, 'asset_interface_id does not belong to asset_id');
        END;

        UPDATE ip_observations
        SET is_current = 0
        WHERE observation_source = 'legacy_network_host';

        UPDATE hostname_observations
        SET is_current = 0
        WHERE source_type = 'legacy_network_host';

        CREATE INDEX ip_observations_source_current_idx
            ON ip_observations(source_key, observation_source, is_current, last_seen_at DESC);
        CREATE INDEX hostname_observations_source_current_idx
            ON hostname_observations(source_key, source_type, is_current, last_seen_at DESC);
        """
    )
```

Extend the registry without modifying versions 1 or 2:

```python
MIGRATIONS = (
    (1, _migration_1),
    (2, _migration_2),
    (3, _migration_3),
)
```

- [ ] **Step 4: Verify GREEN**

```bash
python -m pytest tests/test_netctl_runtime_assets.py -k "migration_3 or interface_guard or finding_table" -q
```

Expected: PASS.

- [ ] **Step 5: Commit**

```bash
git add netctl/migrations.py tests/test_netctl_runtime_assets.py
git commit -m "feat: harden runtime observation integrity"
```

---

### Task 4: Implement the transactional runtime writer

**Files:**
- Create: `netctl/runtime_writer.py`
- Create: `tests/test_netctl_runtime_writer.py`

**Interfaces:**

```python
def sync_runtime_hosts(
    conn: sqlite3.Connection,
    *,
    source: dict[str, Any],
    hosts: list[dict[str, Any]],
    observed_at: str,
) -> dict[str, int]: ...

def recompute_runtime_identity_findings(
    conn: sqlite3.Connection,
    *,
    observed_at: str,
) -> dict[str, int]: ...
```

- [ ] **Step 1: Write failing writer tests**

Cover these exact behaviors:

```text
new MAC creates mac-seeded asset and one interface
same MAC on a later snapshot reuses asset and interface
successful snapshot demotes prior current IP/hostname for that source only
same IP moving to a different MAC preserves old history and makes only new row current
same MAC across distinct active sites creates mac_identity_collision finding
same current IP on two assets creates duplicate_current_ip finding
IP-only host is not auto-merged or used as permanent identity
IP-only host creates unresolved_ip_only_runtime finding
existing nonblank/manual asset fields are not overwritten by collector data
finding disappears only by status=resolved, never by row deletion
```

- [ ] **Step 2: Verify RED**

```bash
python -m pytest tests/test_netctl_runtime_writer.py -q
```

Expected: FAIL because `netctl.runtime_writer` does not exist.

- [ ] **Step 3: Implement stable source semantics**

Use exactly:

```python
source_id = int(source["id"])
source_key = f"network-source:{source_id}"
observation_source = "collector_host"
```

Capture prior current IP-to-asset mappings before demotion:

```python
previous_ip_assets = {
    str(row["ip"]): int(row["asset_id"])
    for row in conn.execute(
        """
        SELECT ip, asset_id
        FROM ip_observations
        WHERE source_key = ?
          AND observation_source = 'collector_host'
          AND is_current = 1
        """,
        (source_key,),
    )
}
```

Demote only the successful source snapshot's prior rows:

```python
conn.execute(
    """
    UPDATE ip_observations SET is_current = 0
    WHERE source_key = ? AND observation_source = 'collector_host' AND is_current = 1
    """,
    (source_key,),
)
conn.execute(
    """
    UPDATE hostname_observations SET is_current = 0
    WHERE source_key = ? AND source_type = 'collector_host' AND is_current = 1
    """,
    (source_key,),
)
```

- [ ] **Step 4: Implement conservative asset upsert**

For a normalized MAC:

```text
asset_key = mac:<MAC>
identity_method = mac_seed
provisional = 0
interface_key = mac:<MAC>
```

On an existing asset update only:

```text
last_seen_at = max(existing, observed_at)
first_seen_at remains unchanged
blank/unknown kind, site, display_name may be filled
nonblank/manual values are preserved
identity method and asset key never change
```

For an IP-only host, do not create a durable asset in PR 2B. Preserve it in legacy tables and upsert a finding with key:

```text
unresolved-ip-only:<source_id>:<normalized-ip>
```

- [ ] **Step 5: Implement current observation upserts**

Use the existing composite identities:

```sql
UNIQUE(asset_id, ip, source_key, observation_source)
UNIQUE(asset_id, hostname, source_key, source_type)
```

On conflict:

```text
first_seen_at = minimum
last_seen_at = observed_at
is_current = 1
site/source_id/interface updated to current valid values
```

- [ ] **Step 6: Record identity movement**

When `previous_ip_assets[ip]` exists and differs from the new asset, upsert a finding:

```text
finding_type = historical_identity_conflict
finding_key = ip-moved:<source_id>:<ip>:<old_asset_id>:<new_asset_id>
severity = warning
```

Preserve old and new asset IDs, source ID, IP, and observation time in `details_json`.

- [ ] **Step 7: Recompute collision findings**

After a successful sync:

```text
mac_identity_collision:
  one MAC-seeded asset has current observations in more than one nonblank site

duplicate_current_ip:
  one IP has current observations for more than one distinct asset
```

Upsert active findings and mark previously open findings of those types `resolved` when the condition is no longer present.

- [ ] **Step 8: Verify GREEN**

```bash
python -m pytest tests/test_netctl_runtime_writer.py -q
```

Expected: PASS.

- [ ] **Step 9: Commit**

```bash
git add netctl/runtime_writer.py tests/test_netctl_runtime_writer.py
git commit -m "feat: add live runtime asset writer"
```

---

### Task 5: Integrate runtime writes atomically with collection

**Files:**
- Modify: `netctl/store.py`
- Modify: `tests/test_netctl_cli.py`
- Modify: `tests/test_netctl_runtime_writer.py`

**Interfaces:**
- Consumes: `sync_runtime_hosts()` and `recompute_runtime_identity_findings()`.
- Produces: one atomic save path for legacy and runtime observations.

- [ ] **Step 1: Write failing integration tests**

Required tests:

```text
successful collection updates legacy and runtime in one commit
runtime writer exception rolls back all legacy writes from that collection
status != ok does not demote prior runtime current rows
repeating the same successful snapshot is idempotent
collection counts include runtime_assets/runtime_ips/runtime_hostnames/runtime_findings
existing hosts/tags/dashboard commands remain operational
```

- [ ] **Step 2: Verify RED**

```bash
python -m pytest tests/test_netctl_runtime_writer.py -k "collection or rollback or failed_status" -q
```

Expected: FAIL because `save_collection()` does not call the runtime writer.

- [ ] **Step 3: Wrap `save_collection()` in a savepoint**

Use this transaction shape:

```python
conn.execute("SAVEPOINT save_collection")
try:
    # existing legacy writes
    # normalize_hosts and _upsert_host
    if status == "ok":
        runtime_counts = sync_runtime_hosts(
            conn,
            source=source,
            hosts=hosts,
            observed_at=observed_at,
        )
        finding_counts = recompute_runtime_identity_findings(
            conn,
            observed_at=observed_at,
        )
    else:
        runtime_counts = {}
        finding_counts = {}
    # collection_runs/network_sources/network_events
    conn.execute("RELEASE SAVEPOINT save_collection")
    conn.commit()
except Exception:
    conn.execute("ROLLBACK TO SAVEPOINT save_collection")
    conn.execute("RELEASE SAVEPOINT save_collection")
    conn.rollback()
    raise
```

Do not demote runtime state when collection status is not `ok`.

- [ ] **Step 4: Include runtime counts without changing existing keys**

Add keys rather than renaming current output:

```python
counts.update(
    {
        "runtime_assets_touched": runtime_counts.get("assets_touched", 0),
        "runtime_ips_current": runtime_counts.get("ips_current", 0),
        "runtime_hostnames_current": runtime_counts.get("hostnames_current", 0),
        "runtime_findings_open": finding_counts.get("open", 0),
    }
)
```

- [ ] **Step 5: Verify GREEN**

```bash
python -m pytest tests/test_netctl_runtime_writer.py tests/test_netctl_cli.py -q
```

Expected: PASS.

- [ ] **Step 6: Commit**

```bash
git add netctl/store.py tests/test_netctl_runtime_writer.py tests/test_netctl_cli.py
git commit -m "feat: dual-write live runtime observations"
```

---

### Task 6: Add runtime read/status commands and deployment verification

**Files:**
- Modify: `netctl/runtime_assets.py`
- Modify: `netctl/cli.py`
- Create: `docs/runbooks/netctl-runtime-live-observations-deploy.md`
- Test: `tests/test_netctl_cli.py`

**Interfaces:**

```bash
netctl --json runtime-assets status
netctl --json runtime-assets inspect --asset-key <key>
netctl --json runtime-assets findings --status open
```

- [ ] **Step 1: Write failing CLI tests**

Assert stable JSON output including:

```text
schema migration versions
asset/interface/current IP/current hostname counts
last successful collection per source
open findings by type/severity
legacy migration report summary
whether any current row still uses migration-only source semantics
```

- [ ] **Step 2: Implement read-only helpers**

Add:

```python
def runtime_identity_status(conn: sqlite3.Connection) -> dict[str, Any]: ...
def inspect_runtime_asset(conn: sqlite3.Connection, asset_key: str) -> dict[str, Any] | None: ...
def list_runtime_identity_findings(conn: sqlite3.Connection, status: str = "open") -> list[dict[str, Any]]: ...
```

No helper may write or contact a source.

- [ ] **Step 3: Implement CLI parser and dispatch**

The commands must use the local SQLite connection only and return nonzero for invalid asset keys/status values.

- [ ] **Step 4: Write deployment runbook**

The runbook must require:

```text
migration 3 present once
interface guard triggers present
migration-created observations are historical
at least two successful collections from one source
first collection creates current rows
second collection proves idempotence/stale demotion
failed synthetic collection does not demote current state
open findings reviewed
legacy commands still work
services active after release
```

- [ ] **Step 5: Verify**

```bash
python -m pytest tests/test_netctl_runtime_assets.py tests/test_netctl_runtime_writer.py tests/test_netctl_cli.py -q
python -m pytest -q
git diff --check
```

Expected: all exit `0`.

- [ ] **Step 6: Commit**

```bash
git add \
  netctl/runtime_assets.py \
  netctl/cli.py \
  tests/test_netctl_cli.py \
  docs/runbooks/netctl-runtime-live-observations-deploy.md
git commit -m "feat: expose runtime identity status"
```

---

# Delivery C — PR 2C context-driven classification

### Task 7: Extend canonical segment intent with observer classification

**Repositories / Files:**
- Modify in `network_configuration`: `schemas/network-context.schema.json`
- Modify in `network_configuration`: `config/network-context.yaml`
- Modify in `network_configuration`: schema validation tests/workflow fixtures

**Interfaces:**
- Produces optional segment field `observer_category`.
- Consumes existing stable segment IDs, CIDRs, roles, sites, and statuses.

- [ ] **Step 1: Add schema enum**

```json
{
  "observer_category": {
    "type": "string",
    "enum": [
      "local_device",
      "site_device",
      "vpn_client",
      "telephony",
      "mgmt",
      "vipnet_transit",
      "wan",
      "noise",
      "unknown"
    ]
  }
}
```

Keep the field optional for backward compatibility, but require it on every active production segment in the canonical YAML.

- [ ] **Step 2: Populate current segments**

Examples:

```yaml
- id: central-lan
  cidr: 192.168.100.0/23
  observer_category: local_device

- id: m-arhiv-lan
  cidr: 192.168.99.0/24
  observer_category: site_device

- id: openvpn-pool
  cidr: 192.168.50.0/24
  observer_category: vpn_client
```

Do not encode classification in Python comments or device names.

- [ ] **Step 3: Validate and merge the cross-repository PR**

```bash
python scripts/validate_network_context.py
```

Expected: canonical context and schema pass; no secrets detected.

---

### Task 8: Replace hard-coded production CIDRs with an active-context classifier

**Files:**
- Create: `netctl/context_classifier.py`
- Modify: `netctl/normalizer.py`
- Modify: `netctl/store.py`
- Create: `tests/test_netctl_context_classifier.py`
- Modify: `tests/test_netctl_cli.py`

**Interfaces:**

```python
@dataclass(frozen=True)
class SegmentRule:
    segment_id: str
    network: ipaddress._BaseNetwork
    observer_category: str
    site: str


def load_active_segment_rules(conn: sqlite3.Connection) -> list[SegmentRule]: ...

def classify_address(
    ip: str,
    *,
    rules: list[SegmentRule],
    source: dict[str, Any],
    has_name: bool,
    network_infra: bool,
) -> str: ...
```

- [ ] **Step 1: Write failing classifier tests**

Cover:

```text
longest-prefix match wins
changing a CIDR in imported context changes classification without Python changes
new site segment classifies correctly
inactive/retired segment is ignored
missing observer_category returns unknown
network_infra source evidence still overrides endpoint category
no active context triggers explicit compatibility fallback warning
```

- [ ] **Step 2: Verify RED**

```bash
python -m pytest tests/test_netctl_context_classifier.py -q
```

Expected: FAIL because classifier does not exist.

- [ ] **Step 3: Load active intent segments**

Resolve the active revision through `context_heads`, then read active `intent_segments.canonical_json`. Parse CIDR with `ipaddress.ip_network(..., strict=False)`, reject malformed rows with a visible error, and sort rules by descending prefix length then stable ID.

- [ ] **Step 4: Refactor the normalizer boundary**

Change:

```python
def normalize_hosts(source, snapshot, now): ...
```

to:

```python
def normalize_hosts(source, snapshot, now, *, segment_rules=None): ...
```

When rules are present, use `classify_address()`. Preserve the old constants only in a named `legacy_segment_rules()` compatibility function; do not use them silently.

- [ ] **Step 5: Make fallback visible**

When no active context/rules exist:

```text
use legacy_segment_rules temporarily
record network event type=context_classifier_fallback
include fallback=true in collection counts
```

Production acceptance requires `fallback=false` after the canonical context is imported.

- [ ] **Step 6: Verify GREEN**

```bash
python -m pytest tests/test_netctl_context_classifier.py tests/test_netctl_cli.py -q
python -m pytest -q
git diff --check
```

Expected: all exit `0`.

- [ ] **Step 7: Commit**

```bash
git add \
  netctl/context_classifier.py \
  netctl/normalizer.py \
  netctl/store.py \
  tests/test_netctl_context_classifier.py \
  tests/test_netctl_cli.py
git commit -m "feat: classify hosts from imported network context"
```

---

### Task 9: Final deployment gate before SNMP/FDB

**Files:**
- Create: `docs/verification/netctl-live-context-readiness.md`
- Modify: `README.md`
- Update: `web_ovpn` tracking issues
- Update: `network_configuration/docs/status/web-ovpn-current-phase.md`

- [ ] **Step 1: Verify two successful collection cycles**

For at least one real source, retain sanitized output proving:

```text
same MAC keeps one asset across cycles
removed source IP becomes historical, not deleted
a failed collection leaves prior current rows unchanged
context_classifier_fallback=false
no cross-asset interface references
findings are explainable or resolved
legacy commands remain operational
```

- [ ] **Step 2: Record readiness document**

Include exact release SHA, migration versions, focused/full test counts, source IDs (not credentials), runtime status counts, fallback status, findings disposition, and service state.

- [ ] **Step 3: Close PR 2B/2C tracking issues**

Do not close based only on merged code. Require deployed verification evidence.

- [ ] **Step 4: Open SNMP implementation gate**

SNMP issue #5 may become current only when:

```text
PR 2A production verification complete
PR 2B live writer deployed and verified
PR 2C context classifier deployed with fallback=false
runtime status command healthy
two successful collection cycles retained
```

---

## Final acceptance matrix

| Requirement | Evidence |
|---|---|
| Merged main is automatically verified | required GitHub Actions checks on PR and `main` push |
| PR 2A is operationally complete | production verification document and Issue #7 closure |
| Runtime assets stay current | two successful source snapshots update current/history correctly |
| Failed collection preserves last state | integration test and deployment check |
| Interface/asset consistency enforced | migration-3 INSERT/UPDATE trigger tests |
| Legacy migration rows are not falsely current | migration-3 state test |
| Same MAC collision is visible | `mac_identity_collision` finding test |
| Duplicate current IP is visible | `duplicate_current_ip` finding test |
| Historical identity movement is preserved | `historical_identity_conflict` finding test |
| IP-only data is not promoted to permanent identity | unresolved finding and legacy preservation test |
| Legacy behavior remains operational | existing CLI/UI test suite and deployment commands |
| Network changes do not require Python CIDR edits | active-context classifier test |
| Missing context is not silent | fallback event/count and production `fallback=false` gate |
| SNMP starts on a stable identity foundation | final readiness document |

## Explicitly deferred

```text
asset merge/alias execution workflow
candidate-merge UI
agent UUID/SMBIOS/serial correlation
user ownership and captive portal
full web UI cutover from network_hosts
legacy table deletion
PostgreSQL migration
SNMP/FDB implementation itself
RouterOS routing_table issue #8
write automation against routers/switches
```
