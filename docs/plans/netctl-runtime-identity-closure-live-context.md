# Netctl Runtime Identity Closure and Live Context Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Close PR 2A with reproducible merged-main and production evidence, implement PR 2B so runtime assets stay synchronized with successful collections, and implement PR 2C so network classification comes from imported context rather than production CIDRs embedded in Python.

**Architecture:** Keep migrations 1 and 2 immutable. Add migration 3 for runtime integrity guards, legacy conflict backfill, and identity findings; write runtime observations inside the existing collection transaction; preserve legacy tables as a compatibility layer. After the writer is stable, extend canonical segment intent with explicit observer classification and make `netctl` use the active imported context with a visible compatibility fallback.

**Tech Stack:** Python 3.12, SQLite, existing `netctl.migrations.MIGRATIONS`, pytest, GitHub Actions, systemd, `network_configuration` YAML and JSON Schema.

## Global Constraints

- Baseline commit: `7427e08f0ce7bdb3957cf407d2d9db1e8c0e36a9`.
- Do not alter migration 2; use migration 3 or later for corrections.
- Migration functions must not call `commit()` or `executescript()`; all writes remain inside the existing `apply_migrations()` savepoint.
- Keep `network_hosts`, `host_observations`, DHCP, ARP, bridge, neighbor, route, tag, UI, CLI, and MCP legacy reads operational.
- IP remains an observation and must not have a global unique runtime constraint.
- Different MAC addresses must never be merged automatically.
- Do not create automatic confirmed runtime-to-intent bindings.
- Failed or partial collection must retain the last successful runtime current state.
- Tests must not contact or change live devices.
- SNMP/FDB ingestion remains blocked until PR 2B and PR 2C are deployed and verified.
- Production CIDRs, sites, and endpoint categories must come from imported context after PR 2C.
- Every production database migration requires SQLite `.backup`, `integrity_check`, application and wrapper backup, post-checks, and tested rollback.

---

## Delivery order

### Delivery A — close PR 2A

```text
required CI on pull requests and main
full test evidence for merged main
migration 2 production deployment
reviewed migration report
legacy command and service checks
Issue #7 closed only after evidence exists
```

### Delivery B — PR 2B live runtime observations

```text
migration 3 integrity guards
legacy identity-conflict backfill
runtime identity findings
live MAC-backed asset writer
per-source current/historical transitions
atomic legacy and runtime writes
runtime status/inspection CLI
```

### Delivery C — PR 2C context-driven classification

```text
observer_category in canonical segment intent
active-context classifier
no silent production CIDR constants
fallback event and fallback=false production gate
```

---

## Problems being closed

| Problem | Consequence | Delivery |
|---|---|---|
| Merge commit `7427e08` has no GitHub CI status | tests exist but merged-main result is not independently recorded | A |
| PR 2A production migration is not verified | Issue #7 cannot be closed safely | A |
| Migration 2 is a one-time copy | runtime assets become stale after later collections | B |
| `asset_id` and `asset_interface_id` can disagree | future writers can create internally inconsistent observations | B |
| migration rows are marked current without a fresh collection | old IPs and names may appear current | B |
| failed collection behavior is not connected to runtime state | false disappearances are possible | B |
| MAC collisions and duplicate current IPs are not explicit findings | bad identity merges can remain hidden | B |
| host/MAC/IP disagreement can be hidden when legacy `host_id` wins | provenance is incomplete | B |
| `netctl.normalizer` contains production CIDRs | topology changes can misclassify devices | C |

---

# Delivery A — close PR 2A

### Task 1: Add mandatory runtime-identity CI

**Files:**
- Create: `.github/workflows/verify-netctl-runtime.yml`

**Interfaces:**
- Consumes: `requirements.txt`, Python 3.12, existing pytest suite.
- Produces: required focused and full-regression checks on every pull request and every push to `main`.

- [ ] **Step 1: Create the workflow**

```yaml
name: Verify netctl runtime identity

on:
  push:
    branches: [main]
  pull_request:
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

The workflow intentionally has no `paths` filter because required checks must also complete for documentation-only pull requests.

- [ ] **Step 2: Run equivalent local verification**

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

- [ ] **Step 4: Configure branch protection**

Require these checks for `main`:

```text
focused-runtime-identity
full-regression
```

Record the repository-setting change in the change ticket. Do not store access tokens or sensitive screenshots in Git.

---

### Task 2: Produce merged-main and production closure evidence

**Files:**
- Modify: `docs/runbooks/netctl-runtime-asset-identity-backup-rollback.md`
- Create: `docs/verification/netctl-runtime-asset-identity-production.md`
- Modify: `README.md`

**Interfaces:**
- Consumes: approved main commit, existing migration-2 runbook.
- Produces: sanitized evidence sufficient to close Issue #7.

- [ ] **Step 1: Verify the exact approved release**

Run from a clean reviewed checkout:

```bash
set -euo pipefail
git switch main
git pull --ff-only
release_sha="$(git rev-parse HEAD)"
remote_main_sha="$(git rev-parse origin/main)"
test "$release_sha" = "$remote_main_sha"
printf '%s\n' "$release_sha"
sha256sum \
  netctl/migrations.py \
  netctl/runtime_assets.py \
  tests/test_netctl_runtime_assets.py
```

Record the printed commit and checksums in the deployment record. Compare the deployed files to these values before opening the production database with the new code.

- [ ] **Step 2: Execute the current production backup/deployment/rollback runbook**

Retain:

```text
backup directory and rollback manifest
SHA256SUMS
PRAGMA integrity_check=ok
schema_migrations before and after
legacy table counts before and after
runtime_asset_migration_reports row
review decision for each unresolved/conflict record
foreign_keys=1
journal_mode=wal
busy_timeout=5000
legacy read-command output
service and timer states
```

- [ ] **Step 3: Capture exact verification values**

```bash
set -euo pipefail
release_sha="$(git rev-parse HEAD)"
deployed_at_utc="$(date -u +%Y-%m-%dT%H:%M:%SZ)"
focused_result="$(python -m pytest -q tests/test_netctl_runtime_assets.py tests/test_netctl_context_import.py tests/test_netctl_context_migrations.py tests/test_netctl_cli.py | tail -n 1)"
full_result="$(python -m pytest -q | tail -n 1)"

migrated_hosts="$(sudo sqlite3 /var/lib/netctl/netctl.sqlite \
  'SELECT mapped_legacy_host_count FROM runtime_asset_migration_reports WHERE migration_version=2;')"
unresolved_hosts="$(sudo sqlite3 /var/lib/netctl/netctl.sqlite \
  'SELECT json_array_length(unresolved_legacy_host_ids_json) FROM runtime_asset_migration_reports WHERE migration_version=2;')"
unresolved_observations="$(sudo sqlite3 /var/lib/netctl/netctl.sqlite \
  'SELECT json_array_length(unresolved_observation_ids_json) FROM runtime_asset_migration_reports WHERE migration_version=2;')"
unresolved_tags="$(sudo sqlite3 /var/lib/netctl/netctl.sqlite \
  'SELECT json_array_length(unresolved_tag_records_json) FROM runtime_asset_migration_reports WHERE migration_version=2;')"
aggregation_conflicts="$(sudo sqlite3 /var/lib/netctl/netctl.sqlite \
  'SELECT json_array_length(aggregation_conflicts_json) FROM runtime_asset_migration_reports WHERE migration_version=2;')"
```

- [ ] **Step 4: Write the sanitized verification document with actual values**

```bash
cat > docs/verification/netctl-runtime-asset-identity-production.md <<EOF
# Runtime asset identity production verification

- release_commit: \`$release_sha\`
- deployed_at_utc: \`$deployed_at_utc\`
- integrity_check: \`ok\`
- schema_migration_2_count: \`1\`
- legacy_counts_diff: \`empty\`
- migrated_hosts: \`$migrated_hosts\`
- unresolved_hosts: \`$unresolved_hosts\`
- unresolved_observations: \`$unresolved_observations\`
- unresolved_tags: \`$unresolved_tags\`
- aggregation_conflicts: \`$aggregation_conflicts\`
- focused_tests: \`$focused_result\`
- full_tests: \`$full_result\`
- services: \`verified\`
- rollback_required: \`false\`

Each nonzero unresolved/conflict count was reviewed against the untouched legacy tables. The detailed records remain in the protected deployment backup directory and are not committed to Git.
EOF
```

Do not commit host inventories, raw database output, credentials, SNMP communities, tokens, or private keys.

- [ ] **Step 5: Close Issue #7 only after evidence is committed**

The closure comment must reference:

```text
release commit
focused and full test result
production verification document
migration-report disposition
service and timer status
```

- [ ] **Step 6: Synchronize `network_configuration`**

Create a documentation PR that marks PR 2A operationally complete and PR 2B current. SNMP remains later.

- [ ] **Step 7: Commit**

```bash
git add \
  docs/runbooks/netctl-runtime-asset-identity-backup-rollback.md \
  docs/verification/netctl-runtime-asset-identity-production.md \
  README.md
git commit -m "docs: verify runtime identity production migration"
```

---

# Delivery B — PR 2B live runtime observations

### Task 3: Add migration 3 integrity guards, backfill, and findings

**Files:**
- Modify: `netctl/migrations.py`
- Modify: `tests/test_netctl_runtime_assets.py`

**Interfaces:**
- Produces: `_migration_3(conn: sqlite3.Connection) -> None`, `_backfill_legacy_identity_conflicts(conn, observed_at) -> int`, and schema version 3.
- Consumes: migration-2 tables unchanged.

- [ ] **Step 1: Write failing tests**

Test:

```text
version 3 is applied once
migration-created legacy observations become historical
cross-asset interface reference fails on INSERT
cross-asset interface reference fails on UPDATE
runtime_identity_findings exists
legacy host_id versus MAC/IP disagreement creates a finding
matching host_id/MAC/IP does not create a finding
migration 3 does not commit or escape the outer savepoint
migration 3 rollback is atomic
reopen is idempotent
```

- [ ] **Step 2: Verify RED**

```bash
python -m pytest tests/test_netctl_runtime_assets.py -k "migration_3 or interface_guard or legacy_identity_conflict or finding_table" -q
```

Expected: FAIL because migration 3 does not exist.

- [ ] **Step 3: Implement migration 3 without `executescript()`**

Use individual `conn.execute()` calls so the existing `apply_migrations()` savepoint remains authoritative:

```python
def _migration_3(conn: sqlite3.Connection) -> None:
    statements = (
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
        )
        """,
        """
        CREATE INDEX runtime_identity_findings_status_type_idx
            ON runtime_identity_findings(status, finding_type, last_seen_at DESC)
        """,
        """
        CREATE TRIGGER ip_observations_interface_asset_insert_guard
        BEFORE INSERT ON ip_observations
        WHEN NEW.asset_interface_id IS NOT NULL
         AND NOT EXISTS (
             SELECT 1 FROM asset_interfaces
             WHERE id = NEW.asset_interface_id AND asset_id = NEW.asset_id
         )
        BEGIN
            SELECT RAISE(ABORT, 'asset_interface_id does not belong to asset_id');
        END
        """,
        """
        CREATE TRIGGER ip_observations_interface_asset_update_guard
        BEFORE UPDATE OF asset_id, asset_interface_id ON ip_observations
        WHEN NEW.asset_interface_id IS NOT NULL
         AND NOT EXISTS (
             SELECT 1 FROM asset_interfaces
             WHERE id = NEW.asset_interface_id AND asset_id = NEW.asset_id
         )
        BEGIN
            SELECT RAISE(ABORT, 'asset_interface_id does not belong to asset_id');
        END
        """,
        """
        CREATE INDEX ip_observations_source_current_idx
            ON ip_observations(source_key, observation_source, is_current, last_seen_at DESC)
        """,
        """
        CREATE INDEX hostname_observations_source_current_idx
            ON hostname_observations(source_key, source_type, is_current, last_seen_at DESC)
        """,
    )
    for statement in statements:
        conn.execute(statement)

    conn.execute(
        """
        UPDATE ip_observations
        SET is_current = 0
        WHERE observation_source = 'legacy_network_host'
        """
    )
    conn.execute(
        """
        UPDATE hostname_observations
        SET is_current = 0
        WHERE source_type = 'legacy_network_host'
        """
    )
    _backfill_legacy_identity_conflicts(conn, utc_now())
```

Registry:

```python
MIGRATIONS = (
    (1, _migration_1),
    (2, _migration_2),
    (3, _migration_3),
)
```

- [ ] **Step 4: Implement conflict backfill**

For every `host_observations` row with a mapped `host_id`:

```text
host asset = legacy_host_asset_mappings(host_id)
MAC candidate = unique mapped asset for normalized observation MAC
IP candidate = unique mapped asset for observation IP
```

When a unique MAC or IP candidate differs from the host asset, upsert:

```text
finding_key=legacy-identity-conflict:<observation_id>
finding_type=historical_identity_conflict
severity=warning
status=open
asset_id=<host asset>
details_json contains observation ID, host asset, MAC candidate, IP candidate, raw identity fields
```

Do not create a finding when all available candidates agree or a candidate is ambiguous/unavailable.

- [ ] **Step 5: Verify GREEN**

```bash
python -m pytest tests/test_netctl_runtime_assets.py -k "migration_3 or interface_guard or legacy_identity_conflict or finding_table" -q
```

Expected: PASS.

- [ ] **Step 6: Commit**

```bash
git add netctl/migrations.py tests/test_netctl_runtime_assets.py
git commit -m "feat: harden runtime observation integrity"
```

---

### Task 4: Implement the live runtime writer

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

- [ ] **Step 1: Write failing tests**

Cover:

```text
new MAC creates one asset and interface
same MAC later reuses both
successful snapshot demotes prior current rows for that source only
IP moving to another MAC preserves history and makes only new row current
IP-only host remains legacy and creates unresolved_ip_only_runtime finding
IP-only finding resolves when the condition disappears or gains a MAC
collector does not overwrite nonblank/manual asset fields
same MAC current in multiple sites creates mac_identity_collision
same current IP on multiple assets creates duplicate_current_ip
movement creates historical_identity_conflict
resolved conditions mark findings resolved instead of deleting them
```

- [ ] **Step 2: Verify RED**

```bash
python -m pytest tests/test_netctl_runtime_writer.py -q
```

Expected: FAIL because the module does not exist.

- [ ] **Step 3: Implement stable source identity and demotion**

```python
source_id = int(source["id"])
source_key = f"network-source:{source_id}"
```

Before demotion, capture prior current IP ownership:

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

Then demote only this source:

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

For a valid normalized MAC:

```text
asset_key = mac:<MAC>
identity_method = mac_seed
provisional = 0
interface_key = mac:<MAC>
```

Existing asset update policy:

```text
first_seen_at unchanged
last_seen_at=max(existing, observed_at)
fill only blank/unknown kind, site, display_name
never replace nonblank/manual fields
never change asset_key or identity_method
```

For IP-only normalized hosts:

```text
do not create a permanent asset in PR 2B
leave the legacy row intact
upsert finding key unresolved-ip-only:<source_id>:<ip>
```

- [ ] **Step 5: Upsert current observations**

Use source key `network-source:<id>` and source type `collector_host`.

On conflict:

```text
first_seen_at=min(existing, observed_at)
last_seen_at=observed_at
is_current=1
site/source/interface updated to current valid values
```

- [ ] **Step 6: Record movement and recompute findings**

Movement finding:

```text
finding_type=historical_identity_conflict
finding_key=ip-moved:<source_id>:<ip>:<old_asset_id>:<new_asset_id>
severity=warning
```

Global conditions:

```text
mac_identity_collision:
  one MAC-seeded asset has current observations in more than one nonblank site

duplicate_current_ip:
  one IP has current observations for more than one asset

unresolved_ip_only_runtime:
  successful current snapshot contains an IP without a usable MAC
```

Upsert active findings and set old findings of all three recomputed types to `resolved` when their conditions disappear. Historical movement findings remain as provenance and are not auto-resolved.

- [ ] **Step 7: Verify GREEN**

```bash
python -m pytest tests/test_netctl_runtime_writer.py -q
```

Expected: PASS.

- [ ] **Step 8: Commit**

```bash
git add netctl/runtime_writer.py tests/test_netctl_runtime_writer.py
git commit -m "feat: add live runtime asset writer"
```

---

### Task 5: Integrate runtime writes atomically with collection

**Files:**
- Modify: `netctl/store.py`
- Modify: `tests/test_netctl_runtime_writer.py`
- Modify: `tests/test_netctl_cli.py`

**Interfaces:**
- Consumes: `sync_runtime_hosts()` and `recompute_runtime_identity_findings()`.
- Produces: one transaction for legacy and runtime collection state.

- [ ] **Step 1: Write failing integration tests**

Test:

```text
successful collection commits legacy and runtime together
runtime writer exception rolls back all writes from that collection
status other than ok does not demote current runtime rows
same successful snapshot is idempotent
collection counts retain old keys and add runtime counters
legacy commands remain green
```

- [ ] **Step 2: Verify RED**

```bash
python -m pytest tests/test_netctl_runtime_writer.py -k "collection or rollback or failed_status" -q
```

- [ ] **Step 3: Add savepoint transaction**

```python
conn.execute("SAVEPOINT save_collection")
try:
    # existing legacy writes and normalize_hosts()
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

    # existing collection_runs, source status and event writes
    conn.execute("RELEASE SAVEPOINT save_collection")
    conn.commit()
except Exception:
    conn.execute("ROLLBACK TO SAVEPOINT save_collection")
    conn.execute("RELEASE SAVEPOINT save_collection")
    conn.rollback()
    raise
```

Do not call the runtime writer when `status != "ok"`.

- [ ] **Step 4: Add runtime counters without renaming existing keys**

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

- [ ] **Step 6: Commit**

```bash
git add netctl/store.py tests/test_netctl_runtime_writer.py tests/test_netctl_cli.py
git commit -m "feat: dual-write live runtime observations"
```

---

### Task 6: Add runtime status and inspection commands

**Files:**
- Modify: `netctl/runtime_assets.py`
- Modify: `netctl/cli.py`
- Modify: `tests/test_netctl_cli.py`
- Create: `docs/runbooks/netctl-runtime-live-observations-deploy.md`

**Interfaces:**

```bash
netctl --json runtime-assets status
netctl --json runtime-assets inspect --asset-key mac:AA:BB:CC:DD:EE:FF
netctl --json runtime-assets findings --status open
```

- [ ] **Step 1: Write failing CLI tests**

Status output must include:

```text
schema migration versions
asset/interface/current IP/current hostname counts
last successful collection per source
open findings by type and severity
migration-2 report summary
count of migration-only rows still marked current
```

- [ ] **Step 2: Add read helpers**

```python
def runtime_identity_status(conn: sqlite3.Connection) -> dict[str, Any]: ...
def inspect_runtime_asset(conn: sqlite3.Connection, asset_key: str) -> dict[str, Any] | None: ...
def list_runtime_identity_findings(
    conn: sqlite3.Connection,
    status: str = "open",
) -> list[dict[str, Any]]: ...
```

All helpers use parameterized SQL and perform no writes.

- [ ] **Step 3: Add CLI parser and dispatch**

Invalid finding status or missing asset must produce JSON error and nonzero exit.

- [ ] **Step 4: Write deployment runbook**

Require:

```text
migration 3 once
both interface guard triggers present
migration-only observations historical
legacy conflict backfill reviewed
first successful collection creates current rows
second collection proves idempotence and stale demotion
failed collection leaves current rows unchanged
findings reviewed
legacy commands work
services healthy
```

- [ ] **Step 5: Verify and commit**

```bash
python -m pytest tests/test_netctl_runtime_assets.py tests/test_netctl_runtime_writer.py tests/test_netctl_cli.py -q
python -m pytest -q
git diff --check

git add \
  netctl/runtime_assets.py \
  netctl/cli.py \
  tests/test_netctl_cli.py \
  docs/runbooks/netctl-runtime-live-observations-deploy.md
git commit -m "feat: expose runtime identity status"
```

---

# Delivery C — PR 2C context-driven classification

### Task 7: Add observer classification to canonical segment intent

**Repository / Files:**
- Modify in `network_configuration`: `schemas/network-context.schema.json`
- Modify in `network_configuration`: `config/network-context.yaml`

**Interfaces:**
- Produces: optional `observer_category` on segment objects.

- [ ] **Step 1: Add schema property**

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

Keep it optional for older revisions, but populate it for every active production segment.

- [ ] **Step 2: Populate current intent**

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

- [ ] **Step 3: Validate through the repository workflow**

Open a PR and require the existing `Validate network context` workflow to complete with `success`. No raw configuration containing credentials may be added.

---

### Task 8: Replace hard-coded CIDRs with the active-context classifier

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
    network: ipaddress.IPv4Network | ipaddress.IPv6Network
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

- [ ] **Step 1: Write failing tests**

Test:

```text
longest prefix wins
CIDR change in imported context changes classification without Python change
new site works without Python change
retired segment is ignored
missing observer_category returns unknown
network_infra evidence overrides endpoint category
local_device without a name remains unknown, preserving current behavior
no active context produces an explicit fallback warning
```

- [ ] **Step 2: Verify RED**

```bash
python -m pytest tests/test_netctl_context_classifier.py -q
```

- [ ] **Step 3: Load active rules**

Resolve active revision through `context_heads`, read active `intent_segments.canonical_json`, parse CIDRs with `ipaddress.ip_network(value, strict=False)`, reject malformed active rows, and sort by descending prefix length then stable segment ID.

- [ ] **Step 4: Refactor normalizer boundary**

Change:

```python
def normalize_hosts(source, snapshot, now): ...
```

to:

```python
def normalize_hosts(source, snapshot, now, *, segment_rules=None): ...
```

When rules exist, use `classify_address()`. Move existing production constants into a named `legacy_segment_rules()` compatibility function and never use them silently.

- [ ] **Step 5: Make fallback visible**

When no active rules exist:

```text
use legacy_segment_rules temporarily
record event type context_classifier_fallback
add context_classifier_fallback=true to collection counts
```

Production acceptance requires `context_classifier_fallback=false`.

- [ ] **Step 6: Verify and commit**

```bash
python -m pytest tests/test_netctl_context_classifier.py tests/test_netctl_cli.py -q
python -m pytest -q
git diff --check

git add \
  netctl/context_classifier.py \
  netctl/normalizer.py \
  netctl/store.py \
  tests/test_netctl_context_classifier.py \
  tests/test_netctl_cli.py
git commit -m "feat: classify hosts from imported context"
```

---

### Task 9: Final readiness gate before SNMP/FDB

**Files:**
- Create: `docs/verification/netctl-live-context-readiness.md`
- Modify: `README.md`
- Update: `web_ovpn` issues
- Update: `network_configuration/docs/status/web-ovpn-current-phase.md`

- [ ] **Step 1: Verify two real successful collection cycles**

Retain sanitized evidence showing:

```text
same MAC remains one asset
removed source IP becomes historical
failed collection leaves prior current state unchanged
context_classifier_fallback=false
no cross-asset interface references
legacy conflict findings reviewed
current collision findings reviewed or resolved
legacy commands remain operational
```

- [ ] **Step 2: Write readiness evidence**

Record exact release SHA, migration versions, focused/full test summary, source IDs without credentials, runtime counts, fallback status, findings disposition, and service status.

- [ ] **Step 3: Close PR 2B and PR 2C tracking issues only after deployment evidence**

Merged code alone is not closure evidence.

- [ ] **Step 4: Open the SNMP gate**

Issue #5 becomes current only after:

```text
PR 2A production verification committed
PR 2B live writer deployed and verified
PR 2C classifier deployed with fallback=false
two successful collection cycles retained
runtime-assets status healthy
```

---

## Final acceptance matrix

| Requirement | Evidence |
|---|---|
| Required CI runs on all PRs and main | GitHub Actions checks without path filters |
| PR 2A operationally complete | production verification document and Issue #7 closure |
| Runtime state stays live | two successful collection-cycle tests and production evidence |
| Failed collection retains state | unit/integration and production verification |
| Interface belongs to the same asset | migration-3 INSERT/UPDATE guard tests |
| Legacy migration rows are historical | migration-3 state test |
| Hidden legacy identity disagreement is retained | migration-3 conflict backfill test |
| Same-MAC collision visible | `mac_identity_collision` finding test |
| Duplicate current IP visible | `duplicate_current_ip` finding test |
| Identity movement preserved | `historical_identity_conflict` test |
| IP-only data is not promoted to permanent identity | unresolved finding and legacy preservation |
| Legacy observer remains operational | regression tests and deployment commands |
| Network CIDR changes do not require Python changes | active-context classifier tests |
| Missing context is visible | fallback event/count and production `fallback=false` gate |
| SNMP starts after stable identity/context | readiness document |

## Explicitly deferred

```text
asset merge and alias execution
candidate-merge UI
agent UUID, SMBIOS, serial and inventory correlation
user ownership and captive portal
full UI cutover from network_hosts
legacy table deletion
PostgreSQL migration
SNMP/FDB implementation
RouterOS routing_table Issue #8
write automation against routers or switches
```
