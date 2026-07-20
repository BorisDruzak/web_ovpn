# Switch Optional State Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Persist read-only current VLAN/PVID and LLDP neighbor state without allowing a failed optional SNMP group to erase its last known valid state.

**Architecture:** Add migration 6 with two source-scoped current-state tables. The existing successful-FDB transaction will replace an optional group only after a confirmed complete success; otherwise it preserves the old rows. The new CLI reads are paginated and read-only.

**Tech Stack:** Python 3.12, SQLite, PySNMP 7.1.27, existing `netctl` SNMP collector/store/CLI, pytest.

## Global Constraints

- Migrations 1–5 are immutable; this work adds only migration 6.
- SNMP is read-only: no SET, port/VLAN/PVID/device writes, or production-source activation.
- Communities never appear in fixtures, database rows, CLI output, logs, exceptions, captures, or Git history.
- Numeric OIDs are authoritative; no runtime MIB downloads.
- A failed FDB still preserves `current_switch_fdb`; optional outcomes never change that rule.
- Only `success_with_rows` and `success_empty` replace optional current state; unsupported, timeout, auth/view failure, protocol failure, and parse error preserve it.
- `success_empty` intentionally clears only its own optional group.
- Tests use sanitized fixtures and injected transports only; no test contacts a device.

---

## Task 11A: Migration 6 and atomic optional current state

**Files:**
- Modify: `netctl/db.py`
- Modify: `netctl/switch_store.py`
- Modify: `netctl/switch_queries.py`
- Modify: `netctl/cli.py`
- Modify: `tests/test_netctl_switch_store.py`
- Modify: `tests/test_netctl_switch_cli.py`

**Interfaces:**

```python
def query_switch_vlans(conn: sqlite3.Connection, *, source: str = "", limit: int = 500, offset: int = 0) -> dict[str, object]: ...
def query_switch_lldp_neighbors(conn: sqlite3.Connection, *, source: str = "", limit: int = 500, offset: int = 0) -> dict[str, object]: ...
```

- [ ] **Step 1: Write failing migration and persistence tests**

Add tests asserting migration 6 creates `current_switch_vlan_memberships` with primary key `(source_id, vlan_id, port_key)` and typed VLAN/PVID columns, plus `current_switch_lldp_neighbors` with primary key `(source_id, local_port_key, chassis_id, port_id)`. Test each group for successful replacement, confirmed-empty clearing, and unsupported/timeout/parse preservation. Also prove optional failure does not prevent a successful required FDB/port transaction.

- [ ] **Step 2: Verify RED**

Run `python -m pytest tests/test_netctl_switch_store.py tests/test_netctl_switch_cli.py -k "vlan or lldp" -q`. Expected: fail because migration 6, replacement helpers and CLI reads do not exist.

- [ ] **Step 3: Implement the minimal atomic contract**

Create migration 6 in `netctl/db.py` with the two additive tables and `(source_id, observed_at DESC)` indexes. In the existing `_atomic()` successful-FDB branch of `collect_and_save_switch()`, replace VLAN rows only if `vlan_current_egress`, `vlan_current_untagged`, and `pvid` all have `SUCCESS_WITH_ROWS` or `SUCCESS_EMPTY`; replace LLDP neighbors only if `lldp_remote` has one of those outcomes. Otherwise never delete current optional rows. Validate persisted mappings and use parameterized SQL only.

Add read-only paginated `switches vlans` and `switches lldp` commands, source filter, default limit 500, maximum 5000, and nonnegative offset. They may return normalized stored values but never raw SNMP varbinds or secrets.

- [ ] **Step 4: Verify GREEN**

Run `python -m pytest tests/test_netctl_switch_store.py tests/test_netctl_switch_cli.py -k "vlan or lldp" -q`. Expected: pass.

- [ ] **Step 5: Commit**

```powershell
git add netctl/db.py netctl/switch_store.py netctl/switch_queries.py netctl/cli.py tests/test_netctl_switch_store.py tests/test_netctl_switch_cli.py
git commit -m "feat: preserve switch optional state"
```

## Task 11B: CSS326 legacy FDB and optional LLDP

**Files:**
- Create: `netctl/snmp/lldp.py`
- Create: `tests/fixtures/snmp/css326.json`
- Modify: `netctl/snmp/oids.py`
- Modify: `netctl/snmp/profiles.py`
- Modify: `netctl/snmp/collector.py`
- Modify: `tests/test_netctl_snmp_profiles.py`
- Modify: `tests/test_netctl_snmp_parsers.py`

**Interface:**

```python
def parse_lldp_neighbors(
    chassis_result: CapabilityResult,
    port_result: CapabilityResult,
    system_name_result: CapabilityResult,
    *,
    ports: Iterable[SwitchPort],
) -> tuple[dict[str, object], ...]: ...
```

- [ ] **Step 1: Write failing fixture tests**

Create a sanitized CSS326 fixture and tests proving: Q-BRIDGE explicitly unsupported selects legacy FDB; ports 1–26 retain one-to-one bridge/ifIndex/physical normalization; fixture upstream entries map to physical 24, 13 and 5; legacy rows use `legacy:unknown`; empty LLDP clears only LLDP; unsupported LLDP keeps FDB successful; and unsupported TP-Link VLAN/PVID/LLDP preserves pre-seeded optional database rows.

- [ ] **Step 2: Verify RED**

Run `python -m pytest tests/test_netctl_snmp_profiles.py tests/test_netctl_snmp_parsers.py tests/test_netctl_switch_store.py -k "css326 or lldp or tplink" -q`. Expected: fail because LLDP parsing/collection and CSS326 fixture/profile do not exist.

- [ ] **Step 3: Implement read-only LLDP and CSS326 support**

Use only numeric LLDP-MIB remote chassis-ID, port-ID and system-name OIDs. Collect all three as the `lldp_remote` optional group, join their common time-mark/local-port/rem-index suffix, validate prefix/suffix/type, and resolve a local port from the collected port map. Successful LLDP parsing returns only `local_port_key`, `chassis_id`, `port_id`, and `system_name`. A malformed successful group becomes sanitized `PARSE_ERROR` outcomes for the three group capabilities (`malformed_lldp`, `SNMP LLDP rows are malformed`) and never fails FDB. CSS326 uses the existing legacy-FDB path and one-to-one ports 1–26.

- [ ] **Step 4: Verify GREEN and regression tests**

Run:

```powershell
python -m pytest tests/test_netctl_snmp_profiles.py tests/test_netctl_snmp_parsers.py tests/test_netctl_switch_store.py tests/test_netctl_switch_cli.py -q
python -m pytest -q
```

Expected: all pass with no live device access.

- [ ] **Step 5: Commit**

```powershell
git add netctl/snmp/lldp.py netctl/snmp/oids.py netctl/snmp/profiles.py netctl/snmp/collector.py tests/fixtures/snmp/css326.json tests/test_netctl_snmp_profiles.py tests/test_netctl_snmp_parsers.py
git commit -m "feat: collect CSS326 legacy FDB and LLDP"
```

## Self-review

- Migration 6 is additive and migrations 1–5 are unchanged.
- Each optional group covers rows, empty, unsupported, timeout/parse preservation.
- FDB failure preservation still passes.
- CLI reads are paginated/read-only.
- No production inventory, source YAML, raw SNMP output or secrets are committed.
