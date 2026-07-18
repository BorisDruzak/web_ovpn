# Netctl SNMP/FDB PR 3A Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Deliver a fully tested, read-only SNMPv2c/DGS collector core without enabling a live source.

**Architecture:** `netctl.snmp` owns typed numeric-OID transport and parsing; `snmp_switch` adapts it to the existing driver contract. Migration 5 and `switch_store` persist switch state separately from RouterOS/runtime assets, replacing current FDB only after an explicit successful FDB outcome.

**Tech Stack:** Python 3.12, SQLite, `pysnmp==7.1.27`, pytest, existing netctl CLI/driver framework.

## Global Constraints

- Work from `origin/main` at `ca728f2` or a fast-forward successor; migrations 1–4 are immutable and migration 5 is the first switch schema change.
- SNMP uses only GET/WALK operations. No SET, device configuration, live collection, source enablement, community or runtime topology belongs in this PR.
- Support only SNMPv2c and reject other versions; resolve a community only from environment/secrets at process time and never persist, log, return, fixture or commit it.
- Numeric OIDs are authoritative. Tests use injected transports and sanitized values only.
- FDB outcome distinguishes rows, confirmed empty, unsupported, timeout, explicit auth/view failure, and parse error. Only rows/confirmed empty may replace `current_switch_fdb`.
- Generic code never assumes FID equals VID; the DGS profile may do so only through a fixture-proven rule.
- A failed source does not block unrelated sources; different MACs do not merge assets automatically.

---

### Task 1: Migration 5 and secret-safe SNMP source configuration

**Files:** `netctl/migrations.py`, `netctl/config.py`, `netctl/db.py`, `tests/test_netctl_snmp_config.py`.

**Interfaces:** `normalize_source()` returns public `driver_options` but never a resolved secret; `MIGRATIONS` gains `(5, _migration_5)`.

- [ ] Write failing tests for ledger `[1,2,3,4,5]`, savepoint rollback, immutable legacy migrations, default `driver_options_json='{}'`, v2c-only validation, scalar-to-options normalization and public-secret redaction.
- [ ] Run `python -m pytest tests/test_netctl_snmp_config.py -q` and confirm RED.
- [ ] Add migration 5 with individual `conn.execute()` statements for `driver_options_json`, switch devices/runs/capabilities/ports/current FDB/FDB events; do not call `commit()` or `executescript()`.
- [ ] Add SNMP option validation and a distinct community environment-name resolver; reject `community` YAML keys and omit `secret_ref` resolution from public source objects.
- [ ] Run `python -m pytest tests/test_netctl_snmp_config.py -q`; commit `feat: add switch schema and SNMP sources`.

### Task 2: Typed, secret-safe SNMP transport

**Files:** `requirements.txt`, `netctl/snmp/__init__.py`, `netctl/snmp/models.py`, `netctl/snmp/outcomes.py`, `netctl/snmp/oids.py`, `netctl/snmp/transport.py`, `tests/test_netctl_snmp_transport.py`.

**Interfaces:** `SnmpOutcome`, `SnmpVarBind`, `CapabilityResult`; `SnmpTransport.walk_numeric(oid) -> CapabilityResult`.

- [ ] Write failing injected-transport tests for numeric OID conversion, successful rows, confirmed empty, no-such-object, timeout, explicit `authorizationError`/`noAccess`, malformed values, and errors that never include community text.
- [ ] Run `python -m pytest tests/test_netctl_snmp_transport.py -q` and confirm RED.
- [ ] Pin `pysnmp==7.1.27`; implement v2c GET/WALK transport with bounded timeout/retries, no MIB lookup and sanitized error codes/messages. Reject unsupported SNMP versions before opening transport.
- [ ] Run focused tests and `python -m pytest tests/test_netctl_snmp_transport.py tests/test_netctl_snmp_config.py -q`; commit `feat: add typed SNMP transport`.

### Task 3: Normalize system, interfaces, bridge map and Q-BRIDGE FDB

**Files:** `netctl/snmp/system.py`, `netctl/snmp/interfaces.py`, `netctl/snmp/fdb.py`, `netctl/snmp/profiles.py`, `netctl/snmp/collector.py`, `tests/test_netctl_snmp_parsers.py`, `tests/test_netctl_snmp_profiles.py`.

**Interfaces:** `SwitchSystem`, `SwitchPort`, `PortResolution`, `SwitchFdbEntry`, `SwitchSnapshot`; `collect_switch_snapshot(source, transport) -> SwitchSnapshot`.

- [ ] Write failing parser tests for ifTable/ifXTable, bridge-port-to-ifIndex mapping, MAC normalization, FID extraction, unsupported Q-BRIDGE versus timeout/parse, and no generic FID-to-VID conversion.
- [ ] Run `python -m pytest tests/test_netctl_snmp_parsers.py tests/test_netctl_snmp_profiles.py -q` and confirm RED.
- [ ] Implement numeric-OID parsers and generic profile selection. Q-BRIDGE is preferred; legacy FDB is not selected after timeout or parse error.
- [ ] Verify `success_empty` yields an empty FDB while unsupported/timeout/parse yield non-replacing outcomes; commit `feat: normalize switch interfaces and FDB`.

### Task 4: DGS fixture and profile vertical slice

**Files:** `tests/fixtures/snmp/dgs.json`, `netctl/snmp/profiles.py`, `tests/test_netctl_snmp_profiles.py`.

**Interfaces:** `DgsProfile` supplies its explicit FID/VID rule and port normalization only for matching fixture-proven DGS data.

- [ ] Add a sanitized numeric-OID fixture with synthetic ports/FDB rows; it contains no source address, community, device backup or complete production inventory.
- [ ] Write RED tests for DGS profile selection, exact fixture count, port/bridge mapping, one known normalized FDB entry, and no FID/VID rule leakage to generic profiles.
- [ ] Implement the DGS profile and run `python -m pytest tests/test_netctl_snmp_profiles.py -k dgs -q`.
- [ ] Commit `feat: add DGS SNMP profile fixture`.

### Task 5: Transactional current FDB and event persistence

**Files:** `netctl/switch_store.py`, `tests/test_netctl_switch_store.py`.

**Interfaces:** `collect_and_save_switch(conn, source, driver, started_at) -> dict`; current FDB replacement and FDB events occur in one transaction.

- [ ] Write failing tests for initial appeared events, identical collection emitting none, one port movement emitting one moved event, confirmed empty replacing state, failed FDB preserving state and emitting no disappeared event, and source isolation.
- [ ] Run `python -m pytest tests/test_netctl_switch_store.py -q` and confirm RED.
- [ ] Implement run creation/finalization, status/outcome persistence, current state diff keyed by `(vlan_key, mac)`, first-seen retention and event insertion without calling existing commit-owning helpers.
- [ ] Run focused tests; commit `feat: persist transactional switch FDB state`.

### Task 6: Driver, CLI surface and focused CI

**Files:** `netctl/drivers/snmp_switch.py`, `netctl/drivers/__init__.py`, `netctl/cli.py`, `netctl/switch_queries.py`, `.github/workflows/verify-netctl-runtime.yml`, `tests/test_netctl_switch_cli.py`.

**Interfaces:** `driver_for()` returns `SnmpSwitchDriver`; CLI has secret-free `sources add-snmp-switch`, source test/collect dispatch, and read-only paginated `switches` queries.

- [ ] Write failing CLI tests: generated YAML has no community, source inspect returns no secret, failed SNMP source does not stop collect-all, switch queries do not write, and FDB output is bounded and raw-varbind-free.
- [ ] Run `python -m pytest tests/test_netctl_switch_cli.py -q` and confirm RED.
- [ ] Implement driver serialization via explicit `to_dict`, CLI validation and pagination; use `collect_and_save_switch`, never legacy `save_collection` for switch snapshots.
- [ ] Add all PR3A SNMP tests to focused CI; run focused suites, `python -m pytest -q`, and `git diff --check`; commit `feat: expose switch collection CLI`.

### Task 7: Read-only release readiness documentation

**Files:** `docs/runbooks/netctl-snmp-dgs-pilot.md`, `README.md`, `tests/test_netctl_switch_cli.py`.

- [ ] Write tests asserting installer/config examples use disabled source and no community value.
- [ ] Document the later pilot gate: SQLite backup/integrity check, migration ledger 1–5, protected environment secret, two manual DGS collections, idempotence and failure-preservation proof. Do not execute it in this PR.
- [ ] Run `python -m pytest -q` and secret scan `git grep -nE '(community|NETCTL_SECRET_.*_COMMUNITY)=' -- ':!docs/plans/netctl-snmp-fdb-collectors.md'`.
- [ ] Commit `docs: add DGS SNMP pilot gate`.

## Plan self-review

- Spec coverage: Tasks 1–6 cover the entire PR3A code path; Task 7 deliberately gates live operation outside this branch.
- No placeholders: live communities, hosts and device output remain external by design; every implementation step has a focused test and command.
- Type consistency: transport returns outcomes consumed by collector; collector snapshot is consumed by store; store result is consumed by CLI.
