# Switch STP and Identity Persistence Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development or superpowers:executing-plans task-by-task.

**Goal:** Persist read-only STP current state and explicitly configured switch identity without implicit asset binding.

**Architecture:** Migration 7 adds `current_switch_stp_state`. The existing successful-FDB transaction replaces STP only after all STP capabilities confirm success/empty; every other outcome preserves prior STP. `switch_devices` identity columns are populated only from source configuration and never inferred from SNMP data.

## Constraints

- Migrations 1–6 are immutable; add only migration 7.
- No SNMP SET, source activation, asset creation, automatic binding, or production deployment.
- STP optional failure never blocks FDB/port/VLAN/LLDP persistence.
- `success_empty` clears STP; unsupported/timeout/auth/parse preserves it.
- CLI reads are paginated, read-only and secret-safe.

## Task 1: STP and identity persistence

**Files:** `netctl/migrations.py`, `netctl/switch_store.py`, `netctl/switch_queries.py`, `netctl/cli.py`, `tests/test_netctl_switch_store.py`, `tests/test_netctl_switch_cli.py`.

- [ ] Write failing tests for migration 7 table `current_switch_stp_state(source_id PRIMARY KEY, protocol, root_bridge_mac, root_port_key, root_path_cost, topology_changes, observed_at)`; STP replace, confirmed-empty clear, unsupported/timeout/auth/parse preserve; successful FDB with failed STP; explicit identity set/clear; invalid asset ID rejection; no implicit asset binding; paginated read-only `switches stp`.
- [ ] Run focused RED: `python -m pytest tests/test_netctl_switch_store.py tests/test_netctl_switch_cli.py -k "stp or identity" -q`.
- [ ] Add migration 7 and index `(observed_at DESC)`. Validate STP normalized mapping and replace it only when all five STP capability outcomes are `SUCCESS_WITH_ROWS` or `SUCCESS_EMPTY`; preserve otherwise. Extend `_upsert_device()` to write source `runtime_asset_id`, `intent_context_id`, `intent_stable_id` only after validating explicit source values. Add parameterized `query_switch_stp()` and `switches stp` (`--limit` 500/max 5000, `--offset` nonnegative).
- [ ] Run focused GREEN and full `python -m pytest -q`.
- [ ] Commit: `git commit -m "feat: persist switch STP and explicit identity"`.

## Verification

- Migrations 1–6 remain byte-for-byte unchanged.
- Failed optional STP does not delete current row and does not change FDB replacement.
- No test or CLI path creates/links an asset from observations.
- No secrets, raw SNMP payloads or source activation are committed.
