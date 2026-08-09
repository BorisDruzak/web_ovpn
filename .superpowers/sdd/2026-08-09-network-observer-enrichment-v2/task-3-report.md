# Task 3 — Port Role / MAC-density Engine — implementation report

## Status

Implemented and verified locally in the isolated worktree
`C:\Users\admin-2\Documents\ui_vpn\.worktrees\network-observer-enrichment-v2`.

Starting Git state:

```text
branch: codex/network-observer-enrichment-v2
HEAD: e39c72377a1d23ac17ed0649f480f8695ea5147c
worktree: clean
```

No deployment, SSH, SNMP write, device configuration, or other production-network action was performed.

## Implementation

- Added migration 22 with constrained `current_switch_port_roles` persistence and indexes.
- Added `netctl/fdb_correlation.py` to aggregate normalized, unique current FDB MACs per port, count known assets and unique OUIs, detect known switch-management MACs, and read the existing per-source `access_port_mac_threshold` option. The canonical fallback remains 10; no competing configuration option was introduced.
- Added `netctl/port_roles.py` with deterministic roles limited to:
  `endpoint`, `backbone`, `downstream_bridge`, `shared_edge`, and `unknown`.
- Port roles are replaced atomically inside the existing topology correlation transaction and reference the topology correlation run.
- Added the bounded read-only CLI query:
  `netctl --json switches port-roles [--source NAME] [--limit N] [--offset N]`.
- Attachment candidates now consume the current port role:
  `backbone` and `downstream_bridge` become uplink-class candidates with a strong score penalty;
  `shared_edge` remains a direct candidate and receives only a confidence/score reduction.
- Confirmed attachment context includes a bounded safe role projection; arbitrary/private keys from stored evidence are not exposed.
- The asset connection card shows role, confidence, MAC count, an optional child switch, and a concise evidence reason.

## Deterministic decision order

1. A confirmed switch link assigns `backbone` at confidence 100.
2. An exact LLDP-known-switch link assigns the parent port `downstream_bridge` and the child-side port `backbone` at confidence 95. Direction uses topology depth first and configured topology role second; it is not guessed when direction is unknown.
3. Other non-conflicting inferred topology assigns `backbone` at confidence 95.
4. A topology conflict assigns `unknown` and retains density evidence without selecting a child.
5. One learned MAC with no known switch-management MAC assigns `endpoint` at confidence 80.
6. Two or three MACs assign `shared_edge` at moderate confidence 55, never an automatic uplink.
7. Four or more MACs below the configured threshold assign `shared_edge` at confidence 65.
8. MAC count at or above the existing threshold assigns `shared_edge` at confidence 70 unless stronger topology/LLDP evidence exists. Density alone never assigns `downstream_bridge`.
9. A management-only or empty port remains `unknown`.

All tie-breaking and output ordering are stable by source/port/link keys. `child_source_id` is only populated for a directionally proven LLDP parent port; no remote port or child switch is manufactured from MAC density.

## Files

Created:

- `netctl/fdb_correlation.py`
- `netctl/port_roles.py`
- `tests/test_netctl_port_roles.py`
- `.superpowers/sdd/2026-08-09-network-observer-enrichment-v2/task-3-report.md`

Modified:

- `netctl/migrations.py`
- `netctl/cli.py`
- `netctl/switch_queries.py`
- `netctl/attachment_candidates.py`
- `netctl/attachment_reconcile.py`
- `netctl/topology_reconcile.py`
- `netctl/context_query.py`
- `app/templates/network_asset_detail.html`
- `tests/test_netctl_attachments.py`
- `tests/test_netctl_context_query.py`
- `tests/test_web_network_observer.py`
- `tests/test_netctl_cli.py`
- `tests/test_netctl_context_migrations.py`

## TDD evidence

Initial RED command:

```text
pytest tests/test_netctl_port_roles.py tests/test_netctl_attachments.py::test_attachment_candidates_apply_port_role_penalties_without_dropping_shared_edge tests/test_netctl_context_query.py::test_confirmed_attachment_exposes_safe_current_port_role tests/test_web_network_observer.py::test_network_asset_card_requires_login_and_renders_confirmed_attachment -q
```

Initial result: 6 failed for the expected missing table/module/API/UI behavior.

The same command after the minimal implementation: 6 passed.

Target files:

```text
pytest tests/test_netctl_port_roles.py tests/test_netctl_attachments.py tests/test_netctl_topology.py tests/test_netctl_context_query.py tests/test_web_network_observer.py -q
```

Result: 96 passed.

The first full run found two hard-coded migration-version expectations still ending at 21. After updating those compatibility contracts, the focused regression command passed 2/2.

Fresh final full suite:

```text
pytest -q
```

Result: 1461 passed, 11 skipped, 0 failed in 223.84 seconds. Existing FastAPI/Starlette/pytest-asyncio deprecation warnings remain; no new test warnings were treated as failures.

## Scope boundary

This change implements only Task 3. It does not implement Task 4 FDB-subtree coverage inference, OPNsense integration, discovery scans, secrets, topology hardcoding, or any production configuration change.

## Review round 1 follow-up

Review source:
`.superpowers/sdd/2026-08-09-network-observer-enrichment-v2/task-3-review-round-1.md`.

Both Important findings were reproduced before the production fix:

```text
pytest tests/test_netctl_port_roles.py::test_conflicting_topology_marks_all_evidence_ports_unknown_deterministically tests/test_netctl_port_roles.py::test_non_learned_other_fdb_status_does_not_create_endpoint_evidence -q
```

RED result: 2 failed. The first port stayed density-based because a conflicting aggregate had an empty direct key; the second became a false endpoint from one `status=other` row.

Fixes:

- Port-role inference now derives one sorted unique port-key set from both a link's direct endpoints and every non-empty evidence endpoint. Conflicting links mark all of those ports `unknown`, and evidence-only ports are included in the result instead of being omitted.
- MAC density and endpoint inference now accept only normalized current FDB rows whose status is exactly `learned`. `other`, `invalid`, `self`, `mgmt`, and unknown statuses do not contribute endpoint/density MACs.
- The conflict regression recomputes the aggregate from reordered evidence and calls inference with reordered links, identities, and depth-map insertion order. The complete `PortRole` tuple remains equal.

GREEN result: 2 passed.

Fresh review-round target result:

```text
98 passed
```

Fresh full-suite result:

```text
1463 passed, 11 skipped, 0 failed in 222.52 seconds
```

Task 4 FDB-subtree correlation and all production/network actions remain out of scope.
