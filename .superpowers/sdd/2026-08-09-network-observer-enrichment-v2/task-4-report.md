# Task 4 — FDB Subtree Correlation — implementation report

## Status

Implemented and verified locally in the isolated worktree
`C:\Users\admin-2\Documents\ui_vpn\.worktrees\network-observer-enrichment-v2`.

Starting Git state:

```text
branch: codex/network-observer-enrichment-v2
HEAD: 6b579e49c36b67c5a51835eb6a6d93bd24ac8a2b
worktree: clean
```

No deployment, SSH, SNMP write, device configuration, or other
production-network action was performed.

## Implementation

- Added deterministic FDB-subtree candidate correlation to
  `netctl/fdb_correlation.py`.
- A child leaf set contains unique, normalized current learned unicast MACs
  and excludes all known switch-management MACs, non-learned/self/invalid
  rows, malformed/zero/multicast/broadcast MACs, and MACs learned on ports
  already proven as non-conflicting backbone links.
- A candidate is strong only when the child has at least four leaf MACs and
  at least 80% of them occur on one parent port.
- When at least one strong candidate for a child also contains the child's
  management MAC, candidates without that signal are discarded. Remaining
  ordering and tie handling are deterministic.
- Evidence records the child source, leaf count, matched count, exact
  coverage, and whether the child management MAC was seen. Port-role
  confidence is the rounded coverage percentage.
- Reverse-port resolution searches the child's FDB for every valid management
  MAC of the candidate parent. A child uplink port is accepted only when the
  result is exactly one unique child port. Zero or multiple ports remain
  unresolved.
- Complete `fdb_subtree` topology evidence is emitted only for candidates with
  an exact reverse port and one unique best parent after management-MAC and
  coverage ranking. Equal upstream winners never create multiple topology
  links; they remain `parent port -> suspected child` port-role evidence.
- Complete subtree evidence is also suppressed when either candidate endpoint
  port is already assigned to another peer by non-conflicting intent, exact
  LLDP, or bidirectional management-MAC/FDB evidence.
- Topology aggregation now resolves contradictory port evidence by the strict
  tier order: declared intent, exact LLDP, bidirectional management-MAC/FDB,
  FDB subtree, then density. Conflicts inside the same strongest tier remain
  conflicts; contradictory weaker evidence cannot replace the selected port.
- One-sided management-MAC evidence remains below subtree evidence for port
  roles, so it cannot hide a stronger suspected-child subtree result.
- Topology reconciliation calculates candidates from stronger links first,
  adds only complete subtree link evidence, calculates depths from the final
  links, and persists the resulting roles in the existing atomic correlation
  transaction.
- Parent candidate ports become `downstream_bridge`; an exactly proven child
  uplink becomes `backbone`. Intent, LLDP, bidirectional management/FDB, and
  conflicts keep their higher existing priority.
- The existing bounded read-only command
  `netctl --json switches port-roles [--source SOURCE]` now exposes the
  allowlisted subtree metrics while continuing to omit arbitrary/private
  evidence fields.
- Asset connection context maps subtree roles to a concise Russian reason.
  The existing card fields render role, confidence, MAC count, suspected
  child source, and the reason without exposing raw evidence.

## Evidence hierarchy

```text
declared intent
> exact LLDP
> bidirectional management-MAC/FDB
> FDB subtree correlation
> one-sided management-MAC / density-only evidence
```

Lower-tier evidence may fill a previously unresolved endpoint, but it cannot
replace a contradictory port selected by a stronger tier. Multiple different
ports at the strongest available tier still produce a topology conflict.

## Files

Created:

- `tests/test_netctl_fdb_subtree.py`
- `.superpowers/sdd/2026-08-09-network-observer-enrichment-v2/task-4-report.md`

Modified:

- `netctl/fdb_correlation.py`
- `netctl/topology_reconcile.py`
- `netctl/port_roles.py`
- `netctl/switch_queries.py`
- `netctl/context_query.py`
- `tests/test_netctl_topology.py`
- `tests/test_netctl_context_query.py`

No schema migration was needed; Task 4 reuses the current link and port-role
tables added by the preceding tasks.

## TDD evidence

Core correlator RED:

```text
pytest tests/test_netctl_fdb_subtree.py -q
```

Initial result: 2 failed because `fdb_subtree_candidates` and
`fdb_subtree_link_evidence` did not exist.

Core GREEN: 2 passed after the minimal correlator implementation.

Strict hierarchy RED:

```text
pytest tests/test_netctl_topology.py::test_aggregate_link_evidence_obeys_strict_conflict_hierarchy -q
```

Initial result: 1 failed because lower-tier contradictory ports made all
three source pairs conflicting. GREEN after tier-aware port selection: 1
passed, including the intent-only-versus-subtree confidence rule.

Port-role/reconciliation RED:

```text
pytest tests/test_netctl_fdb_subtree.py::test_one_sided_subtree_sets_only_parent_port_role tests/test_netctl_fdb_subtree.py::test_stronger_lldp_role_is_not_replaced_by_subtree_candidate tests/test_netctl_fdb_subtree.py::test_reconcile_adds_complete_subtree_link_only_from_exact_reverse_port -q
```

Initial result: 3 failed for the missing `subtree_candidates` integration and
the absent complete link. GREEN after integration: 3 passed.

Public CLI/context RED:

```text
pytest tests/test_netctl_fdb_subtree.py::test_reconcile_adds_complete_subtree_link_only_from_exact_reverse_port tests/test_netctl_context_query.py::test_confirmed_attachment_explains_fdb_subtree_child_role -q
```

Initial behavioral result: CLI exposed only the evidence type and asset
context returned an empty reason. GREEN after the safe projections: 2 passed.

The final edge-case RED proved that generic one-sided management evidence
incorrectly suppressed a one-sided subtree role. After lowering only that
evidence tier, the focused test and the complete Task 4 file passed.

## Verification

Static checks:

```text
git diff --check
python -m compileall -q netctl tests/test_netctl_fdb_subtree.py
```

Result: exit 0.

Expanded target suite:

```text
pytest tests/test_netctl_fdb_subtree.py tests/test_netctl_topology.py tests/test_netctl_port_roles.py tests/test_netctl_attachments.py tests/test_netctl_context_query.py tests/test_netctl_cli.py tests/test_web_network_observer.py -q
```

Result: 197 passed, 1 skipped, 0 failed in 47.15 seconds. Existing framework
deprecation warnings remain.

Fresh full suite:

```text
pytest -q
```

Result: 1473 passed, 11 skipped, 0 failed in 224.97 seconds. Existing
FastAPI/Starlette/pytest-asyncio deprecation warnings remain.

## Independent review

The read-only review found no Critical issues and initially identified two
Important ambiguity cases:

1. A subtree link could reuse a parent or child port already occupied by a
   stronger link to another peer because evidence aggregation is source-pair
   scoped.
2. Two equal upstream parent candidates with one exact child uplink could each
   produce a complete topology link.

Both were reproduced with failing tests before the fixes. Complete link
evidence now filters stronger occupied-port contradictions, groups remaining
candidates by child, ranks management-MAC presence and coverage, and emits
only one unique winner. The reconciliation integration has its own regression
test, so omitting the stronger-link guard recreates the false second link.

Final independent re-review verdict: no remaining Critical or Important
findings; assessment `Ready`.

## Review round 1 follow-up

A subsequent independent review identified two Important consistency defects:

1. Port-role inference consumed every strong subtree candidate even though
   complete topology-link inference selected only one unique winner. A weaker
   candidate for the same child uplink could therefore conflict with the
   selected winner and downgrade that child port to `unknown`.
2. Equal upstream candidates correctly produced no complete topology link,
   but the shared child port could still receive `fdb_subtree_backbone`
   evidence and an arbitrary `peer_source_id` from the first candidate.

Both cases were reproduced before the implementation change:

```text
pytest tests/test_netctl_fdb_subtree.py::test_unique_complete_winner_drives_matching_child_backbone_role tests/test_netctl_fdb_subtree.py::test_equal_ambiguous_parents_do_not_publish_arbitrary_child_peer -q
```

RED result: 2 failed. The first child role was `unknown/20` instead of
`backbone/100`; the equal-parent case published a `backbone` role despite no
complete link.

The unique-winner selection is now a reusable correlator operation. Topology
reconciliation passes that exact selected candidate set to both complete link
evidence and child-side port-role inference. All strong candidates still
contribute non-fabricated parent-side suspected-child evidence, while only a
complete unique winner can contribute child-side `backbone` evidence or a
`peer_source_id`.

GREEN result for the focused command: 2 passed.

Expanded Task 4 target:

```text
pytest tests/test_netctl_fdb_subtree.py tests/test_netctl_topology.py tests/test_netctl_port_roles.py tests/test_netctl_context_query.py tests/test_netctl_cli.py tests/test_web_network_observer.py -q
```

Result: 191 passed, 1 skipped, 0 failed in 46.60 seconds.

Fresh full suite after the review fixes:

```text
pytest -q
```

Result: 1475 passed, 11 skipped, 0 failed in 224.26 seconds. Existing
FastAPI/Starlette/pytest-asyncio deprecation warnings remain.

## Scope boundary

This change implements only Task 4. It does not deploy or collect from live
switches, modify production network configuration, add device writes, invent
CSS port mappings, implement discovery scans, or start later enrichment tasks.
