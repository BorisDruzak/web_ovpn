# Task 8 — Enriched asset context — implementation report

## Status

Implemented and verified locally in the isolated worktree
`C:\Users\admin-2\Documents\ui_vpn\.worktrees\network-observer-enrichment-v2`.

No deployment, SSH, live Nmap/SNMP collection, privilege change, device write,
or production-network action was performed.

## Implementation

- `netctl context-view asset --asset-key ...` now exposes the canonical
  derived V2 classification as top-level `fingerprint` with exactly:
  `device_type`, `confidence`, `evidence`, `alternatives`, `computed_at`, and
  `version`.
- Cached normalized Nmap data is exposed separately as `nmap_fingerprint`.
  The run projection keeps safe identity/status/timing/version/freshness
  fields, normalized ports, and normalized OS matches.
- Removed the temporary `device_fingerprint` response key. The sole internal
  web consumer now reads derived V2 from `fingerprint` and Nmap data from
  `nmap_fingerprint`, preserving the existing card and polling behavior.
- Preserved every unrelated asset-context structure and its meaning,
  including asset, intent, owner, interfaces, attachment, network, topology,
  history, freshness, source health, findings, and the existing empty generic
  `evidence` dictionary.
- Existing confirmed attachment projections continue to expose
  `attachment.port.telemetry` and `attachment.port.role`. Tests now explicitly
  cover exclusion of private, SNMP-community, sudo, and raw-collector fields
  from stored role evidence.

## Bounds and safety

The Task 8 context projections rebuild output from allowlisted fields and
apply defensive bounds even if stored rows are malformed or compromised:

- derived V2: at most 64 evidence items and 8 alternatives;
- normalized Nmap: at most 100 ports and 32 OS matches;
- each OS match: at most 16 OS classes;
- each port or OS class: at most 16 CPE values;
- projected text: at most 512 characters, with smaller limits for run/status
  fields.

Nmap `error_class` and `error_message` are not copied into asset context.
Arbitrary nested keys are dropped. The context does not expose SNMP
communities, sudo details, raw Nmap XML/stderr, raw collector payloads, or
other internal fields.

## Files

Modified:

- `netctl/context_query.py`
- `app/main.py`
- `tests/test_netctl_context_query.py`
- `tests/test_netctl_nmap_cli.py`
- `tests/test_web_network_observer.py`

Created:

- `.superpowers/sdd/2026-08-09-network-observer-enrichment-v2/task-8-report.md`

## TDD evidence

### Mapping-neutral bounds

The first RED run produced two expected failures:

- normalized Nmap context still included `error_class`/`error_message` and
  unbounded nested lists;
- stored derived evidence text exceeded the required context bound.

The strengthened attachment secret-exclusion test already passed, confirming
the pre-existing role projection remained safe. After the minimal allowlisted
projection implementation, the focused result was `3 passed` and the complete
context-query suite was `22 passed`.

### Canonical Task 8 keys

After tests were changed to the approved canonical contract, RED produced:

- four context failures because the producer still returned Nmap under
  `fingerprint` and V2 under `device_fingerprint`;
- two web failures because the sole internal consumer still read those old
  keys.

After changing the producer and web normalizer, the focused canonical result
was `6 passed`.

The expanded target run then identified one stale assertion in the existing
Nmap CLI/context test. Updating that assertion to the approved
`nmap_fingerprint` contract produced a clean full target rerun.

## Verification

Pre-edit baselines:

```text
Focused: 65 passed
Full: 1581 passed, 11 skipped
```

Final expanded target suite:

```text
python -m pytest -q tests/test_netctl_context_query.py tests/test_context_api.py \
  tests/test_web_network_observer.py tests/test_netctl_nmap_store.py \
  tests/test_netctl_nmap_cli.py tests/test_netctl_fingerprint_providers.py \
  tests/test_netctl_attachments.py
```

Result: `156 passed` in 57.07 seconds.

Fresh final full suite:

```text
python -m pytest -q
```

Result: `1583 passed, 11 skipped` in 266.88 seconds. Existing
FastAPI/Starlette/pytest-asyncio deprecation warnings remain.

Static checks:

```text
python -m compileall -q netctl app/main.py tests/test_netctl_context_query.py \
  tests/test_netctl_nmap_cli.py tests/test_web_network_observer.py
git diff --check
```

Both returned exit code 0.

## Scope boundary

This change implements only Task 8. It does not change schema, scanning
policy, Nmap execution, SNMP collection, topology/attachment inference,
deployment artifacts, or production state.
