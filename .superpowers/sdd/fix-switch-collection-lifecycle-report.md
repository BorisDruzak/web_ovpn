# Switch collection lifecycle final-review fix

## Scope and outcome

Fixed only switch collection run lifecycle, final status, persistence-error
finalization, and CLI completion handling. No vendor profile, source
configuration, SNMP transport, device-access, deployment, or rollout behavior
was changed.

The store now commits a `running` run before calling `driver.collect()`. The
snapshot/state write remains a separate atomic transaction. A confirmed
required FDB result with a failed optional VLAN, STP, or LLDP capability writes
the required device/port/FDB state and finalizes the run as `partial`. Both
`success` and `partial` protect current FDB ordering from older snapshots.

If the post-collection persistence transaction fails, its state changes roll
back and a recovery transaction finalizes the already durable run as `failed`
with fixed `persistence_error` / `Switch collection persistence failed` fields.
The injected database error text is not persisted or returned.

The CLI treats `success` and `partial` as completed collections, advances
`last_collect_at`, stores the actual source status, returns exit code zero, and
exposes the store status as `collection_status`.

## Root cause

`collect_and_save_switch()` previously called `driver.collect()` before a run
existed. Run creation, state replacement, and run finalization then shared one
transaction, so any persistence failure rolled the run back together with the
state. The success branch unconditionally selected `success`, and the CLI
considered only exact `success` completed. Stale ordering also ignored partial
runs even though their required FDB state is authoritative.

## TDD evidence

Baseline before new regressions:

```text
python -m pytest tests/test_netctl_snmp_config.py tests/test_netctl_switch_store.py tests/test_netctl_switch_cli.py -q
133 passed in 4.22s
```

RED after adding migration/store/CLI lifecycle expectations:

```text
9 failed, 127 passed in 4.37s
```

The failures were the expected missing committed running run, store-level
partial statuses, and CLI status exposure. The migration status-domain test was
already green because migration 5 correctly permits `partial`; no migration
rewrite was needed.

Focused GREEN after implementation and lifecycle expectation updates:

```text
python -m pytest tests/test_netctl_snmp_config.py tests/test_netctl_switch_store.py tests/test_netctl_switch_cli.py -q
137 passed in 3.78s
```

Additional profile-level status regression:

```text
python -m pytest tests/test_netctl_snmp_profiles.py -k "unsupported_optional_groups or empty_lldp_clears" -q
2 passed, 44 deselected in 0.52s
```

Full verification:

```text
python -m pytest -q
487 passed, 1 skipped, 5360 warnings in 35.78s

python -m compileall -q netctl
exit 0

git diff --check
exit 0, no output
```

The warnings are the repository's existing FastAPI, Starlette,
`pytest-asyncio`, and template deprecation warnings.

## Regression coverage

- Migration status constraint accepts `partial` and rejects an unknown status.
- A second database connection observes the committed `running` row from
  inside the driver call, proving the run exists durably before network I/O.
- Optional VLAN/LLDP failures preserve their current rows while required FDB
  and port state advances and the run finalizes `partial`.
- A partial run prevents an older snapshot from reversing current FDB state.
- Malformed snapshots finalize the pre-created run as sanitized `failed` while
  leaving device, port, capability, FDB, and event state unchanged.
- An injected transaction-B event insert failure rolls all state back, raises
  only the fixed public exception, and leaves a sanitized failed run.
- CLI partial collection returns exit code zero, exposes `collection_status`,
  and updates source collection metadata without a false error.

## Security and safety review

- Required FDB replacement remains fail closed: only `success_with_rows` and
  `success_empty` replace current FDB state.
- Optional failures cannot clear their prior current state.
- Failure records contain fixed error class/message values and enum outcome
  values only; injected secret-bearing exception text is absent.
- No network device, remote host, deployment target, or production database was
  contacted.

## Files changed

- `netctl/switch_store.py`
- `netctl/cli.py`
- `tests/test_netctl_snmp_config.py`
- `tests/test_netctl_switch_store.py`
- `tests/test_netctl_switch_cli.py`
- `tests/test_netctl_snmp_profiles.py`
- `.superpowers/sdd/fix-switch-collection-lifecycle-report.md`

## P1 follow-up: optional unsupported capabilities are healthy

Review identified that the initial partial-status predicate treated every
non-success optional outcome as a failure. That incorrectly marked a switch
`partial` when an optional MIB object was explicitly unsupported, even though
the collector had successfully established that the optional capability was not
available.

`unsupported_no_such_object` is now a healthy optional outcome alongside
`success_with_rows` and `success_empty`. Only actual optional collection
failures (`timeout`, `auth_or_view_failure`, and `parse_error`; protocol
failures are normalized to the same failed outcomes) cause a `partial` run.
Optional current-state preservation remains unchanged for unsupported probes.

### P1 TDD and verification

RED after changing the store/profile expectations before production code:

```text
4 failed, 4 passed, 90 deselected in 1.77s
```

The failures were the unsupported VLAN/LLDP store cases and the TP-Link/CSS326
fixture persistence paths, all incorrectly reported as `partial`.

GREEN:

```text
python -m pytest tests/test_netctl_switch_store.py tests/test_netctl_snmp_profiles.py tests/test_netctl_switch_cli.py -k "optional_error_preserves or unsupported_optional_groups or empty_lldp_clears or partial_collect" -q
9 passed, 133 deselected in 0.93s

python -m pytest -q
487 passed, 1 skipped, 5360 warnings in 37.26s
```

No network device, remote host, deployment target, or production database was
contacted for this follow-up.
