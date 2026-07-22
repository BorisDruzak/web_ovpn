# ALT OR-3P3 Completion Hardening Design

**Date:** 2026-07-22  
**Status:** approved continuation design for draft PR #24

This amendment completes OR-3P3 Tasks 10-13 and overrides conflicting restore and rollout details in the earlier design and plan.

## Invariants

1. A restore failure before production rename ends in durable terminal phase `aborted`.
2. Before the first production rename, the journal enters `originals_moving` and stores the complete path plan, pre-restore digests, snapshot identity and service state.
3. Progress is fsynced after every processed path. A crash between rename and progress write is resolved from exact sibling-path state and digest proof.
4. Successful reversal ends in `rolled_back`. Incomplete proof ends in `manual_recovery_required`, with maintenance services stopped.
5. `recover <restore-id>` is explicit and idempotent. It never selects a transaction or backup implicitly.
6. A rolled-back emergency restore preserves the failed-rollout marker. A successful restore records `committed` before clearing that marker.
7. Restore capacity is checked per filesystem before journal creation or service stop.
8. Every public backup command writes bounded, secret-free start and terminal audit records.
9. The control-plane installer requires one exact rehearsed backup ID before mutation.
10. The static provisioning service exposes only allowlisted bootstrap and metadata regular files.

## Restore phases

```text
prepared -> staged -> services_stopped -> originals_moving
-> originals_moved -> installed -> daemon_reloaded
-> health_checked -> committed
```

Terminal phases are `aborted`, `rolled_back`, and `manual_recovery_required`.

`originals_moving` records, for every exact managed path: component, logical path, desired presence, previous presence, processed state, moved state, and pre-restore digest. The path order must exactly match the six-component policy.

## Recovery

`alt-deploy-backup recover <restore-id>` handles:

- `prepared`, `staged`, `services_stopped`: remove transaction-owned staging, restore recorded units, record `aborted`;
- `originals_moving` and later non-terminal phases: restore rollback siblings or prove untouched paths, restore recorded units, prove every digest, record `rolled_back`;
- `committed`, `rolled_back`, `aborted`: return the terminal result idempotently;
- `manual_recovery_required`: keep maintenance services stopped and return the manual-recovery error.

The journal never stores secret contents and accepts only bounded exact-schema evidence.

## Remaining completion work

After durable recovery, add capacity/audit, the boot and rollout guard, dedicated backup installer, explicit rollback gate, restricted static server, operator documentation and final verification. Repository work must not contact `192.168.100.17` or `192.168.101.111`, and PR #24 remains draft until explicit user approval.
