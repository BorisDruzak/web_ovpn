# Current-model stabilization verification record

## Scope and status

This record covers the S1--S3 implementation described by the current-model
stabilization plan. It is implementation evidence, not evidence that a
production deployment has occurred.

Implemented locally:

- WAL-safe, read-only context snapshots and fail-closed policy preflight.
- Audit records containing actual accepted Unix peer credentials, and private
  signing material delivered through named systemd credentials.
- Authoritative partial-FDB handling, preserved correlation state on failures,
  per-interface attachments, owner context, readiness reasons, and redacted
  backbone-evidence summaries.
- Additive v1 context envelopes with snapshot metadata, signed search cursors,
  bounded topology responses, and ETags.

Not asserted by this record:

- That the application is deployed to a remote host.
- That every network source has complete, current topology evidence.
- That either production-write gate is enabled, disabled, or otherwise
  changed. Deployment preserves both captured values verbatim.

## Data-quality interpretation

Use `netctl context-view source-readiness` before trusting an inferred topology
result. A non-ready source reports stable reason codes such as missing identity
evidence, non-authoritative or stale FDB data, missing port inventory, or
ambiguous management identity. `netctl context-view backbone-evidence` exposes
only bounded decision flags; it does not expose FDB rows or secrets.

## Release checks

Run these commands from the checked-out release tree before considering a
deployment:

```text
python -m pytest -q
python -m compileall -q app netctl netopsctl
git diff --check
rg -n "immutable=1" netctl netopsctl app
```

The last command must have no production-code match. On the target host, follow
the companion rollout runbook: record the existing gate lines, take online
database backups, verify integrity and hashes, install credentials and additive
migrations, restore the exact gate values, then run read-only signed-status,
stale-precondition, address-list-equality, audit-chain, readiness, context
cursor, and ETag checks.

An apply/verify/rollback lifecycle remains separately authorized work. Do not
perform it unless an operator explicitly selects the test asset and the gates
were already enabled before the rollout.
