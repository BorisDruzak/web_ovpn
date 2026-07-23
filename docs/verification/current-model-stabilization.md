# Current-model stabilization verification record

## Scope and status

This record covers the S1--S3 implementation described by the current-model
stabilization plan and its completed sanitized rollout. It does not authorize
RouterOS changes.

Implemented locally:

- WAL-safe, read-only context snapshots and fail-closed policy preflight.
- Audit records containing actual accepted Unix peer credentials, and private
  signing material delivered through named systemd credentials.
- Authoritative partial-FDB handling, preserved correlation state on failures,
  per-interface attachments, owner context, readiness reasons, and redacted
  backbone-evidence summaries.
- Additive v1 context envelopes with snapshot metadata, signed search cursors,
  bounded topology responses, and ETags.

## Sanitized deployment record

On 2026-07-22, release `2b08dae` was deployed through the companion rollout
runbook. The release was verified with the following sanitized evidence:

- Online SQLite backups were created and passed integrity and hash checks.
- The broker socket/service and the web service returned to active state.
- A signed status request, audit-chain verification, and independent audit
  checkpoint verification succeeded.
- The production-write gate remained disabled; the audit-checkpoint health
  gate was preserved. No RouterOS policy or address-list mutation was made as
  part of this rollout.

Later commits require their own rollout record; this entry must not be used as
evidence that they are deployed.

Not asserted by this record:

- That every network source has complete, current topology evidence.

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
