# Netctl correlated-context readiness

Verified against published release `440dbcb` on 2026-07-22. This record is
sanitized: it intentionally contains no IP, MAC, credential, or topology dump.

## Deployment evidence

- The deployed netctl migration ledger is `1..13`.
- The online SQLite backup is
  `/var/lib/netctl/backups/correlated-control-plane-20260722T193000Z/netctl-before.sqlite`.
  Its SHA-256 is `9de1061095a028021ffaf8521e7927f45881b08951c2bc6bef73be50d0a14f63`;
  `PRAGMA integrity_check` returned `ok`.
- The post-deploy collector completed successfully, followed by topology and
  attachment reconciliation. Both `netctl-collect.timer` and
  `netctl-reconcile.timer` are active.
- The aggregate context held 1,033 runtime assets. The latest attachment run
  reported 2 confirmed, 146 ambiguous, and 98 unresolved resolutions. Zero
  switch links were inferred because no eligible backbone evidence was present;
  this is a conservative result, not an invented topology.

## Sanitized acceptance example

`attachment-reconcile-run-4` completed successfully and retained ambiguity
rather than selecting an arbitrary switch port. This validates the fail-closed
attachment contract without exposing an endpoint identity.

## Rollback evidence

The pre-migration backup above is the rollback artifact. Restoring it requires
the sequence in `docs/runbooks/netctl-correlation-rollout.md`; migration-ledger
rows must never be deleted manually.
