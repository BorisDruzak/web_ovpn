# Current model stabilization rollout

This runbook deploys S1–S3 of the current-model stabilization design. It does
not authorize a RouterOS write and does not change either production write gate.

## Preconditions

- The release commit passed focused suites, `pytest -q`, `compileall`,
  `git diff --check`, and the secret-pattern scan.
- `/etc/netopsctl/netopsctl.env` contains both existing gate settings:
  `NETOPSCTL_PRODUCTION_WRITES_ENABLED` and
  `NETOPSCTL_AUDIT_CHECKPOINT_HEALTHY`.
- The four root-owned, regular, non-symlink credential sources exist:
  `/etc/netopsctl/credentials/netopsctl_audit_signing_ed25519.raw`,
  `/etc/netopsctl/credentials/netopsctl_reconcile_signing_ed25519.raw`, and
  `/etc/openvpn-web/credentials/netops_web_signing_ed25519.raw`, plus the
  32-byte-or-longer HMAC key
  `/etc/openvpn-web/credentials/context_api_cursor_signing.raw`.

## Atomic update

1. Record the application commit and copy the two gate lines verbatim into the
   change record. Never replace either line with a literal value.
2. Make online SQLite backups of `/var/lib/netctl/netctl.sqlite` and
   `/var/lib/netopsctl/netopsctl.sqlite`, then run `PRAGMA integrity_check` and
   SHA-256 on each backup as its database owner.
3. Record current desired-policy rows and managed address-list entries with
   read-only broker/RouterOS checks.
4. Stop `netopsctl-reconcile.timer` only if it is currently active, then stop
   `netopsctl.socket` and `netopsctl.service`. Existing managed RouterOS
   entries remain active while the broker is unavailable.
5. Install the application tree, unit files, and additive migrations. Install
   systemd credential sources with root ownership and mode `0600`; do not put
   a private-key path in either environment file.
6. Run `systemctl daemon-reload`, restore the exact captured gate lines, and
   start `netopsctl.socket` and `netopsctl.service`.
7. Re-enable `netopsctl-reconcile.timer` only when it was enabled before the
   update and its dedicated credential verifies. Never enable it as a side
   effect of this rollout.

## Post-update checks

1. Verify both migration ledgers and live `PRAGMA integrity_check` results.
2. Send a signed `status` request through `openvpn-web` and verify the returned
   `writes_enabled` value equals the pre-update operator-selected state.
3. Create a dry-run context change and force a stale snapshot/basis condition;
   verify `stale_precondition`, `replan_required=true`, and zero adapter calls.
4. Compare desired-policy and managed address-list snapshots from before and
   after the update. They must be equal.
5. Verify the audit chain, checkpoint delivery, source readiness output,
   bounded topology response, and cursor/ETag contracts.

## Controlled lifecycle

Run one plan/apply/verify/rollback only after an operator explicitly approves
the selected test asset and the gates were already enabled before deployment.
If either gate was disabled before deployment, do not enable it for this
runbook; record the skipped lifecycle check instead.

## Rollback

1. Stop the broker socket/service and the timer only if it was enabled before
   the failed rollout.
2. Restore the matching application tree and the two online SQLite backups.
3. Restore the captured gate lines verbatim and start the socket/service.
4. Verify migration ledgers, database integrity, signed status, desired-policy
   equality, managed address-list equality, and audit-chain validity.

Do not delete migration records manually and do not use rollback to alter a
RouterOS policy, address-list entry, or production-write gate.
