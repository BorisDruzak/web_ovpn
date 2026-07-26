# Device network card rollout verification — 2026-07-26

## Scope

Local `main` was merged and deployed to the OpenVPN web host with explicit
deployment authorization. The change provides the device network card,
post-collection topology/attachment reconciliation, and 30-day Netctl history
retention. No network-device configuration was modified.

## Preflight and recovery point

- The Netctl SQLite database passed `PRAGMA integrity_check`.
- A SQLite online backup was created under `/var/backups/netctl` before
  installation; its integrity check passed and its SHA-256 was recorded on the
  host.
- The deployment host had sufficient free space for the backup and normal
  operation.

## Local verification

- Merged-tree test suite: `python -m pytest -q --ignore=worktrees` —
  `1007 passed, 5 skipped`.
- Systemd deployment-unit suite after the production-systemd calendar fix:
  `14 passed`.
- `git diff --check` passed.

## Production verification

- The Linux/systemd verifier passed for the collection, reconciliation and
  retention units before the timers were enabled.
- `openvpn-web.service` is active; collection, reconciliation and retention
  timers are active and enabled.
- A manual `netctl --json collect all --reconcile` completed successfully for
  all configured sources. One existing switch source remains `partial`, while
  still returning FDB data; this is recorded as source health rather than being
  represented as a confirmed attachment.
- Retention dry-run for the 30-day cutoff completed with no deletions and kept
  all current and last-successful protected run references.
- A confirmed device context returned switch, port, freshness, topology-path
  and bounded peer information. A separate ambiguous device context returned
  alternatives and did not claim a selected port.

No manual `VACUUM` was run. The scheduled retention service performs cleanup
only; compaction remains the backup-first operator procedure in
`docs/runbooks/netctl-retention-compact.md`.
