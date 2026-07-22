# ALT OR-3P3 Final Verification Evidence

**Date:** 2026-07-22  
**Repository:** `BorisDruzak/web_ovpn`  
**Branch:** `feat/alt-or3p3-completion-20260722`  
**Pull request:** `#24` (draft; merge prohibited without explicit user confirmation)  
**Clean implementation head:** `50bfbfd74bbaaf2d80258d6edde9b37244418cf5`

## Scope

This evidence covers the repository implementation of coordinated same-controller backup, byte-bound verification, isolated restore rehearsal, full six-component restore, durable rollback/recovery, the backup-tool installer, the OR-3P4 rollback-ID gate, the fail-closed service guard, and the allowlisted static service.

It does not claim completion of the live operational gate on controller `192.168.100.17`.

## Safety boundary

- Repository development and CI did not contact or mutate controller `192.168.100.17`.
- Repository development and CI did not contact or mutate accepted workstation `192.168.101.111`.
- CI did not read production Vault, Vault-password, SSH-private-key, job, registration, assignment or backup-archive contents.
- Synthetic tests use isolated filesystem roots, fake commands and loopback-only HTTP probes.
- No real restore and no OR-3P4 live rollout were executed.

## Final acceptance matrix

| Gate | Evidence | Result |
| --- | --- | --- |
| Focused OR-3P3 | GitHub Actions run `29943063330`, job `final-or3p3-gate` | `152 passed` |
| Complete ALT Linux suite | GitHub Actions run `29943063330`, job `final-or3p3-gate` | `550 passed` |
| Python compilation | run `29943063330` | exit `0` |
| Bash syntax | run `29943063330` | exit `0` |
| systemd verification | run `29943063330` | all five managed/guard units accepted |
| Ansible syntax | run `29943063330` | both playbooks accepted with synthetic non-secret Vault inputs |
| Diff/clean-tree hygiene | run `29943063330` | exit `0` |
| Clean-head runtime checks | run `29943995304` | focused job and full regression passed |
| Clean-head context checks | run `29943996025` | context-stage job and independent full regression passed |
| Complete clean-head repository suite | runtime artifact from run `29943995304` | `1510 passed, 2 skipped, 258 warnings`; exit code `0` |

The 258 clean-head warnings are existing FastAPI `on_event` and Starlette `TemplateResponse` deprecation warnings. The increase from the earlier final-gate count reflects additional repository tests present in the current PR merge ref; no OR-3P3 failure was introduced.

## Implemented behavior gates

The verified implementation enforces:

- exactly six coordinated backup/restore components and no selective restore option;
- current-byte verification plus rehearsal evidence bound to the exact verification record;
- no archive of Vault, Vault-password or SSH-private-key contents;
- operation and lifecycle locking across critical create/restore sections;
- same-filesystem staging and a complete protected pre-restore generation;
- durable `prepared -> staged -> services_stopped -> originals_moving -> originals_moved -> installed -> daemon_reloaded -> health_checked -> committed` progression;
- terminal `aborted`, `rolled_back` and `manual_recovery_required` handling;
- explicit idempotent `recover <restore-id>`;
- per-filesystem capacity checks before journal creation or service stop;
- bounded secret-free command audit;
- persistent failed-rollout marker and ephemeral exact rollout/restore permits;
- `alt-deploy-guard.service` before all four provisioning units;
- independent backup-tool installation and preservation of bundles, state, log and fingerprint key;
- exact `--rollback-backup-id` parsing and one read-only `rehearse-status` eligibility call before installer mutation;
- allowlisted unprivileged static delivery limited to `/bootstrap/*`, `/metadata/*` and `/health`;
- no directory listing, registration publication, traversal, symlink following, FIFO or special-file serving.

## Development and review evidence

Major verified implementation commits include:

- `feb10ee0ac059c9608656327a18da2a65e633a62` — guarded restore/rollout state;
- `4885a8c5c9ef34dc3283a6c4cf17e91121b63f42` — backup installer and mandatory rollback gate;
- `6768b8a865f789b0344932f7887c9bc9c3b16e24` — destination hardening and allowlisted static service;
- `9d36482146c7e33b5cb17571087e581bcbac12e9` — synchronized Task 13 documentation/cleanup tree;
- `25c92a317379b3d9cf9cc1e611e9df2c4af85d5a` — complete operator runbook.

The final whole-branch review found no unresolved PR review thread and no Critical or Important finding after the installer, restore, guard and static-service hardening series. Temporary patch, export, verification and locator workflows/files are absent from the clean PR diff, and the standard runtime workflow is byte-identical to its original repository version.

## Operational gate still pending

Repository verification does not authorize a live rollout by itself. After review, merge approval and installation on `192.168.100.17`, the operator must run:

```bash
sudo bash deploy/alt-linux/install-backup-tool.sh
sudo alt-deploy-backup create
sudo alt-deploy-backup verify <backup-id>
sudo alt-deploy-backup rehearse <backup-id>
sudo bash deploy/alt-linux/install-control-plane.sh \
  --rollback-backup-id <the-same-backup-id>
```

The exact successful ID must be retained explicitly. The installer never selects the newest backup. A real restore remains reserved for an unsuccessful guarded rollout or an explicitly approved recovery exercise.
