# ALT Setup Engine V2 acceptance ledger — 2026-10-13

Approved baseline: `3935bad3ab728c886f8f7dca2f93e5baa3ed16f9`.
Scope: component catalog, independent lifecycle, durable jobs, verification,
operator CLI and reusable backend contracts.

## Gates and evidence

| Gate | Current evidence |
| --- | --- |
| Catalog/read-only planning | Targeted POSIX tests cover thirteen components, profiles, invalid catalogs and target/source/identity drift. |
| Durable execution | Synthetic claims/crash/FIFO/conflicts/restart/PID reuse and real localhost Ansible callback tests. |
| Package interruption | Targeted tests and native ALT unprivileged APT simulation; no live installation. |
| Deep verification | Targeted system/domain/certificate/user/component tests; reboot/home/functional states remain separate. |
| CLI/continuity/backup compatibility | Final isolated snapshot: 143 passing operator/jobs/continuity/native recovery/restore/collector checks; two additional missing-directory corruption cases pass. Earlier broader 241 and 32 checks overlap and are not a combined unique total. |
| Integrated synthetic flow | Full Setup -> reboot -> first-login -> independent component -> child worker termination -> UNKNOWN -> fresh noop successor passes. No live AD/SSH/Ansible call in this fixture. |
| Independent review | One whole-change review satisfied after fixing physical DMI lookup, exact reserved recovery snapshot admission, successor-lineage and reservation bindings. |
| Complete regression | First V2 full Linux CI at `2babea4b45ef1d5e87a7f19480b9698319def324`: 5590 passed, 47 failed, 89 skipped, exit 1. Legacy error sequencing and outdated recovery/readiness/UID fixtures corrected; 94 focused checks pass. CI now explicitly installs controller-compatible Ansible 2.18.6 instead of relying on the hosted runner's pipx runtime. Final exact-SHA full CI remains pending. Earlier baseline CI is not V2 proof. |
| Exact-SHA main publication | Pending final regression, review and exact-SHA CI. |
| Controller deployment | Not performed; separate guarded deployment approval required. |
| Live Setup/component/noop/interruption/reboot/login | Not performed; separately confirmed exact plans required. |

Milestones through Task 9 include 341 passing package/worker/resilience checks
and 228 passing verification/role checks. These overlap and are not a unique
combined test total. Linux tests use an isolated directory/venv, outside the
deployed controller. Real Ansible uses synthetic localhost/AD fixtures; it does
not establish live domain acceptance.

## Native ALT preparation

A pre-test disk snapshot of the authorized disposable VM was created. Its SSH
ED25519 fingerprint was verified independently through the hypervisor guest
agent before public-key trust was added. The operator selected an existing AD
employee. No AD employee was created or changed. Addresses, passwords and
personal identities are omitted from this tracked report.

ALT APT 0.5.15lorg2 read-only probes ran as an existing unprivileged account with
empty supplementary groups, `--simulate --no-download` and `Debug::NoLocking`.
Dependency check returned zero; Nextcloud simulation reported two installs and
zero removals. Cache metadata stayed unchanged. An earlier ordinary root
simulation rebuilt cache metadata, so the collector now drops privileges.
No package installation, domain join, bootstrap, reboot or deployment occurred.

## Design rulings

- One published catalog drives artifacts, role selection, profile closure and order.
- Serialized mutation preserves legacy lifecycle contracts; reads avoid that lock.
- Immutable claims and review links prevent replay. UNKNOWN remains historical.
- V2 adapters correlate existing protected Setup/recovery gates and safe events;
  they do not add a domain/account reset path.
- Human functional attestation is separate from technical package checks.
- Backup/restore stops the worker and gates admission outside restored state.
  It cannot erase/alter retained execution or acceptance history. V1 four-unit
  manifests remain supported.
- No UI/API transport, new DB/broker, AD employee changes, OS reinstall, network
  configuration change or fleet rollout is included.

## Evidence still required

Record final source/main and deployed SHAs, full regression command/count/skips,
whole-change review findings, guarded deployment backup/rollback/readiness and
actual workstation commands/job IDs. Prove full Setup, independent component,
verify/noop, interruption/status recovery, changed reboot boot ID and real first
login separately. Keep unperformed document/token checks as functional pending.

GitNexus final committed-baseline checks identify SetupService consumers in CLI
and recovery and JobRepository upstream impact of 28 symbols (10 direct).
Dynamic worker/lease/backup relationships were additionally verified against
source and focused tests. This change adds no cross-repository HTTP contract.
No manual group synchronization or generated manifest edits were performed.

The same independent reviewer accepted the narrow post-CI CLI sequencing fix:
legacy malformed-job errors remain compatible and V2 claim/admission checks
remain mandatory. Production ownership and recovery safeguards were not relaxed.
