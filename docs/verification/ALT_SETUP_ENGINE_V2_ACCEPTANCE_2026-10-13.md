# ALT Setup Engine V2 acceptance ledger — 2026-10-13

Approved baseline: `3935bad3ab728c886f8f7dca2f93e5baa3ed16f9`.
Scope: component catalog, independent lifecycle, durable jobs, verification,
operator CLI and reusable backend contracts.

This ledger records the pre-publication acceptance checkpoint. Subsequent
exact-SHA publication evidence is the Git commit and GitHub workflow metadata;
controller and workstation acceptance still require the separate live gates.

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
| Complete regression | Full Linux CI at `6c999dfe4a2da19ad342034c83ff0ef199300933`: 5645 passed, 89 skipped, 3315 warnings in 933.80s, exit 0 ([run 38485906695](https://github.com/BorisDruzak/web_ovpn/actions/runs/38485906695)). CI explicitly installs controller-compatible Ansible 2.18.6. This is implementation regression evidence; the final pre-install fixture correction requires its own exact-SHA publication CI. |
| Controller-native pre-install checks | Isolated full ALT subset: 2962 passed, 82 skipped, one host-dependent unit-fixture failure in 930.89s. The cache metadata fixture was corrected; both affected test files then passed all 39 checks in 24.57s. Installed production sources were unchanged. |
| Exact-SHA main publication | Requires successful final fixture-revision CI, clean tree and normal main fast-forward. Actual publication receipt is recorded in Git/GitHub metadata. |
| Controller deployment | Guarded deployment of approved `a50db1bb24fd59342afec16d1c8e1881677d7c6e` completed: native root regression 3044 passed, 1 skipped in 945.58s, installer exit 0, all 246 published installed files matched, protected identities unchanged, rollout complete, worker active/enabled, controller ready, no active jobs. The subsequent filter-discovery correction still requires its own exact-SHA CI and deployment approval. |
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
This early preparation performed no package installation, domain join, bootstrap,
reboot or deployment.

Subsequent operator-authorized VM preparation ran the unchanged published
bootstrap after validating its exact hash and controller public-key fingerprint.
Registration and preflight succeeded; strict controller SSH and passwordless sudo
were verified. The VM remains unjoined, with SSSD inactive and no selected-employee
home. Bootstrap dependency installation is VM preparation, not Setup acceptance.

The real read-only collector confirmed physical DMI UUID and returned observations
for all thirteen components; missing domain helpers and home remained unready or
unknown. An existing root-owned APT cache directory with mode `02770` blocked the
protected-cache gate. Authorized VM preparation changed only that directory to
`02755`, preserving owner/group/setgid; no collector safeguard was relaxed.
Native APT health then passed, with cache metadata unchanged during probes.

The same native check exposed a source-validator defect: standard p11 x86_64
`classic gostcrypto` was incorrectly unknown. A focused RED case reproduced it;
the bounded parser fix passes 63 collector/planning/retry/CLI checks, including
negative extra-component cases. The same independent reviewer accepted the fix.
Actual VM probe now reports `approved_p11`, all package-health predicates true,
and a Nextcloud simulation of two installs and zero removals. It does not install
Nextcloud or demonstrate installed V2 CLI/live Setup acceptance. The source-guard
correction subsequently passed the full Linux CI cited above.

The standard source form is documented in the
[official ALT 11.1 manual](https://docs.altlinux.org/ru-RU/alt-server/11.1/pdf/alt-server/alt-server-11.1-alt-server-ru-RU.pdf)
and the [official p11 component registry](https://packages.altlinux.org/ru/p11/about/).

An isolated source archive was also tested using the controller's native Python
3.12.7, pytest 8.3.5, PyYAML 6.0.1, cryptography 42.0.5 and Ansible 2.18.6.
The initial real-Ansible fixture could import the old installed runtime because
its temporary playbook tree lacked the adjacent controller source directory.
Matching the checkout layout corrected that fixture; all ten checks passed.
The full native ALT subset then exposed one unit fixture that mocked APT but
still read the host's cache permissions. Supplying synthetic protected metadata
fixed that dependency; 39 focused tests passed. Neither correction changes the
production filter or collector, and these tests do not constitute deployment.

Operator-authorized storage cleanup removed idle rehearsal/pytest trees,
reproducible caches, six unreferenced old backup generations and one verified
duplicate RPM. Retained histories, credentials, runtime artifacts and all October
backups were preserved. Native backup and retained-restore capacity checks passed;
the operator explicitly accepted the remaining root headroom for guarded deployment.
The independent backup tool was updated, a fresh coordinated generation was
created, verified and rehearsed, and protected input identities stayed unchanged.

The installer then ran the full ALT subset as root: 3043 passed, one skipped,
one failed in 950.69s. Its shortcuts fixture reported a positive synthetic SSS
UID/GID while its home, files and symlinks remained root-owned. The collector
correctly rejected that ownership mismatch. Only the fixture now assigns its
declared synthetic ownership inside its temporary home; all seven collector
tests pass under root in 0.58s. Production checks are unchanged. No rollout marker
was created and the V2 worker was not installed by the rejected attempt.

The corrected fixture revision `a50db1bb24fd59342afec16d1c8e1881677d7c6e`
passed full CI: 5645 passed, 89 skipped, 3315 warnings in 1503.19s, exit 0
([run 38513142725, attempt 2](https://github.com/BorisDruzak/web_ovpn/actions/runs/38513142725)).
Attempt 1 reached the existing 30-minute job limit; only that job was rerun once.
It was published to main and separately approved for the successful guarded
controller deployment above.

The first installed read-only Setup plan then stopped at component preflight:
Ansible could not discover `alt_setup_selection` from an unrelated operator
directory. The earlier synthetic runtime fixture supplied its plugin path in
the environment, masking the missing published config setting. The config now
declares its relative filter directory. A real Ansible regression removes that
environment override, uses the published config without a real Vault credential
path and launches the fixed localhost preflight from a different directory.
It failed at filter discovery before the correction, then all 11 runtime tests
passed under root in 23.52s. Active controller source and the VM were not patched
by this isolated source test. At that filter-discovery gate, the operator selected
`office-standard-v1`; Setup/component apply and reboot had not yet been performed.

## Approved disposable-VM apply: incomplete acceptance

Controller revision `76b5d1334e17d43eec2b65c8582010c9d851892d` completed
the native guarded deployment regression: 3045 passed, 1 skipped in 948.81s.
All 246 installed public files matched the published revision, protected secret
identities matched the fresh verified and rehearsed rollback bundle, and worker,
rollout completion and controller readiness checks passed.

After rechecking the VM snapshot, the operator approved a fresh protected
`office-standard-v1` plan. Native `setup apply --confirm-sha256 ... --detach`
admitted one job before its TTL expired. The worker continued after CLI/SSH exit.
System upgrade, first domain join and the selected application roles ran. The
configure result recorded verified browser, ONLYOFFICE, Nextcloud and Directum
packages. This does not establish independent or functional acceptance.

The run stopped at the full Setup inclusion of `desktop_shortcuts`. The task
referenced a bare `execution_components` variable, while published preflight
creates that list inside `setup_selected_catalog`. The native callback identifies
this failing task and the subsequent rescue failure without exposing task output.
A real localhost Ansible reproduction using the published preflight and inclusion
task failed for all four profiles with `execution_components is undefined`.
The correction references `setup_selected_catalog.execution_components`; the
baseline runtime file passed 11 tests, and the corrected file passed 15 tests
under root in 27.16s. The test role is synthetic and never contacts the VM.

The actual job remains immutable `unknown_requires_review`. Fresh native
read-only verification confirms machine identity, Samba trust, active SSSD,
selected-user resolution and one computer object. Full verification still reports
failure; the domain component is drifted and dependent components are blocked.
Reboot is required and the real user home is absent. No reboot, real first login,
automatic replay, account reset, history repair or successful live acceptance is
claimed. Target/job identifiers remain in ignored local operational receipts.

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
