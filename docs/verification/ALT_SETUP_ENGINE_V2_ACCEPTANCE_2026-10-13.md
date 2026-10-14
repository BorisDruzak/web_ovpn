# ALT Setup Engine V2 acceptance ledger — 2026-10-13

Approved baseline: `3935bad3ab728c886f8f7dca2f93e5baa3ed16f9`.
Scope: component catalog, independent lifecycle, durable jobs, verification,
operator CLI and reusable backend contracts.

This ledger records implementation checks and subsequent controller and disposable
VM evidence. Exact-SHA publication receipts remain in Git/GitHub metadata.
Completed controller deployment and incomplete workstation acceptance are separate.

## Gates and evidence

| Gate | Current evidence |
| --- | --- |
| Catalog/read-only planning | Targeted POSIX tests cover thirteen components, profiles, invalid catalogs and target/source/identity drift. |
| Durable execution | Synthetic claims/crash/FIFO/conflicts/restart/PID reuse and real localhost Ansible callback tests. |
| Package interruption | Targeted tests and native ALT unprivileged APT simulation. One partial live full-Setup installation has run; live interruption/recovery acceptance remains pending. |
| Deep verification | Targeted system/domain/certificate/user/component tests; reboot/home/functional states remain separate. |
| CLI/continuity/backup compatibility | Final isolated snapshot: 143 passing operator/jobs/continuity/native recovery/restore/collector checks; two additional missing-directory corruption cases pass. Earlier broader 241 and 32 checks overlap and are not a combined unique total. |
| Integrated synthetic flow | Full Setup -> reboot -> first-login -> independent component -> child worker termination -> UNKNOWN -> fresh noop successor passes. No live AD/SSH/Ansible call in this fixture. |
| Independent review | One whole-change review satisfied after fixing physical DMI lookup, exact reserved recovery snapshot admission, successor-lineage and reservation bindings. |
| Complete regression | Production revision `ecaeffb9bd1770227c705b195acc4fd407c8d7b4`: 5684 passed, 90 skipped, 3315 warnings in 1471.14s, exit 0 ([run 38545045725](https://github.com/BorisDruzak/web_ovpn/actions/runs/38545045725)). CI uses controller-compatible Ansible 2.18.6. |
| Controller-native pre-install checks | Native guarded installer at the same production revision: 3084 passed, 1 skipped in 991.98s. |
| Exact-SHA main publication | Production revision `ecaeffb9bd1770227c705b195acc4fd407c8d7b4`, including shortcuts/GPO corrections and limited maintenance review, is published on main. |
| Controller deployment | Authorized guarded deployment of the same production revision completed: installer exit 0, 259/259 installed files matched, protected inputs and original history unchanged, rollout complete, worker active/enabled, scoped readiness passed. Ordinary target admission retains UNKNOWN gates. |
| Live Setup/component/noop/interruption/reboot/login | The approved full-Setup attempt remains immutable UNKNOWN. Authorized reboot and independent domain/software verification now pass. Independent component planning still rejects this failed protected predecessor; component/noop/interruption and real first-login acceptance remain pending. |

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

The fresh domain-component probe also exposed a separate status-contract error.
The installed `gpupdate-0.16.1-alt1` reports `enabled` for `gpupdate-setup status`,
`samba` for `active-backend`, and `workstation` for `active-policy`. The collector
incorrectly required `workstation` for both status and policy. The
[ALT Domain administrator guide](https://docs.altlinux.org/ru-RU/alt-domain/11.1/html-single/alt-domain/index.html)
defines status and active-policy as separate read-only operations.

The probe correction changes only the expected status to `enabled`. It retains
Samba trust, active SSSD, backend/policy, successful service result/exit and a
recorded service start as mandatory evidence. Synthetic enabled/disabled/wrong
status and absent/failed service-start cases produced two expected failures
before the correction; all 11 probe-script tests then passed under root in 0.80s.
The actual VM still lacks a recorded `gpupdate.service` start; correcting the
enum alone cannot establish GPO compliance. No GPO execution or reboot was
performed during this investigation.

Full CI of `440bebf57623fc2874c664a93948f6ddeba56c0a` completed with
5653 passed, 89 skipped and one failed static asset assertion in 1491.58s
([run 38536710602](https://github.com/BorisDruzak/web_ovpn/actions/runs/38536710602)).
The old assertion required the undefined bare variable. Its expected published
contract was corrected to the validated catalog reference; production files were
unchanged by that test correction. This failed CI is not publication acceptance.

The corrected exact SHA `3a6bf545be313f80c64c14205d3218dcfa098be4`
passed full CI with **5654 passed, 89 skipped, 3315 warnings in 1476.12s**
([run 38540693531](https://github.com/BorisDruzak/web_ovpn/actions/runs/38540693531));
the retained pytest exit code is 0. It was fast-forwarded and pushed to main.
This source publication does not update the controller or resolve live UNKNOWN.

## Limited controller maintenance review

The operator approved development of the written limited maintenance-review
scope. One canonical native-backup validator produces service-owned protected
30-minute plans and additive SHA-confirmed six-hour receipts. It checks one
finished full-Setup UNKNOWN, its exact two nested leases, immutable original
history, real lifecycle lock and fresh read-only machine/AD/SSH/package/user
evidence. It performs no target write or original-history reclassification.

Focused root testing first failed on missing implementation and explicit
backup/readiness/installer support. The canonical/CLI/readiness/backup subset
passed 71 tests in 35.60s before shared packaging. Native sandbox capture,
verify, rehearsal and restore preserved UNKNOWN and review metadata; default
maintenance remained blocked. Independent review found installed service-user
code readability and missing safe SSS-user evidence. Shared trusted validator
packaging keeps private backup data closed; a real differing-UID process imports
the code but cannot read a root-only sentinel. Safe resolved UID/GID, home path
and realm now have negative coverage. The maintenance/backup-installer subset
passed 42 tests in 36.18s. The reviewer accepted both bounded corrections.
Expanded root regression across maintenance, native backup/history/recovery,
worker/jobs/full dispatch, readiness, backup/control installers and CLI passed
160 tests with one expected non-root-boundary skip in 118.18s. One additional
native-observer composition test passed in 1.19s with fixed read-only collectors.

Those focused tests did not establish publication, live confirmation, deployment
or VM acceptance. The subsequent live results are recorded below.

## Published maintenance deployment and post-reboot verification

Published production revision `ecaeffb9bd1770227c705b195acc4fd407c8d7b4`
passed full CI: **5684 passed, 90 skipped, 3315 warnings in 1471.14s**,
retained pytest exit 0
([run 38545045725](https://github.com/BorisDruzak/web_ovpn/actions/runs/38545045725)).
The final bounded review accepted the shared-validator packaging and resolved
SSS-user evidence corrections. Main and the GitNexus committed index matched
this revision before the live deployment.

The operator confirmed a fresh exact-SHA maintenance review and authorized native
backup creation, verification and isolated rehearsal. All six components were
captured; verification and all eleven rehearsal checks passed. A separately
authorized native deletion of one unreferenced older generation restored the
required free space. Native restore-capacity checks passed without overrides.
Protected inputs and original execution evidence remained unchanged.

The operator then authorized the guarded controller deployment, including the
backup-tool update from the same source. The native installer ran
`python3 -m pytest -q tests/alt_linux` as root: **3084 passed, 1 skipped in
991.98s**. It completed with exit 0. All 259 installed files matched the published
source, the worker was active/enabled, rollout completed and the marker was absent.
Scoped active-job count was zero and scoped readiness passed. These checks used
the explicit controller-maintenance review; ordinary target admission was not
exempted. Retained history fingerprints and protected input identities matched.
No actual controller restore or original UNKNOWN reclassification occurred.

Independent installed `setup verify` initially reported `waiting_reboot` for the
approved disposable VM. Under the operator's authorization for necessary work,
one native VM reboot was performed after confirming the existing snapshot and
absence of pending hypervisor configuration changes. There was no force, replay,
AD account reset or OS reinstall. Fresh verification then reported no remaining
reboot requirement: system/domain-GPO, browser, ONLYOFFICE and Nextcloud were
technically compliant. Directum was technically installed and still required
functional verification. Trust, SSSD and selected-user lookup passed; a local
duplicate user was absent. The real selected-user home was still absent, leaving
Plasma, government certificates and shortcuts blocked on first domain login.
The independent overall component result was `degraded`; the original failed
Setup result and its UNKNOWN job remained unchanged.

Installed component planning with `--after-job` was actually attempted and
rejected with `setup_retry_not_permitted`: this failed full predecessor lacks the
intact completed protected Setup required by the existing component retry gate.
No new component plan or target apply resulted. Maintenance evidence therefore
does not establish successful full Setup or independent component acceptance.
The maintenance receipt bound to the earlier boot snapshot also grants no fresh
admission after the authorized VM reboot.

## Functional CLI coverage audit

The existing command is `setup component accept`, and its dispatcher already
calls the canonical component acceptance service. The additional CLI regression
uses that real service with synthetic machine/user facts: a fresh compliant plan
and explicit human confirmation produce the protected receipt, while mismatched
SHA, expired plans and changed facts produce the native guard errors without a
receipt. The parser rejects a missing `--confirm-functional`. This adds coverage
to the already implemented route; no production behavior changed and no real
Directum workflow was attested. The acceptance/component/execution/jobs/Setup
native subset passed 77 tests before publication of these test/document updates.

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

The production source/deployed revision, regressions, bounded review, guarded
deployment and independent post-reboot verification are recorded above. Private
target/job identifiers, native command receipts and protected logs remain outside
tracked documentation. Full successful Setup, permitted independent component
apply/verify/noop, controlled interruption/status recovery and real first-login
user-file acceptance still need live evidence. The current failed predecessor
continues to block ordinary component retry. Unperformed document/token checks
remain functional pending; the selected office profile does not include the
signing suite or KRFB.

GitNexus final committed-baseline checks identify SetupService consumers in CLI
and recovery and JobRepository upstream impact of 28 symbols (10 direct).
Dynamic worker/lease/backup relationships were additionally verified against
source and focused tests. This change adds no cross-repository HTTP contract.
No manual group synchronization or generated manifest edits were performed.

The same independent reviewer accepted the narrow post-CI CLI sequencing fix:
legacy malformed-job errors remain compatible and V2 claim/admission checks
remain mandatory. Production ownership and recovery safeguards were not relaxed.

## Closed UNKNOWN queue correction (implementation evidence)

A new disposable target alone does not bypass the serialized worker's global
unresolved-execution guard. An admitted but unclaimed candidate was therefore
cancelled through the existing typed claim/transition APIs before target changes.
Its consumed plan/history and the original UNKNOWN and nested leases were kept.
Fresh native closure inspection still proved the original failed protected
results, both leases, current domain trust, SSSD and safe selected-user runtime.

Implementation adds SHA-confirmed queued cancellation and a separate
`queued_other_machine_only` review tied to one exact candidate. Native POSIX
regression: `python3 -m pytest -q tests/alt_linux/test_setup_queue_review.py
tests/alt_linux/test_setup_maintenance_review.py tests/alt_linux/test_setup_worker.py
tests/alt_linux/test_setup_jobs_cli.py tests/alt_linux/test_setup_backup_compatibility.py
tests/alt_linux/test_or3p3_backup_installer.py` — **100 passed, 95.65s, exit 0**.
The cancellation task also passed its 39-test native regression. The new queue
API had 19 failing baseline tests; retained candidate-reference validation had
four RED tests before the exact protected-reference checks were implemented.

These are synthetic/native implementation checks, including real differing-UID
DAC proof for the shared validator. They do not establish new controller
deployment or positive full/component acceptance on the disposable machine.
Full regression, branch review, guarded deployment and remaining real-VM
acceptance must be recorded separately when actually performed.

GitNexus identifies four upstream symbols for the committed MaintenanceReview
baseline (one direct). Its empty worker impact result was not treated as absence
of dependencies: dynamic CLI/worker/lease/backup paths were verified in source
and native tests. No cross-repository HTTP contract is changed.
The required native component-review retry chain additionally reproduced a
queue-closure compatibility failure (RED). Recognizing already validated native
review links only for queue admission fixed it: the same six-file native suite
then passed **101 tests in 97.29s, exit 0**. Maintenance-only checks and the
original UNKNOWN/reservation records remain unchanged.
