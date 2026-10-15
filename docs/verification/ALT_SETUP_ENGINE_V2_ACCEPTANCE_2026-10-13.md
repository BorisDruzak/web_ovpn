# ALT Setup Engine V2 acceptance ledger — 2026-10-13

Approved baseline: `3935bad3ab728c886f8f7dca2f93e5baa3ed16f9`.
Scope: component catalog, independent lifecycle, durable jobs, verification,
operator CLI and reusable backend contracts.

This ledger records implementation checks and subsequent controller and disposable
VM evidence. Exact-SHA publication receipts remain in Git/GitHub metadata.
Controller deployment, technical workstation acceptance and user workflow
attestation are separate. The table summarizes the latest evidence; the dated
entries below retain earlier failures and gates as history.

## Gates and evidence

| Gate | Current evidence |
| --- | --- |
| Catalog/read-only planning | Targeted POSIX tests cover thirteen components, profiles, invalid catalogs and target/source/identity drift. |
| Durable execution | Synthetic claims/crash/FIFO/conflicts/restart/PID reuse and real localhost Ansible callback tests. |
| Package interruption | Targeted package-transaction interruption tests and native ALT unprivileged APT simulation pass. Live interruption uses a file-only component; no live mid-APT interruption is claimed. |
| Deep verification | Targeted system/domain/certificate/user/component tests; reboot/home/functional states remain separate. |
| CLI/continuity/backup compatibility | Final isolated snapshot: 143 passing operator/jobs/continuity/native recovery/restore/collector checks; two additional missing-directory corruption cases pass. Earlier broader 241 and 32 checks overlap and are not a combined unique total. |
| Integrated synthetic flow | Full Setup -> reboot -> first-login -> independent component -> child worker termination -> UNKNOWN -> fresh noop successor passes. No live AD/SSH/Ansible call in this fixture. |
| Independent review | One whole-change review satisfied after fixing physical DMI lookup, exact reserved recovery snapshot admission, successor-lineage and reservation bindings. |
| Complete regression | Runtime revision `314cce46ab8c4f7dbe62b6066791994e25e1f98b`: 5733 passed, 90 skipped, 3315 warnings in 1746.06s, retained exit 0 ([run 38599420531](https://github.com/BorisDruzak/web_ovpn/actions/runs/38599420531)). CI uses controller-compatible Ansible 2.18.6. |
| Controller-native pre-install checks | Stock guarded installer at the same runtime revision: 3133 passed, 1 skipped in 1032.20s. |
| Exact-SHA main publication | Runtime revision `314cce46ab8c4f7dbe62b6066791994e25e1f98b`, including atomic one-candidate queue review, is published on main. This final evidence update changes documentation only. |
| Controller deployment | Authorized guarded deployment completed: installer exit 0, 261/261 installed files matched, protected inputs and original history unchanged, rollout complete, worker active/enabled, scoped readiness passed. The fresh backup verified and rehearsed 11/11 checks. Ordinary UNKNOWN gates remain. |
| Live Setup/component/noop/interruption/reboot/login | New disposable target: full Setup, authorized reboot, real login, shortcuts repair, independent ONLYOFFICE install/verify/noop, file-only interruption/reconciliation and freshly confirmed noop successor pass. Final native whole-machine verification is successful: all nine selected components compliant. The original failed protected attempt and interrupted component remain immutable UNKNOWN. |

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

Whole-branch review found a publication atomicity defect: confirming a different
review for the same candidate, or interruption between receipt and pointer,
could leave an orphan that blocked ledger validation. Both cases reproduced
as **2 failed** on the reviewed source. Confirmation now atomically publishes
one candidate-keyed receipt. Exact retries preserve its lifetime, conflicting
confirmations write nothing, and protected partial staging bytes grant no
authority. The six-file native regression including before/after publication
interruption and unsafe staging checks passed **110 tests in 112.25s, exit 0**.
Actual disposable-target execution and full repository regression remain
separate gates; this result does not claim installed or live acceptance.

## Final technical acceptance — 2026-10-15

The authorized second disposable ALT workstation completed the selected
`office-standard-v1` flow on installed runtime
`314cce46ab8c4f7dbe62b6066791994e25e1f98b`. Native CLI now independently verifies
all nine selected components as compliant, with no reboot pending. Eight have
`technical_verified`; Directum has `installed_verified` and correctly retains
`functional_verification_required`. No document-opening attestation was invented.
Private root receipts retain the exact target UUID, selected AD identities,
plans, SHA confirmations, command outputs and timestamps. This public report
omits private topology and employee identities.

### Installed release and actual operations

The stock guarded controller deployment completed once after a fresh confirmed
maintenance review and backup create/verify/rehearse. Rehearsal passed 11/11
checks. Installer ALT regression passed **3133 tests, 1 skipped, 1032.20s**.
Deployment and final live audit both matched **261 installed files** to the
published runtime. Worker remains active/enabled. Original protected inputs and
failed full-Setup history were not rewritten. Readiness passed within the
authorized maintenance scope at deployment time; ordinary UNKNOWN guards remain.

| Actual durable job | Operation | Observed outcome |
| --- | --- | --- |
| `job-20261014T174057Z-19e93d26` | Full office Setup | 518 structured events; waiting_reboot, one authorized actual reboot, waiting_first_login, real login, then degraded for launcher mode drift. This historical result remains unchanged after component repair. |
| `job-20261014T211114Z-626b213f` | `desktop.shortcuts` repair | successful, changed=true, independently compliant |
| `job-20261014T211448Z-0cb1ded8` | `software.onlyoffice` install | successful, changed=true; 74 structured events and separate native verify successful |
| `job-20261014T212018Z-23ff6c14` | Fresh ONLYOFFICE repeat | noop, successful, changed=false, no Ansible log or events |
| `job-20261014T212351Z-a9f69b61` | Controlled file-only interruption | Worker stopped after a changed apply event; restart reconciled to unknown_requires_review/worker_identity_unverified, without replay |
| `job-20261014T212744Z-3eed57d5` | Fresh same-component `--after-job` successor | Current facts compliant; noop, successful, changed=false; original UNKNOWN request/status unchanged |

Independent software installation used an explicit disposable fixture: RPM's
removal dependency test passed, and complete before/after package identities
proved that only ONLYOFFICE was removed. Its newly confirmed native plan then
reported missing/install. For interruption, only one existing selected-user
launcher mode changed; bytes and ownership remained unchanged. No live package
transaction or domain operation was killed. The stopped service MainPID matched
the claimed worker identity before interruption.

Every component submission used the installed native CLI and background worker,
not a direct Ansible invocation. Each queued candidate received its own fresh
closed-UNKNOWN queue review. One retry queue-plan request was rejected;
subsequent read-only ledger, predecessor, candidate, history and
lock checks passed, and a fresh request for that same candidate succeeded. The
initial cause was not reproduced or declared fixed. Its failed response remains
retained. No consumed Setup plan or claim was replayed.

Final native audit passed catalog/profile list/show, target job history, whole
machine verification and independent ONLYOFFICE verification. Both UNKNOWN
histories remain intact, the interrupted component has a native validated
successor link, and the retained ledger validates after consumption/expiration.
Component source fingerprints were unchanged; component jobs dispatched no
protected domain adapter. No AD employee creation/change, computer reset, OS
reinstallation, production-network change or fleet rollout was performed.

### Delivered contracts and operator use

The versioned YAML catalog, immutable component plans, single-use claims/FIFO
worker, structured Ansible events, independent probes and read-only continuation
form the shared `CLI -> service -> plan -> durable job -> catalog -> Ansible ->
verification` path. `base` and `core-apps` retain legacy meanings. Published
profiles add `office-standard-v1` and `office-signature-v1`.

Integrated executors are `workstation_base`, `plasma_baseline`,
`software_browser`, `software_onlyoffice`, `software_nextcloud_desktop`,
`software_directum`, `software_cryptopro`, `software_cryptopro_cades`,
`software_gosuslugi_plugin`, `government_ca`, `desktop_shortcuts` and optional
`remote_access_krfb`. `domain.ready` uses the existing protected critical adapter;
it is never an ordinary independently replayable software role.

The [catalog guide](../ALT_COMPONENT_CATALOG.md) explains adding a published
approved role/component with an existing verification recipe, dependencies and
new profile version, without rewriting Setup Orchestrator. A new verification
recipe still requires its own reviewed read-only implementation and tests.
The [operator guide](../ALT_SETUP_OPERATOR_GUIDE.md) contains exact commands for
catalog/profile inspection, full or component plan/apply/verify, job status/events,
continuation, permitted retry and actual functional attestation. SHA/TTL, AD/SSH
identity and source drift checks remain mandatory. Arbitrary runtime YAML,
playbooks, paths and shell expressions are not operator inputs.

The [backend guide](../ALT_SETUP_ENGINE_V2.md) records reusable service boundaries
for a future API: component/catalog and job responses use schema 2, events and
protected queue/maintenance records use schema 1. Job status uses the `job`
envelope; component verification exposes `overall_status` and `components`.
Future HTTP authentication/authorization must preserve the same service gates.
No web page, HTTP route, database or message broker was added.

### Verification and remaining operational limits

Exact-runtime full CI: **5733 passed, 90 skipped, 3315 warnings, 1746.06s, exit 0**
([retained run](https://github.com/BorisDruzak/web_ovpn/actions/runs/38599420531)).
The final atomic queue-publication correction had 2 observed RED failures and
then **110 passing native tests in 112.25s**. Earlier milestone and native counts
overlap; they are not summed into a larger unique total. This final documentation
update changes no deployed executable files and requires no repeated heavy CI.

Mutation remains serialized. Signature-profile and KRFB contracts have regression
coverage, but this live office run did not select them; CryptoPro licensing and
real signing workflows are not accepted. Directum document opening remains a
real-user functional check. A login can create launcher/autostart files with
stricter modes than the published baseline, requiring a fresh shortcuts repair.

The browser RPM generated one active vendor APT source outside the approved p11
policy. Authorized disposable-workstation maintenance retained the original and
disabled only that exact entry; later plans then verified three approved sources.
The browser role does not automatically normalize this side effect. See the
operator guide before a later mutation plan; do not weaken source checks.

Historical UNKNOWN is preserved even after a healthy successor. Queue review
recognizes validated native predecessor links. At this preceding live milestone,
the narrow controller-maintenance review still rejected the additional historical
UNKNOWN; controller backup/deployment clearance was not claimed. The maintenance
follow-up below records its subsequent correction and actual guarded deployment.
The older backup/review cannot erase newer execution history. Reboot and first
login remain explicit operator/user actions.

### Controller-maintenance follow-up — 2026-10-15

Controller maintenance is restored through the existing protected review flow.
Runtime source is **`c2f8e42eee18ef656dc28dd6a5c307565b156934`**, commit
`fix(alt-setup): admit reviewed predecessors during maintenance`, published to
`main` and installed through the native procedures.

The defect was inconsistent admission: ordinary backup and queue review already
validated native component-predecessor links, while maintenance included those
links only when inspecting a queued candidate. After a permitted component
successor finished, its retained UNKNOWN predecessor therefore blocked a fresh
controller-maintenance review. Maintenance now reuses the same `reviewed_jobs`
validation outside the candidate-only branch. Active successors, unreviewed
UNKNOWN, missing/tampered links, changed history and expired SHA/TTL still deny.
The review excludes only the explicitly inspected closed full job and its two
correlated legacy reservations. It never authorizes target replay.

Changed implementation files are the backup validator
`deploy/alt-linux/backup/alt_deploy_backup/setup_maintenance_review.py`, its new
`tests/alt_linux/test_setup_maintenance_review_retry.py`, and the backend/operator
guides. No dependency, API, state schema, Ansible role or workstation executor
changed. Only the installed private/public copies of that validator differ from
the preceding runtime. Independent review found no Critical/Important/Minor
issues; live guards remained separate acceptance requirements.

Verification:

- TDD observed 2 failing maintenance cases and 6 passing controls before the fix;
  the new eight-case suite then passed natively in 12.02s.
- Seven-file native regression: **118 passed in 130.45s**, exit 0, including
  maintenance/queue/worker/CLI/backup compatibility and the stock installer.
- Exact-source `python -m pytest -q`: **5741 passed, 90 skipped, 3315 warnings,
  1277.50s**, exit 0 ([retained CI](https://github.com/BorisDruzak/web_ovpn/actions/runs/38706738598)).
  The automatic `main` runtime and ISO-contract checks also passed for this SHA
  ([runtime](https://github.com/BorisDruzak/web_ovpn/actions/runs/38709421997),
  [ISO](https://github.com/BorisDruzak/web_ovpn/actions/runs/38709422000)).
- The unchanged stock controller installer ran its mandatory
  `python -m pytest -q tests/alt_linux`: **3141 passed, 1 skipped in 1080.26s (0:18:00)**.
  Overlapping runs are not added into a larger unique test count.

The published backup-tool installer first updated the matching private/public
validator copies. All 39 previous tool destinations were preserved privately for
code rollback, and the existing valid fingerprint key was loaded and preserved.
All 261 installed file hashes matched the published release. No retained Setup
history or protected input changed. Fresh native maintenance-plan/confirm then
passed, followed by a new six-component backup, verification, **11/11** rehearsal
checks, native rehearsal eligibility and restore-capacity checks.

The first backup capture correctly refused `controller_sources_changed`. A
bounded native repeat observed the actual before/after inventory return values
without changing a validator or comparison; it succeeded with zero changes.
Verification/rehearsal continued on that same newly created bundle. Its creation
reduced free space below the native restore-capacity requirement. One obsolete,
verified but unrehearsed backup was deleted through native `delete` only after
checking that no active restore/current permit referenced it, preserving the
latest prior rehearsed backup and the new backup. Approximately 2.15 GiB was
reclaimed and capacity then passed. The initial capture cause was not reproduced
or declared fixed; the source-change check remains mandatory.

The first stock controller attempt passed all 3141 native tests but refused the
subsequent active-jobs check before rollout began. Fresh diagnostics proved
unchanged history, no snapshot differences, valid exclusions, and zero scoped
active jobs through both installed CLI and the exact stock source CLI. That
refusal's original cause was not established. A bounded retry stopped only the
idle worker after native quiescence, under the existing exclusive admission and
lifecycle locks. It reran the complete unchanged stock installer and all its
mandatory tests, then completed guarded installation, activation, readiness and
rollout completion. Earlier failure logs remain retained.

Final independent installed checks passed: **261** file hashes match the runtime
SHA, scoped active jobs are **0**, controller readiness is true, worker is
active/enabled, rollback backup remains verified/rehearsed, protected inputs match
and native restore capacity passes. Final free space was
**3.33 GiB on `/`** and **10.08 GiB on `/var`**.
Every pre-existing ledger digest remains unchanged; the only additions are the
new native maintenance plan and confirmation. Both UNKNOWN records and the
validated link to the successful component successor remain intact. No workstation,
AD object, claim or legacy reservation was reset or replayed.

New approved components can use the existing
[catalog extension workflow](../ALT_COMPONENT_CATALOG.md) and protected controller
deployment. Each later maintenance operation still needs its own current native
scope, SHA/TTL, quiescence, source/identity checks and eligible backup. This result
does not convert historical UNKNOWN into success or grant general target/fleet
permission. Root-private receipts and hash-verified local evidence retain the
operational details; this report includes no credentials or private identities.

### Controller maintenance stability follow-up — 2026-10-15

The two intermediate refusal classes above now have reproduced lock mechanisms
and installed-code acceptance recorded in the
[maintenance stability report](ALT_MAINTENANCE_STABILITY_2026-10-15.md). It
distinguishes the retained initial old-code capture refusal and diagnostic
transition from the single-attempt guarded installer and postinstallation backup
on fixed code. Exact historical actors remain unproven; native refusal guards and
UNKNOWN history remain intact.
