# ALT AD Setup CLI acceptance — 2026-10-11

**Implementation published and guarded controller deployment performed; disposable-PC live acceptance FAILED at domain join.** L0, L1 and L2 passed. The approved apply created the computer object in the approved OU, but Samba trust failed. SSSD/user lookup/GPO acceptance remains incomplete. Preserve the failed run and binding; automatic replay is blocked. Full regression is not green; independent failures are listed below.

## Baseline

Fresh HEAD/origin main: `74e195abf376cb03537eedcd482d1cdd2d8bfac3`, initial tree clean. GitHub runs `38084079111` and `38084079137` both failed at this SHA. Reproduced collection collisions and two execution_release_invalid failures in isolated Linux copy. Fixes rename endpoint test modules and emulate ownership of explicit synthetic fixture inodes; production ownership/mode/hash/no-follow checks remain active, non-root owner/group negative tests added.

## Controller evidence

Read-only commands: tool/version checks, klist -s, workstationctl --json controller readiness, workstationctl --json vault check. Readiness true, failed_checks empty, no active jobs; Vault healthy. Python 3.12.7, OpenLDAP 2.6.9, Samba 4.20.8-alt2. No existing service ticket. Private temporary probe acquired a ticket from existing delegated Vault identity and performed base-scope domain-object LDAP query with GSSAPI/minssf=56, return code 0. Cache destroyed. Only booleans/return code emitted; no credentials or real identifiers. workstation_contacted=false, directory_write=false. Capability proof does not constitute selected-user L1 or workstation acceptance.

## Implementation checks

Read-only AD commands and setup plan/apply/status/verify implemented with protected TTL/SHA plans, separate bindings, fixed ConfigurePlanner, strict read-only SSH and machine-account identity. Legacy mutation paths cannot bypass domain bindings.

Final focused directory/setup and existing configure/domain contracts: **363 passed**. Baseline-fix focused tests: **62 passed, 3 skipped**; Setup/runtime/precheck set: **29 passed**. Isolated root production-installer module: **36 passed**. Compileall and setup-controller-preflight/stage-03 Ansible syntax passed; diff check passed.

First publication `473ffdbc5b95e4099a2a5dc8634f998f74caae8b`: focused-runtime-identity CI passed. [Managed contract run 38126837966](https://github.com/BorisDruzak/web_ovpn/actions/runs/38126837966) uncovered the next synthetic-fixture dependency: GitHub has no `altserver` service account, so the two CLI tests reached `install_session_storage_failed` after passing the corrected release-ownership checks. RED reproduced on Linux with `ALT_DEPLOY_SERVICE_USER=codex-fixture-account-not-installed` (**2 failed**). Fixture now selects the real test runner's account for synthetic storage, preserving actual mode/ownership handoff operations and all production checks. Same command GREEN: **2 passed**; the workflow's eight-module install-session command GREEN: **34 passed**. Final publication/CI outcomes are in the accompanying delivery message.

Full Linux regression (root in isolated repository and synthetic host roots): **3584 passed, 9 failed, 5 skipped** in 697.65s. Four subsequent concurrency/source-drift/computer-identity regression cases also passed in the final focused run. Every one of these nine full-run failures was separately reproduced on the untouched exact `74e195ab` archive under the same interpreter/environment: **9 failed** in 3.47s. They are independent baseline failures, not new AD/Setup failures:

| Test | Baseline failure |
|---|---|
| test_ansible_assets::test_roles_contain_no_unsafe_ansible_patterns | Existing software_endpoint_agent shell tasks |
| test_alt_install_execution_qemu::test_run_state_has_unpredictable_trust_anchor_and_exact_artifact_identity | Assertion rejects the runner's private temporary-directory name |
| test_install_execution_authorization: three authorization tests | Signing-key fixture parent ownership |
| test_inventory_endpoint_web::test_pc_card_keeps_agent_summary_small_and_shows_endpoint_values_by_field | Old inventory CSS version assertion |
| test_netctl_client::test_run_netctl_transmits_projection_only_through_stdin | Synthetic executable has no POSIX shebang |
| test_vpnctl_management::test_web_summary_returns_only_dashboard_metrics | ALT service-state expectation mismatch |
| test_vpnctl_management::test_management_kill_command | Test runner lacks the expected service group |

Ordinary-user full ALT run earlier: 7 failed, 962 passed, 5 skipped; six installer cases need ownership privileges in their synthetic roots and passed when run as root. These environment requirements remain distinct from the nine failures above. No tests were disabled or security checks weakened.

Commands:

```sh
.venv/bin/python -m pytest -q tests/alt_linux/test_ad_directory.py tests/alt_linux/test_setup_plans.py tests/alt_linux/test_setup_service.py tests/alt_linux/test_setup_runtime.py tests/alt_linux/test_setup_cli.py tests/test_alt_manual_configure_request.py tests/test_alt_domain_ansible_assets.py tests/test_alt_domain_resilience_assets.py --tb=short
.venv/bin/python -m pytest -q tests/alt_linux/test_install_execution.py tests/alt_linux/test_install_session_cli.py tests/test_endpoint_execution_manifest.py tests/test_endpoint_execution_tls.py --tb=short
sudo -n .venv/bin/python -m pytest -q tests --tb=short
sudo -n python3 -m pytest -q --noconftest tests/alt_linux/test_install_execution_production_installer.py
.venv/bin/python -m compileall -q deploy/alt-linux/control/alt_deploy
ANSIBLE_CONFIG=deploy/alt-linux/ansible/ansible.cfg ansible-playbook -i localhost, --syntax-check deploy/alt-linux/ansible/playbooks/03-setup-controller-preflight.yml
ANSIBLE_CONFIG=deploy/alt-linux/ansible/ansible.cfg ansible-playbook -i localhost, --syntax-check deploy/alt-linux/ansible/playbooks/03-configure-domain-workstation.yml
git diff --check
```

GitNexus `web_ovpn` query/context/impact located the committed ConfigurePlanner boundary and indexed CLI consumer. Dynamic source inspection confirmed reuse of the fixed stage-03 entrypoint and shared controller lifecycle/binding state. Existing HTTP APIs, Endpoint SDK/OpenAPI and network-write paths were not changed. GitNexus backup query plus source inspection confirmed the whole controller_state component includes the new state directories; root-owned directory configuration requires a separate backup as documented.

Independent review identified seven defects: lifecycle/binding bypass, descendant OU acceptance, computer identity replacement, lost partial-result/reboot evidence, missing text run ID, omitted role scripts/templates in source fingerprint, and false reboot state on unavailable results. All corrected and re-reviewed with no remaining actionable findings. Linux concurrency, source drift and GUID/SID replacement regressions passed. Review/synthetic tests do not constitute workstation acceptance.

## Live gates

| Gate | Status / reason |
|---|---|
| L0 | PASS: operator selected one disposable ALT PC and existing test user, approved end-to-end checks and separately approved reboot |
| L1 | PASS: real selected-user immutable identity/state, 95 OUs and initial computer absence checked through sealed GSSAPI LDAP |
| L2 | PASS: three deployed-CLI plans had identical semantic content hashes; selected PC configuration hashes and AD user/computer semantic digests unchanged by planning |
| L3 | Controller deployment PASS; approved workstation apply FAILED with domain_join_failed |
| L4 | FAIL: computer created in approved OU, but trust invalid, keytab absent, SSSD inactive, selected-user lookup unsuccessful; GPO false in saved result |
| L5 | Safe live negatives passed as listed below; ambiguous/conflicting directory objects were not manufactured |

PC type: operator-selected disposable ALT Workstation K 11.x, initially outside the domain. No domain leave was necessary or performed. No first-join success, graphical login/home, installed-app/signature-suite or idempotent acceptance is claimed.

### Approved infrastructure actions and receipts

The operator explicitly allowed enabling the selected disabled test user as a narrow exception to the original no-user-writes rule. Native AD enable preserved the same GUID/SID and verified enabled/not locked/not expired. No user creation, password reset, unlock or group edit was performed. A pre-existing test computer OU was selected; no OU or directory ACL was changed.

Directory configuration uses `join-vault` GSSAPI and a root-owned, nonsecret configuration readable by the service account. AD/Setup state and commands use the same service owner. Existing Vault/keys/inventory were preserved. The active Ansible copy is not a Git checkout: source identity was verified by SHA-256 comparisons instead of inferring Git provenance.

Deployment of `ea29741b0fc5e26a9fc31e20d87ae0263138eb3e` used successful OR-3P3 backup `backup-20261011T093938Z-8b8e214b`, manifest SHA-256 `9a094a7abccf495606d5d4ff44bb54cf5247f9ae7874beaa59f5f861d004e040`. Verify and 11-check rehearsal passed; read-only rehearsal eligibility passed. Independent SSH/sudo recovery access was verified. Native `install-control-plane.sh --rollback-backup-id` passed **1007 tests, 1 skipped**; fresh readiness had no failed checks; all 119 published control Python/Ansible files matched with zero mismatches.

Earlier backup attempts were retained with their failed rehearsal evidence. A historical, nonactive assignment quarantine was moved intact under a private maintenance archive, with byte hashes checked and the active assignment preserved. The backup validator now admits deferred-first-login registrations only with a strictly typed, successful, identity-matched configure result and four true domain checks. An unrelated registration still failed that strict validation; the operator separately authorized archiving only that controller registration. Native archive receipt: `archive-20261011T093937Z-c97207c6`. That PC and AD were not contacted or modified. No failed record was relabeled or deleted to obtain PASS.

The selected PC's stale hostname registration was archived natively (`archive-20261011T094607Z-82f3f09a`) after checking no assignment/active job. The exact published register-only bootstrap was executed on the approved PC; registration/preflight succeeded. No employee local account was created.

Applied plan SHA-256: `9b2d91406acbc66cfafd9c5c0f04e5e25282050a00e62f634d9ae4fd8a500308`. Profile `core-apps`, remote profile `none`, exact approved OU, same selected domain user for test and assignment. Full prejoin package upgrade and domain prerequisites ran. Run `setup-run-653edd38191a4a029247b7e62256f801`, configuration run `c3590a2451f84e7e8debd1a48ea72504`, saved status `failed`, phase `domain_join`, `reboot_required=true`, error `domain_join_failed`. The structured partial result was preserved. Components are empty and saved GPO verification false because later phases did not run.

Read-only diagnosis confirms one newly created, enabled computer in the approved OU with the expected DNS hostname, four SPNs and a set password timestamp. The PC has an AD system-auth profile but no valid Samba trust or keytab; its old secrets database remains. The stock ALT `system-auth` script creates the AD object through `net ads join` and restores the previous secrets database when that command fails. Ansible's protected join output is censored by `no_log`; the specific post-creation Samba failure is **UNKNOWN**, not proven to be insufficient permissions, DNS, reboot or package incompatibility. The second join was skipped. No computer reset/delete/move or unguarded retry was performed.

The operator separately approved reboot after the upgrade; reboot completed and a changed boot ID was verified. Post-boot deployed `setup verify` returned `failed`: trust false, SSSD false, selected-user lookup false, local duplicate false, saved GPO false. Keytab is still absent, time synchronized. A domain-wide read-only DNS/SPN lookup found only the selected new computer object, so no other-object DNS/SPN collision was observed. The reboot did not repair trust. Actual PC versions after upgrade: Samba 4.21.9, alterator-auth 0.55, SSSD 2.9.8. First graphical login/home remains untested.

Safe live refusals: disabled selected user before its separately approved enable, nonexistent user, unapproved OU, unregistered machine, stale registry hostname, wrong confirmation SHA (`setup_plan_mismatch`), unresolved failed-plan replay/new plan (`setup_previous_run_unresolved`) and expired plan (`setup_plan_expired`). Expiry used a separately created protected plan with an intentionally old creation clock; original plans were not edited. Both replay/expiry checks returned exit 4 before Ansible execution. Directory unavailability probe used an isolated unreachable URI without changing production configuration/network/DC: it exposed SASL prefix misclassification. Fix `4f3291910ab327abe60b75dfb724e7ccf02fd35d` preserves connectivity errors while keeping TLS priority and actual Kerberos errors; **63 focused tests passed**, independent review had no findings.

Exact `4f32919...` subsequently deployed through the same native guarded path with fresh backup `backup-20261011T100322Z-dcade381`, manifest SHA-256 `9a89dacf1e1561f81ebf1b68d051de81c930710a18adccb05a429902ad672ae0`. Verify, 11-check rehearsal and read-only eligibility passed. Installer suite **1012 passed, 1 skipped** in 218.49s; native install succeeded. Fresh readiness true with all 14 checks true and no failed checks. Post-deployment comparison of 111 control Python and installed Ansible role/playbook/configuration files found zero mismatches. The actual installed LDAP transport returned `ad_dc_unavailable` for the isolated unreachable URI. Saved failed setup status/binding remained intact; no workstation apply was repeated.

### Subsequent exact-SHA code and CI evidence

`35a8b99f4087ebeeab9c39e3427b7ec2f6efab0e` removes the two existing Endpoint enrollment shell tasks using fixed Python argv. Focused checks passed **90 tests**; root ALT suite passed **989 tests, 1 skipped**. `ea29741b0fc5e26a9fc31e20d87ae0263138eb3e` adds strict deferred-login backup validation; focused backup/rehearsal/restore/installer checks passed **51 tests**, stricter type/error cases **18 tests**, with independent review corrections verified.

At exact `ea29741...`, [ALT managed contract CI](https://github.com/BorisDruzak/web_ovpn/actions/runs/38128696543) passed. [Runtime identity CI](https://github.com/BorisDruzak/web_ovpn/actions/runs/38128696535) passed its focused job but full regression had **10 failed, 3606 passed, 11 skipped**. Remaining failures: six nonroot production-installer ownership fixtures, one QEMU execution-challenge ownership fixture, the old inventory CSS assertion, synthetic netctl executable without POSIX shebang, and vpnctl service-state expectation. The former unsafe Ansible shell-assets failure is fixed. These counts supersede earlier historical full-run counts above; no full-green claim is made.

At exact `4f3291910ab327abe60b75dfb724e7ccf02fd35d`, [ALT managed contract CI](https://github.com/BorisDruzak/web_ovpn/actions/runs/38130524197) passed; [runtime/full regression CI](https://github.com/BorisDruzak/web_ovpn/actions/runs/38130524124) passed focused-runtime-identity and finished with **10 failed, 3611 passed, 11 skipped** in 707.57s. The same ten independent failures listed above remain; no new directory/setup failure appears in that summary.

## Continuation and publication

The authorized reboot and deployed read-only status/verify checks are complete; trust remains broken. Continuation requires a separately reviewed recovery procedure for the partial join. V1 has no automatic failed-run recovery; do not delete assignments/runs, retry the failed plan or reset/delete/move the existing computer object. The original computer-reset/delete/move prohibition remains binding; any recovery requiring such writes needs a narrow explicit operator exception and a concrete reviewed procedure before execution. Remaining acceptance includes valid trust, SSSD, selected-user lookup, GPO, first graphical login/home, applications/signatures and a new idempotent plan.

The operator subsequently approved **preparation and independent review only** of a limited recovery with possible machine-password reset while preserving the created computer GUID/OU and failed evidence. [Recovery plan](../superpowers/plans/2026-10-11-alt-partial-join-recovery.md) records the preparation/execution boundary. Review found cross-plan retry evasion and the name-based AD mutation race; both design findings were corrected and independently re-reviewed with no remaining actionable plan findings. The revised design uses a unique failed-run/computer-GUID reservation and refuses execution until an atomic immutable-target provider contract is proven. The plan is explicitly non-executable by design at this checkpoint. No recovery write or failed-state bypass has been performed; provider verification and recovery implementation remain pending work.

Implementation commits: `3ff6a77f14be43e58493f8496faf5658cf6ffb2f` (baseline fixture/module isolation), `a5dd3f4de5a50a2d4c1b8daea179142710a88164` (AD/Setup runtime, CLI, tests, operator documentation), `fa7e4893aa49472e149cd5d49be8f284608df912` (additional concurrency/identity regressions), `473ffdbc5b95e4099a2a5dc8634f998f74caae8b` (initial checkpoint), subsequent CI fixture fix `882b7b63484d14064c387f0defca53fc2fe649c4`, and the three later full SHAs above. Source publication, exact deployed generation and workstation acceptance remain distinct. The goal is incomplete while L4 is failing.

### General regression baseline repaired

Minimal test-only commits `feabe126952beadb7ffa67146584473b8a804b99`,
`5d29a70af9cabbacf3b6396478169194d82cc438`,
`5fb5f8e16c48c48dd40436c016ff1b072b97b7cb`, and
`07d99f034f5ae757469e0fd50bb40cf95f27b67a` corrected the old CSS revision,
isolated command fixtures, modelled root-owned fixtures under non-root POSIX,
and isolated batch preview paths. Production ownership checks and test selection
remain enforced. Actual root checks separately verified the ownership scenarios.

At exact `5fb5f8e16c48c48dd40436c016ff1b072b97b7cb`,
[runtime CI](https://github.com/BorisDruzak/web_ovpn/actions/runs/38162766019)
completed successfully: **4337 passed, 21 skipped**, 804.08 seconds.
At exact `07d99f034f5ae757469e0fd50bb40cf95f27b67a`,
[runtime CI](https://github.com/BorisDruzak/web_ovpn/actions/runs/38163618964)
also completed successfully: **4337 passed, 21 skipped**, 592.82 seconds.
These terminal results supersede the historical red baseline above. They do not
prove recovery, controller installation or the still-failing workstation L4.
The corresponding complete non-root ALT development regression, with final
test fixtures and an isolated bytecode cache, finished with **4338 passed,
20 skipped** in 772.83 seconds. Its frozen sources were not changed during
execution. The later retained-artifact delta is verified separately.

### Retained artifact verification preparation

Separate import, Kerberos and temporary-policy `verify_artifacts` interfaces
verify the genuine protected retained records, original backup, current
credential/configuration bytes and executable/module identities. The static
snapshot excludes only process observations; identity, clock, Samba parameters,
authentication files and unknown/missing facts remain checked. Historical
Kerberos receipts do not assert that a ticket is still valid, and retained
offline configuration does not assert that a running daemon consumed it.
All receipts retain `trust_verified=false`.

Existing pre-start `verify` interfaces still require full current facts and
inactive authentication services. Their final checks follow native package
queries. Independent review found a during-RPM stale-success race; new negative
tests reproduced nine failures, and protected lower-chain/tool rereads after
the final native call corrected it. Two additional tests reproduced service
activation during package queries and verified the final inactive guards.
Independent source review reported no remaining findings.
The genuine facts collector itself reads file metadata before executing native
read-only queries. Three further RED tests exposed a stale snapshot if bytes
changed inside that interval; final protected authentication-file and native-tool
rereads close it without another command cycle.

Final non-root ALT focused verification passed **111 tests** in 16.40 seconds.
The full final-source actual-root ALT suite passed **1773 tests, 1 skipped** in
292.06 seconds. Source/test SHA-256 values matched the Windows candidate before
and after execution, Python compilation and diff checks passed. An earlier
incomplete scratch copy omitted documents and failed 28 documentation checks;
those failures were preserved and the complete corrected copy passed the full
suite. The final native-facts strengthening was independently re-reviewed.
GitNexus located the committed policy/Kerberos workers and their transports;
source inspection confirmed transports carry the complete fixed modules, so
these new interfaces do not add an operator route or cross-repository contract.

This block remains internal recovery preparation. It has no operator execution
entrypoint and performs no AD reset, credential installation, machine
authentication, service start or real workstation change. The fixed startup
worker, bounded stdin transport, recovery coordinator and final exact-plan
execution approval remain required.

### Fixed SSSD startup preparation (2026-10-12)

The internal fixed worker preserves an intent before a single SSSD start,
requires genuine protected lower-chain records and checks a fresh stable
invocation/PID without claiming trust. It rejects jobs, authentication-service
drift, changed stock unit/tool/configuration bytes and any fixed SSSD
environment file. Original restart count must be zero. The request binds the
existing recovery plan ID/SHA and exact 30-minute lifetime; both wall-clock
expiry and the monotonic command budget are enforced before mutation.
Read-only verification of a historical receipt remains possible after expiry.

Four environment-file/restart RED cases, two pre-start boolean-schema RED cases
and four retained service-record boolean-schema RED cases were reproduced and
fixed. Final focused non-root ALT checks passed **86 tests** in 25.87 seconds.
Compilation on Windows/ALT and source hash comparison passed; independent final
source review reported no remaining findings. Full final-source actual-root
ALT regression passed **1819 tests, 1 skipped** in 319.94 seconds. An earlier
frozen candidate passed 1813 with one skip before six final type-drift cases
were added; no source changed during either execution. CI for preceding exact SHA
`1fad845aa16f2916b8ebdd68c0c8a845b90f2d6c` completed successfully in both managed
ALT [38165119175](https://github.com/BorisDruzak/web_ovpn/actions/runs/38165119175)
and full runtime [38165119192](https://github.com/BorisDruzak/web_ovpn/actions/runs/38165119192).

This remains internal preparation, with no installed controller transport or
operator recovery execution route. No real SSSD start, computer-account reset
or recovery mutation occurred. Online identity/trust, service restoration,
temporary-policy restoration, additive Setup continuation, guarded deployment
and final exact-plan execution approval remain required.

### Startup stdin transport preparation (2026-10-12)

Twelve fixed worker sources are carried in a bounded stdin envelope rather
than the remote argv string. The bootstrap checks wire/module hashes, names,
duplicate keys, non-finite values and closed field sets before source execution.
Request bounds remain 128 KiB; the overall source/request wire is at most
1 MiB and the result at most 16 KiB. Only the effects-ledger digest crosses
this boundary. Controller context derives genuine policy/service history,
post-write identity, actual plan dates/SHA and source provenance. A mandatory
read-only authorization callback supplies the future exact approved binding;
there is no default approval or operator execution route.

Twenty-three wire and sixteen controller RED tests first reproduced missing
implementation. Independent review then found final-callback history drift;
a RED regression observed SSH before late failure. A separate RED reproduced
cached approval aliasing. Final protected post-write rereads and snapshot copies
now block both before SSH. Forty-six new checks passed on non-root ALT in
16.51 seconds, including corrupt/oversized wire and reply, durable-record
failure, typed-intent drift and post-persistence approval drift. A child-process
integration loads all genuine modules and runs start/verify only against
private fixtures, with exactly one simulated start and no verification action.
Compilation and source hash comparison passed. Final combined non-root checks
passed 184 tests with three root-only skips in 75.55 seconds. Frozen final-source
actual-root ALT regression passed 1865 tests with one skip in 337.39 seconds.
Independent final source review closed all findings with no further actionable
issues. Exact published CI remains a separate gate.

Both CI workflows for preceding exact SHA
`86580626eac022bc8d6ff7e74f0dd95ed85b9621` completed successfully. No controller
deployment, AD reset, target service start or real recovery execution occurred.
The protected authorization gate and full recovery coordinator remain pending.

### Exact startup approval preparation (2026-10-12)

The new internal attachment binds both recovery/startup SHA confirmations to
protected original history/registration, immutable identities, deployment and
twelve worker sources, exact stock SSSD unit and a bounded readable effects
ledger. A fixed durable binding/ready pair is created before reservation under
the lifecycle lock. Later authorization requires the real protected claim and
genuine post-write continuity, current TTLs and unchanged approval/source data.
No default approval/ledger, operator JSON execution path, Vault opening or
service action exists in this block. Extracting the shared unit validator did
not change the existing worker's conditions.

Thirty-two missing-module RED cases preceded implementation. Review-driven RED
cases covered failed-fsync evidence accepted later, missing actual reservation,
failure marker written after lock release, failed-marker creation after visible
ready and failed exclusion fsync. Exclusion now runs inside the lock, preserves
failed/revoked evidence, and confirms directory durability. Completely unconfirmed
storage returns `recovery_startup_approval_ambiguous` and requires manual recovery;
no cross-crash exclusion guarantee is claimed for unwritable storage. The future
coordinator must not automatically resume a failed binding. Genuine post-write
fixture tests retain original history bytes, open no Vault and accept only the
recorded password version and immutable GUID/SID/OU identity.

Final focused verification passed 169 tests in 92.42 seconds, including the 48
new approval cases. Full root ALT regression passed 1913 tests with one skip in
373.99 seconds. Compilation of 86 candidate Python files, normalized Git/remote
source hashes, diff checks and final independent source review passed. The frozen
tracked-tree archive SHA-256 was
`509da338260b4b8c8f8d68ba72fe1f25f44ca71bfac3e056a366fe0a85b9e6a5`.
The first full run inherited staging umask 077: the existing base-mode negative
fixture's mkdir(0755) became safe 0700, causing one failure with 1912 passes and
one skip. Its five cases and the final full run passed under explicit umask 022
with unchanged source/tests. Reporting-only documentation was updated afterward.
Fresh read-only target checks confirmed the selected identity, inactive SSSD
with zero restarts and absent keytab/SSSD options file; the selected AD employee
remains enabled. No live trust recovery or functional acceptance follows from
these facts. Both CI workflows
for preceding exact SHA `d9f994ce6a8149f2aea5fffaeee5dcdcc20866bf` passed. This
approval block is uninstalled and not yet exposed through a coordinator or CLI.
The protected inventory/review producer, remaining restoration/functional checks
and final exact live execution approval remain required; no real recovery ran.

### Recovery-assisted disposable workstation acceptance (2026-10-13)

For anonymized target `test-vm-02` and existing employee `employee-02`, the
selected workstation's Setup completed successfully through the genuine
SetupService, ConfigurePlanner and fixed stage-03 playbook. The first join and
the subsequent hostname-verification failure remain retained as failed runs.
One authorized machine-password repair preserved the existing computer's
GUID, SID, OU and SPNs. Its worker result remains UNKNOWN; separate fresh
observations proved working trust before a reviewed new Setup context ran.
No new controller backups were created during this repair and continuation.

The installed runtime is `d7499f005dd4ad5deb3e8b175db0a0eb75d3d698`, including
`cf110fbfdd28339ed7ed07700778a5154176daf9`. These changes request explicit
computer identity attributes from Samba and consistently accept the expected
joined workstation FQDN. Native controller installation checks passed 2679
tests with one skip. CI for the installed revision passed 5215 tests with
89 skips; its ISO workflow also succeeded. The final real Setup playbook
reported 276 successful tasks, 47 changes, no unreachable hosts and no failures.

Fresh native `setup verify` confirmed trust, SSSD, selected-user lookup, absence
of a duplicate local user and successful group-policy application. All selected
core-apps components, including the signature suite, reported verified success.
After the operator authenticated with the employee's AD credentials, SSH
confirmed an active local X11 user session through LightDM, the matching domain
UID, and the employee's home directory with matching owner and mode 0700.
A subsequent native verification reported `home_exists=true` and
`home_operations_deferred=false`. No further reboot was required.

A fresh public CLI plan accepted the successful assignment and contained no
domain-join action. Reapplying the completed plan returned its cached successful
result without another configuration run or machine-password change. A wrong
SHA was refused with `setup_plan_mismatch`, with protected results unchanged.
These checks do not constitute a second execution of the complete playbook.

This establishes recovery-assisted acceptance for the selected disposable
workstation. The distribution's Samba package was not upgraded, and its
fresh-join compatibility issue and the bootstrap root/sudo validation issue
remain separate work. The complete original L5 live negative matrix and
unassisted fresh-machine acceptance are not claimed as passed by this result.

### Unassisted fresh-workstation attempt (2026-10-13)

Runtime `ce0e007eaebb363e271d5eef243ebb01553d56d4` includes the technical-user
bootstrap privilege check, fixed desktop-role inclusion, native-host and browser
policy checks, and the first-join compatibility adapter. Its published runtime
CI passed 5244 tests with 89 skips; the ISO workflow also succeeded. Native
controller installation passed 2682 tests with one skip. No new controller
backup was created for this installation or workstation attempt.

For anonymized fresh target `test-vm-03` and existing enabled employee
`employee-03`, the ordinary served bootstrap completed without manual marker
or privilege changes. Native workstation preflight passed all 13 checks. One
exactly confirmed public Setup plan launched the genuine configuration pipeline.
Its full package upgrade completed before the first domain join.

The attempt failed at the compatibility verification gate during domain join:
93 tasks succeeded, nine changed, and one failed. A new computer object was
created in the approved OU with password version 1, but fresh read-only checks
found no system keytab, invalid machine trust and inactive SSSD. The original
native failure detail was censored by the credential-protecting Ansible block;
the precise failure cause remains UNKNOWN. The earlier successful offline-keytab
check on an already joined workstation did not establish first-join acceptance.

The failed Setup and configuration results remain retained. No join replay,
computer reset, deletion or employee change was performed. A native read-only
recovery plan preserves the selected identities and explicitly reports
`execution_available=false`. Applications and browser-extension installation
were not reached on this fresh target. Unassisted Setup acceptance is FAIL;
the CLI's fully automatic fresh-machine path is not ready for acceptance.

### Separate recovery-assisted continuation (2026-10-13)

The same anonymized `test-vm-03` subsequently received one explicitly authorized
machine-password repair. Its worker returned a nonzero result and remains
closed as UNKNOWN. That result was not replayed or rewritten. Independent
observations confirmed working machine credentials and preserved computer
GUID, SID, OU and SPNs; the selected employee remained unchanged.

The operator separately authorized restoration of the stock SSSD policy and
previously active SMB/NMB services, followed by a fresh ordinary Setup context.
This continuation performed no further join or password reset and created no
new controller backup. The genuine stage-03 execution succeeded with 296
successful tasks, 52 changes, zero failures and zero unreachable hosts.

Fresh public `setup verify` confirmed trust, active SSSD, selected-user lookup,
no duplicate local employee, successful group policy and all selected core-apps
components. Four executable application launchers were present in the skeleton
desktop. After the operator logged in with the employee's AD password,
read-only SSH checks confirmed an active local LightDM X11 session with the
selected domain UID, a matching home owner with mode 0700, and all four
executable desktop launchers owned by that employee. Fresh public verification
reported `home_exists=true` and `home_operations_deferred=false`.
No additional reboot was requested by Setup.

Runtime `0a63441607fbd8fd92e8f5760ad5ac4692fb1d86` separates the native first
join from offline keytab creation. Native installation checks passed 2682 tests
with one skip; its full CI passed 5247 tests with 89 skips and its ISO workflow
succeeded. The initial unassisted failure remains retained. Recovery-assisted
success does not establish first-join acceptance for this revised adapter.

A separate fresh technical browser profile, running as a non-root user with
the normal browser sandbox and TLS validation, automatically downloaded
GosPlugin version 1.3.43.0 from the managed policy. The CAdES policy still used
the legacy Manifest V2 identifier and did not download that extension during
the observation window. The installed CAdES native host already allows the
supported Manifest V3 identifier. Commit
`0ea86163433d23cb8328d695f1f9ad3f31898faf` corrects that identifier in the
existing role and its contract test. Actual electronic signing is not claimed.

The corrected role was installed through the normal guarded controller
installer using existing rollback evidence. Native checks passed 2682 tests
with one skip, controller readiness passed all 14 checks, and the installed
role bytes matched the exact published archive.
Full CI for this exact revision passed 5247 tests with 89 skips; its ISO
workflow also succeeded.

A new ordinary public Setup plan/apply on the successfully joined workstation
then passed 259 tasks, with 14 changes, zero failures and zero unreachable
hosts. The existing user home was configured without deferral. No reboot was
required. A new isolated non-root browser profile automatically downloaded
both GosPlugin 1.3.43.0 and CAdES 1.3.17, each using Manifest V3, with no manual
extension installation, sandbox bypass or TLS override. The temporary
technical profile and its browser process were cleaned up after the check;
the employee's graphical session was not used for this isolated proof.
Post-run read-only checks confirmed the unchanged computer identity and
machine-password version 2, retained original UNKNOWN evidence, successful
trust/SSSD/user lookup/GPO, and no home-operation deferral.

Additional live non-mutating CLI checks returned `ad_user_not_found` for an
unknown login, `setup_ou_not_approved` for an unapproved nonexistent OU, and
`machine_not_found` for an unknown UUID. These selected checks do not establish
the complete original L5 matrix.
A fresh ordinary plan accepted the successful assignment and existing trust;
confirmation with a wrong SHA returned `setup_plan_mismatch` before execution.

The installed public CLI also refused the original now-expired successful
continuation plan with `setup_plan_expired`, before any replay. Before/after
hashes of the failed and successful Setup records and the Configure-run
directory inventory were identical. A separate in-memory DirectoryConfig
with a confirmed closed loopback LDAP endpoint exercised the actual installed
LDAP transport and returned `ad_dc_unavailable`. The production directory
configuration was not changed, and no workstation configuration was launched.
Ambiguous AD user objects were not manufactured for live acceptance.

### 2026-10-13: clean-VM package timeout diagnosis

On a separately selected clean workstation `test-vm-04`, normal served bootstrap,
registration and native preflight succeeded. The operator selected enabled
existing `employee-04`; one ordinary public Setup plan/apply then stopped during
the pre-join full package upgrade at the controller's 5400-second subprocess
deadline. No domain-join task had executed. The closed failed run remains
retained; post-failure checks found no AD computer object or machine keytab,
with local authentication and no valid trust. No reset or new backup occurred.

The configured `ftp.altlinux.org` package origin downloaded at approximately
0.06–0.15 MB/s in bounded independent probes on this VM. The same p11 RPM from
`download.basealt.ru` downloaded at 2.15–3.38 MB/s; a separate control origin was
also substantially faster. This establishes the slow configured origin/path
combined with the global timeout as the Setup failure mechanism. It does not
establish whether the remote mirror or a provider/path condition causes that
origin's slowdown. The installed CLI's `domain_join_timeout` label was misleading
for this pre-join failure.

The approved correction selects only stock signed p11 origins, adds a six-hour
fresh Setup budget, reports timeout phase and permits a new normal plan after
strict proof of a closed pre-join timeout. First unassisted join acceptance on
this target was subsequently attempted as recorded below. Synthetic tests and
staged read-only inspection alone do not establish that acceptance.

### 2026-10-13: package correction passed; delegated OS-write mismatch found

Published package/pre-join corrections:
`2cfac53584d7e0570dcb00dc69abf1cde4e64aa5` and
`32d4f852bbfd81d3fe6d40dbb6b9f67ed0ba8221`.
Exact-head runtime-identity CI passed 5311 tests with 89 skips; the ALT ISO
workflow passed. The guarded controller installer passed 2730 tests with one
skip using existing rollback evidence; 173 installed files byte-matched,
readiness passed 14 checks, and eight historical Setup records were unchanged.
No new backup was created.

A new ordinary plan retained the earlier pre-join failed run and used the
six-hour budget. One apply on `test-vm-04` completed the full package upgrade
in approximately 17 minutes, with observed download throughput around
5–6 MB/s. The resulting packages were ALT 11.4, Samba 4.21.9-alt4.p11.1 and
alterator-auth 0.55. This apply then **failed at first domain join** after
creating the computer in the approved OU. The computer remained at KVNO 1;
keytab was absent, trust invalid and SSSD inactive. Application roles had not
run. The failed run is closed and retained; no join replay/reset occurred.

Read-only schema, computer DACL and effective group observations established
a deterministic authorization mismatch: the admitted join principal has no
WriteProperty permission on any of `operatingSystem`, `operatingSystemVersion`
or `operatingSystemServicePack`, through direct, group, broad or property-set
grants. The pinned ALT Samba source revision
`532170350db04e6b9b96943c6ecac92a8c4ae0d2` sends these three properties in one
LDAP Modify when native `osName/osVer` are present, before storing secrets and
creating the keytab. Initial computer creation alone supplies the observed
password, DNS name and four SPNs. Historical native LDAP stderr was censored
and not retained; the precise returned LDAP diagnostic remains unavailable.

An isolated network namespace on the same VM generated an offline keytab from
synthetic credentials and passed the existing byte parser. No real machine
secret values or AD mutations were used for that check. Thus successful
offline-generation tests do not establish successful first-join admission.

The bounded correction omits both optional OS arguments from a validated native
join, preserving DC/OU/Kerberos/cache/no-DNS and all credential verification.
It applies the metadata adapter to newer Samba versions as well; the separate
offline-keytab workaround remains version-gated. RED-to-GREEN tests and native
focused regression passed **421 tests with one skip**. Independent review
found no remaining confirmed P1/P2 after fixing the unaffected-version bypass.
Corrected live first-join/recovery, reboot and graphical-login acceptance remain
**pending**; this result is not a completed fresh-VM Setup.

### 2026-10-13: bounded recovery history after a pre-join timeout

The approved extension admits exactly one closed initial pre-join timeout,
followed by a separately closed first-join failure. It verifies sealed prior
run/plan/request/log hashes, both plan-run indexes, unchanged identities,
strict revision metadata and non-overlapping chronology. Original history
bytes and the five-file recovery envelope remain unchanged. Archived resolution
reads retain this validation after a successful assignment advances. This does
not authorize reset, replay or assignment edits.

RED-to-GREEN covered live history and archived resolution reads. Native broad
regression before the final archived-resolution delta passed **3327 tests with
82 skips**; all recovery tests plus Setup service/runtime tests on the final
delta passed **1641 tests with 77 skips**. Independent review found no remaining
confirmed P1/P2. GitNexus identified the direct planning/resolution consumers;
source and tests verified the continuation and operator paths. Read-only loading
of the selected live failed history passed from the isolated source copy.
The extension was published and installed from
`e9b6ba7b2c56a38f8fd2acb40b7a2d13c4f1cccd`. Exact-head runtime-identity CI
passed **5346 tests with 89 skips**, and ISO CI passed. One guarded install
passed **2746 tests with one skip**, using existing rollback evidence. Its
120 control modules and 61 Ansible files byte-matched the source; 262 retained
history files and directory configuration were unchanged; readiness passed
14 checks. No new backup was created.

An independently reviewed, selected-target recovery plan was prepared and
verified without claiming an attempt or writing AD. It uses one GUID-only
password Modify, sealed credentials, network-isolated native offline preparation,
fixed local import, stock-policy verification and genuine Setup continuation.
Eight private synthetic tests and nine isolated native operations passed.
Reusing native existing-account join was rejected because its fallback can
repeat password operations after partial LDAP failure. At this preparation gate,
concrete reset approval and live continuation were pending; no AD mutation had
been performed by the extension and fresh-VM Setup acceptance was incomplete.

### 2026-10-13: selected-target recovery and ordinary Setup passed

The separately SHA-authorized one-shot GUID-only password Modify on
`test-vm-04` returned zero. The same computer retained GUID/SID/OU and other
observed attributes; KVNO advanced from 1 to 2. Offline native credentials
were prepared and checked before the write, imported once, and verified with
pinned-DC machine AS and Samba trust. Stock SSSD policy was preserved and its
services restored. No new backup, join replay or additional reboot occurred.

One genuine ordinary stage-03 continuation finished successfully in about
six minutes. Its component checks passed for domain identity, SSSD, GPO,
government CA, Plasma, browser, OnlyOffice, Directum, Nextcloud, CryptoPro,
CAdES, GosPlugin and desktop shortcuts. The initial home operation was deferred
until the selected employee's first login; the employee then confirmed that
the desktop opened. SSH inspection verified an active local domain X11 session,
the correct home owner and mode 0700, four executable application shortcuts,
folder links and Nextcloud autostart. Fresh CLI verification reported
`home_exists=true` and `home_operations_deferred=false` with healthy trust and
no local employee duplicate.

A fresh non-root Yandex profile automatically downloaded GosPlugin 1.3.43.0
and CAdES 1.3.17, both MV3; native messaging manifests and launchers were
verified. Signing with a real employee certificate was not tested.
The archived failed revision 2 remained readable after the successful current
binding advanced to revision 3. Exactly 261 existing history files were
byte-unchanged; only the expected mutable binding advanced. A new ordinary
CLI plan omitted domain join and observed the existing home. Controller
readiness passed 14 checks after completion.

This establishes recovery and configured-workstation acceptance. The failed
initial join used the earlier package/pre-join release, so first automatic join
with the corrected native metadata adapter on a clean VM remains **pending**.

### 2026-10-13: clean VM first automatic Setup passed

A new clean `test-vm-05`, assigned to the same `employee-04`, initially had
local authentication, no machine keytab, no AD computer object and no
assignment. The original bootstrap ran once, followed by one ordinary CLI
Setup apply. Full package upgrade, first domain join and all stage-03
components succeeded in 35 minutes 13 seconds. The new machine keytab had
KVNO 1; the structured result reported `recovered=false`. No recovery,
existing-account reset or new backup was used.

One authorized reboot completed. Read-only verification confirmed a new boot,
healthy domain trust, stock SSSD policy, active SSSD/SMB/NMB and selected-user
lookup. A fresh non-root Yandex profile automatically downloaded GosPlugin
1.3.43.0 and CAdES 1.3.17, both MV3; their native hosts were verified.

After the employee confirmed graphical login, SSH inspection verified an
active local domain X11 session, home ownership matching the domain UID/GID,
mode 0700, four executable application shortcuts, network/home folder links
and Nextcloud autostart. Fresh CLI verification reported `home_exists=true`,
`home_operations_deferred=false`, successful GPO verification and no local
employee duplicate. A second ordinary plan omitted domain join; it was not
applied. Operational execution counts were one bootstrap, two plans, one
Setup apply and repeated read-only verification around reboot and login.

Initial graphical attempts used the hostname as the login and failed with
`UNKNOWN USER`; the correct AD login succeeded. A private verification helper
had incorrect encoding in Russian path literals; correcting that helper
allowed all checks to pass without workstation remediation. These were not
Setup or first-join failures.

This completes clean-VM first automatic Setup acceptance for the tested ALT
image and installed release. Actual signing with an employee certificate was
not tested. The existing HTTP bootstrap-helper download transport limitation
remains outside this functional acceptance; this result does not establish
authenticated bootstrap transport or fleet-wide compatibility.
