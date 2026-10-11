# Limited ALT partial-join recovery implementation plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox syntax for tracking.

**Goal:** Prepare one reviewed recovery for the operator-selected disposable PC's failed join, preserving the existing computer GUID/OU and every failed setup record.

**Architecture:** Add an explicit, separately confirmed recovery plan and receipt to the existing Setup service. Reuse the existing protected state primitives, lifecycle lock, directory adapter, Vault and fixed execution boundary. One recovery write requires a provider that targets the pinned immutable computer identity atomically; a hostname-only native join is insufficient. Trust recovery never changes the original setup result to success or silently unblocks its replay.

**Tech Stack:** Python 3.12, protected JSON state, Ansible 2.18, ALT alterator-auth 0.55, Samba 4.21.9, sealed Kerberos/GSSAPI LDAP.

**Spec:** Original AD Setup task and operator's subsequent narrow authorization to **prepare and independently review** recovery; current failure evidence in `docs/verification/ALT_AD_SETUP_CLI_ACCEPTANCE_2026-10-11.md`.

**Status:** Preparation only. This document does not authorize infrastructure execution, implement new commands, or prove the unknown Samba failure resolved. No computer reset/delete/move has been performed. Concrete implementation, offline tests, independent code review, exact-SHA publication/deployment and a final operator confirmation of the resulting recovery plan remain required before any recovery write.

**Current execution blocker:** The stock system-auth/Samba join remains unsuitable because it selects an existing computer by name. Primary AD specifications and actual GUID base searches support a GUID-only LDAP password-write provider; independent review accepted that immutable-object boundary in principle. However the existing local Samba database fails its domain-metadata prerequisite, so a reset followed by `changesecretpw` is not executable. A separately isolated, synthetic offline-import rehearsal succeeded as described below. Source-controlled guards, bounded secret handling, real pinned writable-DC/configuration checks and independent code review remain required. This plan remains non-executable; neither a successful read nor the synthetic rehearsal authorizes a real password write.

## Global constraints

- Exactly the approved disposable PC and the one computer object created by configuration run `c3590a2451f84e7e8debd1a48ea72504`; no fleet or another target.
- Original setup run `setup-run-653edd38191a4a029247b7e62256f801` remains `failed`; preserve its plan, index, result, logs, audit and binding bytes.
- User SID/GUID, login, profiles, computer UUID/hostname and exact computer OU remain unchanged.
- Computer GUID/SID, exact DN/OU, DNS hostname and SPNs are pinned before writing and rechecked afterward; never delete, rename or move the object.
- Any proposed provider write sets a new machine password; enumerate all provider side effects in the recovery plan and reject effects beyond the approved object/attributes. This is not an AD-user password reset. No ACL/group/user changes or unrelated SPN writes.
- Preparation authorization is not execution authorization. Require a new confirmed recovery SHA and explicit narrow approval for the pinned object before the one write.
- No arbitrary command/playbook/path/Ansible variables from the operator. No Domain Admin requirement; if the existing delegated identity lacks rights, stop and request a separate rights review rather than substituting a privileged identity.
- Vault remains the credential source. Password only through protected stdin to kinit, never argv, output or tracked files. Private credential cache always destroyed.
- No blanket retry, automatic reboot, domain leave, `Reset-ADComputer`, failure relabeling, assignment deletion or editing internal JSON to bypass guards.
- Root-owned deployment uses fresh OR-3P3 create/verify/rehearse evidence and the native guard; recovery operator state uses the same service owner as Setup.

## Observed facts and unknowns

Initial LDAP found no selected computer object. The approved pipeline subsequently created one enabled object in the approved OU, with a set password timestamp, expected DNS hostname and four SPNs. Local system-auth now reports AD, but Samba has no working machine credentials, keytab is absent and SSSD/user lookup fail. Approved reboot completed and changed none of those outcomes. No other computer shares the selected DNS/SPNs in the read-only search. Stock system-auth restores the old secrets database when net ads join returns failure; the protected Ansible output was censored. The exact cause of that post-creation failure is UNKNOWN.

Samba 4.21 changed keytab synchronization; this is an investigation lead, not a proven root cause or permission to alter authentication settings. Consult [version-matched net documentation](https://www.samba.org/samba/docs/4.21/man-html/net.8.html) and [keytab synchronization documentation](https://www.samba.org/samba/docs/4.21/man-html/smb.conf.5.html#SYNCMACHINEPASSWORDTOKEYTAB). Check effective settings read-only before choosing a corrective action. Do not weaken Kerberos/TLS or assert that a speculative keytab change fixes trust.

## Provider preparation evidence

- Actual read-only searches using both GUID-only request representations returned the same selected computer GUID/SID/DN. GSSAPI requests required `minssf=128`. RootDSE advertised 40 controls, excluding RFC 4528 assertion control; no assertion fallback is available.
- Installed OpenLDAP 2.6.9 accepted a **synthetic** GUID-only single-attribute `unicodePwd` replace with `ldapmodify -n` against an unreachable loopback URI. This proves local LDIF parsing only, not server modification rights or successful reset.
- Existing Ansible Vault encrypt/decrypt through stdin and stdout preserved synthetic password bytes exactly; encryption output excluded plaintext. Ansible requires a UTF-8 locale, separately from the LDAP diagnostic locale.
- A root-private copy of the actual Samba database failed `net primarytrust dumpinfo` (return code 1). Original database SHA stayed unchanged. Therefore the proposed direct `changesecretpw` path fails before any AD write.
- Installed Samba 4.21.9 successfully composed and imported **synthetic** offline data in an empty-root Bubblewrap sandbox: read-only binaries/libraries, selected nonsecret NSS files, fresh namespaces/dev/proc/tmp, and one root-private writable scratch directory. Production configuration, authentication databases, Unix sockets and network were excluded. Private/state/cache/lock/pid/log/passdb/ncalrpc/winbind paths were relocated; synchronization and hooks disabled.
- Exact synthetic account and salt fields matched; pending password change was NULL. A subsequent local synthetic password change returned zero and the copy's native legacy password value matched the supplied bytes without a newline. Keytab creation and listing returned zero; scratch keytab was root-owned mode 0600 and contained expected machine/host principals with AES keys. Its synthetic KVNO values do not prove real-domain usability; production needs the actual post-reset KVNO and pinned directory attributes.
- Independent review found no blocking isolation flaw, but required production parsers rather than substring matching, bounded output, protected retention, immutable reservation and fresh identity checks before execution.

The reviewed candidate is **one GUID-addressed LDAP reset followed by local offline initialization and fixed keytab synchronization**, never `offlinejoin provision`, `reuse`, or an online join. [AD request DN forms](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-adts/92a54869-38d7-4e71-a3be-5f67a0dcdd7e) and [unicodePwd](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-adts/6e803168-f140-4d23-b2d3-c3a8ab5917d2) define the directory boundary. Samba's [versioned offline-command source](https://raw.githubusercontent.com/samba-team/samba/samba-4.21.9/source3/utils/net_offlinejoin.c), [API implementation](https://raw.githubusercontent.com/samba-team/samba/samba-4.21.9/source3/lib/netapi/joindomain.c), and [local secrets implementation](https://raw.githubusercontent.com/samba-team/samba/samba-4.21.9/source3/passdb/machine_account_secrets.c) define the local boundary.

`composeodj` produces a zero computer RID in this version. Such a blob is **not evidence of the actual AD computer SID**. The candidate uses it only for native local account/domain/password/salt initialization; external directory GUID/SID binding remains authoritative. Production code must explicitly enforce that narrowed contract, validate the real domain metadata and verify all postconditions. Do not patch or invent TDB records.

GUID addressing protects the selected immutable object from hostname replacement. It does not atomically assert OU/name/SPN state. Revalidate before and after; any external drift stops recovery without moving or repairing the object. The only directory attribute explicitly replaced is `unicodePwd`; server-managed password timestamps, KVNO and credential material are expected effects. Pin a writable DC, require SASL sealing of at least 128 bits, and prohibit referrals, application retries, reconnect replay and name-based fallback. Failed or ambiguous responses remain non-retryable.

## Concrete operating sequence

1. Collect the existing protected run with `workstationctl --json setup status RUN_ID` and read-only `setup verify --machine UUID`; never print raw identities or private logs in a public report. Keep the current failed-run result and byte hashes.
2. Freeze a new recovery plan containing the exact registration hash, current PC UUID/hostname, failed run/result/binding hashes, selected user immutable identity, existing computer GUID/SID/DN/OU/DNS/SPNs, current trust/keytab state, effective package/configuration fingerprints, source generation, expiry and the one proposed native write. Current observation alone cannot prove object creation ownership; bind it to the original absence evidence and run time, and have the operator explicitly approve that exact object.
3. Before execution, preserve a protected, coordinated controller backup and a private PC snapshot of authentication configuration and secrets/keytab files, keeping existing bytes/owner/mode. This is evidence preservation, not a promise of AD rollback: restoring old local credentials after a new AD password would not restore trust. Review diagnostic storage and retention before writing.
4. Acquire the existing lifecycle lock, prove no incompatible jobs/processes, revalidate every pinned identity/state/hash, approved OU and TTL. Reserve an immutable recovery-attempt receipt **before** any mutation, keyed uniquely by **original failed run + pinned computer GUID**, independently of plan/attempt IDs. Once reserved, every fresh plan/SHA/attempt for that pair is refused, including after interruption or ambiguous failure. A second process, drift, missing object, duplicate object, valid trust, changed identity or expired plan must stop before writing. If trust is already valid, use read-only reconciliation only; never rejoin it. A later write would require a new separately reviewed, explicitly authorized additive superseding protocol, not deleting/resetting the exclusion record.
5. Require a reviewed immutable-target provider contract for the actual write, not just LDAP pre/post checks or the local controller lock. With a fixed recovery entrypoint and existing delegated Vault credentials, perform **at most one** approved write to that same object. Until atomic GUID targeting is proven, refuse with `recovery_identity_binding_unavailable`; do not invoke stock name-based system-auth/net join on this existing object. Do not run a separate reset followed by a second password-writing join. Never add a generic existing-object override to the normal domain_join role.
6. Immediately re-read directory identity and local trust/keytab/SSSD/user lookup. Emit only safe diagnostic classifications and return codes. If the write or any identity/trust check fails, preserve the attempt as failed/ambiguous, destroy credentials, and stop with no second write. Preserve bounded private diagnostics through a reviewed redactor; do not disable no_log or emit raw registered Ansible results.
7. If trust and identities pass, record an additive `trust_recovered` receipt. This receipt does **not** assert GPO, apps, signature suite, graphical login/home, or complete Setup success. Failed original run/index stay unchanged.
8. Separately review the continuation receipt and a **new** Setup plan: same binding, fresh TTL/SHA, current valid trust and computer GUID/SID. The failed original plan remains permanently non-replayable. A new fixed stage-03 run may then skip domain join and complete the remaining configuration within the already authorized Setup scope; its own new SHA must be reviewed and confirmed. Request new scope approval only if target/actions differ from existing authorization.
9. Accept only actual post-run trust, SSSD, selected-user getent, GPO, no local duplicate, unchanged AD identity/OU and a fresh idempotent plan. Graphical login/home and application/signature checks remain separate acceptance steps.

## Review focus

- An existing computer with the same hostname but another GUID must never be overwritten.
- Failure after an AD write must remain ambiguous and non-retryable even when the client exits nonzero.
- A receipt must not silently convert the original failed run or active failed binding into successful/degraded state.
- Stale/forged/replayed receipt, user/profile/OU drift and concurrent recovery/setup must fail before writes.
- No diagnostic capture may expose Vault data, tickets, machine passwords or key material; diagnostic storage failure must not erase the mutation-attempt receipt.

## Task 1: Protected recovery planning and immutable attempts

**Files:** Create `deploy/alt-linux/control/alt_deploy/setup_recovery.py`, `tests/alt_linux/test_setup_recovery.py`; extend the existing Setup CLI only with explicit fixed recovery operations.

**Interfaces:** Recovery planning consumes the existing directory/registry/probe stores and a named failed run. Produces a protected TTL/SHA plan plus immutable attempt receipts. Computer identity is separate from the selected employee's GUID/SID. No mutation from planning.

- [ ] RED: different target/user/OU/computer GUID, unsupported failure phase, already-valid trust, missing absence evidence, changed binding, plan hash/TTL, unsafe files/owners/symlinks.
- [ ] Implement bounded snapshots using existing private state primitives; no raw IP identity selection or new secret storage.
- [ ] GREEN: byte-preserving plan proof; reserve against original failed run + computer GUID before mutation; prove interrupted receipt and fresh-plan/attempt replay cannot write again.

Storage foundation completed separately from historical eligibility and execution:

- [x] Reuse protected plan envelopes with a distinct recovery namespace; normal Setup cannot load a recovery plan.
- [x] Preserve exact historical JSON bytes and hashes in a fixed five-document archive; refuse missing/extra/invalid evidence and byte drift.
- [x] Reserve once across competing processes and fresh plan IDs using original failed run + computer GUID. Interrupted, corrupt and failed-storage claims remain excluded.
- [x] Fsync the claim and complete directory ancestry before returning success; simulated parent-sync failure never authorizes execution.
- [x] Append a terminal receipt without replacing claim/evidence; a trust receipt requires exact pinned UUID/GUID/SID and strict successful trust/keytab/SSSD/user checks.
- [x] Observe RED then GREEN and independently review the foundation. The review's first-directory durability finding was fixed with RED/GREEN coverage; no further findings in that scope.

The foundation has no CLI entrypoint, provider, directory writer or automatic continuation. It does not validate full historical run eligibility yet. Focused ALT Python 3.12 checks: 35 new state tests plus existing AD/Setup tests, 98 passed. The full `tests/alt_linux` suite passed with 1047 passed and 1 skipped. Python compile and diff checks passed. The Windows runner cannot collect this POSIX-only suite; validation used an isolated source copy on ALT, not the installed controller code.

Historical provenance inspection is implemented in `setup_recovery_history.py` as a separate read-only block:

- [x] Validate the original plan's hash/schema and the failed run's original start-time TTL without authorizing an expired Setup replay.
- [x] Require a first join with computer absence, no prior assignment, fixed domain/OU/user/profile identity and one failed Setup/index/binding/configuration result chain.
- [x] Match the actual producer contract: Configure `configure_critical_phase_failed` with phase `domain_join`, plus Setup `domain_join_failed`. Unsupported phases/conflicts and unavailable/mismatched results remain refused.
- [x] Preserve all five original raw byte streams; refuse missing/changed evidence and derive protected paths only from validated run/plan/configuration/UUID identifiers.
- [x] Observe RED then GREEN with 33 historical tests; combined history/storage/Setup/plan checks passed with 89 tests. Full `tests/alt_linux` passed with 1080 passed and 1 skipped; Python compile and diff checks passed. Independent source review found no actionable issues in this block.
- [x] Read the selected real failed-run evidence using an isolated source copy and verify all five originals remained byte-identical. No attempt, binding revision, password reset or installed controller change was made.

This establishes historical eligibility only. It does not establish current AD-object ownership or safe execution, and has no CLI entrypoint. Fresh registry/user/OU/AD/workstation snapshots, plan generation, lifecycle serialization, provider and continuation remain required before execution approval.

GitNexus impact for the shared `SetupPlanStore` baseline identified four direct importers (`setup.py`, `setup_assignments.py`, `setup_runtime.py`, `setup_cli.py`) and three transitive files, with LOW reported risk. Source inspection and the complete ALT suite verified the existing Setup contracts; the newly staged recovery modules are outside the committed index baseline and remain unconnected to execution.

Read-only current directory inspection is implemented in `setup_recovery_directory.py`:

- [x] Match the normal domain-wide hostname search to an exact GUID-only base lookup, rejecting changed GUID/SID/DN/account/DNS identity and ambiguous results.
- [x] Require an enabled workstation-trust account, bounded creation time/password timestamp/KVNO, the four exact expected SPNs and no other domain object sharing those DNS/SPN values.
- [x] Read the domain GUID/SID and crosscheck the computer SID against it. RootDSE discovery uses authenticated GSSAPI with `minssf=128`; the selected DC URI is pinned in memory and checked again against its RootDSE and NTDS identity.
- [x] Require a synchronized writable DC via `msDS-isRODC=FALSE`; RODC, incomplete state, external hostname or endpoint drift are refused. The existing controller directory configuration stays unchanged.
- [x] Keep normal Directory parsing/transport semantics: singleton attributes remain strict, multivalued SPNs are allowed only in the dedicated recovery parser, and the normal GSSAPI minimum remains unchanged.
- [x] Observe RED then GREEN with 45 new tests; combined directory/history/storage checks passed with 149 tests. Full `tests/alt_linux` passed with 1125 passed and 1 skipped; Python compile and diff checks passed. Independent source review found no actionable issues in the read-only block.
- [x] Inspect the selected existing real computer through the isolated source copy: GUID/SID matched, four SPNs matched, and the pinned DC was writable. No AD attribute or installed controller code was changed.

The writable-DC proof follows the [AD `msDS-isRODC` contract](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-adts/314967d0-e0c6-4c1f-bca1-b3265f781d78). Context7 was queried for OpenLDAP 2.6 behavior; its retrieved generic draft material was insufficient to override the installed CLI/provider evidence. GitNexus was unavailable during this block, so the previous indexed baseline was supplemented by source inspection and regression checks; no manual index/group synchronization was attempted.

Exact published `72c04d90acda7f3c92917e03c192207dff50295d` CI: ALT contract workflow [38134507739](https://github.com/BorisDruzak/web_ovpn/actions/runs/38134507739) passed; focused runtime identity passed in [38134507660](https://github.com/BorisDruzak/web_ovpn/actions/runs/38134507660), while full regression had 10 failures, 3679 passes and 11 skips. The same ten independent failures remain: six non-root installer fixtures, QEMU public-evidence ownership, stale inventory CSS expectation, a synthetic netctl executable without a POSIX shebang, and vpnctl service-state expectation. This is not an all-green CI claim and does not prove installed or workstation acceptance.

## Task 2: Fixed one-attempt recovery execution

**Files:** Create a fixed recovery provider/runtime and focused provider/runtime tests under the existing control package; wire the fixed runner in `setup_recovery.py`. Do not create a generic Ansible override or expose LDAP attributes, scripts, command lines, paths or variables as operator inputs.

**Interfaces:** Consumes only the validated plan and exact attempt identifier. Produces bounded, safe structured identity/trust checks and a terminal receipt; no retry loop.

- [ ] RED: concurrent apply/recovery, drift after lock, object replacement, unapproved OU, source change, insufficient rights, partial AD write, trust failure, unsafe diagnostic capture and lost result.
- [x] Review GUID-only immutable-object addressing using primary specifications and actual read-only searches. Name-based joins remain prohibited; unsupported assertion controls are not used.
- [x] Reject direct local password installation when the preserved database lacks domain metadata; prove a narrowed native offline-initialization mechanism with synthetic data in mount/network/socket isolation.
- [ ] Implement and review that narrowed contract in source: exact metadata validation, durable Vault sealing before mutation, bounded output, isolated prewrite rehearsal, fixed local import/keytab commands, real KVNO/principal/enctype checks and secret cleanup/retention.
- [ ] Implement identity checks before/after the one approved provider operation, lifecycle serialization, credential cleanup, and safe error classification. Do not reuse a generic existing-object override flag.
- [ ] GREEN: syntax/assets checks and synthetic mutation counters prove zero writes on guards, one maximum write on an approved attempt and no write on replay.

## Task 3: Explicit additive continuation

**Files:** Extend `setup_recovery.py`, `setup.py`, `setup_assignments.py`, and `tests/alt_linux/test_setup_service.py`; update operator/error documentation.

**Interfaces:** A verified recovery-resolution receipt references exact original failed run and binding bytes plus pinned computer identity. Fresh Setup planning may recognize that receipt only after fresh trust/identity validation. New Setup apply still requires its own new plan SHA.

- [ ] RED: forged/stale receipt, changed user/OU/profile/computer, failed recovery, original-plan replay, legacy configure bypass and race between reconciliation and new apply.
- [ ] Preserve original failed binding bytes in immutable receipt evidence before any normal new-run binding revision. Never hand-edit result to successful/degraded or delete its index.
- [ ] GREEN: original failed plan stays refused, fresh plan requires valid trust with the pinned GUID/SID, new stage-03 skips domain join, and old failed run/status remain byte-identical.

## Task 4: Independent review and final execution gate

- [ ] Focused recovery plus existing Setup/ConfigurePlanner/domain/security tests; full ALT suite, Python compile, Ansible syntax and diff check.
- [ ] Independent code review of guards, mutation bound, diagnostics and receipt/continuation semantics; fix findings and rerun affected checks.
- [ ] Publish exact SHA, record CI, obtain fresh coordinated backup/rehearsal and native guarded deployment/readiness proof.
- [ ] Produce the real protected recovery plan, show anonymized exact operation/identity evidence and request final execution approval referencing its SHA. Current authorization covers preparation only.
- [ ] Execute the confirmed recovery once only after the immutable-target gate passes; retain all evidence regardless of outcome. Review/confirm a fresh Setup continuation plan within existing authorization if recovery succeeds.

## Decision ledger

- Ruling: replace the proposed recovery Ansible playbook with a fixed GUID-only provider and local native importer — stock name-based join cannot meet the immutable-object guarantee. This adds an explicit bounded execution boundary rather than an override to normal join.
- Ruling: reject `changesecretpw` as the first local step on this target — its protected-copy domain metadata check failed. Offline import is a candidate local initializer, not a second AD password-writing join.
- Ruling: scope the ODJ blob to local initialization — this version's RID0 is not the selected computer SID and cannot establish identity. External GUID/SID binding and real postchecks remain mandatory.
- Ruling: preserve UNKNOWN for the original partial-join cause — no_log hid the decisive output; the missing local metadata is a recovery prerequisite failure, not proof of that original cause.
- Ruling: prepare implementation in an attached managed worktree and validate it in a private ALT source copy — the primary checkout and deployed controller stay separate. Infrastructure recovery remains unexecuted.
