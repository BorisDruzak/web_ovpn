# Limited ALT partial-join recovery implementation plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox syntax for tracking.

**Goal:** Prepare one reviewed recovery for the operator-selected disposable PC's failed join, preserving the existing computer GUID/OU and every failed setup record.

**Architecture:** Add an explicit, separately confirmed recovery plan and receipt to the existing Setup service. Reuse the existing protected state primitives, lifecycle lock, directory adapter, Vault and fixed execution boundary. One recovery write requires a provider that targets the pinned immutable computer identity atomically; a hostname-only native join is insufficient. Trust recovery never changes the original setup result to success or silently unblocks its replay.

**Tech Stack:** Python 3.12, protected JSON state, Ansible 2.18, ALT alterator-auth 0.55, Samba 4.21.9, sealed Kerberos/GSSAPI LDAP.

**Spec:** Original AD Setup task and operator's subsequent narrow authorization to **prepare and independently review** recovery; current failure evidence in `docs/verification/ALT_AD_SETUP_CLI_ACCEPTANCE_2026-10-11.md`.

**Status:** Preparation only. Read-only recovery planning is implemented; no recovery execution command is available. The unknown Samba failure is not resolved and no computer reset/delete/move has been performed. Reviewed provider/local-import implementation, offline tests, exact-SHA publication/deployment and a final operator confirmation of a fresh executable recovery plan remain required before any recovery write.

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
- [x] Implement bounded snapshots using existing private state primitives; no raw IP identity selection or new secret storage.
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

Read-only current workstation facts are implemented in `setup_recovery_probe.py` and `setup_recovery_runtime.py`:

- [x] Collect only bounded hashes and ownership/mode metadata for five fixed authentication files and seven fixed native tools. Private authentication files require mode 0600; redirected, oversized, unowned or writable files are refused. File identity and metadata are checked before, during and after reads.
- [x] Read fixed native package versions, effective Samba parameters, clock synchronization and known incompatible process names. No secret file contents, process arguments or raw native diagnostics are returned; password hooks must be empty.
- [x] Bind the strict SSH response to the registered UUID/hostname, exact schema, protected metadata, snapshot digest and fixed probe-source digest. Reject duplicated JSON fields and unsafe or changed source files.
- [x] Resolve an independent P1 review finding: execute both the recovery facts probe and existing Setup probe with fixed `python3 -I -B -c`, excluding writable working directories from imports and suppressing bytecode writes. Both argv regressions failed before the fix and passed afterwards. Independent follow-up source review confirmed the fix with no further findings.
- [x] Observe RED then GREEN for 24 new facts tests; the combined facts and existing runtime suite passed with 27 tests as the non-root controller service owner. Full `tests/alt_linux` passed with 1149 passed and 1 skipped in 216.35 seconds. Five Python sources compiled and staged diff checks passed.
- [x] Repeat the isolated facts probe twice on the selected real workstation. UUID/hostname matched, all authentication-file and native-tool metadata remained unchanged, clock synchronization was true, no incompatible process was found, and keytab remained absent. All five original historical evidence streams stayed byte-identical. A first history read under root was correctly refused because the preserved state belongs to the controller service account; repeating under that account succeeded without modifying ownership or permissions.

These facts are an observation, not an execution lock or proof of recovery. The current registered identity, files, configuration and process state must be revalidated under the lifecycle lock before any future approved attempt. No recovery writer, installed-controller change or operator execution entrypoint is included in this block.

GitNexus context for the committed `SetupRuntime` baseline identified its `SetupService` importer; new recovery modules are outside that indexed baseline. Source and runtime checks verified the shared probe invocation. Exact published `6e01db5d0d55e393fce691bb84a1c8ddccce7f49` CI: ALT contract workflow [38135564205](https://github.com/BorisDruzak/web_ovpn/actions/runs/38135564205) passed; focused runtime identity passed in [38135564206](https://github.com/BorisDruzak/web_ovpn/actions/runs/38135564206). Full regression retained the same ten independent failures listed above, with 3724 passes and 11 skips.

Protected recovery planning is implemented in `setup_recovery_planning.py` with the explicit read-only `setup recovery plan --failed-run ... --computer-guid ...` CLI:

- [x] Derive the selected machine, employee, exact OU and profiles from the protected original failed run. Crosscheck current registration readiness/jobs/assignment, employee GUID/SID/login/UPN/state, approved OU GUID and the exact existing computer GUID/DN/creation window on a writable DC.
- [x] Require a broken trust, matching workstation identity, no local duplicate, synchronized clock, no incompatible process and valid fixed controller prerequisites. Pin current registration, directory, source and workstation hashes in a protected 30-minute recovery plan.
- [x] Reread registry and all five historical files after workstation reads; reject concurrent state change or appearance of any attempt. Planning creates no lock, attempt, binding or infrastructure mutation.
- [x] List the proposed one-object machine-password operation, expected directory effects and required remaining gates. Always set `execution_available=false`; no recovery apply command is exposed. Creation timing is explicitly not an ownership proof.
- [x] Observe RED then GREEN for 27 initial planning tests and two CLI cases; add three mid-read drift guards. Combined planning/CLI/storage checks passed with 70 tests as the non-root service owner. Full `tests/alt_linux` passed with 1181 passed and 1 skipped in 220.96 seconds. Compile and staged diff checks passed; independent source review found no actionable issues.
- [x] Generate and reload a protected plan against the selected real failed run using the isolated development copy. Original history remained byte-identical, creation-window checks passed, five execution gates remained required and no attempt was reserved. Installed controller code and machine credentials remain unchanged.
- [x] Invoke the actual new CLI handler against the selected real target: return code 0, a protected `recovery-` plan and `execution_available=false`; original evidence remained byte-identical. Two changed controller sources compiled successfully. This used the isolated development copy, not the installed controller command.

This completes the read-only planning interface, not the provider or execution gate. The real preparation plan is non-executable and cannot be used as execution approval; a fresh plan must include the completed reviewed provider and current post-deployment evidence before approval is requested.

## Task 2: Fixed one-attempt recovery execution

**Files:** Create a fixed recovery provider/runtime and focused provider/runtime tests under the existing control package; wire the fixed runner in `setup_recovery.py`. Do not create a generic Ansible override or expose LDAP attributes, scripts, command lines, paths or variables as operator inputs.

**Interfaces:** Consumes only the validated plan and exact attempt identifier. Produces bounded, safe structured identity/trust checks and a terminal receipt; no retry loop.

- [ ] RED: concurrent apply/recovery, drift after lock, object replacement, unapproved OU, source change, insufficient rights, partial AD write, trust failure, unsafe diagnostic capture and lost result.
- [x] Review GUID-only immutable-object addressing using primary specifications and actual read-only searches. Name-based joins remain prohibited; unsupported assertion controls are not used.
- [x] Reject direct local password installation when the preserved database lacks domain metadata; prove a narrowed native offline-initialization mechanism with synthetic data in mount/network/socket isolation.
- [ ] Implement and review that narrowed contract in source: exact metadata validation, durable Vault sealing before mutation, bounded output, isolated prewrite rehearsal, fixed local import/keytab commands, real KVNO/principal/enctype checks and secret cleanup/retention.
- [ ] Implement identity checks before/after the one approved provider operation, lifecycle serialization, credential cleanup, and safe error classification. Do not reuse a generic existing-object override flag.
- [ ] GREEN: syntax/assets checks and synthetic mutation counters prove zero writes on guards, one maximum write on an approved attempt and no write on replay.

Credential sealing is implemented separately in `setup_recovery_credential.py`; it has no CLI, AD provider or workstation importer:

- [x] Generate a 384-bit random machine password in memory only after validating an existing reserved attempt, its historical plan and preserved evidence. Bind the encrypted payload to failed run, computer GUID/SID, machine UUID, plan SHA, claim SHA and evidence SHA.
- [x] Use fixed `/usr/bin/ansible-vault` encrypt/decrypt via protected stdin. Copy the existing protected Vault key into a mode-0600 sealed Linux memory FD; pass only its `/proc/self/fd` name, close it after every operation and write no plaintext key/password copy to disk.
- [x] Run in a private temporary directory with a fixed non-secret empty `ansible.cfg`, minimal environment and Python import/bytecode safeguards. Installed Ansible Core 2.18.6 rejects `/dev/null` as a configuration filename; that observed failure was reproduced and corrected without changing controller configuration.
- [x] Bound stdout/stderr and runtime, kill the entire child process group for excessive output or timeout, and thread stdin writing so a stalled child cannot bypass the deadline. Suppress raw subprocess diagnostics.
- [x] Exclusively create the protected ciphertext, fsync its complete ancestry, reread/decrypt and require an exact roundtrip before creating a separate bound ready marker. Public credential access requires that marker, a fresh directory sync and unchanged reservation/evidence after decryption.
- [x] Resolve an independent readiness finding with RED/GREEN coverage: any preparation failure closes the reserved attempt with an append-only failed receipt when storage permits; the original claim remains excluded if storage is unavailable. Even a visible marker after its final fsync failure cannot reopen a failed attempt. No ciphertext regeneration, replacement, terminal-attempt reopen or automatic retry is supported.
- [x] Observe RED then GREEN for the codec/storage and failure guards. Full ALT passed with 1199 passed and 1 skipped in 217.06 seconds; three native-process/drift cases added after its collection also passed in the final 56-test credential/storage run (21 credential cases), under both service-user and root execution. Compile/diff checks and independent source review passed.
- [x] Exercise the actual installed Vault with synthetic material and synthetic attempt state in a private temporary directory. Sealed-memory-FD roundtrip and durable bound credential creation/access passed; file scans found no plaintext machine password. No selected recovery claim, directory write, workstation contact or installed controller change occurred.

Context7 was consulted for Ansible Vault documentation, but its unversioned snippets were not treated as proof for installed Core 2.18.6; the actual fixed-command synthetic test established compatibility. GitNexus transport was unavailable for `VaultHealthChecker` context, so its existing source contract and regression tests were inspected without manual synchronization. Exact published `1a8e02531caf192a45f86cc0e58452aacb2b29ba` CI: ALT contract workflow [38137365513](https://github.com/BorisDruzak/web_ovpn/actions/runs/38137365513) passed; focused runtime identity passed in [38137365476](https://github.com/BorisDruzak/web_ovpn/actions/runs/38137365476), while full regression retained ten failures with 3780 passes and 11 skips. This does not authorize recovery execution.

The internal one-write adapter is implemented in `setup_recovery_provider.py`; it remains unwired and requires concrete reviewed fresh-state and prewrite producers:

- [x] Refuse missing producers and non-executable plans before mutation. Bind the distinct execution envelope to its read-only snapshot, reserved claim, original evidence, exact GUID/SID and durable sealed credentials.
- [x] Serialize through the lifecycle lock and check current snapshot, source fingerprint, pinned writable DC, delegated GSSAPI transport and minimum SSF 128. Repeat checks after preparation and Kerberos authentication.
- [x] Persist and fsync an exclusive write intent before one fixed GUID-only `unicodePwd` replacement. No name fallback, referrals, continue flag, retry, arbitrary attributes or operator command is exposed. Password travels only as quoted UTF-16LE LDIF through protected stdin; raw subprocess output is discarded.
- [x] Require unchanged object identity/OU/DNS/SPNs and exactly one KVNO increment with a newer password timestamp after the operation. Directory-password evidence is not a trust-recovered receipt. Any entered failure becomes ambiguous; all attempts and intents remain excluded from replay.
- [x] Reproduce and fix sealed-credential replacement during preparation. Pin the protected document before opening it; compare its content and reopened secret after preparation, authentication and intent synchronization. Replacement tests at all four boundaries require zero Modify calls.
- [x] Resolve an independent P1 finding with RED/GREEN coverage: Vault reopening can consume the remaining TTL. Validate TTL after the final credential check, directly before invocation. Expiry retains the write intent and failed receipt while sending zero Modify calls. Independent follow-up source review closed the finding.
- [x] Run all 32 focused provider tests successfully as the controller service owner, including concurrent calls, guard failures, expired plans, credential drift, ambiguous results, cleanup and replay exclusion. A prior synthetic native `ldapmodify -n` parser exercise returned zero; it used loopback and synthetic directory/postcheck state, not real reset rights or trust evidence.
- [x] Full ALT regression passed with 1233 passed and 1 skipped in 219.65 seconds; collection preceded the last review regression. The final provider/credential/storage run passed all 88 tests under root, including that added regression, and final provider source/tests compiled. Staged diff checks passed.

The actual controller-backup producer, real post-write local installation/trust/keytab verification, reserved-attempt fresh-state integration, coordinator and additive Setup continuation remain unimplemented. The adapter's injected test producers do not satisfy those operational gates. No real recovery claim or password replacement has been made and installed controller code is unchanged.

GitNexus context identified the committed `LDAPTransport` consumers before source inspection. OpenLDAP 2.6.9 [tool source](https://raw.githubusercontent.com/openldap/openldap/OPENLDAP_REL_ENG_2_6_9/clients/tools/common.c) establishes that referral chasing defaults to zero; this adapter does not enable it. The AD [unicodePwd specification](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-adts/6e803168-f140-4d23-b2d3-c3a8ab5917d2) describes single-replace administrative password reset over sufficiently protected transport; actual delegated write rights remain untested. Exact published `1f10e7bb082b7c525adcf941e46eadf86432348b` ALT CI [38138239313](https://github.com/BorisDruzak/web_ovpn/actions/runs/38138239313) passed; runtime CI [38138239273](https://github.com/BorisDruzak/web_ovpn/actions/runs/38138239273) retained the same ten independent failures, with 3801 passes and 11 skips.

Fixed workstation preservation is implemented in `setup_recovery_backup.py` and `setup_recovery_backup_runtime.py`; it is an internal preparation primitive, not an operator command:

- [x] Preserve only the five fixed authentication files in one exclusive root-private leaf. Reread current UUID/hostname, file/tool/configuration metadata and quiescence through the fixed collector before and after copying. Require the exact prepared snapshot; no arbitrary source/destination path or script is accepted.
- [x] Copy bounded source bytes through no-follow descriptors, verifying identity/size/owner/group/mode/hash before and after the read. Retain exact bytes and original UID/GID/mode inside mode-0700 backup ancestry; represent missing files explicitly without creating them on the workstation. No restore, credential import, service change or AD operation exists in this module.
- [x] Bind a protected manifest and separate verified marker to the failed run, computer GUID, machine UUID, claim, workstation snapshot and exact source bundle SHA. Fsync copies and complete backup ancestry, reread hashes and exact metadata, and refuse unexpected or redirected evidence. Existing successful or incomplete leaves cannot be overwritten or recreated.
- [x] Resolve a review finding: a visible verified marker after failed final sync remains excluded by a separate failed marker and exact-leaf checks. The original partial directory is retained even if recording the failure also has a storage error; no automatic retry or cleanup is attempted.
- [x] Use fixed strict SSH with no user SSH config, proxy or jump, explicit key/known-hosts paths, minimal environment and isolated Python imports. Only the two protected controller sources execute. Bounded strict JSON on stdin cannot select filesystem paths, code or an operation; only the fixed internal create/verify methods exist. Validate the protected reservation before and after transport and require the exact safe receipt/manifest hashes.
- [x] Resolve a second review finding without changing normal AD transport: `setup_recovery_process.py` supplies deadline-controlled threaded stdin/stdout/stderr, bounded sizes and process-group termination for timeout, overflow or descendant-held pipes. The workstation backup and internal password provider both use it by default. A synthetic stalled-child probe showed the old synchronous input writer exceeded its 0.2-second deadline and needed a four-second outer watchdog.
- [x] Observe RED before the new modules and GREEN afterward. All 80 process/backup/runtime/provider tests passed as the controller service owner, including a real process-group kill test and execution of the generated worker inside an isolated filesystem fixture. Seven changed Python sources compiled and diff checks passed. Independent follow-up review closed both findings with no further actionable issues.
- [x] Full `tests/alt_linux` passed under root with 1282 passed and 1 skipped in 220.62 seconds, including all final new tests. No sources changed after collection.

No real selected-workstation snapshot was created during this block. The wrapper deliberately requires a genuine protected reservation; the future coordinator must integrate preparation evidence and approval without fabricating a claim or bypassing public planning's attempt exclusion. Actual coordinated backups and the isolated native local-import rehearsal remain execution prerequisites. The installed controller and selected workstation authentication files are unchanged.

Source inspection confirms that native coordinated backup creation also acquires `/var/lib/alt-deploy/workstationctl.lock`. Complete preparation before recovery owns that lock. Native `rehearse-status` acquires only the separate nonblocking operation lock and verifies all bundle components and the manifest/verification/rehearsal link, so the future locked prewrite producer may use it to validate previously prepared native evidence. Do not bypass the native guard or drop recovery serialization to work around nested locking.

Exact published `b331eccb401b38987fa519558eb70ff85653b148` ALT CI [38139466637](https://github.com/BorisDruzak/web_ovpn/actions/runs/38139466637) passed; focused runtime identity passed in [38139466654](https://github.com/BorisDruzak/web_ovpn/actions/runs/38139466654), whose full regression retained the same ten independent failures with 3833 passes and 11 skips.

Fixed native preparation primitives are implemented in `setup_recovery_native.py`; they remain internal helpers, without a remote rehearsal producer or recovery execution entry point:

- [x] Validate a closed metadata schema and generate one fixed Samba configuration with all mutable state under `/work`, disabled automatic keytab synchronization and an empty password hook. Refuse injected metadata, linked or unsafe rehearsal directories and unknown operations.
- [x] Require Bubblewrap user, network, PID, IPC and UTS namespaces, dropped capabilities, cleared environment, a fresh filesystem, read-only runtime/NSS mounts and exactly one private writable `/work` mount. No host Samba configuration, authentication database or service socket is mounted.
- [x] Provide only offline compose/import, local `changesecretpw`, secret-free metadata dump, offline keytab creation/listing and a fixed isolated Python read-only TDB password comparison. Passwords and the ODJ blob travel through stdin; the comparison emits only a boolean. No online provision, join, account reuse or directory mutation command exists in this helper.
- [x] Parse the current NDR structure by anchored indentation paths and require exact computer/account/domain GUID/SID/salt and no pending password change. Permit native scoped flag expansions and DNS case normalization. Parse genuine Samba keytab columns, require exact account/HOST principals and complete AES entries, and distinguish placeholder rehearsal versions from a positive directory KVNO.
- [x] Independent review identified a keytab-format mismatch; captured synthetic native output reproduced it before correction. Follow-up review closed the finding with no further actionable issues. All 29 focused tests passed as the controller service owner.
- [x] Full ALT regression passed under root with 1311 passed and 1 skipped in 219.77 seconds; both changed Python sources compiled and staged diff checks passed.
- [x] Run the fixed command chain using installed Samba 4.21.9 and Bubblewrap 0.13.0 with a synthetic password, account and domain identifiers in a private temporary sandbox on the selected disposable workstation. Compose, import, metadata before/after local password writing, read-only exact-password comparison, keytab creation and listing all returned zero; both parsers accepted the genuine output. The original live `secrets.tdb` hash was unchanged. Temporary synthetic state was removed. Placeholder key versions do not prove real-domain trust.

GitNexus supplied committed `RecoveryPlanningRuntime` context before source exploration. Context7 supplied Bubblewrap guidance, checked against the installed version and [versioned Bubblewrap manual](https://raw.githubusercontent.com/containers/bubblewrap/v0.13.0/bwrap.xml). Samba's [native command source](https://raw.githubusercontent.com/samba-team/samba/samba-4.21.9/source3/utils/net.c) and [keytab implementation](https://raw.githubusercontent.com/samba-team/samba/samba-4.21.9/source3/libads/kerberos_keytab.c) were checked for local-only operations and output compatibility. These helpers still need a bounded, protected rehearsal producer, backup-seeded state, source/fact revalidation and attempt-bound evidence integration before they can satisfy the provider's operational prewrite gate.

Exact published `c32c40d5794cf0f568fc99c5e3a45b31a1adbd0e` ALT CI [38140502943](https://github.com/BorisDruzak/web_ovpn/actions/runs/38140502943) passed. Full runtime CI [38140503052](https://github.com/BorisDruzak/web_ovpn/actions/runs/38140503052) retained the same ten previously enumerated independent failures, with 3881 passes and 11 skips; its focused runtime identity job passed. No recovery was executed or deployed by this block.

The protected offline rehearsal producer and transport are implemented in `setup_recovery_rehearsal.py` and `setup_recovery_rehearsal_runtime.py`; they remain internal preparation methods, without a CLI apply or directory writer:

- [x] Bind the exact reserved claim, UUID/hostname, protected backup request/manifest/receipt, sealed credential SHA, metadata and five fixed sources. Validate current facts and backup bytes before and after the native chain. Never fabricate a selected-target reservation to exercise this producer.
- [x] Exclusively retain the rehearsal leaf and request. Seed the private sandbox from the exact preserved original TDB bytes, then run the eight fixed native operations with bounded stdin/stdout/stderr and process-group deadlines. No live authentication path is mounted or installed.
- [x] Remove temporary native secret state before success, reread backup/snapshot evidence and persist a protected verified receipt with fsync. Failures retain a separate exclusion marker, including a visible verified marker after a failed sync; verification refuses failed, incomplete or leftover scratch state. Interrupted attempts cannot be retried automatically.
- [x] Transport only strict bounded JSON over strict registered-IP SSH, isolated Python and five protected fixed sources. A password is supplied only for creation through stdin. Pin the sealed document before decryption and transport; recheck document, password and claim after transport and after final Vault reopening. RED/GREEN regressions cover claim changes at both boundaries.
- [x] Make the process helper usable as a fixed standalone source without an installed controller package. It preserves all deadlines, bounds and fail-closed behavior; standalone errors contain only stable codes, and normal controller use retains ControlError classifications. Its standalone native success/timeout tests passed.
- [x] Reproduce and fix the exact installed ALT version suffix mismatch. Accept only reviewed `4.21.9` and `4.21.9-alt4.p11.1`; refuse other versions before native commands. Execute the entire producer with the installed native tools, synthetic attempt identity, an isolated filesystem fixture and a protected read-only copy of the original live TDB. Rehearsal verification, unchanged backup bytes, scratch removal and unchanged original TDB SHA all passed. This synthetic fixture is not an operational prewrite artifact for the selected failed run.
- [x] Full ALT passed with 1343 passed and 1 skipped in 219.38 seconds; collection preceded five final version/claim/fsync regressions. All 117 final process/backup/rehearsal/runtime/provider tests, including those additions, passed under both root and service-user execution. Six changed Python sources/tests compiled and diff checks passed. Independent source review found no remaining actionable issues.

The generated remote worker was also executed inside an isolated unit filesystem fixture; its source bundle and create/verify protocol worked with fixture-only root, collector and native runner substitutions. No selected recovery claim, AD write, live authentication installation or controller deployment occurred. The real attempt-bound prewrite coordinator and positive directory-KVNO/trust recovery still remain required.

Exact published `8d1248df78aa4c40b67e72fd2e6e9d586642647a` ALT CI [38142056394](https://github.com/BorisDruzak/web_ovpn/actions/runs/38142056394) passed; runtime workflow [38142056381](https://github.com/BorisDruzak/web_ovpn/actions/runs/38142056381) retained the same ten enumerated independent failures, with 3910 passes and 11 skips. Its focused runtime identity job passed.

The reserved fresh-state adapter is implemented in `setup_recovery_reserved_state.py`:

- [x] Keep public planning's unconditional attempt exclusion. The internal adapter accepts only the exact protected execution envelope and its reserved, currently unexpired plan; it neither reserves an attempt nor decrypts credentials.
- [x] Revalidate the protected claim, original five-file history, plan SHA, machine/computer identities and absence of write intent/result before and after fresh directory, registry, source and workstation inspection. Reject any snapshot drift, terminal/interrupted state or expiry.
- [x] Reproduce and fix a final-validation race where original history changed during reservation validation. Tests also integrate the real internal provider with synthetic credentials, LDAP transport and prewrite receipts: unchanged state permits one GUID-only write; changed KVNO before writing permits zero writes. Synthetic receipts are not operational approval evidence.
- [x] All 24 new tests and 175 combined state/history/planning/credential/provider tests passed as the service user. Full ALT passed with 1372 passed and 1 skipped in 224.98 seconds, including all final additions. Independent follow-up review closed with no actionable findings.

The real controller-backup producer, locked prewrite coordinator, authentication installation, trust proof and additive continuation remain required. No selected-target recovery claim, password reset, live authentication installation or deployment occurred in this block.

Exact published `120e0218b7d749662231d9117e58b6cbfa0b80d2` ALT CI [38143108642](https://github.com/BorisDruzak/web_ovpn/actions/runs/38143108642) passed; the focused runtime identity job in [38143108554](https://github.com/BorisDruzak/web_ovpn/actions/runs/38143108554) passed while its full regression was still running when this evidence was recorded.

The native controller backup producer is implemented in `setup_recovery_controller_backup.py`:

- [x] Require the exact reserved fresh-state snapshot, protected claim/history and ready sealed credential document. Persist an exclusive preparation intent before the first external operation; the native controller-state snapshot includes this protected preparation state. A failed or interrupted preparation cannot create another backup for the attempt.
- [x] Invoke only fixed native `guard`, `create`, `verify`, `rehearse` and `rehearse-status` commands with bounded process I/O, a minimal environment and no passwords. Bind the native backup ID, manifest SHA and verification SHA to the exact claim, plan, snapshot and sealed document. Preserve native artifacts on failure.
- [x] Revalidate identity and intent before and after protected receipt persistence. Verification rejects failed/incomplete state and protected evidence drift, then performs native guard and full eligibility verification. It creates no backup and never recursively acquires the lifecycle lock.
- [x] Reproduce and correct an independent-review finding: native create/verify return six components, distinct from the eleven rehearsal checks. Exercise the entire producer through the actual native dispatch/repository/rehearsal implementations in an isolated backup sandbox, with fixture executables and no live controller state.
- [x] Reproduce and fix intent drift during native preparation. Cover native failures, unsafe IDs, changed sealed state, expiry, retry exclusion and a visible receipt after failed persistence. All 16 producer tests and 136 combined producer/provider/reserved/native-backup tests passed as the service user. Both new Python files compiled. Independent follow-up review closed with no remaining actionable findings.
- [x] Full ALT passed under root with 1388 passed and 1 skipped in 228.81 seconds, including all final additions. No Python sources changed after collection; diff checks passed.

No actual selected recovery claim or native backup was created. The real prewrite coordinator, authentication installation, trust proof and additive continuation still remain required.

Exact published `ac9417ebf2778f084b9acac0c4ab3f0923842fb0` ALT CI [38143834218](https://github.com/BorisDruzak/web_ovpn/actions/runs/38143834218) passed. The preceding full runtime CI [38143108554](https://github.com/BorisDruzak/web_ovpn/actions/runs/38143108554) retained the same ten previously enumerated independent failures, with 3947 passes and 11 skips; its focused runtime identity job passed.

The operational prewrite verifier is implemented in `setup_recovery_prewrite.py`:

- [x] Load only a protected closed-schema preparation record bound to the exact current-time executable plan, claim, snapshot and sealed credential. Recheck the supplied password against the exact sealed document; emit no credentials. This verifier creates no preparation record or external write.
- [x] Resolve the same registered target, derive the backup request from the existing runtime's protected fixed sources and exact reserved facts, and validate offline metadata against the pinned writable DC/domain identity. Require matching results from native controller eligibility verification, protected workstation backup verification and protected offline rehearsal verification.
- [x] Return exactly the existing one-write provider's operational receipt schema. Synthetic integration with the real gate/provider permits one GUID-only LDAP write for valid evidence and zero writes for a changed rehearsal receipt; injected native verifiers and mock LDAP remain unit fixtures, not live approval evidence.
- [x] Reproduce and fix original-history drift during the final Vault reopening by repeating fresh-state and current-time plan checks afterward. Also refuse missing/changed preparation records, claim, plan, source request, metadata, cipher, password or verifier receipts. All 17 new verifier tests and 119 combined verifier/runtime/reserved/controller/provider/rehearsal tests passed as the service user; four changed Python files compiled.
- [x] Full ALT passed under root with 1405 passed and 1 skipped in 230.97 seconds, including all final tests. Independent follow-up review closed with no remaining actionable findings; complete source/test/doc diff inspection and diff checks passed.

The coordinator must still create the genuine preparation record using the protected producers before this gate can be used operationally. No selected-target claim, password reset, authentication installation or deployment occurred. GitNexus context was requested before source exploration; the transport was unavailable, so the interfaces were verified directly against the narrowly scoped source and tests.

Exact published `ceeb2d67418dc470b74e5cd395def343c2a2c404` ALT CI [38144511995](https://github.com/BorisDruzak/web_ovpn/actions/runs/38144511995) passed. Its full runtime workflow [38144511867](https://github.com/BorisDruzak/web_ovpn/actions/runs/38144511867) retained the same ten previously enumerated independent failures, with 3987 passes and 11 skips.

The preceding reserved-state commit's full runtime CI [38143834137](https://github.com/BorisDruzak/web_ovpn/actions/runs/38143834137) retained the same ten enumerated independent failures, with 3971 passes and 11 skips. No broader runtime-green claim is made.

The fixed preparation coordinator is implemented in `setup_recovery_prepare.py`:

- [x] Accept only the exact current-time executable envelope and confirmed SHA. Under the lifecycle lock, revalidate the public unreserved snapshot, resolve and validate the pinned writable DC's unique IPv4, preserve all five original bytes in an exclusive claim, create the sealed credential once and persist the bound preparation intent.
- [x] Release the lifecycle lock for native coordinated controller backup creation, then reacquire it and revalidate the exact plan, claim, credential, history, registration and DC resolution before creating the private workstation backup and offline rehearsal. No directory password or live authentication file writer is called.
- [x] Exclusively persist the closed preparation record and bound ready marker, then invoke the real operational prewrite gate. Return only plan/preparation/verification hashes; never include a password. Reserved failures append a terminal failed receipt where storage permits and retain all artifacts and exclusions.
- [x] Require the prewrite gate to validate both the exact preparation intent and ready marker before and after artifact verification. Missing-marker regressions failed against the preceding published verifier and passed with the new checks. A visible ready marker after failed persistence is excluded by the terminal attempt receipt.
- [x] Tests cover reservation/retry exclusion, real lifecycle-lock ordering, unchanged original history, native/remote preparation failures, intervening history drift, unsafe/ambiguous DNS and persistence failure. All 13 coordinator tests and 134 combined coordinator/prewrite/reserved/controller/provider/transport/rehearsal tests passed as the service user; four changed Python files compiled. Independent source review found no actionable issues.
- [x] Full ALT passed under root with 1420 passed and 1 skipped in 228.97 seconds, including all final additions. No Python sources changed after collection; full diff inspection and diff checks passed.

The coordinator tests use the real protected stores, credential codec wrapper, controller producer and prewrite gate with fixture Vault/native/remote dependencies. Those tests are not selected-target backups or live domain acceptance. A read-only `getent ahostsv4 localhost` on ALT confirmed the installed output format; resolution tests use synthetic domain names and addresses. GitNexus located the committed controller producer before interface inspection.

This internal coordinator is not exposed as a CLI execution command. The fixed post-write local importer, trust/SSSD/keytab proof, additive Setup continuation, guarded deployment and exact operator execution approval remain required. No selected-target claim, password reset, authentication installation or deployment occurred in this block.

Exact published `39de633896c7ae7a3671739b0d518cd2f33b354f` ALT CI [38145166769](https://github.com/BorisDruzak/web_ovpn/actions/runs/38145166769) passed. Its full runtime workflow [38145166777](https://github.com/BorisDruzak/web_ovpn/actions/runs/38145166777) was still running when this evidence was recorded.

The in-memory offline keytab binding helper is implemented in `setup_recovery_keytab.py`:

- [x] Parse bounded big-endian FILE-v2 entries, accepting only the two expected machine/host principals and reviewed AES128/AES256/optional RC4 key lengths. Require complete AES pairs, unique entries and the native offline current/previous placeholder versions. Reject foreign principals, unknown algorithms, positive input versions, missing extensions and nonzero holes or padding.
- [x] Preserve current encryption key bytes, principal metadata and timestamps; remove previous entries and bind both the 8-bit and 32-bit version fields to the supplied positive directory KVNO. This function only returns bytes; it does not install a file, contact AD or establish trust. Its future caller must derive the KVNO from the verified single-write provider result.
- [x] Observe the initial missing-module RED, then pass 28 new binary-format tests and 29 existing native-helper tests as the ALT service owner. Compile both new Python files successfully.
- [x] Verify the actual installed Samba offline compose/import/password/keytab sequence in a private network-isolated synthetic fixture on the selected disposable PC. Transform the generated 1020-byte keytab to 511 bytes at synthetic KVNO 257 and validate its principals/enctypes/version with the real native keytab-list parser. The original live secrets checksum remained unchanged; the private fixture was removed. No real domain password was reset.
- [x] Full ALT passed under root with 1448 passed and 1 skipped in 229.31 seconds, including all final additions. Independent review found no actionable issues and separately passed all 28 new tests on Windows Python 3.14 with the POSIX conftest disabled. No Python source changed after full-suite collection; complete diff inspection and diff checks passed.

The selected PC reports MIT Kerberos 1.21.3. Its versioned primary [FILE keytab format documentation](https://web.mit.edu/kerberos/krb5-1.21/doc/formats/keytab_file_format.html) supports the binary layout and the 32-bit KVNO extension. Context7 resolved the Kerberos library but returned no matching format documentation, so this versioned primary reference was used. GitNexus was requested before the narrow native/keytab interface inspection; its transport was unavailable.

Exact published `736b301fb55c7e5a2f7fdac562e3e845f037a19b` ALT CI [38145964265](https://github.com/BorisDruzak/web_ovpn/actions/runs/38145964265) passed. The preceding prewrite commit's full runtime CI [38145166777](https://github.com/BorisDruzak/web_ovpn/actions/runs/38145166777) completed with the same ten previously enumerated failures, 4004 passes and 11 skips. No broader runtime-green claim is made.

The fixed local two-file producer is implemented in `setup_recovery_import.py`:

- [x] Require the closed-schema directory-password-written result bound to the same failed run, computer GUID, machine UUID, claim, sealed credential and rehearsal. Require a positive directory KVNO and computer SID in the pinned domain; caller-side protected-result/password authentication remains mandatory for the future transport.
- [x] Hold a root-private nonblocking local install lock and reserve the pair's private import leaf once. Seed the original backup into the existing Bubblewrap native sequence, validate its metadata/password/keytab, bind current keys to the verified KVNO and revalidate the native keytab list. Never call an online join or AD writer.
- [x] Prepare mode-0600 files in their fixed destination directories, retaining original GIDs. Fsync the exact install intent and ancestry before either replacement. Recheck the workstation facts, inactive authentication services and prepared bytes before individually atomic secrets/keytab replacements. Persist separate progress markers and verify unchanged configuration/tool/identity facts and backup bytes afterward.
- [x] Interrupted, corrupt, changed or failed installs remain excluded. Preserve partial installed state and original backup evidence; never retry, silently roll back to obsolete credentials or claim trust from file installation. Receipt status is only `local_credentials_installed`, with `trust_verified=false`.
- [x] Observe the missing-module RED then pass all 36 new tests and 138 combined importer/keytab/rehearsal/backup/native tests as the ALT service owner. Cover binding drift, every native failure, concurrency/unsafe locks, last-moment staged/service changes, intent sync failure and interruption between replacements. Both new Python files compiled; independent source review found no actionable issues.
- [x] Execute the actual native backup/rehearsal/import producer in an isolated root-private filesystem fixture on the disposable PC, using a read-only copy of its original secrets and a synthetic domain/result/password. Both generated credential files and the local receipt verified at synthetic KVNO 257; the original live secrets checksum remained unchanged and the fixture was removed. Service-state responses in this fixture were injected inactive values; this is not live credential installation or trust acceptance.
- [x] Full ALT passed under root with 1484 passed and 1 skipped in 232.05 seconds, including all final additions. No Python source changed after collection; complete source/test/doc diff inspection and diff checks passed.

Read-only service inspection found `sssd` and `winbind` inactive, but `smb` and `nmb` active. The importer intentionally refuses such live state. A separately reviewed fixed quiescence/restoration step, bound to original service-state evidence, must precede any real reset/install; no service was stopped or restarted here.

The installed SSSD configuration has an AD provider, `ad_update_samba_machine_account_password=true` and no explicit password-age override. The versioned [SSSD 2.9.8 AD documentation](https://raw.githubusercontent.com/SSSD/sssd/2.9.8/src/man/sssd-ad.5.xml) and [renewal implementation](https://raw.githubusercontent.com/SSSD/sssd/2.9.8/src/providers/ad/ad_machine_pw_renewal.c) show automatic adcli renewal, disabled by age zero, and default dynamic DNS updates. These effects must be explicitly suppressed/accounted for during the future service-start/trust proof; arbitrary service startup is not a reviewed one-write recovery. Context7 resolved `/sssd/sssd` but found no matching documentation, so the exact versioned primary sources were consulted. No authentication configuration was changed.

Exact published `f680e17ab697d8d76638b658fc9cda51bb871a42` ALT CI [38146863043](https://github.com/BorisDruzak/web_ovpn/actions/runs/38146863043) passed. Its full runtime CI [38146863049](https://github.com/BorisDruzak/web_ovpn/actions/runs/38146863049) retained the same ten enumerated failures, with 4047 passes and 11 skips. The preceding coordinator's full runtime CI [38145964214](https://github.com/BorisDruzak/web_ovpn/actions/runs/38145964214) likewise retained those failures, with 4019 passes and 11 skips. No blanket runtime-green claim is made.

The actual protected controller-to-PC importer transport, service quiescence/start policy, Kerberos keytab authentication, pinned machine trust/identity, SSSD/user proof, additive continuation and operator execution command remain required. No actual recovery claim, AD reset, live credential replacement or recovery deployment occurred.

The fixed service snapshot and stop-only worker are implemented in `setup_recovery_services.py`:

- [x] Bind the exact installed systemd 258.9-alt1 executable, four canonical authentication service units, current PIDs/states and protected unit hashes to the original backup and workstation facts. Refuse queued jobs, pending reloads, overrides, activation/stop propagation edges, automatic uphold and success/failure actions. Pin all five queried outgoing dependency types and require direct dependencies to have `StopWhenUnneeded=no`; hash their canonical fragments and bounded unit-specific drop-ins.
- [x] Share the root-private local install lock, reserve one permanent services leaf per failed-run/computer pair and fsync a bound intent before each fixed `systemctl stop UNIT --job-mode=fail`. Stop only originally active services in the fixed order. Recheck all service/dependency/configuration/backup facts before and after each stop and retain separate progress receipts. Never start, restart, reset failed state, write authentication files or contact AD.
- [x] Retain failed or partially stopped state with a terminal failure marker. Refuse replay and verification with missing/extra/corrupt artifacts. Final status is only `services_quiesced`; restoration, execution approval and protected transport remain future requirements.
- [x] Observe the initial missing-module RED and reproduce all four review regressions against the preceding implementation. Fix missing success/failure actions, `UpheldBy` and dependency cleanup policy checks. All 40 new tests and 100 combined service/import/backup tests passed as the service owner; both new Python files compiled. Independent follow-up review closed all findings with no additional actionable issues.
- [x] Run the final read-only snapshot collector on the disposable PC: the four fixed units and four related dependencies validated, including the built-in system slice's protected drop-in. Authentication facts remained unchanged; SMB/NMB stayed active. No actual stop worker ran.
- [x] Full ALT passed under root with 1524 passed and 1 skipped in 229.91 seconds, including all final additions. No Python source changed after collection; full source/test/doc inspection and diff checks passed.

The exact installed systemd version was checked with RPM. Context7 resolved `/systemd/systemd` but its available documentation was newer, so stop semantics were verified against the versioned primary [unit documentation](https://raw.githubusercontent.com/systemd/systemd/v258.9/man/systemd.unit.xml), [unit implementation](https://raw.githubusercontent.com/systemd/systemd/v258.9/src/core/unit.c) and [dependency atoms](https://raw.githubusercontent.com/systemd/systemd/v258.9/src/core/unit-dependency-atom.c). GitNexus located the committed recovery interfaces before narrow source inspection.

Exact published `02fa07c8e31271aa414fcfa05a86178d4af8cc99` ALT CI [38147872194](https://github.com/BorisDruzak/web_ovpn/actions/runs/38147872194) passed. Its full runtime CI [38147872147](https://github.com/BorisDruzak/web_ovpn/actions/runs/38147872147) retained the same ten enumerated failures, with 4083 passes and 11 skips. No broader runtime-green claim is made.

This internal worker is not exposed as an execution command. The protected transport, safe service-start policy, real trust/SSSD proof, additive continuation, guarded deployment and final execution approval remain required. No actual recovery claim, service stop, password reset, authentication replacement or recovery deployment occurred in this block.

The fixed service transport is implemented in `setup_recovery_services_runtime.py`:

- [x] Provide internal capture/quiesce/verify methods for the selected reserved identity only. Derive the exact backup request from protected source files, verify the complete bound backup receipt and recheck reservation, source bundles and request before and after SSH. No operator command, service name, alternate filesystem root or source selection is accepted.
- [x] Embed only five protected fixed workers and dispatch the operation in the generated program rather than JSON. Use strict host-key checking, an isolated SSH configuration, no proxies, the controller's fixed identity and isolated root Python. Bound input/output/time and reject duplicate JSON keys, nonzero exits, mismatched receipts and drift without exposing diagnostics. No credential plaintext is needed for these service operations.
- [x] Observe the initial missing-module RED, then pass all 17 new tests and 87 combined service/backup/rehearsal transport tests as the ALT service owner. Execute generated capture, quiesce and verify scripts with the real backup/service producers in an isolated synthetic filesystem; fixture injection supplies that filesystem and simulated systemd only inside the test. No actual workstation service is stopped. Both new Python files compiled.
- [x] Independent source review found no actionable findings. The reviewer did not rerun tests or contact hosts. Caller-side exact execution approval and operational prewrite integration remain required.
- [x] Full ALT passed under root with 1541 passed and 1 skipped in 231.83 seconds. No Python source changed after collection; full source/test/doc inspection and diff checks passed.

Exact published `f53f4abc79b488e08968b8be5c9eba8ed0f8a69d` ALT CI [38149061362](https://github.com/BorisDruzak/web_ovpn/actions/runs/38149061362) passed. Its runtime CI [38149061168](https://github.com/BorisDruzak/web_ovpn/actions/runs/38149061168) was still running when this evidence was recorded; its focused identity job passed.

The transport is not a CLI execution route and was not deployed. No selected recovery claim, native recovery backup, real service quiescence, AD password reset or local authentication replacement was performed. Protected importer transport, safe service restoration/start, live trust proof and continuation remain incomplete.

The service-to-writer gate is implemented in `setup_recovery_service_gate.py` and required by the internal password provider:

- [x] Under the controller lifecycle lock, capture the original fixed service snapshot against the verified preparation and persist a closed plan/claim/credential/snapshot/preparation-bound record plus ready marker. Before one remote quiescence call, persist and reread the exact stop intent; retain the exact remote receipt. Failed or partially completed stops remain terminal and cannot be retried or automatically restarted.
- [x] Require the provider's preparation proof to include verified current service quiescence and its receipt hash. The preparation-only gate no longer authorizes a password write. Require a fixed final service verifier after Kerberos authentication, durable write intent and the final Vault opening; immediately afterward compare the original ciphertext document, ready marker and reservation without reopening Vault, then recheck current TTL/source SHA before the sole GUID-only LDAP dispatch.
- [x] The final service verifier preserves the general reserved-state exclusion for an existing AD intent. It separately checks the current-time plan, reserved original evidence, original history bytes, registration, protected preparation/service markers and remote fixed service receipt. It neither deletes nor ignores the write intent, writes AD/authentication files nor claims restored trust.
- [x] Observe the initial missing-module RED and reproduce the preparation-only writer gap. Independently reproduce six review regressions: authentication/final-Vault service drift, stop-intent drift, ciphertext replacement during remote verification, expiry and source drift during the final service check. Also reproduce a self-audit regression deleting the original preparation-ready marker during the final remote verification; recheck both original preparation markers in normal and light modes. All passed after the targeted fixes. Independent follow-up review closed every finding with no further issues; review was source-only.
- [x] Pass 131 combined service-gate/provider/preparation/prewrite/reserved/transport tests as the ALT service owner. Positive integration uses the real protected gate/provider with simulated remote services and LDAP: one GUID-only write for valid evidence, zero writes for changed service or credential evidence. Original five history files remain byte-identical. Verify the actual lifecycle lock with nonblocking flock probes; compile all six changed Python files.
- [x] Full ALT passed under root with 1567 passed and 1 skipped in 251.66 seconds on the final reviewed version. All six Python source/test files matched the local candidate byte-for-byte; no Python source changed after collection. Complete source/test/doc inspection and diff checks passed.

The first broader run exposed a stale reserved-provider test fixture missing the new mandatory service proof (1557 passes, one failure, one skip). Its fixture was updated to supply explicit simulated service proof and final verifier, preserving the original one-write/drift assertions. An initially blocking nested-lock test was interrupted and corrected to a nonblocking lock probe; the production lock was not changed. Neither intermediate run is final acceptance evidence.

Exact published `a8a0887ddb7fb1b4d48a6b5fa7487291f1170b1e` ALT CI [38149571945](https://github.com/BorisDruzak/web_ovpn/actions/runs/38149571945) passed. Its runtime CI [38149571850](https://github.com/BorisDruzak/web_ovpn/actions/runs/38149571850) retained the same ten enumerated failures, with 4140 passes and 11 skips. No broader runtime-green claim is made.

This gate remains internal and is not connected to an operator execution route. Protected importer transport, service restoration/start policy, Kerberos/trust/SSSD proof, additive continuation, guarded deployment and final exact execution approval remain required. No selected recovery claim, real service stop, AD password reset, authentication replacement or recovery deployment occurred.

The read-only post-write state adapter is implemented in `setup_recovery_postwrite.py`:

- [x] Derive inputs from the protected current-time executable plan, permanent reservation, sealed credential, original preparation/service records and exact AD intent/result. Reconstruct the proof hash named by the intent; accept only KVNO original+1 and a later password timestamp. Recheck the current pinned writable DC over GSSAPI with minimum SSF 128, preserving every other computer field including GUID, SID, OU and SPNs.
- [x] Keep the general reserved prewrite exclusion unchanged. The adapter uses the service gate's protected light context only to validate recorded bindings; it does not claim current local service/configuration/backup verification. Its future caller must hold the lifecycle lock and perform separate fixed local checks.
- [x] Validate the exact credential document schema, every reservation identity field and ciphertext SHA without opening Vault. Repeat all protected evidence, current TTL/source SHA and transport settings after the directory read. Refuse terminal attempts, missing or changed intent/result/markers, original history drift and diagnostics exposure.
- [x] Observe 23 initial missing-module RED cases. Reproduce the independent review's three pre-existing credential corruption cases and the self-audit transport-drift case as RED; fix them. Pass 130 combined post-write/service-gate/provider/prewrite/reserved-state tests, including 29 post-write cases. Both added Python files compiled. Independent follow-up source review closed the finding with no additional issues; the reviewer made no host calls.
- [x] Full ALT passed under root with 1596 passed and 1 skipped in 274.03 seconds. Both added Python files matched the reviewed local candidate byte-for-byte by SHA-256; no Python changes occurred after test collection. Complete source/test/doc inspection and diff checks passed.

This adapter does not open Vault, create a claim, reset AD, stop/start services or install credentials. It is not an operator execution route or a protected importer transport. No recovery deployment or selected workstation mutation was performed. Actual importer transport, safe service restoration/start, trust/SSSD proof, additive continuation and final exact execution approval remain required.

Exact published `a1f160e13cebe030e9f5f120daf9c43056b44488` ALT CI [38151337011](https://github.com/BorisDruzak/web_ovpn/actions/runs/38151337011) passed. Its full runtime CI [38151336983](https://github.com/BorisDruzak/web_ovpn/actions/runs/38151336983) retained the same ten enumerated failures: the six production-installer ownership/readiness fixtures, public QEMU evidence owner, inventory CSS cache expectation, synthetic netctl executable format and vpnctl dashboard state. The exact failed-run summary was 10 failed, 4166 passed and 11 skipped in 757.11 seconds. No broader runtime-green claim is made.

The protected local importer transport is implemented in `setup_recovery_import_runtime.py`:

- [x] Derive the selected machine and verified directory result exclusively from the protected post-write adapter. Reconstruct backup, offline rehearsal and service requests from fixed source bundles; reject mismatched receipts, metadata, identity or native version. Accept no operator-supplied password, result, filesystem path, source, worker or command.
- [x] Own the controller lifecycle lock, fsync a permanent bound import intent before Vault opening/SSH, pass password only through bounded stdin and persist the exact local-install receipt. Recheck all protected context/source hashes and intent before and after transport. Verification opens no Vault. Partial/failed intended imports are terminal and retained; no automatic replay, rollback or service startup.
- [x] Embed only eight fixed protected worker sources. Use strict SSH identity/host-key handling, isolated root Python, bounded input/output/time, duplicate-key rejection and exact request/service-request/service-receipt hashes in the program before mutation. The worker verifies actual saved service quiescence, then repeats service/unit/dependency snapshot checks before every fixed inactive check, including between the two authentication file replacements. Post-install verification checks the current inactive snapshot and the genuine local importer receipt; it does not claim trust.
- [x] Observe the initial 12 missing-module RED cases. Pass 135 combined transport/post-write/import/services/rehearsal-transport tests, then all 17 final importer transport tests and compile both Python files. The added nonblocking lock probe confirms the lifecycle lock spans transport, and intent drift during Vault opening prevents SSH and requests terminal failure.
- [x] Execute the generated program with the real protected backup, rehearsal, service and local import producers in an isolated root-owned synthetic filesystem. Native Samba subprocesses/systemd responses are simulated. Valid install plus readonly verify pass; unit-file drift between actual replacements preserves the second original file; substituted wire identity preserves original credentials. Root-worker cases skip under nonroot ownership because the production receipt requires UID0. The initial fixture was corrected to map worker SystemExit to a process return code and to use root-owned files; that intermediate failure is not acceptance evidence.
- [x] Independent source review found no actionable findings, including a final review of exact wire pinning and generated-worker integration. The reviewer did not run tests or contact hosts.
- [x] Full ALT passed under root with 1613 passed and 1 skipped in 273.05 seconds, including all three generated-worker cases. Both added Python files matched the reviewed local candidate byte-for-byte by SHA-256; no Python source changed after collection. Complete source/test/doc inspection and diff checks passed.

This transport remains internal and was not deployed or called on the selected workstation. It does not reset AD, restart services or verify actual domain trust. Safe service restoration/start, Kerberos/SSSD identity proof, execution coordinator/CLI, additive continuation, guarded deployment and final exact execution approval remain required.

Exact published `abbb802ebe87cb8b3b82fe42caba9c2728e26ee3` ALT CI [38152403537](https://github.com/BorisDruzak/web_ovpn/actions/runs/38152403537) passed. Its runtime CI [38152403539](https://github.com/BorisDruzak/web_ovpn/actions/runs/38152403539) was still running when this evidence was recorded; no broader runtime-green claim is made.

The fixed local machine-keytab proof worker is implemented in `setup_recovery_kerberos.py`:

- [x] Require the genuine current local import receipt, original planned klist metadata and the reviewed MIT 1.21.3 package for all three fixed native tools. Hold the same private local import lock; refuse replay through a permanent per-pair intent and retain failure evidence without diagnostics.
- [x] Use a private root-owned configuration with one pinned IPv4 KDC and DNS/canonicalization/forwarding/proxying disabled. Run only fixed machine-keytab kinit, current-cache klist and kdestroy commands in a bounded minimal environment. Accept exactly the machine principal and one current, short-lived realm TGT; destroy the private FILE cache and configuration before returning. No user credential, AD write, join or service startup is exposed.
- [x] Recheck current import/tool/inactive state and protected request/intent around authentication. Independent review found that the intended configuration hash did not revalidate the actual temporary krb5.conf. Reproduce three RED regressions for preauthentication bytes/mode drift and postauthentication drift; fix by checking exact bytes and protected file metadata immediately before kinit and after native calls/guards. Preauthentication drift permits zero kinit calls. Independent final source review closed the finding with no additional issues; the reviewer made no host calls.
- [x] Pass 88 combined Kerberos/import/keytab tests, including 24 Kerberos cases, and compile both added Python files. Observe initial missing-module RED and separately reproduce request/intent drift before fixing protected artifact checks. Retained verification checks evidence/current files only, never reauthenticates or claims a historical ticket remains valid.
- [x] Validate actual MIT klist output, klist -s and kdestroy cleanup against an isolated public, invalid synthetic FILE v4 cache. This is native format/cleanup evidence only; no network authentication, KDC request or genuine ticket was used. The first manual cache encoding used the wrong key-length width and was corrected to the documented 32-bit counted data before the final compatibility test passed.

- [x] Full ALT passed under root on the final reviewed version: 1637 passed and 1 skipped in 275.75 seconds. Both Python files matched the local candidate byte-for-byte by SHA-256; no Python source changed after collection. Complete source/test/doc inspection and diff checks passed.

The interrupted broader run (1356 passes, one skip before KeyboardInterrupt) predates the configuration fix and is not final acceptance evidence. This worker remains internal, unwired and undeployed: selected workstation keytab authentication, protected proof transport, actual trust/SSSD acceptance, safe service startup and final exact execution approval remain required.

The fixed command/configuration and synthetic cache format were checked against the versioned official [MIT 1.21.3 kinit documentation](https://web.mit.edu/kerberos/krb5-1.21/doc/user/user_commands/kinit.html), [krb5.conf documentation](https://web.mit.edu/kerberos/krb5-1.21/doc/admin/conf_files/krb5_conf.html), [klist documentation](https://web.mit.edu/kerberos/krb5-1.21/doc/user/user_commands/klist.html) and [FILE cache format](https://web.mit.edu/kerberos/krb5-1.21/doc/formats/ccache_file_format.html). Read-only inspection confirmed the selected PC's canonical tools and package; no actual recovery operation ran there.

The next protected Kerberos transport must reconstruct the exact eight-source import request and validate its protected intent/result before forming the separate nine-source proof request. Independent design review requires unique current IPv4 resolution of the pinned DC before and after proof, equal to the prepared KDC address; exact wire hashes for proof and both service documents; stopped unit-policy checks before every inactive check; and current TTL/source/reservation/terminal-document checks immediately before SSH and again after receipt persistence. Retained verification is historical evidence only and opens no Vault; any intended proof, including an ambiguous transport timeout, permanently excludes authentication replay. This design review made no host calls and does not authorize execution.

Exact published `abbb802ebe87cb8b3b82fe42caba9c2728e26ee3` runtime CI [38152403539](https://github.com/BorisDruzak/web_ovpn/actions/runs/38152403539) subsequently completed with the same ten enumerated failures: 10 failed, 4195 passed and 11 skipped in 705.64 seconds. Exact published `983c313993730b4d3c2aec8c7e8914d6ad1fe133` ALT CI [38153295269](https://github.com/BorisDruzak/web_ovpn/actions/runs/38153295269) passed; runtime CI [38153295268](https://github.com/BorisDruzak/web_ovpn/actions/runs/38153295268) retained the same ten failures with 4209 passes and 14 skips in 803.49 seconds. These are verified terminal summaries; no full runtime-green claim is made.

The protected Kerberos proof transport is implemented in `setup_recovery_kerberos_runtime.py`:

- [x] Reconstruct the protected importer request with its original eight-source hash; require the exact protected import intent and closed result, including installed file metadata. Form a separate nine-source machine-proof request. Accept no operator-supplied result, password, source, worker, path or command, and never open Vault.
- [x] Hold the controller lifecycle lock; persist a permanent bound proof intent before strict fixed SSH/root Python transport. Embed exact hashes for all three wire documents; the generated worker checks the expected stopped service/unit/dependency snapshot before every fixed inactive check. Decode bounded duplicate-free results and require the selected machine/realm/DC/KVNO identity, closed schema, tool hash and trust_verified=false.
- [x] Recheck the protected AD GUID/SID/OU/password version, original history, claim/reservation, current plan and worker sources before and after transport and after durable receipt persistence. Resolve the pinned DC hostname to its unique current IPv4 address, equal to the prepared KDC address, every time. Independent review identified a final DNS/TTL gap; reproduce two RED regressions changing history or expiring the plan during the last resolver callback. Repeat protected import/source/intent/result checks after DNS, ending with the full deployment fingerprint and current-time plan load immediately before SSH. Both regressions now permit zero remote calls.
- [x] Pass 93 combined proof-transport/worker/import-transport/postwrite tests, including all 23 proof-transport cases, and compile both added Python files. Execute the generated program against genuine local importer/proof evidence in a root-owned isolated filesystem, with native authentication and service snapshots simulated. Valid proof and retained verification pass; changed wire or service policy permits zero kinit calls. Verify repeats no authentication. Nonblocking flock probes confirm the lifecycle lock spans both actions; directory drift during receipt persistence retains terminal failure and excludes replay.
- [x] Independent final source review closed the DNS/TTL finding with no additional issues. The reviewer did not run tests or contact hosts. Observe the initial 17 missing-module RED cases separately from final acceptance evidence.

- [x] Full ALT passed under root on the final reviewed version: 1660 passed and 1 skipped in 282.11 seconds. Both Python files matched the local candidate byte-for-byte by SHA-256; no Python source changed after collection. Complete source/test/doc inspection and diff checks passed.

This transport remains internal and undeployed; no real recovery proof, AD write, credential replacement or service start was performed on the selected workstation. Safe SSSD/service restoration, execution coordinator/CLI, additive Setup continuation, guarded deployment and final exact execution approval remain required.

Read-only inspection reconfirmed SSSD 2.9.8-alt3, enabled Samba password synchronization, no renewal-age/DNS override, an empty conf.d directory and installed `/usr/sbin/sssctl`. The versioned [SSSD 2.9.8 AD provider manual](https://github.com/SSSD/sssd/blob/2.9.8/src/man/sssd-ad.5.xml) documents renewal disabled by age zero and dynamic DNS enabled by default; the [renewal initializer](https://github.com/SSSD/sssd/blob/2.9.8/src/providers/ad/ad_machine_pw_renewal.c) returns before scheduling renewal at age zero. A bounded startup policy and its explicit removal/restoration still need implementation and independent review; no SSSD configuration was changed.

Independent startup design review requires: preserve the original main config and initially empty snippet directory; persist exact evidence/intent before exclusively creating a fixed root600 per-domain snippet; suppress renewal/DNS and pin ad_server without backup/SRV fallback; verify effective values in addition to syntax. Before each service start, validate its start dependency/conflict/action graph separately from the previous stop graph. Start SSSD first, prove an online backend and selected identity rather than accepting a potentially cached getent alone, and recheck AD identity/version plus credential/config hashes. Restore only originally active smb and nmb through individual permanent intents; keep winbind inactive. On any failure, retain the actual state and snippet without automatic replay or password rollback. The original policy must be restored through an explicit terminal step while SSSD is stopped, with fresh trust checks and separately recorded restart effects; the final concrete execution approval must describe this full lifecycle. This review was design-only and did not perform recovery.

Exact published `fb1591e81bddd37fcf4707dda6840ee97d5aed14` ALT CI [38154798838](https://github.com/BorisDruzak/web_ovpn/actions/runs/38154798838) passed. Runtime CI [38154798773](https://github.com/BorisDruzak/web_ovpn/actions/runs/38154798773) was still running when this evidence was recorded; no full runtime-green claim is made.

The fixed local temporary policy worker is implemented in `setup_recovery_sssd_policy.py`:

- [x] Bind the exact retained importer/Kerberos request and receipt without repeating authentication. Check fixed tool versions, protected executable metadata, initially empty nonwritable snippet directory and original root600 main configuration. Under the existing local lock, permanently record the request, original bytes/metadata and intent before exclusively installing the one fixed root600 snippet; never overwrite an existing attempt or auto-remove failed evidence.
- [x] Disable machine password renewal and dynamic DNS, pin the selected AD server, disable DNS site discovery and restrict enabled domains. Require the actual generated configuration database to contain exactly the expected providers/domain/server values with no backup server. Syntax success alone is insufficient. Preserve the original main file and credential files; the receipt explicitly keeps trust_verified=false.
- [x] Run only fixed `sssctl config-check`, `sssd --genconf` and read-only Python LDB commands in a network-isolated bubblewrap sandbox using private configuration copies. Check configuration, database and scratch NSS bytes/metadata around each command. Pin the real root-owned nonwritable LDB module directory, bounded module names, file hashes/metadata and reviewed package versions before and after every native command.
- [x] Native compatibility initially refused the ALT alternatives link absent from the sandbox and the unmapped `_sssd` identity in its single-UID namespace. Recreate only the fixed alternatives symlink inside the sandbox, and bind fixed minimal scratch passwd/group maps for root/_sssd to namespace UID/GID zero. No host NSS or alternatives configuration is mounted writable or changed. This verifies parsing/effective values only; actual daemon ownership and access checks remain required before service start.
- [x] Observe the missing-module RED cases and a separate scratch-configuration-drift RED before adding guards. Reproduce the missing fixed sandbox-path contract as another RED. Independent review identified the host first lookup symlink could select a different module directory; reproduce a retarget-during-command RED, then pin its exact root-owned target with stable metadata and repeated checks around each command. Pass 76 combined policy/Kerberos/import tests, including 16 policy cases and NSS/module/lookup drift refusals. Both Python files compile. Independent final source review closed the P2 finding with no further issues; the reviewer performed no host calls.
- [x] Execute the final worker's `_offline` with synthetic public domain configuration and a documentation-only server address on the selected ALT host: native config-check, genconf and effective LDB read passed. Hashes of real main config and existing config database, actual snippet filenames and SSSD service state matched before/after. This smoke did not call install_once, authenticate to AD, import credentials, or start/stop services.

Full ALT regression passed under root on the frozen final reviewed candidate: 1676 passed and 1 skipped in 282.31 seconds. Both Python files matched the local candidate byte-for-byte by SHA-256 and compiled; complete source/test/doc inspection and diff checks passed. An earlier in-flight full run overlapped replacement of the review candidate and produced 12 policy fixture failures (1663 passed, 1 skipped); it is excluded from acceptance and was replaced by the frozen final run. The worker remains internal and undeployed, and is not a completed recovery workflow. Protected policy transport, service start graph/online identity and Samba trust proof, terminal policy restoration, execution coordinator/CLI and additive Setup continuation remain required before the exact live execution approval gate.

Exact published `fb1591e81bddd37fcf4707dda6840ee97d5aed14` runtime CI [38154798773](https://github.com/BorisDruzak/web_ovpn/actions/runs/38154798773) completed with the same ten enumerated failures: 10 failed, 4232 passed and 15 skipped in 800.84 seconds. Exact published `a3894e6fc553402252ba60097c2f8dae0fdb97a9` ALT CI [38155654192](https://github.com/BorisDruzak/web_ovpn/actions/runs/38155654192) passed; runtime CI [38155654191](https://github.com/BorisDruzak/web_ovpn/actions/runs/38155654191) completed with those same ten failures: 10 failed, 4252 passed and 18 skipped in 571.80 seconds. No full runtime-green claim is made.

The protected temporary policy transport is implemented in `setup_recovery_sssd_policy_runtime.py`:

- [x] Reconstruct the exact retained nine-source Kerberos request and its protected intent/result, preserving the nested eight-source importer request. Form a separate ten-source policy request, never accepting operator-supplied proof, configuration, source, command or worker path. Open no Vault and perform no new authentication.
- [x] Hold the controller lifecycle lock; permanently persist the bound policy intent before fixed strict SSH/root Python. Hash all three closed wire documents. The generated program checks the complete expected stopped unit/dependency snapshot before every fixed inactive check and calls only the reviewed policy install_once or retained verify helper.
- [x] Require the closed receipt to bind GUID/SID/UUID/KVNO, request/tool/snippet hashes and trust_verified=false. Repeat protected AD/history/claim/source/proof checks before and after SSH, and after durable result persistence. Any entered failed attempt remains terminal and cannot be replayed; retained verify installs no snippet, repeats no native parsing or authentication, and starts no service.
- [x] Observe 20 missing-module RED cases before implementation. A final-source history mutation regression initially demonstrated one unwanted SSH call before refusal; repeat the full protected postwrite context after the last source read, then finish with deployment fingerprint/current TTL checks. All three final history/expiry/proof drift cases now permit zero SSH calls. Independent source review accepted the closure with no further issues and performed no host calls.
- [x] Pass 111 combined policy transport/worker/Kerberos transport/import transport/postwrite tests, including all 26 policy transport cases; compile both added Python files. Execute the generated program against genuine retained importer/Kerberos/policy evidence in a root-owned isolated filesystem with native/systemd calls explicitly simulated. Valid install/verify pass; altered wire or stopped-unit policy permits no snippet installation, kinit or service action. Nonblocking flock checks cover install and verify; directory drift during result persistence retains terminal failure.

Full ALT regression passed under root against the frozen reviewed policy transport candidate: 1702 passed and 1 skipped in 287.33 seconds. Both Python files matched the local candidate by SHA-256 before/after the run and compiled; complete source/test/doc inspection and diff checks passed. A separate synthetic size check measured the fixed remote command at 117462 UTF-8 bytes and closed wire at 14225 bytes, both within the checked transport bounds. This transport remains internal and undeployed; no real temporary policy, AD reset, credential import, machine proof or service restoration was executed. The execution coordinator/operator CLI, service startup/online identity and trust checks, terminal policy restoration, additive Setup continuation, guarded deployment and exact final execution approval remain required.

Exact published `297957a20b15532e268542d9f8e8a9a7d78a70fc` ALT CI [38157556122](https://github.com/BorisDruzak/web_ovpn/actions/runs/38157556122) passed. Runtime CI [38157556104](https://github.com/BorisDruzak/web_ovpn/actions/runs/38157556104) was still running when this evidence was recorded; no full runtime-green claim is made.

### Startup transaction and automatic-restart review

Read-only inspection of the selected disposable ALT host confirmed the canonical SSSD unit has `Restart=on-abnormal`, no overrides, `Requires=system.slice sysinit.target`, and `Wants=nss-user-lookup.target`. The lookup target is currently inactive. A corrected bounded, job-labelled diagnostic visited 172 units and 177 possible unit/job pairs, all loaded and with no observed pending jobs. This conservative inventory includes failure actions and precedes native transaction pruning; it is **not** a prediction that all those jobs will execute and **not** startup acceptance. Earlier exploratory counts are excluded: plain whitespace splitting mishandled systemctl's quoted, escaped device unit names. The corrected traversal used quote-aware parsing and an option terminator before unit names, including `-.slice`. These native representation cases require regressions in the eventual collector. All diagnostics performed only `systemctl show`; they did not start or stop anything.

Version-matched systemd 258.9 source review established that an active dependency is not a safe recursion cutoff: transaction expansion precedes redundant-job removal. Fixed `--job-mode=ignore-requirements` can limit the initial rescue start transaction while retaining ordering, but an abnormal automatic restart does not inherit that mode. The native restart path returns to ordinary dependency expansion. A future worker must account for that separate closure rather than claiming the initial mode prevents all later jobs.

Independent design review accepted the following revised preparation direction. The original task excludes changes to production network configuration; the stronger, self-imposed guarantee of no additional local boot/network service jobs is withdrawn. No executable approval is implied:

- Preserve the stock SSSD unit and restart policy. Do not introduce a runtime unit override, `set-property` workaround or manager-wide `daemon-reload`: those would add a separate lifecycle and generator-effect surface.
- Prepare a bounded, job-labelled initial-start and automatic-restart closure, with canonical identities, dependency/conflict directions, stop/restart propagation, activation triggers, hooks/actions, package/source hashes, and explicit possible consequences for each destination. The exploratory diagnostic alone is insufficient for this gate. Overflow, an unreviewed destination or a forbidden configuration effect must refuse execution.
- Include the reviewed closure and native restart semantics in the immutable recovery plan. Final execution approval must explicitly cover those selected-host service effects and the fact that the controller lock does not exclude other manager clients. Never claim snapshots atomically prevent external jobs or generator/process side effects.
- Before the single controller start attempt, require the effective temporary SSSD policy, imported credentials and unchanged AD GUID/SID/OU/KVNO. Retain renewal/DNS suppression through the entire approved lifecycle. No operator-selectable job mode or arbitrary command is permitted.
- Record invocation identity and `NRestarts`; an unexpected restart, invocation change or ambiguous timeout is terminal for the controller attempt. Retain the actual service state, temporary policy and original evidence; do not claim password rollback, automatically replay start, or invent cleanup outside the approved failure protocol.

Primary versioned sources: [transaction expansion and pruning](https://raw.githubusercontent.com/systemd/systemd/v258.9/src/core/transaction.c), [dependency atoms](https://raw.githubusercontent.com/systemd/systemd/v258.9/src/core/unit-dependency-atom.c), [automatic service restart](https://raw.githubusercontent.com/systemd/systemd/v258.9/src/core/service.c), [job-mode documentation](https://raw.githubusercontent.com/systemd/systemd/v258.9/man/systemctl.xml), and [transient-only Restart setter](https://raw.githubusercontent.com/systemd/systemd/v258.9/src/core/dbus-service.c). This review is preparation only; no AD reset, credential import, real temporary policy installation or service start has occurred.

The read-only inventory collector is implemented in `setup_recovery_start_graph.py`:

- [x] Capture a conservative, job-labelled graph for fixed SSSD/smb/nmb roots with separate verification, stop, restart-propagation and event possibilities. Do not stop recursion at active parents or predict transaction pruning. Preserve manager actions as properties; hashing hooks/environment proves observed stability, not review of their effects. Captured restart policies add automatic-restart possibilities for every reached loaded service with restart policy or force statuses, rather than only SSSD.
- [x] Parse native quoted/escaped names without losing device escapes, preserve root mount/slice names and place `--` before every unit argument. Handle native multiple-command execution arrays as ordered hashes. Enumerate all loaded devices through bounded native JSON and resolve complete following families, including siblings and their additional dependencies; refuse cycles, uninspected leaders and enumeration drift. Independent review found the initial leader-only gap and the non-SSSD restart gap; precise RED regressions now pass for both.
- [x] Capture protected unit/drop-in source hashes and packaged origins, retaining local/generated sources as requiring semantic review. Bind the exact native manager lookup paths. A not-found/inactive/no-job endpoint remains explicitly unresolved with file/template absence observations and incoming graph; it is never silently pruned or treated as an impossible future job. Repeat the full capture, authentication facts and source/absence/tool checks under a fixed total deadline and four-MiB envelope bound. A last package-read source mutation was reproduced RED and is now refused by the final source checks.
- [x] Observe 23 initial missing-module RED cases and additional native representation/family/restart RED regressions. Pass all 36 collector cases and 118 combined collector/services/SSSD policy/transport tests under root, including generated-worker cases; compile both new Python files. The non-root combined run had 115 passes and three explicitly root-only skips; the root run replaced those skips with passes. Independent final source review closed both P2 coverage findings with no further issues; the reviewer contacted no hosts.
- [x] Execute the final diagnostic on the selected ALT host using genuine authentication facts and the existing four-service snapshot before and after. One observed capture contained 219 graph units, 277 possible unit/job pairs, 84 device records and 12 unresolved endpoints; its complete envelope was 880620 bytes. Capture plus the after-snapshot took 7.63 seconds. Authentication facts and the complete four-service snapshot were identical before/after; all recorded collector commands were fixed show/list-units or RPM queries. Counts and transient session/scope identities are observations of that capture, not stable fleet identifiers.

This collector reports `startup_inventory_only` and always `execution_authorized=false`. Conservative try-restart/graceful propagation and event labels do not replace a review of native effects. It remains internal and undeployed: the future executable gate must review unresolved destinations, hooks/environment inputs, manager actions, generated-source origins and volatile transient-unit handling. The observed envelope exceeds the old 131072-byte receipt transport limit, and adding further embedded modules approaches the existing SSH argument limit; the future inventory transport needs its own bounded, reviewed wire/bootstrap rather than silently enlarging an existing receipt or appending source code. No credential import, AD reset, temporary real policy installation or service action ran during this block.

Exact published `2e482310505c1053315485bce28c4e5b92e59283` ALT CI [38158362798](https://github.com/BorisDruzak/web_ovpn/actions/runs/38158362798) passed. Runtime CI [38158362807](https://github.com/BorisDruzak/web_ovpn/actions/runs/38158362807) completed with the same ten enumerated failures: 10 failed, 4291 passed and 21 skipped in 749.87 seconds. Exact published `297957a20b15532e268542d9f8e8a9a7d78a70fc` runtime CI [38157556104](https://github.com/BorisDruzak/web_ovpn/actions/runs/38157556104) also completed with those ten failures: 10 failed, 4268 passed and 18 skipped in 783.54 seconds. Both terminal failed-test lists were inspected; no general runtime-green claim is made. These baseline ownership/synthetic-fixture and stale-expectation failures require separately verified corrections before the final delivery gate.

Full root ALT regression passed against the frozen reviewed collector candidate: 1738 passed and 1 skipped in 280.71 seconds. Both new Python files matched the local candidate by SHA-256 before and after the run. Focused root tests, compilation, complete source/test/document review and diff checks also passed. This evidence covers the diagnostic collector; recovery execution and live Setup acceptance remain pending.

### Fixed startup worker implementation boundary

Independent source review of the existing import/Kerberos/policy composition accepted a finite next implementation: one fixed SSSD startup worker and one controller transport. The conservative inventory is retained as an approval attachment; its digest binds the approved effects ledger. It is not a transaction simulator or a runtime promise that external manager clients cannot act. The final execution approval must explicitly cover the selected workstation's possible local service effects and unresolved observations; hashes alone do not review hooks or environment semantics.

- Implement `start_once(request)` and read-only `verify_started(request, receipt)`. The request binds exact plan/approval SHA, failed-run/computer pair, UUID/GUID/SID/KVNO, existing import/Kerberos/policy receipt hashes, fixed source bundle and reviewed effects ledger. No operator-supplied command, path, module name or job mode is accepted.
- Under the shared local recovery flock, run the genuine existing inactive-service verifiers, then check the stopped-unit baseline, stock SSSD source/options/environment, effective temporary policy, imported credential hashes and observed pending jobs. Write the permanent pair-specific request/start intent and repeat immediate guards before one fixed `systemctl start sssd.service --job-mode=ignore-requirements`. No retry, restart, reload or automatic cleanup follows.
- Observe active/running within a fixed bound, a new nonempty InvocationID/MainPID, and unchanged NRestarts. Require repeated stable invocation observations. Command failure, timeout, invocation change or unexpected restart is terminal even if the daemon actually started; retain real state and policy/evidence. A successful startup receipt binds postchecks and says `trust_verified=false`.
- Extract narrow protected-artifact verification and an explicit post-start static projection for retained records, five authentication files, tools, unit and policy hashes. Existing inactive/import pre-start interfaces stay strict. Do not introduce `allow_active`, substitute collect(), or reuse the old stopped-context chain after startup: policy.verify currently reaches kerberos._inactive, and importer.verify compares the full original facts.
- The controller transport holds its lifecycle lock and validates the actual pinned AD GUID/SID/OU/KVNO, original protected history, source fingerprints, TTL and exact approval before SSH, after receipt and after persistence. Its permanent start intent excludes replay after any entered failure. Post-start composition uses the new artifact verifier instead of the old inactive-only context.
- Use a short fixed isolated-Python bootstrap and bounded duplicate-free stdin envelope containing only the exact reviewed module bundle and closed request. The bootstrap pins per-module hashes and validates the entire envelope before exec. Pass the retained effects-ledger digest rather than the complete 880-KiB inventory in the execution request. RED cases cover stalls, size overflow, duplicate keys, source/wire substitution, generated-worker behavior, durable intent drift and ambiguous start outcomes.

Startup is not online user identity, Samba trust or completed recovery. Those functional checks, restoration of only originally active smb/nmb, terminal temporary-policy restoration and immutable Setup continuation remain required. Current approval still authorizes preparation only; no executable recovery route is approved for live use.

### Runtime regression baseline fixture repairs

Three of the ten previously enumerated runtime failures were reproduced on non-root ALT: 3 failed and 28 passed across `tests/test_netctl_client.py`, `tests/test_inventory_endpoint_web.py` and `tests/test_vpnctl_management.py`. The fake netctl executable lacked a shebang; the PC-card test asserted an obsolete CSS revision; the dashboard fixture created only a Windows command wrapper on Linux and consequently observed the host's real systemctl state. The first wrapper correction also reproduced a Windows failure because shell-false short-name resolution did not find the command wrapper.

The final test-only correction supplies the netctl shebang, matches the existing CSS revision, and uses a child-process harness invoking the real vpnctl CLI main with only systemctl launches redirected to a Python fixture. Production parsing and metrics remain in use. Exact captured systemctl arguments prove both calls use the fixture; active/inactive expectations match its output. Final non-root ALT verification passed all 31 tests in 19.00 seconds; Windows verification passed 30 with one platform skip in 30.06 seconds. All three test files compiled, final source hashes matched the ALT copy, diff checks passed and independent final source review reported no findings. No production code or configuration changed. Seven ownership-related baseline failures, full runtime regression and exact published CI remain pending.

Seven previously enumerated ownership failures were reproduced without root: six production-installer fixtures could not assign root ownership, and the public-evidence scenario simulated euid but retained non-root file owners. Running their complete assertions under fakeroot first demonstrated 37 passes. The final fixture uses fakeroot only in the installer child or the single public-evidence child when the caller is non-root POSIX; genuine root runs retain actual ownership operations. The full runtime CI job explicitly installs fakeroot. Production code, verifier ownership checks and existing test selection remain unchanged; simulated metadata is not proof of real elevated permissions. The public-evidence scenario additionally changes one file to UID 10001, observes the unchanged verifier's owner rejection and restores its owner.

A separate ALT-specific false positive occurred because a manifest test prohibited the substring `private` in legitimate `/tmp/.private` artifact paths. The fixture now deliberately includes that path component while checking recursive field names, private-key filename, PEM marker and JSON-escaped complete private material. The assertions retain artifact/trust-anchor checks. Non-root ALT passed all 83 installer/QEMU tests in 13.51 seconds; actual-root ALT passed all 83 in 10.59 seconds. Windows QEMU tests passed 46 with one platform skip in 9.73 seconds. Independent source review found no issues; its PEM escaping clarification was applied and the final QEMU source separately passed 47 cases under non-root ALT and actual root, plus the affected Windows case. Both final test files compiled and matched their ALT scratch copies by SHA-256; diff checks passed. The broader non-root regression remains running against its frozen source snapshot and has revealed additional failures; no full regression-green claim is made. This block performs no live installer, AD recovery, ISO or workstation configuration operation.

The broader frozen non-root ALT regression completed with 6 failed, 4332 passed and 20 skipped in 776.70 seconds. Five failures were test-environment pollution: earlier actual-root runs left source bytecode caches inaccessible to the ordinary test user. Repeating all 13 backup-installer tests with a separate PYTHONPYCACHEPREFIX passed without a source change. The sixth failure was the batch-preview fixture reading host OpenVPN defaults; explicit temporary SERVER_CONF, STATUS_LOG and MANAGEMENT_SOCKET overrides reproduced RED then passed both batch tests on ALT and Windows. All 15 affected ALT cases passed together; compile, matching source hash, diff check and independent source review passed. The three-line test-only correction was published as `07d99f034f5ae757469e0fd50bb40cf95f27b67a` (`test(runtime): isolate batch preview from host configuration`). A fresh full ALT regression with the isolated cache and final test sources is running; no production VPN operation was performed.

Exact `5d29a70af9cabbacf3b6396478169194d82cc438` runtime CI [38162130710](https://github.com/BorisDruzak/web_ovpn/actions/runs/38162130710) completed with 7 failed, 4330 passed and 21 skipped in 786.68 seconds. Its terminal failed-test list contained only the six installer ownership failures and the public-evidence ownership failure addressed by the subsequent `5fb5f8e16c48c48dd40436c016ff1b072b97b7cb` fixture block. CI for that later SHA remained running at this checkpoint; no full-CI success is implied.

### Retained artifacts checkpoint

The baseline repair CI at exact `5fb5f8e16c48c48dd40436c016ff1b072b97b7cb`
and `07d99f034f5ae757469e0fd50bb40cf95f27b67a` subsequently completed
successfully, each with 4337 passed and 21 skipped. Complete non-root ALT
regression at the repaired baseline passed 4338 with 20 skipped in 772.83
seconds. Earlier red counts above are historical checkpoints.

The next narrow implementation exposes separate import/Kerberos/policy
artifact verifiers. Only process observations are excluded from static facts;
retained files, original backup, identities, tools, policy and clock remain
bound. Historical receipts keep trust false. Strict pre-start verification
retains full facts and closes with an inactive-service check. RED during-RPM,
service-activation and collector-command races led to final protected rereads
without further native commands. Independent review closed all findings.

Final focused non-root ALT checks passed 111 cases in 16.40 seconds; the full
final-source actual-root ALT suite passed 1773 with one skip in 292.06 seconds.
Compilation, matching source hashes and diff checks passed. One earlier
incomplete scratch copy failed 28 documentation checks because docs were absent;
the full copy corrected that test-environment error. The new worker/startup
transport/coordinator remain pending. No recovery execution occurred.

### Fixed startup worker checkpoint (2026-10-12)

The internal worker issues exactly one fixed SSSD start after genuine retained
import, Kerberos, policy and quiescence verification. It durably records an
intent before the command and retains terminal failure evidence without replay,
restart, reload or automatic cleanup. Current state checks bind the stock unit,
manager lookup paths, empty jobs, fresh invocation/PID, zero restart count and
all four authentication services. The fixed optional SSSD environment file
must remain absent, including after the final native observation.

The request follows RecoveryPlanStore's actual `recovery-` plus SHA-256 identity
and exact 30-minute aware lifetime. Mutation checks combine remaining plan
lifetime with a 120-second monotonic budget, rechecking wall time around each
native command. Historical read-only verification does not extend execution
authorization. Canonical JSON comparison rejects boolean/integer substitutions
in startup and historical stop records.

Independent review found environment-file and restart-counter gaps (four RED
cases), then immediate retained-intent type drift (two RED cases). Four more
historical service-record type substitutions were reproduced. All were fixed;
final focused non-root ALT verification passed 86 cases in 25.87 seconds,
source hashes matched, compilation passed and final source review found no
remaining issues. Full final-source actual-root ALT regression passed 1819
cases with one skip in 319.94 seconds. An earlier frozen candidate passed
1813 with one skip before the final six type-drift cases were added. Exact
preceding commit `1fad845aa16f2916b8ebdd68c0c8a845b90f2d6c`
has successful managed ALT and full runtime CI.

No operator route or controller transport invokes this worker yet. It does not
prove online identity, Samba trust, restoration of originally active services
or recovery completion. No actual target start or AD recovery was executed.

### Startup transport checkpoint (2026-10-12)

The fixed startup transport carries twelve named worker modules on stdin.
A small argv bootstrap verifies the complete wire SHA, individual module
hashes, closed envelope/request fields, duplicates, non-finite values and
bounded sizes before executing any source. Request size remains 128 KiB;
module text has its existing 128 KiB bound, total wire is limited to 1 MiB,
and replies to 16 KiB. Only fixed start/verify dispatch exists. The reviewed
effects inventory stays controller-side; only its digest is transmitted.

Controller context reuses the genuine post-write/policy chain, derives actual
plan identity/lifetime and sources, validates retained policy/service receipts
and requires an explicit read-only authorization gate with no default. That
future coordinator-owned gate must derive the exact approved unit, source,
effects and approval binding from protected operator authorization. Contexts
are copied before callbacks and revalidated with a fresh full post-write load,
deployment fingerprint and current plan. A permanent controller intent precedes
SSH; failures do not permit replay, including uncertain receipt persistence.

Initial missing-module RED runs covered 23 bootstrap and 16 controller cases.
Review found last-authorization history drift; one RED showed SSH occurred
before late refusal. A second RED exposed mutable cached approval aliasing.
Fresh protected context rereads and copied snapshots now require zero SSH in
both cases. All 46 new transport/bootstrap cases passed on non-root ALT in
16.51 seconds. A child process executes the genuine twelve modules against
private fixture roots/collectors/runners, observes one start, then verifies
without another service action. This is synthetic integration, not live trust.

Final combined non-root transport/worker/policy/post-write/service checks passed
184 tests with three root-only skips in 75.55 seconds. The frozen final-source
actual-root ALT regression passed 1865 tests with one skip in 337.39 seconds.
Windows/ALT compilation and source SHA comparison passed; independent final
source review closed the findings with no further actionable issues. No source
changed during the final runs. Exact published CI remains a separate gate.

The transport is internal and uninstalled. The actual authorization gate,
online user/trust checks, original-service restoration, temporary-policy
restoration and execution coordinator remain required before the final live
plan approval. No actual recovery operation was performed.

### Exact startup approval preparation (2026-10-12)

The internal startup attachment uses its own fixed content-addressed private
plan directory and a 30-minute TTL. It binds the executable recovery plan
ID/SHA/payload, original evidence and registration, employee/computer/OU/DC
identity, deployment fingerprint, twelve protected worker sources, stock
inactive SSSD unit and a closed bounded effects ledger. The ledger contains
the exact controller start, stock automatic-restart/temporary-policy scope,
conservative dependency interpretation, manager-interference limitation,
specific reviewed effects and unresolved observations. An inventory digest
alone is not review. The real collector/review producer remains required;
there is no default ledger or operator JSON execution interface.

The caller supplies both exact confirmed plan SHAs. Before reservation,
`bind_once` rechecks the genuine fresh planning snapshot and retains a fixed
pair-specific approval binding plus durable ready marker under the lifecycle
lock. Existing claims/bindings/failed/revoked markers exclude replacement.
Read-only authorization requires actual protected claim bytes and genuine
post-write continuity; expected KVNO change is checked by the existing
post-write adapter rather than comparing current AD to the pre-write snapshot.
It rereads both immutable plans, original history, registry, source hashes and
binding and returns an independent snapshot. Neither attachment nor stored
binding alone is proof that the future operator coordinator obtained approval.

Review reproduced visible-binding acceptance after failed fsync, an unreserved
mock context, failure exclusion after lock release, a failed-marker creation
failure and visible-marker durability uncertainty. The entered failure handler
now runs before lock release. If creating a failure record is impossible, it
renames only its exact private ready marker to a fixed revoked path, preserves
all bytes and fsyncs the directory. Unconfirmed exclusion durability returns
`recovery_startup_approval_ambiguous`; the workflow must stop for manual state
recovery. No durable cross-crash guarantee is claimed for unwritable storage,
and a future coordinator must never resume an unsuccessful binding.

Initial missing-module RED covered 32 cases. Final focused verification passed
169 tests in 92.42 seconds, including all 48 new approval cases. Full root ALT
regression passed 1913 tests with one skip in 373.99 seconds against a fresh
tracked-tree archive. Compilation of 86 candidate Python files and normalized
Git/remote source hash comparisons passed; final independent source review
reported no actionable findings. The first full run inherited staging umask 077
and failed only the existing base-mode negative fixture (1912 passed, one skipped);
the unchanged fixture's mkdir(0755) became safe 0700. Its five cases and the final
full run passed with explicit umask 022, without source/test changes. Genuine post-write fixture tests
cover expected KVNO success and changed KVNO/GUID/SID/OU/terminal refusal while
retaining the five original history files and opening no Vault.

This remains preparation. Protected inventory production, execution coordinator
and CLI, online identity/trust, original-service and temporary-policy restoration,
additive Setup continuation, guarded deployment and final exact live approval
remain required. No real recovery, controller deployment or target mutation
occurred. Fresh read-only inspection confirmed the selected target's identity,
inactive SSSD with zero restarts and absent keytab/SSSD options file; the selected
AD employee remains enabled. These facts are not recovery acceptance.
Both CI workflows for preceding exact commit
`d9f994ce6a8149f2aea5fffaeee5dcdcc20866bf` completed successfully.

### Native online-check audit (2026-10-12)

[Exact-package source audit](../../verification/ALT_RECOVERY_NATIVE_TESTJOIN_AUDIT_2026-10-12.md)
confirmed the selected ALT release and relevant applied-source paths. Native
testjoin's server option does not enforce one DC, and secrets/cache access can
write scratch state. Independent review confirmed that enforced peer selection
for native testjoin was an additional restriction, not the original L4 scope.
Keep the mandatory independent pinned Kerberos/AD identity checks, then report
native Samba success separately with peer pinning unverified. No network-policy
or peer-enforcement work is introduced. Complete transitive credential-path and
filesystem-sandbox verification before the bounded online worker. No live
testjoin or recovery mutation was performed for this audit.

### Isolated native online worker (2026-10-12)

[Worker verification](../../verification/ALT_RECOVERY_NATIVE_TESTJOIN_WORKER_2026-10-12.md)
records the fixed internal one-shot Samba check with copied scratch credentials,
read-only private configuration mounts and retained startup continuity. Its
receipt explicitly separates native success from enforced-peer and complete
trust proof. Root verification passed all 27 new cases, including real
bubblewrap mount isolation with a synthetic child. Three independent-review
ordering findings were reproduced as RED regressions and closed; final source
review found no new actionable findings. Controller transport, coordinator,
pinned directory/Kerberos proof, employee resolution and terminal service/policy
handoff remain outstanding. No real native authentication or recovery mutation
was performed. Full root ALT regression passed 1940 tests with one original
skip in 397.57 seconds; all 86 controller modules compiled and tested-file
hashes matched. Publication and exact-commit CI are separate from installation.

### Fixed native bootstrap follow-up (2026-10-12)

An internal bounded thirteen-module stdin builder preserves the original
twelve-module startup request binding and adds a separately hashed native
worker. Only native testjoin and retained-result verification are dispatchable;
there is no operator input for commands, no transport or approval default.
Initial 22-case RED became GREEN; final focused startup/native/bootstrap chain
passed 74 tests in 42.75 seconds, including genuine modules in a private fixture,
one synthetic native invocation and no additional service actions. Independent
review found no actionable findings; 87 modules compiled. Full root ALT
regression passed 1963 tests with one original skip in 400.78 seconds against
a frozen candidate tree; tested Git blobs matched staging. Actual controller integration and the remaining
recovery coordinator/CLI/live gates are still required.

### Controller native transport candidate (2026-10-12)

The fixed native runtime now validates genuine retained startup records, the
protected thirteen-source bundle and an explicit caller authorization gate
under the lifecycle lock. It sends only fixed strict-SSH testjoin/verify
bootstrap packets and validates the complete canonical native receipt. Three
late-callback RED regressions were closed; final local runtime suite passed 23
cases and the focused startup/native/controller chain passed 119 tests in
59.11 seconds. Independent review found no remaining concrete findings. All
88 modules compiled and tested Git blobs matched staging. Full root ALT
regression passed 1986 tests with one original skip in 405.68 seconds against
a frozen candidate tree. Runtime publication is separate from deployment. Protected native-authorization
production, reviewed inventory/effects, coordinator/CLI, user resolution,
terminal policy/service handoff, additive Setup continuation and live gates
remain required. No real native recovery operation was executed.

### Explicit native approval candidate (2026-10-12)

Native scope is explicitly selected in the immutable startup attachment and
included in its confirmed SHA. Default start-only attachments stay compatible
and cannot grant native permission. The read-only native authorization handler
requires the same genuine startup gate, protected postwrite history and exact
startup intent/result hashes, source bundle and retained approval binding.
Initial explicit-scope and handler RED cases reached GREEN; independent review
found no actionable source issue. Genuine-postwrite continuity coverage now
includes both attachment scopes. Native-context fixture composition remains
mocked; no real recovery or service action has occurred. Final verification is
recorded in the native worker report. Coordinator/CLI, reviewed inventory/effects,
user resolution, terminal policy/service handoff, additive continuation and
live gates still remain required.

## Task 3: Explicit additive continuation

### Pre-reservation operator inventory checkpoint (2026-10-12)

Ruling: original SSSD policy restoration is a distinct terminal handoff because
it enables normal renewal/DNS effects. The suppressed-state proof stays
historical after that handoff; a fresh terminal verifier and explicit approved
effects are required. This does not authorize network-policy modification.

The operator startup-inventory command collects the existing conservative
systemd graph through a fixed three-module SHA-bound stdin bootstrap. Its
large immutable private evidence is stored separately from Setup plan state;
execution receipt limits stay unchanged. Pre/post genuine recovery snapshots
bind the selected target, AD identities and original history. No recovery
reservation or service action exists in this command. Independent review and
final test evidence are recorded in the startup inventory report. Reviewed
effects production, selected-user resolution, terminal handoff, execution
coordinator/CLI and additive continuation remain required before recovery can
be performed operationally.

The selected-user NSS worker is implemented internally: one fixed SSSD lookup,
protected original getent/NSS-module dependency hashes/packages, retained
native/startup proof, local-duplicate rejection, and permanent entered-failure
exclusion. It does not prove user authentication. Independent review found
and closed missing NSS-module pinning; see the user-observation verification
report. Explicit optional user approval scope now requires native selection,
pins all fourteen sources and original NSS dependencies, and keeps old
approvals unchanged. The combined native gate checks enabled employee identity
before/after through the pinned postwrite directory and ends directory callbacks
with protected local context rereads. Fixed user wire now verifies bounded
duplicate-free envelope/module hashes, startup/native proof links and employee
form before source execution, with fixed check/verify actions only. Controller
binding/transport execution, terminal handoff and the operational coordinator
remain unfinished; the wire builder supplies no authority.
The distinct bounded bundle channel now fixes the demonstrated real-source
stdin capacity gap for startup/native defaults (one-MiB input, original
sixteen-KiB replies). Native-tool/inventory limits and approval ordering remain
unchanged. The real user envelope passes a synthetic subprocess capacity check;
UserRuntime and real recovery still require the remaining gates.

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

## User controller preparation checkpoint

RecoveryUserAuthorization and RecoveryUserRuntime now bind the combined approval,
protected native/startup evidence, employee identity and fourteen source hashes.
Check/verify use fixed bounded SSH and immutable user records; entered failures
exclude replay. Genuine authorizer/runtime joined tests close the interface gap,
while upstream observations and SSH replies remain synthetic. See the user
controller verification report. Production coordinator composition, terminal
handoff, operator execution, complete producer-chain proof and additive Setup
continuation remain required. No recovery execution is authorized by this block.

## Original configured-policy observation checkpoint

The internal original-policy observer now parses the retained main configuration
with no recovery snippet in a fixed sandbox, and can compare the same approved
observation after exact host snippet absence. It preserves original records and
finishes native callbacks with protected rereads. It reports configured values,
not runtime defaults/daemon consumption/trust, and performs no service or snippet
mutation. See the original-policy verification report. Future terminal approval
must pin this source bundle and receipt before any stop/remove/normal start.
Genuine parser compatibility, service lifecycle and fresh post-handoff evidence
remain required; this observer is not the terminal handoff itself.
The independently reviewed terminal contract is recorded in
[the handoff specification](../specs/2026-10-12-alt-recovery-terminal-handoff.md).
Review identified and removed an evidence cycle: before reservation, a new
read-only baseline collector must approve stable original-policy fields without
future import/startup receipts. The post-install observer then reproduces that
projection; its full receipt is bound in the terminal intent. Implementing this
baseline collector is the next prerequisite, not a completed live gate.

## Pre-reservation baseline worker checkpoint

The internal original-policy baseline worker now operates with fresh facts and
empty conf.d, without requiring future import/startup evidence. Its stable
projection matches the later original-policy observer; full post-only receipts
remain terminal-intent evidence. It observes configured values and keeps defaults,
running-policy and trust claims false. See the baseline verification report.
Fixed transport/CLI and immutable source/target approval binding, reviewed ALT
package/default/effect semantics and the terminal service lifecycle are still
required. The worker closes the evidence cycle but does not authorize recovery.

### Read-only original-policy baseline command

The baseline transport and controller service now expose `setup recovery
policy-baseline --failed-run RUN_ID --computer-guid GUID`. It stores a separate
private thirty-minute SHA plan, never reserves recovery and refuses identity,
source, metadata or evidence drift. Its legacy-compatible request context hash
is not a reservation claim. See the baseline CLI verification report. The real
source worker pipeline is composed through bootstrap in fixtures, but native
responses remain synthetic. Actual parser acceptance, reviewed ALT defaults/
effects, terminal approval/service lifecycle, coordinator and Setup continuation
remain required before live recovery can be proposed for execution.

### Original-policy operative effect inventory

The fixed internal inventory worker now observes 30 configured identity/renewal/
DNS fields with explicit presence, all generated section/key names and four
protected runtime dependencies. Unknown keys remain unreviewed. It preserves
existing baseline/suppression interfaces and grants no defaults/effects/execution
authority. See the effect-inventory specification and verification report.
Source review established conditional ordinary adcli hostname/encryption/SPN
reconciliation beyond password renewal. Fixed transport, actual extended parser
acceptance and a closed reviewed effect manifest must precede terminal approval.

### Operative inventory transport and operator command

`setup recovery policy-effects` now uses fixed eight-source bootstrap, genuine
fresh recovery snapshots and a separate non-executable SHA/TTL plan. Baseline
and extended inventory share one native deadline; the controller validates both
closed receipts, helper ownership/packages and configured/unreviewed projection.
The old seven-source baseline stays supported. Shell-safe literal serialization
keeps both fixed programs below the existing 8192-byte remote-command bound.
See the effect-inventory CLI verification report. Actual installed extended
parser acceptance and the closed reviewed normal-policy manifest remain gates;
the new command grants no reservation or execution authority.
