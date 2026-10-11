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
