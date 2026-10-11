# Limited ALT partial-join recovery implementation plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox syntax for tracking.

**Goal:** Prepare one reviewed recovery for the operator-selected disposable PC's failed join, preserving the existing computer GUID/OU and every failed setup record.

**Architecture:** Add an explicit, separately confirmed recovery plan and receipt to the existing Setup service. Reuse the existing protected state primitives, lifecycle lock, directory adapter, Vault and fixed execution boundary. One recovery write requires a provider that targets the pinned immutable computer identity atomically; a hostname-only native join is insufficient. Trust recovery never changes the original setup result to success or silently unblocks its replay.

**Tech Stack:** Python 3.12, protected JSON state, Ansible 2.18, ALT alterator-auth 0.55, Samba 4.21.9, sealed Kerberos/GSSAPI LDAP.

**Spec:** Original AD Setup task and operator's subsequent narrow authorization to **prepare and independently review** recovery; current failure evidence in `docs/verification/ALT_AD_SETUP_CLI_ACCEPTANCE_2026-10-11.md`.

**Status:** Preparation only. This document does not authorize infrastructure execution, implement new commands, or prove the unknown Samba failure resolved. No computer reset/delete/move has been performed. Concrete implementation, offline tests, independent code review, exact-SHA publication/deployment and a final operator confirmation of the resulting recovery plan remain required before any recovery write.

**Current execution blocker:** The inspected ALT system-auth/Samba join path selects an existing computer by name; it exposes no verified atomic GUID-targeted password-write contract. Pre/post GUID checks cannot close an external AD replacement race. Therefore that existing path must not execute this recovery. A provider guarantee must first be verified against version-matched primary documentation and the directory's read-only capabilities; if none is available, stop with `recovery_identity_binding_unavailable`. Do not introduce an assumed LDAP GUID/assertion-control or Samba flag as a workaround. This plan remains non-executable until that gate is resolved and reviewed.

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

## Task 2: Fixed one-attempt recovery execution

**Files:** Create `deploy/alt-linux/ansible/playbooks/03-recover-domain-workstation.yml` and `tests/alt_linux/test_setup_recovery_ansible.py`; wire the fixed runner in `setup_recovery.py` without exposing playbook/variables as operator inputs.

**Interfaces:** Consumes only the validated plan and exact attempt identifier. Produces bounded, safe structured identity/trust checks and a terminal receipt; no retry loop.

- [ ] RED: concurrent apply/recovery, drift after lock, object replacement, unapproved OU, source change, insufficient rights, partial AD write, trust failure, unsafe diagnostic capture and lost result.
- [ ] First prove the provider's atomic immutable-target semantics using primary specifications and read-only capability evidence; otherwise keep execution fail-closed. Local locking and name-based joins do not meet that requirement.
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
