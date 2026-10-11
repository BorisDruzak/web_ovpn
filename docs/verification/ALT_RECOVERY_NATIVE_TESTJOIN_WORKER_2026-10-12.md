# Recovery native Samba check: internal worker

This block adds a one-shot internal worker and protected verifier. It is not
controller transport, an operator command, a complete recovery coordinator or
live acceptance. No selected workstation recovery or actual AD authentication
was performed for this block.

## Behavior

The worker requires the genuine retained SSSD startup request and receipt,
unexpired approval, exact reviewed executable bytes and package versions. It
reserves a protected pair-specific evidence directory under the existing
recovery lock. An entered failure permanently excludes replay; retained failed
evidence is not automatically removed.

The fixed `net ads testjoin` command runs in bubblewrap using a private copy of
the imported Samba secret. Private NSS, DNS, Kerberos and Samba configuration
replace host inputs; configuration mounts are read-only. Host keytab, Samba
state, SSSD configuration and runtime sockets are absent. Scratch authentication
state may be written inside the isolated directory and must be removed before
the retained verification receipt is committed. Host credentials, services and
directory objects are not written by this worker.

Protected request/intent records and pinned scratch inputs are checked after
the last command-producing preflight, immediately before native invocation.
Postchecks require the same live credentials, retained startup/service state,
tools and original evidence. Final verification performs tool queries before
the genuine startup verifier and rereads canonical evidence afterward.

Native Samba discovery does not enforce a single peer. Its receipt explicitly
retains `native_testjoin_peer_pinning_verified=false`, `trust_verified=false`
and `temporary_policy_retained=true`. Mandatory pinned Kerberos and fresh AD
GUID/SID/OU/KVNO continuity, employee resolution and terminal policy/service
handoff remain separate coordinator obligations. The exact-package source audit
is recorded in [the preceding audit](ALT_RECOVERY_NATIVE_TESTJOIN_AUDIT_2026-10-12.md);
it is not binary attestation or proof of every transitive native call path.

## Verification and independent review

- Initial missing-worker RED: 15 failures; initial GREEN: 15 passes in 14.36 s.
- Root sandbox expansion: 18 passes in 16.71 s, with the real bubblewrap probe
  executed rather than skipped. This probe uses a fixed Python child, synthetic
  private configuration and no real AD credentials or authentication.
- Six RED regressions reproduced scratch replacement during guards and live
  artifact drift after final tool queries. Corrected root suite: 24 passes in
  24.21 s.
- Standalone source namespace RED reproduced relative-import incompatibility;
  explicit trusted native dependency injection passed with 25 root cases.
- Two RED regressions reproduced final startup-callback request/intent drift:
  2 failures in 2.53 s. Both now require zero native invocations.
- Final root worker suite: `python -m pytest -q --tb=short
  tests/alt_linux/test_setup_recovery_native_testjoin.py`: **27 passed in
  24.95 s**. Authentication success/error cases use a fixed synthetic runner;
  the real sandbox test separately verifies mount isolation.
- Independent reviewer closed all three concrete ordering findings and found
  no new actionable source findings. Review does not establish live recovery.

- Full root ALT regression: `python -m pytest -q --tb=short tests/alt_linux`:
  **1940 passed, 1 skipped in 397.57 s**, with explicit staging umask 022.
  The new real bubblewrap probe executed. The original unrelated skip remains.
- Compiled all **86 Python modules** under `deploy/alt-linux/control/alt_deploy`.
  Local and tested worker/test file SHA-256 values matched exactly;
  `git diff --cached --check` passed. The tested copy is the tracked baseline
  archive plus these two candidate source/test files.

Publication does not install this internal worker. Exact-commit CI remains a
separate check after publication. Controller integration, exact protected
execution plans, guarded deployment and final live execution approval remain
outstanding.

## Fixed native bootstrap follow-up

The additional internal stdin builder dispatches only `testjoin` and `verify`.
It validates a closed bounded envelope, its full SHA and all thirteen module
hashes before compiling any source. The original retained startup request
continues to hash the first twelve modules; the thirteenth native module is
bound separately by its module hash and the full envelope. No startup receipt
or approval is rewritten. The future controller must read every source through
its protected source reader and bind the deployed fingerprint and exact
approval; the builder alone provides no execution authority or transport.

Initial missing-module RED: **22 failures in 0.45 s**. First GREEN: **22 passes
in 7.93 s**. The expanded suite passed **23 cases in 9.49 s**, including genuine
thirteen-module bootstrap and retained-result verification in a private fixture.
The final focused chain (`test_setup_recovery_native_wire.py`,
`test_setup_recovery_native_testjoin.py`, `test_setup_recovery_start_wire.py`)
passed **74 tests in 42.75 s**. Its genuine-bootstrap fixture verifies one
synthetic native invocation, removed scratch, unchanged startup request and zero
service actions during native execution/verification. No AD authentication
occurs in that fixture.

Independent source review found no actionable findings. All **87 controller
Python modules** compiled. Full root ALT regression against frozen candidate
tree `139baa14c945959b78d537ac9f78a433883fdedb` passed **1963 tests, one original
skip in 400.78 s**. Tested source/test Git blob hashes matched the staged files.
Publication is separate from installation; controller integration remains next.

## Controller transport candidate

The internal controller runtime uses the lifecycle lock, genuine retained
startup context/receipt checks, protected thirteen-source loading and mandatory
caller-supplied exact native authorization. The authorization binds the recovery
plan, full source bundle, startup request/receipt, startup approval and effects
ledger; there is no default authority. Its fixed SSH transport retains strict
host-key verification and carries the bounded bootstrap sources on stdin.
Native receipt validation binds exact tool metadata/package digest and refuses
complete-trust or enforced-peer claims. No Vault, AD write or service action is
introduced by this transport.

Initial missing-runtime RED: **14 failures in 0.46 s**; first GREEN: **14 passes
in 6.51 s**. Three late-startup callback regressions reproduced native approval,
thirteenth-source and failed-marker drift before SSH: **3 failures in 1.65 s**.
Corrected final checks reread native authorization, protected sources and full
local postwrite history, deployment fingerprint, exact plan dates/SHA/payload,
startup records and the permanent native failure marker before SSH. The final
expanded suite passed **23 tests in 10.11 s**, including late native-authorization
callbacks and postpersist failure exclusion. Independent source review closed
the findings and found no new actionable issue.

Final focused runtime/native/startup chain passed **119 tests in 59.11 s**.
These runtime fixtures mock authorization/postwrite state and SSH; they are not
real AD or infrastructure acceptance. All **88 controller Python modules**
compiled; tested candidate source/test Git blobs matched staging. Full root ALT
regression against frozen tree `558050b4211b4ae1b08b8d318479d815e143c08e`
passed **1986 tests, one original skip in 405.68 s**. Runtime publication remains
separate from installation and exact-commit CI. Complete state-storage unavailability remains a boundary of
best-effort terminal error recording and requires manual state recovery.
