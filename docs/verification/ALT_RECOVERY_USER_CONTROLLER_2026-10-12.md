# Recovery user controller authority and transport

Preparation only. `RecoveryUserAuthorization` now binds the combined explicitly
approved user scope to the genuine native/startup authorization chain, selected
employee identity, fourteen source hashes, original NSS dependency metadata and
protected startup/native receipts. It repeats authority callbacks and finishes
with local protected-state rereads. Native failure markers, changed receipts,
revoked bindings, disabled employees and a native-only approval refuse the check.

`RecoveryUserRuntime` requires explicit caller-owned authority. The future
production coordinator must supply `RecoveryUserAuthorization`; no CLI or
authority default is introduced. Fixed strict SSH transports the fourteen-source
bundle with a one-MiB stdin limit and independent sixteen-KiB reply limits. The
quoted command is checked before intent. Protected intent/result/failure records
bind the plan, request, source set and authority. Entered failures permanently
exclude a new check; verify reuses retained proof without creating a new attempt.
Worker receipts require bounded nonzero UID/GID, exact proof links and tool
metadata; login and online-authentication claims remain false. No user password,
GUI login, home creation, directory write or service handoff is performed here.

RED: missing authorization module produced **14 failures in 8.80 seconds**;
missing runtime produced **18 failures in 0.42 seconds**. The first GREEN runs
passed **14 tests in 10.41 seconds** and **18 tests in 11.30 seconds**. Five
additional callback-drift tests refuse SSH after changes to native result,
user intent/failure, protected context or sources. Joined controller integration
adds genuine UserAuthorization, UserRuntime, NativeAuthorization and
StartupAuthorization against protected records. It checks retained check/verify
proof and employee disablement immediately after intent persistence.

Final focused user authority/runtime/integration plus existing native authority
and runtime suites passed **77 tests in 50.67 seconds**. Independent review found
no actionable issue. The joined tests still substitute startup/native context
observations and SSH receipts; the genuine remote worker does not execute. They
prove interface composition, not the entire protected producer chain, live NSS,
trust, user authentication or selected-PC acceptance.

All **94 controller Python modules** compiled. Full root ALT regression passed
**2161 tests, one original skip, in 509.15 seconds** against candidate tree
`f9ec848b3de148cf6a695b6636c95cef2b53748d`. All **253 controller and ALT test
Python files** matched the isolated tested copy by SHA-256. Only this report
changed after the frozen tree. `git diff --check` passed. Exact-commit general CI
remains a separate publication check. Terminal
policy/service handoff, production coordinator, operator execution and additive
Setup continuation remain unfinished. Recovery has not been executed or deployed.
