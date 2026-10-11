# Recovery explicit selected-user approval scope

Preparation only. `RecoveryStartupPlans.create(..., native_check=True,
user_check=True)` creates a distinct immutable startup attachment with the
employee GUID/SID/login/UPN, exact fixed NSS lookup, the original protected
getent/SSSD NSS dependency metadata and reviewed packages, and all fourteen
worker source hashes. User selection requires a genuine boolean and native
selection. Existing startup-only/native-only plans gain no employee lookup
permission. Closed-schema loading reconstitutes the exact expected scope;
altered scope, identity, dependencies or sources fail before execution.

The native authorization recognizes the combined scope only through genuine
startup plan validation and the same confirmed binding. For this scope it
reads the employee before and after its continuity checks via the existing
postwrite directory adapter, preserving the writable-DC URI/GSSAPI/SSF guard.
The employee must remain enabled with all four selected identity fields.
The last directory callback is followed by local protected postwrite,
plan/source/history/TTL, startup-record and binding rereads. No employee or
computer write, Vault opening, SSH, service operation or reservation is added.

RED: 21 tests failed before optional user scope existed. One additional test
showed the native gate refused the new explicit combined scope. Six fresh
employee-state/identity cases then failed before the AD guards were added.
Independent review found a final-directory-callback gap: credential or AD-write
evidence could change after the last protected-context check. Both cases
reproduced RED (two failures in 1.54 seconds). The final local context reread
fix was independently reviewed; no further actionable finding was reported.

Tests use genuine protected planning/binding/history fixtures and synthetic
AD/postwrite/startup observations. The directory-config fixture is synthetic;
the real pinned-DC checker is reused in source but no live employee lookup or
recovery acceptance is asserted. User transport/runtime, terminal policy and
service handoff, operator execution coordinator and additive Setup continuation
remain unfinished. The attachment records preparation; it is not an operator
recovery execution command. Final focused scope/startup/native authorization
suite passed **99 tests in 51.23 seconds**; all **91 controller Python modules**
compiled and `git diff --check` passed. Full root ALT regression passed
**2082 tests, one original skip, in 461.71 seconds** against candidate tree
`ee450f6a4904a7c424c90950f3c003a22d8c83f8`. Source/test SHA-256 values matched
the isolated tested copy; only this report changed after the frozen tree.
Exact-commit general CI remains a separate publication check.
