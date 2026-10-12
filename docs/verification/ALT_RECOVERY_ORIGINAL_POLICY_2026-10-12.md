# Recovery original configured-policy observation

Preparation only. The temporary SSSD policy disables renewal/DNS behavior; its
artifact verifier must not be reused to claim restored ordinary policy. The new
`setup_recovery_original_policy` module separately observes retained original
configuration in the fixed existing three-command bwrap parser sandbox. Scratch
conf.d is empty; host main configuration, temporary snippet, credentials,
services and retained records are unchanged. Private temporary parser files are
created and removed inside the protected policy evidence directory.

`observe` requires the original five policy records, exact temporary snippet,
unchanged main bytes/metadata, genuine retained import/Kerberos evidence and
pinned parser/tool/module inputs. `verify_restored` instead requires an empty
host conf.d, including refusal of dangling symlinks, and exactly matches a
caller-supplied approved observation. This is an internal fixed observer; the
future terminal authority must bind its source bundle and expected receipt to
an explicitly approved plan. Neither function removes a snippet, starts/stops a
service, authenticates an employee or authorizes recovery execution.

The receipt carries only allowlisted configured AD-provider/domain/renewal/DNS
attributes and protected metadata digests. Missing attributes remain empty.
`defaults_verified`, `running_policy_verified` and `trust_verified` are false:
reading config.ldb is not proof of runtime defaults, daemon consumption, allowed
normal renewal/DNS effects or trust. Unsupported configured values refuse the
observation. Exact canonical hashes distinguish boolean flags from integer zero.
Original recovery failure records are neither edited nor removed.

RED: the missing module produced **27 failures in 1.24 seconds**. First GREEN
passed **27 tests in 8.79 seconds**; an invalid Python string escape warning was
fixed. Final focused original-policy plus existing temporary-policy suites
passed **52 tests in 13.65 seconds** without that warning. Negative cases cover
records/bytes/packages/snippets, duplicate/extra/oversized output, syntax and
isolated config/module drift, the final native collector, wrong domain,
unsupported scalar/provider values and changed approved restored receipts.
Independent review found no actionable issue. All **95 controller Python
modules** compiled. Full root ALT regression passed **2197 tests, one original
skip, in 526.90 seconds**. All **255 controller/ALT test Python files** matched
the isolated tested copy by SHA-256. Candidate source/test tree was frozen at
`6f41aae9ed6765bff5e198c935cc7799159de96b`; only documentation changed afterward.
`git diff --check` passed. Exact-commit CI is a separate publication check.
These tests run synthetic parser callbacks; genuine parser
compatibility, terminal service lifecycle, source/approval binding, operator
execution and fresh selected-machine acceptance remain unverified.
