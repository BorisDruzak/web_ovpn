# Recovery fixed selected-user stdin transport

Preparation only. This module builds a bounded fixed bootstrap and JSON stdin
bundle; it does not invoke SSH, obtain approval, reserve an attempt, open Vault,
change directory objects or control services. The future controller runtime
must bind the explicit user attachment, fresh AD employee state, genuine native
receipt and protected lifecycle before and after actual transport.

Fourteen named modules are carried on stdin. The bootstrap hashes the entire
bounded duplicate-free envelope and every module before source execution.
It preserves the original startup source digest over the first twelve modules
and the user source digest over all fourteen. Startup/native receipt links,
false trust/peer-pinning claims, employee identity form, approval digest and the
two fixed actions are checked before loading modules. The genuine user worker
then validates retained native/startup/policy evidence before `getent`.
Employee shape validation is not fresh AD lookup or operator authorization.
The caller owns those gates; this builder cannot infer authority from a receipt.
The actual fourteen-source dictionary alone measured 166880 canonical bytes,
above the generic execution wrapper's 131072-byte stdin limit. The controller
integration must therefore use a separately bounded one-MiB bundle input with
the existing 16-KiB reply limit; the generic native-tool wrapper must retain its
old bounds. This capacity gate is unfinished, not hidden by synthetic dispatch.

Bounds: one MiB envelope, 128 KiB per module/request and 16 KiB per reply.
The bootstrap stays below the existing 8192-byte fixed remote-command bound;
source text never appears in its argv. Only `check` and retained `verify` exist;
there is no login, arbitrary command, service action or credential recovery path.
Malformed input returns only the fixed redacted error code.

RED: missing module caused **33 failures in 0.58 seconds**. The new/native
transport suites initially passed **56 tests in 21.39 seconds**. Tests include subprocess
bootstrap dispatch, duplicate/nonfinite JSON, oversized requests, unexpected
modules, source/proof substitutions, user mismatch and unsupported actions.
Dispatch fixtures use synthetic workers and never inspect the host. A separate
case reads all fourteen genuine module sources and verifies bundle/command
bounds, but does not execute recovery on a workstation. Genuine user-worker
behavior is covered separately by its fixture suite.

An additional check of the complete shell-quoted remote command exposed an
8279-byte command above the 8192-byte limit (two RED failures in 1.09 seconds).
Using a canonical ASCII JSON constant literal instead of Python repr retains
the exact bindings while reducing quote expansion. Measured bootstrap/command:
6726/7610 bytes for check. The strengthened focused suite passed **56 tests in
21.73 seconds**. The earlier full run was intentionally interrupted for this
source fix (824 passed, one skip); it is not a passing full result.

Independent review reported no actionable transport finding, while retaining
the explicit controller/fresh-AD/approval gates as unfinished. All **92
controller Python modules** compiled; `git diff --check` passed. Final full root
ALT regression passed **2115 tests, one original skip, in 478.30 seconds**.
Candidate tree `05c997da7ffa9070d15c515cb1e028a7c6fe53a2` was frozen before
recording the capacity finding and final results; only this report changed
afterward. Source/test SHA-256 values matched the isolated tested copy.
Exact-commit general CI remains separate after publication. This is not live
recovery acceptance or proof of the unfinished controller transport capacity.
