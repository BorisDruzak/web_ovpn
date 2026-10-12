# Recovery bounded source-envelope channel

Preparation only. The real fourteen-source user envelope exceeded the generic
native-command wrapper's 128-KiB stdin bound. Reusing that wrapper would refuse
the request before bootstrap execution. A separate `bounded_bundle_run` now
accepts at most one MiB of UTF-8 stdin while preserving the existing 16-KiB
limits independently for stdout and stderr, deadlines, process-group retirement
and diagnostic redaction. The common process implementation is unchanged.

SSSD startup and native controller runtimes choose this channel explicitly
when no runner is supplied. An explicitly injected runner remains unchanged;
the parent/native-tool runner is not enlarged. The old native-command wrapper,
inventory envelope and systemctl property wrappers retain their original
bounds. Authority/context/intent ordering and fixed strict SSH construction
are unchanged. No directory write, service action, reservation or live SSH is
performed by this source change or its tests.

RED: **seven failures in 0.39 seconds** demonstrated missing channel support
and both default runtimes refusing the larger input. Final focused
process/startup-runtime/native-runtime/user-wire suites passed **98 tests in
31.21 seconds**. New cases verify one-MiB input admission, pre-spawn oversized
refusal, independent stdout/stderr overflow redaction, a blocked stdin writer's
deadline and runtime-default capacity while the inner runner still refuses
larger input. The real fourteen-module user bundle is sent through the channel
to a synthetic subprocess byte counter and refused by the old wrapper. This
proves stdin capacity without running the genuine worker or connecting to a PC.

Independent review reported no actionable finding. All **92 controller Python
modules** compiled and `git diff --check` passed. Full root ALT regression
passed **2122 tests, one original skip, in 481.81 seconds** against candidate
tree `05ad7c0f47c6cb1e709c826fc0f824201fd20058`. Source/test SHA-256 values
matched the isolated tested copy; only this report changed after the frozen
tree. Exact-commit general CI remains a separate publication check.
Controller UserRuntime/approval binding, terminal policy/service
handoff, operator execution and additive Setup continuation remain unfinished;
this fixes the capacity gate, not live recovery acceptance.
