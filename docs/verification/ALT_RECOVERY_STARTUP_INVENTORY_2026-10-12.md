# Recovery operator startup inventory

Preparation only: `setup recovery startup-inventory --failed-run RUN
--computer-guid GUID` reads the one history-selected PC and creates its own
protected evidence/summary plan. It cannot reserve an attempt, reset AD,
install credentials, start/stop services or approve execution.

The existing graph collector is transported on stdin with its probe/process
dependencies. The fixed isolated Python bootstrap checks a bounded duplicate-
free envelope and all module hashes before compiling any source. SSH retains
strict host-key checking, explicit key/known-hosts paths and a 60-second outer
deadline. Inventory transport has separate 1-MiB input/4-MiB output bounds;
native property reads have a 64-KiB bound. Existing execution wrappers retain
their old 128-KiB input/16-KiB output bounds and process-group timeout behavior.

The 4-MiB graph cannot fit the existing 512-KiB Setup state contract. It is
stored as private immutable 128-KiB ASCII chunks with individual hashes and a
last-written manifest, plus the full canonical document hash/byte count.
Incomplete, substituted or extra files fail closed. The summary plan uses
ordinary protected SetupPlanStore TTL/SHA semantics in a separate namespace.
Planning rereads the genuine recovery snapshot before and after capture and
after evidence persistence; all five failed-history files remain unchanged.

Initial new process-wrapper RED: three failures; final process suite passed
13 tests in 2.22 seconds. Initial missing inventory module RED: 14 failures in
0.45 seconds. Initial CLI dispatch RED: one failure. Two additional regressions
exposed missing-evidence reads creating directories and boolean manifest
schema acceptance; both were fixed after observing RED. The combined
inventory/collector/process/CLI suites passed 71 tests in 2.48 seconds.

Fixtures include genuine protected history/planning and existing graph
collection with synthetic directory/native responses. The subprocess bootstrap
uses synthetic source bodies for large-result and source-substitution cases;
that does not prove actual selected-host capture or real AD acceptance. An
additional bootstrap case loads all three actual modules with fixture probe/
native responses and produces the exact genuine graph, preserving fixture
file bytes. Independent source review found two concrete issues: inherited
SSH config and directory recreation during a disappearing-leaf read race.
Both were reproduced (two failures in 0.39 seconds) and fixed: SSH now uses
`-F /dev/null`, `ProxyJump=none` and `PermitLocalCommand=no`; evidence reads
perform pure metadata validation without mkdir. No other concrete finding was
reported. The final focused suite passed **73 tests in 2.55 seconds**.

All **90 controller Python modules** compiled; actual CLI help returned zero
and displayed only the fixed failed-run/GUID inputs. Tested source/test SHA-256
values matched staging. No live service or recovery operation was performed.
Full root ALT regression against frozen candidate tree
`2366f2fcf8755023683d65eae3cea7aa06163103` passed **2029 tests, one original
skip in 409.86 seconds**. `git diff --check` passed. Only the verification
report was extended after the frozen tree; tested source/test files did not
change. General exact-commit CI remains a separate check after publication.

Installation, actual selected-host capture, semantic effects review, employee
resolution and terminal service/policy handoff remain separate work. This
operator command supplies evidence for those gates and cannot execute recovery.
