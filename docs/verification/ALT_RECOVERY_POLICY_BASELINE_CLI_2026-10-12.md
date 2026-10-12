# Recovery original-policy baseline operator CLI

Preparation only. `workstationctl setup recovery policy-baseline --failed-run
RUN_ID --computer-guid GUID` now derives the registered machine and existing
employee/OU from the original protected failed history. It gathers original
configured SSSD policy over fixed strict SSH, stores a private SHA-bound plan
with the existing thirty-minute TTL, and prints `Execution available: false`
and `Defaults verified: false`. It does not reserve an attempt, open a recovery
credential, create a workstation backup, remove a snippet or start a service.
Old Setup/AD/configure commands remain unchanged.

The fixed stdin envelope binds seven modules and a closed baseline request.
Duplicate/nonfinite/oversized JSON, module/source/facts/metadata mismatches are
refused before source execution. The real quoted SSH command stays below 8192
bytes; input is limited to one MiB and replies to sixteen KiB. The worker has
one shared 120-second native/collector deadline, with a 150-second controller
transport bound. Error output is fixed and redacted.

Runtime binds registry UUID/hostname/IP/raw hash, snapshot, source bundle,
request digest, original config metadata and the closed false-claim receipt.
Service repeats genuine snapshot/DC-resolution/source reads under the controller
lock before and after its own plan. Invalid DC hostname is rejected before DNS
lookup. Changed employee, registration, facts, DC or source bundle refuses the
plan. The legacy backup-schema `claim_sha256` slot is only a scope-tagged
read-only snapshot context hash here; no reservation is created and provider
claim/credential guards remain mandatory. This frame is never claim evidence.

RED: missing transport module produced **23 failures in 1.34 seconds**; transport
GREEN passed **23 tests in 7.12 seconds** after fixing a string-escape warning.
Runtime/service module RED had **21 failures in 1.40 seconds**, then **21 passed
in 6.41 seconds**. CLI and pre-resolution host checks had **three failures in
1.18 seconds**. A source-change callback after the final directory snapshot
produced **one failure in 0.66 seconds**; fresh source rereads closed that gap.
Final combined transport/runtime/CLI plus baseline/original/temporary-policy,
old CLI and startup-inventory suites passed **149 tests in 37.36 seconds**.

Independent source review found no actionable issue. All **98 controller Python
modules** compiled, CLI help and `git diff --check` passed. A genuine worker
pipeline runs through bootstrap against real fixture files with synthetic
collector/native parser responses and preserves those files. This closes the
source/interface composition gap, not actual package/parser or selected-PC
acceptance. Full ALT regression passed **2270 tests, one skipped in 549.21
seconds** against frozen candidate tree
`083cd382902ec32e6957f2b1cd6a2c3735a8301e`. All **262 controller and ALT test
Python files** matched the isolated tested copy by SHA-256. Only documentation
changed after that freeze. Exact-commit CI remains a publication gate.
Future terminal approval must bind a fresh snapshot and stable baseline
projection, plus independently reviewed default/effect semantics. The terminal
service lifecycle, execution coordinator and additive Setup continuation remain
unfinished; no real recovery or controller deployment occurred in this block.
