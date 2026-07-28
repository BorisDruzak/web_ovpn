# Task 4 report: PR4b QEMU dry-run evidence

## Status

Implementation and all available static/contract verification are complete in
the local worktree. Manual writable/readonly QEMU acceptance is **blocked and
was not run** on this host because its prerequisite probe fails. No QEMU PASS
claim or manual evidence archive is recorded.

PR5 remains blocked until the documented manual Linux/QEMU gate runs
successfully and its non-secret evidence is reviewed.

## Commit

- `757d8a7065109eeca18075e1a4332e0d6a8c19af` —
  `test: prove agent dry-run safety`

## Implemented scope

- Added `deploy/alt-linux/qemu/run-agent-v1-dry-run-acceptance.sh`.
  - It accepts source ISO, static helper, OVMF code/vars, and an evidence
    directory only. It has no target-disk argument.
  - It creates disposable 64 GiB qcow2 backing images under a private
    `mktemp` directory.
  - The writable variant receives a disposable writable qcow2 overlay.
  - The independent readonly variant receives its disposable backing with
    QEMU `readonly=on`.
  - QEMU starts paused so the first QMP snapshot precedes guest execution.
  - Both variants require the exact guest line
    `PASS: signed plan verified; disk preflight passed; no target writes`.
- Added `deploy/alt-linux/qemu/agent_v1_test_api.py`.
  - Generates a temporary Ed25519 keypair.
  - Starts the production install-session API on loopback only.
  - Requires real effective UID 0 and invokes the production approval service.
  - Approves only after the real `waiting_for_approval` heartbeat.
  - Exports only bounded public/root-approval state, never the credential,
    key, raw inventory, plan, signature, or response data.
  - Parses QMP JSON and recursively checks the selected target plus every
    reported `parent`/`backing` block node.
  - Requires `wr_bytes`, `wr_operations`, and every reported integer `wr_*`
    counter to be zero in both snapshots.
  - Requires unchanged backing SHA-256 and both writable/readonly summaries
    before emitting the final exact PASS line.
- Added `tests/test_alt_install_agent_v1_qemu.py` and CI execution/syntax
  wiring.
- Added `docs/ALT_INSTALL_AGENT_V1_QEMU_ACCEPTANCE.md` with the safety
  boundary, manual command, prerequisites, evidence contents, and secret
  exclusions.

No deployment, production API mutation, network-device change, physical-disk
access, or real-disk write was performed.

## TDD evidence

Initial RED:

- `python -m pytest -q tests/test_alt_install_agent_v1_qemu.py`
- Result: `9 failed`.
- Expected reason: the test API/evidence utility and QEMU harness did not yet
  exist.

Nested QMP regression RED:

- Added a transcript whose selected target reported zero top-level writes but
  whose nested backing node reported `wr_bytes=4096`.
- Result before the recursive fix: `1 failed, 9 passed`.
- Expected reason: the first verifier version inspected only top-level target
  statistics.

GREEN after the recursive graph fix:

- `python -m pytest -q tests/test_alt_install_agent_v1_qemu.py`
- Result: `10 passed`.

The contract suite also rejects a changed backing SHA-256, missing target
device, omitted readonly variant, and nonzero top-level target write counter.

## Verification

Fresh pre-commit checks against the staged implementation:

- Agent plus QEMU contracts:
  - `python -m pytest -q tests/test_alt_install_agent_v1.py tests/test_alt_install_agent_v1_qemu.py`
  - `34 passed, 1 skipped`
- Install-session repository/state/auth/signing/service/approval/API/CLI
  contracts with `--noconftest`:
  - `18 passed, 2 skipped`
- Existing managed-ISO spike contract:
  - `14 passed`
- `bash -n deploy/alt-linux/qemu/run-agent-v1-dry-run-acceptance.sh`
  - pass
- `python -m py_compile deploy/alt-linux/qemu/agent_v1_test_api.py tests/test_alt_install_agent_v1_qemu.py`
  - pass
- `git diff --cached --check`
  - pass

The pytest skips are existing platform-dependent cases on Windows. Pytest also
emitted the repository's existing `pytest-asyncio` default-loop-scope
deprecation warning; it did not affect test results.

`go test ./...` was unavailable because Go is not installed on this Windows
host. Task 4 did not change the previously verified Go helper.

Independent safety review initially found that nested QMP `parent`/`backing`
statistics needed recursive validation. The regression and fix above address
that finding. Re-review reported no remaining Critical or Important issue in
scope.

## Explicit manual prerequisite block

The harness prerequisite probe was executed:

```text
agent-v1-qemu: Missing required command: qemu-system-x86_64
agent-v1-qemu: Missing required command: qemu-img
agent-v1-qemu: Missing required command: xorriso
agent-v1-qemu: Missing required command: cpio
prerequisite_exit=1
```

The manual gate additionally needs:

- a Linux host with Python AF_UNIX sockets and real root execution;
- readable regular OVMF code and vars template files;
- the exact pinned ALT KWorkstation 11.4 source ISO;
- the built, verified static Linux amd64 `alt-install-helper`; and
- sufficient workspace for the approximately 10.7 GB source and managed ISO.

Those QEMU/OVMF/source-ISO/helper artifacts are not available in this
worktree. Therefore:

- neither writable nor readonly VM was started;
- the real guest PASS line was not observed;
- no QMP/backing-SHA manual evidence exists to archive; and
- no non-secret manual acceptance bundle was created.

The manual operator must follow
`docs/ALT_INSTALL_AGENT_V1_QEMU_ACCEPTANCE.md` on a suitable isolated Linux
acceptance host. Only the documented sanitized evidence directory may be
archived after review.

## Round 1 fix report

### Commit

- `4a60dfec771f4f7157ab1f9fc8bef7a9b3d088db` —
  `fix: bind QEMU readonly evidence`

### Findings addressed

1. **Readonly was configured but not independently verified.**
   - Root cause: the QMP transcript contained only `query-blockstats`.
     Variant identity came from a caller-supplied summary label, so no
     measured QEMU field distinguished writable from readonly.
   - Fix: every QMP snapshot now includes `query-block` as well as
     `query-blockstats`. The verifier requires the selected target's
     `inserted.ro` to be a strict boolean and binds it to the variant:
     `false` for writable and `true` for readonly.
   - The verifier also requires `inserted.drv=qcow2`. Both measured readonly
     values are preserved in the variant summary, and finalization validates
     them again. A writable summary relabeled `readonly` now fails before the
     final PASS line.

2. **Missing parent/backing statistics could pass as a target-only graph.**
   - Root cause: recursive checking covered every relation that happened to
     be present but had no independent topology contract describing which
     relations must be present.
   - Fix: `query-block.inserted.backing_file_depth` now supplies that
     topology contract. The fixed harness topology is:
     - writable overlay: backing depth 1;
     - readonly fresh qcow2: backing depth 0.
   - Every qcow2 format node implied by that depth must have its
     file-protocol `parent` statistics. Every backing level implied by the
     depth must exist, and a deeper unexpected backing level is rejected.
     All additional reported `parent`/`backing` nodes remain recursively
     checked for zero integer `wr_*` counters.
   - This is fail-closed without requiring a backing relation from the
     legitimate depth-zero readonly qcow2.

3. **The shell harness safety surface lacked executable contract coverage.**
   - The harness now exposes `--describe-safety-contract`, which needs no
     QEMU/root prerequisites and reports values shared with the full runtime:
     no target input, 64 GiB target size, writable qcow2 overlay/backing,
     readonly qcow2 plus `readonly=on`, the fixed managed-ISO builder, and the
     fixed source-identity manifest.
   - Runtime image creation and QEMU drive construction use those same
     target-size, format, and readonly variables.
   - The source identity manifest is an explicit validated regular-file input
     beside the fixed managed-ISO builder.
   - A shell invocation test proves that a caller-supplied `--target /dev/sda`
     is rejected by the real argument parser before any prerequisite or QEMU
     action.

### TDD evidence

RED after adding the Round 1 contracts against the previous implementation:

- `python -m pytest -q tests/test_alt_install_agent_v1_qemu.py`
- Result: `10 failed, 7 passed`.
- Observed failures included:
  - valid QMP transcripts containing `query-block` were not understood;
  - a writable summary relabeled readonly incorrectly emitted the exact PASS
    line;
  - missing required topology relations were not distinguished;
  - `--describe-safety-contract` was rejected as unknown.

GREEN after the fixes:

- `python -m pytest -q tests/test_alt_install_agent_v1_qemu.py`
- Result: `18 passed`.

New regressions cover:

- writable QMP evidence relabeled readonly;
- finalization of a target-only readonly graph;
- missing qcow2 file-protocol parent statistics;
- missing writable backing statistics at reported depth 1;
- legitimate readonly depth 0 with no backing relation;
- executable rejection of a caller-supplied target path; and
- executable reporting of the runtime disposable-target, readonly, and
  pinned-source build contract.

### Verification

Fresh staged verification before the fix commit:

- `python -m pytest -q tests/test_alt_install_agent_v1_qemu.py tests/test_alt_install_agent_v1.py`
  - `42 passed, 1 skipped`
- `bash -n deploy/alt-linux/qemu/run-agent-v1-dry-run-acceptance.sh`
  - pass
- `python -m py_compile deploy/alt-linux/qemu/agent_v1_test_api.py tests/test_alt_install_agent_v1_qemu.py`
  - pass
- `git diff --cached --check`
  - pass

The unchanged manual prerequisite probe still exits 1 and names:

- `qemu-system-x86_64`;
- `qemu-img`;
- `xorriso`; and
- `cpio`.

No real QEMU run, deployment, physical-disk access, or manual acceptance
evidence was performed or claimed in this fix round. PR5 remains gated on the
documented isolated Linux acceptance run.

## Round 2 fix report

### Commit

- `c28a4397eb3468df29340ec5a8352dcf8f254696` —
  `fix: exercise disposable QEMU targets`

### Finding addressed

**The shell safety check described constants but did not execute target
creation or QEMU drive construction.**

- Root cause: `--describe-safety-contract` printed variables that the full
  harness also used, but the test could pass without proving the executable
  relationship between the harness-owned `mktemp` directory, each
  `variant_work` directory, `qemu-img` creation, and the resulting QEMU
  `-drive` value.
- Fix: disposable target preparation and target-drive composition now live
  in shared shell functions called by the full `run_variant` path.
- The safe `--exercise-target-contract` mode creates its own private
  `mktemp` work directory and invokes those same functions for both variants.
  It does not accept a target path, start QEMU, require root, build an ISO, or
  contact any deployment or production service.
- The executable regression test places a recording `qemu-img` double first
  in `PATH` and proves that the shared path:
  - creates both backing files as qcow2 with a virtual size of 64 GiB;
  - creates the writable overlay as qcow2 with its harness-owned qcow2
    backing;
  - points the writable QEMU drive at that overlay without a readonly flag;
  - points the readonly QEMU drive at its independent backing with
    `readonly=on`;
  - derives both variant directories and every target path from the
    harness-owned temporary work directory; and
  - removes the temporary target tree after the exercise.
- The existing executable rejection of caller-supplied
  `--target /dev/sda`, fixed managed-ISO builder assertion, and fixed
  source-identity manifest assertion remain in the focused suite.

### TDD evidence

RED after adding the executable Round 2 regression against the previous
implementation:

- `python -m pytest -q tests/test_alt_install_agent_v1_qemu.py::test_harness_exercises_its_executable_disposable_target_contract`
- Result: `1 failed`.
- Expected reason: `--exercise-target-contract` was rejected with usage and
  exit 2 because no executable contract path existed.

GREEN after sharing target/drive construction and adding the safe exercise
mode:

- `python -m pytest -q tests/test_alt_install_agent_v1_qemu.py::test_harness_exercises_its_executable_disposable_target_contract`
- Result: `1 passed`.

### Verification

Fresh verification before the fix commit:

- `python -m pytest -q tests/test_alt_install_agent_v1_qemu.py tests/test_alt_install_agent_v1.py`
  - `43 passed, 1 skipped`
- `bash -n deploy/alt-linux/qemu/run-agent-v1-dry-run-acceptance.sh`
  - pass
- `python -m py_compile tests/test_alt_install_agent_v1_qemu.py deploy/alt-linux/qemu/agent_v1_test_api.py`
  - pass
- `git diff --check`
  - pass

The unchanged manual prerequisite probe still exits 1 and names:

- `qemu-system-x86_64`;
- `qemu-img`;
- `xorriso`; and
- `cpio`.

No real QEMU run, deployment, physical-disk access, or manual acceptance
evidence was performed or claimed in Round 2. PR5 remains gated on the
documented isolated Linux acceptance run.
