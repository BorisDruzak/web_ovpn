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
