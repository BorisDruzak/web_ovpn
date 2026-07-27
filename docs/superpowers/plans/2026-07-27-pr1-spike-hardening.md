# PR1 Spike Hardening Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Make the ALT 11.4 managed-ISO technical spike internally consistent and prove its fail-closed hold before merge.

**Architecture:** Keep the proven initrd `post/network-up` hook as the single early integration point. The fixture becomes a test-only state observer; the agent reports progress and heartbeats, while the QEMU harness validates those reports and zero target-disk writes. The ISO verifier validates the embedded initrd payload rather than only boot menus.

**Tech Stack:** Bash/initrd, Python stdlib HTTP server, pytest, xorriso, cpio/gzip, QEMU/QMP.

## Global Constraints

- PR1 remains a no-write spike: no Alterator, `ai`, `curl=`, installer, partitioning, or target-disk writes.
- Managed flow is UEFI-only; Syslinux retains only vendor/manual boot choices.
- GRUB default is local disk with a 10-second timeout.
- Fixture endpoints are test-only and accept bounded, validated payloads only.
- PR2 is not started by this plan.

---

### Task 1: Align the documented initrd boundary

**Files:**
- Modify: `docs/ALT_MANAGED_ISO_TECHNICAL_SPIKE.md`, `docs/superpowers/plans/2026-07-26-alt-managed-iso-pr1.md`
- Modify: `deploy/alt-linux/iso/manifests/alt-kworkstation-11.4-install-x86_64.json`, `deploy/alt-linux/iso/inspect-upstream-iso.sh`
- Test: `tests/alt_linux/test_managed_iso_spike.py`

**Interfaces:**
- Produces manifest field `runlevel_dispatcher_sha256` for `/etc/rc.d/rc`.
- Documents `lib/initrd/post/network-up/99-sosnadmin-spike` as the blocking hook preceding `bootchain`.

- [x] Write a failing test requiring `runlevel_dispatcher_sha256`, the exact hook path, and no `rc.sysexec` claim.
- [x] Rename the manifest/inspector key and update the documentation and original plan to describe the observed runlevel sequence.
- [x] Verify the test passes and the inspector still verifies the pinned upstream ISO.

### Task 2: Make boot support and timeout explicit

**Files:**
- Modify: `deploy/alt-linux/iso/boot-menu/grub.cfg.patch`, `deploy/alt-linux/iso/boot-menu/isolinux.cfg.patch`
- Modify: `deploy/alt-linux/iso/verify-spike-iso.sh`, `docs/ALT_MANAGED_ISO_TECHNICAL_SPIKE.md`
- Test: `tests/alt_linux/test_managed_iso_spike.py`

**Interfaces:**
- GRUB contract: `set default=harddisk`, `set timeout=10`, one managed UEFI entry.
- Syslinux contract: no `sosnadmin.mode=spike` entry.

- [x] Add failing assertions for timeout `10` and absence of the managed Syslinux entry.
- [x] Patch GRUB and remove the Syslinux managed entry while preserving manual ALT boot.
- [x] Extend the verifier assertions and run focused tests.

### Task 3: Add fixture state reporting and minimal inventory validation

**Files:**
- Modify: `deploy/alt-linux/install-agent/lib/protocol.sh`, `deploy/alt-linux/install-agent/spike-agent`
- Modify: `deploy/alt-linux/install-agent/spike-server/server.py`, `deploy/alt-linux/install-agent/spike-server/repository.py`, `deploy/alt-linux/install-agent/spike-server/ctl.py`
- Test: `tests/alt_linux/test_managed_iso_spike.py`

**Interfaces:**
- `POST /spike/v1/sessions/<session>/state` accepts `{"state":"agent_started|inventory_ready|waiting_for_approval|spike_approved"}`.
- Repository records an ordered bounded state history and the fixture rejects malformed inventory without `machine`, `boot_media`, and `build_id`.

- [x] Write failing Python tests for valid state transitions, two approved heartbeats, unknown state rejection, nonnumeric `Content-Length`, and minimal inventory rejection.
- [x] Implement bounded state storage and strict request parsing; return 400 for malformed length or schema.
- [x] Report each state from the agent; make `spike_hold` report `spike_approved` every 5 seconds after approval.
- [x] Run the fixture and agent tests until green.

### Task 4: Make networking retry safely

**Files:**
- Modify: `deploy/alt-linux/install-agent/lib/network.sh`, `deploy/alt-linux/install-agent/lib/dhcp-hook.sh`
- Test: `tests/alt_linux/test_managed_iso_spike.py`

**Interfaces:**
- `request_dhcp()` ignores `lo` and repeats bounded DHCP/route attempts until a controller route appears.

- [x] Add a failing test that requires the explicit `lo` skip and retry loop.
- [x] Implement the retry loop without returning control to installer flow on failures.
- [x] Run Bash syntax and focused tests.

### Task 5: Verify the embedded initrd contract

**Files:**
- Modify: `deploy/alt-linux/iso/verify-spike-iso.sh`, `deploy/alt-linux/iso/build-spike-iso.sh`
- Test: `tests/alt_linux/test_managed_iso_spike.py`

**Interfaces:**
- Generated adjacent `<iso>.build-manifest.json` binds the pinned source SHA-256, generated ISO SHA-256, and embedded initrd SHA-256 to a format version.

- [x] Add failing verifier tests for missing hook, agent, library, bad mode, forbidden installer token, and missing build manifest.
- [x] Extract `/boot/initrd.img`, check gzip/newc, extract required payload paths, modes, exact hook content, hashes, and forbidden tokens.
- [x] Generate and validate the build manifest; run verifier against the real rebuilt ISO.

### Task 6: Harden the builder lifecycle

**Files:**
- Modify: `deploy/alt-linux/iso/build-spike-iso.sh`
- Test: `tests/alt_linux/test_managed_iso_spike.py`

**Interfaces:**
- Builder removes its exact temporary output on any error and fails before build when the output filesystem lacks space for source ISO plus 512 MiB.

- [x] Add failing tests for `trap` cleanup and portable `df -Pk` capacity validation.
- [x] Implement same-filesystem free-space check and exact temporary-output cleanup.
- [x] Run a forced real build and static verifier.

### Task 7: Prove approved hold in the QEMU acceptance harness

**Files:**
- Modify: `deploy/alt-linux/qemu/run-spike-readonly-acceptance.sh`, `docs/ALT_MANAGED_ISO_TECHNICAL_SPIKE.md`
- Test: `tests/alt_linux/test_managed_iso_spike.py`

**Interfaces:**
- Harness waits for `waiting_for_approval`, approves, then requires at least two `spike_approved` state reports before printing `PASS`.

- [x] Add failing static harness tests for state polling and two-heartbeat threshold.
- [x] Remove `-serial none`; retain serial log as diagnostic evidence and make fixture state reports the automated acceptance signal.
- [x] Run the isolated QEMU harness with a read-only target; record the generated build manifest and no-write result in the technical document.

### Task 8: Add isolated PR1 CI coverage and publish the correction

**Files:**
- Create: `.github/workflows/alt-managed-iso-spike.yml`
- Modify: `docs/ALT_MANAGED_ISO_TECHNICAL_SPIKE.md`

- [x] Add a PR-path-filtered job that runs focused pytest and Bash syntax checks.
- [x] Implement the workflow without downloading the proprietary ISO or executing QEMU in GitHub Actions.
- [ ] Run the complete local PR1 test set, commit the correction, push it, and update PR #34.

## Coverage Review

- Integration-boundary mismatch: Task 1.
- Missing post-approval proof: Tasks 3 and 7.
- Weak ISO verifier: Task 5.
- Timeout and unsupported BIOS entry: Task 2.
- Minimal inventory and malformed HTTP input: Task 3.
- Network, builder cleanup, and space checks: Tasks 4 and 6.
- Focused CI: Task 8.
