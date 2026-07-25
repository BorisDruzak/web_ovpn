# ALT Managed ISO PR1 Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use `superpowers:executing-plans` to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Build a guarded ALT 11.4 managed-ISO spike that proves DHCP, inventory, fixture-session creation and approval without starting the installer or writing to a target disk.

**Architecture:** The build is tied to the exact upstream ISO by a committed manifest and exact initrd patch anchor. A Bash-only agent executes before `etc/rc.d/rc.sysexec` hands control to the live system, creates a bounded inventory and polls a rootless Python fixture; every spike outcome enters a non-returning hold. UEFI uses an explicit local-loader chainload entry, while runtime safety is proved in a disposable QEMU UEFI VM with a read-only target disk.

**Tech Stack:** Bash, gzip/newc CPIO, xorriso, GRUB, Syslinux, Python 3 standard library, pytest, QEMU with OVMF/QMP.

## Global Constraints

- Work from a dedicated feature worktree; do not change the source ISO or production controller runtime.
- Support only `/var/alt-kworkstation-11.4-install-x86_64.iso` and abort on a source, initrd, GRUB, Syslinux or handoff-hash mismatch.
- The managed kernel command line includes `ip=dhcp`, `sosnadmin.mode=spike`, `sosnadmin.controller=http://192.168.100.17:18089` and `sosnadmin.build=<build-id>` only in addition to the stock installer line; it contains no `ai`, `curl=`, or `automatic`.
- The spike agent uses Bash and initrd-proven commands only: `bash`, `curl`, `ip`, `findmnt`, `udevadm`, `blkid`, `sha256sum`, and `dialog`.
- The agent must not call `alterator-autoinstall`, `alterator-wizard`, `sfdisk`, `wipefs`, `mkfs`, `fdisk`, `parted`, `dd of=`, `mount -o rw`, `reboot`, `poweroff`, `systemctl`, or any stage-2 handoff.
- No production API, systemd unit, `/srv/alt-deploy` state, or `/var/lib/alt-deploy` state is added or changed.
- CI uses only a synthetic mini-ISO fixture; the 10.71 GB upstream ISO is manual-acceptance input.
- The QEMU acceptance target disk is read-only, with its backing-file SHA-256 and QMP block statistics captured before and after boot.

---

## Planned File Structure

```text
deploy/alt-linux/
├── iso/
│   ├── inspect-upstream-iso.sh
│   ├── build-spike-iso.sh
│   ├── verify-spike-iso.sh
│   ├── manifests/alt-kworkstation-11.4-install-x86_64.json
│   ├── boot-menu/grub.cfg.patch
│   ├── boot-menu/isolinux.cfg.patch
│   ├── initrd-patches/early-agent-gate.patch
│   └── initrd-overlay/usr/libexec/sosnadmin-install-spike
├── install-agent/
│   ├── spike-agent
│   ├── lib/cmdline.sh
│   ├── lib/network.sh
│   ├── lib/inventory.sh
│   ├── lib/protocol.sh
│   ├── lib/ui.sh
│   └── spike-server/{server.py,ctl.py,repository.py}
└── qemu/run-spike-readonly-acceptance.sh
tests/alt_linux/test_managed_iso_spike.py
docs/ALT_MANAGED_ISO_TECHNICAL_SPIKE.md
```

## Task 1: Pin and inspect the exact upstream ISO

**Files:**
- Create: `deploy/alt-linux/iso/inspect-upstream-iso.sh`
- Create: `deploy/alt-linux/iso/manifests/alt-kworkstation-11.4-install-x86_64.json`
- Test: `tests/alt_linux/test_managed_iso_spike.py`

**Interfaces:**
- Consumes: `inspect-upstream-iso.sh --source <ISO> --manifest <JSON>`.
- Produces: a zero-exit verification only when size and SHA-256 values for the ISO, `/boot/initrd.img`, `/boot/grub/grub.cfg`, `/syslinux/isolinux.cfg`, and decompressed `etc/rc.d/rc.sysexec` equal the manifest.

- [ ] **Step 1: Write failing manifest/inspection tests**

```python
def test_inspector_requires_all_pinned_paths_and_hashes() -> None:
    text = INSPECTOR.read_text(encoding="utf-8")
    for token in (
        "boot/initrd.img", "boot/grub/grub.cfg", "syslinux/isolinux.cfg",
        "etc/rc.d/rc.sysexec", "sha256sum", "xorriso",
    ):
        assert token in text

def test_manifest_has_real_exact_fields() -> None:
    manifest = json.loads(MANIFEST.read_text(encoding="utf-8"))
    assert manifest["source_size_bytes"] == 10710822912
    assert re.fullmatch(r"[0-9a-f]{64}", manifest["source_sha256"])
```

- [ ] **Step 2: Run the focused test and confirm it fails**

Run: `.venv/bin/python -m pytest -q tests/alt_linux/test_managed_iso_spike.py -k inspector`

Expected: failure because the script and manifest do not exist.

- [ ] **Step 3: Implement the inspector and generate the pinned manifest**

Use `xorriso -osirrox on -indev` to read the three ISO files to a temporary directory, stream `boot/initrd.img` through `gzip -dc | cpio -i --to-stdout etc/rc.d/rc.sysexec`, and calculate SHA-256 with `sha256sum`. Refuse a source basename other than `alt-kworkstation-11.4-install-x86_64.iso`, a missing tool, malformed JSON, a zero size, or any mismatch. Store actual values obtained from the provided source ISO; do not invent a hash.

- [ ] **Step 4: Run the inspector against the real source ISO**

Run on the ALT build host:

```bash
bash deploy/alt-linux/iso/inspect-upstream-iso.sh \
  --source /var/alt-kworkstation-11.4-install-x86_64.iso \
  --manifest deploy/alt-linux/iso/manifests/alt-kworkstation-11.4-install-x86_64.json
```

Expected: zero exit and an output line for each pinned artifact.

- [ ] **Step 5: Run the focused test and commit**

Run: `.venv/bin/python -m pytest -q tests/alt_linux/test_managed_iso_spike.py -k inspector`

Commit: `git add deploy/alt-linux/iso tests/alt_linux/test_managed_iso_spike.py && git commit -m "feat: pin managed ISO source manifest"`

## Task 2: Implement the fail-closed Bash agent and local UI

**Files:**
- Create: `deploy/alt-linux/install-agent/spike-agent`
- Create: `deploy/alt-linux/install-agent/lib/cmdline.sh`
- Create: `deploy/alt-linux/install-agent/lib/network.sh`
- Create: `deploy/alt-linux/install-agent/lib/inventory.sh`
- Create: `deploy/alt-linux/install-agent/lib/protocol.sh`
- Create: `deploy/alt-linux/install-agent/lib/ui.sh`
- Test: `tests/alt_linux/test_managed_iso_spike.py`

**Interfaces:**
- Consumes: exact cmdline keys `sosnadmin.mode`, `sosnadmin.controller`, `sosnadmin.build` and environment overrides `SOSNADMIN_PROC_ROOT`, `SOSNADMIN_SYS_ROOT`, `SOSNADMIN_BIN_DIR` for unit tests.
- Produces: `spike-agent` exits only for invalid direct invocation; when called by the initrd gate it runs `spike_hold <state>` forever after any terminal state.

- [ ] **Step 1: Write failing safety and parser tests**

```python
def test_agent_rejects_disallowed_cmdline_and_never_returns_after_hold() -> None:
    text = AGENT.read_text(encoding="utf-8")
    assert "spike_hold" in text
    assert "while :; do" in text
    assert "alterator-autoinstall" not in text
    assert "systemctl" not in text

def test_inventory_limits_and_json_normalization_are_explicit() -> None:
    text = INVENTORY.read_text(encoding="utf-8")
    assert "max_interfaces=16" in text
    assert "max_disks=16" in text
    assert "sanitize_json_string" in text
```

- [ ] **Step 2: Run the focused test and confirm it fails**

Run: `.venv/bin/python -m pytest -q tests/alt_linux/test_managed_iso_spike.py -k agent`

Expected: failure because the agent files do not exist.

- [ ] **Step 3: Implement bounded read-only agent behavior**

Implement exact-token parsing without `eval`; accept only `http://192.168.100.17:18089` in PR1. Wait for `ip -4 route get 192.168.100.17`, collect no more than 16 interfaces and 16 non-loop/ram/zram disks, derive boot media from `findmnt -n -o SOURCE,FSTYPE,OPTIONS /image`, normalize untrusted values to bounded ASCII JSON strings, and display `waiting_for_network`, `controller_unavailable`, `waiting_for_approval`, `spike_approved`, `spike_cancelled`, or `spike_failed` through `dialog` with tty fallback.

- [ ] **Step 4: Add executable and syntax verification**

Run:

```bash
chmod 0755 deploy/alt-linux/install-agent/spike-agent
find deploy/alt-linux/install-agent -type f -name '*.sh' -print0 | xargs -0 -r -n1 bash -n
bash -n deploy/alt-linux/install-agent/spike-agent
```

- [ ] **Step 5: Run focused tests and commit**

Run: `.venv/bin/python -m pytest -q tests/alt_linux/test_managed_iso_spike.py -k agent`

Commit: `git add deploy/alt-linux/install-agent tests/alt_linux/test_managed_iso_spike.py && git commit -m "feat: add fail-closed initrd spike agent"`

## Task 3: Add the rootless spike-server fixture

**Files:**
- Create: `deploy/alt-linux/install-agent/spike-server/repository.py`
- Create: `deploy/alt-linux/install-agent/spike-server/server.py`
- Create: `deploy/alt-linux/install-agent/spike-server/ctl.py`
- Test: `tests/alt_linux/test_managed_iso_spike.py`

**Interfaces:**
- `POST /spike/v1/sessions` accepts at most 32 KiB of bounded inventory JSON and returns `201` with a plain-text `spike-...` identifier.
- `GET /spike/v1/sessions/<id>/decision` returns exactly `waiting`, `approved`, or `cancelled` as plain text.
- `ctl.py approve <id>` transitions only `waiting -> approved`; all repeated approvals are idempotent.

- [ ] **Step 1: Write failing fixture tests**

```python
def test_fixture_rejects_oversized_or_invalid_session_payload(client) -> None:
    assert client.post("/spike/v1/sessions", data=b"{").status_code == 400
    assert client.post("/spike/v1/sessions", data=b"x" * 32769).status_code == 413

def test_approval_is_idempotent_and_terminal(tmp_path: Path) -> None:
    repo = Repository(tmp_path)
    session = repo.create_session({"machine": {"uuid": "u"}})
    assert repo.approve(session) == "approved"
    assert repo.approve(session) == "approved"
    assert repo.cancel(session) == "approved"
```

- [ ] **Step 2: Run the focused test and confirm it fails**

Run: `.venv/bin/python -m pytest -q tests/alt_linux/test_managed_iso_spike.py -k fixture`

Expected: failure because the fixture modules do not exist.

- [ ] **Step 3: Implement atomic private fixture state**

Use only Python standard-library `http.server`, `json`, `pathlib`, `tempfile`, and `os.replace`. Create state root mode `0700`, session files mode `0600`, IDs matching `spike-YYYYMMDDTHHMMSSZ-[0-9a-f]{8}`, and fixed filenames only. Reject directory traversal, unknown sessions, payloads above 32 KiB, more than 16 interfaces/disks, invalid transition values, and fields exceeding the agent limits. Derive and record peer IP from the HTTP connection rather than trusting payload input.

- [ ] **Step 4: Run focused fixture tests**

Run: `.venv/bin/python -m pytest -q tests/alt_linux/test_managed_iso_spike.py -k fixture`

Expected: PASS.

- [ ] **Step 5: Commit**

Commit: `git add deploy/alt-linux/install-agent/spike-server tests/alt_linux/test_managed_iso_spike.py && git commit -m "feat: add isolated managed ISO spike fixture"`

## Task 4: Patch initrd at the verified handoff and build the ISO

**Files:**
- Create: `deploy/alt-linux/iso/initrd-patches/early-agent-gate.patch`
- Create: `deploy/alt-linux/iso/initrd-overlay/usr/libexec/sosnadmin-install-spike`
- Create: `deploy/alt-linux/iso/build-spike-iso.sh`
- Test: `tests/alt_linux/test_managed_iso_spike.py`

**Interfaces:**
- Consumes: `build-spike-iso.sh --source <ISO> --output <ISO> [--force]`.
- Produces: a new ISO only after manifest verification, one successful patch application, an overlay install and boot-geometry replay.

- [ ] **Step 1: Write failing initrd gate and builder tests**

```python
def test_gate_is_exactly_before_vendor_sysexec_and_blocks_spike_handoff() -> None:
    patch = GATE_PATCH.read_text(encoding="utf-8")
    assert "etc/rc.d/rc.sysexec" in patch
    assert "sosnadmin.mode=spike" in patch
    assert patch.index("sosnadmin-install-spike") < patch.index("exec runas /sbin/init")

def test_builder_refuses_unknown_source_and_existing_output() -> None:
    text = BUILDER.read_text(encoding="utf-8")
    assert "--force" in text
    assert "xorriso" in text
    assert "gzip -n" in text
```

- [ ] **Step 2: Run the focused test and confirm it fails**

Run: `.venv/bin/python -m pytest -q tests/alt_linux/test_managed_iso_spike.py -k 'gate or builder'`

Expected: failure because the patch and builder do not exist.

- [ ] **Step 3: Implement a transaction-like builder**

Preflight `xorriso`, `cpio`, `gzip`, `patch`, `sha256sum`, `mktemp`, required free space, source readability, and absent output unless `--force`. Use a private `mktemp -d`, extract only the pinned boot artifacts, verify their hashes, decompress initrd, apply the patch with `patch --fuzz=0 --forward`, assert exactly one injected marker, copy the agent and libraries into the overlay, rebuild `newc | gzip -n`, apply exact GRUB/Syslinux patches, and use xorriso boot replay to write a temporary ISO before an atomic rename to output. Trap cleanup on every exit path.

- [ ] **Step 4: Run synthetic mini-ISO builder test and real ISO smoke build**

Run CI fixture test first:

```bash
.venv/bin/python -m pytest -q tests/alt_linux/test_managed_iso_spike.py -k 'gate or builder'
```

Then, only on the ALT build host:

```bash
bash deploy/alt-linux/iso/build-spike-iso.sh \
  --source /var/alt-kworkstation-11.4-install-x86_64.iso \
  --output /var/tmp/alt-kworkstation-11.4-sosnadmin-spike.iso
```

Expected: output ISO exists, original ISO mtime and SHA-256 remain unchanged.

- [ ] **Step 5: Commit**

Commit: `git add deploy/alt-linux/iso tests/alt_linux/test_managed_iso_spike.py && git commit -m "feat: build fail-closed managed ISO spike"`

## Task 5: Implement and verify BIOS/UEFI boot menus

**Files:**
- Create: `deploy/alt-linux/iso/boot-menu/grub.cfg.patch`
- Create: `deploy/alt-linux/iso/boot-menu/isolinux.cfg.patch`
- Create: `deploy/alt-linux/iso/verify-spike-iso.sh`
- Test: `tests/alt_linux/test_managed_iso_spike.py`

**Interfaces:**
- Consumes: `verify-spike-iso.sh --iso <ISO> --manifest <JSON>`.
- Produces: zero exit only when default is `harddisk`, UEFI local loader paths omit `/EFI/BOOT/BOOTX64.EFI`, managed entry has required tokens and normal entry retains its stock command line.

- [ ] **Step 1: Write failing menu-contract tests**

```python
def test_uefi_menu_has_safe_local_loader_priority_and_managed_tokens() -> None:
    text = GRUB_PATCH.read_text(encoding="utf-8")
    assert "set default=harddisk" in text
    assert "/EFI/altlinux/shimx64.efi" in text
    assert "/EFI/Microsoft/Boot/bootmgfw.efi" in text
    assert "/EFI/BOOT/BOOTX64.EFI" not in text
    assert "ip=dhcp" in text and "sosnadmin.mode=spike" in text
```

- [ ] **Step 2: Run the focused test and confirm it fails**

Run: `.venv/bin/python -m pytest -q tests/alt_linux/test_managed_iso_spike.py -k menu`

Expected: failure because menu patches do not exist.

- [ ] **Step 3: Implement menu patches and verifier**

Keep the unmodified vendor installation entry as `Normal ALT installation`. Add `Boot from local disk` as the UEFI default with timeout five. Search and chainload in the pinned ALT-shim, ALT-GRUB, Windows order; display an error and return to the menu on no match. Add `Sosnadmin managed installation [SPIKE]` with only the allowed appended tokens. Preserve BIOS as local-disk default and normal installer manual. Add a read-only Diagnostics menu item that displays no shell and performs no installer transition.

- [ ] **Step 4: Run menu verification**

Run:

```bash
bash deploy/alt-linux/iso/verify-spike-iso.sh \
  --iso /var/tmp/alt-kworkstation-11.4-sosnadmin-spike.iso \
  --manifest deploy/alt-linux/iso/manifests/alt-kworkstation-11.4-install-x86_64.json
```

Expected: verifier prints all menu contracts and exits zero.

- [ ] **Step 5: Commit**

Commit: `git add deploy/alt-linux/iso tests/alt_linux/test_managed_iso_spike.py && git commit -m "feat: add safe managed ISO boot menus"`

## Task 6: Add QEMU read-only acceptance harness

**Files:**
- Create: `deploy/alt-linux/qemu/run-spike-readonly-acceptance.sh`
- Test: `tests/alt_linux/test_managed_iso_spike.py`

**Interfaces:**
- Consumes: `--iso <spike.iso> --ovmf-code <OVMF_CODE.fd> --ovmf-vars <OVMF_VARS.fd> --target <disk.img> --fixture-url <http://192.168.100.17:18089>`.
- Produces: `acceptance/<run-id>/{serial.log,before.json,after.json,target.before.sha256,target.after.sha256}` and a non-zero exit on any safety failure.

- [ ] **Step 1: Write failing harness-contract tests**

```python
def test_qemu_harness_makes_target_read_only_and_checks_console_and_stats() -> None:
    text = QEMU_HARNESS.read_text(encoding="utf-8")
    assert "readonly=on" in text
    assert "query-blockstats" in text
    assert "target.before.sha256" in text
    assert "waiting_for_approval" in text
    assert "spike_approved" in text
```

- [ ] **Step 2: Run the focused test and confirm it fails**

Run: `.venv/bin/python -m pytest -q tests/alt_linux/test_managed_iso_spike.py -k qemu`

Expected: failure because the harness does not exist.

- [ ] **Step 3: Implement the manual acceptance harness**

Require `qemu-system-x86_64`, `qemu-img`, `socat`, `sha256sum`, OVMF code/vars, and an existing fixture server. Copy OVMF vars and create only a disposable target disk if no target is supplied; attach it with `readonly=on`, boot ISO as read-only CD-ROM, enable QMP and serial logging, and use `-no-reboot`. Capture QMP `query-blockstats` before and after approval. Require guest console state `waiting_for_approval`, operator approval, `spike_approved`, `NO DISK CHANGES WERE MADE`, no `install2`, no `alterator`, no `sysexec` success marker, unchanged target hash and zero write statistics. Do not put this test in CI.

- [ ] **Step 4: Perform the authorized manual acceptance run**

Run the fixture under `altserver` in a foreground terminal, then run the harness against the generated ISO. Use `ctl.py approve <session-id>` only after the serial console reports `waiting_for_approval`.

Expected: harness prints the evidence directory and `PASS: no target-disk write I/O`.

- [ ] **Step 5: Commit**

Commit: `git add deploy/alt-linux/qemu tests/alt_linux/test_managed_iso_spike.py && git commit -m "test: add readonly managed ISO acceptance harness"`

## Task 7: Publish operational documentation and complete verification

**Files:**
- Create: `docs/ALT_MANAGED_ISO_TECHNICAL_SPIKE.md`
- Modify: `deploy/alt-linux/README.md`
- Test: `tests/alt_linux/test_managed_iso_spike.py`

**Interfaces:**
- Consumes: the final source manifest, built ISO verification output and QEMU evidence directory.
- Produces: an operator runbook that distinguishes this no-write spike from production installation and gives exact rollback-free cleanup instructions.

- [ ] **Step 1: Write failing documentation-contract tests**

```python
def test_technical_spike_documentation_states_no_write_and_manual_scope() -> None:
    text = SPIKE_DOC.read_text(encoding="utf-8")
    for phrase in ("no write I/O", "read-only", "18089", "does not start Alterator"):
        assert phrase in text
```

- [ ] **Step 2: Run the focused test and confirm it fails**

Run: `.venv/bin/python -m pytest -q tests/alt_linux/test_managed_iso_spike.py -k documentation`

Expected: failure because the documentation does not exist.

- [ ] **Step 3: Write the operator documentation**

Document prerequisites, exact source path, manifest check, builder invocation, fixture lifecycle, menu semantics, UEFI loader behavior, known HTTP test-only boundary, operator approval/cancel commands, QEMU read-only acceptance evidence, expected console states and cleanup of `/var/tmp/alt-install-spike` only after the fixture exits. State that this PR neither installs ALT nor starts Alterator nor changes controller runtime.

- [ ] **Step 4: Run complete repository verification**

Run on Linux:

```bash
.venv/bin/python -m pytest -q tests/alt_linux
find deploy/alt-linux/iso deploy/alt-linux/install-agent deploy/alt-linux/qemu -type f \( -name '*.sh' -o -name 'spike-agent' \) -print0 | xargs -0 -r -n1 bash -n
python3 -m py_compile deploy/alt-linux/install-agent/spike-server/*.py
git diff --check
```

Expected: all tests pass, all shell files parse, Python fixture compiles, and no whitespace errors exist.

- [ ] **Step 5: Commit**

Commit: `git add docs deploy/alt-linux/README.md tests/alt_linux/test_managed_iso_spike.py && git commit -m "docs: add managed ISO technical spike runbook"`

## Plan Self-Review

- Gate 1 is implemented and tested in Tasks 1 and 4.
- Gate 2 is implemented and tested in Task 5, with the installed ALT EFI paths pinned by the approved specification.
- Gate 3 is implemented and manually accepted in Task 6; source tests only validate its harness contract.
- Bash-only agent, isolated fixture, no production controller changes, static forbidden-command checks, source pinning, menu contract and documentation are covered by Tasks 1 through 7.
- There are no production API, controller installer, Ansible, Vault, registration or assignment changes in the plan.
