# ALT V2 bootstrap and production-key QEMU acceptance Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Make a clean V2 ISO boot establish its signed V1 preflight itself and
prove the V2 install path in a controller-key-resident disposable QEMU run.

**Architecture:** The V2 agent reuses the V1 entrypoint in library-only mode
for session creation, signed-plan verification, and disk preflight, then
continues with its existing V2 bundle and execution flow.  The harness starts
both V1 and V2 APIs in its private namespace, root-approves only its uniquely
created disposable session, and retains all existing V2 execution boundaries.

**Tech Stack:** Bash initrd agents and harness, Python controller/QMP support,
pytest, generic OVMF QEMU, systemd/Linux namespaces.

## Global Constraints

- Production private keys and session credentials stay on `192.168.100.17`.
- Proxmox ISO access is read-only and temporary; the host never receives a
  production private key or controller state.
- Only harness-created qcow2 target/sentinel disks may be supplied to QEMU.
- V1 plan approval and V2 execution approval are separate root operations.
- New code follows test-first RED/GREEN verification.

---

### Task 1: Reusable V1 preflight configuration for V2

**Files:**
- Modify: `deploy/alt-linux/install-agent/v1/lib/config.sh`
- Modify: `deploy/alt-linux/install-agent/v2/alt-install-execution-agent`
- Test: `tests/test_alt_install_agent_v1.py`
- Test: `tests/test_alt_install_execution_agent.py`

**Interfaces:**
- Produces `config_load_v2_preflight() -> status`, which accepts only
  `agent-v2`, reads the embedded V1 URL, and exports
  `ALT_INSTALL_CONTROLLER`.
- Consumes the existing V1 entrypoint with `ALT_INSTALL_AGENT_LIBRARY_ONLY=1`.

- [ ] **Step 1: Write failing configuration tests.**

```python
def test_v2_preflight_uses_pinned_v1_controller(tmp_path: Path) -> None:
    completed = _run_bash("source .../config.sh; config_load_v2_preflight; printf %s \"$ALT_INSTALL_CONTROLLER\"")
    assert completed.stdout == "http://192.168.100.17:18090\n"

def test_v2_preflight_rejects_an_unpinned_v1_controller(tmp_path: Path) -> None:
    completed = _run_bash("source .../config.sh; config_load_v2_preflight")
    assert completed.returncode != 0
```

- [ ] **Step 2: Run the two tests and confirm the helper is absent.**

Run: `python -m pytest tests/test_alt_install_agent_v1.py tests/test_alt_install_execution_agent.py -q -k v2_preflight`

- [ ] **Step 3: Implement `config_load_v2_preflight`.**  Share the existing
  canonical file validation, accept only the `agent-v2` mode, ignore the V2
  command-line controller for V1 HTTP traffic, and export only the embedded
  `http://192.168.100.17:18090` controller value.

- [ ] **Step 4: Run the focused tests and verify GREEN.**

- [ ] **Step 5: Commit.**

### Task 2: V2 clean-boot session and preflight lifecycle

**Files:**
- Modify: `deploy/alt-linux/install-agent/v2/alt-install-execution-agent`
- Modify: `deploy/alt-linux/install-agent/v1/lib/protocol.sh`
- Test: `tests/test_alt_install_execution_agent.py`

**Interfaces:**
- Consumes `config_load_v2_preflight`, V1 `network_prepare`,
  `generate_create_nonce`, inventory, session, heartbeat, plan, and preflight
  helpers.
- Produces one V1 `preflight_ready` session before
  `protocol_download_execution_bundle` is called.

- [ ] **Step 1: Write a failing ordered-lifecycle test.**

```python
def test_v2_agent_bootstraps_v1_preflight_before_bundle_download() -> None:
    source = AGENT.read_text(encoding="utf-8")
    assert source.index("protocol_heartbeat preflight_ready") < source.index("protocol_download_execution_bundle")
```

- [ ] **Step 2: Run the test and confirm it fails on the current V2 order.**

- [ ] **Step 3: Implement the V1 bootstrap in V2.**  Source the V1 entrypoint
  in library-only mode, keep V2 config authoritative for HTTPS, run the exact
  V1 non-destructive sequence, use `ALT_INSTALL_AGENT_VERSION` in V1
  heartbeats, and route every failure to an existing terminal hold.

- [ ] **Step 4: Add failure tests for nonce, inventory, session, plan,
  signature, disk-preflight, and preflight-heartbeat failures.**

- [ ] **Step 5: Run `python -m pytest tests/test_alt_install_execution_agent.py tests/test_alt_install_agent_v1.py -q` and commit.**

### Task 3: Disposable V1 plan approval in the QEMU harness

**Files:**
- Modify: `deploy/alt-linux/qemu/agent_v2_test_api.py`
- Modify: `deploy/alt-linux/qemu/run-agent-v2-execution-acceptance.sh`
- Test: `tests/test_alt_install_execution_qemu.py`

**Interfaces:**
- Produces `approve-disposable-session --state-dir <DIR>` that identifies one
  harness-created awaiting-approval session, calls the real root CLI, and
  emits a signed approval attestation.
- Consumes repository status and the harness QEMU UUID/target binding.

- [ ] **Step 1: Write failing support tests.**

```python
def test_disposable_plan_approval_rejects_zero_or_multiple_new_sessions() -> None:
    with pytest.raises(AcceptanceError, match="single disposable session"):
        approve_disposable_session(state, statuses=lambda: [])

def test_disposable_plan_approval_uses_authoritative_inventory_and_disk() -> None:
    assert cli_calls == [["--json", "install-sessions", "approve", session_id, ...]]
```

- [ ] **Step 2: Run the tests and confirm the command is absent.**

- [ ] **Step 3: Implement the support command and attestation.**  Require the
  exact generated VM/session binding, inventory SHA-256, `/dev/vda` disk
  fingerprint, root euid, and the fixed disposable reason; reject state
  changes and unexpected sessions.

- [ ] **Step 4: Extend the shell harness.**  Start the V1 session API before
  the V2 API inside the owned namespace; wait for exactly one eligible
  session, approve it, then wait for `execution_pending`.  Record/cleanup the
  V1 API PID with the same pidfd identity policy as the other processes.

- [ ] **Step 5: Run `python -m pytest tests/test_alt_install_execution_qemu.py -q` and commit.**

### Task 4: Controller-host acceptance runner and read-only ISO transport

**Files:**
- Create: `deploy/alt-linux/qemu/run-agent-v2-controller-acceptance.sh`
- Modify: `docs/verification/alt-install-execution-v2-qemu.md`
- Test: `tests/test_alt_install_execution_qemu.py`

**Interfaces:**
- Consumes `--source-iso`, `--iso`, a root-only local controller credential,
  OVMF paths, and an evidence root.
- Produces only the existing sealed evidence package and PASS line.

- [ ] **Step 1: Write failing contract tests.**  Assert the wrapper rejects
  non-controller hosts, writable/network ISO inputs, a non-local evidence
  root, insufficient free space, and private-key paths outside the protected
  controller credential directory.

- [ ] **Step 2: Run the tests and confirm the wrapper is absent.**

- [ ] **Step 3: Implement the root-only wrapper.**  Validate a temporary
  read-only mount of the two ISO files, reserve local workspace capacity,
  call the existing harness with canonical OVMF paths and controller-local
  credential, and unmount/remove only the verified temporary transport.

- [ ] **Step 4: Document a temporary forced-SFTP/SSHFS publication from pve2
  to `.17`.**  The pve side exposes only the two ISO files read-only; the
  controller key and temporary authorization are removed after the result is
  exported.

- [ ] **Step 5: Run the focused tests and commit.**

### Task 5: Deployment and real acceptance

**Files:**
- Create: `docs/verification/alt-install-execution-v2-qemu-<UTC-run>.md`
- Update: `docs/verification/alt-install-execution-v2-qemu.md`

- [ ] **Step 1: Run the complete execution-focused regression suite.**

Run: `python -m pytest tests/test_alt_install_execution_iso.py tests/test_alt_install_execution_qemu.py tests/test_alt_install_execution_agent.py tests/test_install_execution_authorization.py -q`

- [ ] **Step 2: Deploy the merged controller runner to `.17` without changing
  existing V1/V2 systemd services.**  Verify unit status and controller health
  before creating the disposable acceptance session.

- [ ] **Step 3: Establish the temporary read-only pve2 ISO transport and
  verify source/managed SHA-256 at both ends.**

- [ ] **Step 4: Execute the controller-host generic-OVMF acceptance.**  Record
  the exact PASS line, evidence directory, public-evidence verifier result,
  ISO digest, and confirmation that only the disposable target changed.

- [ ] **Step 5: Remove the temporary transport authorization/mount, commit the
  sanitized verification record, merge to main, and run the complete suite.**
