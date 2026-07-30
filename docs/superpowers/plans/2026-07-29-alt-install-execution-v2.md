# ALT Install Execution V2 Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Deliver a TLS-protected, separately root-authorized ALT 11.4 automatic-install path that writes only to the signed target disk and is proven first in disposable OVMF QEMU.

**Architecture:** V2 preserves V1 as a no-write preflight. A separate TLS listener and root-only execution authorization create a signed session-bound metadata bundle. The initrd agent verifies it, serves it on loopback, then permits stock `install2.target`; a first-boot report closes the session.

**Tech Stack:** Python stdlib HTTP/TLS and cryptography, existing Ed25519 signer, static Go helper, Bash/initrd, systemd, xorriso, QEMU/QMP, pytest and Go tests.

## Global Constraints

- V1 `:18090` and its dry-run menu remain byte-compatible and no-write.
- V2 binds only `192.168.100.17:18092` over TLS; its ISO embeds only CA and public plan key.
- The opt-in V2 entry uses `systemd.unit=install2.target ai curl=http://127.0.0.1:18192`; it is never default.
- Plan approval cannot write a disk. A five-minute, single-use root execution authorization is required.
- The bundle contains exactly `autoinstall.scm`, `vm-profile.scm`, `pkg-groups.tar`, and `install-scripts.tar`.
- Before hook return, repeat plan verification and disk preflight. Every error holds without writing.
- A real asset remains behind an explicit pilot record; no post-write rollback is promised.

---

### Task 1: Add V2 TLS material and hardened listener

**Files:**
- Modify: `deploy/alt-linux/control/alt_deploy/config.py`
- Create: `deploy/alt-linux/control/alt_deploy/install_tls.py`
- Create: `deploy/alt-linux/api/install_execution_server.py`
- Create: `deploy/alt-linux/systemd/alt-install-execution.service`
- Create: `deploy/alt-linux/install-install-execution-api.sh`
- Test: `tests/alt_linux/test_install_execution_tls.py`
- Test: `tests/alt_linux/test_install_execution_production_installer.py`

**Interfaces:** Produce `ensure_execution_tls_material(settings) -> TLSMaterial` and a TLS server configured for the V2 router.

- [ ] **Step 1: Write the failing TLS tests**

```python
def test_tls_material_is_root_owned_and_idempotent(tmp_path):
    material = ensure_execution_tls_material(settings_in(tmp_path))
    assert material.server_private_key.stat().st_mode & 0o777 == 0o600
    assert ensure_execution_tls_material(settings_in(tmp_path)) == material

def test_tls_listener_rejects_plain_http_and_wrong_ca(running_tls_server):
    assert request_plain_http(running_tls_server) == 400
    with pytest.raises(ssl.SSLCertVerificationError):
        request_https(running_tls_server, cafile=wrong_ca)
```

- [ ] **Step 2: Verify failure**

Run: `pytest tests/alt_linux/test_install_execution_tls.py -q`

Expected: missing V2 settings and TLS module.

- [ ] **Step 3: Implement the smallest secure listener**

Add separate V2 address, port, TLS-root, CA, certificate and private-key settings. Create and validate material using no-follow file descriptors: TLS 1.3 minimum, server certificate IP SAN `192.168.100.17`, root-only key `0600`, public certificate `0644`. The service runs as `altserver`, uses systemd 255 `LoadCredential=execution-tls-key:<root-key-path>` and `%d/execution-tls-key` rather than reading the root-owned key path, has the same hardening as V1, and does not alter V1.

- [ ] **Step 4: Verify**

Run: `pytest tests/alt_linux/test_install_execution_tls.py tests/alt_linux/test_install_execution_production_installer.py -q`

Expected: trusted CA success, plain HTTP/wrong CA/expired certificate failure, correct modes, idempotency, hardened unit, V1 unaffected.

- [ ] **Step 5: Commit**

```bash
git add deploy/alt-linux/control/alt_deploy/config.py deploy/alt-linux/control/alt_deploy/install_tls.py deploy/alt-linux/api/install_execution_server.py deploy/alt-linux/systemd/alt-install-execution.service deploy/alt-linux/install-install-execution-api.sh tests/alt_linux/test_install_execution_tls.py tests/alt_linux/test_install_execution_production_installer.py
git commit -m "feat(alt-install): add execution TLS listener"
```

### Task 2: Implement immutable execution authorization and bundle storage

**Files:**
- Modify: `deploy/alt-linux/control/alt_deploy/install_session_repository.py`
- Modify: `deploy/alt-linux/control/alt_deploy/install_session_state.py`
- Create: `deploy/alt-linux/control/alt_deploy/install_execution.py`
- Create: `deploy/alt-linux/control/alt_deploy/install_execution_manifest.py`
- Modify: `deploy/alt-linux/control/alt_deploy/install_renderer.py`
- Test: `tests/alt_linux/test_install_execution.py`
- Test: `tests/alt_linux/test_install_execution_manifest.py`

**Interfaces:** Produce `ExecutionAuthorizationService.authorize(...)`, `cancel(...)`, `claim(...)`, canonical `ExecutionManifestV1`, and repository reads for named bundle files.

- [ ] **Step 1: Write failing state and binding tests**

```python
def test_execution_binds_the_approved_plan_and_target(session):
    result = service.authorize(session.id, plan_sha256=session.plan_sha256,
        inventory_sha256=session.inventory_sha256,
        disk_fingerprint=session.fingerprint, confirm_target="/dev/vda",
        reason="disposable OVMF acceptance")
    assert result.manifest.target_disk == "/dev/vda"

def test_duplicate_or_cancelled_execution_cannot_publish_again(session):
    service.authorize(...)
    with pytest.raises(ControlError, match="execution"):
        service.authorize(...)
```

- [ ] **Step 2: Verify failure**

Run: `pytest tests/alt_linux/test_install_execution.py tests/alt_linux/test_install_execution_manifest.py -q`

Expected: missing execution domain.

- [ ] **Step 3: Implement atomic execution revision publication**

Publish an `execution-0001` directory through the existing no-follow temporary-file/rename pattern. It contains only manifest, manifest signature, four named artifacts and internal digest metadata; every file is regular and `0600`. Add an optional exact-key `execution` status object with append-only transitions `not_authorized -> authorized -> claimed -> handoff_started -> installer_started -> installed|failed`; cancellation and expiry are terminal. Bind the signed manifest to session, plan hash, inventory hash, target path/fingerprint, ISO/profile and each artifact name/length/hash. Refuse non-root, stale preflight, mismatched acknowledgement, duplicate, cancelled, expired, symlink, extra filename or malformed source archive. Status and errors never serialize a yescrypt hash.

- [ ] **Step 4: Verify**

Run: `pytest tests/alt_linux/test_install_execution.py tests/alt_linux/test_install_execution_manifest.py tests/alt_linux/test_install_session_repository.py tests/alt_linux/test_install_session_state.py -q`

Expected: all transitions, contention and secret-redaction tests pass; existing V1 status is compatible.

- [ ] **Step 5: Commit**

```bash
git add deploy/alt-linux/control/alt_deploy/install_session_repository.py deploy/alt-linux/control/alt_deploy/install_session_state.py deploy/alt-linux/control/alt_deploy/install_execution.py deploy/alt-linux/control/alt_deploy/install_execution_manifest.py deploy/alt-linux/control/alt_deploy/install_renderer.py tests/alt_linux/test_install_execution.py tests/alt_linux/test_install_execution_manifest.py
git commit -m "feat(alt-install): authorize signed execution bundles"
```

### Task 3: Add V2 TLS routes and root CLI

**Files:**
- Modify: `deploy/alt-linux/api/install_session_api.py`
- Modify: `deploy/alt-linux/api/install_session_server.py`
- Modify: `deploy/alt-linux/control/alt_deploy/cli.py`
- Test: `tests/alt_linux/test_install_execution_api.py`
- Test: `tests/alt_linux/test_install_session_cli.py`
- Test: `tests/alt_linux/test_install_session_api.py`

**Interfaces:** V2 provides authenticated manifest/artifact reads and one claim endpoint. CLI adds `authorize-execution` and `cancel-execution`.

- [ ] **Step 1: Write failing V2 routing tests**

```python
def test_bundle_route_requires_tls_bearer_and_exact_filename(tls_server, session):
    assert get(tls_server, session.manifest_url).status == 401
    assert get(tls_server, session.artifact_url("../status.json"), session.bearer).status == 404
    assert get(tls_server, session.artifact_url("autoinstall.scm"), session.bearer).headers["Cache-Control"] == "no-store"
```

- [ ] **Step 2: Verify failure**

Run: `pytest tests/alt_linux/test_install_execution_api.py tests/alt_linux/test_install_session_cli.py -q`

Expected: routes and commands do not exist.

- [ ] **Step 3: Implement bounded TLS-only APIs**

Keep every V1 method and route unchanged. Under `/v2/install-sessions/<id>/execution/`, require TLS and a valid Bearer credential, stream only an exact regular expected file with bounded length and no-store, and provide atomic claim. The CLI requires root plus exact `--plan-sha256`, `--inventory-sha256`, `--disk-fingerprint`, `--confirm-target`, and `--reason`; show/list redact execution internals and all secret material.

- [ ] **Step 4: Verify**

Run: `pytest tests/alt_linux/test_install_execution_api.py tests/alt_linux/test_install_session_cli.py tests/alt_linux/test_install_session_api.py -q`

Expected: plain HTTP, redirects, unknown paths and missing/invalid credentials fail with no fallback.

- [ ] **Step 5: Commit**

```bash
git add deploy/alt-linux/api/install_session_api.py deploy/alt-linux/api/install_session_server.py deploy/alt-linux/control/alt_deploy/cli.py tests/alt_linux/test_install_execution_api.py tests/alt_linux/test_install_session_cli.py tests/alt_linux/test_install_session_api.py
git commit -m "feat(alt-install): serve execution bundles over TLS"
```

### Task 4: Add helper bundle verification and loopback metadata relay

**Files:**
- Modify: `deploy/alt-linux/install-agent/helper/command.go`
- Modify: `deploy/alt-linux/install-agent/helper/cmd/alt-install-helper/main.go`
- Create: `deploy/alt-linux/install-agent/helper/execution.go`
- Create: `deploy/alt-linux/install-agent/helper/execution_test.go`
- Create: `deploy/alt-linux/install-agent/v2/alt-install-execution-agent`
- Create: `deploy/alt-linux/install-agent/v2/lib/config.sh`
- Create: `deploy/alt-linux/install-agent/v2/lib/protocol.sh`
- Create: `deploy/alt-linux/install-agent/v2/lib/ui.sh`
- Test: `tests/test_alt_install_execution_agent.py`

**Interfaces:** Add helper commands `download-execution-bundle`, `verify-execution-bundle`, and `serve-execution-metadata`; V2 agent either returns after safe handoff or holds indefinitely without writing.

- [ ] **Step 1: Write failing Go and Bash tests**

```go
func TestServeExecutionMetadataRejectsQueryAndTraversal(t *testing.T) {
    relay := startRelay(t, validBundle(t), time.Now().Add(time.Minute))
    requireStatus(t, relay.URL+"/autoinstall.scm?x=1", http.StatusNotFound)
    requireStatus(t, relay.URL+"/../status.json", http.StatusNotFound)
}
```

```python
def test_agent_holds_without_execution_authorization(tmp_path):
    completed = run_agent(tmp_path, execution_state="not_authorized")
    assert "terminal=execution_pending" in completed.stdout
    assert destructive_commands_were_not_called(completed)
```

- [ ] **Step 2: Verify failure**

Run: `cd deploy/alt-linux/install-agent/helper && go test ./...`

Run: `pytest tests/test_alt_install_execution_agent.py -q`

Expected: missing execution commands and V2 agent.

- [ ] **Step 3: Implement exact verification and relay**

Use a Go TLS client with embedded CA, exact HTTPS URL, no proxy, redirect rejection and response limits. Verify canonical signed manifest and plan/inventory/fingerprint/path/expiry bindings plus all four artifact hashes before listening. Bind only `127.0.0.1:18192`; accept GET/HEAD for four literal paths, reject queries/traversal/every other method, send fixed lengths/no-store, and stop after every file is served or deadline. The Bash agent repeats V1 plan verification and disk preflight immediately before relay launch, records handoff, backgrounds relay and returns; every other branch invokes terminal hold.

- [ ] **Step 4: Verify**

Run: `cd deploy/alt-linux/install-agent/helper && go test ./...`

Run: `pytest tests/test_alt_install_execution_agent.py tests/test_alt_install_agent_v1.py -q`

Expected: relay refusal coverage passes and V1 retains no-write behaviour.

- [ ] **Step 5: Commit**

```bash
git add deploy/alt-linux/install-agent/helper deploy/alt-linux/install-agent/v2 tests/test_alt_install_execution_agent.py
git commit -m "feat(alt-install): verify and relay execution metadata"
```

### Task 5: Build and verify an opt-in managed V2 ISO

**Files:**
- Create: `deploy/alt-linux/iso/agent-v2/build-managed-iso.sh`
- Create: `deploy/alt-linux/iso/agent-v2/verify-managed-iso.sh`
- Create: `deploy/alt-linux/iso/agent-v2/boot-menu/grub.cfg.patch`
- Create: `deploy/alt-linux/iso/agent-v2/boot-menu/isolinux.cfg.patch`
- Create: `deploy/alt-linux/iso/agent-v2/initrd-overlay/lib/initrd/post/network-up/99-alt-install-execution-v2`
- Modify: `deploy/alt-linux/release/build-managed-iso-release.sh`
- Test: `tests/test_alt_install_execution_iso.py`

**Interfaces:** Output immutable `alt-kworkstation-11.4-agent-v2-<release-id>.iso` plus non-secret sidecar manifest.

- [ ] **Step 1: Write the failing menu contract**

```python
def test_v2_iso_has_opt_in_execution_menu_and_loopback_metadata(tmp_path):
    grub = extract(build_v2_fixture(tmp_path), "/boot/grub/grub.cfg")
    assert 'menuentry "Signed-plan installation [ROOT APPROVAL REQUIRED]"' in grub
    assert "ai curl=http://127.0.0.1:18192" in grub
    assert "set default=harddisk" in grub
    assert "curl=http://192.168.100.17" not in grub
```

- [ ] **Step 2: Verify failure**

Run: `pytest tests/test_alt_install_execution_iso.py -q`

Expected: V2 builder and verifier are absent.

- [ ] **Step 3: Implement fixed-point ISO build**

Reuse V1's source identity, atomic staging and final-size fixed point. Embed CA, public key, V2 helper and agent only. Preserve normal install and V1 menus. Add one UEFI-only non-default entry with V2 mode, TLS controller URL, `systemd.unit=install2.target`, loopback `ai curl`, DHCP and console. Verify exact payload/modes, no secret-like files, exact command line and rejection of unsafe output replacement or controller URL.

- [ ] **Step 4: Verify**

Run: `pytest tests/test_alt_install_execution_iso.py tests/test_alt_install_agent_v1_release.py -q`

Expected: V2 contract passes and V1 release behaviour remains unchanged.

- [ ] **Step 5: Commit**

```bash
git add deploy/alt-linux/iso/agent-v2 deploy/alt-linux/release/build-managed-iso-release.sh tests/test_alt_install_execution_iso.py
git commit -m "feat(alt-install): build opt-in execution ISO"
```

### Task 6: Prove execution only on a disposable OVMF target

**Files:**
- Create: `deploy/alt-linux/qemu/run-agent-v2-execution-acceptance.sh`
- Create: `deploy/alt-linux/qemu/agent_v2_test_api.py`
- Create: `tests/test_alt_install_execution_qemu.py`
- Create: `docs/verification/alt-install-execution-v2-qemu.md`

**Interfaces:** Produce a non-secret receipt with root-authorization timeline, selected target QMP counters, read-only sentinel counters and postflight result.

- [ ] **Step 1: Write the failing evidence assertions**

```python
def test_execution_requires_root_authorization_and_never_writes_sentinel(evidence):
    assert evidence.before_authorization.target_write_bytes == 0
    assert evidence.before_authorization.sentinel_write_bytes == 0
    assert evidence.after_install.target_write_bytes > 0
    assert evidence.after_install.sentinel_write_bytes == 0
    assert evidence.postflight_state == "installed"
```

- [ ] **Step 2: Verify failure**

Run: `pytest tests/test_alt_install_execution_qemu.py -q`

Expected: V2 QEMU harness is absent.

- [ ] **Step 3: Implement generic-OVMF acceptance**

Clone the canonical V1 QMP safety patterns, not VM114 configuration. Create a writable disposable target and read-only sentinel, both with QMP counters and before/after SHA-256. Prove zero writes while waiting; run the real root authorization for `/dev/vda`; require verified handoff, stock installer completion, then boot without ISO and require authenticated postflight. Clean only harness-created process, TAP and temporary directory.

- [ ] **Step 4: Verify**

Run: `pytest tests/test_alt_install_execution_qemu.py -q`

Run: `deploy/alt-linux/qemu/run-agent-v2-execution-acceptance.sh --check-prerequisites`

Expected: contract tests pass; prerequisites report exact missing host tools without claiming acceptance.

- [ ] **Step 5: Commit**

```bash
git add deploy/alt-linux/qemu/run-agent-v2-execution-acceptance.sh deploy/alt-linux/qemu/agent_v2_test_api.py tests/test_alt_install_execution_qemu.py docs/verification/alt-install-execution-v2-qemu.md
git commit -m "test(alt-install): prove execution on disposable OVMF"
```

### Task 7: Add backup-gated rollout and a validation-only real-machine pilot gate

**Files:**
- Create: `deploy/alt-linux/release/rollout-install-execution-v2.sh`
- Create: `deploy/alt-linux/release/verify-install-execution-pilot.py`
- Create: `docs/runbooks/alt-install-execution-v2.md`
- Create: `docs/verification/alt-install-execution-v2-pilot-template.md`
- Test: `tests/test_alt_install_execution_rollout.py`

**Interfaces:** Consumes successful backup/rehearsal, merged commit, immutable V2 ISO, Task 6 receipt and a pilot record; produces production rollout receipt and pilot validation only.

- [ ] **Step 1: Write the failing gates**

```python
def test_rollout_stops_before_mutation_without_rehearsed_backup(tmp_path):
    completed = run_rollout(tmp_path, backup_state="not_rehearsed")
    assert completed.returncode != 0
    assert not completed.service_files_changed

def test_pilot_requires_asset_disk_iso_window_and_owner(tmp_path):
    assert validate_pilot_record(tmp_path / "missing-window.json").code == "pilot_window_missing"
```

- [ ] **Step 2: Verify failure**

Run: `pytest tests/test_alt_install_execution_rollout.py -q`

Expected: rollout and pilot gate are absent.

- [ ] **Step 3: Implement deployment and pilot validation**

Require named backup/rehearsal, no active execution session, merged commit and source ISO digest. Stage V2 runtime, install/health-check only V2 listener, publish immutable V2 ISO and run Task 6 against production before receipt. On failure stop before the next mutation and restore only staged V2 runtime. Validate a pilot JSON containing asset ID, DMI UUID, exact disk fingerprint/path, ISO digest, maintenance start/end and rollback owner. It must never authorize execution or access a disk.

- [ ] **Step 4: Verify**

Run: `pytest tests/test_alt_install_execution_rollout.py -q`

Run: `python -m pytest -q`

Expected: focused tests and Linux CI regression pass. On Windows, record the existing POSIX-only ALT suite skip separately; it is not Linux acceptance.

- [ ] **Step 5: Commit**

```bash
git add deploy/alt-linux/release/rollout-install-execution-v2.sh deploy/alt-linux/release/verify-install-execution-pilot.py docs/runbooks/alt-install-execution-v2.md docs/verification/alt-install-execution-v2-pilot-template.md tests/test_alt_install_execution_rollout.py
git commit -m "feat(alt-install): gate execution rollout and pilot"
```

## Plan self-review

- **Spec coverage:** Tasks 1--3 implement TLS, root authorization, state and API; Tasks 4--5 implement relay and ISO; Task 6 proves write boundaries/postflight; Task 7 adds rollout and pilot gates.
- **No placeholders:** every task has named files, interfaces, test code, commands, expected output and a commit.
- **Compatibility:** V1 uses a separate service/port/menu and remains no-write throughout.
