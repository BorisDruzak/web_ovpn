# ALT stale registration recovery Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Add an auditable root-only recovery command that archives one assigned machine's legacy stale `failed/` registration record without altering its assignment or target workstation.

**Architecture:** A focused recovery service owns the narrow legacy predicate, safe byte preservation, manifest creation and idempotent cleanup under the existing controller lock. The CLI exposes read-only preview and root-gated apply; it is not a generic JSON editor or release workflow.

**Tech Stack:** Python 3.12 standard library, existing `alt_deploy` JSON and locking conventions, pytest, argparse.

## Global Constraints

- Accept only a regular file in `registration/failed/` whose basename matches its UUID or machine key, JSON status is exactly `awaiting_assignment`, and machine has an existing assignment.
- Preserve original record bytes before deleting the active record; write SHA-256, operator identity, reason and timestamp into a private recovery manifest.
- Fail closed for symlinks, malformed JSON, identity/status mismatch, unassigned machines and active jobs.
- Do not change assignments, jobs, Vault, SSH material, unrelated registrations, or the target workstation.
- Apply is root-only and repeat apply returns the completed recovery archive without another mutation.

---

### Task 1: Define recovery service and safety tests

**Files:**
- Create: `deploy/alt-linux/control/alt_deploy/stale_registration_recovery.py`
- Create: `tests/alt_linux/test_stale_registration_recovery.py`

**Interfaces:**
- `StaleRegistrationRecoveryService(settings).preview(identifier) -> RecoveryPreview`
- `StaleRegistrationRecoveryService(settings).apply(identifier, reason, operator_env=None) -> RecoveryResult`
- Both result types expose `to_public_dict()`.

- [ ] **Step 1: Write failing preview and apply tests**

```python
def test_preview_describes_only_assigned_failed_awaiting_record(tmp_path: Path) -> None:
    sandbox = make_controller_sandbox(tmp_path)
    source = write_registration(sandbox.settings, "failed", payload_with_status("awaiting_assignment"))
    AssignmentRepository(sandbox.settings).write(TEST_MACHINE_UUID, assignment_payload())

    preview = StaleRegistrationRecoveryService(sandbox.settings).preview(TEST_MACHINE_UUID)

    assert preview.source_state == "failed"
    assert preview.record_sha256 == hashlib.sha256(source.read_bytes()).hexdigest()
    assert source.exists()

def test_apply_archives_exact_bytes_then_removes_only_stale_source(tmp_path: Path) -> None:
    sandbox = make_controller_sandbox(tmp_path)
    source = write_registration(sandbox.settings, "failed", payload_with_status("awaiting_assignment"))
    original = source.read_bytes()
    AssignmentRepository(sandbox.settings).write(TEST_MACHINE_UUID, assignment_payload())

    result = StaleRegistrationRecoveryService(sandbox.settings).apply(
        TEST_MACHINE_UUID, "Clear legacy failed registration", operator_env=operator_env()
    )

    assert not source.exists()
    assert recovery_record(sandbox.settings, result.recovery_id).read_bytes() == original
    assert AssignmentRepository(sandbox.settings).get(TEST_MACHINE_UUID) is not None
```

- [ ] **Step 2: Verify RED**

Run: `python3 -m pytest -q tests/alt_linux/test_stale_registration_recovery.py`

Expected: collection fails because `alt_deploy.stale_registration_recovery` does not exist.

- [ ] **Step 3: Implement minimal service**

```python
class StaleRegistrationRecoveryService:
    def preview(self, identifier: str) -> RecoveryPreview: ...

    def apply(self, identifier: str, reason: str, *, operator_env: Mapping[str, str] | None = None) -> RecoveryResult:
        with exclusive_lock(self.settings.lock_file):
            completed = self._find_completed(identifier)
            if completed is not None:
                return self._result_from_completed(completed)
            candidate = self._load_exact_stale_candidate(identifier)
            self._assert_assignment_present(candidate.identity.machine_uuid)
            self._assert_no_active_job(candidate.identity.machine_uuid)
            return self._archive_and_remove(candidate, validate_archive_reason(reason), operator_env)
```

Use `lstat`, `O_NOFOLLOW`, SHA-256 and fsync-based atomic writes. Store original bytes and `manifest.json` in a `recovery-<UTC>-<token>` directory under `Settings.machine_archives_dir`. Remove the source only after the archive and manifest are durable.

- [ ] **Step 4: Add rejection and idempotency tests**

```python
@pytest.mark.parametrize("state,status", [("ready", "awaiting_assignment"), ("failed", "failed")])
def test_preview_rejects_non_legacy_conflict(tmp_path: Path, state: str, status: str) -> None: ...

def test_apply_rejects_unassigned_stale_record(tmp_path: Path) -> None: ...
def test_apply_rejects_symlink_and_preserves_source(tmp_path: Path) -> None: ...
def test_repeat_apply_returns_existing_recovery_without_second_archive(tmp_path: Path) -> None: ...
```

Run: `python3 -m pytest -q tests/alt_linux/test_stale_registration_recovery.py`

Expected: PASS.

- [ ] **Step 5: Commit**

```bash
git add deploy/alt-linux/control/alt_deploy/stale_registration_recovery.py tests/alt_linux/test_stale_registration_recovery.py
git commit -m "feat: recover stale ALT registration records"
```

### Task 2: Expose CLI preview and root-only apply

**Files:**
- Modify: `deploy/alt-linux/control/alt_deploy/cli.py`
- Modify: `tests/alt_linux/test_machine_archive_cli.py`

- [ ] **Step 1: Write failing CLI tests**

```python
def test_recovery_preview_returns_public_metadata(tmp_path: Path) -> None: ...

def test_recovery_apply_requires_root_before_mutation(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    monkeypatch.setattr(os, "geteuid", lambda: 1000)
    exit_code, payload = invoke_cli([
        "--json", "machines", "recover-stale-registration", "apply",
        TEST_MACHINE_UUID, "--reason", "legacy cleanup",
    ])
    assert exit_code == 6
    assert payload["error"]["code"] == "root_required"
```

- [ ] **Step 2: Verify RED**

Run: `python3 -m pytest -q tests/alt_linux/test_machine_archive_cli.py -k recovery`

Expected: parser rejects `recover-stale-registration`.

- [ ] **Step 3: Add parser and dispatch**

```python
recovery = machine_commands.add_parser("recover-stale-registration")
recovery_commands = recovery.add_subparsers(dest="machine_recovery_command", required=True)
recovery_preview = recovery_commands.add_parser("preview")
recovery_preview.add_argument("machine_identifier")
recovery_apply = recovery_commands.add_parser("apply")
recovery_apply.add_argument("machine_identifier")
recovery_apply.add_argument("--reason", required=True)
```

Import the recovery service, route preview without root and return `root_required` before creating a service on non-root apply.

- [ ] **Step 4: Verify GREEN and commit**

Run: `python3 -m pytest -q tests/alt_linux/test_machine_archive_cli.py -k recovery`

Expected: PASS.

```bash
git add deploy/alt-linux/control/alt_deploy/cli.py tests/alt_linux/test_machine_archive_cli.py
git commit -m "feat: expose stale registration recovery CLI"
```

### Task 3: Document, verify and publish

**Files:**
- Modify: `deploy/alt-linux/README.md`
- Modify: `docs/ALT_WORKSTATION_PROVISIONING_NEXT_STEPS.md`
- Modify: `tests/alt_linux/test_stale_registration_recovery.py`

- [ ] **Step 1: Write failing documentation assertion**

```python
def test_recovery_documentation_forbids_direct_json_edit() -> None:
    readme = (REPO_ROOT / "deploy/alt-linux/README.md").read_text(encoding="utf-8")
    assert "recover-stale-registration" in readme
    assert "Do not edit registration JSON directly" in readme
```

- [ ] **Step 2: Verify RED**

Run: `python3 -m pytest -q tests/alt_linux/test_stale_registration_recovery.py -k documentation`

Expected: FAIL because the operator documentation lacks the command and direct-edit prohibition.

- [ ] **Step 3: Document only the approved workflow**

Document preview/apply, root requirement, private recovery archive, idempotency, and the prohibition on direct registration JSON editing. State that this is neither reassignment nor a release workflow.

- [ ] **Step 4: Run full verification**

```bash
python3 -m pytest -q tests/alt_linux
python3 -m py_compile deploy/alt-linux/control/alt_deploy/*.py
bash -n deploy/alt-linux/install-control-plane.sh
cd deploy/alt-linux/ansible
ANSIBLE_CONFIG="$PWD/ansible.cfg" ansible-playbook --syntax-check playbooks/01-preflight.yml
ANSIBLE_CONFIG="$PWD/ansible.cfg" ansible-playbook --syntax-check playbooks/02-provision-account.yml
```

Expected: all commands succeed; `git diff --check` is clean.

- [ ] **Step 5: Commit and publish**

```bash
git add deploy/alt-linux/README.md docs/ALT_WORKSTATION_PROVISIONING_NEXT_STEPS.md tests/alt_linux/test_stale_registration_recovery.py
git commit -m "docs: add stale registration recovery runbook"
git push -u origin codex/recover-stale-registration
```

Open a PR to `main`, merge only after full verification, then update the server rollout worktree to the merged commit.

