# ALT Workstation Provisioning OR-2B2 Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Detect a non-executable `alt-job-stage` before Ansible starts and prove the existing controller permission audit/repair failure contracts as formal operational outcomes.

**Architecture:** `AnsibleController._validate_provision_files()` keeps the existing required-file map and adds one worker-context executable check for `job_stage_helper`. Worker behavior is not changed: a controller configuration error is recorded as `failed/connecting` and returns process code `1`. `ControllerPermissionAuditor` remains limited to `altserver`-owned private state; OR-2B2 primarily adds executable tests and only changes that module if a RED test proves a production defect.

**Tech Stack:** Python 3.11, pytest, pathlib, `os.access`, dataclasses, existing `AnsibleController`, `worker.run_job`, `JobRepository`, `AssignmentRepository`, `ControllerPermissionAuditor`, GitHub Actions.

## Global Constraints

- Base `main` commit: `d9d2a3abeb5aeed8dad6dc525e0e7f51f858ff7a`.
- Missing and non-executable helper must keep `error.code=provision_not_configured` and internal exit code `7`.
- Worker process return code for the configuration failure must remain `1`.
- Failed helper jobs must remain `state=failed`, `stage=connecting`, with no result or assignment.
- Missing assets use `details.missing`; executable failures use `details.not_executable`; empty keys are omitted.
- `os.access(path, os.X_OK)` is the execution predicate.
- Do not add root-owned runtime files to `ControllerPermissionAuditor` policies.
- Do not change worker stage ordering, Vault checks, SSH classification, Ansible roles, installer modes, systemd units, web API, or web UI.
- Permission public codes and exit codes remain unchanged.
- Root-required and blocked repair must call neither `os.fchown` nor `os.fchmod`.
- Unexpected repair failure may report only `exc.__class__.__name__`; transactional rollback is not claimed.
- Permission operations must preserve pre-existing sentinel job and assignment bytes.
- Tests use only synthetic controller state under `tmp_path`; no real controller, secrets, SSH targets, or reference VM.
- Temporary CI workflows and patch helpers must be removed before Ready for review.

---

## File Map

**Modify production:**

- `deploy/alt-linux/control/alt_deploy/ansible.py` — add structured `job_stage_helper` executable validation.

**Conditional production modification only after a proven RED defect:**

- `deploy/alt-linux/control/alt_deploy/controller_permissions.py` — preserve existing contracts; change only if a focused test demonstrates incorrect behavior.

**Modify test support:**

- `tests/alt_linux/support/controller_sandbox.py` — provision-boundary assets and queued/launching job helpers if they reduce repeated setup.
- `tests/alt_linux/support/outcomes.py` — two helper and five permission outcomes.

**Create tests:**

- `tests/alt_linux/test_or2b2_runtime_permissions.py` — helper validation, worker integration, retryability, permission outcome evidence.

**Modify tests:**

- `tests/alt_linux/test_operational_reliability_contract.py` — exact 26-scenario catalog and boundary invariants.
- `tests/alt_linux/test_controller_permissions.py` — audit/repair spies, race/failure/idempotency and sentinel isolation.

---

### Task 1: Extend the Operational Outcome Catalog

**Files:**
- Modify: `tests/alt_linux/support/outcomes.py`
- Modify: `tests/alt_linux/test_operational_reliability_contract.py`

**Interfaces:**
- Consumes: existing immutable `OperationalOutcome` and 19 outcomes.
- Produces: 26 exact outcomes using boundaries `worker_configuration`, `permission_audit`, `permission_repair_authorization`, `permission_repair_safety`, `permission_repair_execution`, and `permission_repair`.

- [ ] **Step 1: Write the failing exact-catalog tests**

Add these IDs to `EXPECTED_SCENARIO_IDS`:

```python
{
    "provision-stage-helper-missing",
    "provision-stage-helper-not-executable",
    "controller-permissions-unhealthy",
    "controller-permissions-repair-root-required",
    "controller-permissions-repair-blocked",
    "controller-permissions-repair-failed",
    "controller-permissions-repaired",
}
```

Add the new allowed boundaries and exact assertions:

```python
if item.boundary == "worker_configuration":
    assert item.error_code == "provision_not_configured"
    assert item.command_exit_code == 1
    assert item.job_state == "failed"
    assert item.job_stage == "connecting"
    assert item.assignment_created is False
    assert item.retryable is True
    assert item.failure_kind is None

permission_contracts = {
    "permission_audit": ("controller_permissions_unhealthy", 8, True),
    "permission_repair_authorization": ("root_required", 3, True),
    "permission_repair_safety": (
        "controller_permissions_repair_blocked",
        9,
        True,
    ),
    "permission_repair_execution": (
        "controller_permissions_repair_failed",
        10,
        True,
    ),
    "permission_repair": (None, 0, None),
}
if item.boundary in permission_contracts:
    error_code, exit_code, retryable = permission_contracts[item.boundary]
    assert item.error_code == error_code
    assert item.command_exit_code == exit_code
    assert item.job_state is None
    assert item.job_stage is None
    assert item.assignment_created is False
    assert item.retryable is retryable
    assert item.failure_kind is None
```

Add:

```python
def test_catalog_contains_twenty_six_proven_outcomes() -> None:
    assert len(PROVEN_OPERATIONAL_OUTCOMES) == 26
```

- [ ] **Step 2: Run the contract tests and verify RED**

Run:

```bash
python -m pytest -q tests/alt_linux/test_operational_reliability_contract.py
```

Expected: FAIL because the seven OR-2B2 records and boundaries do not exist.

- [ ] **Step 3: Add the seven immutable records**

Use the two helper records:

```python
OperationalOutcome(
    scenario_id="provision-stage-helper-missing",
    boundary="worker_configuration",
    error_code="provision_not_configured",
    command_exit_code=1,
    job_state="failed",
    job_stage="connecting",
    assignment_created=False,
    retryable=True,
    required_evidence=(
        "structured_configuration_detail",
        "worker_exit_one",
        "failed_job_finished_at",
        "connecting_stage_preserved",
        "ansible_subprocess_not_called",
        "no_result_created",
        "no_assignment_created",
        "new_job_retry_after_fix",
    ),
)
```

Repeat with scenario ID `provision-stage-helper-not-executable`.

Add the five permission records with the exact code/exit/boundary contracts from Step 1. Required evidence:

```python
# unhealthy
("safe_path_matrix", "sentinel_job_unchanged", "sentinel_assignment_unchanged")

# root required
("authorization_before_mutation", "no_fchown", "no_fchmod", "sentinels_unchanged")

# blocked
("safety_block_before_mutation", "no_fchown", "no_fchmod", "sentinels_unchanged")

# failed
("partial_mutation_possible", "safe_system_error_class_only", "file_descriptors_closed")

# repaired
("changed_paths_exact", "post_repair_audit_ok", "second_repair_idempotent", "jobs_unchanged", "assignments_unchanged")
```

- [ ] **Step 4: Run the contract tests and verify GREEN**

```bash
python -m pytest -q tests/alt_linux/test_operational_reliability_contract.py
```

Expected: PASS with exactly 26 outcomes.

- [ ] **Step 5: Commit**

```bash
git add tests/alt_linux/support/outcomes.py \
  tests/alt_linux/test_operational_reliability_contract.py
git commit -m "test: define OR-2B2 operational outcomes"
```

---

### Task 2: Add the Stage-Helper Executable Gate

**Files:**
- Modify: `deploy/alt-linux/control/alt_deploy/ansible.py`
- Create/Modify: `tests/alt_linux/test_or2b2_runtime_permissions.py`

**Interfaces:**
- Consumes: `AnsibleController._validate_provision_files(job: JobRecord) -> None`.
- Produces: `ControlError(code="provision_not_configured", exit_code=7)` with non-empty `details.missing` and/or `details.not_executable`.

- [ ] **Step 1: Write focused failing tests**

Create a helper that prepares every required file except the selected helper condition. Add direct tests:

```python
def test_missing_stage_helper_is_only_missing(...) -> None:
    controller, job, helper = prepare_controller_boundary(..., helper_mode=None)
    with pytest.raises(ControlError) as caught:
        controller._validate_provision_files(job)
    assert caught.value.code == "provision_not_configured"
    assert caught.value.exit_code == 7
    assert caught.value.details == {
        "missing": [{"name": "job_stage_helper", "path": str(helper)}]
    }


def test_non_executable_stage_helper_is_structured(...) -> None:
    controller, job, helper = prepare_controller_boundary(..., helper_mode=0o644)
    with pytest.raises(ControlError) as caught:
        controller._validate_provision_files(job)
    assert caught.value.details == {
        "not_executable": [
            {"name": "job_stage_helper", "path": str(helper)}
        ]
    }


def test_executable_stage_helper_passes_validation(...) -> None:
    controller, job, _ = prepare_controller_boundary(..., helper_mode=0o755)
    controller._validate_provision_files(job)
```

Add a mixed failure test proving both non-empty keys appear and empty keys do not.

- [ ] **Step 2: Run focused tests and verify RED**

```bash
python -m pytest -q tests/alt_linux/test_or2b2_runtime_permissions.py -k "stage_helper and validation"
```

Expected: non-executable helper test fails because current code checks only `is_file()`.

- [ ] **Step 3: Implement the minimal gate**

In `ansible.py`, import `os` and replace the final error construction in `_validate_provision_files()` with:

```python
helper = self.settings.job_stage_helper_path
not_executable = []
if helper.is_file() and not os.access(helper, os.X_OK):
    not_executable.append(
        {
            "name": "job_stage_helper",
            "path": str(helper),
        }
    )

details: dict[str, object] = {}
if missing:
    details["missing"] = missing
if not_executable:
    details["not_executable"] = not_executable

if details:
    raise ControlError(
        code="provision_not_configured",
        message=(
            "ALT workstation provisioning "
            "is not fully configured"
        ),
        exit_code=7,
        details=details,
    )
```

Do not change the required-file dictionary or any Ansible command construction.

- [ ] **Step 4: Run focused tests and verify GREEN**

```bash
python -m pytest -q tests/alt_linux/test_or2b2_runtime_permissions.py -k "stage_helper and validation"
```

Expected: PASS.

- [ ] **Step 5: Commit**

```bash
git add deploy/alt-linux/control/alt_deploy/ansible.py \
  tests/alt_linux/test_or2b2_runtime_permissions.py
git commit -m "fix: reject non-executable ALT stage helper"
```

---

### Task 3: Prove Worker Failure State and Retryability

**Files:**
- Modify: `tests/alt_linux/support/controller_sandbox.py`
- Modify: `tests/alt_linux/test_or2b2_runtime_permissions.py`

**Interfaces:**
- Consumes: real `worker.run_job()`, real `AnsibleController`, `JobRepository.create()`, and `JobStageManager.advance(..., "launching")`.
- Produces: executable proof for `failed/connecting` and a successful new job after helper repair.

- [ ] **Step 1: Add reusable provision-boundary setup**

Add to `ControllerSandbox`:

```python
def configure_provision_boundary(self, *, helper_mode: int | None) -> dict[str, Path]:
    ansible_playbook = self.install_fake_ansible_playbook()
    self.settings.private_key_file.parent.mkdir(parents=True, exist_ok=True)
    self.settings.private_key_file.write_text("test-key\n", encoding="utf-8")
    self.settings.known_hosts_file.write_text("test-host\n", encoding="utf-8")
    playbook = self.settings.ansible_project_dir / "playbooks" / "02-provision-account.yml"
    playbook.parent.mkdir(parents=True, exist_ok=True)
    playbook.write_text("---\n", encoding="utf-8")
    helper = self.settings.job_stage_helper_path
    if helper_mode is not None:
        helper.parent.mkdir(parents=True, exist_ok=True)
        helper.write_text("#!/bin/sh\nexit 0\n", encoding="utf-8")
        helper.chmod(helper_mode)
    return {
        "ansible_playbook": ansible_playbook,
        "private_key": self.settings.private_key_file,
        "known_hosts": self.settings.known_hosts_file,
        "provision_playbook": playbook,
        "job_stage_helper": helper,
    }
```

Use only synthetic content.

- [ ] **Step 2: Write the worker failure tests**

For both missing and mode `0644`:

```python
job = JobRepository(settings).create(provision_request())
JobStageManager(settings).advance(job.job_id, "launching")
monkeypatch.setattr(
    "alt_deploy.ansible.subprocess.run",
    lambda *args, **kwargs: pytest.fail("subprocess must not run"),
)
registration_before = registration_path.read_bytes()
rc = run_job(job.job_id, settings, AnsibleController(settings))
stored = jobs.get(job.job_id)
assert rc == 1
assert stored.state == "failed"
assert stored.stage == "connecting"
assert stored.status["finished_at"]
assert stored.status["error"].startswith("provision_not_configured:")
assert not (stored.job_dir / "result.json").exists()
assert assignments.get(TEST_MACHINE_UUID) is None
assert registration_path.read_bytes() == registration_before
```

- [ ] **Step 3: Run worker tests and verify GREEN against Task 2**

```bash
python -m pytest -q tests/alt_linux/test_or2b2_runtime_permissions.py -k "worker and stage_helper"
```

Expected: PASS; if it fails, fix test setup, not worker production behavior unless a spec contradiction is proven.

- [ ] **Step 4: Write retryability test through the real controller**

Create first failed job with helper `0644`. Then make helper `0755`, create a second job, advance it to `launching`, and monkeypatch only `alt_deploy.ansible.subprocess.run`:

```python
def fake_run(command, **kwargs):
    assert os.access(settings.job_stage_helper_path, os.X_OK)
    result_arg = next(
        item for item in command if item.startswith("provision_result_file=")
    )
    result_path = Path(result_arg.split("=", 1)[1])
    atomic_write_json(result_path, successful_provision_result(job_id=second.job_id))
    manager = JobStageManager(settings)
    for stage in ("identity", "employee", "login_screen", "verifying"):
        manager.advance(second.job_id, stage)
    return subprocess.CompletedProcess(command, 0)
```

Then assert:

```python
assert run_job(second.job_id, settings, AnsibleController(settings)) == 0
assert jobs.get(first.job_id).state == "failed"
assert jobs.get(second.job_id).state == "successful"
assert jobs.get(second.job_id).stage == "complete"
assert assignments.get(TEST_MACHINE_UUID)["job_id"] == second.job_id
```

- [ ] **Step 5: Run retryability test and verify GREEN**

```bash
python -m pytest -q tests/alt_linux/test_or2b2_runtime_permissions.py -k "retry_after_helper_fix"
```

Expected: PASS through real `_validate_provision_files()`.

- [ ] **Step 6: Commit**

```bash
git add tests/alt_linux/support/controller_sandbox.py \
  tests/alt_linux/test_or2b2_runtime_permissions.py
git commit -m "test: prove ALT helper failure recovery"
```

---

### Task 4: Prove Permission Audit Outcomes and Isolation

**Files:**
- Modify: `tests/alt_linux/test_controller_permissions.py`
- Modify: `tests/alt_linux/test_or2b2_runtime_permissions.py`

**Interfaces:**
- Consumes: existing `ControllerPermissionAuditor.check()` and CLI `controller permissions`.
- Produces: exact safe matrices and byte-equivalent sentinel job/assignment evidence.

- [ ] **Step 1: Add a sentinel-state helper**

Create a synthetic queued job and assignment payload with different machine UUIDs, then capture:

```python
sentinels = {
    "job_request": (job.job_dir / "request.json").read_bytes(),
    "job_status": (job.job_dir / "status.json").read_bytes(),
    "assignment": assignment_path.read_bytes(),
}
```

Do not place secret-like keys in sentinel payloads.

- [ ] **Step 2: Add unhealthy audit tests**

Cover wrong mode, missing path, and symlink/type mismatch. Assert:

```python
assert rc == 8
assert payload["error"]["code"] == "controller_permissions_unhealthy"
paths = payload["error"]["details"]["paths"]
assert set(paths) == EXPECTED_PATH_KEYS
assert paths[affected][expected_false_key] is False
assert "fixture ciphertext" not in serialized
assert "fixture password" not in serialized
assert_sentinel_bytes_unchanged(...)
```

Use controlled metadata mocks for owner/group mismatch rather than requiring privileged `chown`.

- [ ] **Step 3: Run audit tests**

```bash
python -m pytest -q tests/alt_linux/test_controller_permissions.py -k "reports_unhealthy or audit_isolation"
```

Expected: PASS on existing production behavior. A failure indicates either fixture setup or a proven production defect requiring review before changing code.

- [ ] **Step 4: Bind the audit test to the outcome record**

Use `get_outcome("controller-permissions-unhealthy")` and assert its exact code/exit/retryability before the CLI assertions.

- [ ] **Step 5: Commit**

```bash
git add tests/alt_linux/test_controller_permissions.py \
  tests/alt_linux/test_or2b2_runtime_permissions.py
git commit -m "test: prove controller permission audit outcomes"
```

---

### Task 5: Prove Permission Repair Safety, Failure Redaction, and Idempotency

**Files:**
- Modify: `tests/alt_linux/test_controller_permissions.py`
- Conditional Modify: `deploy/alt-linux/control/alt_deploy/controller_permissions.py`

**Interfaces:**
- Consumes: existing `ControllerPermissionAuditor.repair()`.
- Produces: executable evidence for root-required, blocked, failed, and repaired outcomes.

- [ ] **Step 1: Strengthen root-required test with syscall spies**

Monkeypatch:

```python
monkeypatch.setattr(os, "geteuid", lambda: 1000)
monkeypatch.setattr(os, "fchown", lambda *args: pytest.fail("fchown called"))
monkeypatch.setattr(os, "fchmod", lambda *args: pytest.fail("fchmod called"))
```

Assert `root_required/3` and unchanged sentinel bytes.

- [ ] **Step 2: Strengthen blocked tests with syscall spies**

For missing path, symlink and lstat/open race, use the same mutation spies. Assert exact `missing_paths`/`unsafe_paths`, code `controller_permissions_repair_blocked`, exit `9`, and unchanged sentinels.

For the race case monkeypatch `_open_policy()` to raise `FileNotFoundError(errno.ENOENT, ...)` for one named policy after the initial lstat pass.

- [ ] **Step 3: Add execution-failure redaction and descriptor-closure tests**

Parameterize `os.fchown` and `os.fchmod` failures:

```python
raise PermissionError("sensitive path marker")
```

Assert:

```python
assert rc == 10
assert payload["error"]["code"] == "controller_permissions_repair_failed"
assert payload["error"]["details"] == {"system_error": "PermissionError"}
assert "sensitive path marker" not in stdout
```

Track descriptors returned from `_open_policy()` and spy on `os.close` to prove every opened descriptor is closed in `finally`.

Do not assert rollback of earlier paths.

- [ ] **Step 4: Add successful repair and idempotency test**

With wrong directory mode `0755` and secret mode `0644`, mocked root EUID and current user/group as configured principals:

```python
first = auditor.repair()
assert first["changed"] == list(EXPECTED_PATH_KEYS_IN_POLICY_ORDER)
assert auditor.check()["status"] == "ok"
second = auditor.repair()
assert second["changed"] == []
assert_sentinel_bytes_unchanged(...)
```

- [ ] **Step 5: Run all permission repair tests**

```bash
python -m pytest -q tests/alt_linux/test_controller_permissions.py
```

Expected: PASS without production changes. If a test proves a real defect, make the smallest possible change in `controller_permissions.py`, add a regression assertion for that exact defect, and document it in the verification note.

- [ ] **Step 6: Commit**

```bash
git add tests/alt_linux/test_controller_permissions.py \
  deploy/alt-linux/control/alt_deploy/controller_permissions.py
git commit -m "test: prove controller permission repair contracts"
```

If the production file did not change, omit it from `git add`.

---

### Task 6: Full Verification, Review, and PR Preparation

**Files:**
- Create: `docs/superpowers/plans/2026-07-20-alt-or2b2-verification.md`
- Temporary Create/Delete: `.github/workflows/or2b2-verification.yml`

**Interfaces:**
- Consumes: final OR-2B2 branch.
- Produces: fresh counts, compile/diff evidence, clean PR diff, and no temporary workflow.

- [ ] **Step 1: Run the focused gate**

```bash
python -m pytest -q \
  tests/alt_linux/test_or2b2_runtime_permissions.py \
  tests/alt_linux/test_controller_permissions.py \
  tests/alt_linux/test_operational_reliability_contract.py
```

Expected: PASS.

- [ ] **Step 2: Run the complete ALT suite**

```bash
python -m pytest -q tests/alt_linux
```

Expected: PASS.

- [ ] **Step 3: Run the complete repository suite**

```bash
python -m pytest -q
```

Expected: PASS with zero failures.

- [ ] **Step 4: Compile production boundaries**

```bash
python -m py_compile \
  deploy/alt-linux/control/alt_deploy/ansible.py \
  deploy/alt-linux/control/alt_deploy/controller_permissions.py
```

Expected: exit `0`.

- [ ] **Step 5: Check diff integrity**

```bash
git diff --check origin/main...HEAD
```

Expected: no output and exit `0`.

- [ ] **Step 6: Write verification evidence**

Record exact branch SHA, merge-ref SHA, command outputs, counts, production files changed, and whether `controller_permissions.py` remained unchanged. State explicitly that no real controller state, helper, Vault, key, or target VM was accessed.

- [ ] **Step 7: Delete temporary CI workflow**

Remove `.github/workflows/or2b2-verification.yml` and verify it is absent from the final changed-file list.

- [ ] **Step 8: Review the final diff**

Confirm:

```text
production scope: ansible.py only, unless a proven permission defect required a minimal fix
no worker/Ansible role/installer changes
26 exact outcomes
no secret-bearing fixture values in JSON evidence
no temporary workflow or patch helper
```

- [ ] **Step 9: Commit evidence and open/update PR**

```bash
git add docs/superpowers/plans/2026-07-20-alt-or2b2-verification.md
git commit -m "docs: verify OR-2B2 runtime permission outcomes"
```

Create or update a draft PR, wait for final merge-ref checks, then mark it Ready for review. Do not merge without explicit user confirmation.
