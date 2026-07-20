# ALT Workstation Provisioning OR-2B1 Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Replace the duplicated shallow Vault validation in provisioning with the same safe health model used by `vault check`, while preserving existing public error codes and rejecting unhealthy Vault state before any job, launcher, target, or assignment operation.

**Architecture:** `VaultHealthChecker` becomes the single source of truth. It builds an allowlisted boolean check matrix using `Settings.service_user` ownership and dependency-gated decrypt; its public `check()` keeps the existing `vault_unhealthy/7` contract. `ProvisionPlanner` calls the checker and remaps only `vault_unhealthy` to the existing `vault_not_configured/4` envelope with the same checks. Test-only outcomes and sandbox helpers cover eight provisioning Vault outcomes, the full failure matrix, root/service-user consistency, start-before-job safety, and retryability.

**Tech Stack:** Python 3.11, pytest, dataclasses, pathlib, `pwd`, `stat`, `subprocess`, existing `alt_deploy.cli.main`, `VaultHealthChecker`, `ProvisionPlanner`, `JobRepository`, `AssignmentRepository`, GitHub Actions.

## Global Constraints

- Base `main` commit: `d4be833106c2194b3a20a00069f1ae8297f02eb4`.
- `vault check` must keep `error.code=vault_unhealthy`, exit code `7`.
- `provision preview/start` must keep `error.code=vault_not_configured`, exit code `4`.
- All three surfaces must expose the same safe `details.checks` matrix.
- Owner policy must use `Settings.service_user`, not caller EUID.
- Decrypt must not run unless file existence, owner, mode, and Vault header checks all pass.
- Missing files must retain `details.missing`; invalid header must retain `details.path`.
- No secret values, decrypted text, subprocess stdout, or subprocess stderr may enter CLI JSON, evidence metadata, or fixtures.
- All Vault failures must occur before `jobs.create()`, launcher invocation, target connection, or assignment write.
- Do not change worker, SSH classification, Ansible roles, stage-helper behavior, permission repair, web API, or web UI.
- Do not read production Vault state or access the accepted reference VM.
- Temporary CI workflow must be removed before final PR review.

---

## File Map

**Modify production:**

- `deploy/alt-linux/control/alt_deploy/vault.py` — configured-owner resolution, dependency-gated `_build_checks()`, unchanged public `check()` envelope.
- `deploy/alt-linux/control/alt_deploy/provision.py` — replace duplicate `_validate_vault()` implementation with `VaultHealthChecker` and exact remapping.

**Modify test support:**

- `tests/alt_linux/support/controller_sandbox.py` — reusable synthetic Vault boundary setup and request-file helper.
- `tests/alt_linux/support/outcomes.py` — eight OR-2B1 `vault_gate` outcomes.

**Create tests:**

- `tests/alt_linux/test_or2b1_vault_gate.py` — checker matrix, CLI surfaces, start-before-job safety, caller consistency, retryability, secret-redaction assertions.

**Modify tests:**

- `tests/alt_linux/test_operational_reliability_contract.py` — 19-scenario catalog and `vault_gate` invariants.
- `tests/alt_linux/test_vault_health.py` — preserve legacy healthy/unhealthy contracts and add configured-owner regression coverage if needed.

---

### Task 1: Extend the Operational Outcome Catalog

**Files:**
- Modify: `tests/alt_linux/support/outcomes.py`
- Modify: `tests/alt_linux/test_operational_reliability_contract.py`

**Interfaces:**
- Consumes: existing `OperationalOutcome` with optional `failure_kind` and 11 proven outcomes.
- Produces: eight immutable `boundary="vault_gate"` outcomes and a 19-scenario exact catalog.

- [ ] **Step 1: Write failing catalog tests**

Add these scenario IDs to `EXPECTED_SCENARIO_IDS`:

```python
{
    "provision-vault-file-missing",
    "provision-vault-password-file-missing",
    "provision-vault-header-invalid",
    "provision-vault-decrypt-failed",
    "provision-vault-variable-missing",
    "provision-vault-yescrypt-invalid",
    "provision-vault-mode-invalid",
    "provision-vault-owner-invalid",
}
```

Add `vault_gate` to the allowed boundaries and enforce:

```python
if item.boundary == "vault_gate":
    assert item.error_code == "vault_not_configured"
    assert item.command_exit_code == 4
    assert item.job_state is None
    assert item.job_stage is None
    assert item.assignment_created is False
    assert item.retryable is True
    assert item.failure_kind is None
```

Add an exact scenario count assertion:

```python
def test_catalog_contains_nineteen_proven_outcomes() -> None:
    assert len(PROVEN_OPERATIONAL_OUTCOMES) == 19
```

- [ ] **Step 2: Run the exact catalog tests and verify RED**

```bash
python -m pytest -q \
  tests/alt_linux/test_operational_reliability_contract.py
```

Expected: failure because the eight scenario IDs and `vault_gate` boundary records do not exist.

- [ ] **Step 3: Add the eight immutable outcome records**

Append eight `OperationalOutcome` records with this common structure:

```python
OperationalOutcome(
    scenario_id="provision-vault-file-missing",
    boundary="vault_gate",
    error_code="vault_not_configured",
    command_exit_code=4,
    job_state=None,
    job_stage=None,
    assignment_created=False,
    retryable=True,
    required_evidence=(
        "checks_matrix",
        "no_job_created",
        "no_assignment_created",
        "no_target_operation",
    ),
)
```

Use the exact scenario IDs from Step 1. Keep `failure_kind=None` through the dataclass default.

- [ ] **Step 4: Run catalog tests and verify GREEN**

```bash
python -m pytest -q \
  tests/alt_linux/test_operational_reliability_contract.py
```

Expected: all contract tests pass.

- [ ] **Step 5: Commit**

```bash
git add \
  tests/alt_linux/support/outcomes.py \
  tests/alt_linux/test_operational_reliability_contract.py
git commit -m "test: define OR-2B1 Vault outcomes"
```

---

### Task 2: Build the Synthetic Vault Test Boundary

**Files:**
- Modify: `tests/alt_linux/support/controller_sandbox.py`
- Create: `tests/alt_linux/test_or2b1_vault_gate.py`

**Interfaces:**
- Produces: `ControllerSandbox.configure_vault_boundary(...) -> dict[str, Path]` and `ControllerSandbox.write_provision_request() -> Path`.
- Test fixtures must remain beneath `sandbox.root` and contain only explicit synthetic values.

- [ ] **Step 1: Write failing sandbox tests**

Add:

```python
def test_sandbox_configures_vault_boundary(tmp_path: Path) -> None:
    sandbox = make_controller_sandbox(tmp_path)
    assets = sandbox.configure_vault_boundary()

    assert set(assets) == {
        "vault_file",
        "password_file",
        "ansible_vault",
    }
    assert assets["vault_file"].read_text(encoding="utf-8").startswith(
        "$ANSIBLE_VAULT;"
    )
    assert stat.S_IMODE(assets["vault_file"].stat().st_mode) == 0o600
    assert stat.S_IMODE(assets["password_file"].stat().st_mode) == 0o600
    for path in assets.values():
        path.relative_to(sandbox.root)
```

Add:

```python
def test_sandbox_writes_provision_request(tmp_path: Path) -> None:
    sandbox = make_controller_sandbox(tmp_path)
    request_path = sandbox.write_provision_request()
    assert read_json(request_path) == provision_request()
```

- [ ] **Step 2: Verify RED**

```bash
python -m pytest -q \
  tests/alt_linux/test_or2b1_vault_gate.py \
  -k "sandbox"
```

Expected: failures because the helpers are absent.

- [ ] **Step 3: Implement the minimal sandbox helpers**

Add a helper that creates:

```text
ansible/group_vars/vault.yml                  mode 0600
.ansible-vault-pass                           mode 0600
bin/ansible-vault                             mode 0755
```

The fake executable must print only a synthetic decrypted mapping:

```sh
#!/bin/sh
printf '%s\n' "vault_employee_password_hash: '\$y\$test-only-hash'"
```

Return all three paths. Set `ALT_DEPLOY_ANSIBLE_VAULT` in tests, not globally inside the sandbox object.

Add `write_provision_request()` using `atomic_write_json()` and the existing `provision_request()` factory.

- [ ] **Step 4: Verify GREEN**

```bash
python -m pytest -q \
  tests/alt_linux/test_or2b1_vault_gate.py \
  -k "sandbox"
```

Expected: all sandbox tests pass.

- [ ] **Step 5: Commit**

```bash
git add \
  tests/alt_linux/support/controller_sandbox.py \
  tests/alt_linux/test_or2b1_vault_gate.py
git commit -m "test: add isolated Vault boundary"
```

---

### Task 3: Make Vault Health Deterministic by Configured Service User

**Files:**
- Modify: `deploy/alt-linux/control/alt_deploy/vault.py`
- Modify: `tests/alt_linux/test_or2b1_vault_gate.py`
- Modify if required: `tests/alt_linux/test_vault_health.py`

**Interfaces:**
- Produces: `VaultHealthChecker._build_checks() -> dict[str, bool]`.
- Owner resolution: `pwd.getpwnam(settings.service_user).pw_uid`.
- Public `check()` remains unchanged except that it consumes `_build_checks()`.

- [ ] **Step 1: Write failing configured-owner and dependency-gating tests**

Test identical results for root and non-root caller EUID:

```python
def test_vault_checks_do_not_depend_on_caller_euid(...):
    root_checks = checker._build_checks()
    monkeypatch.setattr(os, "geteuid", lambda: 1000)
    user_checks = checker._build_checks()
    assert root_checks == user_checks
```

Patch `vault.pwd.getpwnam` to return the actual fixture owner UID for `settings.service_user`.

Test missing service user:

```python
def test_missing_service_user_fails_owner_checks(...):
    monkeypatch.setattr(
        "alt_deploy.vault.pwd.getpwnam",
        lambda username: (_ for _ in ()).throw(KeyError(username)),
    )
    checks = checker._build_checks()
    assert checks["vault_file_owner"] is False
    assert checks["password_file_owner"] is False
```

Test structural failure prevents decrypt:

```python
def test_invalid_mode_prevents_decrypt_attempt(...):
    vault_file.chmod(0o644)
    called = False
    monkeypatch.setattr(checker, "_decrypt", fake_decrypt)
    checks = checker._build_checks()
    assert called is False
    assert checks["decryptable"] is False
    assert checks["variable_present"] is False
    assert checks["yescrypt_format"] is False
```

- [ ] **Step 2: Verify RED**

```bash
python -m pytest -q \
  tests/alt_linux/test_or2b1_vault_gate.py \
  -k "caller_euid or service_user or prevents_decrypt"
```

Expected: failure because owner checks use `os.geteuid()` and `_build_checks()` does not exist.

- [ ] **Step 3: Implement configured-owner and `_build_checks()`**

In `vault.py`:

```python
import pwd
```

Replace the current-owner helper with:

```python
def _service_uid(self) -> int | None:
    try:
        return pwd.getpwnam(self.settings.service_user).pw_uid
    except KeyError:
        return None

@staticmethod
def _owned_by(path: Path, expected_uid: int | None) -> bool:
    if expected_uid is None:
        return False
    try:
        return path.stat().st_uid == expected_uid
    except OSError:
        return False
```

Implement `_build_checks()` in this order:

1. existence;
2. configured owner;
3. mode;
4. header;
5. compute `structural_ok` from those seven booleans;
6. decrypt only when `structural_ok`;
7. extract required variable;
8. evaluate yescrypt.

Return exactly the existing ten keys.

Refactor `check()` to:

```python
checks = self._build_checks()
if not all(checks.values()):
    raise ControlError(...)
return {"status": "ok", "checks": checks}
```

- [ ] **Step 4: Run checker and legacy Vault tests**

```bash
python -m pytest -q \
  tests/alt_linux/test_or2b1_vault_gate.py \
  tests/alt_linux/test_vault_health.py \
  -k "vault or service_user or caller_euid or decrypt"
```

Expected: all selected tests pass and existing `vault_unhealthy/7` behavior remains intact.

- [ ] **Step 5: Commit**

```bash
git add \
  deploy/alt-linux/control/alt_deploy/vault.py \
  tests/alt_linux/test_or2b1_vault_gate.py \
  tests/alt_linux/test_vault_health.py
git commit -m "fix: make Vault health deterministic"
```

---

### Task 4: Cover the Complete Vault Failure Matrix

**Files:**
- Modify: `tests/alt_linux/test_or2b1_vault_gate.py`
- Modify if necessary: `deploy/alt-linux/control/alt_deploy/vault.py`

**Interfaces:**
- Consumes: `_build_checks()` and existing `_decrypt()` behavior.
- Produces: executable tests for every structural, decrypt, variable, hash, owner, and mode failure class.

- [ ] **Step 1: Add parameterized checker/CLI failure fixtures**

Cover:

```text
vault file missing
password file missing
invalid header
ansible-vault unavailable
decrypt timeout
decrypt returncode non-zero
required variable missing
invalid yescrypt
vault mode invalid
password mode invalid
vault owner invalid
password owner invalid
```

For each state call real CLI:

```python
result = run_json_cli(["vault", "check"], settings=sandbox.settings)
assert result.exit_code == 7
assert result.payload["error"]["code"] == "vault_unhealthy"
assert result.payload["error"]["details"]["checks"] == expected_checks
```

Assert synthetic secrets are absent from serialized stdout/stderr:

```python
for forbidden in (
    "test-only-vault-password",
    "$y$test-only-hash",
    "vault_employee_password_hash",
    "decrypt-stderr-marker",
):
    assert forbidden not in serialized
```

- [ ] **Step 2: Run matrix tests and verify failures expose gaps, not infrastructure errors**

```bash
python -m pytest -q \
  tests/alt_linux/test_or2b1_vault_gate.py \
  -k "vault_check_matrix"
```

Expected before any needed fix: tests may fail only on exact matrix values or redaction, not on fixture setup.

- [ ] **Step 3: Make the minimum checker corrections**

Do not add new public fields. Correct only ordering or downstream boolean dependencies needed by the exact matrix:

```text
structural false -> decryptable/variable_present/yescrypt_format false
decrypt false -> variable_present/yescrypt_format false
variable missing -> yescrypt_format false
```

- [ ] **Step 4: Verify the complete checker matrix GREEN**

```bash
python -m pytest -q \
  tests/alt_linux/test_or2b1_vault_gate.py \
  -k "vault_check_matrix"
```

Expected: all matrix tests pass.

- [ ] **Step 5: Commit**

```bash
git add \
  deploy/alt-linux/control/alt_deploy/vault.py \
  tests/alt_linux/test_or2b1_vault_gate.py
git commit -m "test: cover Vault health failures"
```

---

### Task 5: Replace ProvisionPlanner’s Shallow Vault Validation

**Files:**
- Modify: `deploy/alt-linux/control/alt_deploy/provision.py`
- Modify: `tests/alt_linux/test_or2b1_vault_gate.py`

**Interfaces:**
- Consumes: `VaultHealthChecker(settings).check()`.
- Produces: `_validate_vault()` remapping only `vault_unhealthy` to `vault_not_configured/4`.

- [ ] **Step 1: Write failing preview-surface parity tests**

For each of the eight operational outcomes:

1. call `vault check` and capture `details.checks`;
2. call real CLI `provision preview` for the same filesystem state;
3. assert:

```python
assert preview.exit_code == 4
assert preview.payload["error"]["code"] == "vault_not_configured"
assert preview.payload["error"]["details"]["checks"] == vault_checks
assert JobRepository(settings).list() == []
assert AssignmentRepository(settings).get(TEST_MACHINE_UUID) is None
assert read_json(registration_path) == registration_before
```

Exact compatibility fields:

```text
missing Vault/password file -> details.missing present with sorted path strings
invalid Vault header -> details.path equals Vault path
all other failures -> neither details.missing nor details.path
```

- [ ] **Step 2: Verify RED**

```bash
python -m pytest -q \
  tests/alt_linux/test_or2b1_vault_gate.py \
  -k "preview"
```

Expected: shallow preview validation passes invalid decrypt/variable/hash/mode/owner states or lacks the full checks matrix.

- [ ] **Step 3: Replace `_validate_vault()` implementation**

Import:

```python
from .vault import VaultHealthChecker
```

Implement:

```python
def _validate_vault(self) -> None:
    try:
        VaultHealthChecker(self.settings).check()
    except ControlError as exc:
        if exc.code != "vault_unhealthy":
            raise

        checks = dict(exc.details.get("checks") or {})
        details: dict[str, object] = {"checks": checks}

        missing = []
        if not checks.get("vault_file_exists", False):
            missing.append(str(self.vault_file))
        if not checks.get("password_file_exists", False):
            missing.append(str(self.vault_password_file))
        if missing:
            details["missing"] = missing
        elif not checks.get("vault_header", False):
            details["path"] = str(self.vault_file)

        raise ControlError(
            code="vault_not_configured",
            message=(
                "Ansible Vault is not configured for "
                "workstation provisioning"
            ),
            exit_code=4,
            details=details,
        ) from exc
```

Remove the duplicate file/header implementation and obsolete file-reading imports if unused.

- [ ] **Step 4: Verify preview parity GREEN**

```bash
python -m pytest -q \
  tests/alt_linux/test_or2b1_vault_gate.py \
  -k "preview"
```

Expected: all preview scenarios fail before mutation with identical checks to `vault check`.

- [ ] **Step 5: Commit**

```bash
git add \
  deploy/alt-linux/control/alt_deploy/provision.py \
  tests/alt_linux/test_or2b1_vault_gate.py
git commit -m "fix: gate provisioning on Vault health"
```

---

### Task 6: Prove Start-Before-Job Safety and Retryability

**Files:**
- Modify: `tests/alt_linux/test_or2b1_vault_gate.py`

**Interfaces:**
- Consumes: unified planner gate.
- Produces: evidence that representative start failures occur before job creation and that corrected Vault state permits a later preview.

- [ ] **Step 1: Add start tests for decrypt, owner, and mode failures**

Patch `alt_deploy.provision.os.geteuid` to return `0`. Use a launcher stub that raises if called:

```python
class ForbiddenLauncher:
    def launch(self, job_id: str) -> str:
        raise AssertionError("launcher must not be called")
```

Call real CLI `provision start`; assert:

```python
assert result.exit_code == 4
assert result.payload["error"]["code"] == "vault_not_configured"
assert JobRepository(settings).list() == []
assert AssignmentRepository(settings).get(TEST_MACHINE_UUID) is None
```

No fake worker account or `chown` path should be reached.

- [ ] **Step 2: Add retryability test**

On one sandbox:

1. configure invalid yescrypt output;
2. preview and assert `vault_not_configured`;
3. rewrite fake decrypt output to valid `$y$test-only-hash`;
4. preview again and assert `exit_code=0`, `status=ok`;
5. assert no job and no assignment after both calls.

- [ ] **Step 3: Run start/retryability tests**

```bash
python -m pytest -q \
  tests/alt_linux/test_or2b1_vault_gate.py \
  -k "start or retryable"
```

Expected: all tests pass without target or launcher access.

- [ ] **Step 4: Commit**

```bash
git add tests/alt_linux/test_or2b1_vault_gate.py
git commit -m "test: prove Vault gate fails before jobs"
```

---

### Task 7: Full Verification and PR Cleanup

**Files:**
- Create temporarily: `.github/workflows/or2b1-verification.yml`
- Create: `docs/superpowers/plans/2026-07-20-alt-or2b1-verification.md`
- Delete before final diff: `.github/workflows/or2b1-verification.yml`

**Interfaces:**
- Produces: fresh, auditable counts and a final branch containing no temporary workflow or secret-bearing artifact.

- [ ] **Step 1: Run focused verification**

```bash
python -m pytest -q \
  tests/alt_linux/test_or2b1_vault_gate.py \
  tests/alt_linux/test_vault_health.py \
  tests/alt_linux/test_operational_reliability_contract.py
```

- [ ] **Step 2: Run ALT and full suites**

```bash
python -m pytest -q tests/alt_linux
python -m pytest -q
```

- [ ] **Step 3: Compile changed production modules**

```bash
python -m py_compile \
  deploy/alt-linux/control/alt_deploy/vault.py \
  deploy/alt-linux/control/alt_deploy/provision.py
```

- [ ] **Step 4: Run diff check**

```bash
git diff --check origin/main...HEAD
```

- [ ] **Step 5: Record evidence**

Document exact head SHA, test counts, warnings, compile result, diff result, and security statement. Do not include synthetic password/hash contents in the document.

- [ ] **Step 6: Remove temporary workflow**

Delete `.github/workflows/or2b1-verification.yml`, confirm final diff contains only approved production/test/docs paths, and wait for repository-native full-regression workflows on final head.

- [ ] **Step 7: Review and prepare PR**

Review all production patches for:

```text
configured service owner
no EUID dependency
dependency-gated decrypt
exact error-code preservation
no secret output
no job/launcher/assignment before gate success
no OR-2B2 scope
```

Open or update a draft PR, add verification evidence, and mark Ready only when all checks are successful.
