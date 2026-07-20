# ALT Workstation Provisioning OR-1 Test Harness Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Создать test-only foundation для этапов operational reliability: изолированный controller sandbox, безопасные payload factories, JSON CLI runner, типизированный каталог уже доказанных outcomes и перевести на него пять репрезентативных сценариев.

**Architecture:** Новая инфраструктура располагается только в `tests/alt_linux/support/` и не меняет production-код. Тестовые данные и controller filesystem создаются под `tmp_path`; outcome-каталог хранит ожидаемый внешний контракт, а существующие regression tests подтверждают его фактическим поведением CLI, job repository и assignment repository.

**Tech Stack:** Python 3, pytest, dataclasses, pathlib, существующие `alt_deploy.Settings`, `alt_deploy.cli.main`, `JobRepository`, `JobStageManager`, `AssignmentRepository`.

## Global Constraints

- Не изменять `deploy/alt-linux/control/`.
- Не изменять `deploy/alt-linux/ansible/`.
- Не выполнять реальные SSH-подключения, systemd units или provisioning.
- Не читать активный Vault и не использовать runtime state контроллера.
- Не обращаться к эталонной VM `192.168.101.111`.
- Не добавлять YAML/JSON scenario engine или pytest plugin.
- Не переносить массово весь существующий test suite.
- Каталог содержит только пять уже доказанных outcomes.
- Fixtures не содержат реальные пароли, password hashes, Vault values или SSH private keys.
- Каждый логический блок завершается focused tests и отдельным коммитом.

---

## File Map

**Create:**

- `tests/alt_linux/support/__init__.py` — маркирует общий test-support package.
- `tests/alt_linux/support/payloads.py` — детерминированные безопасные payload factories и тестовые идентификаторы.
- `tests/alt_linux/support/controller_sandbox.py` — изолированный filesystem/controller boundary на основе `Settings`.
- `tests/alt_linux/support/cli.py` — единый JSON CLI runner.
- `tests/alt_linux/support/outcomes.py` — immutable outcome model, каталог и lookup.
- `tests/alt_linux/test_operational_reliability_contract.py` — контрактные тесты support package и outcome-каталога.

**Modify:**

- `tests/alt_linux/test_provision_start.py` — root-required и launch-failed используют новый harness/outcomes.
- `tests/alt_linux/test_job_reconcile.py` — worker-not-started, worker-lost и result-recovered используют новый harness/outcomes.

**Do not modify:**

- `tests/alt_linux/conftest.py` — portable `altserver` fixture остаётся действующим.
- Остальные test modules — cross-import cleanup вне пяти выбранных сценариев не входит в OR-1.

---

### Task 1: Safe Payload Factories

**Files:**
- Create: `tests/alt_linux/support/__init__.py`
- Create: `tests/alt_linux/support/payloads.py`
- Create: `tests/alt_linux/test_operational_reliability_contract.py`

**Interfaces:**
- Produces: `TEST_MACHINE_UUID`, `SECOND_TEST_MACHINE_UUID`, `machine_registration_payload()`, `provision_request()`, `assignment_payload()`, `successful_provision_result()`.
- Consumes: no test helpers from neighboring test modules.

- [ ] **Step 1: Write failing payload-factory tests**

Create `tests/alt_linux/test_operational_reliability_contract.py` with:

```python
from __future__ import annotations

from tests.alt_linux.support.payloads import (
    SECOND_TEST_MACHINE_UUID,
    TEST_MACHINE_UUID,
    assignment_payload,
    machine_registration_payload,
    provision_request,
    successful_provision_result,
)


def test_payload_factories_return_independent_mappings() -> None:
    first = provision_request()
    second = provision_request()

    assert first == second
    assert first is not second

    first["employee_login"] = "changed"
    assert second["employee_login"] == "i-ivanov"


def test_payload_factories_use_only_test_identifiers() -> None:
    registration = machine_registration_payload()
    request = provision_request()
    assignment = assignment_payload(job_id="job-test")
    result = successful_provision_result(job_id="job-test")

    assert registration["uuid"] == TEST_MACHINE_UUID
    assert request["machine_uuid"] == TEST_MACHINE_UUID
    assert assignment["machine_uuid"] == TEST_MACHINE_UUID
    assert result["machine_uuid"] == TEST_MACHINE_UUID
    assert SECOND_TEST_MACHINE_UUID != TEST_MACHINE_UUID


def test_successful_result_has_complete_verification_contract() -> None:
    result = successful_provision_result(job_id="job-test")

    assert result["job_id"] == "job-test"
    assert result["verification"] == {
        "hostname": True,
        "employee_exists": True,
        "employee_not_wheel": True,
        "employee_no_sudo": True,
        "ansible_sudo": True,
        "lightdm_hides_ansible": True,
        "lightdm_shows_employee": True,
        "lightdm_autologin_disabled": True,
    }
```

- [ ] **Step 2: Run tests and verify RED**

Run:

```bash
.venv/bin/python -m pytest -q \
  tests/alt_linux/test_operational_reliability_contract.py
```

Expected: collection fails with `ModuleNotFoundError: No module named 'tests.alt_linux.support'` or missing exported symbols.

- [ ] **Step 3: Create support package and payload factories**

Create `tests/alt_linux/support/__init__.py`:

```python
"""Shared test-only support for ALT operational reliability tests."""
```

Create `tests/alt_linux/support/payloads.py`:

```python
from __future__ import annotations

from typing import Any

TEST_MACHINE_UUID = "53b03180-5d78-11f0-bd95-f027db877a00"
SECOND_TEST_MACHINE_UUID = "11111111-2222-3333-4444-555555555555"
TEST_REGISTERED_AT = "2026-07-16T08:00:00+00:00"
TEST_COMPLETED_AT = "2026-07-16T13:00:00+00:00"


def machine_registration_payload(
    *,
    machine_uuid: str = TEST_MACHINE_UUID,
    hostname: str = "alt-auto-test",
    ip: str = "192.0.2.56",
    mac: str = "02:00:00:00:00:56",
    status: str = "ready",
    registered_at: str = TEST_REGISTERED_AT,
    preflight_ok: bool = False,
) -> dict[str, object]:
    payload: dict[str, object] = {
        "machine_key": machine_uuid,
        "uuid": machine_uuid,
        "hostname": hostname,
        "ip": ip,
        "mac": mac,
        "registered_at": registered_at,
        "status": status,
    }
    if preflight_ok:
        payload["status"] = "awaiting_assignment"
        payload["preflight"] = {
            "status": "ok",
            "checks": {
                "uuid": True,
                "alt_release": True,
            },
        }
    return payload


def provision_request(
    *,
    machine_uuid: str = TEST_MACHINE_UUID,
    employee_login: str = "i-ivanov",
    employee_full_name: str = "Иванов Иван Иванович",
    final_hostname: str = "buh-023",
    profile: str = "standard",
) -> dict[str, str]:
    return {
        "machine_uuid": machine_uuid,
        "employee_login": employee_login,
        "employee_full_name": employee_full_name,
        "final_hostname": final_hostname,
        "profile": profile,
    }


def assignment_payload(
    *,
    machine_uuid: str = TEST_MACHINE_UUID,
    job_id: str = "job-test",
) -> dict[str, object]:
    return {
        **provision_request(machine_uuid=machine_uuid),
        "job_id": job_id,
        "completed_at": TEST_COMPLETED_AT,
        "verification": {
            "hostname": True,
            "employee_exists": True,
        },
    }


def successful_provision_result(
    *,
    job_id: str,
    machine_uuid: str = TEST_MACHINE_UUID,
) -> dict[str, Any]:
    return {
        **provision_request(machine_uuid=machine_uuid),
        "job_id": job_id,
        "completed_at": TEST_COMPLETED_AT,
        "verification": {
            "hostname": True,
            "employee_exists": True,
            "employee_not_wheel": True,
            "employee_no_sudo": True,
            "ansible_sudo": True,
            "lightdm_hides_ansible": True,
            "lightdm_shows_employee": True,
            "lightdm_autologin_disabled": True,
        },
    }
```

- [ ] **Step 4: Run focused tests and verify GREEN**

Run:

```bash
.venv/bin/python -m pytest -q \
  tests/alt_linux/test_operational_reliability_contract.py
```

Expected: `3 passed`.

- [ ] **Step 5: Commit**

```bash
git add \
  tests/alt_linux/support/__init__.py \
  tests/alt_linux/support/payloads.py \
  tests/alt_linux/test_operational_reliability_contract.py
git commit -m "test: add ALT reliability payload factories"
```

---

### Task 2: Isolated Controller Sandbox

**Files:**
- Create: `tests/alt_linux/support/controller_sandbox.py`
- Modify: `tests/alt_linux/test_operational_reliability_contract.py`

**Interfaces:**
- Consumes: `machine_registration_payload()` from Task 1.
- Produces: `ControllerSandbox`, `make_controller_sandbox()` and methods `register_machine()`, `install_fake_stage_helper()`, `install_fake_ansible_playbook()`, `configure_fake_vault()`.

- [ ] **Step 1: Write failing sandbox tests**

Append to `tests/alt_linux/test_operational_reliability_contract.py`:

```python
from pathlib import Path

from alt_deploy.jsonio import read_json

from tests.alt_linux.support.controller_sandbox import (
    make_controller_sandbox,
)


def test_controller_sandbox_keeps_all_paths_under_tmp_path(
    tmp_path: Path,
) -> None:
    sandbox = make_controller_sandbox(tmp_path)

    controlled_paths = (
        sandbox.settings.registration_root,
        sandbox.settings.state_root,
        sandbox.settings.jobs_dir,
        sandbox.settings.assignments_dir,
        sandbox.settings.lock_file,
        sandbox.settings.ansible_project_dir,
        sandbox.settings.known_hosts_file,
        sandbox.settings.private_key_file,
        sandbox.settings.ansible_playbook_path,
        sandbox.settings.systemd_run_path,
        sandbox.settings.worker_path,
        sandbox.settings.job_stage_helper_path,
        sandbox.settings.workstationctl_path,
    )

    for path in controlled_paths:
        path.relative_to(sandbox.root)


def test_controller_sandbox_registers_machine_explicitly(
    tmp_path: Path,
) -> None:
    sandbox = make_controller_sandbox(tmp_path)
    path = sandbox.register_machine(
        state="ready",
        preflight_ok=True,
    )

    payload = read_json(path)
    assert path.parent.name == "ready"
    assert payload["status"] == "awaiting_assignment"
    assert payload["preflight"]["status"] == "ok"


def test_controller_sandbox_installs_only_requested_assets(
    tmp_path: Path,
) -> None:
    sandbox = make_controller_sandbox(tmp_path)

    assert not sandbox.settings.job_stage_helper_path.exists()
    assert not sandbox.settings.ansible_playbook_path.exists()

    sandbox.install_fake_stage_helper()
    sandbox.install_fake_ansible_playbook()
    sandbox.configure_fake_vault()

    assert sandbox.settings.job_stage_helper_path.stat().st_mode & 0o111
    assert sandbox.settings.ansible_playbook_path.stat().st_mode & 0o111
    assert (
        sandbox.settings.ansible_project_dir
        / "group_vars"
        / "vault.yml"
    ).read_text(encoding="utf-8").startswith("$ANSIBLE_VAULT;")
```

- [ ] **Step 2: Run sandbox tests and verify RED**

Run:

```bash
.venv/bin/python -m pytest -q \
  tests/alt_linux/test_operational_reliability_contract.py \
  -k controller_sandbox
```

Expected: import fails because `support.controller_sandbox` does not exist.

- [ ] **Step 3: Implement the sandbox**

Create `tests/alt_linux/support/controller_sandbox.py`:

```python
from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path

from alt_deploy.config import Settings
from alt_deploy.jsonio import atomic_write_json

from .payloads import (
    TEST_MACHINE_UUID,
    machine_registration_payload,
)


@dataclass(frozen=True)
class ControllerSandbox:
    settings: Settings
    root: Path

    def _write_executable(self, path: Path, content: str) -> Path:
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(content, encoding="utf-8")
        path.chmod(0o755)
        return path

    def register_machine(
        self,
        *,
        state: str = "ready",
        machine_uuid: str = TEST_MACHINE_UUID,
        preflight_ok: bool = False,
    ) -> Path:
        path = (
            self.settings.registration_root
            / state
            / f"{machine_uuid}.json"
        )
        atomic_write_json(
            path,
            machine_registration_payload(
                machine_uuid=machine_uuid,
                status=state,
                preflight_ok=preflight_ok,
            ),
        )
        return path

    def install_fake_stage_helper(self) -> Path:
        return self._write_executable(
            self.settings.job_stage_helper_path,
            "#!/bin/sh\nexit 0\n",
        )

    def install_fake_ansible_playbook(self) -> Path:
        return self._write_executable(
            self.settings.ansible_playbook_path,
            "#!/bin/sh\nexit 0\n",
        )

    def configure_fake_vault(self) -> tuple[Path, Path]:
        vault_file = (
            self.settings.ansible_project_dir
            / "group_vars"
            / "vault.yml"
        )
        vault_file.parent.mkdir(parents=True, exist_ok=True)
        vault_file.write_text(
            "$ANSIBLE_VAULT;1.1;AES256\ntest-ciphertext\n",
            encoding="utf-8",
        )
        vault_file.chmod(0o600)

        password_file = (
            self.settings.ansible_project_dir.parent
            / ".ansible-vault-pass"
        )
        password_file.write_text(
            "test-only-vault-passphrase\n",
            encoding="utf-8",
        )
        password_file.chmod(0o600)
        return vault_file, password_file


def make_controller_sandbox(tmp_path: Path) -> ControllerSandbox:
    root = tmp_path / "alt-controller"
    registration = root / "registration"
    state = root / "state"
    ansible_project = root / "ansible"
    bin_dir = root / "bin"

    settings = Settings(
        registration_root=registration,
        state_root=state,
        jobs_dir=state / "jobs",
        assignments_dir=state / "assignments",
        lock_file=state / "workstationctl.lock",
        ansible_project_dir=ansible_project,
        known_hosts_file=root / "ssh" / "known_hosts",
        private_key_file=root / "ssh" / "id_ed25519",
        ansible_playbook_path=bin_dir / "ansible-playbook",
        systemd_run_path=bin_dir / "systemd-run",
        worker_path=bin_dir / "alt-provision-worker",
        job_stage_helper_path=bin_dir / "alt-job-stage",
        workstationctl_path=bin_dir / "workstationctl",
    )
    return ControllerSandbox(settings=settings, root=root)
```

- [ ] **Step 4: Run focused tests and verify GREEN**

Run:

```bash
.venv/bin/python -m pytest -q \
  tests/alt_linux/test_operational_reliability_contract.py \
  -k controller_sandbox
```

Expected: `3 passed`.

- [ ] **Step 5: Commit**

```bash
git add \
  tests/alt_linux/support/controller_sandbox.py \
  tests/alt_linux/test_operational_reliability_contract.py
git commit -m "test: add isolated ALT controller sandbox"
```

---

### Task 3: JSON CLI Runner

**Files:**
- Create: `tests/alt_linux/support/cli.py`
- Modify: `tests/alt_linux/test_operational_reliability_contract.py`

**Interfaces:**
- Consumes: `Settings`, production `alt_deploy.cli.main`.
- Produces: immutable `CliResult` and `run_json_cli(args, settings=...)`.

- [ ] **Step 1: Write failing CLI runner tests**

Append:

```python
from tests.alt_linux.support.cli import run_json_cli


def test_run_json_cli_captures_success_payload(tmp_path: Path) -> None:
    sandbox = make_controller_sandbox(tmp_path)
    sandbox.register_machine()

    result = run_json_cli(
        ["machines", "list"],
        settings=sandbox.settings,
    )

    assert result.exit_code == 0
    assert result.stderr == ""
    assert result.payload["status"] == "ok"
    assert result.payload["machines"][0]["uuid"] == TEST_MACHINE_UUID


def test_run_json_cli_preserves_error_exit_code(tmp_path: Path) -> None:
    sandbox = make_controller_sandbox(tmp_path)

    result = run_json_cli(
        [
            "machines",
            "show",
            "00000000-0000-0000-0000-000000000000",
        ],
        settings=sandbox.settings,
    )

    assert result.exit_code == 3
    assert result.payload["status"] == "error"
    assert result.payload["error"]["code"] == "machine_not_found"
```

- [ ] **Step 2: Run and verify RED**

```bash
.venv/bin/python -m pytest -q \
  tests/alt_linux/test_operational_reliability_contract.py \
  -k run_json_cli
```

Expected: import fails because `support.cli` does not exist.

- [ ] **Step 3: Implement JSON CLI runner**

Create `tests/alt_linux/support/cli.py`:

```python
from __future__ import annotations

import io
import json
from collections.abc import Sequence
from dataclasses import dataclass

from alt_deploy.cli import main
from alt_deploy.config import Settings


@dataclass(frozen=True)
class CliResult:
    exit_code: int
    stdout: str
    stderr: str
    payload: dict[str, object]


def run_json_cli(
    args: Sequence[str],
    *,
    settings: Settings,
) -> CliResult:
    stdout = io.StringIO()
    stderr = io.StringIO()
    argv = ["--json", *args]
    exit_code = main(
        argv,
        settings=settings,
        stdout=stdout,
        stderr=stderr,
    )
    stdout_text = stdout.getvalue()
    stderr_text = stderr.getvalue()

    try:
        raw_payload = json.loads(stdout_text)
    except json.JSONDecodeError as exc:
        raise AssertionError(
            "workstationctl did not emit one valid JSON document; "
            f"stdout={stdout_text!r}; stderr={stderr_text!r}"
        ) from exc

    if not isinstance(raw_payload, dict):
        raise AssertionError(
            "workstationctl JSON payload must be an object; "
            f"payload={raw_payload!r}"
        )

    return CliResult(
        exit_code=exit_code,
        stdout=stdout_text,
        stderr=stderr_text,
        payload=raw_payload,
    )
```

- [ ] **Step 4: Run focused tests and verify GREEN**

```bash
.venv/bin/python -m pytest -q \
  tests/alt_linux/test_operational_reliability_contract.py \
  -k run_json_cli
```

Expected: `2 passed`.

- [ ] **Step 5: Commit**

```bash
git add \
  tests/alt_linux/support/cli.py \
  tests/alt_linux/test_operational_reliability_contract.py
git commit -m "test: add workstationctl JSON test runner"
```

---

### Task 4: Operational Outcome Catalog

**Files:**
- Create: `tests/alt_linux/support/outcomes.py`
- Modify: `tests/alt_linux/test_operational_reliability_contract.py`

**Interfaces:**
- Consumes: `CANONICAL_STAGES` from production as a read-only canonical constant.
- Produces: `OperationalOutcome`, `PROVEN_OPERATIONAL_OUTCOMES`, `get_outcome()`.

- [ ] **Step 1: Write failing catalog contract tests**

Append:

```python
import re
from dataclasses import asdict

import pytest

from alt_deploy.job_stages import CANONICAL_STAGES
from tests.alt_linux.support.outcomes import (
    PROVEN_OPERATIONAL_OUTCOMES,
    get_outcome,
)


EXPECTED_SCENARIO_IDS = {
    "provision-start-root-required",
    "provision-start-launch-failed",
    "reconcile-worker-not-started-created",
    "reconcile-worker-lost-employee",
    "reconcile-result-recovered",
}


def test_proven_outcome_catalog_has_exact_approved_scenarios() -> None:
    assert {
        outcome.scenario_id
        for outcome in PROVEN_OPERATIONAL_OUTCOMES
    } == EXPECTED_SCENARIO_IDS


def test_proven_outcome_catalog_is_internally_consistent() -> None:
    scenario_ids = [
        outcome.scenario_id
        for outcome in PROVEN_OPERATIONAL_OUTCOMES
    ]
    assert len(scenario_ids) == len(set(scenario_ids))

    for outcome in PROVEN_OPERATIONAL_OUTCOMES:
        assert re.fullmatch(r"[a-z0-9]+(?:-[a-z0-9]+)*", outcome.scenario_id)
        assert outcome.boundary in {
            "authorization",
            "launcher",
            "reconciliation",
            "result_recovery",
        }
        assert outcome.job_state in {
            None,
            "queued",
            "running",
            "successful",
            "failed",
        }
        assert outcome.job_stage in {None, *CANONICAL_STAGES}
        assert outcome.required_evidence
        assert len(outcome.required_evidence) == len(
            set(outcome.required_evidence)
        )

        if outcome.job_state == "successful":
            assert outcome.job_stage == "complete"
        if outcome.job_state == "failed":
            assert outcome.job_stage != "complete"
            assert outcome.assignment_created is False


def test_outcome_metadata_contains_no_secret_like_names() -> None:
    serialized = repr(
        [asdict(item) for item in PROVEN_OPERATIONAL_OUTCOMES]
    ).lower()
    for forbidden in (
        "password",
        "private_key",
        "vault_employee_password_hash",
        "secret_value",
        "api_token",
    ):
        assert forbidden not in serialized


def test_get_outcome_fails_closed_for_unknown_scenario() -> None:
    with pytest.raises(KeyError, match="unknown-scenario"):
        get_outcome("unknown-scenario")
```

- [ ] **Step 2: Run and verify RED**

```bash
.venv/bin/python -m pytest -q \
  tests/alt_linux/test_operational_reliability_contract.py \
  -k outcome
```

Expected: import fails because `support.outcomes` does not exist.

- [ ] **Step 3: Implement immutable model and five outcomes**

Create `tests/alt_linux/support/outcomes.py`:

```python
from __future__ import annotations

from dataclasses import dataclass


@dataclass(frozen=True)
class OperationalOutcome:
    scenario_id: str
    boundary: str
    error_code: str | None
    command_exit_code: int
    job_state: str | None
    job_stage: str | None
    assignment_created: bool
    retryable: bool | None
    required_evidence: tuple[str, ...]


PROVEN_OPERATIONAL_OUTCOMES: tuple[OperationalOutcome, ...] = (
    OperationalOutcome(
        scenario_id="provision-start-root-required",
        boundary="authorization",
        error_code="root_required",
        command_exit_code=6,
        job_state=None,
        job_stage=None,
        assignment_created=False,
        retryable=None,
        required_evidence=(
            "cli_error",
            "no_job_created",
            "no_assignment_created",
        ),
    ),
    OperationalOutcome(
        scenario_id="provision-start-launch-failed",
        boundary="launcher",
        error_code="job_launch_failed",
        command_exit_code=6,
        job_state="failed",
        job_stage="launching",
        assignment_created=False,
        retryable=None,
        required_evidence=(
            "cli_error",
            "finished_at",
            "stage_history_created_launching",
            "no_assignment_created",
        ),
    ),
    OperationalOutcome(
        scenario_id="reconcile-worker-not-started-created",
        boundary="reconciliation",
        error_code="worker_not_started",
        command_exit_code=0,
        job_state="failed",
        job_stage="created",
        assignment_created=False,
        retryable=True,
        required_evidence=(
            "reconciliation_action_queued_recoverable",
            "finished_at",
            "stage_preserved",
            "no_assignment_created",
        ),
    ),
    OperationalOutcome(
        scenario_id="reconcile-worker-lost-employee",
        boundary="reconciliation",
        error_code="worker_lost",
        command_exit_code=0,
        job_state="failed",
        job_stage="employee",
        assignment_created=False,
        retryable=None,
        required_evidence=(
            "reconciliation_action_worker_lost",
            "last_real_stage_preserved",
            "no_result_created",
            "no_assignment_created",
        ),
    ),
    OperationalOutcome(
        scenario_id="reconcile-result-recovered",
        boundary="result_recovery",
        error_code=None,
        command_exit_code=0,
        job_state="successful",
        job_stage="complete",
        assignment_created=True,
        retryable=None,
        required_evidence=(
            "reconciliation_action_result_recovered",
            "recording_complete_transition",
            "result_file_recorded",
            "server_assignment_matches_result",
        ),
    ),
)

_OUTCOMES_BY_ID = {
    outcome.scenario_id: outcome
    for outcome in PROVEN_OPERATIONAL_OUTCOMES
}


def get_outcome(scenario_id: str) -> OperationalOutcome:
    try:
        return _OUTCOMES_BY_ID[scenario_id]
    except KeyError as exc:
        raise KeyError(
            f"Unknown operational outcome: {scenario_id}"
        ) from exc
```

- [ ] **Step 4: Run focused tests and verify GREEN**

```bash
.venv/bin/python -m pytest -q \
  tests/alt_linux/test_operational_reliability_contract.py \
  -k outcome
```

Expected: `4 passed`.

- [ ] **Step 5: Run the complete new contract module**

```bash
.venv/bin/python -m pytest -q \
  tests/alt_linux/test_operational_reliability_contract.py
```

Expected: all tests in the module pass.

- [ ] **Step 6: Commit**

```bash
git add \
  tests/alt_linux/support/outcomes.py \
  tests/alt_linux/test_operational_reliability_contract.py
git commit -m "test: define proven ALT operational outcomes"
```

---

### Task 5: Migrate Root and Launch Failure Scenarios

**Files:**
- Modify: `tests/alt_linux/test_provision_start.py`

**Interfaces:**
- Consumes: `make_controller_sandbox()`, `provision_request()`, `run_json_cli()`, `get_outcome()`.
- Preserves: existing `RecordingLauncher`, `FailingLauncher` and unrelated tests.

- [ ] **Step 1: Replace cross-test imports only for selected scenarios**

Add imports:

```python
from alt_deploy.assignments import AssignmentRepository
from tests.alt_linux.support.cli import run_json_cli
from tests.alt_linux.support.controller_sandbox import (
    make_controller_sandbox,
)
from tests.alt_linux.support.outcomes import get_outcome
from tests.alt_linux.support.payloads import (
    TEST_MACHINE_UUID,
    provision_request,
)
```

Keep legacy imports required by unrelated tests. Do not rename the module-wide legacy `MACHINE_UUID` until all remaining tests no longer depend on it.

- [ ] **Step 2: Convert root-required to a CLI contract test**

Replace the selected test with:

```python
def test_provision_start_requires_root(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    outcome = get_outcome("provision-start-root-required")
    sandbox = make_controller_sandbox(tmp_path)
    sandbox.install_fake_stage_helper()
    sandbox.configure_fake_vault()
    sandbox.register_machine(preflight_ok=True)

    request_path = tmp_path / "request.json"
    request_path.write_text(
        json.dumps(provision_request()),
        encoding="utf-8",
    )
    monkeypatch.setattr(
        "alt_deploy.provision.os.geteuid",
        lambda: 1000,
    )

    result = run_json_cli(
        [
            "provision",
            "start",
            TEST_MACHINE_UUID,
            "--vars-file",
            str(request_path),
        ],
        settings=sandbox.settings,
    )

    assert result.exit_code == outcome.command_exit_code
    assert result.payload["error"]["code"] == outcome.error_code
    assert JobRepository(sandbox.settings).list() == []
    assert (
        AssignmentRepository(sandbox.settings).get(TEST_MACHINE_UUID)
        is None
    )
```

- [ ] **Step 3: Run root-required test and verify GREEN**

```bash
.venv/bin/python -m pytest -q \
  tests/alt_linux/test_provision_start.py::test_provision_start_requires_root
```

Expected: `1 passed`.

- [ ] **Step 4: Convert launch failure to new sandbox and outcome**

Replace the selected test with:

```python
def test_launch_failure_is_persisted(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    outcome = get_outcome("provision-start-launch-failed")
    sandbox = make_controller_sandbox(tmp_path)
    sandbox.install_fake_stage_helper()
    sandbox.configure_fake_vault()
    sandbox.register_machine(preflight_ok=True)

    monkeypatch.setattr(
        "alt_deploy.provision.os.geteuid",
        lambda: 0,
    )
    monkeypatch.setattr(
        "alt_deploy.provision.os.chown",
        lambda path, uid, gid: None,
    )

    request = ProvisionRequest.from_mapping(
        provision_request(),
        expected_uuid=TEST_MACHINE_UUID,
    )
    planner = ProvisionPlanner(
        sandbox.settings,
        launcher=FailingLauncher(),
    )

    with pytest.raises(ControlError) as exc:
        planner.start(TEST_MACHINE_UUID, request)

    assert exc.value.code == outcome.error_code
    assert exc.value.exit_code == outcome.command_exit_code

    jobs = JobRepository(sandbox.settings).list()
    assert len(jobs) == 1
    assert jobs[0].state == outcome.job_state
    assert jobs[0].stage == outcome.job_stage
    assert [
        item["stage"]
        for item in jobs[0].status["stage_history"]
    ] == ["created", "launching"]
    assert jobs[0].status["finished_at"]
    assert (
        AssignmentRepository(sandbox.settings).get(TEST_MACHINE_UUID)
        is None
    )
```

- [ ] **Step 5: Run both migrated tests**

```bash
.venv/bin/python -m pytest -q \
  tests/alt_linux/test_provision_start.py \
  -k "requires_root or launch_failure_is_persisted"
```

Expected: `2 passed`.

- [ ] **Step 6: Run complete provision-start module**

```bash
.venv/bin/python -m pytest -q \
  tests/alt_linux/test_provision_start.py
```

Expected: all tests pass.

- [ ] **Step 7: Commit**

```bash
git add tests/alt_linux/test_provision_start.py
git commit -m "test: migrate provision failure contracts to OR-1 harness"
```

---

### Task 6: Migrate Reconciliation Scenarios

**Files:**
- Modify: `tests/alt_linux/test_job_reconcile.py`

**Interfaces:**
- Consumes: sandbox, payloads, CLI runner and outcome catalog from Tasks 1–4.
- Preserves: existing `_systemctl_result()` and `_advance_to_stage()` helpers because they remain local reconciliation-specific helpers.

- [ ] **Step 1: Add support imports**

```python
from tests.alt_linux.support.cli import run_json_cli
from tests.alt_linux.support.controller_sandbox import (
    make_controller_sandbox,
)
from tests.alt_linux.support.outcomes import get_outcome
from tests.alt_linux.support.payloads import (
    TEST_MACHINE_UUID,
    provision_request,
    successful_provision_result,
)
```

- [ ] **Step 2: Migrate worker-lost scenario**

Change setup and assertions to:

```python
outcome = get_outcome("reconcile-worker-lost-employee")
sandbox = make_controller_sandbox(tmp_path)
settings = sandbox.settings
jobs = JobRepository(settings)
created = jobs.create(provision_request())
# Existing _advance_to_stage and fake_systemctl body remain unchanged.

result = run_json_cli(
    ["jobs", "reconcile"],
    settings=settings,
)
assert result.exit_code == outcome.command_exit_code
assert result.payload["reconciliation"]["changed"][0]["action"] == (
    "worker_lost"
)

reconciled = jobs.get(created.job_id)
assert reconciled.state == outcome.job_state
assert reconciled.stage == outcome.job_stage
assert reconciled.status["error_code"] == outcome.error_code
assert not (reconciled.job_dir / "result.json").exists()
assert AssignmentRepository(settings).get(TEST_MACHINE_UUID) is None
```

- [ ] **Step 3: Migrate worker-not-started-created scenario**

Use:

```python
outcome = get_outcome("reconcile-worker-not-started-created")
sandbox = make_controller_sandbox(tmp_path)
settings = sandbox.settings
jobs = JobRepository(settings)
queued = jobs.create(provision_request())

result = run_json_cli(
    ["jobs", "reconcile"],
    settings=settings,
)
assert result.exit_code == outcome.command_exit_code
assert result.payload["reconciliation"]["changed"][0]["action"] == (
    "queued_recoverable"
)

reconciled = jobs.get(queued.job_id)
assert reconciled.state == outcome.job_state
assert reconciled.stage == outcome.job_stage
assert reconciled.status["error_code"] == outcome.error_code
assert reconciled.status["retryable"] is outcome.retryable
assert reconciled.status["finished_at"]
assert AssignmentRepository(settings).get(TEST_MACHINE_UUID) is None
```

Keep the existing `fail_if_systemctl_runs` assertion so a job with no unit cannot query systemd.

- [ ] **Step 4: Migrate result-recovered scenario**

Use:

```python
outcome = get_outcome("reconcile-result-recovered")
sandbox = make_controller_sandbox(tmp_path)
settings = sandbox.settings
jobs = JobRepository(settings)
assignments = AssignmentRepository(settings)
created = jobs.create(provision_request())
unit_name = f"alt-provision-{created.job_id}.service"
running = _advance_to_stage(
    settings,
    created.job_id,
    "recording",
    unit_name=unit_name,
)
result_payload = successful_provision_result(job_id=running.job_id)
atomic_write_json(running.job_dir / "result.json", result_payload)
# Existing inactive-worker fake_systemctl body remains unchanged.

cli_result = run_json_cli(
    ["jobs", "reconcile"],
    settings=settings,
)
assert cli_result.exit_code == outcome.command_exit_code
assert cli_result.payload["reconciliation"]["changed"][0]["action"] == (
    "result_recovered"
)

recovered = jobs.get(running.job_id)
assert recovered.state == outcome.job_state
assert recovered.stage == outcome.job_stage
assert [
    item["stage"]
    for item in recovered.status["stage_history"]
][-2:] == ["recording", "complete"]
assert recovered.status["result_file"] == str(
    running.job_dir / "result.json"
)
assert assignments.get(running.machine_uuid) == result_payload
```

- [ ] **Step 5: Run three migrated reconciliation tests**

```bash
.venv/bin/python -m pytest -q \
  tests/alt_linux/test_job_reconcile.py \
  -k "missing_running_worker_failed or unlaunched_queue_retryable or recovers_validated_result"
```

Expected: `3 passed`.

- [ ] **Step 6: Run complete reconciliation module**

```bash
.venv/bin/python -m pytest -q \
  tests/alt_linux/test_job_reconcile.py
```

Expected: all tests pass.

- [ ] **Step 7: Commit**

```bash
git add tests/alt_linux/test_job_reconcile.py
git commit -m "test: migrate reconciliation outcomes to OR-1 harness"
```

---

### Task 7: Full Verification and PR Preparation

**Files:**
- Verify all files changed in Tasks 1–6.
- Do not make opportunistic production changes during this task.

**Interfaces:**
- Consumes: complete OR-1 branch.
- Produces: verified commit history and reviewable PR.

- [ ] **Step 1: Run the focused OR-1 modules**

```bash
.venv/bin/python -m pytest -q \
  tests/alt_linux/test_operational_reliability_contract.py \
  tests/alt_linux/test_provision_start.py \
  tests/alt_linux/test_job_reconcile.py
```

Expected: exit `0`, no failures.

- [ ] **Step 2: Run the complete ALT suite**

```bash
.venv/bin/python -m pytest -q tests/alt_linux
```

Expected: exit `0`, no failures.

- [ ] **Step 3: Run the full repository suite**

```bash
.venv/bin/python -m pytest -q
```

Expected: exit `0`, no failures.

- [ ] **Step 4: Compile changed Python files**

```bash
.venv/bin/python -m py_compile \
  tests/alt_linux/support/__init__.py \
  tests/alt_linux/support/payloads.py \
  tests/alt_linux/support/controller_sandbox.py \
  tests/alt_linux/support/cli.py \
  tests/alt_linux/support/outcomes.py \
  tests/alt_linux/test_operational_reliability_contract.py \
  tests/alt_linux/test_provision_start.py \
  tests/alt_linux/test_job_reconcile.py
```

Expected: exit `0`, no output.

- [ ] **Step 5: Check whitespace and branch scope**

```bash
git diff --check origin/main...HEAD
git diff --name-only origin/main...HEAD
git status --short
```

Expected:

- `git diff --check` emits no output;
- changed paths are limited to the approved spec, plan and `tests/alt_linux/` files;
- worktree is clean after commits.

- [ ] **Step 6: Review history**

```bash
git log --oneline --decorate origin/main..HEAD
```

Expected: separate documentation, payload, sandbox, CLI, outcome, provision migration and reconciliation migration commits; no force-pushed or rewritten accepted history.

- [ ] **Step 7: Push and open PR**

```bash
git push -u origin feat/alt-or1-test-harness
```

Open a PR into `main` with:

```text
Title: test: add ALT operational reliability harness

Summary:
- add isolated controller sandbox and safe payload factories;
- add JSON CLI runner;
- formalize five proven operational outcomes;
- migrate root, launcher and reconciliation scenarios;
- keep production and Ansible behavior unchanged.

Verification:
- focused OR-1 tests: PASS with exact count;
- tests/alt_linux: PASS with exact count;
- full pytest: PASS with exact count;
- py_compile: PASS;
- git diff --check: PASS.
```

Do not claim PASS or include counts until each command has been run on the final commit and its output inspected.
