# ALT Workstation Provisioning OR-1 Test Harness Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Создать test-only foundation для operational reliability: изолированный controller sandbox, безопасные payload factories, JSON CLI runner, типизированный каталог пяти уже доказанных outcomes и перевести на него пять репрезентативных regression tests.

**Architecture:** Вся новая логика располагается в `tests/alt_linux/support/`; production и Ansible не меняются. Controller state создаётся только под `tmp_path`, а outcome-каталог является ожидаемым контрактом, который проверяется фактическим состоянием CLI, jobs и assignments.

**Tech Stack:** Python 3, pytest, dataclasses, pathlib, существующие `Settings`, `alt_deploy.cli.main`, `JobRepository`, `JobStageManager`, `AssignmentRepository`.

## Global Constraints

- Не изменять `deploy/alt-linux/control/` или `deploy/alt-linux/ansible/`.
- Не выполнять реальные SSH, systemd, Ansible или provisioning operations.
- Не читать активный Vault и runtime state контроллера.
- Не обращаться к эталонной VM `192.168.101.111`.
- Не добавлять pytest plugin либо YAML/JSON scenario engine.
- Каталог содержит ровно пять уже доказанных outcomes.
- Fixtures используют только синтетические данные и documentation-range IP `192.0.2.0/24`.
- Каждый логический блок завершается focused tests и отдельным коммитом.

---

## File Map

**Create:**

- `tests/alt_linux/support/__init__.py`
- `tests/alt_linux/support/payloads.py`
- `tests/alt_linux/support/controller_sandbox.py`
- `tests/alt_linux/support/cli.py`
- `tests/alt_linux/support/outcomes.py`
- `tests/alt_linux/test_operational_reliability_contract.py`

**Modify:**

- `tests/alt_linux/test_provision_start.py`
- `tests/alt_linux/test_job_reconcile.py`

**Do not modify:** production, Ansible, installer, bootstrap, `tests/alt_linux/conftest.py`.

---

### Task 1: Payload Factories

**Files:**
- Create: `tests/alt_linux/support/__init__.py`
- Create: `tests/alt_linux/support/payloads.py`
- Create: `tests/alt_linux/test_operational_reliability_contract.py`

**Interfaces:**
- Produces: `TEST_MACHINE_UUID`, `SECOND_TEST_MACHINE_UUID`, `machine_registration_payload()`, `provision_request()`, `assignment_payload()`, `successful_provision_result()`.

- [ ] **Step 1: Write RED tests**

Create `tests/alt_linux/test_operational_reliability_contract.py`:

```python
from __future__ import annotations

from support.payloads import (
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


def test_payload_factories_use_test_identifiers() -> None:
    assert machine_registration_payload()["uuid"] == TEST_MACHINE_UUID
    assert provision_request()["machine_uuid"] == TEST_MACHINE_UUID
    assert assignment_payload(job_id="job-test")["machine_uuid"] == (
        TEST_MACHINE_UUID
    )
    assert successful_provision_result(
        job_id="job-test"
    )["machine_uuid"] == TEST_MACHINE_UUID
    assert SECOND_TEST_MACHINE_UUID != TEST_MACHINE_UUID


def test_successful_result_has_complete_verification_contract() -> None:
    result = successful_provision_result(job_id="job-test")

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

- [ ] **Step 2: Verify RED**

```bash
.venv/bin/python -m pytest -q \
  tests/alt_linux/test_operational_reliability_contract.py
```

Expected: collection fails because `support.payloads` does not exist.

- [ ] **Step 3: Implement factories**

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
            "checks": {"uuid": True, "alt_release": True},
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
        "verification": {"hostname": True, "employee_exists": True},
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

- [ ] **Step 4: Verify GREEN and commit**

```bash
.venv/bin/python -m pytest -q \
  tests/alt_linux/test_operational_reliability_contract.py
git add tests/alt_linux/support tests/alt_linux/test_operational_reliability_contract.py
git commit -m "test: add ALT reliability payload factories"
```

Expected: `3 passed` before commit.

---

### Task 2: Controller Sandbox

**Files:**
- Create: `tests/alt_linux/support/controller_sandbox.py`
- Modify: `tests/alt_linux/test_operational_reliability_contract.py`

**Interfaces:**
- Produces: `ControllerSandbox`, `make_controller_sandbox()`, `register_machine()`, `install_fake_stage_helper()`, `install_fake_ansible_playbook()`, `configure_fake_vault()`.

- [ ] **Step 1: Append RED tests**

```python
from pathlib import Path

from alt_deploy.jsonio import read_json
from support.controller_sandbox import make_controller_sandbox


def test_controller_sandbox_keeps_paths_under_root(tmp_path: Path) -> None:
    sandbox = make_controller_sandbox(tmp_path)
    paths = (
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
    for path in paths:
        path.relative_to(sandbox.root)


def test_controller_sandbox_registers_machine(tmp_path: Path) -> None:
    sandbox = make_controller_sandbox(tmp_path)
    path = sandbox.register_machine(state="ready", preflight_ok=True)
    payload = read_json(path)

    assert path.parent.name == "ready"
    assert payload["status"] == "awaiting_assignment"
    assert payload["preflight"]["status"] == "ok"


def test_controller_sandbox_installs_requested_assets(
    tmp_path: Path,
) -> None:
    sandbox = make_controller_sandbox(tmp_path)
    assert not sandbox.settings.job_stage_helper_path.exists()
    assert not sandbox.settings.ansible_playbook_path.exists()

    sandbox.install_fake_stage_helper()
    sandbox.install_fake_ansible_playbook()
    vault_file, password_file = sandbox.configure_fake_vault()

    assert sandbox.settings.job_stage_helper_path.stat().st_mode & 0o111
    assert sandbox.settings.ansible_playbook_path.stat().st_mode & 0o111
    assert vault_file.read_text(encoding="utf-8").startswith(
        "$ANSIBLE_VAULT;"
    )
    assert password_file.stat().st_mode & 0o077 == 0
```

- [ ] **Step 2: Verify RED**

```bash
.venv/bin/python -m pytest -q \
  tests/alt_linux/test_operational_reliability_contract.py \
  -k controller_sandbox
```

Expected: import fails because `support.controller_sandbox` does not exist.

- [ ] **Step 3: Implement sandbox**

Create `tests/alt_linux/support/controller_sandbox.py`:

```python
from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path

from alt_deploy.config import Settings
from alt_deploy.jsonio import atomic_write_json

from .payloads import TEST_MACHINE_UUID, machine_registration_payload


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
            "test-only-passphrase\n",
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

- [ ] **Step 4: Verify GREEN and commit**

```bash
.venv/bin/python -m pytest -q \
  tests/alt_linux/test_operational_reliability_contract.py \
  -k controller_sandbox
git add tests/alt_linux/support/controller_sandbox.py \
  tests/alt_linux/test_operational_reliability_contract.py
git commit -m "test: add isolated ALT controller sandbox"
```

Expected: `3 passed` for the selected tests.

---

### Task 3: JSON CLI Runner

**Files:**
- Create: `tests/alt_linux/support/cli.py`
- Modify: `tests/alt_linux/test_operational_reliability_contract.py`

**Interfaces:**
- Produces: `CliResult`, `run_json_cli()`.

- [ ] **Step 1: Append RED tests**

```python
from support.cli import run_json_cli


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

- [ ] **Step 2: Verify RED**

```bash
.venv/bin/python -m pytest -q \
  tests/alt_linux/test_operational_reliability_contract.py \
  -k run_json_cli
```

Expected: import fails because `support.cli` does not exist.

- [ ] **Step 3: Implement runner**

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
    exit_code = main(
        ["--json", *args],
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

- [ ] **Step 4: Verify GREEN and commit**

```bash
.venv/bin/python -m pytest -q \
  tests/alt_linux/test_operational_reliability_contract.py \
  -k run_json_cli
git add tests/alt_linux/support/cli.py \
  tests/alt_linux/test_operational_reliability_contract.py
git commit -m "test: add workstationctl JSON test runner"
```

Expected: `2 passed` for the selected tests.

---

### Task 4: Outcome Catalog

**Files:**
- Create: `tests/alt_linux/support/outcomes.py`
- Modify: `tests/alt_linux/test_operational_reliability_contract.py`

**Interfaces:**
- Produces: `OperationalOutcome`, `PROVEN_OPERATIONAL_OUTCOMES`, `get_outcome()`.

- [ ] **Step 1: Append RED tests**

```python
import re
from dataclasses import asdict

import pytest

from alt_deploy.job_stages import CANONICAL_STAGES
from support.outcomes import PROVEN_OPERATIONAL_OUTCOMES, get_outcome

EXPECTED_SCENARIO_IDS = {
    "provision-start-root-required",
    "provision-start-launch-failed",
    "reconcile-worker-not-started-created",
    "reconcile-worker-lost-employee",
    "reconcile-result-recovered",
}


def test_proven_outcome_catalog_has_exact_scenarios() -> None:
    assert {
        item.scenario_id for item in PROVEN_OPERATIONAL_OUTCOMES
    } == EXPECTED_SCENARIO_IDS


def test_proven_outcome_catalog_is_consistent() -> None:
    scenario_ids = [
        item.scenario_id for item in PROVEN_OPERATIONAL_OUTCOMES
    ]
    assert len(scenario_ids) == len(set(scenario_ids))

    for item in PROVEN_OPERATIONAL_OUTCOMES:
        assert re.fullmatch(
            r"[a-z0-9]+(?:-[a-z0-9]+)*",
            item.scenario_id,
        )
        assert item.boundary in {
            "authorization",
            "launcher",
            "reconciliation",
            "result_recovery",
        }
        assert item.job_state in {
            None,
            "queued",
            "running",
            "successful",
            "failed",
        }
        assert item.job_stage in {None, *CANONICAL_STAGES}
        assert item.required_evidence
        assert len(item.required_evidence) == len(
            set(item.required_evidence)
        )
        if item.job_state == "successful":
            assert item.job_stage == "complete"
        if item.job_state == "failed":
            assert item.job_stage != "complete"
            assert item.assignment_created is False


def test_outcome_metadata_contains_no_secret_names() -> None:
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


def test_get_outcome_fails_closed() -> None:
    with pytest.raises(KeyError, match="unknown-scenario"):
        get_outcome("unknown-scenario")
```

- [ ] **Step 2: Verify RED**

```bash
.venv/bin/python -m pytest -q \
  tests/alt_linux/test_operational_reliability_contract.py \
  -k outcome
```

Expected: import fails because `support.outcomes` does not exist.

- [ ] **Step 3: Implement catalog**

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
        "provision-start-root-required",
        "authorization",
        "root_required",
        6,
        None,
        None,
        False,
        None,
        ("cli_error", "no_job_created", "no_assignment_created"),
    ),
    OperationalOutcome(
        "provision-start-launch-failed",
        "launcher",
        "job_launch_failed",
        6,
        "failed",
        "launching",
        False,
        None,
        (
            "cli_error",
            "finished_at",
            "stage_history_created_launching",
            "no_assignment_created",
        ),
    ),
    OperationalOutcome(
        "reconcile-worker-not-started-created",
        "reconciliation",
        "worker_not_started",
        0,
        "failed",
        "created",
        False,
        True,
        (
            "reconciliation_action_queued_recoverable",
            "finished_at",
            "stage_preserved",
            "no_assignment_created",
        ),
    ),
    OperationalOutcome(
        "reconcile-worker-lost-employee",
        "reconciliation",
        "worker_lost",
        0,
        "failed",
        "employee",
        False,
        None,
        (
            "reconciliation_action_worker_lost",
            "last_real_stage_preserved",
            "no_result_created",
            "no_assignment_created",
        ),
    ),
    OperationalOutcome(
        "reconcile-result-recovered",
        "result_recovery",
        None,
        0,
        "successful",
        "complete",
        True,
        None,
        (
            "reconciliation_action_result_recovered",
            "recording_complete_transition",
            "result_file_recorded",
            "server_assignment_matches_result",
        ),
    ),
)

_OUTCOMES_BY_ID = {
    item.scenario_id: item for item in PROVEN_OPERATIONAL_OUTCOMES
}


def get_outcome(scenario_id: str) -> OperationalOutcome:
    try:
        return _OUTCOMES_BY_ID[scenario_id]
    except KeyError as exc:
        raise KeyError(
            f"Unknown operational outcome: {scenario_id}"
        ) from exc
```

- [ ] **Step 4: Verify GREEN and commit**

```bash
.venv/bin/python -m pytest -q \
  tests/alt_linux/test_operational_reliability_contract.py
git add tests/alt_linux/support/outcomes.py \
  tests/alt_linux/test_operational_reliability_contract.py
git commit -m "test: define proven ALT operational outcomes"
```

Expected: complete contract module passes.

---

### Task 5: Provision Failure Contracts

**Files:**
- Modify: `tests/alt_linux/test_provision_start.py`

**Interfaces:**
- Consumes: sandbox, payloads, CLI runner, outcome catalog.

- [ ] **Step 1: Add imports**

```python
from alt_deploy.assignments import AssignmentRepository
from support.cli import run_json_cli
from support.controller_sandbox import make_controller_sandbox
from support.outcomes import get_outcome
from support.payloads import TEST_MACHINE_UUID, provision_request
```

Keep existing imports needed by unrelated tests.

- [ ] **Step 2: Replace root-required test**

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
    assert AssignmentRepository(sandbox.settings).get(
        TEST_MACHINE_UUID
    ) is None
```

- [ ] **Step 3: Replace launch-failed test**

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
        item["stage"] for item in jobs[0].status["stage_history"]
    ] == ["created", "launching"]
    assert jobs[0].status["finished_at"]
    assert AssignmentRepository(sandbox.settings).get(
        TEST_MACHINE_UUID
    ) is None
```

- [ ] **Step 4: Verify and commit**

```bash
.venv/bin/python -m pytest -q \
  tests/alt_linux/test_provision_start.py \
  -k "requires_root or launch_failure_is_persisted"
.venv/bin/python -m pytest -q tests/alt_linux/test_provision_start.py
git add tests/alt_linux/test_provision_start.py
git commit -m "test: migrate provision failures to OR-1 harness"
```

Expected: selected and complete module pass.

---

### Task 6: Reconciliation Contracts

**Files:**
- Modify: `tests/alt_linux/test_job_reconcile.py`

**Interfaces:**
- Consumes: sandbox, payloads, CLI runner, outcome catalog.
- Reuses existing local `_systemctl_result()` and `_advance_to_stage()` without changing them.

- [ ] **Step 1: Add imports**

```python
from support.cli import run_json_cli
from support.controller_sandbox import make_controller_sandbox
from support.outcomes import get_outcome
from support.payloads import (
    TEST_MACHINE_UUID,
    provision_request as reliability_provision_request,
    successful_provision_result,
)
```

Keep existing `provision_request` and `successful_result` imports for unrelated tests.

- [ ] **Step 2: Replace worker-lost test completely**

```python
def test_jobs_reconcile_marks_missing_running_worker_failed(
    monkeypatch,
    tmp_path: Path,
) -> None:
    outcome = get_outcome("reconcile-worker-lost-employee")
    sandbox = make_controller_sandbox(tmp_path)
    settings = sandbox.settings
    jobs = JobRepository(settings)
    created = jobs.create(reliability_provision_request())
    unit_name = f"alt-provision-{created.job_id}.service"
    running = _advance_to_stage(
        settings,
        created.job_id,
        "employee",
        unit_name=unit_name,
    )

    def fake_systemctl(
        command,
        *,
        shell,
        text,
        capture_output,
        timeout,
        check,
    ):
        assert shell is False
        assert text is True
        assert capture_output is True
        assert timeout == 15
        assert check is False
        return _systemctl_result(
            command,
            unit_name=unit_name,
            load_state="not-found",
            active_state="inactive",
            sub_state="dead",
        )

    monkeypatch.setattr(subprocess, "run", fake_systemctl)
    result = run_json_cli(
        ["jobs", "reconcile"],
        settings=settings,
    )

    assert result.exit_code == outcome.command_exit_code
    assert result.payload["reconciliation"]["changed"] == [
        {
            "job_id": running.job_id,
            "previous_state": "running",
            "state": "failed",
            "action": "worker_lost",
        }
    ]
    reconciled = jobs.get(running.job_id)
    assert reconciled.state == outcome.job_state
    assert reconciled.stage == outcome.job_stage
    assert reconciled.status["error_code"] == outcome.error_code
    assert not (reconciled.job_dir / "result.json").exists()
    assert AssignmentRepository(settings).get(TEST_MACHINE_UUID) is None
```

- [ ] **Step 3: Replace worker-not-started-created test completely**

```python
def test_jobs_reconcile_marks_unlaunched_queue_retryable(
    monkeypatch,
    tmp_path: Path,
) -> None:
    outcome = get_outcome("reconcile-worker-not-started-created")
    sandbox = make_controller_sandbox(tmp_path)
    settings = sandbox.settings
    jobs = JobRepository(settings)
    queued = jobs.create(reliability_provision_request())

    def fail_if_systemctl_runs(*args, **kwargs):
        raise AssertionError(
            "queued job without unit must not query systemd"
        )

    monkeypatch.setattr(subprocess, "run", fail_if_systemctl_runs)
    result = run_json_cli(
        ["jobs", "reconcile"],
        settings=settings,
    )

    assert result.exit_code == outcome.command_exit_code
    assert result.payload["reconciliation"]["changed"] == [
        {
            "job_id": queued.job_id,
            "previous_state": "queued",
            "state": "failed",
            "action": "queued_recoverable",
            "retryable": True,
        }
    ]
    reconciled = jobs.get(queued.job_id)
    assert reconciled.state == outcome.job_state
    assert reconciled.stage == outcome.job_stage
    assert reconciled.status["error_code"] == outcome.error_code
    assert reconciled.status["retryable"] is outcome.retryable
    assert reconciled.status["finished_at"]
    assert AssignmentRepository(settings).get(TEST_MACHINE_UUID) is None
```

- [ ] **Step 4: Replace result-recovered test completely**

```python
def test_jobs_reconcile_recovers_validated_result_after_interruption(
    monkeypatch,
    tmp_path: Path,
) -> None:
    outcome = get_outcome("reconcile-result-recovered")
    sandbox = make_controller_sandbox(tmp_path)
    settings = sandbox.settings
    jobs = JobRepository(settings)
    assignments = AssignmentRepository(settings)
    created = jobs.create(reliability_provision_request())
    unit_name = f"alt-provision-{created.job_id}.service"
    running = _advance_to_stage(
        settings,
        created.job_id,
        "recording",
        unit_name=unit_name,
    )
    result_payload = successful_provision_result(
        job_id=running.job_id
    )
    atomic_write_json(running.job_dir / "result.json", result_payload)

    def fake_systemctl(
        command,
        *,
        shell,
        text,
        capture_output,
        timeout,
        check,
    ):
        assert shell is False
        assert text is True
        assert capture_output is True
        assert timeout == 15
        assert check is False
        return _systemctl_result(
            command,
            unit_name=unit_name,
            load_state="not-found",
            active_state="inactive",
            sub_state="dead",
        )

    monkeypatch.setattr(subprocess, "run", fake_systemctl)
    cli_result = run_json_cli(
        ["jobs", "reconcile"],
        settings=settings,
    )

    assert cli_result.exit_code == outcome.command_exit_code
    assert cli_result.payload["reconciliation"]["changed"] == [
        {
            "job_id": running.job_id,
            "previous_state": "running",
            "state": "successful",
            "action": "result_recovered",
        }
    ]
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

- [ ] **Step 5: Verify and commit**

```bash
.venv/bin/python -m pytest -q \
  tests/alt_linux/test_job_reconcile.py \
  -k "missing_running_worker_failed or unlaunched_queue_retryable or recovers_validated_result"
.venv/bin/python -m pytest -q tests/alt_linux/test_job_reconcile.py
git add tests/alt_linux/test_job_reconcile.py
git commit -m "test: migrate reconciliation outcomes to OR-1 harness"
```

Expected: selected and complete module pass.

---

### Task 7: Verification and PR

**Files:** all approved OR-1 files only.

- [ ] **Step 1: Focused gate**

```bash
.venv/bin/python -m pytest -q \
  tests/alt_linux/test_operational_reliability_contract.py \
  tests/alt_linux/test_provision_start.py \
  tests/alt_linux/test_job_reconcile.py
```

Expected: exit `0`.

- [ ] **Step 2: ALT and full gates**

```bash
.venv/bin/python -m pytest -q tests/alt_linux
.venv/bin/python -m pytest -q
```

Expected: both commands exit `0`.

- [ ] **Step 3: Compile and diff checks**

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
git diff --check origin/main...HEAD
git diff --name-only origin/main...HEAD
git status --short
```

Expected: compile and diff checks exit `0`; no production or Ansible files changed; worktree clean after commits.

- [ ] **Step 4: Push and open PR**

```bash
git push -u origin feat/alt-or1-test-harness
```

PR title:

```text
test: add ALT operational reliability harness
```

PR body must include exact observed test counts. Do not claim PASS for a command that was not executed on the final commit.
