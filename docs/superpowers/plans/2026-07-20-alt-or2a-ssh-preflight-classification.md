# ALT Workstation Provisioning OR-2A Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Сохранить публичный `preflight_failed`, но добавить детерминированную безопасную классификацию SSH/preflight failures через `error.details.failure_kind` и доказать retryability без создания jobs или assignments.

**Architecture:** В `alt_deploy.ansible` добавляется внутренний pure-classifier с фиксированным allowlist и conservative fallback `ansible_failed`. `run_preflight()` добавляет `failure_kind` во все собственные ветви `preflight_failed`; passwordless-sudo assert получает контролируемый Ansible marker. OR-1 outcome model и sandbox расширяются test-only контрактами, а новый self-contained модуль проверяет CLI, registration persistence, strict SSH options и повторный успешный preflight.

**Tech Stack:** Python 3, pytest, dataclasses, pathlib, subprocess, существующие `alt_deploy.cli.main`, `AnsibleController`, `MachineRepository`, `JobRepository`, `AssignmentRepository`, Ansible YAML.

## Global Constraints

- Базовый commit `main`: `689fb9622b85d3585382a308ebe31f59ab9da7d3`.
- Сохранить `ControlError.code = preflight_failed` и `exit_code = 5`.
- Добавить только allowlisted `failure_kind`: `ssh_timeout`, `ssh_unreachable`, `ssh_host_key_mismatch`, `ssh_authentication_failed`, `sudo_unavailable`, `ansible_failed`.
- Не классифицировать `run_provision()` и не менять provision worker error codes.
- Не менять job stages, assignment boundary, Vault или controller permission behavior.
- Не проверять executable-bit stage helper в OR-2A.
- Не выполнять реальные SSH, Ansible provisioning или обращения к эталонной VM.
- Сохранить `StrictHostKeyChecking=yes`, `ProxyCommand=none`, `IdentitiesOnly=yes`, `ConnectTimeout=10`.
- Не возвращать произвольный diagnostic text через `failure_kind`.
- Unknown/ambiguous diagnostics всегда классифицировать как `ansible_failed`.
- Не добавлять реальные private keys, known-host records или runtime state в fixtures.
- Временный verification workflow удалить до итогового PR diff.

---

## File Map

**Modify production:**

- `deploy/alt-linux/control/alt_deploy/ansible.py` — allowlist, pure classifier и добавление `failure_kind` в четыре ветви `preflight_failed`.
- `deploy/alt-linux/ansible/roles/preflight/tasks/main.yml` — контролируемый marker `ALT_PREFLIGHT_FAILURE:sudo_unavailable` в существующем sudo assert.

**Modify test support:**

- `tests/alt_linux/support/controller_sandbox.py` — явная подготовка файлов preflight boundary.
- `tests/alt_linux/support/outcomes.py` — поле `failure_kind` и шесть OR-2A outcomes.

**Create tests:**

- `tests/alt_linux/test_or2a_preflight_failures.py` — pure classifier, CLI persistence, fallback, retryability и strict SSH regression.

**Modify tests:**

- `tests/alt_linux/test_operational_reliability_contract.py` — каталог из 11 scenarios и invariants для `boundary=preflight`.

---

### Task 1: Extend the Operational Outcome Contract

**Files:**
- Modify: `tests/alt_linux/support/outcomes.py`
- Modify: `tests/alt_linux/test_operational_reliability_contract.py`

**Interfaces:**
- Consumes: existing `OperationalOutcome` and five OR-1 records.
- Produces: `failure_kind: str | None = None`, six preflight outcomes and an 11-scenario catalog.

- [ ] **Step 1: Write failing catalog tests**

Update `EXPECTED_SCENARIO_IDS` in `tests/alt_linux/test_operational_reliability_contract.py` to include:

```python
EXPECTED_SCENARIO_IDS = {
    "provision-start-root-required",
    "provision-start-launch-failed",
    "reconcile-worker-not-started-created",
    "reconcile-worker-lost-employee",
    "reconcile-result-recovered",
    "preflight-ssh-timeout",
    "preflight-ssh-unreachable",
    "preflight-ssh-host-key-mismatch",
    "preflight-ssh-authentication-failed",
    "preflight-sudo-unavailable",
    "preflight-ansible-failed",
}

PREFLIGHT_FAILURE_KINDS = {
    "ssh_timeout",
    "ssh_unreachable",
    "ssh_host_key_mismatch",
    "ssh_authentication_failed",
    "sudo_unavailable",
    "ansible_failed",
}
```

Extend the boundary assertion and add field invariants inside the existing catalog loop:

```python
assert item.boundary in {
    "authorization",
    "launcher",
    "reconciliation",
    "result_recovery",
    "preflight",
}

if item.boundary == "preflight":
    assert item.error_code == "preflight_failed"
    assert item.command_exit_code == 5
    assert item.job_state is None
    assert item.job_stage is None
    assert item.assignment_created is False
    assert item.retryable is True
    assert item.failure_kind in PREFLIGHT_FAILURE_KINDS
else:
    assert item.failure_kind is None
```

Add an exact mapping test:

```python
def test_preflight_outcomes_have_expected_failure_kinds() -> None:
    expected = {
        "preflight-ssh-timeout": "ssh_timeout",
        "preflight-ssh-unreachable": "ssh_unreachable",
        "preflight-ssh-host-key-mismatch": "ssh_host_key_mismatch",
        "preflight-ssh-authentication-failed": (
            "ssh_authentication_failed"
        ),
        "preflight-sudo-unavailable": "sudo_unavailable",
        "preflight-ansible-failed": "ansible_failed",
    }

    assert {
        scenario_id: get_outcome(scenario_id).failure_kind
        for scenario_id in expected
    } == expected
```

- [ ] **Step 2: Run focused tests and verify RED**

```bash
.venv/bin/python -m pytest -q \
  tests/alt_linux/test_operational_reliability_contract.py
```

Expected: FAIL because `OperationalOutcome` has no `failure_kind` and the six scenario IDs are absent.

- [ ] **Step 3: Extend the immutable model and catalog**

Append the field to the dataclass in `tests/alt_linux/support/outcomes.py`:

```python
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
    failure_kind: str | None = None
```

Append six records to `PROVEN_OPERATIONAL_OUTCOMES`:

```python
    OperationalOutcome(
        "preflight-ssh-timeout",
        "preflight",
        "preflight_failed",
        5,
        None,
        None,
        False,
        True,
        (
            "cli_failure_kind_ssh_timeout",
            "registration_error_persisted",
            "no_job_created",
            "no_assignment_created",
        ),
        "ssh_timeout",
    ),
    OperationalOutcome(
        "preflight-ssh-unreachable",
        "preflight",
        "preflight_failed",
        5,
        None,
        None,
        False,
        True,
        (
            "cli_failure_kind_ssh_unreachable",
            "registration_error_persisted",
            "strict_ssh_options_preserved",
            "no_job_created",
            "no_assignment_created",
        ),
        "ssh_unreachable",
    ),
    OperationalOutcome(
        "preflight-ssh-host-key-mismatch",
        "preflight",
        "preflight_failed",
        5,
        None,
        None,
        False,
        True,
        (
            "cli_failure_kind_ssh_host_key_mismatch",
            "registration_error_persisted",
            "no_job_created",
            "no_assignment_created",
        ),
        "ssh_host_key_mismatch",
    ),
    OperationalOutcome(
        "preflight-ssh-authentication-failed",
        "preflight",
        "preflight_failed",
        5,
        None,
        None,
        False,
        True,
        (
            "cli_failure_kind_ssh_authentication_failed",
            "registration_error_persisted",
            "no_job_created",
            "no_assignment_created",
        ),
        "ssh_authentication_failed",
    ),
    OperationalOutcome(
        "preflight-sudo-unavailable",
        "preflight",
        "preflight_failed",
        5,
        None,
        None,
        False,
        True,
        (
            "controlled_sudo_marker",
            "cli_failure_kind_sudo_unavailable",
            "registration_error_persisted",
            "no_job_created",
            "no_assignment_created",
        ),
        "sudo_unavailable",
    ),
    OperationalOutcome(
        "preflight-ansible-failed",
        "preflight",
        "preflight_failed",
        5,
        None,
        None,
        False,
        True,
        (
            "conservative_fallback",
            "registration_error_persisted",
            "no_job_created",
            "no_assignment_created",
        ),
        "ansible_failed",
    ),
```

- [ ] **Step 4: Run catalog tests and verify GREEN**

```bash
.venv/bin/python -m pytest -q \
  tests/alt_linux/test_operational_reliability_contract.py
```

Expected: all operational reliability contract tests pass.

- [ ] **Step 5: Commit**

```bash
git add \
  tests/alt_linux/support/outcomes.py \
  tests/alt_linux/test_operational_reliability_contract.py
git commit -m "test: define OR-2A preflight outcomes"
```

---

### Task 2: Add the Pure Preflight Failure Classifier

**Files:**
- Create: `tests/alt_linux/test_or2a_preflight_failures.py`
- Modify: `deploy/alt-linux/control/alt_deploy/ansible.py`

**Interfaces:**
- Produces: internal `_classify_preflight_failure(*, stdout, stderr) -> str`.
- Produces: internal `_PREFLIGHT_FAILURE_KINDS` allowlist.
- Does not alter `run_preflight()` in this task.

- [ ] **Step 1: Write failing pure-classifier tests**

Create `tests/alt_linux/test_or2a_preflight_failures.py` with imports and parameterized cases:

```python
from __future__ import annotations

import subprocess
from pathlib import Path

import pytest

from alt_deploy.ansible import _classify_preflight_failure

PREFLIGHT_FAILURE_KINDS = {
    "ssh_timeout",
    "ssh_unreachable",
    "ssh_host_key_mismatch",
    "ssh_authentication_failed",
    "sudo_unavailable",
    "ansible_failed",
}


@pytest.mark.parametrize(
    ("stdout", "stderr", "expected"),
    [
        (
            "ALT_PREFLIGHT_FAILURE:sudo_unavailable\nPLAY RECAP",
            "Host key verification failed",
            "sudo_unavailable",
        ),
        (
            "",
            "WARNING: REMOTE HOST IDENTIFICATION HAS CHANGED!",
            "ssh_host_key_mismatch",
        ),
        (
            "",
            "Host key verification failed.",
            "ssh_host_key_mismatch",
        ),
        (
            "",
            "Permission denied (publickey,password).",
            "ssh_authentication_failed",
        ),
        (
            "Authentication failed for ansible",
            "",
            "ssh_authentication_failed",
        ),
        (
            "",
            "ssh: connect to host 192.0.2.56 port 22: Connection timed out",
            "ssh_timeout",
        ),
        (
            "",
            "ssh: connect to host 192.0.2.56 port 22: Connection refused",
            "ssh_unreachable",
        ),
        (
            "fatal: [192.0.2.56]: UNREACHABLE!",
            "",
            "ansible_failed",
        ),
        (
            "ALT_PREFLIGHT_FAILURE:unknown_kind",
            "",
            "ansible_failed",
        ),
        (
            None,
            None,
            "ansible_failed",
        ),
    ],
)
def test_classify_preflight_failure(
    stdout: str | None,
    stderr: str | None,
    expected: str,
) -> None:
    result = _classify_preflight_failure(
        stdout=stdout,
        stderr=stderr,
    )

    assert result == expected
    assert result in PREFLIGHT_FAILURE_KINDS


def test_host_key_mismatch_precedes_authentication_text() -> None:
    result = _classify_preflight_failure(
        stdout="",
        stderr=(
            "REMOTE HOST IDENTIFICATION HAS CHANGED!\n"
            "Permission denied (publickey)."
        ),
    )

    assert result == "ssh_host_key_mismatch"
```

- [ ] **Step 2: Run classifier tests and verify RED**

```bash
.venv/bin/python -m pytest -q \
  tests/alt_linux/test_or2a_preflight_failures.py \
  -k "classify_preflight_failure or host_key_mismatch"
```

Expected: collection FAIL because `_classify_preflight_failure` does not exist.

- [ ] **Step 3: Implement the minimal pure classifier**

Add after `_bounded()` in `deploy/alt-linux/control/alt_deploy/ansible.py`:

```python
_PREFLIGHT_FAILURE_KINDS = frozenset(
    {
        "ssh_timeout",
        "ssh_unreachable",
        "ssh_host_key_mismatch",
        "ssh_authentication_failed",
        "sudo_unavailable",
        "ansible_failed",
    }
)

_CONTROLLED_PREFLIGHT_MARKERS = {
    "ALT_PREFLIGHT_FAILURE:sudo_unavailable": "sudo_unavailable",
}


def _classify_preflight_failure(
    *,
    stdout: str | None,
    stderr: str | None,
) -> str:
    combined = "\n".join(
        value
        for value in (stdout, stderr)
        if isinstance(value, str) and value
    )

    for marker, failure_kind in _CONTROLLED_PREFLIGHT_MARKERS.items():
        if marker in combined:
            return failure_kind

    normalized = combined.casefold()

    if (
        "remote host identification has changed" in normalized
        or "host key verification failed" in normalized
        or (
            "offending " in normalized
            and " key in " in normalized
        )
    ):
        return "ssh_host_key_mismatch"

    if any(
        marker in normalized
        for marker in (
            "permission denied (publickey",
            "authentication failed",
            "no more authentication methods to try",
        )
    ):
        return "ssh_authentication_failed"

    if any(
        marker in normalized
        for marker in (
            "connection timed out",
            "operation timed out",
            "timeout waiting for",
        )
    ):
        return "ssh_timeout"

    if any(
        marker in normalized
        for marker in (
            "connection refused",
            "no route to host",
            "network is unreachable",
            "connection reset by peer",
            "connection closed by remote host",
        )
    ):
        return "ssh_unreachable"

    return "ansible_failed"
```

- [ ] **Step 4: Run classifier tests and verify GREEN**

```bash
.venv/bin/python -m pytest -q \
  tests/alt_linux/test_or2a_preflight_failures.py \
  -k "classify_preflight_failure or host_key_mismatch"
```

Expected: classifier tests pass.

- [ ] **Step 5: Commit**

```bash
git add \
  deploy/alt-linux/control/alt_deploy/ansible.py \
  tests/alt_linux/test_or2a_preflight_failures.py
git commit -m "feat: classify ALT preflight failures"
```

---

### Task 3: Add the Controlled Passwordless-Sudo Marker

**Files:**
- Modify: `deploy/alt-linux/ansible/roles/preflight/tasks/main.yml`
- Modify: `tests/alt_linux/test_or2a_preflight_failures.py`

**Interfaces:**
- Consumes: `_classify_preflight_failure()` marker support.
- Produces: exact internal marker `ALT_PREFLIGHT_FAILURE:sudo_unavailable` in the existing assert failure message.

- [ ] **Step 1: Write a failing marker-presence test**

Append:

```python
def test_preflight_role_contains_controlled_sudo_marker() -> None:
    role_path = (
        Path(__file__).resolve().parents[2]
        / "deploy"
        / "alt-linux"
        / "ansible"
        / "roles"
        / "preflight"
        / "tasks"
        / "main.yml"
    )
    content = role_path.read_text(encoding="utf-8")

    assert content.count(
        "ALT_PREFLIGHT_FAILURE:sudo_unavailable"
    ) == 1
```

- [ ] **Step 2: Run marker test and verify RED**

```bash
.venv/bin/python -m pytest -q \
  tests/alt_linux/test_or2a_preflight_failures.py::test_preflight_role_contains_controlled_sudo_marker
```

Expected: FAIL because the marker is absent.

- [ ] **Step 3: Add the marker without changing the assert condition**

Replace the existing `fail_msg` for `Validate passwordless sudo` with:

```yaml
    fail_msg: >-
      ALT_PREFLIGHT_FAILURE:sudo_unavailable
      The ansible account has no passwordless sudo
```

Do not change:

```yaml
    that:
      - preflight_ansible_sudo.rc == 0
```

- [ ] **Step 4: Run marker test and Ansible syntax-check**

```bash
.venv/bin/python -m pytest -q \
  tests/alt_linux/test_or2a_preflight_failures.py::test_preflight_role_contains_controlled_sudo_marker

ANSIBLE_CONFIG=deploy/alt-linux/ansible/ansible.cfg \
  ansible-playbook --syntax-check \
  deploy/alt-linux/ansible/playbooks/01-preflight.yml
```

Expected: marker test PASS and Ansible syntax-check exit code 0.

- [ ] **Step 5: Commit**

```bash
git add \
  deploy/alt-linux/ansible/roles/preflight/tasks/main.yml \
  tests/alt_linux/test_or2a_preflight_failures.py
git commit -m "feat: mark passwordless sudo preflight failure"
```

---

### Task 4: Prepare an Explicit Isolated Preflight Boundary

**Files:**
- Modify: `tests/alt_linux/support/controller_sandbox.py`
- Modify: `tests/alt_linux/test_or2a_preflight_failures.py`

**Interfaces:**
- Produces: `ControllerSandbox.configure_preflight_boundary() -> dict[str, Path]`.
- Creates only synthetic files under `sandbox.root`.

- [ ] **Step 1: Write a failing sandbox-boundary test**

Append:

```python
from support.controller_sandbox import make_controller_sandbox


def test_sandbox_configures_preflight_boundary(tmp_path: Path) -> None:
    sandbox = make_controller_sandbox(tmp_path)
    assets = sandbox.configure_preflight_boundary()

    assert set(assets) == {
        "ansible_playbook",
        "private_key",
        "known_hosts",
        "preflight_playbook",
    }
    for path in assets.values():
        path.relative_to(sandbox.root)
        assert path.is_file()

    assert assets["ansible_playbook"].stat().st_mode & 0o111
    assert assets["private_key"].read_text(encoding="utf-8") == (
        "test-only-private-key-placeholder\n"
    )
```

- [ ] **Step 2: Run boundary test and verify RED**

```bash
.venv/bin/python -m pytest -q \
  tests/alt_linux/test_or2a_preflight_failures.py::test_sandbox_configures_preflight_boundary
```

Expected: FAIL because `configure_preflight_boundary()` does not exist.

- [ ] **Step 3: Implement the sandbox helper**

Add to `ControllerSandbox`:

```python
    def configure_preflight_boundary(self) -> dict[str, Path]:
        ansible_playbook = self.install_fake_ansible_playbook()

        self.settings.private_key_file.parent.mkdir(
            parents=True,
            exist_ok=True,
        )
        self.settings.private_key_file.write_text(
            "test-only-private-key-placeholder\n",
            encoding="utf-8",
        )
        self.settings.private_key_file.chmod(0o600)

        self.settings.known_hosts_file.write_text(
            "test-only-known-host-placeholder\n",
            encoding="utf-8",
        )
        self.settings.known_hosts_file.chmod(0o600)

        preflight_playbook = (
            self.settings.ansible_project_dir
            / "playbooks"
            / "01-preflight.yml"
        )
        preflight_playbook.parent.mkdir(parents=True, exist_ok=True)
        preflight_playbook.write_text("---\n", encoding="utf-8")

        return {
            "ansible_playbook": ansible_playbook,
            "private_key": self.settings.private_key_file,
            "known_hosts": self.settings.known_hosts_file,
            "preflight_playbook": preflight_playbook,
        }
```

- [ ] **Step 4: Run boundary test and verify GREEN**

```bash
.venv/bin/python -m pytest -q \
  tests/alt_linux/test_or2a_preflight_failures.py::test_sandbox_configures_preflight_boundary
```

Expected: PASS.

- [ ] **Step 5: Commit**

```bash
git add \
  tests/alt_linux/support/controller_sandbox.py \
  tests/alt_linux/test_or2a_preflight_failures.py
git commit -m "test: add isolated preflight boundary"
```

---

### Task 5: Persist `failure_kind` Through the Real CLI

**Files:**
- Modify: `deploy/alt-linux/control/alt_deploy/ansible.py`
- Modify: `tests/alt_linux/test_or2a_preflight_failures.py`

**Interfaces:**
- Consumes: classifier, OR-2A outcomes, sandbox preflight boundary and `run_json_cli()`.
- Produces: `failure_kind` in all four `run_preflight()`-originated `preflight_failed` branches.

- [ ] **Step 1: Add failing CLI scenario tests**

Add imports:

```python
from alt_deploy.assignments import AssignmentRepository
from alt_deploy.jobs import JobRepository
from alt_deploy.jsonio import atomic_write_json, read_json
from support.cli import run_json_cli
from support.outcomes import get_outcome
from support.payloads import TEST_MACHINE_UUID
```

Add test cases:

```python
CLI_FAILURE_CASES = (
    (
        "preflight-ssh-unreachable",
        4,
        "",
        "ssh: connect to host 192.0.2.56 port 22: Connection refused",
    ),
    (
        "preflight-ssh-host-key-mismatch",
        4,
        "",
        "REMOTE HOST IDENTIFICATION HAS CHANGED!",
    ),
    (
        "preflight-ssh-authentication-failed",
        4,
        "",
        "Permission denied (publickey).",
    ),
    (
        "preflight-sudo-unavailable",
        2,
        "ALT_PREFLIGHT_FAILURE:sudo_unavailable",
        "",
    ),
    (
        "preflight-ansible-failed",
        2,
        "Unsupported operating system",
        "",
    ),
)


@pytest.mark.parametrize(
    ("scenario_id", "returncode", "stdout", "stderr"),
    CLI_FAILURE_CASES,
)
def test_preflight_cli_persists_classified_failure(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
    scenario_id: str,
    returncode: int,
    stdout: str,
    stderr: str,
) -> None:
    outcome = get_outcome(scenario_id)
    sandbox = make_controller_sandbox(tmp_path)
    sandbox.configure_preflight_boundary()
    record_path = sandbox.register_machine()
    captured: dict[str, object] = {}

    def fake_run(command, **kwargs):
        captured["command"] = command
        captured["kwargs"] = kwargs
        return subprocess.CompletedProcess(
            command,
            returncode,
            stdout,
            stderr,
        )

    monkeypatch.setattr(
        "alt_deploy.ansible.subprocess.run",
        fake_run,
    )

    result = run_json_cli(
        ["preflight", TEST_MACHINE_UUID],
        settings=sandbox.settings,
    )

    assert result.exit_code == outcome.command_exit_code
    assert result.payload["error"]["code"] == outcome.error_code
    assert result.payload["error"]["details"]["failure_kind"] == (
        outcome.failure_kind
    )

    record = read_json(record_path)
    assert record["status"] == "preflight_failed"
    assert record["preflight"]["error"]["details"] == (
        result.payload["error"]["details"]
    )
    assert JobRepository(sandbox.settings).list() == []
    assert AssignmentRepository(sandbox.settings).get(
        TEST_MACHINE_UUID
    ) is None

    ssh_args = next(
        value
        for value in captured["command"]
        if value.startswith("--ssh-common-args=")
    )
    assert "StrictHostKeyChecking=yes" in ssh_args
    assert "ProxyCommand=none" in ssh_args
    assert "IdentitiesOnly=yes" in ssh_args
    assert "ConnectTimeout=10" in ssh_args
```

Add timeout test:

```python
def test_preflight_cli_classifies_timeout_exception(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    outcome = get_outcome("preflight-ssh-timeout")
    sandbox = make_controller_sandbox(tmp_path)
    sandbox.configure_preflight_boundary()
    record_path = sandbox.register_machine()

    def fake_run(command, **kwargs):
        raise subprocess.TimeoutExpired(command, kwargs["timeout"])

    monkeypatch.setattr(
        "alt_deploy.ansible.subprocess.run",
        fake_run,
    )

    result = run_json_cli(
        ["preflight", TEST_MACHINE_UUID],
        settings=sandbox.settings,
    )

    assert result.exit_code == 5
    assert result.payload["error"]["details"]["failure_kind"] == (
        outcome.failure_kind
    )
    assert result.payload["error"]["details"]["timeout"] == 180
    assert read_json(record_path)["status"] == "preflight_failed"
    assert JobRepository(sandbox.settings).list() == []
    assert AssignmentRepository(sandbox.settings).get(
        TEST_MACHINE_UUID
    ) is None
```

Add missing/malformed result fallback tests:

```python
@pytest.mark.parametrize("malformed", [False, True])
def test_preflight_result_failures_use_ansible_fallback(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
    malformed: bool,
) -> None:
    sandbox = make_controller_sandbox(tmp_path)
    sandbox.configure_preflight_boundary()
    record_path = sandbox.register_machine()

    def fake_run(command, **kwargs):
        if malformed:
            result_arg = next(
                value
                for value in command
                if value.startswith("preflight_result_file=")
            )
            result_path = Path(result_arg.split("=", 1)[1])
            result_path.write_text("not-json", encoding="utf-8")
        return subprocess.CompletedProcess(command, 0, "PLAY RECAP", "")

    monkeypatch.setattr(
        "alt_deploy.ansible.subprocess.run",
        fake_run,
    )

    result = run_json_cli(
        ["preflight", TEST_MACHINE_UUID],
        settings=sandbox.settings,
    )

    assert result.exit_code == 5
    assert result.payload["error"]["details"]["failure_kind"] == (
        "ansible_failed"
    )
    assert read_json(record_path)["status"] == "preflight_failed"
```

- [ ] **Step 2: Run CLI scenarios and verify RED**

```bash
.venv/bin/python -m pytest -q \
  tests/alt_linux/test_or2a_preflight_failures.py \
  -k "cli_persists or timeout_exception or result_failures"
```

Expected: FAIL because current errors do not include `details.failure_kind`.

- [ ] **Step 3: Add `failure_kind` to every owned failure branch**

Change timeout details:

```python
details={
    "failure_kind": "ssh_timeout",
    "timeout": exc.timeout,
},
```

Change non-zero result details:

```python
details={
    "failure_kind": _classify_preflight_failure(
        stdout=completed.stdout,
        stderr=completed.stderr,
    ),
    "returncode": completed.returncode,
    "stdout": _bounded(completed.stdout),
    "stderr": _bounded(completed.stderr),
},
```

Change missing-result details:

```python
details={
    "failure_kind": "ansible_failed",
    "stdout": _bounded(completed.stdout),
    "stderr": _bounded(completed.stderr),
},
```

Change invalid-result error to include:

```python
details={"failure_kind": "ansible_failed"},
```

Do not alter `preflight_not_configured` or `machine_missing_ip`.

- [ ] **Step 4: Run CLI scenarios and verify GREEN**

```bash
.venv/bin/python -m pytest -q \
  tests/alt_linux/test_or2a_preflight_failures.py \
  -k "cli_persists or timeout_exception or result_failures"
```

Expected: all selected tests pass.

- [ ] **Step 5: Commit**

```bash
git add \
  deploy/alt-linux/control/alt_deploy/ansible.py \
  tests/alt_linux/test_or2a_preflight_failures.py
git commit -m "feat: persist classified preflight failures"
```

---

### Task 6: Prove Retryability After a Classified Failure

**Files:**
- Modify: `tests/alt_linux/test_or2a_preflight_failures.py`

**Interfaces:**
- Consumes: completed OR-2A classifier and existing `MachineRepository.persist_preflight()` behavior.
- Produces: executable evidence that a failed machine can return to `awaiting_assignment` after the cause is corrected.

- [ ] **Step 1: Write the retryability test**

Append:

```python
def test_preflight_is_retryable_after_transport_failure(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    sandbox = make_controller_sandbox(tmp_path)
    sandbox.configure_preflight_boundary()
    record_path = sandbox.register_machine()
    attempts = 0

    def fake_run(command, **kwargs):
        nonlocal attempts
        attempts += 1
        if attempts == 1:
            return subprocess.CompletedProcess(
                command,
                4,
                "",
                "Connection refused",
            )

        result_arg = next(
            value
            for value in command
            if value.startswith("preflight_result_file=")
        )
        result_path = Path(result_arg.split("=", 1)[1])
        atomic_write_json(
            result_path,
            {
                "status": "ok",
                "checks": {
                    "alt_release": True,
                    "uuid": True,
                },
            },
        )
        return subprocess.CompletedProcess(
            command,
            0,
            "PLAY RECAP",
            "",
        )

    monkeypatch.setattr(
        "alt_deploy.ansible.subprocess.run",
        fake_run,
    )

    failed = run_json_cli(
        ["preflight", TEST_MACHINE_UUID],
        settings=sandbox.settings,
    )
    succeeded = run_json_cli(
        ["preflight", TEST_MACHINE_UUID],
        settings=sandbox.settings,
    )

    assert failed.exit_code == 5
    assert failed.payload["error"]["details"]["failure_kind"] == (
        "ssh_unreachable"
    )
    assert succeeded.exit_code == 0

    record = read_json(record_path)
    assert record["status"] == "awaiting_assignment"
    assert record["preflight"]["status"] == "ok"
    assert attempts == 2
    assert JobRepository(sandbox.settings).list() == []
    assert AssignmentRepository(sandbox.settings).get(
        TEST_MACHINE_UUID
    ) is None
```

- [ ] **Step 2: Run retryability test**

```bash
.venv/bin/python -m pytest -q \
  tests/alt_linux/test_or2a_preflight_failures.py::test_preflight_is_retryable_after_transport_failure
```

Expected: PASS after Task 5. A failure indicates an OR-2A defect and must be fixed before proceeding.

- [ ] **Step 3: Run the complete OR-2A module**

```bash
.venv/bin/python -m pytest -q \
  tests/alt_linux/test_or2a_preflight_failures.py
```

Expected: all OR-2A tests pass.

- [ ] **Step 4: Commit**

```bash
git add tests/alt_linux/test_or2a_preflight_failures.py
git commit -m "test: prove preflight retryability"
```

---

### Task 7: Full Verification and Pull Request

**Files:**
- Verify all OR-2A files.
- Create/update: `docs/superpowers/plans/2026-07-20-alt-or2a-verification.md` only with factual evidence.
- Temporary: `.github/workflows/or2a-verification.yml`, then delete before final diff.

**Interfaces:**
- Consumes: completed OR-2A branch.
- Produces: reviewable PR with reproducible test evidence and no temporary workflow.

- [ ] **Step 1: Verify final diff scope**

```bash
git diff --name-only origin/main...HEAD
```

Expected files only:

```text
docs/superpowers/plans/2026-07-20-alt-or2a-ssh-preflight-classification.md
docs/superpowers/specs/2026-07-20-alt-or2a-ssh-preflight-classification-design.md
deploy/alt-linux/control/alt_deploy/ansible.py
deploy/alt-linux/ansible/roles/preflight/tasks/main.yml
tests/alt_linux/support/controller_sandbox.py
tests/alt_linux/support/outcomes.py
tests/alt_linux/test_operational_reliability_contract.py
tests/alt_linux/test_or2a_preflight_failures.py
```

A verification evidence document may also be present. No Vault, key, runtime state or unrelated production file may appear.

- [ ] **Step 2: Run focused tests**

```bash
.venv/bin/python -m pytest -q \
  tests/alt_linux/test_or2a_preflight_failures.py \
  tests/alt_linux/test_operational_reliability_contract.py
```

Expected: exit code 0 with exact count recorded from output.

- [ ] **Step 3: Run ALT suite**

```bash
.venv/bin/python -m pytest -q tests/alt_linux
```

Expected: exit code 0 with exact count recorded.

- [ ] **Step 4: Run full repository suite**

```bash
.venv/bin/python -m pytest -q
```

Expected: exit code 0 with exact pass/warning count recorded.

- [ ] **Step 5: Run Ansible syntax and diff checks**

```bash
ANSIBLE_CONFIG=deploy/alt-linux/ansible/ansible.cfg \
  ansible-playbook --syntax-check \
  deploy/alt-linux/ansible/playbooks/01-preflight.yml

git diff --check origin/main...HEAD
```

Expected: both commands exit 0.

- [ ] **Step 6: Record evidence without secrets**

Create `docs/superpowers/plans/2026-07-20-alt-or2a-verification.md` containing:

```markdown
# OR-2A verification

- tested commit SHA;
- focused OR-2A pass count;
- complete `tests/alt_linux` pass count;
- full repository pass/warning count;
- Ansible syntax-check result;
- `git diff --check` result;
- statement that no real SSH, Vault, runtime controller or target VM was accessed.
```

Use actual values only. Do not write placeholders or claim PASS before commands complete.

- [ ] **Step 7: Remove temporary CI and confirm final head workflows**

Delete `.github/workflows/or2a-verification.yml`, commit the deletion/evidence update, and allow the repository's existing pull-request workflows to finish on final head.

- [ ] **Step 8: Open the PR**

PR title:

```text
feat: classify ALT preflight failures
```

PR body must state:

- compatibility: `preflight_failed` and exit code 5 unchanged;
- six new allowlisted `failure_kind` values;
- controlled sudo marker;
- registration persistence and retryability evidence;
- no jobs or assignments on failures;
- exact verification results;
- production files changed are limited to `ansible.py` and preflight role YAML;
- OR-2B remains separate.

Do not merge without explicit user authorization.
