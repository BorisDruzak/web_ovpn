# ALT Workstation Provisioning MVP Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Build the CLI-first control plane and Ansible roles that take a registered ALT Workstation K 11.2 machine from `READY` through automatic preflight to a logged, asynchronous local-employee provisioning result.

**Architecture:** A stdlib-only Python package named `alt_deploy` runs on `192.168.100.17` and exposes `workstationctl`. It reads registration JSON, invokes Ansible with strict SSH host-key checking, persists machine/job/assignment state atomically, and launches provisioning workers as transient systemd services. Ansible remains the only component that changes target workstations; the future web service on `192.168.100.30` will call this control plane through a constrained API.

**Tech Stack:** Python 3.12, pytest 8, Ansible Core 2.18, YAML, systemd, OpenSSH, ALT Workstation K 11.2, LightDM, AccountsService.

## Verified implementation update (2026-07-17)

The implementation and first physical-machine run are complete. The current
contract is authoritative in
[`docs/ALT_WORKSTATION_PROVISIONING_CONTEXT.md`](../../ALT_WORKSTATION_PROVISIONING_CONTEXT.md).

Verified differences from the original plan:

- LightDM plus AccountsService is the verified display and account stack;
- employee login validation excludes dots;
- automated direct-IP SSH uses `ProxyCommand=none`;
- the provision playbook explicitly loads Vault through `vars_files`;
- `provision start` requires root;
- successful assignment is displayed as `assigned`;
- sudo denial verification uses `LC_ALL=C` and the actual ALT denial text;
- machine `53b03180-5d78-11f0-bd95-f027db877a00` completed
  `job-20260717T112903Z-71b5afe0`, survived reboot, and passed a real Plasma
  login as the employee;
- the verified implementation baseline was `80 passed` before documentation
  regression tests were added.

## Global Constraints

- Target operating system is ALT Workstation K 11.2, KDE/Plasma, UEFI, DHCP, Btrfs.
- Controller and all Ansible secrets remain on `192.168.100.17`.
- The future web server on `192.168.100.30` receives no SSH private key, Vault file, or direct workstation SSH access.
- The employee is a local account entered manually by the operator.
- `employee_login` is lowercase ASCII and may contain only letters, digits, `_`, and `-`.
- `final_hostname` is lowercase ASCII and may contain only letters, digits, and `-`; it starts and ends with a letter or digit and is at most 63 characters.
- The only accepted profile is `standard`.
- The shared employee password is represented only by an encrypted yescrypt hash in Ansible Vault.
- No password, password hash, Vault password, private key, or license may appear in Git, request JSON, result JSON, command-line literals, or logs.
- The employee is not a member of `wheel` and has no sudo authorization.
- AccountsService marks only `ansible` as a system account, keeps `osn-admin` and the employee visible, and LightDM autologin stays disabled.
- A successful assignment blocks another normal provision request for the same UUID.
- One active provision job is allowed per machine UUID.
- All subprocess calls use argument lists and `shell=False`.
- SSH uses `/home/altserver/.ssh/known_hosts_autoinstall` with `StrictHostKeyChecking=yes` and `ProxyCommand=none`.
- The MVP does not install applications, import personal certificates, enroll a domain, reassign a workstation, or implement destructive rollback.

---

## Implementation File Map

```text
deploy/alt-linux/
├── control/
│   ├── alt_deploy/
│   │   ├── __init__.py              # package metadata
│   │   ├── config.py                # filesystem and executable settings
│   │   ├── errors.py                # stable CLI error contract
│   │   ├── jsonio.py                # atomic private JSON I/O
│   │   ├── models.py                # machine, request, job dataclasses
│   │   ├── registry.py              # pending/ready/failed machine repository
│   │   ├── ansible.py               # safe Ansible command construction/execution
│   │   ├── assignments.py           # successful assignment repository
│   │   ├── jobs.py                  # job store and bounded logs
│   │   ├── locks.py                 # controller-wide file lock
│   │   ├── provision.py             # validation and deterministic preview
│   │   ├── launcher.py              # transient systemd launcher
│   │   ├── worker.py                # asynchronous job executor
│   │   └── cli.py                   # workstationctl command parser
│   ├── workstationctl               # installed CLI wrapper
│   └── alt-provision-worker         # installed worker wrapper
├── ansible/
│   ├── ansible.cfg
│   ├── group_vars/
│   │   ├── all.yml
│   │   └── vault.yml.example
│   ├── playbooks/
│   │   ├── 01-preflight.yml
│   │   └── 02-provision-account.yml
│   └── roles/
│       ├── preflight/
│       ├── workstation_identity/
│       ├── local_employee/
│       ├── lightdm_accounts/
│       └── provision_verify/
├── api/process_pending.py            # invoke automatic preflight
├── install-control-plane.sh          # install/update controller files
└── README.md                          # operating runbook

tests/alt_linux/
├── conftest.py
├── test_jsonio.py
├── test_registry_cli.py
├── test_preflight.py
├── test_process_pending.py
├── test_jobs.py
├── test_provision_preview.py
├── test_provision_start.py
├── test_worker.py
└── test_ansible_assets.py
```

---

### Task 1: Control Package Foundation and Atomic JSON Storage

**Files:**
- Create: `deploy/alt-linux/control/alt_deploy/__init__.py`
- Create: `deploy/alt-linux/control/alt_deploy/config.py`
- Create: `deploy/alt-linux/control/alt_deploy/errors.py`
- Create: `deploy/alt-linux/control/alt_deploy/jsonio.py`
- Create: `tests/alt_linux/conftest.py`
- Create: `tests/alt_linux/test_jsonio.py`
- Create: `tests/alt_linux/test_config.py`

**Interfaces:**
- Produces: `Settings.from_env() -> Settings`
- Produces: `ControlError(code: str, message: str, exit_code: int, details: dict | None)`
- Produces: `read_json(path: Path) -> dict[str, object]`
- Produces: `atomic_write_json(path: Path, payload: Mapping[str, object], mode: int = 0o600) -> None`
- Produces: `ensure_private_dir(path: Path) -> None`

- [ ] **Step 1: Add the test import path and failing JSON/config tests**

```python
# tests/alt_linux/conftest.py
from __future__ import annotations

import sys
from pathlib import Path

CONTROL_ROOT = Path(__file__).resolve().parents[2] / "deploy" / "alt-linux" / "control"
sys.path.insert(0, str(CONTROL_ROOT))
```

```python
# tests/alt_linux/test_jsonio.py
from __future__ import annotations

import json
import stat
from pathlib import Path

from alt_deploy.jsonio import atomic_write_json, ensure_private_dir, read_json


def test_atomic_write_json_replaces_file_and_sets_private_mode(tmp_path: Path) -> None:
    destination = tmp_path / "state" / "record.json"

    atomic_write_json(destination, {"status": "queued"})
    atomic_write_json(destination, {"status": "running", "count": 2})

    assert read_json(destination) == {"status": "running", "count": 2}
    assert stat.S_IMODE(destination.stat().st_mode) == 0o600
    assert list(destination.parent.glob(".*.tmp")) == []


def test_ensure_private_dir_uses_0700(tmp_path: Path) -> None:
    destination = tmp_path / "jobs"
    ensure_private_dir(destination)
    assert stat.S_IMODE(destination.stat().st_mode) == 0o700


def test_read_json_rejects_non_object(tmp_path: Path) -> None:
    path = tmp_path / "bad.json"
    path.write_text(json.dumps(["not", "an", "object"]), encoding="utf-8")

    try:
        read_json(path)
    except ValueError as exc:
        assert "JSON object" in str(exc)
    else:
        raise AssertionError("read_json accepted a JSON array")
```

```python
# tests/alt_linux/test_config.py
from pathlib import Path

from alt_deploy.config import Settings


def test_settings_accept_environment_overrides(monkeypatch, tmp_path: Path) -> None:
    monkeypatch.setenv("ALT_DEPLOY_REGISTRATION_ROOT", str(tmp_path / "registration"))
    monkeypatch.setenv("ALT_DEPLOY_STATE_ROOT", str(tmp_path / "state"))
    monkeypatch.setenv("ALT_DEPLOY_ANSIBLE_PROJECT", str(tmp_path / "ansible"))

    settings = Settings.from_env()

    assert settings.registration_root == tmp_path / "registration"
    assert settings.jobs_dir == tmp_path / "state" / "jobs"
    assert settings.assignments_dir == tmp_path / "state" / "assignments"
    assert settings.ansible_project_dir == tmp_path / "ansible"
```

- [ ] **Step 2: Run the tests and verify imports fail**

Run:

```bash
pytest -q tests/alt_linux/test_jsonio.py tests/alt_linux/test_config.py
```

Expected: collection fails with `ModuleNotFoundError: No module named 'alt_deploy'`.

- [ ] **Step 3: Implement the package foundation**

```python
# deploy/alt-linux/control/alt_deploy/__init__.py
"""ALT workstation deployment control plane."""

__version__ = "0.1.0"
```

```python
# deploy/alt-linux/control/alt_deploy/config.py
from __future__ import annotations

import os
from dataclasses import dataclass
from pathlib import Path


@dataclass(frozen=True)
class Settings:
    registration_root: Path
    state_root: Path
    jobs_dir: Path
    assignments_dir: Path
    lock_file: Path
    ansible_project_dir: Path
    known_hosts_file: Path
    private_key_file: Path
    ansible_playbook_path: Path
    systemd_run_path: Path
    worker_path: Path
    workstationctl_path: Path

    @classmethod
    def from_env(cls) -> "Settings":
        registration_root = Path(
            os.environ.get("ALT_DEPLOY_REGISTRATION_ROOT", "/srv/alt-deploy/registration")
        )
        state_root = Path(os.environ.get("ALT_DEPLOY_STATE_ROOT", "/var/lib/alt-deploy"))
        ansible_project = Path(
            os.environ.get("ALT_DEPLOY_ANSIBLE_PROJECT", "/home/altserver/ansible")
        )
        return cls(
            registration_root=registration_root,
            state_root=state_root,
            jobs_dir=state_root / "jobs",
            assignments_dir=state_root / "assignments",
            lock_file=state_root / "workstationctl.lock",
            ansible_project_dir=ansible_project,
            known_hosts_file=Path(
                os.environ.get(
                    "ALT_DEPLOY_KNOWN_HOSTS",
                    "/home/altserver/.ssh/known_hosts_autoinstall",
                )
            ),
            private_key_file=Path(
                os.environ.get("ALT_DEPLOY_PRIVATE_KEY", "/home/altserver/.ssh/id_ed25519")
            ),
            ansible_playbook_path=Path(
                os.environ.get("ALT_DEPLOY_ANSIBLE_PLAYBOOK", "/usr/bin/ansible-playbook")
            ),
            systemd_run_path=Path(
                os.environ.get("ALT_DEPLOY_SYSTEMD_RUN", "/usr/bin/systemd-run")
            ),
            worker_path=Path(
                os.environ.get(
                    "ALT_DEPLOY_WORKER", "/usr/local/libexec/alt-provision-worker"
                )
            ),
            workstationctl_path=Path(
                os.environ.get("ALT_DEPLOY_WORKSTATIONCTL", "/usr/local/sbin/workstationctl")
            ),
        )
```

```python
# deploy/alt-linux/control/alt_deploy/errors.py
from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any


@dataclass
class ControlError(Exception):
    code: str
    message: str
    exit_code: int = 1
    details: dict[str, Any] = field(default_factory=dict)

    def __str__(self) -> str:
        return self.message

    def to_dict(self) -> dict[str, Any]:
        payload: dict[str, Any] = {
            "status": "error",
            "error": {"code": self.code, "message": self.message},
        }
        if self.details:
            payload["error"]["details"] = self.details
        return payload
```

```python
# deploy/alt-linux/control/alt_deploy/jsonio.py
from __future__ import annotations

import json
import os
from collections.abc import Mapping
from pathlib import Path
from typing import Any


def ensure_private_dir(path: Path) -> None:
    path.mkdir(parents=True, exist_ok=True)
    os.chmod(path, 0o700)


def read_json(path: Path) -> dict[str, Any]:
    payload = json.loads(path.read_text(encoding="utf-8"))
    if not isinstance(payload, dict):
        raise ValueError(f"Expected JSON object in {path}")
    return payload


def atomic_write_json(
    path: Path,
    payload: Mapping[str, object],
    mode: int = 0o600,
) -> None:
    ensure_private_dir(path.parent)
    temporary = path.parent / f".{path.name}.{os.getpid()}.tmp"
    try:
        temporary.write_text(
            json.dumps(dict(payload), ensure_ascii=False, indent=2) + "\n",
            encoding="utf-8",
        )
        os.chmod(temporary, mode)
        os.replace(temporary, path)
    finally:
        temporary.unlink(missing_ok=True)
```

- [ ] **Step 4: Run the focused tests**

Run:

```bash
pytest -q tests/alt_linux/test_jsonio.py tests/alt_linux/test_config.py
```

Expected: `4 passed`.

- [ ] **Step 5: Commit the foundation**

```bash
git add deploy/alt-linux/control/alt_deploy tests/alt_linux
git commit -m "feat: add ALT deployment control foundation"
```

---

### Task 2: Machine Repository and `machines list/show`

**Files:**
- Create: `deploy/alt-linux/control/alt_deploy/models.py`
- Create: `deploy/alt-linux/control/alt_deploy/registry.py`
- Create: `deploy/alt-linux/control/alt_deploy/cli.py`
- Create: `deploy/alt-linux/control/workstationctl`
- Create: `tests/alt_linux/test_registry_cli.py`

**Interfaces:**
- Consumes: `Settings`, `ControlError`, `read_json`
- Produces: `MachineRecord.to_public_dict() -> dict[str, object]`
- Produces: `MachineRepository.list() -> list[MachineRecord]`
- Produces: `MachineRepository.get(machine_uuid: str) -> MachineRecord`
- Produces: `cli.main(argv, settings, stdout, stderr) -> int`

- [ ] **Step 1: Write failing repository and CLI tests**

```python
# tests/alt_linux/test_registry_cli.py
from __future__ import annotations

import io
import json
from pathlib import Path

from alt_deploy.cli import main
from alt_deploy.config import Settings
from alt_deploy.jsonio import atomic_write_json
from alt_deploy.registry import MachineRepository


def make_settings(tmp_path: Path) -> Settings:
    registration = tmp_path / "registration"
    state = tmp_path / "state"
    return Settings(
        registration_root=registration,
        state_root=state,
        jobs_dir=state / "jobs",
        assignments_dir=state / "assignments",
        lock_file=state / "workstationctl.lock",
        ansible_project_dir=tmp_path / "ansible",
        known_hosts_file=tmp_path / "known_hosts",
        private_key_file=tmp_path / "id_ed25519",
        ansible_playbook_path=Path("/usr/bin/ansible-playbook"),
        systemd_run_path=Path("/usr/bin/systemd-run"),
        worker_path=Path("/usr/local/libexec/alt-provision-worker"),
        workstationctl_path=Path("/usr/local/sbin/workstationctl"),
    )


def write_machine(settings: Settings, state: str, registered_at: str) -> None:
    atomic_write_json(
        settings.registration_root / state / "53b03180-5d78-11f0-bd95-f027db877a00.json",
        {
            "machine_key": "53b03180-5d78-11f0-bd95-f027db877a00",
            "uuid": "53b03180-5d78-11f0-bd95-f027db877a00",
            "hostname": "alt-auto-test",
            "ip": "192.168.101.56",
            "mac": "c0:9b:f4:62:54:e5",
            "registered_at": registered_at,
            "status": state,
        },
    )


def test_repository_prefers_newest_duplicate_record(tmp_path: Path) -> None:
    settings = make_settings(tmp_path)
    write_machine(settings, "ready", "2026-07-16T07:00:00+00:00")
    write_machine(settings, "pending", "2026-07-16T08:00:00+00:00")

    machines = MachineRepository(settings).list()

    assert len(machines) == 1
    assert machines[0].registration_state == "pending"


def test_machines_list_emits_json(tmp_path: Path) -> None:
    settings = make_settings(tmp_path)
    write_machine(settings, "ready", "2026-07-16T08:00:00+00:00")
    stdout = io.StringIO()
    stderr = io.StringIO()

    rc = main(["--json", "machines", "list"], settings=settings, stdout=stdout, stderr=stderr)

    assert rc == 0
    payload = json.loads(stdout.getvalue())
    assert payload["status"] == "ok"
    assert payload["machines"][0]["uuid"] == "53b03180-5d78-11f0-bd95-f027db877a00"
    assert payload["machines"][0]["ip"] == "192.168.101.56"


def test_machines_show_returns_not_found_error(tmp_path: Path) -> None:
    settings = make_settings(tmp_path)
    stdout = io.StringIO()

    rc = main(
        ["--json", "machines", "show", "00000000-0000-0000-0000-000000000000"],
        settings=settings,
        stdout=stdout,
        stderr=io.StringIO(),
    )

    assert rc == 3
    payload = json.loads(stdout.getvalue())
    assert payload["error"]["code"] == "machine_not_found"
```

- [ ] **Step 2: Verify the tests fail**

Run:

```bash
pytest -q tests/alt_linux/test_registry_cli.py
```

Expected: import failure for `alt_deploy.cli` or `alt_deploy.registry`.

- [ ] **Step 3: Implement machine parsing, deduplication, and CLI output**

Implement `MachineRecord` as an immutable dataclass with these fields:

```python
# deploy/alt-linux/control/alt_deploy/models.py
from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path
from typing import Any


@dataclass(frozen=True)
class MachineRecord:
    machine_key: str
    uuid: str
    hostname: str
    ip: str
    mac: str
    registered_at: str
    registration_state: str
    status: str
    record_path: Path
    raw: dict[str, Any]

    @classmethod
    def from_mapping(
        cls,
        payload: dict[str, Any],
        *,
        registration_state: str,
        record_path: Path,
    ) -> "MachineRecord":
        machine_key = str(payload.get("machine_key") or "").lower()
        machine_uuid = str(payload.get("uuid") or machine_key).lower()
        if not machine_key or not machine_uuid:
            raise ValueError(f"Machine identity missing in {record_path}")
        return cls(
            machine_key=machine_key,
            uuid=machine_uuid,
            hostname=str(payload.get("hostname") or ""),
            ip=str(payload.get("ip") or ""),
            mac=str(payload.get("mac") or "").lower(),
            registered_at=str(payload.get("registered_at") or ""),
            registration_state=registration_state,
            status=str(payload.get("status") or registration_state),
            record_path=record_path,
            raw=dict(payload),
        )

    def to_public_dict(self) -> dict[str, Any]:
        return {
            "machine_key": self.machine_key,
            "uuid": self.uuid,
            "hostname": self.hostname,
            "ip": self.ip,
            "mac": self.mac,
            "registered_at": self.registered_at,
            "registration_state": self.registration_state,
            "status": self.status,
            "preflight": self.raw.get("preflight"),
            "assignment": None,
            "active_job": None,
        }
```

Implement `MachineRepository` so it scans `pending`, `ready`, and `failed`, ignores dotfiles, skips malformed JSON with a diagnostic exception only when directly requested, and deduplicates by newest ISO timestamp:

```python
# deploy/alt-linux/control/alt_deploy/registry.py
from __future__ import annotations

from datetime import datetime
from pathlib import Path

from .config import Settings
from .errors import ControlError
from .jsonio import read_json
from .models import MachineRecord


class MachineRepository:
    def __init__(self, settings: Settings):
        self.settings = settings

    @staticmethod
    def _sort_key(record: MachineRecord) -> tuple[datetime, int]:
        try:
            timestamp = datetime.fromisoformat(record.registered_at)
        except ValueError:
            timestamp = datetime.min
        precedence = {"failed": 0, "ready": 1, "pending": 2}[record.registration_state]
        return timestamp, precedence

    def list(self) -> list[MachineRecord]:
        selected: dict[str, MachineRecord] = {}
        for state in ("pending", "ready", "failed"):
            directory = self.settings.registration_root / state
            if not directory.exists():
                continue
            for path in sorted(directory.glob("*.json")):
                try:
                    record = MachineRecord.from_mapping(
                        read_json(path), registration_state=state, record_path=path
                    )
                except (OSError, ValueError):
                    continue
                current = selected.get(record.machine_key)
                if current is None or self._sort_key(record) > self._sort_key(current):
                    selected[record.machine_key] = record
        return sorted(selected.values(), key=lambda item: (item.hostname, item.machine_key))

    def get(self, machine_uuid: str) -> MachineRecord:
        normalized = machine_uuid.strip().lower()
        for record in self.list():
            if record.uuid == normalized or record.machine_key == normalized:
                return record
        raise ControlError(
            "machine_not_found",
            f"Machine not found: {normalized}",
            exit_code=3,
            details={"machine_uuid": normalized},
        )
```

Implement `cli.py` with an injectable `Settings` and streams. The JSON success contract is `{"status":"ok", ...}`; a `ControlError` is serialized with `to_dict()` and returns its `exit_code`.

```python
# deploy/alt-linux/control/alt_deploy/cli.py
from __future__ import annotations

import argparse
import json
import sys
from collections.abc import Sequence
from typing import TextIO

from .config import Settings
from .errors import ControlError
from .registry import MachineRepository


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="workstationctl")
    parser.add_argument("--json", action="store_true", dest="as_json")
    commands = parser.add_subparsers(dest="command", required=True)
    machines = commands.add_parser("machines")
    machine_commands = machines.add_subparsers(dest="machine_command", required=True)
    machine_commands.add_parser("list")
    show = machine_commands.add_parser("show")
    show.add_argument("machine_uuid")
    return parser


def _write_json(stream: TextIO, payload: dict[str, object]) -> None:
    stream.write(json.dumps(payload, ensure_ascii=False, indent=2) + "\n")


def main(
    argv: Sequence[str] | None = None,
    *,
    settings: Settings | None = None,
    stdout: TextIO = sys.stdout,
    stderr: TextIO = sys.stderr,
) -> int:
    parsed = build_parser().parse_args(list(argv) if argv is not None else None)
    active_settings = settings or Settings.from_env()
    repository = MachineRepository(active_settings)
    try:
        if parsed.command == "machines" and parsed.machine_command == "list":
            payload = {"status": "ok", "machines": [m.to_public_dict() for m in repository.list()]}
        elif parsed.command == "machines" and parsed.machine_command == "show":
            payload = {"status": "ok", "machine": repository.get(parsed.machine_uuid).to_public_dict()}
        else:
            raise ControlError("unsupported_command", "Unsupported command", exit_code=2)
    except ControlError as exc:
        if parsed.as_json:
            _write_json(stdout, exc.to_dict())
        else:
            stderr.write(f"ERROR [{exc.code}]: {exc.message}\n")
        return exc.exit_code

    if parsed.as_json:
        _write_json(stdout, payload)
    else:
        stdout.write(json.dumps(payload, ensure_ascii=False, indent=2) + "\n")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
```

```python
#!/usr/bin/python3
# deploy/alt-linux/control/workstationctl
from __future__ import annotations

import sys
from pathlib import Path

PACKAGE_ROOT = Path("/opt/alt-deploy-control")
sys.path.insert(0, str(PACKAGE_ROOT))

from alt_deploy.cli import main

raise SystemExit(main())
```

- [ ] **Step 4: Run repository and CLI tests**

Run:

```bash
pytest -q tests/alt_linux/test_registry_cli.py
```

Expected: `3 passed`.

- [ ] **Step 5: Commit machine discovery**

```bash
git add deploy/alt-linux/control tests/alt_linux/test_registry_cli.py
git commit -m "feat: add workstation machine discovery CLI"
```

---

### Task 3: Non-Mutating Ansible Preflight and CLI Persistence

**Files:**
- Create: `deploy/alt-linux/control/alt_deploy/ansible.py`
- Modify: `deploy/alt-linux/control/alt_deploy/registry.py`
- Modify: `deploy/alt-linux/control/alt_deploy/cli.py`
- Create: `deploy/alt-linux/ansible/ansible.cfg`
- Create: `deploy/alt-linux/ansible/group_vars/all.yml`
- Create: `deploy/alt-linux/ansible/playbooks/01-preflight.yml`
- Create: `deploy/alt-linux/ansible/roles/preflight/defaults/main.yml`
- Create: `deploy/alt-linux/ansible/roles/preflight/tasks/main.yml`
- Create: `tests/alt_linux/test_preflight.py`

**Interfaces:**
- Produces: `AnsibleController.run_preflight(machine, employee_login="") -> dict[str, object]`
- Produces: `MachineRepository.persist_preflight(machine, payload, succeeded) -> MachineRecord`
- Adds CLI: `workstationctl --json preflight <uuid>`

- [ ] **Step 1: Write failing command-construction and persistence tests**

```python
# tests/alt_linux/test_preflight.py
from __future__ import annotations

import io
import json
import subprocess
from pathlib import Path

from alt_deploy.ansible import AnsibleController
from alt_deploy.cli import main
from alt_deploy.jsonio import atomic_write_json, read_json
from test_registry_cli import make_settings, write_machine


def test_preflight_uses_inline_inventory_and_strict_known_hosts(tmp_path: Path) -> None:
    settings = make_settings(tmp_path)
    settings.private_key_file.write_text("private", encoding="utf-8")
    settings.known_hosts_file.write_text("host key", encoding="utf-8")
    settings.ansible_project_dir.mkdir(parents=True)
    captured: list[list[str]] = []

    def fake_run(command: list[str], timeout: int) -> subprocess.CompletedProcess[str]:
        captured.append(command)
        result_arg = next(value for value in command if value.startswith("preflight_result_file="))
        result_path = Path(result_arg.split("=", 1)[1])
        atomic_write_json(result_path, {"status": "ok", "checks": {"alt_release": True}})
        return subprocess.CompletedProcess(command, 0, "PLAY RECAP ok=10", "")

    write_machine(settings, "ready", "2026-07-16T08:00:00+00:00")
    machine = __import__("alt_deploy.registry", fromlist=["MachineRepository"]).MachineRepository(settings).list()[0]

    result = AnsibleController(settings, runner=fake_run).run_preflight(machine)

    command = captured[0]
    assert f"{machine.ip}," in command
    assert f"--private-key={settings.private_key_file}" in command
    assert any("StrictHostKeyChecking=yes" in value for value in command)
    assert result["status"] == "ok"


def test_preflight_cli_persists_success(tmp_path: Path, monkeypatch) -> None:
    settings = make_settings(tmp_path)
    write_machine(settings, "ready", "2026-07-16T08:00:00+00:00")

    monkeypatch.setattr(
        "alt_deploy.cli.AnsibleController.run_preflight",
        lambda self, machine, employee_login="": {"status": "ok", "checks": {"uuid": True}},
    )
    stdout = io.StringIO()

    rc = main(
        ["--json", "preflight", "53b03180-5d78-11f0-bd95-f027db877a00"],
        settings=settings,
        stdout=stdout,
        stderr=io.StringIO(),
    )

    assert rc == 0
    record = read_json(settings.registration_root / "ready" / "53b03180-5d78-11f0-bd95-f027db877a00.json")
    assert record["status"] == "awaiting_assignment"
    assert record["preflight"]["status"] == "ok"
    assert json.loads(stdout.getvalue())["preflight"]["checks"]["uuid"] is True
```

- [ ] **Step 2: Verify the tests fail**

Run:

```bash
pytest -q tests/alt_linux/test_preflight.py
```

Expected: import failure for `alt_deploy.ansible`.

- [ ] **Step 3: Implement the safe Ansible controller and preflight persistence**

`AnsibleController` must:

1. Validate that the private key, known-hosts file, playbook, and `/usr/bin/ansible-playbook` exist.
2. Create a private temporary directory.
3. Build this argument-list shape without a shell:

```python
[
    "/usr/bin/ansible-playbook",
    "-i", "192.168.101.56,",
    "-u", "ansible",
    "--private-key=/home/altserver/.ssh/id_ed25519",
    "--ssh-common-args=-o UserKnownHostsFile=/home/altserver/.ssh/known_hosts_autoinstall -o StrictHostKeyChecking=yes -o IdentitiesOnly=yes -o ConnectTimeout=10 -o ProxyCommand=none",
    "-e", "ansible_python_interpreter=/usr/bin/python3",
    "-e", "machine_uuid=53b03180-5d78-11f0-bd95-f027db877a00",
    "-e", "preflight_employee_login=",
    "-e", "preflight_result_file=/private/temp/result.json",
    "/home/altserver/ansible/playbooks/01-preflight.yml",
]
```

4. Use `subprocess.run(command, shell=False, text=True, capture_output=True, timeout=180, check=False)`.
5. Raise `ControlError("preflight_failed", ..., exit_code=5)` with bounded stdout/stderr if Ansible fails or the result file is absent.
6. Return the parsed result object when successful.

Add this persistence method to `MachineRepository`:

```python
def persist_preflight(
    self,
    machine: MachineRecord,
    payload: dict[str, object],
    *,
    succeeded: bool,
) -> MachineRecord:
    from datetime import datetime, timezone
    from .jsonio import atomic_write_json

    record = dict(machine.raw)
    record["preflight"] = dict(payload)
    record["preflight_checked_at"] = datetime.now(timezone.utc).isoformat()
    record["status"] = "awaiting_assignment" if succeeded else "preflight_failed"
    atomic_write_json(machine.record_path, record)
    return MachineRecord.from_mapping(
        record,
        registration_state=machine.registration_state,
        record_path=machine.record_path,
    )
```

Extend `cli.py` with a top-level `preflight` parser accepting `machine_uuid`; instantiate `AnsibleController`, run the check, persist it, and emit:

```json
{
  "status": "ok",
  "machine_uuid": "53b03180-5d78-11f0-bd95-f027db877a00",
  "preflight": {
    "status": "ok",
    "checks": {}
  }
}
```

- [ ] **Step 4: Add the read-only Ansible preflight assets**

```ini
# deploy/alt-linux/ansible/ansible.cfg
[defaults]
host_key_checking = True
retry_files_enabled = False
stdout_callback = default
interpreter_python = /usr/bin/python3
vault_password_file = /home/altserver/.ansible-vault-pass

[ssh_connection]
pipelining = True
```

```yaml
# deploy/alt-linux/ansible/group_vars/all.yml
ansible_python_interpreter: /usr/bin/python3
preflight_min_home_bytes: 2147483648
```

```yaml
# deploy/alt-linux/ansible/playbooks/01-preflight.yml
---
- name: Validate registered ALT workstation
  hosts: all
  gather_facts: true
  become: true
  roles:
    - role: preflight
```

```yaml
# deploy/alt-linux/ansible/roles/preflight/defaults/main.yml
---
preflight_employee_login: ""
preflight_result_file: ""
preflight_min_home_bytes: 2147483648
```

Create `roles/preflight/tasks/main.yml` with only read/assert operations on the target. It must:

- slurp `/etc/altlinux-release` and assert it starts with `ALT Workstation K 11.`;
- read `/sys/class/dmi/id/product_uuid` and compare lowercase UUIDs;
- verify `ansible` and `osn-admin` with `getent passwd`;
- run `sudo -n true` with `become: false` to prove the SSH account retains passwordless sudo;
- verify the LightDM and AccountsService packages, active `accounts-daemon`, and the active LightDM display-manager service;
- choose `/home` from `ansible_mounts`, falling back to `/`, and assert at least `2147483648` available bytes;
- conditionally run `getent passwd <preflight_employee_login>` only when a login was supplied;
- build `preflight_payload` containing `status`, release, UUID, static hostname, available bytes, and boolean check values;
- delegate one `ansible.builtin.copy` task to localhost to write `preflight_result_file` with mode `0600`.

The final delegated task must be exactly guarded by:

```yaml
when: preflight_result_file | length > 0
delegate_to: localhost
become: false
run_once: true
```

- [ ] **Step 5: Run tests and Ansible syntax validation**

Run in the repository:

```bash
pytest -q tests/alt_linux/test_preflight.py
```

Run on the deployment server after copying the Ansible tree:

```bash
cd /home/altserver/ansible
ansible-playbook --syntax-check playbooks/01-preflight.yml
```

Expected: tests pass and syntax check reports `playbook: playbooks/01-preflight.yml`.

- [ ] **Step 6: Commit preflight**

```bash
git add deploy/alt-linux/control deploy/alt-linux/ansible tests/alt_linux/test_preflight.py
git commit -m "feat: add workstation preflight control"
```

---

### Task 4: Automatic Preflight After Registration

**Files:**
- Modify: `deploy/alt-linux/api/process_pending.py`
- Create: `tests/alt_linux/test_process_pending.py`

**Interfaces:**
- Consumes: installed `workstationctl --json preflight <uuid>`
- Changes successful registration state from `ready` to `awaiting_assignment`
- Persists failed preflight details in the existing `failed` registration directory

- [ ] **Step 1: Write a failing process-pending test**

Load `process_pending.py` with `importlib.util.spec_from_file_location`, replace its `PENDING_DIR`, `READY_DIR`, `FAILED_DIR`, `KNOWN_HOSTS`, and `PRIVATE_KEY` with `tmp_path` locations, and monkeypatch `wait_for_ssh` and `run_command`.

The fake command runner must return:

- successful `ssh-keygen` and `ssh-keyscan` results;
- successful `ansible.builtin.ping` output;
- successful `workstationctl --json preflight` output:

```json
{
  "status": "ok",
  "machine_uuid": "53b03180-5d78-11f0-bd95-f027db877a00",
  "preflight": {"status": "ok", "checks": {"uuid": true}}
}
```

Assert that the final ready record contains:

```python
assert record["status"] == "awaiting_assignment"
assert record["preflight"]["checks"]["uuid"] is True
```

Add a second test where workstationctl returns exit code `5`; assert the record moves to `failed` and `error` contains `Automatic preflight failed`.

- [ ] **Step 2: Run the test and confirm current behavior fails**

```bash
pytest -q tests/alt_linux/test_process_pending.py
```

Expected: the success record still has `status == "ready"` and no preflight payload.

- [ ] **Step 3: Add the automatic preflight invocation**

In `process_pending.py`, define:

```python
WORKSTATIONCTL = os.environ.get("ALT_DEPLOY_WORKSTATIONCTL", "/usr/local/sbin/workstationctl")
```

After successful Ansible ping and before moving the record to `READY_DIR`, execute:

```python
preflight = run_command(
    [WORKSTATIONCTL, "--json", "preflight", machine_key],
    timeout=240,
)
if preflight.returncode != 0:
    raise RuntimeError(
        "Automatic preflight failed:\n"
        + preflight.stdout[-10000:]
        + "\n"
        + preflight.stderr[-10000:]
    )
try:
    preflight_payload = json.loads(preflight.stdout)
except json.JSONDecodeError as exc:
    raise RuntimeError("Automatic preflight returned invalid JSON") from exc
if preflight_payload.get("status") != "ok":
    raise RuntimeError("Automatic preflight did not return status=ok")
```

Then store:

```python
record["status"] = "awaiting_assignment"
record["preflight"] = preflight_payload["preflight"]
record["preflight_verified_at"] = utc_now()
```

Do not change the isolated known-hosts behavior or disable strict checking.

- [ ] **Step 4: Run tests**

```bash
pytest -q tests/alt_linux/test_process_pending.py
```

Expected: both success and failure tests pass.

- [ ] **Step 5: Commit automatic preflight**

```bash
git add deploy/alt-linux/api/process_pending.py tests/alt_linux/test_process_pending.py
git commit -m "feat: run preflight after workstation registration"
```

---

### Task 5: Private Job, Assignment, and Lock Repositories

**Files:**
- Create: `deploy/alt-linux/control/alt_deploy/locks.py`
- Create: `deploy/alt-linux/control/alt_deploy/jobs.py`
- Create: `deploy/alt-linux/control/alt_deploy/assignments.py`
- Modify: `deploy/alt-linux/control/alt_deploy/models.py`
- Modify: `deploy/alt-linux/control/alt_deploy/registry.py`
- Create: `tests/alt_linux/test_jobs.py`

**Interfaces:**
- Produces: `exclusive_lock(path: Path)` context manager
- Produces: `JobRepository.create(request) -> JobRecord`
- Produces: `JobRepository.update(job_id, **fields) -> JobRecord`
- Produces: `JobRepository.active_for_machine(uuid) -> JobRecord | None`
- Produces: `JobRepository.read_log(job_id, max_bytes=2_000_000) -> dict`
- Produces: `AssignmentRepository.get(uuid) -> dict | None`
- Produces: `AssignmentRepository.write(uuid, payload) -> None`

- [ ] **Step 1: Write failing persistence and concurrency tests**

Cover these behaviors in `tests/alt_linux/test_jobs.py`:

1. `create()` makes a `0700` job directory with private `request.json` and `status.json`.
2. Generated IDs match `job-YYYYMMDDTHHMMSSZ-xxxxxxxx`.
3. `update()` preserves immutable job ID and machine UUID.
4. `active_for_machine()` recognizes only `queued` and `running`.
5. `read_log()` returns the last 2,000,000 bytes and sets `truncated=true` when the file is larger.
6. `AssignmentRepository.write()` rejects a payload containing any key whose lowercase name contains `password`, `secret`, `token`, `private_key`, or `vault`.
7. `exclusive_lock()` prevents a second nonblocking acquisition in the same test process through a child process.

- [ ] **Step 2: Verify tests fail**

```bash
pytest -q tests/alt_linux/test_jobs.py
```

Expected: imports fail for `alt_deploy.jobs`, `alt_deploy.assignments`, and `alt_deploy.locks`.

- [ ] **Step 3: Implement lock and repositories**

Use `fcntl.flock(file_descriptor, fcntl.LOCK_EX)` in `exclusive_lock`; create the parent directory privately before opening the lock file.

Define `JobRecord` in `models.py` with:

```python
@dataclass(frozen=True)
class JobRecord:
    job_id: str
    machine_uuid: str
    state: str
    stage: str
    created_at: str
    updated_at: str
    job_dir: Path
    request: dict[str, Any]
    status: dict[str, Any]
```

`JobRepository.create()` must:

- generate the ID with UTC time plus `secrets.token_hex(4)`;
- create `request.json` with only the validated operator fields;
- create `status.json` containing `queued`, `stage=created`, and timestamps;
- create an empty `ansible.log` with mode `0600`;
- never accept a request object containing a password-like key.

`AssignmentRepository.write()` must atomically create:

```text
/var/lib/alt-deploy/assignments/<uuid>.json
```

and refuse to overwrite an existing successful assignment with different content.

Extend `MachineRecord.to_public_dict()` through `MachineRepository` enrichment so `machines list/show` includes the matching assignment and active job when present.

- [ ] **Step 4: Run persistence tests and earlier CLI regression tests**

```bash
pytest -q tests/alt_linux/test_jobs.py tests/alt_linux/test_registry_cli.py
```

Expected: all tests pass.

- [ ] **Step 5: Commit persistence**

```bash
git add deploy/alt-linux/control/alt_deploy tests/alt_linux/test_jobs.py
git commit -m "feat: add provision job and assignment stores"
```

---

### Task 6: Provision Request Validation and Deterministic Preview

**Files:**
- Create: `deploy/alt-linux/control/alt_deploy/provision.py`
- Modify: `deploy/alt-linux/control/alt_deploy/models.py`
- Modify: `deploy/alt-linux/control/alt_deploy/cli.py`
- Create: `tests/alt_linux/test_provision_preview.py`

**Interfaces:**
- Produces: `ProvisionRequest.from_mapping(payload, expected_uuid) -> ProvisionRequest`
- Produces: `ProvisionPlanner.preview(machine_uuid, request) -> dict[str, object]`
- Adds CLI: `workstationctl --json provision preview <uuid> --vars-file <file>`

- [ ] **Step 1: Write table-driven failing validation tests**

Use `pytest.mark.parametrize` for these rejected inputs and exact error codes:

```text
employee_login="Root"                 -> invalid_employee_login
employee_login="ansible"              -> protected_employee_login
employee_login="ivanov@local"         -> invalid_employee_login
employee_full_name=""                  -> invalid_employee_full_name
final_hostname="-buh-01"               -> invalid_hostname
final_hostname="buh_01"                -> invalid_hostname
profile="crypto"                       -> invalid_profile
unknown field "employee_password"      -> unknown_request_fields
machine_uuid differs from CLI argument  -> machine_uuid_mismatch
```

Add success assertions that normalization produces lowercase login/hostname and the preview action list is exactly:

```json
[
  "validate_registered_machine",
  "run_preflight",
  "set_final_hostname",
  "create_or_reconcile_local_employee",
  "remove_employee_admin_rights",
  "hide_ansible_from_lightdm",
  "keep_employee_visible_in_lightdm",
  "disable_lightdm_autologin",
  "verify_provisioning",
  "write_assignment_records"
]
```

Add conflict tests for existing assignment, active job, duplicate assigned hostname, and duplicate assigned employee login.

- [ ] **Step 2: Run tests and verify failure**

```bash
pytest -q tests/alt_linux/test_provision_preview.py
```

Expected: import failure for `ProvisionPlanner`.

- [ ] **Step 3: Implement strict request parsing and preview**

`ProvisionRequest` must accept exactly these keys:

```python
{
    "machine_uuid",
    "employee_login",
    "employee_full_name",
    "final_hostname",
    "profile",
}
```

Use these regular expressions:

```python
LOGIN_RE = re.compile(r"^[a-z0-9](?:[a-z0-9_-]{0,30}[a-z0-9])?$")
HOSTNAME_RE = re.compile(r"^[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?$")
```

Reject `root`, `ansible`, and `osn-admin` as protected logins. Reject control characters and full names longer than 200 Unicode characters.

`ProvisionPlanner.preview()` must run under `exclusive_lock(settings.lock_file)` and perform all conflict checks before returning:

```json
{
  "status": "ok",
  "machine_uuid": "...",
  "request": {
    "machine_uuid": "...",
    "employee_login": "i-ivanov",
    "employee_full_name": "Иванов Иван Иванович",
    "final_hostname": "buh-023",
    "profile": "standard"
  },
  "actions": [],
  "secrets_required": ["vault_employee_password_hash"]
}
```

The preview must check that `/home/altserver/ansible/group_vars/vault.yml` and `/home/altserver/.ansible-vault-pass` exist, but must not read or return their contents.

- [ ] **Step 4: Add the CLI parser and run tests**

Add `provision preview`, requiring `--vars-file`. Read the file with `read_json`, parse it through `ProvisionRequest`, then call `ProvisionPlanner.preview()`.

Run:

```bash
pytest -q tests/alt_linux/test_provision_preview.py
```

Expected: all validation and conflict tests pass.

- [ ] **Step 5: Commit preview**

```bash
git add deploy/alt-linux/control/alt_deploy tests/alt_linux/test_provision_preview.py
git commit -m "feat: add workstation provision preview"
```

---

### Task 7: Provision Start, Transient systemd Unit, and Job CLI

**Files:**
- Create: `deploy/alt-linux/control/alt_deploy/launcher.py`
- Modify: `deploy/alt-linux/control/alt_deploy/provision.py`
- Modify: `deploy/alt-linux/control/alt_deploy/cli.py`
- Create: `tests/alt_linux/test_provision_start.py`

**Interfaces:**
- Produces: `SystemdLauncher.launch(job_id: str) -> str`
- Produces: `ProvisionPlanner.start(machine_uuid, request) -> JobRecord`
- Adds CLI: `provision start`, `jobs status`, `jobs log`

- [ ] **Step 1: Write failing launcher/start/job CLI tests**

Assert the launcher calls exactly one argument-list command beginning with:

```python
[
    "/usr/bin/systemd-run",
    "--unit=alt-provision-job-20260716T121530Z-a1b2c3d4",
    "--description=ALT workstation provision job-20260716T121530Z-a1b2c3d4",
    "--uid=altserver",
    "--gid=altserver",
    "--working-directory=/home/altserver/ansible",
    "--property=Type=exec",
    "--property=NoNewPrivileges=yes",
    "--property=PrivateTmp=yes",
    "--collect",
    "/usr/local/libexec/alt-provision-worker",
    "--job-id",
    "job-20260716T121530Z-a1b2c3d4",
]
```

Assert `shell=False`, `check=False`, and a 30-second timeout.

Test that `provision start`:

- repeats preview validation under the lock;
- creates the job before launching;
- returns immediately with `state=queued` and a job ID;
- marks the job `failed` with stage `launch` if systemd-run fails;
- rejects a second active job for the same machine.

Test that `jobs status` returns `status.json`, and `jobs log` returns `log`, `truncated`, and current job state.

- [ ] **Step 2: Run tests and verify failure**

```bash
pytest -q tests/alt_linux/test_provision_start.py
```

Expected: import failure for `alt_deploy.launcher` or unsupported CLI commands.

- [ ] **Step 3: Implement transient launch and start transaction**

`SystemdLauncher.launch()` uses `subprocess.run` with the exact command shape above. On nonzero return it raises:

```python
ControlError(
    "job_launch_failed",
    "Unable to launch transient provision service",
    exit_code=6,
    details={"stderr": completed.stderr[-4000:]},
)
```

`ProvisionPlanner.start()` must:

1. Acquire `exclusive_lock`.
2. Repeat every preview validation.
3. Create the job.
4. Launch the transient unit.
5. Save `systemd_unit` to `status.json`.
6. Return the queued job.

If launch fails, persist `state=failed`, `stage=launch`, `finished_at`, and the bounded error before re-raising.

Require effective UID 0 only for `provision start`; list/show/preflight/preview/status/log remain usable by `altserver` when filesystem permissions allow them.

- [ ] **Step 4: Add job CLI commands and run tests**

CLI commands:

```text
workstationctl --json provision start <uuid> --vars-file <file>
workstationctl --json jobs status <job_id>
workstationctl --json jobs log <job_id>
```

Success response from `provision start`:

```json
{
  "status": "ok",
  "job": {
    "job_id": "job-...",
    "machine_uuid": "...",
    "state": "queued",
    "stage": "created",
    "systemd_unit": "alt-provision-job-....service"
  }
}
```

Run:

```bash
pytest -q tests/alt_linux/test_provision_start.py
```

Expected: all tests pass.

- [ ] **Step 5: Commit start and job inspection**

```bash
git add deploy/alt-linux/control/alt_deploy tests/alt_linux/test_provision_start.py
git commit -m "feat: launch logged workstation provision jobs"
```

---

### Task 8: Asynchronous Worker and Assignment Finalization

**Files:**
- Create: `deploy/alt-linux/control/alt_deploy/worker.py`
- Create: `deploy/alt-linux/control/alt-provision-worker`
- Modify: `deploy/alt-linux/control/alt_deploy/ansible.py`
- Create: `tests/alt_linux/test_worker.py`

**Interfaces:**
- Produces: `AnsibleController.run_provision(job, log_stream) -> dict[str, object]`
- Produces: `worker.run_job(job_id, settings, controller) -> int`
- The worker is the only component that transitions `queued -> running -> successful|failed`

- [ ] **Step 1: Write failing worker lifecycle tests**

Create a queued job fixture and fake Ansible controller.

Success test assertions:

- status changes to `running`, stage `ansible`;
- fake controller receives the validated request and a writable log stream;
- result JSON contains final hostname, employee login, profile, and verification checks;
- server assignment is written only after controller success;
- final status is `successful`, stage `complete`, and has `finished_at`;
- no persisted JSON key contains `password`, `secret`, `token`, `private_key`, or `vault`.

Failure test assertions:

- controller exception produces `failed`, stage `ansible`, exit code `1`;
- no assignment file exists;
- error text is bounded to 10,000 characters;
- partial `ansible.log` remains available.

- [ ] **Step 2: Run tests and verify failure**

```bash
pytest -q tests/alt_linux/test_worker.py
```

Expected: import failure for `alt_deploy.worker`.

- [ ] **Step 3: Implement provision command construction**

`AnsibleController.run_provision()` builds:

```python
[
    "/usr/bin/ansible-playbook",
    "-i", f"{machine.ip},",
    "-u", "ansible",
    f"--private-key={settings.private_key_file}",
    f"--ssh-common-args={strict_ssh_args}",
    "-e", "ansible_python_interpreter=/usr/bin/python3",
    "-e", f"@{job.job_dir / 'request.json'}",
    "-e", f"job_id={job.job_id}",
    "-e", f"provision_result_file={job.job_dir / 'provision-result.json'}",
    str(settings.ansible_project_dir / "playbooks" / "02-provision-account.yml"),
]
```

Run with `stdout=log_stream`, `stderr=subprocess.STDOUT`, `shell=False`, `timeout=1800`, and `check=False`. Do not pass the Vault password or employee hash on the command line. Read and return `provision-result.json` only on exit code `0`; otherwise raise a bounded `ControlError("ansible_provision_failed", ...)`.

- [ ] **Step 4: Implement the worker transaction**

`run_job()` must:

1. Load the queued job and request.
2. Resolve the current machine by UUID and ensure its IP is present.
3. Update state to `running`, stage `ansible`, and set `started_at`.
4. Open `ansible.log` in append mode with permissions `0600`.
5. Write a non-secret header containing job ID, UUID, IP, login, hostname, and UTC start time.
6. Run Ansible.
7. Validate the result object contains exactly the expected public assignment fields and verification map.
8. Write `result.json`.
9. Write the server assignment through `AssignmentRepository`.
10. Mark the job `successful`, stage `complete`.
11. On any exception, append a bounded diagnostic and mark the job failed.

```python
#!/usr/bin/python3
# deploy/alt-linux/control/alt-provision-worker
from __future__ import annotations

import sys
from pathlib import Path

sys.path.insert(0, str(Path("/opt/alt-deploy-control")))

from alt_deploy.worker import main

raise SystemExit(main())
```

- [ ] **Step 5: Run worker tests**

```bash
pytest -q tests/alt_linux/test_worker.py
```

Expected: success/failure lifecycle tests pass.

- [ ] **Step 6: Commit worker**

```bash
git add deploy/alt-linux/control tests/alt_linux/test_worker.py
git commit -m "feat: execute provision jobs asynchronously"
```

---

### Task 9: Ansible Hostname, Employee, LightDM, AccountsService, and Verification Roles

**Files:**
- Create: `deploy/alt-linux/ansible/group_vars/vault.yml.example`
- Create: `deploy/alt-linux/ansible/playbooks/02-provision-account.yml`
- Create: `deploy/alt-linux/ansible/roles/workstation_identity/tasks/main.yml`
- Create: `deploy/alt-linux/ansible/roles/local_employee/tasks/main.yml`
- Create: `deploy/alt-linux/ansible/roles/lightdm_accounts/tasks/main.yml`
- Create: `deploy/alt-linux/ansible/roles/provision_verify/tasks/main.yml`
- Create: `deploy/alt-linux/ansible/roles/provision_verify/templates/assignment.json.j2`
- Create: `tests/alt_linux/test_ansible_assets.py`

**Interfaces:**
- Consumes provision vars: `machine_uuid`, `employee_login`, `employee_full_name`, `final_hostname`, `profile`, `job_id`, `provision_result_file`
- Consumes Vault var: `vault_employee_password_hash`
- Produces target: `/var/lib/alt-workstation/assignment.json`
- Produces controller artifact: `provision_result_file`

- [ ] **Step 1: Write failing static safety tests**

`tests/alt_linux/test_ansible_assets.py` must load every YAML file with `yaml.safe_load_all` and assert:

- both playbooks parse;
- `02-provision-account.yml` includes roles in this exact order: `workstation_identity`, `local_employee`, `lightdm_accounts`, `provision_verify`;
- the employee task uses `ansible.builtin.user` with `password: "{{ vault_employee_password_hash }}"`, `update_password: always`, `groups: ""`, and `no_log: true`;
- no tracked Ansible file contains the previously discussed cleartext shared password;
- AccountsService records contain `SystemAccount=true` for `ansible` and `SystemAccount=false` for the employee; the LightDM drop-in contains empty `autologin-user` and `autologin-user-timeout=0`;
- the target assignment template contains no password-like field;
- no role uses `ansible.builtin.shell`, `ignore_errors`, or `StrictHostKeyChecking=no`.

- [ ] **Step 2: Run tests and verify missing files fail**

```bash
pytest -q tests/alt_linux/test_ansible_assets.py
```

Expected: missing playbook/roles failure.

- [ ] **Step 3: Create the provision playbook and identity role**

```yaml
# deploy/alt-linux/ansible/playbooks/02-provision-account.yml
---
- name: Provision ALT workstation local employee
  hosts: all
  gather_facts: true
  become: true

  vars_files:
    - ../group_vars/vault.yml

  pre_tasks:
    - name: Validate required provision variables
      ansible.builtin.assert:
        that:
          - machine_uuid | length > 0
          - employee_login | length > 0
          - employee_full_name | length > 0
          - final_hostname | length > 0
          - profile == 'standard'
          - job_id | length > 0
          - provision_result_file | length > 0
        fail_msg: Required provision variables are missing
  roles:
    - role: workstation_identity
    - role: local_employee
    - role: lightdm_accounts
    - role: provision_verify
```

```yaml
# deploy/alt-linux/ansible/roles/workstation_identity/tasks/main.yml
---
- name: Set final static hostname
  ansible.builtin.hostname:
    name: "{{ final_hostname }}"
    use: systemd

- name: Read final static hostname
  ansible.builtin.command:
    argv: [hostnamectl, --static]
  register: workstation_static_hostname
  changed_when: false

- name: Verify final static hostname
  ansible.builtin.assert:
    that:
      - workstation_static_hostname.stdout | trim == final_hostname
    fail_msg: Final hostname did not apply
```

- [ ] **Step 4: Create the local employee role**

The role must reject an incompatible existing account before mutation, create a same-name primary group, and then reconcile the account:

```yaml
---
- name: Read existing employee passwd entry
  ansible.builtin.command:
    argv: [getent, passwd, "{{ employee_login }}"]
  register: employee_existing_passwd
  changed_when: false
  failed_when: false

- name: Parse existing employee passwd entry
  ansible.builtin.set_fact:
    employee_existing_fields: "{{ employee_existing_passwd.stdout.split(':') if employee_existing_passwd.rc == 0 else [] }}"

- name: Reject incompatible existing employee account
  ansible.builtin.assert:
    that:
      - employee_existing_fields | length == 0 or employee_existing_fields[2] | int >= 1000
      - employee_existing_fields | length == 0 or employee_existing_fields[5] == '/home/' + employee_login
      - employee_login not in ['root', 'ansible', 'osn-admin']
    fail_msg: Existing local account conflicts with requested employee

- name: Ensure employee primary group exists
  ansible.builtin.group:
    name: "{{ employee_login }}"
    state: present

- name: Create or reconcile local employee
  ansible.builtin.user:
    name: "{{ employee_login }}"
    comment: "{{ employee_full_name }}"
    group: "{{ employee_login }}"
    groups: ""
    home: "/home/{{ employee_login }}"
    shell: /bin/bash
    create_home: true
    password: "{{ vault_employee_password_hash }}"
    update_password: always
    password_lock: false
    password_expire_max: 99999
    expires: -1
    state: present
  no_log: true

- name: Read employee supplementary groups
  ansible.builtin.command:
    argv: [id, -nG, "{{ employee_login }}"]
  register: employee_groups
  changed_when: false

- name: Verify employee has no wheel membership
  ansible.builtin.assert:
    that:
      - "'wheel' not in employee_groups.stdout.split()"
    fail_msg: Employee unexpectedly belongs to wheel
```

- [ ] **Step 5: Create the LightDM and AccountsService role**

```yaml
# deploy/alt-linux/ansible/roles/lightdm_accounts/tasks/main.yml
---
- name: Ensure AccountsService user directory exists
  ansible.builtin.file:
    path: /var/lib/AccountsService/users
    state: directory
    owner: root
    group: root
    mode: "0700"

- name: Hide ansible account from LightDM
  ansible.builtin.copy:
    dest: /var/lib/AccountsService/users/ansible
    owner: root
    group: root
    mode: "0644"
    content: |
      [User]
      SystemAccount=true
  register: lightdm_accounts_ansible_record

- name: Keep employee account visible in LightDM
  ansible.builtin.copy:
    dest: "/var/lib/AccountsService/users/{{ employee_login }}"
    owner: root
    group: root
    mode: "0644"
    content: |
      [User]
      SystemAccount=false
  register: lightdm_accounts_employee_record

- name: Restart AccountsService after visibility changes
  ansible.builtin.systemd_service:
    name: accounts-daemon
    state: restarted
  when:
    - >-
      lightdm_accounts_ansible_record.changed
      or lightdm_accounts_employee_record.changed

- name: Ensure LightDM configuration directory exists
  ansible.builtin.file:
    path: /etc/lightdm/lightdm.conf.d
    state: directory
    owner: root
    group: root
    mode: "0755"

- name: Disable LightDM autologin
  ansible.builtin.copy:
    dest: /etc/lightdm/lightdm.conf.d/90-alt-workstation.conf
    owner: root
    group: root
    mode: "0644"
    content: |
      [Seat:*]
      autologin-user=
      autologin-user-timeout=0
```

Do not restart LightDM during provisioning. Restart AccountsService only when its managed visibility records change.

- [ ] **Step 6: Create final verification and assignment artifacts**

`provision_verify` must:

- verify static hostname;
- `getent passwd` employee and validate home and shell;
- verify no `wheel` group;
- run `sudo -n -l -U <employee>` with `LC_ALL=C` and `failed_when: false`; assert the command completed and the combined output contains `is not allowed to run sudo`;
- run `sudo -n true` with `become: false` to prove `ansible` still has passwordless sudo;
- read the `ansible` and employee AccountsService records and the managed LightDM drop-in, then assert their required values;
- create `/var/lib/alt-workstation` mode `0700`;
- write target assignment only after all assertions;
- write the public controller result through a delegated localhost copy.

```jinja2
{
  "machine_uuid": {{ machine_uuid | to_json }},
  "final_hostname": {{ final_hostname | to_json }},
  "employee_login": {{ employee_login | to_json }},
  "employee_full_name": {{ employee_full_name | to_json }},
  "profile": {{ profile | to_json }},
  "job_id": {{ job_id | to_json }},
  "completed_at": {{ ansible_date_time.iso8601 | to_json }}
}
```

Use this template for `/var/lib/alt-workstation/assignment.json`; then build the controller result by combining the same public values with:

```yaml
verification:
  hostname: true
  employee_exists: true
  employee_not_wheel: true
  employee_no_sudo: true
  ansible_sudo: true
  lightdm_hides_ansible: true
  lightdm_shows_employee: true
  lightdm_autologin_disabled: true
```

The delegated result copy must be the last task.

- [ ] **Step 7: Add the Vault example and run safety tests**

```yaml
# deploy/alt-linux/ansible/group_vars/vault.yml.example
---
# Create the active encrypted file only on 192.168.100.17.
# The value is a yescrypt hash, not a cleartext password.
vault_employee_password_hash: ""
```

Run:

```bash
pytest -q tests/alt_linux/test_ansible_assets.py
```

On the controller:

```bash
cd /home/altserver/ansible
ansible-playbook --syntax-check playbooks/02-provision-account.yml
```

Expected: tests and syntax check pass.

- [ ] **Step 8: Commit Ansible provisioning roles**

```bash
git add deploy/alt-linux/ansible tests/alt_linux/test_ansible_assets.py
git commit -m "feat: provision ALT local employee accounts"
```

---

### Task 10: Controller Installation, Vault Setup, Documentation, and End-to-End Acceptance

**Files:**
- Create: `deploy/alt-linux/install-control-plane.sh`
- Modify: `deploy/alt-linux/README.md`
- Modify: `.gitignore`
- Modify: `docs/ALT_LINUX_AUTOINSTALL.md`
- Create: `tests/alt_linux/test_install_assets.py`

**Interfaces:**
- Installs package to `/opt/alt-deploy-control/alt_deploy`
- Installs CLI to `/usr/local/sbin/workstationctl`
- Installs worker to `/usr/local/libexec/alt-provision-worker`
- Installs Ansible source into `/home/altserver/ansible`
- Creates `/var/lib/alt-deploy/jobs`, `/var/lib/alt-deploy/assignments`, and the lock file parent with `altserver:altserver` ownership

- [ ] **Step 1: Write failing installation-asset tests**

Assert the install script:

- starts with `set -Eeuo pipefail`;
- refuses to run unless UID is zero;
- installs root-owned executable wrappers;
- installs the Python package read-only;
- creates state directories owned by `altserver` mode `0700`;
- copies Ansible playbooks/roles without deleting unrelated old files;
- installs the updated `process_pending.py`;
- runs Python compile checks, Bash syntax checks, pytest, and Ansible syntax checks before restarting services;
- never creates or copies a Vault secret from the repository.

- [ ] **Step 2: Run test and verify the installer is missing**

```bash
pytest -q tests/alt_linux/test_install_assets.py
```

Expected: missing install script failure.

- [ ] **Step 3: Implement the idempotent installation script**

The script must use `install` and `cp -a` rather than deleting `/home/altserver/ansible`. Required operations:

```bash
#!/bin/bash
set -Eeuo pipefail

if [[ ${EUID} -ne 0 ]]; then
    echo "Run as root" >&2
    exit 1
fi

REPO_ROOT=$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)
ALT_ROOT="${REPO_ROOT}/deploy/alt-linux"

install -d -o root -g root -m 0755 /opt/alt-deploy-control
rm -rf /opt/alt-deploy-control/alt_deploy
cp -a "${ALT_ROOT}/control/alt_deploy" /opt/alt-deploy-control/alt_deploy
chown -R root:root /opt/alt-deploy-control
find /opt/alt-deploy-control -type d -exec chmod 0755 {} +
find /opt/alt-deploy-control -type f -exec chmod 0644 {} +

install -o root -g root -m 0755 "${ALT_ROOT}/control/workstationctl" /usr/local/sbin/workstationctl
install -d -o root -g root -m 0755 /usr/local/libexec
install -o root -g root -m 0755 "${ALT_ROOT}/control/alt-provision-worker" /usr/local/libexec/alt-provision-worker

install -d -o altserver -g altserver -m 0700 \
    /var/lib/alt-deploy \
    /var/lib/alt-deploy/jobs \
    /var/lib/alt-deploy/assignments

install -d -o altserver -g altserver -m 0750 \
    /home/altserver/ansible \
    /home/altserver/ansible/playbooks \
    /home/altserver/ansible/roles \
    /home/altserver/ansible/group_vars

install -o altserver -g altserver -m 0644 \
    "${ALT_ROOT}/ansible/ansible.cfg" \
    /home/altserver/ansible/ansible.cfg
install -o altserver -g altserver -m 0644 \
    "${ALT_ROOT}/ansible/group_vars/all.yml" \
    /home/altserver/ansible/group_vars/all.yml
cp -a "${ALT_ROOT}/ansible/playbooks/." /home/altserver/ansible/playbooks/
cp -a "${ALT_ROOT}/ansible/roles/." /home/altserver/ansible/roles/
chown -R altserver:altserver /home/altserver/ansible/playbooks /home/altserver/ansible/roles

install -o root -g root -m 0755 \
    "${ALT_ROOT}/api/process_pending.py" \
    /opt/alt-deploy-api/process_pending.py

python3 -m py_compile /opt/alt-deploy-control/alt_deploy/*.py /opt/alt-deploy-api/process_pending.py
bash -n "${ALT_ROOT}/bootstrap/bootstrap.sh"
cd "${REPO_ROOT}"
pytest -q tests/alt_linux
sudo -u altserver bash -lc \
    'cd /home/altserver/ansible && ansible-playbook --syntax-check playbooks/01-preflight.yml && ansible-playbook --syntax-check playbooks/02-provision-account.yml'

systemctl restart alt-deploy-process.path
```

Do not use `rm -rf` anywhere under `/home/altserver/ansible` or `/var/lib/alt-deploy`.

- [ ] **Step 4: Document secure Vault creation on the controller**

Add these exact commands to the runbook; they prompt interactively and do not put either password in shell history:

```bash
sudo -u altserver bash -lc '
set -Eeuo pipefail
umask 077
HASH=$(mkpasswd --method=yescrypt)
printf "vault_employee_password_hash: %s\n" "${HASH}" > /tmp/alt-workstation-vault.yml
unset HASH
'

sudo install -o altserver -g altserver -m 0600 /dev/null \
  /home/altserver/.ansible-vault-pass
sudo -u altserver sh -c 'read -r -s -p "Vault password: " p; printf "\n" >&2; printf "%s\n" "$p" > /home/altserver/.ansible-vault-pass; unset p'

sudo -u altserver env \
  ANSIBLE_VAULT_PASSWORD_FILE=/home/altserver/.ansible-vault-pass \
  ansible-vault encrypt \
  /tmp/alt-workstation-vault.yml \
  --output /home/altserver/ansible/group_vars/vault.yml

sudo rm -f /tmp/alt-workstation-vault.yml
sudo chmod 0600 \
  /home/altserver/.ansible-vault-pass \
  /home/altserver/ansible/group_vars/vault.yml
```

Document that the previously discussed shared password must be rotated before production because it appeared in chat.

- [ ] **Step 5: Update Git exclusions and operating docs**

Add to `.gitignore`:

```gitignore
# ALT deployment active secrets and runtime state
deploy/alt-linux/ansible/group_vars/vault.yml
alt-deploy-state/
```

Document:

- install/update command;
- `machines list/show` examples;
- automatic preflight lifecycle;
- request JSON format;
- preview/start/status/log commands;
- job and assignment directories;
- strict SSH key handling;
- recovery from failed jobs by correcting the cause and rerunning the same request;
- explicit prohibition on deleting old employee data.

- [ ] **Step 6: Run the ALT provisioning test suite**

```bash
.venv/bin/python -m pytest -q tests/alt_linux
```

The unrelated OpenVPN tests require `/etc/openvpn/vpnctl.env` and are outside this workstream.

- [ ] **Step 7: Deploy the controller files on `192.168.100.17`**

```bash
cd /path/to/web_ovpn
sudo bash deploy/alt-linux/install-control-plane.sh
sudo systemctl status alt-deploy-process.path --no-pager
sudo -u altserver /usr/local/sbin/workstationctl --json machines list
```

Expected: path unit active and the test workstation visible.

- [ ] **Step 8: Run end-to-end preflight and provisioning on the disposable ALT test machine**

Select the first awaiting machine without hardcoding an IP:

```bash
UUID=$(sudo -u altserver workstationctl --json machines list | python3 -c '
import json, sys
machines=json.load(sys.stdin)["machines"]
print(next(m["uuid"] for m in machines if m["status"] == "awaiting_assignment"))
')
```

Rerun preflight:

```bash
sudo -u altserver workstationctl --json preflight "${UUID}"
```

Create a request with no secret:

```bash
cat >/tmp/alt-provision-request.json <<EOF
{
  "machine_uuid": "${UUID}",
  "employee_login": "test-user",
  "employee_full_name": "Тестовый Пользователь",
  "final_hostname": "alt-test-01",
  "profile": "standard"
}
EOF
chmod 0600 /tmp/alt-provision-request.json
```

Preview and start:

```bash
sudo -u altserver workstationctl --json provision preview "${UUID}" \
  --vars-file /tmp/alt-provision-request.json

START_JSON=$(sudo workstationctl --json provision start "${UUID}" \
  --vars-file /tmp/alt-provision-request.json)
printf "%s\n" "${START_JSON}"
JOB_ID=$(printf "%s" "${START_JSON}" | python3 -c 'import json,sys; print(json.load(sys.stdin)["job"]["job_id"])')
```

Poll without WebSocket:

```bash
while true; do
  STATUS_JSON=$(sudo -u altserver workstationctl --json jobs status "${JOB_ID}")
  printf "%s\n" "${STATUS_JSON}"
  STATE=$(printf "%s" "${STATUS_JSON}" | python3 -c 'import json,sys; print(json.load(sys.stdin)["job"]["state"])')
  case "${STATE}" in
    successful|failed) break ;;
  esac
  sleep 2
done

sudo -u altserver workstationctl --json jobs log "${JOB_ID}"
```

Verify target state through the isolated SSH helper:

```bash
IP=$(sudo -u altserver workstationctl --json machines show "${UUID}" | python3 -c 'import json,sys; print(json.load(sys.stdin)["machine"]["ip"])')
ssh-alt "${IP}" '
set -e
hostnamectl --static
getent passwd test-user
id -nG test-user
sudo test -f /var/lib/alt-workstation/assignment.json
sudo cat /var/lib/alt-workstation/assignment.json
sudo cat /var/lib/AccountsService/users/ansible
sudo cat /var/lib/AccountsService/users/test-user
sudo cat /etc/lightdm/lightdm.conf.d/90-alt-workstation.conf
'
```

Confirm a second normal provision is rejected:

```bash
sudo workstationctl --json provision start "${UUID}" \
  --vars-file /tmp/alt-provision-request.json
```

Expected: nonzero exit and `error.code == "machine_already_assigned"`.

- [ ] **Step 9: Commit installer and documentation**

```bash
git add .gitignore deploy/alt-linux docs/ALT_LINUX_AUTOINSTALL.md tests/alt_linux/test_install_assets.py
git commit -m "docs: add ALT provisioning deployment runbook"
```

---

## Final Verification Checklist

Run before opening the implementation PR:

```bash
.venv/bin/python -m pytest -q tests/alt_linux
python3 -m py_compile deploy/alt-linux/control/alt_deploy/*.py deploy/alt-linux/api/process_pending.py
bash -n deploy/alt-linux/control/workstationctl
bash -n deploy/alt-linux/control/alt-provision-worker
bash -n deploy/alt-linux/install-control-plane.sh
```

On `192.168.100.17`:

```bash
sudo -u altserver bash -lc 'cd /home/altserver/ansible && ansible-playbook --syntax-check playbooks/01-preflight.yml'
sudo -u altserver bash -lc 'cd /home/altserver/ansible && ansible-playbook --syntax-check playbooks/02-provision-account.yml'
sudo -u altserver workstationctl --json machines list
```

Spec coverage check:

- automatic preflight and `awaiting_assignment`: Tasks 3-4;
- machine list/show: Task 2 plus Task 5 enrichment;
- strict validation and preview: Task 6;
- asynchronous systemd jobs and logs: Tasks 7-8;
- local employee, hostname, LightDM, AccountsService, and no sudo: Task 9;
- assignment-only-after-verification and retry safety: Tasks 5, 8, and 9;
- secure installation and Vault handling: Task 10;
- web UI and application roles remain explicitly deferred.
