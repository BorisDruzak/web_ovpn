# ALT Structured Job Stages Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Replace coarse `stage=ansible` job state with a strict, timestamped, fail-closed stage history shared by the planner, worker, Ansible role markers, reconciliation, retention, and `jobs status`.

**Architecture:** A focused `job_stages.py` domain module owns the canonical sequence, validates every job status, and performs atomic one-step transitions under the existing controller lock. The planner and worker call it directly; Ansible invokes the same domain logic through an internal localhost-only helper. Existing test jobs are not migrated: they are backed up and explicitly removed during a separately approved runtime rollout before the strict schema is installed.

**Tech Stack:** Python 3.12 standard library, pytest, argparse, atomic JSON files, fcntl locking, Ansible Core, systemd.

## Global Constraints

- Work only from the isolated ALT provisioning worktree whose `HEAD` equals `origin/feat/alt-workstation-provisioning-mvp`; the local branch name may remain `work/alt-workstation-mvp`.
- Run only `tests/alt_linux` by default. The unrelated OpenVPN suite requires `/etc/openvpn/vpnctl.env`.
- Do not rerun `provision start` for assigned UUID `53b03180-5d78-11f0-bd95-f027db877a00`.
- Do not read or print `/home/altserver/.ansible-vault-pass`, decrypted Vault content, password hashes, or private keys.
- Canonical stages are exactly: `created`, `launching`, `validating`, `connecting`, `identity`, `employee`, `login_screen`, `verifying`, `recording`, `complete`.
- `state` remains one of `queued`, `running`, `successful`, `failed`; failure is not a stage.
- Every new job has a non-empty `stage_history`; old jobs are not migrated or synthesized.
- A failed job keeps its last reached stage.
- A successful job must end at `stage=complete`.
- Repeating the current stage on a non-terminal job is a byte-for-byte no-op.
- Backward transitions, skipped transitions, unknown stages, and terminal-job markers fail closed.
- `JobRepository.update()` must reject direct changes to `stage` and `stage_history`.
- Real malformed `job-*` directories must not disappear from list, active-job, reconciliation, or cleanup operations.
- Stage-marker tasks run only on the controller with `delegate_to: localhost`, `become: false`, `run_once: true`, and `changed_when: false`.
- No stage is derived by parsing human Ansible output or task names.
- No public `workstationctl jobs stage` command is added.
- No runtime installation, test-job deletion, or live provisioning occurs until separately approved after full repository verification.

---

## Implementation File Map

```text
deploy/alt-linux/control/
├── alt-job-stage                         # installed internal helper wrapper
└── alt_deploy/
    ├── config.py                         # helper executable setting
    ├── job_stages.py                     # schema, validation, transitions
    ├── job_stage_helper.py               # helper argument/JSON contract
    ├── jobs.py                           # strict repository integration
    ├── provision.py                      # created -> launching
    ├── worker.py                         # validating/connecting/recording/complete
    ├── ansible.py                        # helper preflight and extra var
    ├── job_reconcile.py                  # preserve/recover real stage
    └── job_retention.py                  # fail closed through strict repository

deploy/alt-linux/ansible/playbooks/
└── 02-provision-account.yml              # marker/include_role sequence

deploy/alt-linux/install-control-plane.sh  # installs and verifies helper

tests/alt_linux/
├── test_job_stages.py                    # stage schema and transition domain
├── test_jobs.py                          # created history and strict repository
├── test_provision_start.py               # planner launching transition
├── test_worker.py                        # complete worker stage flow
├── test_job_stage_helper.py              # internal helper contract
├── test_ansible_assets.py                # marker placement and safety
├── test_job_reconcile.py                 # stage-preserving recovery
├── test_job_retention.py                 # malformed history fail-closed
├── test_install_assets.py                # helper installation
└── test_job_stage_documentation.py       # operating contract

docs/
├── ALT_WORKSTATION_PROVISIONING_CONTEXT.md
├── ALT_WORKSTATION_PROVISIONING_NEXT_STEPS.md
└── superpowers/specs/2026-07-18-alt-job-stages-design.md

deploy/alt-linux/README.md
```

---

### Task 1: Define and Validate the Canonical Stage Schema

**Files:**
- Create: `deploy/alt-linux/control/alt_deploy/job_stages.py`
- Create: `tests/alt_linux/test_job_stages.py`

**Interfaces:**
- Produces: `CANONICAL_STAGES: tuple[str, ...]`
- Produces: `FORWARD_UPDATE_FIELDS: frozenset[str]`
- Produces: `TERMINAL_STATES: frozenset[str]`
- Produces: `initial_stage_history(entered_at: str) -> list[dict[str, str]]`
- Produces: `validate_job_stage_status(status: Mapping[str, object], *, job_id: str) -> None`
- Produces stable error code: `job_stage_history_invalid`

- [ ] **Step 1: Write pure failing schema tests**

Create `tests/alt_linux/test_job_stages.py`:

```python
from __future__ import annotations

from copy import deepcopy
from datetime import datetime, timezone

import pytest

from alt_deploy.errors import ControlError
from alt_deploy.job_stages import (
    CANONICAL_STAGES,
    initial_stage_history,
    validate_job_stage_status,
)


def valid_status() -> dict[str, object]:
    created_at = "2026-07-18T12:00:00+00:00"
    return {
        "job_id": "job-20260718T120000Z-a1b2c3d4",
        "machine_uuid": (
            "53b03180-5d78-11f0-bd95-f027db877a00"
        ),
        "state": "queued",
        "stage": "created",
        "created_at": created_at,
        "updated_at": created_at,
        "stage_history": [
            {
                "stage": "created",
                "entered_at": created_at,
            }
        ],
    }


def test_canonical_stage_order_is_stable() -> None:
    assert CANONICAL_STAGES == (
        "created",
        "launching",
        "validating",
        "connecting",
        "identity",
        "employee",
        "login_screen",
        "verifying",
        "recording",
        "complete",
    )


def test_initial_history_normalizes_timezone_to_utc() -> None:
    history = initial_stage_history(
        "2026-07-18T17:00:00+05:00"
    )

    assert history == [
        {
            "stage": "created",
            "entered_at": (
                "2026-07-18T12:00:00+00:00"
            ),
        }
    ]


def test_valid_created_status_is_accepted() -> None:
    validate_job_stage_status(
        valid_status(),
        job_id="job-20260718T120000Z-a1b2c3d4",
    )


@pytest.mark.parametrize(
    "mutation",
    [
        lambda status: status.pop("stage_history"),
        lambda status: status.update(
            stage_history=[]
        ),
        lambda status: status.update(
            stage_history=[
                {
                    "stage": "created",
                    "entered_at": (
                        "2026-07-18T12:00:00"
                    ),
                }
            ]
        ),
        lambda status: status.update(
            stage_history=[
                {
                    "stage": "employee",
                    "entered_at": (
                        "2026-07-18T12:00:00+00:00"
                    ),
                }
            ],
            stage="employee",
        ),
        lambda status: status.update(
            stage_history=[
                {
                    "stage": "created",
                    "entered_at": (
                        "2026-07-18T12:00:00+00:00"
                    ),
                },
                {
                    "stage": "validating",
                    "entered_at": (
                        "2026-07-18T12:00:01+00:00"
                    ),
                },
            ],
            stage="validating",
            state="running",
        ),
        lambda status: status.update(
            stage_history=[
                {
                    "stage": "created",
                    "entered_at": (
                        "2026-07-18T12:00:02+00:00"
                    ),
                },
                {
                    "stage": "launching",
                    "entered_at": (
                        "2026-07-18T12:00:01+00:00"
                    ),
                },
            ],
            stage="launching",
        ),
        lambda status: status.update(
            stage="launching"
        ),
        lambda status: status.update(
            state="successful"
        ),
    ],
)
def test_invalid_stage_status_is_rejected(
    mutation,
) -> None:
    status = deepcopy(valid_status())
    mutation(status)

    with pytest.raises(ControlError) as exc:
        validate_job_stage_status(
            status,
            job_id=str(status["job_id"]),
        )

    assert exc.value.code == (
        "job_stage_history_invalid"
    )
```

- [ ] **Step 2: Run tests and verify RED**

```bash
.venv/bin/python -m pytest -q \
  tests/alt_linux/test_job_stages.py
```

Expected: collection fails because `alt_deploy.job_stages` does not exist.

- [ ] **Step 3: Implement the pure schema module**

Create `deploy/alt-linux/control/alt_deploy/job_stages.py`:

```python
from __future__ import annotations

from collections.abc import Mapping
from datetime import datetime, timezone

from .errors import ControlError


CANONICAL_STAGES: tuple[str, ...] = (
    "created",
    "launching",
    "validating",
    "connecting",
    "identity",
    "employee",
    "login_screen",
    "verifying",
    "recording",
    "complete",
)

STAGE_INDEX = {
    stage: index
    for index, stage in enumerate(CANONICAL_STAGES)
}

FORWARD_UPDATE_FIELDS = frozenset(
    {
        "state",
        "started_at",
        "finished_at",
        "systemd_unit",
        "result_file",
    }
)

TERMINAL_STATES = frozenset(
    {
        "successful",
        "failed",
    }
)


def _invalid(
    job_id: str,
    message: str,
) -> ControlError:
    return ControlError(
        code="job_stage_history_invalid",
        message=message,
        exit_code=4,
        details={"job_id": job_id},
    )


def _parse_timestamp(
    value: object,
    *,
    job_id: str,
) -> datetime:
    text = str(value or "").strip()

    try:
        parsed = datetime.fromisoformat(text)
    except ValueError as exc:
        raise _invalid(
            job_id,
            "Provision job stage timestamp is invalid",
        ) from exc

    if parsed.tzinfo is None:
        raise _invalid(
            job_id,
            "Provision job stage timestamp has no timezone",
        )

    return parsed.astimezone(timezone.utc)


def initial_stage_history(
    entered_at: str,
) -> list[dict[str, str]]:
    parsed = _parse_timestamp(
        entered_at,
        job_id="new-job",
    )
    return [
        {
            "stage": "created",
            "entered_at": parsed.isoformat(),
        }
    ]


def validate_job_stage_status(
    status: Mapping[str, object],
    *,
    job_id: str,
) -> None:
    state = str(status.get("state") or "").strip()
    stage = str(status.get("stage") or "").strip()
    history = status.get("stage_history")

    if stage not in STAGE_INDEX:
        raise _invalid(
            job_id,
            "Provision job stage is unknown",
        )

    if not isinstance(history, list) or not history:
        raise _invalid(
            job_id,
            "Provision job stage history is missing or empty",
        )

    previous_time: datetime | None = None
    observed_stages: list[str] = []

    for index, raw_item in enumerate(history):
        if (
            not isinstance(raw_item, dict)
            or set(raw_item)
            != {"stage", "entered_at"}
        ):
            raise _invalid(
                job_id,
                "Provision job stage history item is invalid",
            )

        item_stage = str(
            raw_item["stage"] or ""
        ).strip()

        if (
            index >= len(CANONICAL_STAGES)
            or item_stage != CANONICAL_STAGES[index]
        ):
            raise _invalid(
                job_id,
                "Provision job stage history is not contiguous",
            )

        entered_at = _parse_timestamp(
            raw_item["entered_at"],
            job_id=job_id,
        )

        if (
            previous_time is not None
            and entered_at < previous_time
        ):
            raise _invalid(
                job_id,
                "Provision job stage timestamps move backwards",
            )

        observed_stages.append(item_stage)
        previous_time = entered_at

    if stage != observed_stages[-1]:
        raise _invalid(
            job_id,
            "Provision job stage does not match stage history",
        )

    if state == "queued" and stage not in {
        "created",
        "launching",
    }:
        raise _invalid(
            job_id,
            "Queued job has an invalid stage",
        )

    if state == "running" and not (
        STAGE_INDEX["validating"]
        <= STAGE_INDEX[stage]
        <= STAGE_INDEX["recording"]
    ):
        raise _invalid(
            job_id,
            "Running job has an invalid stage",
        )

    if (
        state == "successful"
        and stage != "complete"
    ):
        raise _invalid(
            job_id,
            "Successful job is not complete",
        )

    if state == "failed" and stage == "complete":
        raise _invalid(
            job_id,
            "Failed job cannot be complete",
        )

    if state not in {
        "queued",
        "running",
        "successful",
        "failed",
    }:
        raise _invalid(
            job_id,
            "Provision job state is unknown",
        )
```

- [ ] **Step 4: Run focused tests and the existing jobs regression**

```bash
.venv/bin/python -m pytest -q \
  tests/alt_linux/test_job_stages.py \
  tests/alt_linux/test_jobs.py
```

Expected: PASS; Task 1 does not yet change persisted job records.

- [ ] **Step 5: Commit**

```bash
git add \
  deploy/alt-linux/control/alt_deploy/job_stages.py \
  tests/alt_linux/test_job_stages.py
git commit -m "feat: define provision job stage schema"
```

---

### Task 2: Integrate Strict Job Storage and Atomic Stage Transitions

**Files:**
- Modify: `deploy/alt-linux/control/alt_deploy/job_stages.py`
- Modify: `deploy/alt-linux/control/alt_deploy/jobs.py`
- Modify: `tests/alt_linux/test_job_stages.py`
- Modify: `tests/alt_linux/test_jobs.py`

**Interfaces:**
- Produces: `JobStageManager(settings, *, clock=None, repository=None)`
- Produces: `advance(job_id: str, next_stage: str, *, updates: Mapping[str, object] | None = None) -> JobRecord`
- Produces: `advance_unlocked(job_id: str, next_stage: str, *, updates: Mapping[str, object] | None = None) -> JobRecord`
- Changes: `JobRepository.create()` initializes strict history.
- Changes: `JobRepository.get()` and `.list()` fail closed on malformed real job records.
- Changes: `JobRepository.update()` rejects stage fields and validates the complete result.
- Current-stage calls on non-terminal jobs are byte-for-byte no-ops.

- [ ] **Step 1: Write failing repository integration tests**

Append to `tests/alt_linux/test_job_stages.py`:

```python
from pathlib import Path

from alt_deploy.jobs import JobRepository
from alt_deploy.jsonio import (
    atomic_write_json,
    read_json,
)

from test_jobs import provision_request
from test_registry_cli import make_settings


def test_new_job_has_created_stage_history(
    tmp_path: Path,
) -> None:
    settings = make_settings(tmp_path)
    job = JobRepository(settings).create(
        provision_request()
    )

    status = read_json(
        job.job_dir / "status.json"
    )
    assert status["state"] == "queued"
    assert status["stage"] == "created"
    assert status["stage_history"] == [
        {
            "stage": "created",
            "entered_at": status["created_at"],
        }
    ]


def test_malformed_real_job_is_not_hidden_by_list(
    tmp_path: Path,
) -> None:
    settings = make_settings(tmp_path)
    repository = JobRepository(settings)
    job = repository.create(provision_request())
    status = read_json(
        job.job_dir / "status.json"
    )
    status.pop("stage_history")
    atomic_write_json(
        job.job_dir / "status.json",
        status,
    )

    with pytest.raises(ControlError) as exc:
        repository.get(job.job_id)

    assert exc.value.code == (
        "job_stage_history_invalid"
    )

    with pytest.raises(ControlError) as exc:
        repository.list()

    assert exc.value.code == (
        "job_stage_history_invalid"
    )


def test_repository_update_rejects_direct_stage_changes(
    tmp_path: Path,
) -> None:
    settings = make_settings(tmp_path)
    repository = JobRepository(settings)
    job = repository.create(provision_request())

    with pytest.raises(ControlError) as exc:
        repository.update(
            job.job_id,
            stage="launching",
        )

    assert exc.value.code == (
        "job_stage_update_forbidden"
    )

    with pytest.raises(ControlError) as exc:
        repository.update(
            job.job_id,
            stage_history=[],
        )

    assert exc.value.code == (
        "job_stage_update_forbidden"
    )
```

- [ ] **Step 2: Write failing transition tests**

Append to `tests/alt_linux/test_job_stages.py`:

```python
from datetime import timedelta

from alt_deploy.job_stages import JobStageManager


class FixedClock:
    def __init__(self, after: str) -> None:
        self.current = (
            datetime.fromisoformat(after)
            .astimezone(timezone.utc)
            + timedelta(seconds=1)
        )

    def __call__(self) -> str:
        value = self.current.isoformat()
        self.current += timedelta(seconds=1)
        return value


def test_stage_manager_advances_one_stage_atomically(
    tmp_path: Path,
) -> None:
    settings = make_settings(tmp_path)
    repository = JobRepository(settings)
    job = repository.create(provision_request())
    manager = JobStageManager(
        settings,
        clock=FixedClock(job.created_at),
        repository=repository,
    )
    unit = f"alt-provision-{job.job_id}.service"

    launched = manager.advance(
        job.job_id,
        "launching",
        updates={"systemd_unit": unit},
    )

    assert launched.stage == "launching"
    assert launched.state == "queued"
    assert launched.status["systemd_unit"] == unit
    assert [
        item["stage"]
        for item in launched.status["stage_history"]
    ] == ["created", "launching"]


def test_repeated_current_stage_is_byte_identical_noop(
    tmp_path: Path,
) -> None:
    settings = make_settings(tmp_path)
    repository = JobRepository(settings)
    job = repository.create(provision_request())
    manager = JobStageManager(
        settings,
        repository=repository,
    )
    manager.advance(job.job_id, "launching")

    status_path = job.job_dir / "status.json"
    before = status_path.read_bytes()

    repeated = manager.advance(
        job.job_id,
        "launching",
        updates={"state": "running"},
    )

    assert repeated.state == "queued"
    assert status_path.read_bytes() == before


def test_stage_manager_rejects_skipped_transition(
    tmp_path: Path,
) -> None:
    settings = make_settings(tmp_path)
    repository = JobRepository(settings)
    job = repository.create(provision_request())
    manager = JobStageManager(
        settings,
        repository=repository,
    )

    with pytest.raises(ControlError) as exc:
        manager.advance(job.job_id, "validating")

    assert exc.value.code == (
        "invalid_job_stage_transition"
    )
    assert repository.get(job.job_id).stage == "created"


def test_stage_manager_rejects_backward_transition(
    tmp_path: Path,
) -> None:
    settings = make_settings(tmp_path)
    repository = JobRepository(settings)
    job = repository.create(provision_request())
    manager = JobStageManager(
        settings,
        repository=repository,
    )
    manager.advance(job.job_id, "launching")

    with pytest.raises(ControlError) as exc:
        manager.advance(job.job_id, "created")

    assert exc.value.code == (
        "invalid_job_stage_transition"
    )
    assert repository.get(job.job_id).stage == (
        "launching"
    )


def test_stage_manager_rejects_later_stage_skip(
    tmp_path: Path,
) -> None:
    settings = make_settings(tmp_path)
    repository = JobRepository(settings)
    job = repository.create(provision_request())
    manager = JobStageManager(
        settings,
        repository=repository,
    )
    manager.advance(job.job_id, "launching")
    manager.advance(
        job.job_id,
        "validating",
        updates={
            "state": "running",
            "started_at": (
                "2026-07-18T12:00:00+00:00"
            ),
        },
    )
    manager.advance(job.job_id, "connecting")

    with pytest.raises(ControlError) as exc:
        manager.advance(job.job_id, "employee")

    assert exc.value.code == (
        "invalid_job_stage_transition"
    )
    assert repository.get(job.job_id).stage == (
        "connecting"
    )


def test_stage_manager_uses_common_controller_lock(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    from contextlib import contextmanager

    settings = make_settings(tmp_path)
    repository = JobRepository(settings)
    job = repository.create(provision_request())
    locked_paths: list[Path] = []

    @contextmanager
    def fake_lock(path: Path):
        locked_paths.append(path)
        yield

    monkeypatch.setattr(
        "alt_deploy.job_stages.exclusive_lock",
        fake_lock,
    )

    JobStageManager(
        settings,
        repository=repository,
    ).advance(
        job.job_id,
        "launching",
    )

    assert locked_paths == [settings.lock_file]


def test_terminal_job_rejects_repeated_stage(
    tmp_path: Path,
) -> None:
    settings = make_settings(tmp_path)
    repository = JobRepository(settings)
    job = repository.create(provision_request())
    manager = JobStageManager(
        settings,
        repository=repository,
    )
    manager.advance(job.job_id, "launching")
    repository.update(
        job.job_id,
        state="failed",
        finished_at="2026-07-18T12:00:00+00:00",
        error="launch failed",
    )

    with pytest.raises(ControlError) as exc:
        manager.advance(job.job_id, "launching")

    assert exc.value.code == "job_stage_terminal"


def test_stage_manager_rejects_unapproved_update_fields(
    tmp_path: Path,
) -> None:
    settings = make_settings(tmp_path)
    repository = JobRepository(settings)
    job = repository.create(provision_request())
    manager = JobStageManager(
        settings,
        repository=repository,
    )

    with pytest.raises(ControlError) as exc:
        manager.advance(
            job.job_id,
            "launching",
            updates={"error": "not allowed"},
        )

    assert exc.value.code == (
        "invalid_job_stage_update"
    )
```

- [ ] **Step 3: Update the existing jobs tests to use the new domain**

In `tests/alt_linux/test_jobs.py`, import:

```python
from alt_deploy.job_stages import JobStageManager
```

Replace the body of `test_update_preserves_job_identity` with:

```python
settings = make_settings(tmp_path)
repository = JobRepository(settings)
original = repository.create(provision_request())
unit = f"alt-provision-{original.job_id}.service"

updated = JobStageManager(
    settings,
    repository=repository,
).advance(
    original.job_id,
    "launching",
    updates={"systemd_unit": unit},
)

assert updated.job_id == original.job_id
assert updated.machine_uuid == MACHINE_UUID
assert updated.state == "queued"
assert updated.stage == "launching"
assert updated.status["systemd_unit"] == unit
```

Replace `test_active_for_machine_accepts_only_queued_or_running` with:

```python
def test_active_for_machine_accepts_only_queued_or_running(
    tmp_path: Path,
) -> None:
    settings = make_settings(tmp_path)
    repository = JobRepository(settings)
    job = repository.create(provision_request())
    manager = JobStageManager(
        settings,
        repository=repository,
    )

    active = repository.active_for_machine(MACHINE_UUID)
    assert active is not None
    assert active.state == "queued"

    manager.advance(job.job_id, "launching")
    manager.advance(
        job.job_id,
        "validating",
        updates={
            "state": "running",
            "started_at": (
                "2026-07-18T12:00:00+00:00"
            ),
        },
    )

    active = repository.active_for_machine(MACHINE_UUID)
    assert active is not None
    assert active.state == "running"
    assert active.stage == "validating"

    repository.update(
        job.job_id,
        state="failed",
        finished_at="2026-07-18T12:01:00+00:00",
        error="test failure",
    )

    assert repository.active_for_machine(
        MACHINE_UUID
    ) is None
```

Extend `test_create_job_uses_private_files_and_valid_id`:

```python
status = read_json(job.job_dir / "status.json")
assert status["stage"] == "created"
assert status["stage_history"] == [
    {
        "stage": "created",
        "entered_at": status["created_at"],
    }
]
```

- [ ] **Step 4: Run tests and verify RED**

```bash
.venv/bin/python -m pytest -q \
  tests/alt_linux/test_job_stages.py \
  tests/alt_linux/test_jobs.py
```

Expected: FAIL because `JobStageManager` is absent, created jobs have no
`stage_history`, and malformed real jobs are still skipped.

- [ ] **Step 5: Implement `JobStageManager`**

Append to `job_stages.py`:

```python
from collections.abc import Callable
from copy import deepcopy
from typing import TYPE_CHECKING

from .assignments import assert_safe_payload
from .config import Settings
from .jsonio import atomic_write_json
from .locks import exclusive_lock

if TYPE_CHECKING:
    from .jobs import JobRepository
    from .models import JobRecord


Clock = Callable[[], str]


def _utc_now() -> str:
    return datetime.now(timezone.utc).isoformat()


class JobStageManager:
    def __init__(
        self,
        settings: Settings,
        *,
        clock: Clock | None = None,
        repository: "JobRepository | None" = None,
    ) -> None:
        if repository is None:
            from .jobs import JobRepository

            repository = JobRepository(settings)

        self.settings = settings
        self.clock = clock or _utc_now
        self.jobs = repository

    @staticmethod
    def _validate_updates(
        updates: Mapping[str, object],
        *,
        job_id: str,
    ) -> None:
        unexpected = set(updates) - FORWARD_UPDATE_FIELDS
        if unexpected:
            raise ControlError(
                code="invalid_job_stage_update",
                message=(
                    "Provision job stage update contains "
                    "unsupported fields"
                ),
                exit_code=4,
                details={
                    "job_id": job_id,
                    "fields": sorted(unexpected),
                },
            )

    def advance_unlocked(
        self,
        job_id: str,
        next_stage: str,
        *,
        updates: Mapping[str, object] | None = None,
    ) -> "JobRecord":
        requested_updates = dict(updates or {})
        self._validate_updates(
            requested_updates,
            job_id=job_id,
        )

        job = self.jobs.get(job_id)
        validate_job_stage_status(
            job.status,
            job_id=job.job_id,
        )

        if job.state in TERMINAL_STATES:
            raise ControlError(
                code="job_stage_terminal",
                message=(
                    "Terminal provision job cannot "
                    "change stage"
                ),
                exit_code=4,
                details={"job_id": job.job_id},
            )

        if next_stage not in STAGE_INDEX:
            raise ControlError(
                code="invalid_job_stage_transition",
                message="Provision job stage is unknown",
                exit_code=4,
                details={
                    "job_id": job.job_id,
                    "stage": next_stage,
                },
            )

        if next_stage == job.stage:
            return job

        expected_index = STAGE_INDEX[job.stage] + 1
        if (
            expected_index >= len(CANONICAL_STAGES)
            or STAGE_INDEX[next_stage] != expected_index
        ):
            raise ControlError(
                code="invalid_job_stage_transition",
                message=(
                    "Provision job stage transition "
                    "is not the immediate next step"
                ),
                exit_code=4,
                details={
                    "job_id": job.job_id,
                    "current_stage": job.stage,
                    "requested_stage": next_stage,
                },
            )

        entered_at = _parse_timestamp(
            self.clock(),
            job_id=job.job_id,
        ).isoformat()

        history = deepcopy(
            job.status["stage_history"]
        )
        last_entered_at = _parse_timestamp(
            history[-1]["entered_at"],
            job_id=job.job_id,
        )

        if (
            datetime.fromisoformat(entered_at)
            < last_entered_at
        ):
            raise ControlError(
                code="job_stage_history_invalid",
                message=(
                    "Provision job stage timestamp "
                    "moves backwards"
                ),
                exit_code=4,
                details={"job_id": job.job_id},
            )

        status_payload = dict(job.status)
        history.append(
            {
                "stage": next_stage,
                "entered_at": entered_at,
            }
        )
        status_payload.update(requested_updates)
        status_payload["stage"] = next_stage
        status_payload["stage_history"] = history
        status_payload["job_id"] = job.job_id
        status_payload["machine_uuid"] = (
            job.machine_uuid
        )
        status_payload["created_at"] = job.created_at
        status_payload["updated_at"] = entered_at

        assert_safe_payload(status_payload)
        validate_job_stage_status(
            status_payload,
            job_id=job.job_id,
        )
        atomic_write_json(
            job.job_dir / "status.json",
            status_payload,
        )
        return self.jobs.get(job.job_id)

    def advance(
        self,
        job_id: str,
        next_stage: str,
        *,
        updates: Mapping[str, object] | None = None,
    ) -> "JobRecord":
        with exclusive_lock(self.settings.lock_file):
            return self.advance_unlocked(
                job_id,
                next_stage,
                updates=updates,
            )
```

- [ ] **Step 6: Integrate strict validation into `JobRepository`**

In `jobs.py`, import:

```python
from .job_stages import (
    initial_stage_history,
    validate_job_stage_status,
)
```

In `create()` add to `status_payload`:

```python
"stage_history": initial_stage_history(timestamp),
```

Immediately before writing `status.json`, call:

```python
validate_job_stage_status(
    status_payload,
    job_id=job_id,
)
```

In `_load_from_dir()`, after reading `status_payload`, call:

```python
validate_job_stage_status(
    status_payload,
    job_id=job_dir.name,
)
```

In `list()`, replace:

```python
try:
    jobs.append(
        self._load_from_dir(job_dir)
    )
except ControlError:
    continue
```

with:

```python
jobs.append(
    self._load_from_dir(job_dir)
)
```

At the beginning of `update()` add:

```python
if {"stage", "stage_history"} & set(fields):
    raise ControlError(
        code="job_stage_update_forbidden",
        message=(
            "Provision job stages must be changed "
            "through JobStageManager"
        ),
        exit_code=4,
        details={"job_id": job_id},
    )
```

Before `atomic_write_json()` in `update()`, call:

```python
validate_job_stage_status(
    status_payload,
    job_id=job.job_id,
)
```

- [ ] **Step 7: Run focused tests and repository regressions**

```bash
.venv/bin/python -m pytest -q \
  tests/alt_linux/test_job_stages.py \
  tests/alt_linux/test_jobs.py
```

Expected: PASS.

- [ ] **Step 8: Commit**

```bash
git add \
  deploy/alt-linux/control/alt_deploy/job_stages.py \
  deploy/alt-linux/control/alt_deploy/jobs.py \
  tests/alt_linux/test_job_stages.py \
  tests/alt_linux/test_jobs.py
git commit -m "feat: add strict atomic job stage transitions"
```

---

### Task 3: Integrate `created -> launching` into Provision Start

**Files:**
- Modify: `deploy/alt-linux/control/alt_deploy/provision.py`
- Modify: `tests/alt_linux/test_provision_start.py`

**Interfaces:**
- Consumes: `JobStageManager.advance_unlocked()`
- Changes: `ProvisionPlanner.start()` records `launching` and `systemd_unit` before ownership preparation and `systemd-run`.
- Launch or ownership failure sets `state=failed` without changing `stage=launching`.

- [ ] **Step 1: Update planner tests to require the launching stage**

In `tests/alt_linux/test_provision_start.py`, extend `test_provision_start_creates_and_launches_job`:

```python
stored = JobRepository(settings).get(job.job_id)
assert stored.state == "queued"
assert stored.stage == "launching"
assert [
    item["stage"]
    for item in stored.status["stage_history"]
] == ["created", "launching"]
assert stored.status["systemd_unit"] == (
    f"alt-provision-{job.job_id}.service"
)
```

Replace the launch-failure stage assertion in `test_launch_failure_is_persisted`:

```python
jobs = JobRepository(settings).list()
assert len(jobs) == 1
assert jobs[0].state == "failed"
assert jobs[0].stage == "launching"
assert [
    item["stage"]
    for item in jobs[0].status["stage_history"]
] == ["created", "launching"]
```

Add:

```python
def test_launching_stage_is_persisted_before_launcher_runs(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    settings = prepare_preview_environment(tmp_path)
    monkeypatch.setattr(
        "alt_deploy.provision.os.geteuid",
        lambda: 0,
    )

    class InspectingLauncher:
        def launch(self, job_id: str) -> str:
            stored = JobRepository(settings).get(job_id)
            assert stored.stage == "launching"
            assert stored.status["systemd_unit"] == (
                f"alt-provision-{job_id}.service"
            )
            return f"alt-provision-{job_id}.service"

    planner = ProvisionPlanner(
        settings,
        launcher=InspectingLauncher(),
    )
    job = planner.start(
        MACHINE_UUID,
        parsed_request(),
    )

    assert job.stage == "launching"
```

- [ ] **Step 2: Run focused tests and verify RED**

```bash
.venv/bin/python -m pytest -q \
  tests/alt_linux/test_provision_start.py
```

Expected: FAIL because start still writes `systemd_unit` through `JobRepository.update()` and launch failure still tries to set `stage=launch`.

- [ ] **Step 3: Integrate the stage manager**

In `ProvisionPlanner.__init__()`:

```python
from .job_stages import JobStageManager
```

```python
self.stages = JobStageManager(
    settings,
    repository=self.jobs,
)
```

In `start()`, replace this current block:

```python
job = self.jobs.update(
    job.job_id,
    systemd_unit=expected_systemd_unit,
)
```

with:

```python
job = self.stages.advance_unlocked(
    job.job_id,
    "launching",
    updates={
        "systemd_unit": expected_systemd_unit,
    },
)
```

Replace launch-failure persistence with:

```python
failed_job = self.jobs.update(
    job.job_id,
    state="failed",
    finished_at=utc_now(),
    error=error_text,
)
```

Do not pass `stage` to `JobRepository.update()`.

- [ ] **Step 4: Run planner tests and related CLI tests**

```bash
.venv/bin/python -m pytest -q \
  tests/alt_linux/test_provision_start.py \
  tests/alt_linux/test_job_stages.py \
  tests/alt_linux/test_registry_cli.py
```

Expected: PASS.

- [ ] **Step 5: Commit**

```bash
git add \
  deploy/alt-linux/control/alt_deploy/provision.py \
  tests/alt_linux/test_provision_start.py
git commit -m "feat: record provision launching stage"
```

---

### Task 4: Integrate Worker Stages and Preserve Failure Location

**Files:**
- Modify: `deploy/alt-linux/control/alt_deploy/worker.py`
- Modify: `tests/alt_linux/test_worker.py`

**Interfaces:**
- Consumes: `JobStageManager.advance()`
- Worker sequence: `launching -> validating -> connecting`, Ansible markers through `verifying`, then `recording -> complete`.
- `launching -> validating` atomically sets `state=running` and `started_at`.
- `recording -> complete` atomically sets `state=successful`, `finished_at`, and `result_file`.
- Failure update changes state/error/timestamps only and preserves the current stage.

- [ ] **Step 1: Make fake controllers advance through Ansible-owned stages**

In `tests/alt_linux/test_worker.py`, add:

```python
from alt_deploy.job_stages import JobStageManager


def advance_ansible_stages(settings, job_id: str) -> None:
    manager = JobStageManager(settings)
    for stage in (
        "identity",
        "employee",
        "login_screen",
        "verifying",
    ):
        manager.advance(job_id, stage)
```

Change `SuccessfulController`:

```python
class SuccessfulController:
    def __init__(self, settings) -> None:
        self.settings = settings
        self.received_job_id = ""

    def run_provision(
        self,
        job,
        log_stream: TextIO,
    ) -> dict[str, Any]:
        self.received_job_id = job.job_id
        advance_ansible_stages(
            self.settings,
            job.job_id,
        )
        log_stream.write(
            "TASK [local_employee : Create employee]\n"
        )
        log_stream.flush()
        return successful_result(job.job_id)
```

Replace `FailedVerificationController` with:

```python
class FailedVerificationController:
    def __init__(self, settings) -> None:
        self.settings = settings

    def run_provision(
        self,
        job,
        log_stream: TextIO,
    ) -> dict[str, Any]:
        advance_ansible_stages(
            self.settings,
            job.job_id,
        )
        result = successful_result(job.job_id)
        result["verification"]["hostname"] = False
        log_stream.write(
            "Provision returned failed verification\n"
        )
        log_stream.flush()
        return result
```

Instantiate it with `FailedVerificationController(settings)`.

Create a controller for recording failure:

```python
class RecordingResultController:
    def __init__(self, settings) -> None:
        self.settings = settings

    def run_provision(
        self,
        job,
        log_stream: TextIO,
    ) -> dict[str, Any]:
        advance_ansible_stages(
            self.settings,
            job.job_id,
        )
        return successful_result(job.job_id)
```

- [ ] **Step 2: Update worker lifecycle tests**

Before each direct `run_job()` call, put the created job into `launching`:

```python
JobStageManager(settings).advance(
    job.job_id,
    "launching",
    updates={
        "systemd_unit": (
            f"alt-provision-{job.job_id}.service"
        )
    },
)
```

In the success test require:

```python
controller = SuccessfulController(settings)
result_code = run_job(
    job.job_id,
    settings,
    controller,
)

stored_job = jobs.get(job.job_id)
assert stored_job.state == "successful"
assert stored_job.stage == "complete"
assert [
    item["stage"]
    for item in stored_job.status["stage_history"]
] == [
    "created",
    "launching",
    "validating",
    "connecting",
    "identity",
    "employee",
    "login_screen",
    "verifying",
    "recording",
    "complete",
]
```

In generic controller failure, assert:

```python
assert stored_job.state == "failed"
assert stored_job.stage == "connecting"
assert [
    item["stage"]
    for item in stored_job.status["stage_history"]
] == [
    "created",
    "launching",
    "validating",
    "connecting",
]
```

In failed result verification, assert final stage `verifying`.

Add assignment-write failure:

```python
def test_assignment_failure_remains_at_recording(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    settings = prepare_preview_environment(tmp_path)
    jobs = JobRepository(settings)
    job = jobs.create(valid_request())
    JobStageManager(settings).advance(
        job.job_id,
        "launching",
        updates={
            "systemd_unit": (
                f"alt-provision-{job.job_id}.service"
            )
        },
    )

    def fail_assignment(self, machine_uuid, payload):
        raise ControlError(
            code="assignment_write_failed",
            message="fixture assignment failure",
            exit_code=7,
        )

    monkeypatch.setattr(
        "alt_deploy.worker.AssignmentRepository.write",
        fail_assignment,
    )

    rc = run_job(
        job.job_id,
        settings,
        RecordingResultController(settings),
    )

    assert rc == 1
    stored = jobs.get(job.job_id)
    assert stored.state == "failed"
    assert stored.stage == "recording"
    result_path = job.job_dir / "result.json"
    assert result_path.is_file()
    assert read_json(result_path) == successful_result(
        job.job_id
    )
    assert AssignmentRepository(settings).get(
        MACHINE_UUID
    ) is None
```

The worker enters `recording` before writing `result.json`; therefore an assignment-write failure must preserve the validated result file while leaving the controller assignment absent.

- [ ] **Step 3: Run focused tests and verify RED**

```bash
.venv/bin/python -m pytest -q \
  tests/alt_linux/test_worker.py
```

Expected: FAIL because the worker still writes `stage=ansible`, skips the canonical sequence, and failure handling overwrites the stage.

- [ ] **Step 4: Implement worker transitions**

In `run_job()` create:

```python
stages = JobStageManager(
    settings,
    repository=jobs,
)
```

After verifying the job is queued and before machine lookup:

```python
started_at = utc_now()
job = stages.advance(
    job.job_id,
    "validating",
    updates={
        "state": "running",
        "started_at": started_at,
    },
)
```

After machine lookup and IP validation, immediately before `controller.run_provision()`:

```python
job = stages.advance(
    job.job_id,
    "connecting",
)
```

After `_validate_result()` succeeds:

```python
job = stages.advance(
    job.job_id,
    "recording",
)
```

After `result.json` and assignment writes:

```python
finished_at = utc_now()
stages.advance(
    job.job_id,
    "complete",
    updates={
        "state": "successful",
        "finished_at": finished_at,
        "result_file": str(
            job.job_dir / "result.json"
        ),
    },
)
```

Replace failure update:

```python
with exclusive_lock(settings.lock_file):
    current = jobs.get(job.job_id)
    if current.state not in {"successful", "failed"}:
        jobs.update(
            current.job_id,
            state="failed",
            finished_at=utc_now(),
            error=error_text,
        )
```

Do not pass `stage` in failure handling.

Import:

```python
from .job_stages import JobStageManager
from .locks import exclusive_lock
```

- [ ] **Step 5: Run worker and stage-domain tests**

```bash
.venv/bin/python -m pytest -q \
  tests/alt_linux/test_worker.py \
  tests/alt_linux/test_job_stages.py \
  tests/alt_linux/test_provision_start.py
```

Expected: PASS.

- [ ] **Step 6: Commit**

```bash
git add \
  deploy/alt-linux/control/alt_deploy/worker.py \
  tests/alt_linux/test_worker.py
git commit -m "feat: track structured provision worker stages"
```

---

### Task 5: Add the Internal Stage Helper and Install Contract

**Files:**
- Modify: `deploy/alt-linux/control/alt_deploy/config.py`
- Create: `deploy/alt-linux/control/alt_deploy/job_stage_helper.py`
- Create: `deploy/alt-linux/control/alt-job-stage`
- Modify: `deploy/alt-linux/install-control-plane.sh`
- Create: `tests/alt_linux/test_job_stage_helper.py`
- Modify: `tests/alt_linux/test_registry_cli.py`
- Modify: `tests/alt_linux/test_install_assets.py`

**Interfaces:**
- Adds setting: `job_stage_helper_path: Path`
- Adds environment variable: `ALT_DEPLOY_JOB_STAGE_HELPER`
- Produces parser arguments: required `--job-id`; required `--stage` is validated against `CANONICAL_STAGES` by `JobStageManager` so unknown-stage errors use the same JSON error contract
- Produces success payload type: `dict[str, object]` with exact keys `status`, `job_id`, `stage`, and `changed`
- Installs helper at `/usr/local/libexec/alt-job-stage`.

- [ ] **Step 1: Extend Settings fixtures with the helper path**

In `config.py` add the dataclass field after `worker_path`:

```python
job_stage_helper_path: Path
```

In `Settings.from_env()` add:

```python
job_stage_helper_path=Path(
    os.environ.get(
        "ALT_DEPLOY_JOB_STAGE_HELPER",
        "/usr/local/libexec/alt-job-stage",
    )
),
```

In `tests/alt_linux/test_registry_cli.py::make_settings` add:

```python
job_stage_helper_path=(
    tmp_path / "alt-job-stage"
),
```

In `tests/alt_linux/test_config.py`, extend the expected `Settings.from_env()` contract:

```python
monkeypatch.setenv(
    "ALT_DEPLOY_JOB_STAGE_HELPER",
    str(tmp_path / "alt-job-stage"),
)
settings = Settings.from_env()
assert settings.job_stage_helper_path == (
    tmp_path / "alt-job-stage"
)
```

`make_settings()` is the shared constructor used by the remaining ALT tests, so no other direct `Settings(...)` fixture needs a field update.

- [ ] **Step 2: Write failing helper tests**

Create `tests/alt_linux/test_job_stage_helper.py`:

```python
from __future__ import annotations

import io
import json
from pathlib import Path

from alt_deploy.job_stage_helper import main
from alt_deploy.job_stages import JobStageManager
from alt_deploy.jobs import JobRepository

from test_jobs import provision_request
from test_registry_cli import make_settings


def test_helper_advances_allowlisted_stage(
    tmp_path: Path,
) -> None:
    settings = make_settings(tmp_path)
    job = JobRepository(settings).create(
        provision_request()
    )
    JobStageManager(settings).advance(
        job.job_id,
        "launching",
    )
    JobStageManager(settings).advance(
        job.job_id,
        "validating",
        updates={
            "state": "running",
            "started_at": (
                "2026-07-18T12:00:00+00:00"
            ),
        },
    )
    JobStageManager(settings).advance(
        job.job_id,
        "connecting",
    )

    stdout = io.StringIO()
    rc = main(
        [
            "--job-id",
            job.job_id,
            "--stage",
            "identity",
        ],
        settings=settings,
        stdout=stdout,
        stderr=io.StringIO(),
    )

    assert rc == 0
    payload = json.loads(stdout.getvalue())
    assert payload == {
        "status": "ok",
        "job_id": job.job_id,
        "stage": "identity",
        "changed": True,
    }


def test_helper_repeated_stage_reports_no_change(
    tmp_path: Path,
) -> None:
    settings = make_settings(tmp_path)
    job = JobRepository(settings).create(
        provision_request()
    )
    manager = JobStageManager(settings)
    manager.advance(job.job_id, "launching")

    before = (
        job.job_dir / "status.json"
    ).read_bytes()
    stdout = io.StringIO()

    rc = main(
        [
            "--job-id",
            job.job_id,
            "--stage",
            "launching",
        ],
        settings=settings,
        stdout=stdout,
        stderr=io.StringIO(),
    )

    assert rc == 0
    assert json.loads(stdout.getvalue())["changed"] is False
    assert (
        job.job_dir / "status.json"
    ).read_bytes() == before


def test_helper_rejects_invalid_transition_as_json(
    tmp_path: Path,
) -> None:
    settings = make_settings(tmp_path)
    job = JobRepository(settings).create(
        provision_request()
    )
    stdout = io.StringIO()

    rc = main(
        [
            "--job-id",
            job.job_id,
            "--stage",
            "identity",
        ],
        settings=settings,
        stdout=stdout,
        stderr=io.StringIO(),
    )

    assert rc == 4
    payload = json.loads(stdout.getvalue())
    assert payload["error"]["code"] == (
        "invalid_job_stage_transition"
    )


def test_helper_rejects_unknown_stage_as_json(
    tmp_path: Path,
) -> None:
    settings = make_settings(tmp_path)
    job = JobRepository(settings).create(
        provision_request()
    )
    stdout = io.StringIO()

    rc = main(
        [
            "--job-id",
            job.job_id,
            "--stage",
            "arbitrary-stage",
        ],
        settings=settings,
        stdout=stdout,
        stderr=io.StringIO(),
    )

    assert rc == 4
    payload = json.loads(stdout.getvalue())
    assert payload["error"]["code"] == (
        "invalid_job_stage_transition"
    )
    assert set(payload["error"]) <= {
        "code",
        "message",
        "details",
    }


def test_helper_rejects_unknown_job_as_json(
    tmp_path: Path,
) -> None:
    settings = make_settings(tmp_path)
    stdout = io.StringIO()

    rc = main(
        [
            "--job-id",
            "job-20260718T120000Z-deadbeef",
            "--stage",
            "launching",
        ],
        settings=settings,
        stdout=stdout,
        stderr=io.StringIO(),
    )

    assert rc == 3
    payload = json.loads(stdout.getvalue())
    assert payload["error"]["code"] == "job_not_found"
```

- [ ] **Step 3: Run tests and verify RED**

```bash
.venv/bin/python -m pytest -q \
  tests/alt_linux/test_job_stage_helper.py
```

Expected: FAIL because `alt_deploy.job_stage_helper` does not exist.

- [ ] **Step 4: Implement helper module and wrapper**

Create `job_stage_helper.py`:

```python
from __future__ import annotations

import argparse
import json
import sys
from collections.abc import Sequence
from typing import TextIO

from .config import Settings
from .errors import ControlError
from .job_stages import JobStageManager


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="alt-job-stage"
    )
    parser.add_argument("--job-id", required=True)
    parser.add_argument(
        "--stage",
        required=True,
    )
    return parser


def _write_json(
    stream: TextIO,
    payload: dict[str, object],
) -> None:
    stream.write(
        json.dumps(
            payload,
            ensure_ascii=False,
            separators=(",", ":"),
        )
        + "\n"
    )


def main(
    argv: Sequence[str] | None = None,
    *,
    settings: Settings | None = None,
    stdout: TextIO = sys.stdout,
    stderr: TextIO = sys.stderr,
) -> int:
    parsed = build_parser().parse_args(
        list(argv) if argv is not None else None
    )
    active_settings = settings or Settings.from_env()
    manager = JobStageManager(active_settings)

    try:
        before = manager.jobs.get(parsed.job_id)
        after = manager.advance(
            parsed.job_id,
            parsed.stage,
        )
    except ControlError as exc:
        _write_json(stdout, exc.to_dict())
        return exc.exit_code

    _write_json(
        stdout,
        {
            "status": "ok",
            "job_id": after.job_id,
            "stage": after.stage,
            "changed": (
                before.status != after.status
            ),
        },
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
```

Create `deploy/alt-linux/control/alt-job-stage`:

```python
#!/usr/bin/python3

from __future__ import annotations

import sys
from pathlib import Path

sys.path.insert(
    0,
    str(Path("/opt/alt-deploy-control")),
)

from alt_deploy.job_stage_helper import main

raise SystemExit(main())
```

- [ ] **Step 5: Update installer and installation tests**

In `install-control-plane.sh`, next to the worker install:

```bash
install -o root -g root -m 0755 \
    "${ALT_ROOT}/control/alt-job-stage" \
    /usr/local/libexec/alt-job-stage
```

Extend installer verification so it compiles both the installed package and
the helper wrapper source before service restart:

```bash
python3 -m py_compile \
    /opt/alt-deploy-control/alt_deploy/*.py \
    /opt/alt-deploy-api/process_pending.py \
    "${ALT_ROOT}/control/alt-job-stage"
```

In `tests/alt_linux/test_install_assets.py`, require the literal source and destination paths and mode `0755`:

```python
assert '"${ALT_ROOT}/control/alt-job-stage"' in installer
assert "/usr/local/libexec/alt-job-stage" in installer
assert "python3 -m py_compile" in installer
assert '"${ALT_ROOT}/control/alt-job-stage"' in installer
```

- [ ] **Step 6: Run helper, config, and installer tests**

```bash
.venv/bin/python -m pytest -q \
  tests/alt_linux/test_job_stage_helper.py \
  tests/alt_linux/test_config.py \
  tests/alt_linux/test_registry_cli.py \
  tests/alt_linux/test_install_assets.py
```

Expected: PASS.

- [ ] **Step 7: Commit**

```bash
git add \
  deploy/alt-linux/control/alt_deploy/config.py \
  deploy/alt-linux/control/alt_deploy/job_stage_helper.py \
  deploy/alt-linux/control/alt-job-stage \
  deploy/alt-linux/install-control-plane.sh \
  tests/alt_linux/test_job_stage_helper.py \
  tests/alt_linux/test_registry_cli.py \
  tests/alt_linux/test_install_assets.py
git commit -m "feat: add internal provision stage helper"
```

---

### Task 6: Add Explicit Ansible Stage Markers

**Files:**
- Modify: `deploy/alt-linux/control/alt_deploy/ansible.py`
- Modify: `deploy/alt-linux/ansible/playbooks/02-provision-account.yml`
- Modify: `tests/alt_linux/test_worker.py`
- Modify: `tests/alt_linux/test_ansible_assets.py`

**Interfaces:**
- `AnsibleController._validate_provision_files()` requires `settings.job_stage_helper_path`.
- `run_provision()` passes the exact extra-var string `job_stage_helper_path=/usr/local/libexec/alt-job-stage` in production and the configured fixture path in tests.
- Playbook replaces top-level `roles:` with ordered marker and `include_role` tasks.

- [ ] **Step 1: Write failing command/precheck tests**

Extend `tests/alt_linux/test_worker.py::test_ansible_run_provision_uses_safe_command`:

```python
settings.job_stage_helper_path.write_text(
    "#!/usr/bin/python3\n",
    encoding="utf-8",
)
settings.job_stage_helper_path.chmod(0o755)
```

Add to command assertions:

```python
assert (
    f"job_stage_helper_path="
    f"{settings.job_stage_helper_path}"
) in command
```

Add:

```python
def test_run_provision_requires_stage_helper_before_ansible(
    tmp_path: Path,
) -> None:
    settings = prepare_preview_environment(tmp_path)
    settings.private_key_file.write_text(
        "private fixture",
        encoding="utf-8",
    )
    settings.known_hosts_file.write_text(
        "host key fixture",
        encoding="utf-8",
    )
    playbook = (
        settings.ansible_project_dir
        / "playbooks"
        / "02-provision-account.yml"
    )
    playbook.parent.mkdir(
        parents=True,
        exist_ok=True,
    )
    playbook.write_text("---\n", encoding="utf-8")

    job = JobRepository(settings).create(
        valid_request()
    )

    with pytest.raises(ControlError) as exc:
        with (
            job.job_dir / "ansible.log"
        ).open("a", encoding="utf-8") as log_stream:
            AnsibleController(
                settings
            ).run_provision(job, log_stream)

    assert exc.value.code == "provision_not_configured"
    assert any(
        item["name"] == "job_stage_helper"
        for item in exc.value.details["missing"]
    )
```

- [ ] **Step 2: Write failing static playbook marker test**

In `tests/alt_linux/test_ansible_assets.py`, parse `02-provision-account.yml` and require the task sequence:

```python
play = load_yaml(
    "deploy/alt-linux/ansible/playbooks/"
    "02-provision-account.yml"
)[0]
tasks = play["tasks"]

expected = [
    ("Record identity provision stage", "identity"),
    ("Run workstation identity role", "workstation_identity"),
    ("Record employee provision stage", "employee"),
    ("Run local employee role", "local_employee"),
    ("Record login screen provision stage", "login_screen"),
    ("Run LightDM accounts role", "lightdm_accounts"),
    ("Record verification provision stage", "verifying"),
    ("Run provision verification role", "provision_verify"),
]

observed = []
for task in tasks:
    if "ansible.builtin.command" in task:
        argv = task["ansible.builtin.command"]["argv"]
        observed.append((task["name"], argv[-1]))
        assert task["delegate_to"] == "localhost"
        assert task["become"] is False
        assert task["run_once"] is True
        assert task["changed_when"] is False
    else:
        observed.append(
            (
                task["name"],
                task["ansible.builtin.include_role"]["name"],
            )
        )

assert observed == expected
assert "roles" not in play
```

- [ ] **Step 3: Run focused tests and verify RED**

```bash
.venv/bin/python -m pytest -q \
  tests/alt_linux/test_worker.py::test_ansible_run_provision_uses_safe_command \
  tests/alt_linux/test_worker.py::test_run_provision_requires_stage_helper_before_ansible \
  tests/alt_linux/test_ansible_assets.py
```

Expected: FAIL because the helper is not checked/passed and the playbook still uses `roles:`.

- [ ] **Step 4: Update Ansible controller**

In `_validate_provision_files()` add:

```python
"job_stage_helper": (
    self.settings.job_stage_helper_path
),
```

In the command list before `str(self.provision_playbook)` add:

```python
"-e",
(
    "job_stage_helper_path="
    f"{self.settings.job_stage_helper_path}"
),
```

- [ ] **Step 5: Replace playbook roles with markers and includes**

Keep `vars_files` and `pre_tasks`. Replace `roles:` with:

```yaml
  tasks:
    - name: Record identity provision stage
      ansible.builtin.command:
        argv:
          - "{{ job_stage_helper_path }}"
          - --job-id
          - "{{ job_id }}"
          - --stage
          - identity
      delegate_to: localhost
      become: false
      run_once: true
      changed_when: false

    - name: Run workstation identity role
      ansible.builtin.include_role:
        name: workstation_identity

    - name: Record employee provision stage
      ansible.builtin.command:
        argv:
          - "{{ job_stage_helper_path }}"
          - --job-id
          - "{{ job_id }}"
          - --stage
          - employee
      delegate_to: localhost
      become: false
      run_once: true
      changed_when: false

    - name: Run local employee role
      ansible.builtin.include_role:
        name: local_employee

    - name: Record login screen provision stage
      ansible.builtin.command:
        argv:
          - "{{ job_stage_helper_path }}"
          - --job-id
          - "{{ job_id }}"
          - --stage
          - login_screen
      delegate_to: localhost
      become: false
      run_once: true
      changed_when: false

    - name: Run LightDM accounts role
      ansible.builtin.include_role:
        name: lightdm_accounts

    - name: Record verification provision stage
      ansible.builtin.command:
        argv:
          - "{{ job_stage_helper_path }}"
          - --job-id
          - "{{ job_id }}"
          - --stage
          - verifying
      delegate_to: localhost
      become: false
      run_once: true
      changed_when: false

    - name: Run provision verification role
      ansible.builtin.include_role:
        name: provision_verify
```

Add to the pre-task assertion:

```yaml
- job_stage_helper_path | length > 0
```

- [ ] **Step 6: Run Python tests and playbook syntax**

```bash
.venv/bin/python -m pytest -q \
  tests/alt_linux/test_worker.py \
  tests/alt_linux/test_ansible_assets.py \
  tests/alt_linux/test_job_stage_helper.py

ANSIBLE_CONFIG="$PWD/deploy/alt-linux/ansible/ansible.cfg" \
  ansible-playbook --syntax-check \
  deploy/alt-linux/ansible/playbooks/02-provision-account.yml
```

Expected: tests PASS and syntax check prints the playbook path.

- [ ] **Step 7: Commit**

```bash
git add \
  deploy/alt-linux/control/alt_deploy/ansible.py \
  deploy/alt-linux/ansible/playbooks/02-provision-account.yml \
  tests/alt_linux/test_worker.py \
  tests/alt_linux/test_ansible_assets.py
git commit -m "feat: mark Ansible provision role stages"
```

---

### Task 7: Make Reconciliation Preserve and Recover Structured Stages

**Files:**
- Modify: `deploy/alt-linux/control/alt_deploy/job_reconcile.py`
- Modify: `tests/alt_linux/test_job_reconcile.py`

**Interfaces:**
- Reconciliation never writes `stage=reconcile`.
- Queued missing-worker failure preserves `created` or `launching`.
- Running worker loss and result rejection preserve the current stage.
- Result recovery is accepted only from `state=running, stage=recording`.
- Successful recovery performs `recording -> complete` through `JobStageManager.advance_unlocked()`.

- [ ] **Step 1: Add a valid-history fixture and replace direct stage mutation**

At the top of `tests/alt_linux/test_job_reconcile.py`, add `pytest`, `ControlError`, and the stage manager imports:

```python
import pytest

from alt_deploy.errors import ControlError
from alt_deploy.job_stages import JobStageManager
```

Add this helper below `_systemctl_result()`:

```python
def advance_to_stage(
    settings,
    job_id: str,
    target: str,
) -> None:
    manager = JobStageManager(settings)
    sequence = (
        "launching",
        "validating",
        "connecting",
        "identity",
        "employee",
        "login_screen",
        "verifying",
        "recording",
    )

    for stage in sequence:
        current = manager.jobs.get(job_id)
        if current.stage == target:
            return

        updates = None
        if stage == "validating":
            updates = {
                "state": "running",
                "started_at": (
                    "2026-07-18T12:00:00+00:00"
                ),
            }

        manager.advance(
            job_id,
            stage,
            updates=updates,
        )

        if stage == target:
            return

    raise AssertionError(
        f"Unable to advance {job_id} to {target}"
    )
```

Replace each direct fixture update of `state="running", stage="ansible"` with:

```python
advance_to_stage(
    settings,
    created.job_id,
    "employee",
)
running = jobs.get(created.job_id)
```

For queued jobs with a recorded unit, advance only to `launching` while recording the exact unit atomically:

```python
queued = JobStageManager(
    settings,
    repository=jobs,
).advance(
    created.job_id,
    "launching",
    updates={"systemd_unit": unit_name},
)
```

For running fixtures, set `systemd_unit` during `created -> launching`, then advance through `validating` to the test's intended stage:

```python
manager = JobStageManager(
    settings,
    repository=jobs,
)
manager.advance(
    created.job_id,
    "launching",
    updates={"systemd_unit": unit_name},
)
advance_to_stage(
    settings,
    created.job_id,
    "employee",
)
running = jobs.get(created.job_id)
```

- [ ] **Step 2: Require stage preservation and recording-only recovery**

Change the existing missing-running-worker assertions to:

```python
reconciled = jobs.get(running.job_id)
assert reconciled.state == "failed"
assert reconciled.stage == "employee"
assert reconciled.status["error_code"] == "worker_lost"
assert [
    item["stage"]
    for item in reconciled.status["stage_history"]
][-1] == "employee"
```

Change the queued-without-unit assertions to:

```python
reconciled = jobs.get(queued.job_id)
assert reconciled.state == "failed"
assert reconciled.stage == "created"
assert reconciled.status["error_code"] == (
    "worker_not_started"
)
```

Change the queued-with-recorded-missing-unit assertions to:

```python
reconciled = jobs.get(queued.job_id)
assert reconciled.state == "failed"
assert reconciled.stage == "launching"
assert reconciled.status["error_code"] == (
    "worker_not_started"
)
assert reconciled.status["systemd_unit"] == unit_name
```

For the existing valid-result recovery test, construct a recording-stage job:

```python
manager = JobStageManager(
    settings,
    repository=jobs,
)
manager.advance(
    created.job_id,
    "launching",
    updates={"systemd_unit": unit_name},
)
advance_to_stage(
    settings,
    created.job_id,
    "recording",
)
running = jobs.get(created.job_id)
result = successful_result(running.job_id)
atomic_write_json(
    running.job_dir / "result.json",
    result,
)
```

After reconciliation require:

```python
recovered = jobs.get(running.job_id)
assert recovered.state == "successful"
assert recovered.stage == "complete"
assert [
    item["stage"]
    for item in recovered.status["stage_history"]
][-2:] == ["recording", "complete"]
assert recovered.status["finished_at"] == (
    result["completed_at"]
)
assert recovered.status["result_file"] == str(
    running.job_dir / "result.json"
)
```

Add a test proving that an otherwise valid result cannot be recovered before `recording`:

```python
def test_jobs_reconcile_rejects_result_before_recording(
    monkeypatch,
    tmp_path: Path,
) -> None:
    settings = make_settings(tmp_path)
    jobs = JobRepository(settings)
    created = jobs.create(provision_request())
    unit_name = f"alt-provision-{created.job_id}.service"
    manager = JobStageManager(
        settings,
        repository=jobs,
    )
    manager.advance(
        created.job_id,
        "launching",
        updates={"systemd_unit": unit_name},
    )
    advance_to_stage(
        settings,
        created.job_id,
        "verifying",
    )
    running = jobs.get(created.job_id)
    atomic_write_json(
        running.job_dir / "result.json",
        successful_result(running.job_id),
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
        return _systemctl_result(
            command,
            unit_name=unit_name,
            load_state="not-found",
            active_state="inactive",
            sub_state="dead",
        )

    monkeypatch.setattr(
        subprocess,
        "run",
        fake_systemctl,
    )

    with pytest.raises(ControlError) as exc:
        JobReconciler(settings).reconcile()

    assert exc.value.code == (
        "job_reconcile_invalid_stage"
    )
    assert jobs.get(running.job_id).stage == "verifying"
    assert AssignmentRepository(settings).get(
        running.machine_uuid
    ) is None
```

For malformed or failed-result tests in the same file, advance the fixture to `verifying` and assert the resulting failed job remains at `verifying`.

- [ ] **Step 3: Run reconciliation tests and verify RED**

```bash
.venv/bin/python -m pytest -q \
  tests/alt_linux/test_job_reconcile.py
```

Expected: FAIL because reconciliation still writes `stage=reconcile` and recovers from any running stage.

- [ ] **Step 4: Implement stage-preserving reconciliation**

In `JobReconciler.__init__()`:

```python
from .job_stages import JobStageManager
```

```python
self.stages = JobStageManager(
    settings,
    repository=self.jobs,
)
```

Remove `stage="reconcile"` from `_reconcile_queued()`, `_reject_result()`, and `_reconcile_running()` updates.

At the start of `_recover_result()` after confirming worker inactivity and result existence:

```python
if job.stage != "recording":
    raise ControlError(
        code="job_reconcile_invalid_stage",
        message=(
            "Provision result recovery requires "
            "stage=recording"
        ),
        exit_code=4,
        details={
            "job_id": job.job_id,
            "stage": job.stage,
        },
    )
```

Replace the current successful recovery update:

```python
self.jobs.update(
    job.job_id,
    state="successful",
    stage="complete",
    finished_at=str(result["completed_at"]),
    result_file=str(result_path),
)
```

with:

```python
self.stages.advance_unlocked(
    job.job_id,
    "complete",
    updates={
        "state": "successful",
        "finished_at": str(
            result["completed_at"]
        ),
        "result_file": str(result_path),
    },
)
```

`reconcile()` already holds the common lock, so use the unlocked stage method.

- [ ] **Step 5: Run reconciliation and worker regressions**

```bash
.venv/bin/python -m pytest -q \
  tests/alt_linux/test_job_reconcile.py \
  tests/alt_linux/test_worker.py \
  tests/alt_linux/test_job_stages.py
```

Expected: PASS.

- [ ] **Step 6: Commit**

```bash
git add \
  deploy/alt-linux/control/alt_deploy/job_reconcile.py \
  tests/alt_linux/test_job_reconcile.py
git commit -m "feat: preserve stages during job reconciliation"
```

---

### Task 8: Prove Retention and Machine Reads Fail Closed

**Files:**
- Modify: `tests/alt_linux/test_job_retention.py`
- Modify: `tests/alt_linux/test_registry_cli.py`

**Interfaces:**
- Retention behavior remains 90/14 days.
- Active jobs remain protected.
- Malformed real job history raises `job_stage_history_invalid`; it is not classified, skipped, deleted, or repaired.
- Machine list/show also fails closed instead of omitting a malformed active job.

- [ ] **Step 1: Replace raw retention status mutation with valid stage helpers**

In `tests/alt_linux/test_job_retention.py`, import:

```python
from alt_deploy.job_stages import JobStageManager
```

Replace `_set_status()` with these helpers:

```python
def _advance_to_stage(
    settings,
    job_id: str,
    target: str,
) -> None:
    manager = JobStageManager(settings)
    for stage in (
        "launching",
        "validating",
        "connecting",
        "identity",
        "employee",
        "login_screen",
        "verifying",
        "recording",
    ):
        current = manager.jobs.get(job_id)
        if current.stage == target:
            return

        updates = None
        if stage == "validating":
            updates = {
                "state": "running",
                "started_at": current.updated_at,
            }

        manager.advance(
            job_id,
            stage,
            updates=updates,
        )

        if stage == target:
            return

    raise AssertionError(
        f"Unable to advance {job_id} to {target}"
    )


def _finish_job(
    settings,
    job_id: str,
    *,
    state: str,
    finished_at: str,
) -> None:
    manager = JobStageManager(settings)

    if state == "successful":
        _advance_to_stage(
            settings,
            job_id,
            "recording",
        )
        current = manager.jobs.get(job_id)
        manager.advance(
            job_id,
            "complete",
            updates={
                "state": "successful",
                "finished_at": finished_at,
                "result_file": str(
                    current.job_dir / "result.json"
                ),
            },
        )
        return

    if state != "failed":
        raise AssertionError(
            f"Unsupported terminal fixture state: {state}"
        )

    _advance_to_stage(
        settings,
        job_id,
        "verifying",
    )
    manager.jobs.update(
        job_id,
        state="failed",
        finished_at=finished_at,
        error="fixture failure",
    )


def _set_created_at(
    job,
    created_at: str,
) -> None:
    status = read_json(
        job.job_dir / "status.json"
    )
    status["created_at"] = created_at
    atomic_write_json(
        job.job_dir / "status.json",
        status,
    )
```

Replace the terminal fixture calls in all three retention tests:

```python
_finish_job(
    settings,
    expired.job_id,
    state="successful",
    finished_at=(
        now - timedelta(days=120)
    ).isoformat(),
)
```

```python
_finish_job(
    settings,
    archivable.job_id,
    state="failed",
    finished_at=(
        now - timedelta(days=30)
    ).isoformat(),
)
```

```python
_finish_job(
    settings,
    recent.job_id,
    state="successful",
    finished_at=(
        now - timedelta(days=5)
    ).isoformat(),
)
```

For the old queued active fixture, leave its stage at `created` and only set the
retention-independent creation timestamp:

```python
_set_created_at(
    active,
    (
        now - timedelta(days=400)
    ).isoformat(),
)
```

For the old running active fixture, advance to `validating` and then set the old
creation timestamp:

```python
_advance_to_stage(
    settings,
    active.job_id,
    "validating",
)
_set_created_at(
    active,
    (
        now - timedelta(days=400)
    ).isoformat(),
)
```

- [ ] **Step 2: Add malformed-history fail-closed tests**

Add to `test_job_retention.py`:

```python
def test_cleanup_fails_closed_on_malformed_real_job(
    tmp_path: Path,
) -> None:
    settings = make_settings(tmp_path)
    jobs = JobRepository(settings)
    job = jobs.create(provision_request())
    status = read_json(job.job_dir / "status.json")
    status.pop("stage_history")
    atomic_write_json(job.job_dir / "status.json", status)

    with pytest.raises(ControlError) as exc:
        JobRetentionManager(settings).cleanup(
            apply=False,
            now=datetime(
                2026,
                7,
                18,
                12,
                0,
                tzinfo=timezone.utc,
            ),
        )

    assert exc.value.code == "job_stage_history_invalid"
    assert job.job_dir.is_dir()
```

Add to `test_registry_cli.py`:

```python
def test_machine_list_fails_closed_on_malformed_job(
    tmp_path: Path,
) -> None:
    settings = make_settings(tmp_path)
    write_machine(
        settings,
        "ready",
        "2026-07-18T12:00:00+00:00",
    )
    job = JobRepository(settings).create(
        provision_request()
    )
    status = read_json(job.job_dir / "status.json")
    status["stage_history"] = []
    atomic_write_json(job.job_dir / "status.json", status)

    with pytest.raises(ControlError) as exc:
        MachineRepository(settings).list()

    assert exc.value.code == "job_stage_history_invalid"
```

- [ ] **Step 3: Run focused tests**

```bash
.venv/bin/python -m pytest -q \
  tests/alt_linux/test_job_retention.py \
  tests/alt_linux/test_registry_cli.py \
  tests/alt_linux/test_jobs.py
```

Expected after Tasks 1-7: PASS. `JobRetentionManager.cleanup()` calls the now-strict `JobRepository.list()`, so no retention production-code change is expected.

- [ ] **Step 4: Run CLI cleanup and reconciliation regressions**

```bash
.venv/bin/python -m pytest -q \
  tests/alt_linux/test_job_retention_cli.py \
  tests/alt_linux/test_job_reconcile.py \
  tests/alt_linux/test_job_retention.py
```

Expected: PASS.

- [ ] **Step 5: Commit**

```bash
git add \
  tests/alt_linux/test_job_retention.py \
  tests/alt_linux/test_registry_cli.py
git commit -m "test: enforce stage safety across job readers"
```

---

### Task 9: Document Phase 2.3 and Run the Full Repository Gate

**Files:**
- Create: `tests/alt_linux/test_job_stage_documentation.py`
- Modify: `deploy/alt-linux/README.md`
- Modify: `docs/ALT_WORKSTATION_PROVISIONING_CONTEXT.md`
- Modify: `docs/ALT_WORKSTATION_PROVISIONING_NEXT_STEPS.md`

**Interfaces:**
- Documents canonical stages, history, last-stage failure semantics, helper boundary, no migration, and explicit rollout.
- Marks Phase 2.3 implemented only after the full test gate is green.

- [ ] **Step 1: Write failing documentation contract test**

Create `tests/alt_linux/test_job_stage_documentation.py`:

```python
from __future__ import annotations

from pathlib import Path


REPO_ROOT = Path(__file__).resolve().parents[2]


def normalized(relative_path: str) -> str:
    return " ".join(
        (
            REPO_ROOT / relative_path
        ).read_text(encoding="utf-8").split()
    )


def test_structured_stage_contract_is_documented() -> None:
    required = {
        "deploy/alt-linux/README.md": (
            "created launching validating connecting identity employee login_screen verifying recording complete",
            "stage_history",
            "/usr/local/libexec/alt-job-stage",
            "No automatic migration",
        ),
        "docs/ALT_WORKSTATION_PROVISIONING_CONTEXT.md": (
            "Phase 2.3 structured job stages",
            "failure preserves the last reached stage",
            "stage_history",
            "No automatic migration",
        ),
        "docs/ALT_WORKSTATION_PROVISIONING_NEXT_STEPS.md": (
            "### 2.3 More precise job stages",
            "Status: implemented",
            "recording",
            "complete",
        ),
    }

    for relative_path, fragments in required.items():
        content = normalized(relative_path)
        for fragment in fragments:
            assert fragment in content, (
                f"Missing stage documentation in "
                f"{relative_path}: {fragment}"
            )
```

- [ ] **Step 2: Run documentation test and verify RED**

```bash
.venv/bin/python -m pytest -q \
  tests/alt_linux/test_job_stage_documentation.py
```

Expected: FAIL on the first missing contract fragment.

- [ ] **Step 3: Update operating documentation**

Document:

```text
created -> launching -> validating -> connecting
-> identity -> employee -> login_screen
-> verifying -> recording -> complete
```

State that:

- `jobs status` returns `stage_history`;
- each entry contains only `stage` and timezone-aware `entered_at`;
- failure preserves the last reached stage;
- the internal helper is not a public operator/API command;
- marker failure stops the next role;
- no automatic migration exists;
- existing pre-Phase-2.3 test jobs must be backed up and explicitly removed before rollout;
- the assigned reference UUID must not be provisioned again.

In the roadmap set:

```text
### 2.3 More precise job stages

Status: implemented.
```

only in the same commit that follows a green full gate.

- [ ] **Step 4: Run the complete pre-commit verification**

The worktree is expected to contain the documentation changes at this point, so
this pre-commit gate checks behavior and whitespace but not cleanliness:

```bash
LOG_DIR="/tmp/alt-phase-2-3-precommit-$(date +%Y%m%d-%H%M%S)"
mkdir -p "$LOG_DIR"

.venv/bin/python -m pytest -q tests/alt_linux \
  >"$LOG_DIR/tests.log" 2>&1

python3 -m py_compile \
  deploy/alt-linux/control/alt_deploy/*.py \
  deploy/alt-linux/api/process_pending.py \
  deploy/alt-linux/control/alt-job-stage \
  >"$LOG_DIR/compile.log" 2>&1

bash -n deploy/alt-linux/install-control-plane.sh
bash -n deploy/alt-linux/bootstrap/bootstrap.sh

ANSIBLE_CONFIG="$PWD/deploy/alt-linux/ansible/ansible.cfg" \
  ansible-playbook --syntax-check \
  deploy/alt-linux/ansible/playbooks/01-preflight.yml \
  >"$LOG_DIR/preflight-syntax.log" 2>&1

ANSIBLE_CONFIG="$PWD/deploy/alt-linux/ansible/ansible.cfg" \
  ansible-playbook --syntax-check \
  deploy/alt-linux/ansible/playbooks/02-provision-account.yml \
  >"$LOG_DIR/provision-syntax.log" 2>&1

git diff --check
```

Expected: every command exits `0`.

- [ ] **Step 5: Commit the verified documentation**

```bash
git add \
  deploy/alt-linux/README.md \
  docs/ALT_WORKSTATION_PROVISIONING_CONTEXT.md \
  docs/ALT_WORKSTATION_PROVISIONING_NEXT_STEPS.md \
  tests/alt_linux/test_job_stage_documentation.py
git commit -m "docs: record structured provision job stages"
```

- [ ] **Step 6: Run the final clean-worktree gate**

```bash
LOG_DIR="/tmp/alt-phase-2-3-final-$(date +%Y%m%d-%H%M%S)"
mkdir -p "$LOG_DIR"

.venv/bin/python -m pytest -q tests/alt_linux \
  >"$LOG_DIR/tests.log" 2>&1

python3 -m py_compile \
  deploy/alt-linux/control/alt_deploy/*.py \
  deploy/alt-linux/api/process_pending.py \
  deploy/alt-linux/control/alt-job-stage \
  >"$LOG_DIR/compile.log" 2>&1

bash -n deploy/alt-linux/install-control-plane.sh
bash -n deploy/alt-linux/bootstrap/bootstrap.sh

ANSIBLE_CONFIG="$PWD/deploy/alt-linux/ansible/ansible.cfg" \
  ansible-playbook --syntax-check \
  deploy/alt-linux/ansible/playbooks/01-preflight.yml \
  >"$LOG_DIR/preflight-syntax.log" 2>&1

ANSIBLE_CONFIG="$PWD/deploy/alt-linux/ansible/ansible.cfg" \
  ansible-playbook --syntax-check \
  deploy/alt-linux/ansible/playbooks/02-provision-account.yml \
  >"$LOG_DIR/provision-syntax.log" 2>&1

git diff --check
test -z "$(git status --short)"
echo "LOGS=$LOG_DIR"
```

Expected:

```text
all ALT tests pass
Python compile exits 0
both Bash syntax checks exit 0
both playbook syntax checks exit 0
git diff --check exits 0
worktree is clean
```

---

### Task 10: Controlled Runtime Rollout and New-Machine Live Acceptance

**Files:**
- No repository code changes.
- Runtime paths changed only after a separate explicit operator approval:
  - `/var/lib/alt-deploy/jobs/`
  - `/opt/alt-deploy-control/`
  - `/usr/local/libexec/alt-job-stage`
  - `/usr/local/libexec/alt-provision-worker`
  - `/home/altserver/ansible/playbooks/02-provision-account.yml`

**Interfaces:**
- Produces reviewed manifest: `/root/phase-2-3-old-jobs.txt`
- Removes only the four terminal pre-Phase-2.3 test-job directories listed in that manifest.
- Leaves `/var/lib/alt-deploy/assignments` untouched.
- Installs the strict schema and helper.
- Performs read-only post-install checks.
- Live full-stage acceptance uses a new clean VM or physical workstation, never the assigned reference UUID.

- [ ] **Step 1: Audit old jobs and generate a non-mutating manifest**

Run this from the controller before installing the strict schema:

```bash
sudo -u altserver python3 - <<'PY'
from __future__ import annotations

import json
import os
import re
import stat
from pathlib import Path

root = Path("/var/lib/alt-deploy/jobs")
manifest = Path("/tmp/phase-2-3-old-jobs.txt")
job_id_re = re.compile(
    r"^job-\d{8}T\d{6}Z-[0-9a-f]{8}$"
)
active_states = {"queued", "running"}
allowed_terminal_states = {"successful", "failed"}
reviewed: list[str] = []

if not root.is_dir():
    raise SystemExit(f"jobs root is missing: {root}")

with os.scandir(root) as entries:
    for entry in sorted(entries, key=lambda item: item.name):
        if not job_id_re.fullmatch(entry.name):
            continue
        if not entry.is_dir(follow_symlinks=False):
            raise SystemExit(
                f"unsafe job entry: {entry.name}"
            )

        status_path = Path(entry.path) / "status.json"
        status_stat = status_path.lstat()
        if not stat.S_ISREG(status_stat.st_mode):
            raise SystemExit(
                f"unsafe status file: {status_path}"
            )

        payload = json.loads(
            status_path.read_text(encoding="utf-8")
        )
        state = str(payload.get("state") or "")
        stage = str(payload.get("stage") or "")

        if state in active_states:
            raise SystemExit(
                f"active job blocks rollout: "
                f"{entry.name} state={state}"
            )
        if state not in allowed_terminal_states:
            raise SystemExit(
                f"unexpected old job state: "
                f"{entry.name} state={state}"
            )
        if "stage_history" in payload:
            raise SystemExit(
                f"job already uses the new schema: {entry.name}"
            )

        reviewed.append(entry.name)
        print(
            f"REVIEW {entry.name} "
            f"state={state} stage={stage}"
        )

if len(reviewed) != 4:
    raise SystemExit(
        f"expected exactly 4 old test jobs, "
        f"found {len(reviewed)}"
    )

manifest.write_text(
    "".join(f"{job_id}\n" for job_id in reviewed),
    encoding="utf-8",
)
os.chmod(manifest, 0o600)
print(f"MANIFEST={manifest}")
PY
```

Expected: exactly four `REVIEW` lines, no active job, and
`MANIFEST=/tmp/phase-2-3-old-jobs.txt`.

- [ ] **Step 2: Stop for explicit review before any deletion**

Display the exact manifest:

```bash
cat /tmp/phase-2-3-old-jobs.txt
```

Compare every ID with the read-only audit output. Obtain explicit operator
approval for those exact four IDs. Do not continue automatically from the audit
command into deletion.

After approval, freeze the reviewed manifest as root:

```bash
sudo install \
  -o root \
  -g root \
  -m 0600 \
  /tmp/phase-2-3-old-jobs.txt \
  /root/phase-2-3-old-jobs.txt
```

- [ ] **Step 3: Back up jobs and installed runtime**

```bash
STAMP="$(date +%Y%m%d-%H%M%S)"

sudo tar -C / -czf \
  "/root/alt-deploy-jobs-before-phase-2-3-${STAMP}.tar.gz" \
  var/lib/alt-deploy/jobs

RUNTIME_PATHS=(
  opt/alt-deploy-control
  usr/local/sbin/workstationctl
  usr/local/libexec/alt-provision-worker
)

if sudo test -e /usr/local/libexec/alt-job-stage; then
  RUNTIME_PATHS+=(
    usr/local/libexec/alt-job-stage
  )
fi

sudo tar -C / -czf \
  "/root/alt-deploy-runtime-before-phase-2-3-${STAMP}.tar.gz" \
  "${RUNTIME_PATHS[@]}"
```

Do not include Vault files, Vault password files, assignments, or private keys.

- [ ] **Step 4: Remove only the reviewed manifest entries without following symlinks**

Run this only after Step 2 approval and Step 3 backup:

```bash
sudo python3 - <<'PY'
from __future__ import annotations

import json
import os
import re
import stat
from pathlib import Path

root = Path("/var/lib/alt-deploy/jobs")
manifest = Path("/root/phase-2-3-old-jobs.txt")
job_id_re = re.compile(
    r"^job-\d{8}T\d{6}Z-[0-9a-f]{8}$"
)
terminal_states = {"successful", "failed"}


def remove_no_follow(path: Path) -> None:
    entry_stat = path.lstat()
    if stat.S_ISDIR(entry_stat.st_mode):
        with os.scandir(path) as entries:
            for entry in entries:
                child = path / entry.name
                if entry.is_dir(follow_symlinks=False):
                    remove_no_follow(child)
                else:
                    child.unlink()
        path.rmdir()
        return
    path.unlink()


job_ids = [
    line.strip()
    for line in manifest.read_text(
        encoding="utf-8"
    ).splitlines()
    if line.strip()
]

if len(job_ids) != 4 or len(set(job_ids)) != 4:
    raise SystemExit(
        "reviewed manifest must contain 4 unique job IDs"
    )

for job_id in job_ids:
    if not job_id_re.fullmatch(job_id):
        raise SystemExit(
            f"invalid job ID in manifest: {job_id}"
        )

    job_dir = root / job_id
    if job_dir.parent != root:
        raise SystemExit(
            f"job path escaped root: {job_dir}"
        )

    job_stat = job_dir.lstat()
    if not stat.S_ISDIR(job_stat.st_mode):
        raise SystemExit(
            f"job path is not a real directory: {job_dir}"
        )

    status_path = job_dir / "status.json"
    status_stat = status_path.lstat()
    if not stat.S_ISREG(status_stat.st_mode):
        raise SystemExit(
            f"status path is unsafe: {status_path}"
        )

    payload = json.loads(
        status_path.read_text(encoding="utf-8")
    )
    state = str(payload.get("state") or "")
    if state not in terminal_states:
        raise SystemExit(
            f"refusing non-terminal job: "
            f"{job_id} state={state}"
        )
    if "stage_history" in payload:
        raise SystemExit(
            f"refusing new-schema job: {job_id}"
        )

for job_id in job_ids:
    remove_no_follow(root / job_id)
    print(f"REMOVED={job_id}")
PY
```

Verify assignments were not touched:

```bash
sudo -u altserver find \
  /var/lib/alt-deploy/assignments \
  -maxdepth 1 \
  -type f \
  -printf '%f\n' \
  | sort
```

- [ ] **Step 5: Install runtime**

```bash
sudo bash deploy/alt-linux/install-control-plane.sh
```

Expected: all ALT tests and both playbook syntax checks pass before the
pending-registration path unit restarts.

- [ ] **Step 6: Verify installed strict-stage components**

```bash
sudo test -x /usr/local/libexec/alt-job-stage

sudo cmp -s \
  deploy/alt-linux/control/alt_deploy/job_stages.py \
  /opt/alt-deploy-control/alt_deploy/job_stages.py

sudo cmp -s \
  deploy/alt-linux/control/alt-job-stage \
  /usr/local/libexec/alt-job-stage

sudo -u altserver workstationctl --json vault check
sudo -u altserver workstationctl --json controller permissions
sudo -u altserver workstationctl --json jobs cleanup
sudo -u altserver workstationctl --json jobs reconcile
sudo systemctl is-active --quiet alt-deploy-process.path
```

Expected:

```text
Vault healthy
controller permissions healthy
cleanup checked=0 after old jobs are removed
reconciliation checked=0
path unit active
```

Do not run `jobs cleanup --apply`.

- [ ] **Step 7: Accept the full sequence on a new clean workstation**

On a new VM or physical workstation:

1. complete ALT autoinstall and registration;
2. confirm preflight reaches `awaiting_assignment`;
3. create a non-secret request for that new UUID;
4. run `provision preview`;
5. run `provision start` as root;
6. poll `jobs status`;
7. extract the history with:

```bash
sudo -u altserver workstationctl \
  --json \
  jobs status "$JOB_ID" \
  | python3 -c '
import json
import sys
job = json.load(sys.stdin)["job"]
print(job["state"])
for item in job["stage_history"]:
    print(item["stage"], item["entered_at"])
'
```

8. verify the exact stage order:

```text
created
launching
validating
connecting
identity
employee
login_screen
verifying
recording
complete
```

9. verify `state=successful`;
10. reboot and verify graphical LightDM login;
11. verify controller and target assignments;
12. verify a repeat normal provision request returns
    `machine_already_assigned`.

Do not use UUID `53b03180-5d78-11f0-bd95-f027db877a00`.

---

## Final Acceptance Matrix

| Requirement | Task / evidence |
| --- | --- |
| Every new job starts at `created` with UTC history | Tasks 1-2 creation tests |
| Strict contiguous history and state/stage compatibility | Tasks 1-2 validator tests |
| Byte-identical repeated marker | Task 2 no-op test and Task 5 helper test |
| Backwards, skipped, unknown, terminal transitions rejected | Tasks 2 and 5 |
| Common lock and atomic stage/history write | Task 2 lock/transition tests |
| Direct repository stage update forbidden | Task 2 repository test |
| Planner persists `launching` before launcher | Task 3 |
| Worker records validating/connecting/recording/complete | Task 4 |
| Failure preserves last stage | Tasks 3-4 and 7 |
| Internal helper has a constrained JSON contract | Task 5 |
| Ansible role boundaries emit markers | Task 6 static and syntax tests |
| Marker failure stops target role sequence | Task 6 command contract |
| Reconciliation preserves stages and recovers only recording | Task 7 |
| Malformed real jobs fail closed in readers | Tasks 2 and 8 |
| Retention policy and symlink safety remain intact | Task 8 regressions |
| Public `jobs status` contains `stage_history` | JobRecord public payload plus Tasks 2 and 9 |
| No old-job migration or hidden deletion | Task 9 docs and Task 10 reviewed rollout |
| Installer deploys and verifies helper | Tasks 5 and 9 |
| Complete live history on a clean workstation | Task 10 |
| Assigned reference UUID is never reprovisioned | Global constraints and Task 10 |

## Explicitly Deferred

```text
progress percentage
estimated time remaining
stage-derived automatic retries
public stage mutation command
separate event database
migration of old job records
web UI changes
constrained HTTP API
release/reassignment workflow
automatic cleanup or reconciliation services
```
