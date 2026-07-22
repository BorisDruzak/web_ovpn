from __future__ import annotations

import json
import re
import stat
from dataclasses import dataclass
from pathlib import Path

from .errors import BackupError
from .fs import assert_safe_parents, read_regular_bytes
from .settings import BackupSettings
from .systemd import PROCESSOR_UNIT, SystemdManager


_JOB_ID = re.compile(r"^job-\d{8}T\d{6}Z-[0-9a-f]{8}$")
_JOB_STATES = frozenset({"queued", "running", "successful", "failed"})
_ACTIVE_JOB_STATES = frozenset({"queued", "running"})
_SAFE_STAGE = re.compile(r"^[a-z][a-z0-9_]{0,99}$")


@dataclass(frozen=True)
class QuiescenceSnapshot:
    active_job_ids: tuple[str, ...]
    pending_filenames: tuple[str, ...]
    processor_active: bool
    transient_units: tuple[str, ...]


def _preflight(message: str) -> BackupError:
    return BackupError(
        code="backup_preflight_failed",
        message=message,
        exit_code=4,
    )


def _directory_or_absent(path: Path) -> bool:
    assert_safe_parents(path)
    if not path.exists() and not path.is_symlink():
        return False
    try:
        metadata = path.lstat()
    except OSError as exc:
        raise _preflight("Controller state directory cannot be inspected") from exc
    if not stat.S_ISDIR(metadata.st_mode):
        raise _preflight("Controller state path is not a safe directory")
    return True


class QuiescenceChecker:
    def __init__(
        self,
        settings: BackupSettings,
        *,
        systemd_manager: SystemdManager | None = None,
    ) -> None:
        self.settings = settings
        self.systemd = systemd_manager or SystemdManager(settings)

    def _jobs(self) -> list[dict[str, str]]:
        jobs_root = self.settings.controller_state_root / "jobs"
        if not _directory_or_absent(jobs_root):
            return []
        active: list[dict[str, str]] = []
        try:
            children = sorted(jobs_root.iterdir(), key=lambda item: item.name)
        except OSError as exc:
            raise _preflight("Job store cannot be enumerated") from exc
        for job_dir in children:
            try:
                metadata = job_dir.lstat()
            except OSError as exc:
                raise _preflight("Job entry cannot be inspected") from exc
            if (
                not stat.S_ISDIR(metadata.st_mode)
                or not _JOB_ID.fullmatch(job_dir.name)
            ):
                raise _preflight("Job store contains an invalid entry")
            raw = read_regular_bytes(
                job_dir / "status.json",
                max_bytes=1024 * 1024,
            )
            try:
                payload = json.loads(raw.decode("utf-8"))
            except (UnicodeDecodeError, json.JSONDecodeError) as exc:
                raise _preflight("Job status JSON is invalid") from exc
            if not isinstance(payload, dict):
                raise _preflight("Job status must be an object")
            payload_job_id = payload.get("job_id", job_dir.name)
            state = payload.get("state")
            stage = payload.get("stage")
            if (
                payload_job_id != job_dir.name
                or not isinstance(state, str)
                or state not in _JOB_STATES
                or not isinstance(stage, str)
                or not _SAFE_STAGE.fullmatch(stage)
            ):
                raise _preflight("Job status fields are invalid")
            if state in _ACTIVE_JOB_STATES:
                active.append(
                    {
                        "job_id": job_dir.name,
                        "state": state,
                        "stage": stage,
                    }
                )
        return active

    def _pending(self) -> tuple[str, ...]:
        pending_root = self.settings.registration_root / "pending"
        if not _directory_or_absent(pending_root):
            return ()
        names: list[str] = []
        try:
            children = sorted(
                pending_root.iterdir(),
                key=lambda item: item.name,
            )
        except OSError as exc:
            raise _preflight(
                "Pending registration directory cannot be enumerated"
            ) from exc
        for path in children:
            if not path.name.endswith(".json"):
                continue
            try:
                metadata = path.lstat()
            except OSError as exc:
                raise _preflight(
                    "Pending registration cannot be inspected"
                ) from exc
            if not stat.S_ISREG(metadata.st_mode):
                raise _preflight(
                    "Pending registration entry is unsafe"
                )
            names.append(path.name)
        return tuple(names)

    def assert_quiescent(self) -> QuiescenceSnapshot:
        active_jobs = self._jobs()
        if active_jobs:
            raise BackupError(
                code="backup_active_jobs",
                message="Active provision jobs block backup operation",
                exit_code=4,
                details={"jobs": active_jobs[:20]},
            )

        transient_units = self.systemd.active_transient_units()
        if transient_units:
            raise BackupError(
                code="backup_active_jobs",
                message="Active transient provision units block backup operation",
                exit_code=4,
                details={"transient_units": list(transient_units[:20])},
            )

        pending = self._pending()
        if pending:
            raise BackupError(
                code="backup_pending_registration",
                message="Pending registrations block backup operation",
                exit_code=4,
                details={"pending": list(pending[:50])},
            )

        unit_states = {state.name: state for state in self.systemd.capture()}
        processor_active = (
            unit_states[PROCESSOR_UNIT].active_state == "active"
        )
        if processor_active:
            raise BackupError(
                code="backup_processor_active",
                message="Pending registration processor is active",
                exit_code=4,
            )

        return QuiescenceSnapshot(
            active_job_ids=(),
            pending_filenames=(),
            processor_active=False,
            transient_units=(),
        )
