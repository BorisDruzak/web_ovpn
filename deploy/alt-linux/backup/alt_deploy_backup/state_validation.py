from __future__ import annotations

import hashlib
import json
import re
import stat
from datetime import datetime
from pathlib import Path

from .errors import BackupError
from .fs import read_regular_bytes
from .manifest import BackupManifest

_JOB_ID = re.compile(r"^job-\d{8}T\d{6}Z-[0-9a-f]{8}$")
_MACHINE_ID = re.compile(r"^[0-9a-f-]{8,64}$")
_REGISTRATION_ID = re.compile(r"^reg-[0-9a-f]{32}$")
_ARCHIVE_ID = re.compile(r"^archive-\d{8}T\d{6}Z-[0-9a-f]{8}$")
_SHA256 = re.compile(r"^[0-9a-f]{64}$")
_CANONICAL_STAGES = (
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
_STAGE_INDEX = {stage: index for index, stage in enumerate(_CANONICAL_STAGES)}
_JOB_STATES = frozenset({"queued", "running", "successful", "failed"})
_REGISTRATION_STATES = ("pending", "ready", "failed")
_ARCHIVE_PHASES = frozenset(
    {"prepared", "copied", "committed", "cleaned", "aborted"}
)
_MAX_JSON = 16 * 1024 * 1024


def _failure(message: str) -> BackupError:
    return BackupError(
        code="backup_rehearsal_failed",
        message=message,
        exit_code=4,
    )


def _pairs_object(pairs: list[tuple[str, object]]) -> dict[str, object]:
    result: dict[str, object] = {}
    for key, value in pairs:
        if key in result:
            raise ValueError("duplicate JSON key")
        result[key] = value
    return result


def _read_object(
    path: Path,
    *,
    maximum: int = _MAX_JSON,
) -> tuple[dict[str, object], bytes]:
    try:
        raw = read_regular_bytes(path, max_bytes=maximum)
        payload = json.loads(
            raw.decode("utf-8"),
            object_pairs_hook=_pairs_object,
        )
    except (
        BackupError,
        UnicodeDecodeError,
        json.JSONDecodeError,
        ValueError,
    ) as exc:
        raise _failure("Rehearsal state JSON is invalid") from exc
    if not isinstance(payload, dict):
        raise _failure("Rehearsal state JSON must be an object")
    return payload, raw


def _safe_directory(path: Path, *, optional: bool = False) -> bool:
    if not path.exists() and not path.is_symlink():
        if optional:
            return False
        raise _failure("Required rehearsal state directory is missing")
    try:
        metadata = path.lstat()
    except OSError as exc:
        raise _failure(
            "Rehearsal state directory cannot be inspected"
        ) from exc
    if not stat.S_ISDIR(metadata.st_mode) or stat.S_ISLNK(
        metadata.st_mode
    ):
        raise _failure("Rehearsal state directory is unsafe")
    return True


def _children(path: Path) -> list[Path]:
    try:
        return sorted(path.iterdir(), key=lambda item: item.name)
    except OSError as exc:
        raise _failure(
            "Rehearsal state directory cannot be enumerated"
        ) from exc


def _validate_timestamp(value: object) -> datetime:
    if not isinstance(value, str) or not value:
        raise _failure("State timestamp is invalid")
    try:
        parsed = datetime.fromisoformat(value)
    except ValueError as exc:
        raise _failure("State timestamp is invalid") from exc
    if parsed.tzinfo is None:
        raise _failure("State timestamp has no timezone")
    return parsed


def _validate_optional_json(path: Path) -> None:
    if not path.exists() and not path.is_symlink():
        return
    _read_object(path)


class StateValidator:
    def _validate_job_history(
        self,
        status: dict[str, object],
        *,
        state: str,
        stage: str,
    ) -> None:
        history = status.get("stage_history")
        if not isinstance(history, list) or not history:
            raise _failure("Job stage history is missing or empty")
        previous_time: datetime | None = None
        observed: list[str] = []
        for index, entry in enumerate(history):
            if not isinstance(entry, dict) or set(entry) != {
                "stage",
                "entered_at",
            }:
                raise _failure("Job stage history entry is invalid")
            entry_stage = entry.get("stage")
            if (
                not isinstance(entry_stage, str)
                or index >= len(_CANONICAL_STAGES)
                or entry_stage != _CANONICAL_STAGES[index]
            ):
                raise _failure("Job stage history is not contiguous")
            entered_at = _validate_timestamp(entry.get("entered_at"))
            if previous_time is not None and entered_at < previous_time:
                raise _failure("Job stage timestamps move backwards")
            previous_time = entered_at
            observed.append(entry_stage)
        if observed[-1] != stage:
            raise _failure("Job stage does not match stage history")
        if state == "queued" and stage not in {"created", "launching"}:
            raise _failure("Queued job has an invalid stage")
        if state == "running" and not (
            _STAGE_INDEX["validating"]
            <= _STAGE_INDEX[stage]
            <= _STAGE_INDEX["recording"]
        ):
            raise _failure("Running job has an invalid stage")
        if state == "successful" and stage != "complete":
            raise _failure("Successful job is not complete")
        if state == "failed" and stage == "complete":
            raise _failure("Failed job cannot be complete")

    def _validate_jobs(self, root: Path) -> str:
        if not _safe_directory(root, optional=True):
            return "jobs"
        for job_dir in _children(root):
            try:
                metadata = job_dir.lstat()
            except OSError as exc:
                raise _failure("Job entry cannot be inspected") from exc
            if (
                not stat.S_ISDIR(metadata.st_mode)
                or stat.S_ISLNK(metadata.st_mode)
                or not _JOB_ID.fullmatch(job_dir.name)
            ):
                raise _failure("Job store contains an invalid entry")
            status, _ = _read_object(job_dir / "status.json")
            request, _ = _read_object(job_dir / "request.json")
            job_id = status.get("job_id", job_dir.name)
            state = status.get("state")
            stage = status.get("stage")
            machine_uuid = str(
                status.get("machine_uuid")
                or request.get("machine_uuid")
                or ""
            ).strip().lower()
            if (
                job_id != job_dir.name
                or not isinstance(state, str)
                or state not in _JOB_STATES
                or not isinstance(stage, str)
                or stage not in _STAGE_INDEX
                or not _MACHINE_ID.fullmatch(machine_uuid)
            ):
                raise _failure("Job status identity is invalid")
            self._validate_job_history(
                status,
                state=state,
                stage=stage,
            )
            _validate_optional_json(job_dir / "result.json")
            _validate_optional_json(job_dir / "provision-result.json")
            for child in _children(job_dir):
                if child.name not in {
                    "status.json",
                    "request.json",
                    "result.json",
                    "provision-result.json",
                    "ansible.log",
                    "ansible.log.gz",
                }:
                    raise _failure(
                        "Job directory contains an unexpected object"
                    )
                child_metadata = child.lstat()
                if not stat.S_ISREG(child_metadata.st_mode):
                    raise _failure("Job file is not regular")
        return "jobs"

    def _validate_assignments(self, root: Path) -> str:
        if not _safe_directory(root, optional=True):
            return "assignments"
        for path in _children(root):
            try:
                metadata = path.lstat()
            except OSError as exc:
                raise _failure(
                    "Assignment entry cannot be inspected"
                ) from exc
            if (
                not stat.S_ISREG(metadata.st_mode)
                or not path.name.endswith(".json")
                or not _MACHINE_ID.fullmatch(path.stem)
            ):
                raise _failure("Assignment entry is invalid")
            payload, _ = _read_object(path)
            machine_uuid = str(
                payload.get("machine_uuid") or ""
            ).strip().lower()
            if machine_uuid != path.stem:
                raise _failure(
                    "Assignment identity does not match filename"
                )
        return "assignments"

    def _validate_registrations(self, root: Path) -> str:
        if not _safe_directory(root, optional=True):
            return "registrations"
        unexpected = {
            child.name for child in _children(root)
        } - set(_REGISTRATION_STATES)
        if unexpected:
            raise _failure(
                "Registration root contains an unexpected object"
            )
        for state in _REGISTRATION_STATES:
            state_root = root / state
            if not _safe_directory(state_root, optional=True):
                continue
            for path in _children(state_root):
                metadata = path.lstat()
                if (
                    not stat.S_ISREG(metadata.st_mode)
                    or not path.name.endswith(".json")
                ):
                    raise _failure("Registration entry is unsafe")
                payload, _ = _read_object(
                    path,
                    maximum=1024 * 1024,
                )
                machine_key = str(
                    payload.get("machine_key") or ""
                ).strip().lower()
                machine_uuid = str(
                    payload.get("uuid") or machine_key
                ).strip().lower()
                status = str(
                    payload.get("status") or state
                ).strip().lower()
                generation = str(
                    payload.get("registration_id") or ""
                ).strip().lower()
                if (
                    not machine_key
                    or not machine_uuid
                    or status != state
                    or path.stem not in {machine_key, machine_uuid}
                    or (
                        generation
                        and not _REGISTRATION_ID.fullmatch(generation)
                    )
                ):
                    raise _failure(
                        "Registration identity or generation is invalid"
                    )
        return "registrations"

    def _validate_archive_transaction(
        self,
        directory: Path,
        *,
        completed: bool,
    ) -> None:
        archive_id = directory.name
        if not _ARCHIVE_ID.fullmatch(archive_id):
            raise _failure("Machine archive identifier is invalid")
        allowed = {
            "transaction.json",
            "manifest.json",
            "commit.json",
            "records",
        }
        if {child.name for child in _children(directory)} - allowed:
            raise _failure(
                "Machine archive contains an unexpected object"
            )
        transaction, _ = _read_object(
            directory / "transaction.json"
        )
        if (
            transaction.get("schema_version") != 1
            or transaction.get("archive_id") != archive_id
            or transaction.get("phase") not in _ARCHIVE_PHASES
            or not isinstance(transaction.get("machine_key"), str)
            or not transaction.get("machine_key")
            or not isinstance(transaction.get("machine_uuid"), str)
            or not transaction.get("machine_uuid")
        ):
            raise _failure("Machine archive transaction is invalid")
        plans = transaction.get("planned_sources")
        if not isinstance(plans, list) or not plans:
            raise _failure("Machine archive source plan is invalid")
        planned_states: set[str] = set()
        for plan in plans:
            if not isinstance(plan, dict):
                raise _failure(
                    "Machine archive source plan entry is invalid"
                )
            state = plan.get("state")
            if (
                state not in _REGISTRATION_STATES
                or state in planned_states
                or plan.get("archive_name") != f"{state}.json"
                or not isinstance(plan.get("generation"), str)
                or not plan.get("generation")
                or type(plan.get("size")) is not int
                or plan.get("size", -1) < 0
                or not isinstance(plan.get("sha256"), str)
                or not _SHA256.fullmatch(str(plan.get("sha256")))
            ):
                raise _failure(
                    "Machine archive source plan values are invalid"
                )
            planned_states.add(str(state))

        manifest_path = directory / "manifest.json"
        commit_path = directory / "commit.json"
        if completed or manifest_path.exists() or commit_path.exists():
            manifest, manifest_raw = _read_object(manifest_path)
            commit, _ = _read_object(commit_path)
            if (
                manifest.get("schema_version") != 1
                or manifest.get("archive_id") != archive_id
                or manifest.get("machine_key")
                != transaction.get("machine_key")
                or manifest.get("machine_uuid")
                != transaction.get("machine_uuid")
                or manifest.get("commit_phase") != "committed"
                or commit.get("schema_version") != 1
                or commit.get("archive_id") != archive_id
                or commit.get("machine_key")
                != transaction.get("machine_key")
                or commit.get("machine_uuid")
                != transaction.get("machine_uuid")
                or commit.get("manifest_sha256")
                != hashlib.sha256(manifest_raw).hexdigest()
            ):
                raise _failure(
                    "Machine archive commit binding is invalid"
                )
            records = manifest.get("records")
            records_root = directory / "records"
            if not isinstance(records, list) or not records:
                raise _failure(
                    "Machine archive manifest records are invalid"
                )
            _safe_directory(records_root)
            seen: set[str] = set()
            for record in records:
                if not isinstance(record, dict):
                    raise _failure(
                        "Machine archive record entry is invalid"
                    )
                state = record.get("state")
                filename = record.get("filename")
                size = record.get("size")
                digest = record.get("sha256")
                if (
                    state not in _REGISTRATION_STATES
                    or state in seen
                    or filename != f"{state}.json"
                    or type(size) is not int
                    or size < 0
                    or not isinstance(digest, str)
                    or not _SHA256.fullmatch(digest)
                ):
                    raise _failure(
                        "Machine archive record metadata is invalid"
                    )
                raw = read_regular_bytes(
                    records_root / str(filename),
                    max_bytes=1024 * 1024,
                )
                if (
                    len(raw) != size
                    or hashlib.sha256(raw).hexdigest() != digest
                ):
                    raise _failure(
                        "Machine archive record hash is invalid"
                    )
                seen.add(str(state))

    def _validate_machine_archives(self, root: Path) -> str:
        if not _safe_directory(root, optional=True):
            return "machine_archives"
        completed_ids: set[str] = set()
        for child in _children(root):
            if child.name == ".transactions":
                _safe_directory(child)
                for transaction in _children(child):
                    _safe_directory(transaction)
                    self._validate_archive_transaction(
                        transaction,
                        completed=False,
                    )
                continue
            _safe_directory(child)
            if child.name in completed_ids:
                raise _failure(
                    "Duplicate completed machine archive exists"
                )
            completed_ids.add(child.name)
            self._validate_archive_transaction(
                child,
                completed=True,
            )
        return "machine_archives"

    def validate_tree(
        self,
        rehearsal_root: Path,
        manifest: BackupManifest,
    ) -> tuple[str, ...]:
        del manifest
        controller_state = (
            rehearsal_root
            / "controller-state"
            / "var"
            / "lib"
            / "alt-deploy"
        )
        registration_state = (
            rehearsal_root
            / "registration-state"
            / "srv"
            / "alt-deploy"
            / "registration"
        )
        checks = (
            self._validate_jobs(controller_state / "jobs"),
            self._validate_assignments(
                controller_state / "assignments"
            ),
            self._validate_registrations(registration_state),
            self._validate_machine_archives(
                controller_state / "machine-archives"
            ),
        )
        return checks
