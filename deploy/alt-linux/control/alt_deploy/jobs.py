from __future__ import annotations

import gzip
import os
import re
import secrets
import stat
from collections.abc import Mapping
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, BinaryIO

from .assignments import assert_safe_payload
from .config import Settings
from .errors import ControlError
from .jsonio import (
    atomic_write_json,
    ensure_private_dir,
    read_json,
)
from .models import JobRecord


JOB_ID_RE = re.compile(
    r"^job-\d{8}T\d{6}Z-[0-9a-f]{8}$"
)

ACTIVE_STATES = {
    "queued",
    "running",
}


def utc_now() -> str:
    return datetime.now(timezone.utc).isoformat()


class JobRepository:
    def __init__(self, settings: Settings):
        self.settings = settings

    def _job_dir(self, job_id: str) -> Path:
        normalized = job_id.strip()

        if not JOB_ID_RE.fullmatch(normalized):
            raise ControlError(
                code="job_not_found",
                message=f"Job not found: {job_id}",
                exit_code=3,
            )

        return self.settings.jobs_dir / normalized

    def _generate_job_id(self) -> str:
        timestamp = datetime.now(
            timezone.utc
        ).strftime("%Y%m%dT%H%M%SZ")

        return (
            f"job-{timestamp}-"
            f"{secrets.token_hex(4)}"
        )

    def _load_from_dir(
        self,
        job_dir: Path,
    ) -> JobRecord:
        request_path = job_dir / "request.json"
        status_path = job_dir / "status.json"

        try:
            request = read_json(request_path)
            status_payload = read_json(status_path)
        except (OSError, ValueError) as exc:
            raise ControlError(
                code="job_invalid",
                message=(
                    f"Invalid job record: {job_dir.name}"
                ),
                exit_code=4,
            ) from exc

        return JobRecord(
            job_id=str(
                status_payload.get("job_id")
                or job_dir.name
            ),
            machine_uuid=str(
                status_payload.get("machine_uuid")
                or request.get("machine_uuid")
                or ""
            ),
            state=str(
                status_payload.get("state") or ""
            ),
            stage=str(
                status_payload.get("stage") or ""
            ),
            created_at=str(
                status_payload.get("created_at") or ""
            ),
            updated_at=str(
                status_payload.get("updated_at") or ""
            ),
            job_dir=job_dir,
            request=request,
            status=status_payload,
        )

    def create(
        self,
        request: Mapping[str, object],
    ) -> JobRecord:
        record = dict(request)

        assert_safe_payload(record)

        machine_uuid = str(
            record.get("machine_uuid") or ""
        ).strip().lower()

        if not machine_uuid:
            raise ControlError(
                code="invalid_job_request",
                message=(
                    "Job request has no machine UUID"
                ),
                exit_code=4,
            )

        record["machine_uuid"] = machine_uuid

        ensure_private_dir(self.settings.jobs_dir)

        for _ in range(20):
            job_id = self._generate_job_id()
            job_dir = self.settings.jobs_dir / job_id

            try:
                job_dir.mkdir(mode=0o700)
            except FileExistsError:
                continue

            os.chmod(job_dir, 0o700)
            break
        else:
            raise ControlError(
                code="job_id_generation_failed",
                message=(
                    "Unable to allocate a unique job ID"
                ),
                exit_code=4,
            )

        timestamp = utc_now()

        status_payload: dict[str, object] = {
            "job_id": job_id,
            "machine_uuid": machine_uuid,
            "state": "queued",
            "stage": "created",
            "created_at": timestamp,
            "updated_at": timestamp,
        }

        atomic_write_json(
            job_dir / "request.json",
            record,
        )
        atomic_write_json(
            job_dir / "status.json",
            status_payload,
        )

        log_path = job_dir / "ansible.log"
        log_path.touch(exist_ok=False)
        os.chmod(log_path, 0o600)

        return self.get(job_id)

    def get(self, job_id: str) -> JobRecord:
        job_dir = self._job_dir(job_id)

        try:
            entry_stat = job_dir.lstat()
        except OSError:
            entry_stat = None

        if (
            entry_stat is None
            or not stat.S_ISDIR(entry_stat.st_mode)
        ):
            raise ControlError(
                code="job_not_found",
                message=f"Job not found: {job_id}",
                exit_code=3,
            )

        return self._load_from_dir(job_dir)

    def list(self) -> list[JobRecord]:
        if not self.settings.jobs_dir.exists():
            return []

        jobs: list[JobRecord] = []

        for job_dir in sorted(
            self.settings.jobs_dir.glob("job-*")
        ):
            try:
                entry_stat = job_dir.lstat()
            except OSError:
                continue

            if not stat.S_ISDIR(entry_stat.st_mode):
                continue

            try:
                jobs.append(
                    self._load_from_dir(job_dir)
                )
            except ControlError:
                continue

        return sorted(
            jobs,
            key=lambda job: (
                job.created_at,
                job.job_id,
            ),
            reverse=True,
        )

    def update(
        self,
        job_id: str,
        **fields: object,
    ) -> JobRecord:
        job = self.get(job_id)
        status_payload = dict(job.status)

        fields.pop("job_id", None)
        fields.pop("machine_uuid", None)
        fields.pop("created_at", None)

        status_payload.update(fields)

        status_payload["job_id"] = job.job_id
        status_payload["machine_uuid"] = job.machine_uuid
        status_payload["created_at"] = job.created_at
        status_payload["updated_at"] = utc_now()

        assert_safe_payload(status_payload)

        atomic_write_json(
            job.job_dir / "status.json",
            status_payload,
        )

        return self.get(job_id)

    def active_for_machine(
        self,
        machine_uuid: str,
    ) -> JobRecord | None:
        normalized = machine_uuid.strip().lower()

        for job in self.list():
            if (
                job.machine_uuid.lower() == normalized
                and job.state in ACTIVE_STATES
            ):
                return job

        return None

    @staticmethod
    def _open_regular_binary(path: Path) -> BinaryIO:
        try:
            entry_stat = path.lstat()
        except OSError as exc:
            raise ControlError(
                code="job_log_not_found",
                message="Provision job log was not found",
                exit_code=3,
            ) from exc

        if not stat.S_ISREG(entry_stat.st_mode):
            raise ControlError(
                code="job_log_unsafe",
                message="Provision job log is not a regular file",
                exit_code=4,
            )

        flags = os.O_RDONLY
        if hasattr(os, "O_NOFOLLOW"):
            flags |= os.O_NOFOLLOW

        try:
            descriptor = os.open(path, flags)
        except OSError as exc:
            raise ControlError(
                code="job_log_read_failed",
                message="Unable to open provision job log",
                exit_code=4,
            ) from exc

        return os.fdopen(descriptor, "rb")

    @staticmethod
    def _read_stream_tail(
        handle: BinaryIO,
        max_bytes: int,
    ) -> tuple[bytes, bool]:
        tail = bytearray()
        total = 0

        while True:
            chunk = handle.read(64 * 1024)
            if not chunk:
                break

            total += len(chunk)
            tail.extend(chunk)

            if len(tail) > max_bytes:
                del tail[:-max_bytes]

        return bytes(tail), total > max_bytes

    def read_log(
        self,
        job_id: str,
        max_bytes: int = 2_000_000,
    ) -> dict[str, Any]:
        if max_bytes < 1:
            raise ControlError(
                code="invalid_log_limit",
                message="Log byte limit must be positive",
                exit_code=4,
            )

        job = self.get(job_id)
        log_path = job.job_dir / "ansible.log"
        archive_path = job.job_dir / "ansible.log.gz"

        try:
            log_stat = log_path.lstat()
        except FileNotFoundError:
            log_stat = None
        except OSError as exc:
            raise ControlError(
                code="job_log_read_failed",
                message="Unable to inspect provision job log",
                exit_code=4,
            ) from exc

        archived = False

        if log_stat is not None:
            if not stat.S_ISREG(log_stat.st_mode):
                raise ControlError(
                    code="job_log_unsafe",
                    message="Provision job log is not a regular file",
                    exit_code=4,
                )

            with self._open_regular_binary(log_path) as handle:
                size = log_stat.st_size
                truncated = size > max_bytes
                if truncated:
                    handle.seek(-max_bytes, os.SEEK_END)
                raw = handle.read()
        else:
            archived = True

            try:
                with self._open_regular_binary(
                    archive_path
                ) as raw_archive:
                    with gzip.GzipFile(
                        fileobj=raw_archive,
                        mode="rb",
                    ) as archive:
                        raw, truncated = self._read_stream_tail(
                            archive,
                            max_bytes,
                        )
            except (
                gzip.BadGzipFile,
                EOFError,
                OSError,
            ) as exc:
                raise ControlError(
                    code="job_log_archive_invalid",
                    message="Archived provision job log is invalid",
                    exit_code=4,
                ) from exc

        return {
            "job_id": job.job_id,
            "machine_uuid": job.machine_uuid,
            "state": job.state,
            "stage": job.stage,
            "log": raw.decode(
                "utf-8",
                errors="replace",
            ),
            "truncated": truncated,
            "archived": archived,
        }
