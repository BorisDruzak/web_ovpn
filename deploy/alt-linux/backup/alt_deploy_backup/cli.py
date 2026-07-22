from __future__ import annotations

import json
import os
import sys
from collections.abc import Mapping, Sequence
from pathlib import Path

from .errors import BackupError
from .rehearsal import RehearsalService
from .repository import BackupRepository
from .settings import BackupSettings


COMMANDS_WITHOUT_ID = {"create", "list"}
COMMANDS_WITH_ID = {
    "verify",
    "rehearse",
    "rehearse-status",
    "restore",
    "delete",
}


def _parse(argv: Sequence[str]) -> tuple[str, str | None]:
    if len(argv) == 1 and argv[0] in COMMANDS_WITHOUT_ID:
        return argv[0], None
    if len(argv) == 2 and argv[0] in COMMANDS_WITH_ID:
        return argv[0], argv[1]
    raise BackupError(
        code="backup_usage",
        message="Invalid backup command",
        exit_code=2,
    )


def _test_uid_override(environ: Mapping[str, str]) -> int | None:
    raw = environ.get("ALT_DEPLOY_BACKUP_EFFECTIVE_UID")
    if raw is None:
        return None
    if (
        environ.get("ALT_DEPLOY_BACKUP_TEST_MODE") != "1"
        or Path(environ.get("ALT_DEPLOY_BACKUP_TEST_ROOT", "/"))
        == Path("/")
    ):
        raise BackupError(
            code="backup_preflight_failed",
            message="Effective UID override is test-only",
            exit_code=6,
        )
    value = str(raw).strip()
    if not value.isdecimal():
        raise BackupError(
            code="backup_preflight_failed",
            message="Effective UID override is invalid",
            exit_code=6,
        )
    return int(value)


def _settings(environ: Mapping[str, str]) -> BackupSettings:
    try:
        return BackupSettings.from_env(environ)
    except (KeyError, ValueError) as exc:
        raise BackupError(
            code="backup_preflight_failed",
            message="Backup configuration is invalid",
            exit_code=6,
        ) from exc


def _dispatch(
    command: str,
    backup_id: str | None,
    settings: BackupSettings,
) -> dict[str, object]:
    repository = BackupRepository(settings)
    if command == "create":
        result = repository.create()
        return {
            "status": "ok",
            "result": "backup_created",
            "backup_id": result.backup_id,
            "component_count": result.component_count,
            "manifest_sha256": result.manifest_sha256,
            "services_restored": result.services_restored,
        }
    if command == "list":
        backups = repository.list()
        return {
            "status": "ok",
            "result": "backups_listed",
            "count": len(backups),
            "backups": [backup.to_dict() for backup in backups],
        }
    if backup_id is None:
        raise BackupError(
            code="backup_usage",
            message="Backup identifier is required",
            exit_code=2,
        )
    if command == "verify":
        result = repository.verify(backup_id, write_evidence=True)
        return {
            "status": "ok",
            "result": "backup_verified",
            "backup_id": result.backup_id,
            "component_count": result.component_count,
            "manifest_sha256": result.manifest_sha256,
            "evidence_written": result.evidence_written,
        }
    if command == "rehearse":
        result = RehearsalService(repository).rehearse(backup_id)
        return {
            "status": "ok",
            "result": "backup_rehearsed",
            "backup_id": result.backup_id,
            "manifest_sha256": result.manifest_sha256,
            "check_count": result.check_count,
            "rehearsal_passed": result.rehearsal_passed,
        }
    if command == "delete":
        result = repository.delete(backup_id)
        return {
            "status": "ok",
            "result": "backup_deleted",
            "backup_id": result.backup_id,
            "deleted_bytes": result.deleted_bytes,
        }
    if command == "rehearse-status":
        result = repository.assert_rehearsed_eligibility(backup_id)
        return {
            "status": "ok",
            "result": "backup_rehearsed",
            "backup_id": result.backup_id,
            "manifest_sha256": result.manifest_sha256,
            "verification_sha256": result.verification_sha256,
        }
    raise BackupError(
        code="backup_preflight_failed",
        message="Backup command is not implemented yet",
        exit_code=4,
    )


def main(
    argv: Sequence[str] | None = None,
    *,
    environ: Mapping[str, str] | None = None,
    effective_uid: int | None = None,
) -> int:
    args = list(sys.argv[1:] if argv is None else argv)
    env: Mapping[str, str] = os.environ if environ is None else environ
    uid = os.geteuid() if effective_uid is None else effective_uid

    try:
        if uid != 0:
            raise BackupError(
                code="backup_not_root",
                message="Backup operation requires root",
                exit_code=6,
            )
        command, backup_id = _parse(args)
        payload = _dispatch(command, backup_id, _settings(env))
        print(json.dumps(payload, ensure_ascii=False))
        return 0
    except BackupError as exc:
        print(json.dumps(exc.to_dict(), ensure_ascii=False))
        return exc.exit_code


if __name__ == "__main__":
    module_environment = os.environ
    try:
        module_uid = _test_uid_override(module_environment)
    except BackupError as error:
        print(json.dumps(error.to_dict(), ensure_ascii=False))
        raise SystemExit(error.exit_code)
    raise SystemExit(
        main(
            environ=module_environment,
            effective_uid=module_uid,
        )
    )
