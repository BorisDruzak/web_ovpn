from __future__ import annotations

import json
import os
import secrets
import sys
from collections.abc import Mapping, Sequence
from pathlib import Path

from .audit import AuditLog
from .errors import BackupError
from .guard import GuardState
from .rehearsal import RehearsalService
from .repository import BackupRepository
from .restore import RestoreService
from .secrets import FingerprintKeyStore
from .settings import BackupSettings


COMMANDS_WITHOUT_ID = {"create", "list", "guard", "install-check"}
COMMANDS_WITH_ID = {
    "verify",
    "rehearse",
    "rehearse-status",
    "restore",
    "recover",
    "delete",
    "rollout-begin",
    "rollout-authorize",
    "rollout-revoke",
    "rollout-abort",
    "rollout-complete",
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
    if command == "install-check":
        FingerprintKeyStore(settings).ensure()
        return {"status": "ok", "result": "backup_tool_ready"}
    guard = GuardState(settings)
    if command == "guard":
        guard.assert_control_plane_allowed()
        return {"status": "ok", "result": "control_plane_allowed"}
    if backup_id is not None and command == "rollout-begin":
        guard.begin_rollout(backup_id)
        return {
            "status": "ok",
            "result": "rollout_started",
            "backup_id": backup_id,
        }
    if backup_id is not None and command == "rollout-authorize":
        guard.authorize_rollout(backup_id)
        return {
            "status": "ok",
            "result": "rollout_authorized",
            "backup_id": backup_id,
        }
    if backup_id is not None and command == "rollout-revoke":
        guard.revoke_rollout(backup_id)
        return {
            "status": "ok",
            "result": "rollout_revoked",
            "backup_id": backup_id,
        }
    if backup_id is not None and command == "rollout-abort":
        guard.abort_rollout(backup_id)
        return {
            "status": "ok",
            "result": "rollout_aborted",
            "backup_id": backup_id,
        }
    if backup_id is not None and command == "rollout-complete":
        guard.complete_rollout(backup_id)
        return {
            "status": "ok",
            "result": "rollout_completed",
            "backup_id": backup_id,
        }
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
    if command == "restore":
        result = RestoreService(repository).restore(backup_id)
        return {
            "status": "ok",
            "result": "backup_restored",
            "backup_id": result.backup_id,
            "phase": result.phase,
            "services_restored": result.services_restored,
            "rollback_performed": result.rollback_performed,
            "cleanup_complete": result.cleanup_complete,
        }
    if command == "recover":
        result = RestoreService(repository).recover(backup_id)
        return {
            "status": "ok",
            "result": "backup_recovered",
            "restore_id": backup_id,
            "backup_id": result.backup_id,
            "phase": result.phase,
            "services_restored": result.services_restored,
            "rollback_performed": result.rollback_performed,
            "cleanup_complete": result.cleanup_complete,
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
        message="Backup command is not implemented",
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

    audit: AuditLog | None = None
    audit_started = False
    try:
        if uid != 0:
            raise BackupError(
                code="backup_not_root",
                message="Backup operation requires root",
                exit_code=6,
            )
        command, backup_id = _parse(args)
        settings = _settings(env)
        if command == "install-check":
            payload = _dispatch(command, backup_id, settings)
            print(json.dumps(payload, ensure_ascii=False))
            return 0
        audit = AuditLog(
            settings,
            operation_id=f"op-{secrets.token_hex(8)}",
            command=command,
            backup_id=backup_id,
        )
        audit.write("command_started", status="started")
        audit_started = True
        payload = _dispatch(command, backup_id, settings)
        audit.write(
            "command_completed",
            status="ok",
            result=str(payload.get("result", "ok")),
        )
        print(json.dumps(payload, ensure_ascii=False))
        return 0
    except BackupError as exc:
        if audit is not None and audit_started:
            try:
                audit.write(
                    "command_failed",
                    status="error",
                    error_code=exc.code,
                )
            except BackupError as audit_error:
                exc = audit_error
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
