from __future__ import annotations

import os
import pwd
from collections.abc import Mapping
from dataclasses import dataclass
from pathlib import Path


_IDENTITY_OVERRIDE_KEYS = (
    "ALT_DEPLOY_BACKUP_EXPECTED_ROOT_UID",
    "ALT_DEPLOY_BACKUP_EXPECTED_ROOT_GID",
    "ALT_DEPLOY_BACKUP_EXPECTED_SERVICE_UID",
    "ALT_DEPLOY_BACKUP_EXPECTED_SERVICE_GID",
)


def _non_negative_decimal(env: Mapping[str, str], key: str) -> int:
    raw = str(env.get(key, "")).strip()
    if not raw.isdecimal():
        raise ValueError(f"Invalid identity override: {key}")
    value = int(raw)
    if value < 0:
        raise ValueError(f"Invalid identity override: {key}")
    return value


def _identity_values(
    env: Mapping[str, str],
    root: Path,
) -> tuple[int, int, int, int, bool]:
    test_mode = env.get("ALT_DEPLOY_BACKUP_TEST_MODE") == "1"
    if test_mode:
        if root == Path("/"):
            raise ValueError("Test mode requires a synthetic root")
        return (
            _non_negative_decimal(
                env,
                "ALT_DEPLOY_BACKUP_EXPECTED_ROOT_UID",
            ),
            _non_negative_decimal(
                env,
                "ALT_DEPLOY_BACKUP_EXPECTED_ROOT_GID",
            ),
            _non_negative_decimal(
                env,
                "ALT_DEPLOY_BACKUP_EXPECTED_SERVICE_UID",
            ),
            _non_negative_decimal(
                env,
                "ALT_DEPLOY_BACKUP_EXPECTED_SERVICE_GID",
            ),
            True,
        )

    if "ALT_DEPLOY_BACKUP_TEST_ROOT" in env:
        raise ValueError("Synthetic root requires test mode")
    if any(key in env for key in _IDENTITY_OVERRIDE_KEYS):
        raise ValueError("Identity overrides require test mode")

    service_user = env.get("ALT_DEPLOY_SERVICE_USER", "altserver")
    account = pwd.getpwnam(service_user)
    return 0, 0, account.pw_uid, account.pw_gid, False


@dataclass(frozen=True)
class BackupSettings:
    backup_root: Path
    private_state_root: Path
    rehearsal_root: Path
    operation_lock: Path
    lifecycle_lock: Path
    log_file: Path
    registration_root: Path
    controller_state_root: Path
    ansible_root: Path
    vault_file: Path
    vault_password_file: Path
    ssh_private_key: Path
    runtime_control_root: Path
    runtime_api_root: Path
    workstationctl_path: Path
    worker_path: Path
    stage_helper_path: Path
    systemd_root: Path
    bootstrap_root: Path
    metadata_root: Path
    fingerprint_key: Path
    ssh_keygen_path: Path
    ansible_playbook_path: Path
    systemctl_path: Path
    systemd_analyze_path: Path
    tar_path: Path
    zstd_path: Path
    service_user: str
    service_group: str
    expected_root_uid: int
    expected_root_gid: int
    expected_service_uid: int
    expected_service_gid: int
    test_mode: bool

    @classmethod
    def from_env(
        cls,
        environ: Mapping[str, str] | None = None,
    ) -> "BackupSettings":
        env: Mapping[str, str] = (
            os.environ if environ is None else environ
        )
        test_mode = env.get("ALT_DEPLOY_BACKUP_TEST_MODE") == "1"
        root = Path(
            env.get("ALT_DEPLOY_BACKUP_TEST_ROOT", "/")
            if test_mode
            else "/"
        )
        if not root.is_absolute():
            raise ValueError("Backup root prefix must be absolute")

        (
            root_uid,
            root_gid,
            service_uid,
            service_gid,
            resolved_test_mode,
        ) = _identity_values(env, root)

        def rooted(path: str) -> Path:
            absolute = Path(path)
            if root == Path("/"):
                return absolute
            return root / path.lstrip("/")

        return cls(
            backup_root=rooted("/var/backups/alt-deploy"),
            private_state_root=rooted("/var/lib/alt-deploy-backup"),
            rehearsal_root=rooted(
                "/var/tmp/alt-deploy-restore-test"
            ),
            operation_lock=rooted(
                "/run/lock/alt-deploy-backup.lock"
            ),
            lifecycle_lock=rooted(
                "/var/lib/alt-deploy/workstationctl.lock"
            ),
            log_file=rooted("/var/log/alt-deploy-backup.log"),
            registration_root=rooted(
                "/srv/alt-deploy/registration"
            ),
            controller_state_root=rooted("/var/lib/alt-deploy"),
            ansible_root=rooted("/home/altserver/ansible"),
            vault_file=rooted(
                "/home/altserver/ansible/group_vars/vault.yml"
            ),
            vault_password_file=rooted(
                "/home/altserver/.ansible-vault-pass"
            ),
            ssh_private_key=rooted(
                "/home/altserver/.ssh/id_ed25519"
            ),
            runtime_control_root=rooted("/opt/alt-deploy-control"),
            runtime_api_root=rooted("/opt/alt-deploy-api"),
            workstationctl_path=rooted(
                "/usr/local/sbin/workstationctl"
            ),
            worker_path=rooted(
                "/usr/local/libexec/alt-provision-worker"
            ),
            stage_helper_path=rooted(
                "/usr/local/libexec/alt-job-stage"
            ),
            systemd_root=rooted("/etc/systemd/system"),
            bootstrap_root=rooted("/srv/alt-deploy/bootstrap"),
            metadata_root=rooted("/srv/alt-deploy/metadata"),
            fingerprint_key=rooted(
                "/var/lib/alt-deploy-backup/fingerprint.key"
            ),
            ssh_keygen_path=Path(
                env.get(
                    "ALT_DEPLOY_BACKUP_SSH_KEYGEN",
                    "/usr/bin/ssh-keygen",
                )
            ),
            ansible_playbook_path=Path(
                env.get(
                    "ALT_DEPLOY_BACKUP_ANSIBLE_PLAYBOOK",
                    "/usr/bin/ansible-playbook",
                )
            ),
            systemctl_path=Path(
                env.get(
                    "ALT_DEPLOY_BACKUP_SYSTEMCTL",
                    "/usr/bin/systemctl",
                )
            ),
            systemd_analyze_path=Path(
                env.get(
                    "ALT_DEPLOY_BACKUP_SYSTEMD_ANALYZE",
                    "/usr/bin/systemd-analyze",
                )
            ),
            tar_path=Path(
                env.get(
                    "ALT_DEPLOY_BACKUP_TAR",
                    "/usr/bin/tar",
                )
            ),
            zstd_path=Path(
                env.get(
                    "ALT_DEPLOY_BACKUP_ZSTD",
                    "/usr/bin/zstd",
                )
            ),
            service_user=env.get(
                "ALT_DEPLOY_SERVICE_USER",
                "altserver",
            ),
            service_group=env.get(
                "ALT_DEPLOY_SERVICE_GROUP",
                "altserver",
            ),
            expected_root_uid=root_uid,
            expected_root_gid=root_gid,
            expected_service_uid=service_uid,
            expected_service_gid=service_gid,
            test_mode=resolved_test_mode,
        )
