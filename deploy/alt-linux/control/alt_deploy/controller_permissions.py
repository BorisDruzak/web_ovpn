from __future__ import annotations

import grp
import pwd
import stat
from dataclasses import dataclass
from pathlib import Path

from .config import Settings
from .errors import ControlError


@dataclass(frozen=True)
class PathPolicy:
    path: Path
    mode: int


class ControllerPermissionAuditor:
    def __init__(self, settings: Settings) -> None:
        self.settings = settings

    def _policies(self) -> dict[str, PathPolicy]:
        vault_file = (
            self.settings.ansible_project_dir
            / "group_vars"
            / "vault.yml"
        )
        vault_password_file = (
            self.settings.ansible_project_dir.parent
            / ".ansible-vault-pass"
        )

        return {
            "state_root": PathPolicy(
                self.settings.state_root,
                0o700,
            ),
            "jobs_dir": PathPolicy(
                self.settings.jobs_dir,
                0o700,
            ),
            "assignments_dir": PathPolicy(
                self.settings.assignments_dir,
                0o700,
            ),
            "registration_root": PathPolicy(
                self.settings.registration_root,
                0o700,
            ),
            "ssh_dir": PathPolicy(
                self.settings.known_hosts_file.parent,
                0o700,
            ),
            "vault_file": PathPolicy(vault_file, 0o600),
            "vault_password_file": PathPolicy(
                vault_password_file,
                0o600,
            ),
        }

    def _expected_ids(self) -> tuple[int | None, int | None]:
        try:
            uid = pwd.getpwnam(self.settings.service_user).pw_uid
        except KeyError:
            uid = None

        try:
            gid = grp.getgrnam(self.settings.service_group).gr_gid
        except KeyError:
            gid = None

        return uid, gid

    @staticmethod
    def _check_path(
        policy: PathPolicy,
        expected_uid: int | None,
        expected_gid: int | None,
    ) -> dict[str, bool]:
        try:
            metadata = policy.path.stat()
        except OSError:
            return {
                "exists": False,
                "owner_ok": False,
                "group_ok": False,
                "mode_ok": False,
            }

        return {
            "exists": True,
            "owner_ok": (
                expected_uid is not None
                and metadata.st_uid == expected_uid
            ),
            "group_ok": (
                expected_gid is not None
                and metadata.st_gid == expected_gid
            ),
            "mode_ok": (
                stat.S_IMODE(metadata.st_mode) == policy.mode
            ),
        }

    def check(self) -> dict[str, object]:
        expected_uid, expected_gid = self._expected_ids()
        paths = {
            name: self._check_path(
                policy,
                expected_uid,
                expected_gid,
            )
            for name, policy in self._policies().items()
        }

        healthy = all(
            all(result.values())
            for result in paths.values()
        )

        if not healthy:
            raise ControlError(
                code="controller_permissions_unhealthy",
                message="Controller permission audit failed",
                exit_code=8,
                details={"paths": paths},
            )

        return {
            "status": "ok",
            "paths": paths,
        }
