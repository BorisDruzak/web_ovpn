from __future__ import annotations

import errno
import grp
import os
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
    is_directory: bool


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
                True,
            ),
            "jobs_dir": PathPolicy(
                self.settings.jobs_dir,
                0o700,
                True,
            ),
            "assignments_dir": PathPolicy(
                self.settings.assignments_dir,
                0o700,
                True,
            ),
            "registration_root": PathPolicy(
                self.settings.registration_root,
                0o700,
                True,
            ),
            "ssh_dir": PathPolicy(
                self.settings.known_hosts_file.parent,
                0o700,
                True,
            ),
            "vault_file": PathPolicy(
                vault_file,
                0o600,
                False,
            ),
            "vault_password_file": PathPolicy(
                vault_password_file,
                0o600,
                False,
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
    def _type_is_expected(
        metadata: os.stat_result,
        policy: PathPolicy,
    ) -> bool:
        if stat.S_ISLNK(metadata.st_mode):
            return False
        if policy.is_directory:
            return stat.S_ISDIR(metadata.st_mode)
        return stat.S_ISREG(metadata.st_mode)

    @classmethod
    def _check_path(
        cls,
        policy: PathPolicy,
        expected_uid: int | None,
        expected_gid: int | None,
    ) -> dict[str, bool]:
        try:
            metadata = policy.path.lstat()
        except OSError:
            return {
                "exists": False,
                "owner_ok": False,
                "group_ok": False,
                "mode_ok": False,
                "type_ok": False,
            }

        type_ok = cls._type_is_expected(metadata, policy)

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
                type_ok
                and stat.S_IMODE(metadata.st_mode) == policy.mode
            ),
            "type_ok": type_ok,
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

    @staticmethod
    def _open_policy(policy: PathPolicy) -> int:
        flags = os.O_RDONLY | os.O_CLOEXEC | os.O_NOFOLLOW
        if policy.is_directory:
            flags |= os.O_DIRECTORY
        return os.open(policy.path, flags)

    def repair(self) -> dict[str, object]:
        if os.geteuid() != 0:
            raise ControlError(
                code="root_required",
                message=(
                    "Controller permission repair must run as root"
                ),
                exit_code=3,
            )

        expected_uid, expected_gid = self._expected_ids()
        missing_principals: list[str] = []
        if expected_uid is None:
            missing_principals.append(self.settings.service_user)
        if expected_gid is None:
            missing_principals.append(self.settings.service_group)

        if missing_principals:
            raise ControlError(
                code="controller_permissions_repair_blocked",
                message="Controller permission repair is unsafe",
                exit_code=9,
                details={
                    "missing_paths": [],
                    "unsafe_paths": [],
                    "missing_principals": missing_principals,
                },
            )

        policies = self._policies()
        missing_paths: list[str] = []
        unsafe_paths: list[str] = []

        for name, policy in policies.items():
            try:
                metadata = policy.path.lstat()
            except FileNotFoundError:
                missing_paths.append(name)
                continue
            except OSError:
                unsafe_paths.append(name)
                continue

            if not self._type_is_expected(metadata, policy):
                unsafe_paths.append(name)

        if missing_paths or unsafe_paths:
            raise ControlError(
                code="controller_permissions_repair_blocked",
                message="Controller permission repair is unsafe",
                exit_code=9,
                details={
                    "missing_paths": missing_paths,
                    "unsafe_paths": unsafe_paths,
                },
            )

        opened: dict[str, tuple[PathPolicy, int]] = {}
        open_missing: list[str] = []
        open_unsafe: list[str] = []

        try:
            for name, policy in policies.items():
                try:
                    descriptor = self._open_policy(policy)
                except OSError as exc:
                    if exc.errno == errno.ENOENT:
                        open_missing.append(name)
                    else:
                        open_unsafe.append(name)
                    continue

                metadata = os.fstat(descriptor)
                if not self._type_is_expected(metadata, policy):
                    os.close(descriptor)
                    open_unsafe.append(name)
                    continue

                opened[name] = (policy, descriptor)

            if open_missing or open_unsafe:
                raise ControlError(
                    code="controller_permissions_repair_blocked",
                    message="Controller permission repair is unsafe",
                    exit_code=9,
                    details={
                        "missing_paths": open_missing,
                        "unsafe_paths": open_unsafe,
                    },
                )

            changed: list[str] = []

            for name, (policy, descriptor) in opened.items():
                metadata = os.fstat(descriptor)
                owner_or_group_changed = (
                    metadata.st_uid != expected_uid
                    or metadata.st_gid != expected_gid
                )
                mode_changed = (
                    stat.S_IMODE(metadata.st_mode) != policy.mode
                )

                if owner_or_group_changed:
                    os.fchown(
                        descriptor,
                        expected_uid,
                        expected_gid,
                    )
                if mode_changed:
                    os.fchmod(descriptor, policy.mode)

                if owner_or_group_changed or mode_changed:
                    changed.append(name)

        except ControlError:
            raise
        except OSError as exc:
            raise ControlError(
                code="controller_permissions_repair_failed",
                message="Controller permission repair failed",
                exit_code=10,
                details={"system_error": exc.__class__.__name__},
            ) from exc
        finally:
            for _, descriptor in opened.values():
                try:
                    os.close(descriptor)
                except OSError:
                    pass

        audit = self.check()
        return {
            "status": "ok",
            "changed": changed,
            "paths": audit["paths"],
        }
