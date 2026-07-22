from __future__ import annotations

import hashlib
import os
import shutil
import stat
import subprocess
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path

from . import __version__
from .bundle_management import BundleManager
from .components import component_specs
from .errors import BackupError
from .fs import assert_safe_parents, fsync_directory, read_regular_bytes
from .locks import exclusive_operation_lock
from .manifest import RehearsalEvidence, SCHEMA_VERSION
from .repository import BackupRepository
from .state_validation import StateValidator


@dataclass(frozen=True)
class RehearsalResult:
    backup_id: str
    manifest_sha256: str
    check_count: int
    rehearsal_passed: bool


def _failed(message: str) -> BackupError:
    return BackupError(
        code="backup_rehearsal_failed",
        message=message,
        exit_code=4,
    )


class RehearsalService:
    def __init__(
        self,
        repository: BackupRepository,
        *,
        state_validator: StateValidator | None = None,
    ) -> None:
        self.repository = repository
        self.settings = repository.settings
        self.state_validator = state_validator or StateValidator()

    def _ensure_private_root(self) -> None:
        path = self.settings.rehearsal_root
        assert_safe_parents(path)
        if not path.exists() and not path.is_symlink():
            try:
                path.mkdir(parents=True, mode=0o700)
                os.chown(
                    path,
                    self.settings.expected_root_uid,
                    self.settings.expected_root_gid,
                )
                os.chmod(path, 0o700)
                fsync_directory(path.parent)
            except (OSError, BackupError) as exc:
                raise _failed("Rehearsal root cannot be created safely") from exc
        try:
            metadata = path.lstat()
        except OSError as exc:
            raise _failed("Rehearsal root cannot be inspected") from exc
        if (
            not stat.S_ISDIR(metadata.st_mode)
            or stat.S_ISLNK(metadata.st_mode)
            or metadata.st_uid != self.settings.expected_root_uid
            or metadata.st_gid != self.settings.expected_root_gid
            or stat.S_IMODE(metadata.st_mode) != 0o700
        ):
            raise _failed("Rehearsal root metadata is unsafe")

    def _create_selected_root(self, backup_id: str) -> Path:
        self._ensure_private_root()
        selected = self.settings.rehearsal_root / backup_id
        if selected.exists() or selected.is_symlink():
            raise _failed(
                "A previous rehearsal tree exists and requires explicit removal"
            )
        try:
            selected.mkdir(mode=0o700)
            os.chown(
                selected,
                self.settings.expected_root_uid,
                self.settings.expected_root_gid,
            )
            os.chmod(selected, 0o700)
            fsync_directory(selected.parent)
        except (OSError, BackupError) as exc:
            raise _failed("Rehearsal tree cannot be created safely") from exc
        return selected

    def _remove_tree(self, path: Path) -> None:
        try:
            root_metadata = path.lstat()
        except OSError:
            return
        if not stat.S_ISDIR(root_metadata.st_mode) or stat.S_ISLNK(
            root_metadata.st_mode
        ):
            raise _failed("Rehearsal cleanup target is unsafe")
        expected_device = root_metadata.st_dev

        def remove(current: Path) -> None:
            try:
                metadata = current.lstat()
            except OSError as exc:
                raise _failed("Rehearsal cleanup entry cannot be inspected") from exc
            if metadata.st_dev != expected_device:
                raise _failed("Rehearsal cleanup crossed a filesystem boundary")
            if stat.S_ISDIR(metadata.st_mode) and not stat.S_ISLNK(
                metadata.st_mode
            ):
                try:
                    children = list(current.iterdir())
                except OSError as exc:
                    raise _failed("Rehearsal cleanup cannot enumerate a directory") from exc
                for child in children:
                    remove(child)
                try:
                    current.rmdir()
                except OSError as exc:
                    raise _failed("Rehearsal cleanup cannot remove a directory") from exc
            else:
                try:
                    current.unlink()
                except OSError as exc:
                    raise _failed("Rehearsal cleanup cannot remove a file") from exc

        remove(path)
        fsync_directory(path.parent)

    def _extract_all(self, selected: Path, bundle_path: Path) -> None:
        for spec in component_specs(self.settings):
            temporary = selected / f".extract-{spec.name}"
            try:
                temporary.mkdir(mode=0o700)
                self.repository.archive_engine.extract_for_rehearsal(
                    spec,
                    bundle_path / spec.filename,
                    temporary,
                )
                source = temporary / spec.namespace
                destination = selected / spec.namespace
                if not source.is_dir() or source.is_symlink():
                    raise _failed("Extracted component namespace is missing")
                if destination.exists() or destination.is_symlink():
                    raise _failed("Extracted component namespace is duplicated")
                os.replace(source, destination)
                temporary.rmdir()
                fsync_directory(selected)
            except BackupError:
                raise
            except OSError as exc:
                raise _failed("Component rehearsal extraction failed") from exc

    @staticmethod
    def _kind(metadata: os.stat_result) -> str:
        if stat.S_ISDIR(metadata.st_mode):
            return "directory"
        if stat.S_ISREG(metadata.st_mode):
            return "regular"
        if stat.S_ISLNK(metadata.st_mode):
            return "symlink"
        return "special"

    def _validate_manifest_paths(self, selected: Path, manifest) -> str:
        for component in manifest.components:
            for record in component.paths:
                path = (
                    selected
                    / component.namespace
                    / record.absolute_path.lstrip("/")
                )
                exists = path.exists() or path.is_symlink()
                if record.present != exists:
                    raise _failed(
                        "Extracted component presence does not match manifest"
                    )
                if not record.present:
                    continue
                try:
                    metadata = path.lstat()
                except OSError as exc:
                    raise _failed("Extracted component cannot be inspected") from exc
                if self._kind(metadata) != record.kind:
                    raise _failed("Extracted component kind does not match manifest")
                if record.mode is not None and stat.S_IMODE(metadata.st_mode) != record.mode:
                    raise _failed("Extracted component mode does not match manifest")
        return "manifest_metadata"

    def _compile_python(self, selected: Path) -> str:
        roots = (
            selected / "runtime" / "opt" / "alt-deploy-control",
            selected / "runtime" / "opt" / "alt-deploy-api",
        )
        for root in roots:
            if not root.exists():
                continue
            for path in sorted(root.rglob("*.py")):
                if path.is_symlink() or not path.is_file():
                    raise _failed("Restored Python source is unsafe")
                raw = read_regular_bytes(path, max_bytes=64 * 1024 * 1024)
                try:
                    source = raw.decode("utf-8")
                    compile(source, str(path), "exec", dont_inherit=True)
                except (UnicodeDecodeError, SyntaxError) as exc:
                    raise _failed("Restored Python source has invalid syntax") from exc
        return "python_syntax"

    def _run_bounded(
        self,
        arguments: list[str],
        *,
        cwd: Path | None = None,
        env: dict[str, str] | None = None,
        message: str,
    ) -> None:
        try:
            result = subprocess.run(
                arguments,
                cwd=cwd,
                env=env,
                check=False,
                text=True,
                capture_output=True,
                timeout=120,
            )
        except (OSError, subprocess.TimeoutExpired) as exc:
            raise _failed(message) from exc
        if (
            result.returncode != 0
            or len(result.stdout) > 1024 * 1024
            or len(result.stderr) > 1024 * 1024
        ):
            raise _failed(message)

    def _validate_shell(self, selected: Path) -> str:
        candidates = (
            selected / "runtime" / "usr" / "local" / "sbin" / "workstationctl",
            selected / "runtime" / "usr" / "local" / "libexec" / "alt-provision-worker",
            selected / "runtime" / "usr" / "local" / "libexec" / "alt-job-stage",
            selected / "deployment-assets" / "srv" / "alt-deploy" / "bootstrap" / "bootstrap.sh",
            selected / "deployment-assets" / "srv" / "alt-deploy" / "bootstrap" / "alt-bootstrap-register",
        )
        for path in candidates:
            if not path.exists():
                continue
            raw = read_regular_bytes(path, max_bytes=16 * 1024 * 1024)
            first_line = raw.splitlines()[0] if raw.splitlines() else b""
            if b"sh" in first_line:
                self._run_bounded(
                    ["/bin/bash", "-n", str(path)],
                    message="Restored shell entrypoint has invalid syntax",
                )
        return "shell_syntax"

    def _validate_systemd(self, selected: Path) -> str:
        unit_root = selected / "systemd" / "etc" / "systemd" / "system"
        units = sorted(unit_root.glob("alt-deploy-*")) if unit_root.exists() else []
        for unit in units:
            if unit.is_symlink() or not unit.is_file():
                raise _failed("Restored systemd unit is unsafe")
        if units:
            self._run_bounded(
                [
                    str(self.settings.systemd_analyze_path),
                    "verify",
                    *[str(unit) for unit in units],
                ],
                message="Restored systemd unit verification failed",
            )
        return "systemd_units"

    def _validate_ansible(self, selected: Path) -> str:
        ansible_root = selected / "ansible" / "home" / "altserver" / "ansible"
        playbooks = (
            sorted((ansible_root / "playbooks").glob("*.yml"))
            if (ansible_root / "playbooks").exists()
            else []
        )
        for playbook in playbooks:
            if playbook.is_symlink() or not playbook.is_file():
                raise _failed("Restored Ansible playbook is unsafe")
            environment = os.environ.copy()
            environment["ANSIBLE_CONFIG"] = str(ansible_root / "ansible.cfg")
            self._run_bounded(
                [
                    str(self.settings.ansible_playbook_path),
                    "--syntax-check",
                    "--inventory",
                    "localhost,",
                    "--vault-password-file",
                    str(self.settings.vault_password_file),
                    "--extra-vars",
                    f"@{self.settings.vault_file}",
                    str(playbook),
                ],
                cwd=ansible_root,
                env=environment,
                message="Restored Ansible syntax verification failed",
            )
        return "ansible_syntax"

    def _scan_secrets(self, selected: Path) -> str:
        prohibited = (
            selected
            / "ansible"
            / "home"
            / "altserver"
            / "ansible"
            / "group_vars"
            / "vault.yml",
            selected
            / "ansible"
            / "home"
            / "altserver"
            / ".ansible-vault-pass",
            selected
            / "ansible"
            / "home"
            / "altserver"
            / ".ssh"
            / "id_ed25519",
        )
        if any(path.exists() or path.is_symlink() for path in prohibited):
            raise _failed("Prohibited secret path exists in rehearsal tree")
        secret_values = tuple(
            raw
            for raw in (
                read_regular_bytes(
                    self.settings.vault_file,
                    max_bytes=16 * 1024 * 1024,
                ),
                read_regular_bytes(
                    self.settings.vault_password_file,
                    max_bytes=64 * 1024,
                ),
                read_regular_bytes(
                    self.settings.ssh_private_key,
                    max_bytes=1024 * 1024,
                ),
            )
            if raw
        )
        for path in sorted(selected.rglob("*")):
            if path.is_symlink() or not path.is_file():
                continue
            metadata = path.lstat()
            if metadata.st_size > 64 * 1024 * 1024:
                continue
            raw = read_regular_bytes(path, max_bytes=64 * 1024 * 1024)
            if any(secret in raw for secret in secret_values):
                raise _failed("Secret content exists in rehearsal tree")
        return "secret_exclusion"

    def rehearse(self, backup_id: str) -> RehearsalResult:
        self.repository.verify(backup_id, write_evidence=True)
        selected: Path | None = None
        successful = False
        try:
            with exclusive_operation_lock(self.settings):
                manager = BundleManager(self.repository)
                verified = manager._verify_bundle(backup_id)
                verification_raw = read_regular_bytes(
                    verified.path / "verification.json",
                    max_bytes=4 * 1024 * 1024,
                )
                selected = self._create_selected_root(backup_id)
                self._extract_all(selected, verified.path)
                checks = (
                    "component_extraction",
                    self._validate_manifest_paths(selected, verified.manifest),
                    self._compile_python(selected),
                    self._validate_shell(selected),
                    self._validate_systemd(selected),
                    self._validate_ansible(selected),
                    *self.state_validator.validate_tree(
                        selected,
                        verified.manifest,
                    ),
                    self._scan_secrets(selected),
                )
                evidence = RehearsalEvidence(
                    schema_version=SCHEMA_VERSION,
                    utility_version=__version__,
                    backup_id=backup_id,
                    completed_at=datetime.now(timezone.utc).isoformat(),
                    manifest_sha256=verified.manifest_sha256,
                    verification_sha256=hashlib.sha256(
                        verification_raw
                    ).hexdigest(),
                    secret_identities=verified.manifest.secret_identities,
                    passed_checks=tuple(checks),
                    status="ok",
                )
                self.repository._write_private_bytes(
                    verified.path / "rehearsal.json",
                    evidence.to_bytes(),
                )
                successful = True
                result = RehearsalResult(
                    backup_id=backup_id,
                    manifest_sha256=verified.manifest_sha256,
                    check_count=len(checks),
                    rehearsal_passed=True,
                )
            if selected is not None:
                self._remove_tree(selected)
            return result
        except BackupError as exc:
            if exc.code == "backup_rehearsal_failed":
                raise
            raise _failed("Backup restore rehearsal failed") from exc
        except (OSError, ValueError) as exc:
            raise _failed("Backup restore rehearsal failed") from exc
        finally:
            if successful and selected is not None and selected.exists():
                self._remove_tree(selected)
