from __future__ import annotations

import fcntl
import hashlib
import json
import os
import secrets
import stat
import subprocess
from collections.abc import Iterator
from contextlib import contextmanager
from dataclasses import asdict, dataclass
from datetime import datetime, timezone
from pathlib import Path

from .bundle_management import BundleManager
from .components import ComponentSpec, component_specs
from .errors import BackupError
from .extracted_metadata import apply_archive_metadata
from .fs import assert_safe_parents, fsync_directory, read_regular_bytes
from .locks import exclusive_lifecycle_lock, exclusive_operation_lock
from .manifest import BackupManifest
from .repository import BackupRepository
from .restore_journal import RestoreJournal
from .state_validation import StateValidator


@dataclass(frozen=True)
class StagedPath:
    component: str
    absolute_path: str
    production_path: Path
    staged_path: Path | None
    rollback_path: Path
    present: bool


@dataclass(frozen=True)
class StagedGeneration:
    backup_id: str
    restore_id: str
    extracted_root: Path
    paths: tuple[StagedPath, ...]
    manifest: BackupManifest


@dataclass(frozen=True)
class PreRestoreGeneration:
    root: Path
    components: tuple[str, ...]
    manifest_sha256: str


@dataclass(frozen=True)
class RestoreResult:
    backup_id: str
    phase: str
    services_restored: bool
    rollback_performed: bool


def _staging(message: str) -> BackupError:
    return BackupError(
        code="restore_staging_failed",
        message=message,
        exit_code=4,
    )


def _health(message: str) -> BackupError:
    return BackupError(
        code="restore_health_check_failed",
        message=message,
        exit_code=4,
    )


def _manual(restore_id: str) -> BackupError:
    return BackupError(
        code="restore_manual_recovery_required",
        message="Restore requires manual recovery",
        exit_code=6,
        details={"restore_id": restore_id},
    )


class RestoreService:
    def __init__(
        self,
        repository: BackupRepository,
        *,
        state_validator: StateValidator | None = None,
        fail_stage_component: str | None = None,
        fail_health_check: str | None = None,
        fail_rollback: bool = False,
    ) -> None:
        self.repository = repository
        self.settings = repository.settings
        self.state_validator = state_validator or StateValidator()
        self.fail_stage_component = fail_stage_component
        self.fail_health_check = fail_health_check
        self.fail_rollback = fail_rollback

    def _manager(self) -> BundleManager:
        return BundleManager(self.repository)

    def _assert_eligibility_unlocked(self, backup_id: str):
        manager = self._manager()
        verified = manager._verify_bundle(backup_id)
        evidence_verified, rehearsed = manager._evidence_state(verified)
        if not evidence_verified:
            raise BackupError(
                code="backup_not_verified",
                message="Backup verification evidence is missing or stale",
                exit_code=4,
            )
        if not rehearsed:
            raise BackupError(
                code="backup_not_rehearsed",
                message="Backup rehearsal evidence is missing or stale",
                exit_code=4,
            )
        return verified

    def prepare_restore(self, backup_id: str) -> RestoreJournal:
        self.repository.assert_rehearsed_eligibility(backup_id)
        self.repository.quiescence.assert_quiescent()
        return RestoreJournal.create(self.settings, backup_id)

    @staticmethod
    def _write_all(descriptor: int, raw: bytes) -> None:
        offset = 0
        while offset < len(raw):
            written = os.write(descriptor, raw[offset:])
            if written < 1:
                raise _staging("Restore copy made no progress")
            offset += written

    def _copy_path(self, source: Path, destination: Path) -> None:
        assert_safe_parents(destination)
        if destination.exists() or destination.is_symlink():
            raise _staging("Restore staging destination already exists")
        try:
            metadata = source.lstat()
        except OSError as exc:
            raise _staging("Restore staging source cannot be inspected") from exc
        if stat.S_ISDIR(metadata.st_mode):
            try:
                destination.mkdir(mode=0o700)
                os.chown(
                    destination,
                    metadata.st_uid,
                    metadata.st_gid,
                    follow_symlinks=False,
                )
                for child in sorted(source.iterdir(), key=lambda item: item.name):
                    self._copy_path(child, destination / child.name)
                os.chmod(
                    destination,
                    stat.S_IMODE(metadata.st_mode) & 0o1777,
                    follow_symlinks=False,
                )
                os.utime(
                    destination,
                    ns=(metadata.st_atime_ns, metadata.st_mtime_ns),
                    follow_symlinks=False,
                )
                fsync_directory(destination)
            except (OSError, BackupError) as exc:
                raise _staging("Restore directory staging failed") from exc
            return
        if stat.S_ISREG(metadata.st_mode):
            raw = read_regular_bytes(source, max_bytes=64 * 1024 * 1024 * 1024)
            flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL
            if hasattr(os, "O_NOFOLLOW"):
                flags |= os.O_NOFOLLOW
            try:
                descriptor = os.open(destination, flags, 0o600)
            except OSError as exc:
                raise _staging("Restore file staging failed") from exc
            try:
                os.fchown(descriptor, metadata.st_uid, metadata.st_gid)
                os.fchmod(descriptor, stat.S_IMODE(metadata.st_mode) & 0o1777)
                self._write_all(descriptor, raw)
                os.fsync(descriptor)
            except OSError as exc:
                raise _staging("Restore file metadata staging failed") from exc
            finally:
                os.close(descriptor)
            try:
                os.utime(
                    destination,
                    ns=(metadata.st_atime_ns, metadata.st_mtime_ns),
                    follow_symlinks=False,
                )
                fsync_directory(destination.parent)
            except (OSError, BackupError) as exc:
                raise _staging("Restore file staging synchronization failed") from exc
            return
        if stat.S_ISLNK(metadata.st_mode):
            try:
                target = os.readlink(source)
                os.symlink(target, destination)
                os.chown(
                    destination,
                    metadata.st_uid,
                    metadata.st_gid,
                    follow_symlinks=False,
                )
                fsync_directory(destination.parent)
            except (OSError, BackupError) as exc:
                raise _staging("Restore link staging failed") from exc
            return
        raise _staging("Restore staging source contains a special file")

    def _remove_path(self, path: Path) -> None:
        try:
            metadata = path.lstat()
        except OSError:
            return
        if stat.S_ISDIR(metadata.st_mode) and not stat.S_ISLNK(metadata.st_mode):
            for child in list(path.iterdir()):
                self._remove_path(child)
            path.rmdir()
        else:
            path.unlink()
        fsync_directory(path.parent)

    def _extract_generation(
        self,
        backup_id: str,
        transaction: RestoreJournal,
    ) -> tuple[Path, BackupManifest]:
        verified = self._assert_eligibility_unlocked(backup_id)
        extracted_root = transaction.directory / "extracted"
        if extracted_root.exists() or extracted_root.is_symlink():
            raise _staging("Restore extraction root already exists")
        try:
            extracted_root.mkdir(mode=0o700)
            os.chown(
                extracted_root,
                self.settings.expected_root_uid,
                self.settings.expected_root_gid,
            )
        except OSError as exc:
            raise _staging("Restore extraction root cannot be created") from exc
        for spec in component_specs(self.settings):
            temporary = extracted_root / f".extract-{spec.name}"
            archive_path = verified.path / spec.filename
            try:
                temporary.mkdir(mode=0o700)
                self.repository.archive_engine.extract_for_rehearsal(
                    spec,
                    archive_path,
                    temporary,
                )
                apply_archive_metadata(
                    self.repository.archive_engine,
                    spec,
                    archive_path,
                    temporary,
                )
                os.replace(
                    temporary / spec.namespace,
                    extracted_root / spec.namespace,
                )
                temporary.rmdir()
            except (OSError, BackupError) as exc:
                raise _staging("Restore component extraction failed") from exc
        return extracted_root, verified.manifest

    def _stage_path_name(self, restore_id: str, final_path: Path) -> str:
        suffix = final_path.name or "root"
        return f".alt-deploy-{restore_id}-stage-{suffix}"

    def _rollback_path_name(self, restore_id: str, final_path: Path) -> str:
        suffix = final_path.name or "root"
        return f".alt-deploy-{restore_id}-rollback-{suffix}"

    def _insert_live_vault(self, staged_ansible: Path) -> None:
        self.repository.secrets.assert_matches(
            self._assert_eligibility_unlocked(
                self._current_backup_id
            ).manifest.secret_identities
        )
        destination = staged_ansible / "group_vars" / "vault.yml"
        destination.parent.mkdir(parents=True, exist_ok=True)
        self._copy_path(self.settings.vault_file, destination)

    def stage(
        self,
        backup_id: str,
        transaction: RestoreJournal,
    ) -> StagedGeneration:
        if transaction.phase != "prepared" or transaction.backup_id != backup_id:
            raise _staging("Restore transaction is not prepared")
        self._current_backup_id = backup_id
        created: list[Path] = []
        extracted_root: Path | None = None
        try:
            extracted_root, manifest = self._extract_generation(
                backup_id,
                transaction,
            )
            staged_paths: list[StagedPath] = []
            for component in manifest.components:
                if self.fail_stage_component == component.name:
                    raise _staging("Injected restore staging failure")
                for record in component.paths:
                    production = self.repository._controller_path(
                        record.absolute_path
                    )
                    assert_safe_parents(production)
                    parent = production.parent
                    try:
                        parent_metadata = parent.lstat()
                    except OSError as exc:
                        raise _staging(
                            "Restore production parent cannot be inspected"
                        ) from exc
                    if not stat.S_ISDIR(parent_metadata.st_mode):
                        raise _staging("Restore production parent is unsafe")
                    staged = parent / self._stage_path_name(
                        transaction.restore_id,
                        production,
                    )
                    rollback = parent / self._rollback_path_name(
                        transaction.restore_id,
                        production,
                    )
                    if any(
                        path.exists() or path.is_symlink()
                        for path in (staged, rollback)
                    ):
                        raise _staging("Restore sibling path already exists")
                    staged_value: Path | None = None
                    if record.present:
                        source = (
                            extracted_root
                            / component.namespace
                            / record.absolute_path.lstrip("/")
                        )
                        self._copy_path(source, staged)
                        created.append(staged)
                        staged_value = staged
                        if component.name == "ansible":
                            self._insert_live_vault(staged)
                    staged_paths.append(
                        StagedPath(
                            component=component.name,
                            absolute_path=record.absolute_path,
                            production_path=production,
                            staged_path=staged_value,
                            rollback_path=rollback,
                            present=record.present,
                        )
                    )
            transaction.transition(
                "prepared",
                "staged",
                {
                    "paths": [
                        {
                            "component": path.component,
                            "absolute_path": path.absolute_path,
                            "present": path.present,
                        }
                        for path in staged_paths
                    ]
                },
            )
            return StagedGeneration(
                backup_id=backup_id,
                restore_id=transaction.restore_id,
                extracted_root=extracted_root,
                paths=tuple(staged_paths),
                manifest=manifest,
            )
        except BackupError:
            for path in reversed(created):
                self._remove_path(path)
            if extracted_root is not None:
                self._remove_path(extracted_root)
            raise
        except OSError as exc:
            for path in reversed(created):
                self._remove_path(path)
            if extracted_root is not None:
                self._remove_path(extracted_root)
            raise _staging("Restore staging failed") from exc

    def create_pre_restore_snapshot(
        self,
        transaction: RestoreJournal,
    ) -> PreRestoreGeneration:
        timestamp = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")
        parent = self.settings.backup_root / f"pre-restore-{timestamp}"
        root = parent / transaction.restore_id
        if parent.exists() or parent.is_symlink():
            raise _staging("Pre-restore snapshot identifier collided")
        try:
            root.mkdir(parents=True, mode=0o700)
            os.chown(
                parent,
                self.settings.expected_root_uid,
                self.settings.expected_root_gid,
            )
            os.chmod(parent, 0o700)
            os.chown(
                root,
                self.settings.expected_root_uid,
                self.settings.expected_root_gid,
            )
            os.chmod(root, 0o700)
        except OSError as exc:
            raise _staging("Pre-restore snapshot root cannot be created") from exc
        records: list[dict[str, object]] = []
        try:
            for spec in component_specs(self.settings):
                record = self.repository.archive_engine.capture(
                    spec,
                    root / spec.filename,
                )
                records.append(
                    {
                        "name": record.name,
                        "filename": record.filename,
                        "size_bytes": record.size_bytes,
                        "sha256": record.sha256,
                    }
                )
            secret_identities = self.repository.secrets.capture()
            unit_states = self.repository.systemd.capture()
            payload = {
                "schema_version": 1,
                "restore_id": transaction.restore_id,
                "backup_id": transaction.backup_id,
                "created_at": datetime.now(timezone.utc).isoformat(),
                "components": records,
                "systemd_units": [
                    asdict(state) for state in unit_states
                ],
                "secret_identities": [
                    asdict(identity)
                    for identity in secret_identities
                ],
            }
            raw = (
                json.dumps(
                    payload,
                    ensure_ascii=False,
                    sort_keys=True,
                    indent=2,
                )
                + "\n"
            ).encode("utf-8")
            self.repository._write_private_bytes(
                root / "pre-restore-manifest.json",
                raw,
            )
            return PreRestoreGeneration(
                root=root,
                components=tuple(
                    str(record["name"]) for record in records
                ),
                manifest_sha256=hashlib.sha256(raw).hexdigest(),
            )
        except (BackupError, OSError):
            self._remove_path(parent)
            raise

    def _tree_digest(self, path: Path) -> str:
        digest = hashlib.sha256()

        def add(current: Path, relative: str) -> None:
            if not current.exists() and not current.is_symlink():
                digest.update(f"absent:{relative}\n".encode())
                return
            metadata = current.lstat()
            mode = stat.S_IMODE(metadata.st_mode)
            digest.update(
                f"{relative}:{metadata.st_uid}:{metadata.st_gid}:{mode}:".encode()
            )
            if stat.S_ISDIR(metadata.st_mode):
                digest.update(b"directory\n")
                for child in sorted(current.iterdir(), key=lambda item: item.name):
                    add(child, f"{relative}/{child.name}")
            elif stat.S_ISREG(metadata.st_mode):
                digest.update(b"regular:")
                raw = read_regular_bytes(
                    current,
                    max_bytes=64 * 1024 * 1024 * 1024,
                )
                digest.update(hashlib.sha256(raw).digest())
                digest.update(b"\n")
            elif stat.S_ISLNK(metadata.st_mode):
                digest.update(b"symlink:")
                digest.update(os.readlink(current).encode("utf-8"))
                digest.update(b"\n")
            else:
                raise _staging("Production path contains a special file")

        add(path, path.name or "/")
        return digest.hexdigest()

    @contextmanager
    def _staged_lifecycle_lock(
        self,
        staged: StagedGeneration,
    ) -> Iterator[None]:
        state = next(
            (
                path
                for path in staged.paths
                if path.absolute_path == "/var/lib/alt-deploy"
            ),
            None,
        )
        if state is None or state.staged_path is None:
            raise _staging("Staged controller lifecycle lock is unavailable")
        lock_path = state.staged_path / "workstationctl.lock"
        flags = os.O_RDWR
        if hasattr(os, "O_NOFOLLOW"):
            flags |= os.O_NOFOLLOW
        try:
            descriptor = os.open(lock_path, flags)
        except OSError as exc:
            raise _staging("Staged lifecycle lock cannot be opened") from exc
        try:
            metadata = os.fstat(descriptor)
            if not stat.S_ISREG(metadata.st_mode):
                raise _staging("Staged lifecycle lock is unsafe")
            fcntl.flock(descriptor, fcntl.LOCK_EX)
            try:
                yield
            finally:
                fcntl.flock(descriptor, fcntl.LOCK_UN)
        finally:
            os.close(descriptor)

    def _daemon_reload(self) -> None:
        try:
            result = subprocess.run(
                [str(self.settings.systemctl_path), "daemon-reload"],
                check=False,
                capture_output=True,
                timeout=60,
            )
        except (OSError, subprocess.TimeoutExpired) as exc:
            raise _health("systemd daemon-reload failed") from exc
        if result.returncode != 0:
            raise _health("systemd daemon-reload failed")

    def _compile_python_root(self, root: Path) -> None:
        if not root.exists():
            return
        for path in sorted(root.rglob("*.py")):
            raw = read_regular_bytes(path, max_bytes=64 * 1024 * 1024)
            try:
                compile(raw.decode("utf-8"), str(path), "exec")
            except (UnicodeDecodeError, SyntaxError) as exc:
                raise _health("Restored runtime Python syntax is invalid") from exc

    def _run_health_command(
        self,
        arguments: list[str],
        *,
        cwd: Path | None = None,
        env: dict[str, str] | None = None,
        name: str,
    ) -> None:
        if self.fail_health_check == name:
            raise _health(f"Injected restore health failure: {name}")
        try:
            result = subprocess.run(
                arguments,
                cwd=cwd,
                env=env,
                check=False,
                capture_output=True,
                timeout=120,
            )
        except (OSError, subprocess.TimeoutExpired) as exc:
            raise _health(f"Restore health check failed: {name}") from exc
        if result.returncode != 0:
            raise _health(f"Restore health check failed: {name}")

    def _health_checks(self, manifest: BackupManifest) -> tuple[str, ...]:
        if self.fail_health_check == "runtime_syntax":
            raise _health("Injected restore health failure: runtime_syntax")
        self._compile_python_root(self.settings.runtime_control_root)
        self._compile_python_root(self.settings.runtime_api_root)

        for path in (
            self.settings.workstationctl_path,
            self.settings.worker_path,
            self.settings.stage_helper_path,
            self.settings.bootstrap_root / "bootstrap.sh",
            self.settings.bootstrap_root / "alt-bootstrap-register",
        ):
            if not path.exists():
                continue
            raw = read_regular_bytes(path, max_bytes=16 * 1024 * 1024)
            lines = raw.splitlines()
            if lines and b"sh" in lines[0]:
                self._run_health_command(
                    ["/bin/bash", "-n", str(path)],
                    name="shell_syntax",
                )

        units = [
            self.settings.systemd_root / state.name
            for state in manifest.systemd_units
            if state.load_state != "not-found"
        ]
        if units:
            self._run_health_command(
                [
                    str(self.settings.systemd_analyze_path),
                    "verify",
                    *[str(path) for path in units],
                ],
                name="systemd_units",
            )

        ansible_playbooks = sorted(
            (self.settings.ansible_root / "playbooks").glob("*.yml")
        )
        for playbook in ansible_playbooks:
            environment = os.environ.copy()
            environment["ANSIBLE_CONFIG"] = str(
                self.settings.ansible_root / "ansible.cfg"
            )
            self._run_health_command(
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
                cwd=self.settings.ansible_root,
                env=environment,
                name="ansible_syntax",
            )

        if self.fail_health_check == "state_validation":
            raise _health("Injected restore health failure: state_validation")
        self.state_validator._validate_jobs(
            self.settings.controller_state_root / "jobs"
        )
        self.state_validator._validate_assignments(
            self.settings.controller_state_root / "assignments"
        )
        self.state_validator._validate_registrations(
            self.settings.registration_root
        )
        self.state_validator._validate_machine_archives(
            self.settings.controller_state_root / "machine-archives"
        )
        self.repository.secrets.assert_matches(manifest.secret_identities)
        self.repository.quiescence.assert_quiescent()
        return (
            "runtime_syntax",
            "shell_syntax",
            "systemd_units",
            "ansible_syntax",
            "state_validation",
            "secret_identities",
            "quiescence",
        )

    def _move_originals(
        self,
        staged: StagedGeneration,
    ) -> tuple[dict[str, str], ...]:
        evidence: list[dict[str, str]] = []
        for path in staged.paths:
            production_exists = (
                path.production_path.exists()
                or path.production_path.is_symlink()
            )
            if production_exists:
                try:
                    os.replace(path.production_path, path.rollback_path)
                    fsync_directory(path.production_path.parent)
                except (OSError, BackupError) as exc:
                    raise _staging("Current production path cannot be moved") from exc
            evidence.append(
                {
                    "absolute_path": path.absolute_path,
                    "rollback": str(path.rollback_path),
                    "previously_present": str(production_exists).lower(),
                }
            )
        return tuple(evidence)

    def _install_staged(self, staged: StagedGeneration) -> None:
        for path in staged.paths:
            if path.present:
                if path.staged_path is None:
                    raise _staging("Expected staged path is missing")
                try:
                    os.replace(path.staged_path, path.production_path)
                    fsync_directory(path.production_path.parent)
                except (OSError, BackupError) as exc:
                    raise _staging("Staged path cannot be installed") from exc

    def _rollback(
        self,
        staged: StagedGeneration,
        journal: RestoreJournal,
        pre_states,
        pre_digests: dict[str, str],
    ) -> None:
        self.repository.systemd.stop_maintenance()
        if self.fail_rollback:
            raise _manual(journal.restore_id)
        for path in reversed(staged.paths):
            if path.production_path.exists() or path.production_path.is_symlink():
                self._remove_path(path.production_path)
            if path.rollback_path.exists() or path.rollback_path.is_symlink():
                try:
                    os.replace(path.rollback_path, path.production_path)
                    fsync_directory(path.production_path.parent)
                except (OSError, BackupError) as exc:
                    raise _manual(journal.restore_id) from exc
        self._daemon_reload()
        self.repository.systemd.restore(
            pre_states,
            activate_health_services=True,
        )
        for path in staged.paths:
            if self._tree_digest(path.production_path) != pre_digests[
                path.absolute_path
            ]:
                raise _manual(journal.restore_id)
        journal.transition(
            journal.phase,
            "rolled_back",
            {"proof": "content_digests_match"},
        )

    def _cleanup_success(self, staged: StagedGeneration) -> None:
        for path in staged.paths:
            if path.rollback_path.exists() or path.rollback_path.is_symlink():
                self._remove_path(path.rollback_path)
            if path.staged_path is not None and (
                path.staged_path.exists() or path.staged_path.is_symlink()
            ):
                self._remove_path(path.staged_path)
        if staged.extracted_root.exists():
            self._remove_path(staged.extracted_root)

    def restore(self, backup_id: str) -> RestoreResult:
        self.repository.assert_rehearsed_eligibility(backup_id)
        self.repository.quiescence.assert_quiescent()
        with exclusive_operation_lock(self.settings):
            verified = self._assert_eligibility_unlocked(backup_id)
            pre_states = self.repository.systemd.capture()
            journal = RestoreJournal.create(self.settings, backup_id)
            staged: StagedGeneration | None = None
            mutation_started = False
            pre_digests: dict[str, str] = {}
            try:
                self.repository.systemd.stop_maintenance()
                with exclusive_lifecycle_lock(self.settings):
                    verified = self._assert_eligibility_unlocked(backup_id)
                    self.repository.secrets.assert_matches(
                        verified.manifest.secret_identities
                    )
                    self.repository.quiescence.assert_quiescent()
                    snapshot = self.create_pre_restore_snapshot(journal)
                    staged = self.stage(backup_id, journal)
                    journal.transition(
                        "staged",
                        "services_stopped",
                        {
                            "pre_restore_manifest_sha256": (
                                snapshot.manifest_sha256
                            )
                        },
                    )
                    pre_digests = {
                        path.absolute_path: self._tree_digest(
                            path.production_path
                        )
                        for path in staged.paths
                    }
                    with self._staged_lifecycle_lock(staged):
                        moved = self._move_originals(staged)
                        mutation_started = True
                        journal.transition(
                            "services_stopped",
                            "originals_moved",
                            {"paths": list(moved)},
                        )
                        self._install_staged(staged)
                        journal.transition(
                            "originals_moved",
                            "installed",
                            {"path_count": len(staged.paths)},
                        )
                        self._daemon_reload()
                        journal.transition(
                            "installed",
                            "daemon_reloaded",
                            {},
                        )
                        checks = self._health_checks(staged.manifest)
                        self.repository.systemd.restore(
                            staged.manifest.systemd_units,
                            activate_health_services=True,
                        )
                        journal.transition(
                            "daemon_reloaded",
                            "health_checked",
                            {"checks": list(checks)},
                        )
                        journal.transition(
                            "health_checked",
                            "committed",
                            {"services_restored": True},
                        )
                self._cleanup_success(staged)
                return RestoreResult(
                    backup_id=backup_id,
                    phase="committed",
                    services_restored=True,
                    rollback_performed=False,
                )
            except BackupError as original:
                if mutation_started and staged is not None:
                    try:
                        self._rollback(
                            staged,
                            journal,
                            pre_states,
                            pre_digests,
                        )
                    except BackupError:
                        try:
                            journal.transition(
                                journal.phase,
                                "manual_recovery_required",
                                {"services_stopped": True},
                            )
                        except BackupError:
                            pass
                        self.repository.systemd.stop_maintenance()
                        raise _manual(journal.restore_id)
                    raise original
                if staged is not None:
                    self._cleanup_success(staged)
                self.repository.systemd.restore(
                    pre_states,
                    activate_health_services=True,
                )
                raise
