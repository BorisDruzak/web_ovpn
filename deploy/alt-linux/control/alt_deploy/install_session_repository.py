from __future__ import annotations

import json
import hashlib
import os
import re
import secrets
import stat
from collections.abc import Mapping
from pathlib import Path
from typing import Any

from .config import Settings
from .errors import ControlError


SESSION_ID_RE = re.compile(
    r"^install-\d{8}T\d{6}Z-[0-9a-f]{8}$"
)
_SHA256_RE = re.compile(r"^[0-9a-f]{64}$")
EXECUTION_BUNDLE_FILES: tuple[str, ...] = (
    "execution-manifest.json",
    "execution-manifest-signature.json",
    "autoinstall.scm",
    "vm-profile.scm",
    "pkg-groups.tar",
    "install-scripts.tar",
)
_EXECUTION_DIGEST_FILE = "execution-digests.json"
_EXECUTION_ALL_FILES = frozenset(
    (*EXECUTION_BUNDLE_FILES, _EXECUTION_DIGEST_FILE)
)
_MAX_EXECUTION_FILE_BYTES = 64 * 1024 * 1024


class InstallSessionRepository:
    """Private, file-backed persistence for validated install sessions."""

    def __init__(self, settings: Settings) -> None:
        self.settings = settings

    def _service_owner(self) -> tuple[int, int] | None:
        """Return the service account only when root must hand files over.

        Normal API writes already run as ``altserver``.  Root-only approval is
        the one path that would otherwise create unreadable plan artefacts.
        """
        if os.name == "nt" or not hasattr(os, "geteuid") or os.geteuid() != 0:
            return None
        try:
            import pwd

            account = pwd.getpwnam(self.settings.service_user)
        except (ImportError, KeyError) as exc:
            raise self._failed("Install service account cannot be resolved") from exc
        return account.pw_uid, account.pw_gid

    def _set_owner(self, descriptor: int, owner: tuple[int, int] | None) -> None:
        if owner is None:
            return
        try:
            os.fchown(descriptor, owner[0], owner[1])
        except OSError as exc:
            raise self._failed("Install session ownership cannot be assigned") from exc

    def _make_private_directory(
        self, path: Path, *, owner: tuple[int, int] | None = None
    ) -> None:
        try:
            path.mkdir(mode=0o700)
            os.chmod(path, 0o700)
            if owner is not None:
                os.chown(path, owner[0], owner[1])
        except OSError as exc:
            raise self._failed("Install session directory cannot be created") from exc

    @staticmethod
    def _invalid(message: str) -> ControlError:
        return ControlError(
            code="install_session_invalid",
            message=message,
            exit_code=4,
        )

    @staticmethod
    def _failed(message: str) -> ControlError:
        return ControlError(
            code="install_session_storage_failed",
            message=message,
            exit_code=6,
        )

    @staticmethod
    def _validate_session_id(session_id: str) -> str:
        normalized = session_id.strip()
        if not SESSION_ID_RE.fullmatch(normalized):
            raise ControlError(
                code="install_session_id_invalid",
                message="Install session ID is invalid",
                exit_code=4,
            )
        return normalized

    @staticmethod
    def _encoded_json(payload: Mapping[str, object]) -> bytes:
        return (
            json.dumps(dict(payload), ensure_ascii=True, sort_keys=True)
            + "\n"
        ).encode("utf-8")

    def _ensure_private_directory(self, path: Path) -> None:
        if path.exists() or path.is_symlink():
            metadata = path.lstat()
            if not stat.S_ISDIR(metadata.st_mode):
                raise self._invalid(
                    "Install session root is not a directory"
                )
            if os.name != "nt" and stat.S_IMODE(metadata.st_mode) != 0o700:
                raise self._invalid(
                    "Install session directory permissions are invalid"
                )
            return
        try:
            path.mkdir(parents=True, mode=0o700)
            os.chmod(path, 0o700)
        except OSError as exc:
            raise self._failed(
                "Install session directory cannot be created"
            ) from exc

    def _fsync_directory(self, path: Path) -> None:
        if os.name == "nt":
            return
        flags = os.O_RDONLY
        if hasattr(os, "O_DIRECTORY"):
            flags |= os.O_DIRECTORY
        try:
            descriptor = os.open(path, flags)
        except OSError as exc:
            raise self._failed(
                "Install session directory cannot be synchronized"
            ) from exc
        try:
            os.fsync(descriptor)
        except OSError as exc:
            raise self._failed(
                "Install session directory synchronization failed"
            ) from exc
        finally:
            os.close(descriptor)

    def _create_file(
        self,
        path: Path,
        data: bytes,
        *,
        owner: tuple[int, int] | None = None,
    ) -> None:
        flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL
        if hasattr(os, "O_BINARY"):
            flags |= os.O_BINARY
        if hasattr(os, "O_NOFOLLOW"):
            flags |= os.O_NOFOLLOW
        try:
            descriptor = os.open(path, flags, 0o600)
        except OSError as exc:
            raise self._failed(
                "Install session file cannot be created"
            ) from exc
        try:
            os.fchmod(descriptor, 0o600)
            self._set_owner(descriptor, owner)
            offset = 0
            while offset < len(data):
                written = os.write(descriptor, data[offset:])
                if written < 1:
                    raise self._failed(
                        "Install session file write made no progress"
                    )
                offset += written
            os.fsync(descriptor)
        except OSError as exc:
            raise self._failed(
                "Install session file cannot be written"
            ) from exc
        finally:
            os.close(descriptor)

    def _read_regular_bytes(self, path: Path) -> bytes:
        try:
            before = path.lstat()
        except OSError as exc:
            raise self._invalid(
                "Install session file cannot be inspected"
            ) from exc
        if not stat.S_ISREG(before.st_mode):
            raise self._invalid(
                "Install session state contains a non-regular file"
            )
        flags = os.O_RDONLY
        if hasattr(os, "O_NOFOLLOW"):
            flags |= os.O_NOFOLLOW
        try:
            descriptor = os.open(path, flags)
        except OSError as exc:
            raise self._invalid(
                "Install session file cannot be opened safely"
            ) from exc
        try:
            opened = os.fstat(descriptor)
            if not stat.S_ISREG(opened.st_mode):
                raise self._invalid(
                    "Install session file changed during safe open"
                )
            chunks: list[bytes] = []
            while True:
                chunk = os.read(descriptor, 64 * 1024)
                if not chunk:
                    break
                chunks.append(chunk)
            return b"".join(chunks)
        finally:
            os.close(descriptor)

    def directory(self, session_id: str) -> Path:
        return self.settings.install_sessions_dir / self._validate_session_id(
            session_id
        )

    def create(
        self,
        *,
        session_id: str,
        inventory_bytes: bytes,
        credential_sha256: str,
        create_nonce_sha256: str,
        status: Mapping[str, object],
    ) -> None:
        normalized = self._validate_session_id(session_id)
        if not isinstance(inventory_bytes, bytes) or not inventory_bytes:
            raise self._invalid("Install inventory bytes are invalid")
        if not _SHA256_RE.fullmatch(credential_sha256):
            raise self._invalid("Install credential hash is invalid")
        if not _SHA256_RE.fullmatch(create_nonce_sha256):
            raise self._invalid("Install create nonce hash is invalid")
        if status.get("session_id") != normalized:
            raise self._invalid("Install session status identity is invalid")
        self._ensure_private_directory(self.settings.install_sessions_dir)
        destination = self.directory(normalized)
        if destination.exists() or destination.is_symlink():
            raise ControlError(
                code="install_session_conflict",
                message="Install session already exists",
                exit_code=4,
            )
        temporary = self.settings.install_sessions_dir / (
            f".{normalized}.{secrets.token_hex(4)}.tmp"
        )
        try:
            self._make_private_directory(temporary)
            self._create_file(temporary / "inventory.json", inventory_bytes)
            self._create_file(
                temporary / "auth.json",
                self._encoded_json(
                    {
                        "schema_version": 1,
                        "credential_sha256": credential_sha256,
                        "create_nonce_sha256": create_nonce_sha256,
                    }
                ),
            )
            self._create_file(
                temporary / "status.json",
                self._encoded_json(status),
            )
            self._fsync_directory(temporary)
            os.replace(temporary, destination)
            self._fsync_directory(self.settings.install_sessions_dir)
        except ControlError:
            raise
        except OSError as exc:
            raise self._failed(
                "Install session cannot be published"
            ) from exc
        finally:
            if temporary.exists() and not temporary.is_symlink():
                for child in temporary.iterdir():
                    child.unlink()
                temporary.rmdir()

    def load_status(self, session_id: str) -> dict[str, Any]:
        directory = self.directory(session_id)
        try:
            metadata = directory.lstat()
        except OSError as exc:
            raise ControlError(
                code="install_session_not_found",
                message="Install session does not exist",
                exit_code=4,
            ) from exc
        if not stat.S_ISDIR(metadata.st_mode):
            raise self._invalid("Install session is not a directory")
        try:
            payload = json.loads(
                self._read_regular_bytes(
                    directory / "status.json"
                ).decode("utf-8")
            )
        except (UnicodeDecodeError, json.JSONDecodeError) as exc:
            raise self._invalid("Install session status is invalid") from exc
        if not isinstance(payload, dict):
            raise self._invalid("Install session status is not an object")
        return payload

    def replace_status(
        self,
        session_id: str,
        status: Mapping[str, object],
        *,
        allow_lifecycle: bool = False,
        allow_execution: bool = False,
    ) -> None:
        directory = self.directory(session_id)
        if status.get("session_id") != session_id:
            raise self._invalid("Install session status identity is invalid")
        try:
            metadata = directory.lstat()
        except OSError as exc:
            raise ControlError(
                code="install_session_not_found",
                message="Install session does not exist",
                exit_code=4,
            ) from exc
        if not stat.S_ISDIR(metadata.st_mode):
            raise self._invalid("Install session is not a directory")
        current = self.load_status(session_id)
        if not allow_lifecycle and any(
            status.get(field) != current.get(field)
            for field in ("state", "stage", "stage_history")
        ):
            raise ControlError(
                code="install_session_lifecycle_update_forbidden",
                message="Install session lifecycle requires stage manager",
                exit_code=4,
            )
        current_execution = current.get("execution")
        next_execution = status.get("execution")
        if current_execution != next_execution:
            if not allow_execution:
                raise ControlError(
                    code="install_execution_update_forbidden",
                    message=(
                        "Install execution lifecycle requires execution service"
                    ),
                    exit_code=4,
                )
            from .install_session_state import (
                validate_execution_transition,
            )

            validate_execution_transition(
                current_execution, next_execution
            )
        destination = directory / "status.json"
        temporary = directory / (
            f".status.json.{secrets.token_hex(4)}.tmp"
        )
        try:
            self._create_file(
                temporary,
                self._encoded_json(status),
                owner=self._service_owner(),
            )
            os.replace(temporary, destination)
        except ControlError:
            raise
        except OSError as exc:
            raise self._failed(
                "Install session status cannot be replaced"
            ) from exc
        try:
            self._fsync_directory(directory)
        except ControlError as exc:
            raise ControlError(
                code="install_session_status_commit_uncertain",
                message="Install session status replacement is durable-uncertain",
                exit_code=6,
            ) from exc
        finally:
            temporary.unlink(missing_ok=True)

    def load_inventory_bytes(self, session_id: str) -> bytes:
        directory = self.directory(session_id)
        if not directory.is_dir() or directory.is_symlink():
            raise ControlError(
                code="install_session_not_found",
                message="Install session does not exist",
                exit_code=4,
            )
        return self._read_regular_bytes(directory / "inventory.json")

    def load_credential_sha256(self, session_id: str) -> str:
        directory = self.directory(session_id)
        try:
            payload = json.loads(
                self._read_regular_bytes(directory / "auth.json").decode("utf-8")
            )
        except (UnicodeDecodeError, json.JSONDecodeError) as exc:
            raise self._invalid("Install session authorization is invalid") from exc
        value = payload.get("credential_sha256") if isinstance(payload, dict) else None
        if not isinstance(value, str) or not _SHA256_RE.fullmatch(value):
            raise self._invalid("Install session authorization is invalid")
        return value

    def load_create_nonce_sha256(self, session_id: str) -> str:
        directory = self.directory(session_id)
        try:
            payload = json.loads(
                self._read_regular_bytes(directory / "auth.json").decode("utf-8")
            )
        except (UnicodeDecodeError, json.JSONDecodeError) as exc:
            raise self._invalid("Install session authorization is invalid") from exc
        value = payload.get("create_nonce_sha256") if isinstance(payload, dict) else None
        if not isinstance(value, str) or not _SHA256_RE.fullmatch(value):
            raise self._invalid("Install session authorization is invalid")
        return value

    def find_status_by_create_nonce_sha256(
        self, create_nonce_sha256: str
    ) -> dict[str, Any] | None:
        if not _SHA256_RE.fullmatch(create_nonce_sha256):
            raise self._invalid("Install create nonce hash is invalid")
        for status in self.list_statuses():
            stored = self.load_create_nonce_sha256(str(status.get("session_id", "")))
            if stored == create_nonce_sha256:
                return status
        return None

    def load_approval(self, session_id: str) -> dict[str, Any]:
        try:
            payload = json.loads(
                self._read_regular_bytes(
                    self.directory(session_id) / "approval.json"
                ).decode("utf-8")
            )
        except (UnicodeDecodeError, json.JSONDecodeError, OSError) as exc:
            raise self._invalid("Install session approval is invalid") from exc
        if not isinstance(payload, dict):
            raise self._invalid("Install session approval is invalid")
        return payload

    def read_revision_file(self, session_id: str, filename: str) -> bytes:
        if filename not in {"plan.json", "plan-signature.json"}:
            raise self._invalid("Install session revision filename is invalid")
        return self._read_regular_bytes(
            self.directory(session_id) / "revision-0001" / filename
        )

    def list_statuses(self) -> list[dict[str, Any]]:
        root = self.settings.install_sessions_dir
        if not root.exists() and not root.is_symlink():
            return []
        metadata = root.lstat()
        if not stat.S_ISDIR(metadata.st_mode):
            raise self._invalid("Install session root is not a directory")
        results: list[dict[str, Any]] = []
        for path in sorted(root.iterdir()):
            if not stat.S_ISDIR(path.lstat().st_mode) or not SESSION_ID_RE.fullmatch(path.name):
                raise self._invalid("Install session root contains an unsafe object")
            results.append(self.load_status(path.name))
        return results

    def publish_revision(
        self,
        session_id: str,
        *,
        plan_bytes: bytes,
        plan_sha256: str,
        signature: Mapping[str, object],
    ) -> None:
        directory = self.directory(session_id)
        revision = directory / "revision-0001"
        if revision.exists() or revision.is_symlink():
            raise ControlError(
                code="install_session_revision_conflict",
                message="Install session revision already exists",
                exit_code=4,
            )
        temporary = directory / f".revision-0001.{secrets.token_hex(4)}.tmp"
        owner = self._service_owner()
        try:
            self._make_private_directory(temporary, owner=owner)
            self._create_file(temporary / "plan.json", plan_bytes, owner=owner)
            self._create_file(
                temporary / "plan.sha256", (plan_sha256 + "\n").encode("ascii"),
                owner=owner,
            )
            self._create_file(
                temporary / "plan-signature.json", self._encoded_json(signature),
                owner=owner,
            )
            self._fsync_directory(temporary)
            os.replace(temporary, revision)
            self._fsync_directory(directory)
        except ControlError:
            raise
        except OSError as exc:
            raise self._failed("Install session revision cannot be published") from exc
        finally:
            if temporary.exists() and not temporary.is_symlink():
                for child in temporary.iterdir():
                    child.unlink()
                temporary.rmdir()

    def write_approval(
        self,
        session_id: str,
        approval: Mapping[str, object],
    ) -> None:
        directory = self.directory(session_id)
        destination = directory / "approval.json"
        if destination.exists() or destination.is_symlink():
            raise ControlError(
                code="install_session_approval_conflict",
                message="Install session approval already exists",
                exit_code=4,
            )
        temporary = directory / f".approval.json.{secrets.token_hex(4)}.tmp"
        try:
            self._create_file(
                temporary,
                self._encoded_json(approval),
                owner=self._service_owner(),
            )
            os.replace(temporary, destination)
            self._fsync_directory(directory)
        except ControlError:
            raise
        except OSError as exc:
            raise self._failed("Install session approval cannot be written") from exc
        finally:
            temporary.unlink(missing_ok=True)

    def discard_partial_publication(self, session_id: str) -> None:
        """Remove only the two artefacts of an incomplete approval attempt."""
        directory = self.directory(session_id)
        approval = directory / "approval.json"
        revision = directory / "revision-0001"
        try:
            if approval.is_symlink() or revision.is_symlink():
                raise self._invalid("Install session publication is unsafe")
            if approval.exists():
                approval.unlink()
            if revision.exists():
                metadata = revision.lstat()
                if not stat.S_ISDIR(metadata.st_mode):
                    raise self._invalid("Install session revision is unsafe")
                for name in ("plan.json", "plan.sha256", "plan-signature.json"):
                    child = revision / name
                    if child.exists() and not child.is_symlink():
                        child.unlink()
                revision.rmdir()
            self._fsync_directory(directory)
        except ControlError:
            raise
        except OSError as exc:
            raise self._failed("Incomplete install approval cannot be removed") from exc

    def has_partial_publication(self, session_id: str) -> bool:
        directory = self.directory(session_id)
        return any(
            (directory / name).exists() or (directory / name).is_symlink()
            for name in ("approval.json", "revision-0001")
        )

    @staticmethod
    def _execution_digest_bytes(
        files: Mapping[str, bytes],
    ) -> bytes:
        return (
            json.dumps(
                {
                    "schema_version": 1,
                    "files": {
                        name: hashlib.sha256(files[name]).hexdigest()
                        for name in EXECUTION_BUNDLE_FILES
                    },
                },
                ensure_ascii=True,
                sort_keys=True,
                separators=(",", ":"),
            ).encode("utf-8")
            + b"\n"
        )

    def publish_execution(
        self,
        session_id: str,
        *,
        files: Mapping[str, bytes],
    ) -> None:
        if set(files) != set(EXECUTION_BUNDLE_FILES) or any(
            not isinstance(files[name], bytes)
            or not 1 <= len(files[name]) <= _MAX_EXECUTION_FILE_BYTES
            for name in EXECUTION_BUNDLE_FILES
        ):
            raise self._invalid("Install execution bundle is invalid")
        directory = self.directory(session_id)
        destination = directory / "execution-0001"
        if destination.exists() or destination.is_symlink():
            raise ControlError(
                code="install_execution_conflict",
                message="Install execution revision already exists",
                exit_code=4,
            )
        temporary = directory / (
            f".execution-0001.{secrets.token_hex(4)}.tmp"
        )
        owner = self._service_owner()
        try:
            self._make_private_directory(temporary, owner=owner)
            for name in EXECUTION_BUNDLE_FILES:
                self._create_file(
                    temporary / name, files[name], owner=owner
                )
            self._create_file(
                temporary / _EXECUTION_DIGEST_FILE,
                self._execution_digest_bytes(files),
                owner=owner,
            )
            self._fsync_directory(temporary)
            os.replace(temporary, destination)
            self._fsync_directory(directory)
        except ControlError:
            raise
        except OSError as exc:
            raise self._failed(
                "Install execution revision cannot be published"
            ) from exc
        finally:
            if temporary.exists() and not temporary.is_symlink():
                for child in temporary.iterdir():
                    child.unlink()
                temporary.rmdir()

    def _read_execution_regular_bytes(self, path: Path) -> bytes:
        try:
            before = path.lstat()
        except OSError as exc:
            raise self._invalid(
                "Install execution revision cannot be inspected"
            ) from exc
        if not stat.S_ISREG(before.st_mode):
            raise self._invalid(
                "Install execution revision contains a non-regular file"
            )
        flags = os.O_RDONLY
        if hasattr(os, "O_BINARY"):
            flags |= os.O_BINARY
        if hasattr(os, "O_NOFOLLOW"):
            flags |= os.O_NOFOLLOW
        try:
            descriptor = os.open(path, flags)
        except OSError as exc:
            raise self._invalid(
                "Install execution revision file cannot be opened safely"
            ) from exc
        try:
            opened = os.fstat(descriptor)
            if (
                not stat.S_ISREG(opened.st_mode)
                or opened.st_dev != before.st_dev
                or opened.st_ino != before.st_ino
            ):
                raise self._invalid(
                    "Install execution revision file changed during safe open"
                )
            if (
                os.name != "nt"
                and stat.S_IMODE(opened.st_mode) != 0o600
            ):
                raise self._invalid(
                    "Install execution revision permissions are invalid"
                )
            if not 1 <= opened.st_size <= _MAX_EXECUTION_FILE_BYTES:
                raise self._invalid(
                    "Install execution revision file size is invalid"
                )
            chunks: list[bytes] = []
            size = 0
            while True:
                chunk = os.read(descriptor, 64 * 1024)
                if not chunk:
                    break
                size += len(chunk)
                if size > _MAX_EXECUTION_FILE_BYTES:
                    raise self._invalid(
                        "Install execution revision file size is invalid"
                    )
                chunks.append(chunk)
            if size != opened.st_size:
                raise self._invalid(
                    "Install execution revision file changed during read"
                )
            return b"".join(chunks)
        finally:
            os.close(descriptor)

    def _read_execution_snapshot_at(
        self, directory: Path
    ) -> dict[str, bytes]:
        try:
            metadata = directory.lstat()
        except OSError as exc:
            raise self._invalid(
                "Install execution revision cannot be inspected"
            ) from exc
        if not stat.S_ISDIR(metadata.st_mode):
            raise self._invalid(
                "Install execution revision is not a directory"
            )
        try:
            children = {child.name: child for child in directory.iterdir()}
        except OSError as exc:
            raise self._invalid(
                "Install execution revision cannot be inspected"
            ) from exc
        if set(children) != _EXECUTION_ALL_FILES:
            raise self._invalid(
                "Install execution revision filenames are invalid"
            )
        snapshot = {
            name: self._read_execution_regular_bytes(children[name])
            for name in _EXECUTION_ALL_FILES
        }
        try:
            digest_raw = snapshot[_EXECUTION_DIGEST_FILE]
            digest_document = json.loads(digest_raw.decode("utf-8"))
        except (UnicodeDecodeError, json.JSONDecodeError) as exc:
            raise self._invalid(
                "Install execution digest metadata is invalid"
            ) from exc
        if (
            not isinstance(digest_document, dict)
            or set(digest_document) != {"schema_version", "files"}
            or type(digest_document.get("schema_version")) is not int
            or digest_document.get("schema_version") != 1
            or not isinstance(digest_document.get("files"), dict)
            or set(digest_document["files"]) != set(EXECUTION_BUNDLE_FILES)
            or digest_raw
            != self._execution_digest_bytes(
                {
                    name: snapshot[name]
                    for name in EXECUTION_BUNDLE_FILES
                }
            )
        ):
            raise self._invalid(
                "Install execution digest metadata is invalid"
            )
        return {
            name: snapshot[name] for name in EXECUTION_BUNDLE_FILES
        }

    def _read_execution_snapshot(
        self, session_id: str
    ) -> dict[str, bytes]:
        return self._read_execution_snapshot_at(
            self.directory(session_id) / "execution-0001"
        )

    def read_execution_file(self, session_id: str, filename: str) -> bytes:
        if filename not in EXECUTION_BUNDLE_FILES:
            raise self._invalid(
                "Install execution revision filename is invalid"
            )
        return self.read_execution_files(session_id)[filename]

    def read_execution_files(
        self, session_id: str
    ) -> dict[str, bytes]:
        return self._read_execution_snapshot(session_id)

    def has_execution_publication(self, session_id: str) -> bool:
        path = self.directory(session_id) / "execution-0001"
        return path.exists() or path.is_symlink()

    def discard_partial_execution(
        self,
        session_id: str,
        *,
        expected_files: Mapping[str, bytes] | None = None,
    ) -> None:
        session_directory = self.directory(session_id)
        directory = session_directory / "execution-0001"
        quarantine = session_directory / (
            f".execution-0001.{secrets.token_hex(4)}.discard"
        )
        try:
            os.replace(directory, quarantine)
            self._fsync_directory(session_directory)
            snapshot = self._read_execution_snapshot_at(quarantine)
            if (
                expected_files is not None
                and (
                    set(expected_files) != set(EXECUTION_BUNDLE_FILES)
                    or any(
                        not isinstance(expected_files[name], bytes)
                        or snapshot[name] != expected_files[name]
                        for name in EXECUTION_BUNDLE_FILES
                    )
                )
            ):
                raise self._invalid(
                    "Install execution revision changed before reconciliation"
                )
            for name in _EXECUTION_ALL_FILES:
                (quarantine / name).unlink()
            quarantine.rmdir()
            self._fsync_directory(session_directory)
        except ControlError:
            if quarantine.exists() or quarantine.is_symlink():
                try:
                    if directory.exists() or directory.is_symlink():
                        raise self._failed(
                            "Install execution reconciliation destination changed"
                        )
                    os.replace(quarantine, directory)
                    self._fsync_directory(session_directory)
                except ControlError:
                    raise
                except OSError as exc:
                    raise self._failed(
                        "Install execution reconciliation cannot be restored"
                    ) from exc
            raise
        except OSError as exc:
            if quarantine.exists() or quarantine.is_symlink():
                try:
                    if not directory.exists() and not directory.is_symlink():
                        os.replace(quarantine, directory)
                        self._fsync_directory(session_directory)
                except (ControlError, OSError):
                    raise self._failed(
                        "Install execution reconciliation cannot be restored"
                    ) from exc
            raise self._failed(
                "Incomplete install execution cannot be removed"
            ) from exc
