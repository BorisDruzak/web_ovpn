from __future__ import annotations

import json
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


class InstallSessionRepository:
    """Private, file-backed persistence for validated install sessions."""

    def __init__(self, settings: Settings) -> None:
        self.settings = settings

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
            if stat.S_IMODE(metadata.st_mode) != 0o700:
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

    def _create_file(self, path: Path, data: bytes) -> None:
        flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL
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
        status: Mapping[str, object],
    ) -> None:
        normalized = self._validate_session_id(session_id)
        if not isinstance(inventory_bytes, bytes) or not inventory_bytes:
            raise self._invalid("Install inventory bytes are invalid")
        if not _SHA256_RE.fullmatch(credential_sha256):
            raise self._invalid("Install credential hash is invalid")
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
            temporary.mkdir(mode=0o700)
            os.chmod(temporary, 0o700)
            self._create_file(temporary / "inventory.json", inventory_bytes)
            self._create_file(
                temporary / "auth.json",
                self._encoded_json(
                    {
                        "schema_version": 1,
                        "credential_sha256": credential_sha256,
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
        destination = directory / "status.json"
        temporary = directory / (
            f".status.json.{secrets.token_hex(4)}.tmp"
        )
        try:
            self._create_file(temporary, self._encoded_json(status))
            os.replace(temporary, destination)
            self._fsync_directory(directory)
        except ControlError:
            raise
        except OSError as exc:
            raise self._failed(
                "Install session status cannot be replaced"
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
        try:
            temporary.mkdir(mode=0o700)
            os.chmod(temporary, 0o700)
            self._create_file(temporary / "plan.json", plan_bytes)
            self._create_file(
                temporary / "plan.sha256", (plan_sha256 + "\n").encode("ascii")
            )
            self._create_file(
                temporary / "plan-signature.json", self._encoded_json(signature)
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
