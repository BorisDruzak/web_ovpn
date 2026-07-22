from __future__ import annotations

import hashlib
import hmac
import os
import secrets as secrets_module
import stat
import subprocess
from collections.abc import Sequence
from dataclasses import dataclass
from pathlib import Path

from .errors import BackupError
from .fs import assert_safe_parents, fsync_directory, read_regular_bytes
from .settings import BackupSettings


_LOGICAL_SECRET_PATHS = {
    "vault": "/home/altserver/ansible/group_vars/vault.yml",
    "vault_password": "/home/altserver/.ansible-vault-pass",
    "ssh_private_key": "/home/altserver/.ssh/id_ed25519",
}


@dataclass(frozen=True)
class SecretIdentity:
    path: str
    kind: str
    uid: int
    gid: int
    owner: str
    group: str
    mode: int
    size: int
    identity: str


def _secret_invalid(message: str) -> BackupError:
    return BackupError(
        code="backup_secret_invalid",
        message=message,
        exit_code=4,
    )


def _secret_mismatch(message: str) -> BackupError:
    return BackupError(
        code="restore_secret_mismatch",
        message=message,
        exit_code=4,
    )


def vault_identity(raw: bytes) -> str:
    if not raw.startswith(b"$ANSIBLE_VAULT;"):
        raise _secret_invalid("Vault file is invalid")
    return "sha256:" + hashlib.sha256(raw).hexdigest()


def password_identity(raw: bytes, key: bytes) -> str:
    return "hmac-sha256:" + hmac.new(
        key,
        raw,
        hashlib.sha256,
    ).hexdigest()


class FingerprintKeyStore:
    def __init__(self, settings: BackupSettings):
        self.settings = settings

    def load(self) -> bytes:
        path = self.settings.fingerprint_key
        try:
            metadata = path.lstat()
        except OSError as exc:
            raise _secret_invalid(
                "Fingerprint key cannot be inspected"
            ) from exc
        if (
            not stat.S_ISREG(metadata.st_mode)
            or metadata.st_uid != self.settings.expected_root_uid
            or metadata.st_gid != self.settings.expected_root_gid
            or stat.S_IMODE(metadata.st_mode) != 0o600
            or metadata.st_size != 32
        ):
            raise _secret_invalid("Fingerprint key metadata is invalid")
        raw = read_regular_bytes(path, max_bytes=32)
        if len(raw) != 32:
            raise _secret_invalid("Fingerprint key length is invalid")
        return raw

    def _validate_parent(self, path: Path) -> None:
        assert_safe_parents(path.parent)
        if not path.parent.exists() and not path.parent.is_symlink():
            if not self.settings.test_mode:
                raise _secret_invalid(
                    "Fingerprint key parent is missing"
                )
            path.parent.mkdir(parents=True, mode=0o700)
        assert_safe_parents(path)
        try:
            metadata = path.parent.lstat()
        except OSError as exc:
            raise _secret_invalid(
                "Fingerprint key parent cannot be inspected"
            ) from exc
        if (
            not stat.S_ISDIR(metadata.st_mode)
            or metadata.st_uid != self.settings.expected_root_uid
            or metadata.st_gid != self.settings.expected_root_gid
            or stat.S_IMODE(metadata.st_mode) != 0o700
        ):
            raise _secret_invalid(
                "Fingerprint key parent metadata is invalid"
            )

    @staticmethod
    def _write_all(descriptor: int, raw: bytes) -> None:
        offset = 0
        while offset < len(raw):
            written = os.write(descriptor, raw[offset:])
            if written < 1:
                raise _secret_invalid(
                    "Fingerprint key write made no progress"
                )
            offset += written

    def _remove_created_key(
        self,
        path: Path,
        created_metadata: os.stat_result,
    ) -> None:
        try:
            current = path.lstat()
        except OSError:
            return
        if (
            not stat.S_ISREG(current.st_mode)
            or current.st_dev != created_metadata.st_dev
            or current.st_ino != created_metadata.st_ino
        ):
            return
        try:
            path.unlink()
        except OSError:
            return
        try:
            fsync_directory(path.parent)
        except BackupError:
            return

    def ensure(self) -> bytes:
        path = self.settings.fingerprint_key
        if path.exists() or path.is_symlink():
            return self.load()

        self._validate_parent(path)
        raw = secrets_module.token_bytes(32)
        flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL
        if hasattr(os, "O_NOFOLLOW"):
            flags |= os.O_NOFOLLOW
        try:
            descriptor = os.open(path, flags, 0o600)
        except FileExistsError:
            return self.load()
        except OSError as exc:
            raise _secret_invalid(
                "Fingerprint key cannot be created safely"
            ) from exc

        created_metadata = os.fstat(descriptor)
        file_synced = False
        try:
            os.fchown(
                descriptor,
                self.settings.expected_root_uid,
                self.settings.expected_root_gid,
            )
            os.fchmod(descriptor, 0o600)
            self._write_all(descriptor, raw)
            os.fsync(descriptor)
            file_synced = True
        except BackupError:
            raise
        except OSError as exc:
            raise _secret_invalid("Fingerprint key write failed") from exc
        finally:
            os.close(descriptor)
            if not file_synced:
                self._remove_created_key(path, created_metadata)

        try:
            fsync_directory(path.parent)
        except BackupError:
            self._remove_created_key(path, created_metadata)
            raise
        return self.load()


class SecretIdentityProvider:
    def __init__(
        self,
        settings: BackupSettings,
        *,
        key_store: FingerprintKeyStore | None = None,
    ) -> None:
        self.settings = settings
        self.key_store = key_store or FingerprintKeyStore(settings)

    def _read_service_secret(
        self,
        path: Path,
        *,
        kind: str,
        max_bytes: int,
    ) -> tuple[bytes, os.stat_result]:
        try:
            before = path.lstat()
        except OSError as exc:
            raise _secret_invalid(
                f"Secret file cannot be inspected: {kind}"
            ) from exc
        if (
            not stat.S_ISREG(before.st_mode)
            or before.st_uid != self.settings.expected_service_uid
            or before.st_gid != self.settings.expected_service_gid
            or stat.S_IMODE(before.st_mode) != 0o600
        ):
            raise _secret_invalid(
                f"Secret file metadata is invalid: {kind}"
            )
        raw = read_regular_bytes(path, max_bytes=max_bytes)
        try:
            after = path.lstat()
        except OSError as exc:
            raise _secret_invalid(
                f"Secret file changed during capture: {kind}"
            ) from exc
        if (
            after.st_dev != before.st_dev
            or after.st_ino != before.st_ino
            or after.st_size != before.st_size
            or after.st_mtime_ns != before.st_mtime_ns
            or after.st_ctime_ns != before.st_ctime_ns
        ):
            raise _secret_invalid(
                f"Secret file changed during capture: {kind}"
            )
        return raw, after

    def _identity_record(
        self,
        *,
        kind: str,
        metadata: os.stat_result,
        identity: str,
    ) -> SecretIdentity:
        return SecretIdentity(
            path=_LOGICAL_SECRET_PATHS[kind],
            kind=kind,
            uid=metadata.st_uid,
            gid=metadata.st_gid,
            owner=self.settings.service_user,
            group=self.settings.service_group,
            mode=stat.S_IMODE(metadata.st_mode),
            size=metadata.st_size,
            identity=identity,
        )

    def _ssh_fingerprint(self) -> str:
        command = str(self.settings.ssh_keygen_path)
        try:
            public_result = subprocess.run(
                [
                    command,
                    "-y",
                    "-f",
                    str(self.settings.ssh_private_key),
                ],
                check=False,
                capture_output=True,
            )
        except OSError as exc:
            raise _secret_invalid(
                "SSH public identity command failed"
            ) from exc
        if public_result.returncode != 0 or not public_result.stdout.strip():
            raise _secret_invalid("SSH private key format is invalid")

        try:
            fingerprint_result = subprocess.run(
                [command, "-lf", "-", "-E", "sha256"],
                input=public_result.stdout,
                check=False,
                capture_output=True,
            )
        except OSError as exc:
            raise _secret_invalid(
                "SSH fingerprint command failed"
            ) from exc
        if fingerprint_result.returncode != 0:
            raise _secret_invalid("SSH fingerprint is unavailable")
        try:
            tokens = fingerprint_result.stdout.decode("utf-8").split()
        except UnicodeDecodeError as exc:
            raise _secret_invalid("SSH fingerprint output is invalid") from exc
        fingerprint = next(
            (
                token
                for token in tokens
                if token.startswith("SHA256:")
            ),
            None,
        )
        if fingerprint is None or len(fingerprint) > 500:
            raise _secret_invalid("SSH fingerprint output is invalid")
        return "ssh-public-fingerprint:" + fingerprint

    def _capture(
        self,
        *,
        create_key: bool,
    ) -> tuple[SecretIdentity, ...]:
        key = self.key_store.ensure() if create_key else self.key_store.load()
        vault_raw, vault_metadata = self._read_service_secret(
            self.settings.vault_file,
            kind="vault",
            max_bytes=16 * 1024 * 1024,
        )
        password_raw, password_metadata = self._read_service_secret(
            self.settings.vault_password_file,
            kind="vault_password",
            max_bytes=64 * 1024,
        )
        _, ssh_metadata = self._read_service_secret(
            self.settings.ssh_private_key,
            kind="ssh_private_key",
            max_bytes=1024 * 1024,
        )
        return (
            self._identity_record(
                kind="vault",
                metadata=vault_metadata,
                identity=vault_identity(vault_raw),
            ),
            self._identity_record(
                kind="vault_password",
                metadata=password_metadata,
                identity=password_identity(password_raw, key),
            ),
            self._identity_record(
                kind="ssh_private_key",
                metadata=ssh_metadata,
                identity=self._ssh_fingerprint(),
            ),
        )

    def capture(self) -> tuple[SecretIdentity, ...]:
        return self._capture(create_key=True)

    def assert_matches(
        self,
        expected: Sequence[SecretIdentity],
    ) -> None:
        try:
            current = self._capture(create_key=False)
        except BackupError as exc:
            raise _secret_mismatch(
                "Current secret identity cannot be verified"
            ) from exc

        expected_by_kind = {item.kind: item for item in expected}
        current_by_kind = {item.kind: item for item in current}
        if (
            len(expected_by_kind) != len(expected)
            or len(current_by_kind) != len(current)
            or set(expected_by_kind) != set(current_by_kind)
        ):
            raise _secret_mismatch("Secret identity set does not match")
        for kind in sorted(expected_by_kind):
            left = expected_by_kind[kind]
            right = current_by_kind[kind]
            if (
                left.path != right.path
                or left.kind != right.kind
                or left.uid != right.uid
                or left.gid != right.gid
                or left.owner != right.owner
                or left.group != right.group
                or left.mode != right.mode
                or left.size != right.size
                or not hmac.compare_digest(left.identity, right.identity)
            ):
                raise _secret_mismatch(
                    f"Secret identity does not match: {kind}"
                )
