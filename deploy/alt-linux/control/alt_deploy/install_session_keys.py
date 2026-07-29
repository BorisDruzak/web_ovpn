from __future__ import annotations

import json
import os
import stat
from collections.abc import Callable
from pathlib import Path

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from .config import Settings
from .install_session_signing import (
    load_private_signer,
    load_public_verifier,
    public_key_metadata,
)


_EUID: Callable[[], int] = getattr(os, "geteuid", lambda: 0)


def _lstat(path: Path, *, description: str) -> os.stat_result | None:
    try:
        metadata = path.lstat()
    except FileNotFoundError:
        return None
    except OSError as exc:
        raise ValueError(f"Install signing {description} cannot be inspected") from exc
    if stat.S_ISLNK(metadata.st_mode):
        raise ValueError(f"Install signing {description} must not be a symlink")
    return metadata


def _fsync_directory(path: Path) -> None:
    if os.name == "nt":
        return
    flags = os.O_RDONLY
    if hasattr(os, "O_DIRECTORY"):
        flags |= os.O_DIRECTORY
    if hasattr(os, "O_NOFOLLOW"):
        flags |= os.O_NOFOLLOW
    try:
        descriptor = os.open(path, flags)
    except OSError as exc:
        raise ValueError("Install signing key directory cannot be opened safely") from exc
    try:
        os.fsync(descriptor)
    except OSError as exc:
        raise ValueError("Install signing key directory cannot be synchronized") from exc
    finally:
        os.close(descriptor)


def _require_root_owner(metadata: os.stat_result, *, description: str) -> None:
    if os.name != "nt" and (metadata.st_uid != 0 or metadata.st_gid != 0):
        raise ValueError(f"Install signing {description} ownership is invalid")


def _validate_root_parent_chain(path: Path) -> None:
    current = path
    while True:
        metadata = _lstat(current, description="key parent")
        if metadata is None or not stat.S_ISDIR(metadata.st_mode):
            raise ValueError("Install signing key parent is not a directory")
        _require_root_owner(metadata, description="key parent")
        parent = current.parent
        if parent == current:
            return
        current = parent


def _validate_root_directory(path: Path, *, mode: int, description: str) -> None:
    _validate_root_parent_chain(path)
    metadata = _lstat(path, description=description)
    if metadata is None or not stat.S_ISDIR(metadata.st_mode):
        raise ValueError("Install signing key directory is not a directory")
    if os.name != "nt" and stat.S_IMODE(metadata.st_mode) != mode:
        raise ValueError("Install signing key directory permissions are invalid")


def _ensure_root_directory(path: Path, *, mode: int, description: str) -> None:
    metadata = _lstat(path, description=description)
    if metadata is None:
        _validate_root_parent_chain(path.parent)
        try:
            path.mkdir(mode=mode)
        except FileExistsError:
            metadata = _lstat(path, description=description)
            if metadata is None:
                raise ValueError("Install signing key directory disappeared")
        except OSError as exc:
            raise ValueError("Install signing key directory cannot be created") from exc
        else:
            try:
                if os.name != "nt":
                    os.chown(path, 0, 0)
                os.chmod(path, mode)
            except OSError as exc:
                raise ValueError("Install signing key directory permissions cannot be set") from exc
            _fsync_directory(path.parent)
    _validate_root_directory(path, mode=mode, description=description)


def _write_all(descriptor: int, content: bytes) -> None:
    offset = 0
    while offset < len(content):
        try:
            written = os.write(descriptor, content[offset:])
        except OSError as exc:
            raise ValueError("Install signing key cannot be written") from exc
        if written <= 0:
            raise ValueError("Install signing key cannot be written")
        offset += written


def _create_regular_exclusive(path: Path, content: bytes, *, mode: int) -> None:
    flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL
    if hasattr(os, "O_BINARY"):
        flags |= os.O_BINARY
    if hasattr(os, "O_NOFOLLOW"):
        flags |= os.O_NOFOLLOW
    try:
        descriptor = os.open(path, flags, mode)
    except FileExistsError as exc:
        raise ValueError("Install signing key material already exists") from exc
    except OSError as exc:
        raise ValueError("Install signing key cannot be created") from exc
    try:
        try:
            if os.name != "nt":
                os.fchown(descriptor, 0, 0)
            os.fchmod(descriptor, mode)
        except AttributeError:
            os.chmod(path, mode)
        metadata = os.fstat(descriptor)
        if not stat.S_ISREG(metadata.st_mode):
            raise ValueError("Install signing key is not a regular file")
        if os.name != "nt" and stat.S_IMODE(metadata.st_mode) != mode:
            raise ValueError("Install signing key permissions are invalid")
        _require_root_owner(metadata, description="key")
        _write_all(descriptor, content)
        os.fsync(descriptor)
    except OSError as exc:
        raise ValueError("Install signing key cannot be synchronized") from exc
    finally:
        os.close(descriptor)
    _fsync_directory(path.parent)


def _pkcs8_pem(private_key: Ed25519PrivateKey) -> bytes:
    return private_key.private_bytes(
        serialization.Encoding.PEM,
        serialization.PrivateFormat.PKCS8,
        serialization.NoEncryption(),
    )


def _canonical_json(metadata: dict[str, object]) -> bytes:
    return (
        json.dumps(metadata, sort_keys=True, separators=(",", ":")).encode("utf-8")
        + b"\n"
    )


def ensure_install_session_keypair(
    settings: Settings,
    *,
    euid: Callable[[], int] = _EUID,
) -> dict[str, object]:
    """Create the root-owned pair once, or validate the existing immutable pair."""
    if os.name != "nt" and euid() != 0:
        raise ValueError("Install signing key initialization requires root")

    private_path = settings.install_signing_private_key
    public_path = settings.install_signing_public_key
    private_metadata = _lstat(private_path, description="private key")
    public_metadata = _lstat(public_path, description="public key")
    if (private_metadata is None) != (public_metadata is None):
        raise ValueError("Install signing key pair is incomplete")
    if private_metadata is None:
        _ensure_root_directory(
            private_path.parent, mode=0o700, description="private key directory"
        )
        private = Ed25519PrivateKey.generate()
        _create_regular_exclusive(private_path, _pkcs8_pem(private), mode=0o600)
        _ensure_root_directory(
            public_path.parent, mode=0o755, description="public key directory"
        )
        _create_regular_exclusive(
            public_path,
            _canonical_json(public_key_metadata(private.public_key())),
            mode=0o644,
        )

    _validate_root_directory(
        private_path.parent, mode=0o700, description="private key directory"
    )
    _validate_root_directory(
        public_path.parent, mode=0o755, description="public key directory"
    )

    private = load_private_signer(private_path)
    public = load_public_verifier(public_path)
    metadata = public_key_metadata(public)
    if public_key_metadata(private.public_key())["key_id"] != metadata["key_id"]:
        raise ValueError("Install signing key pair is not matching")
    return metadata
