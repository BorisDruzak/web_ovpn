from __future__ import annotations

import os
import stat
from pathlib import Path


def read_ed25519_private_key(
    credential_name: str,
    *,
    role: str,
    credentials_directory: Path | None = None,
) -> bytes:
    """Read one systemd-delivered private key without accepting an arbitrary path."""
    directory = credentials_directory
    if directory is None:
        raw_directory = os.environ.get("CREDENTIALS_DIRECTORY", "")
        directory = Path(raw_directory) if raw_directory else None
    if directory is None or not credential_name or "/" in credential_name or "\\" in credential_name:
        raise ValueError(f"invalid {role} credential")
    path = directory / credential_name
    try:
        metadata = path.lstat()
        if not stat.S_ISREG(metadata.st_mode) or stat.S_ISLNK(metadata.st_mode):
            raise ValueError
        # systemd 255 delivers LoadCredential files as root:root 0440 while
        # granting the service process access through the credential mount.
        # Group read is therefore accepted, but no write/execute or world bit.
        if stat.S_IMODE(metadata.st_mode) & 0o037:
            raise ValueError
        value = path.read_bytes()
    except (OSError, ValueError) as exc:
        raise ValueError(f"invalid {role} credential") from exc
    if len(value) != 32:
        raise ValueError(f"invalid {role} credential")
    return value
