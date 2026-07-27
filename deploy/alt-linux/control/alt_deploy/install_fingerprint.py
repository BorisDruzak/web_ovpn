from __future__ import annotations

from hashlib import sha256
import json

from .install_inventory import DiskInventory


def disk_fingerprint(disk: DiskInventory) -> str:
    """Return a canonical, bounded identity hash for a validated disk."""
    if not isinstance(disk, DiskInventory):
        raise TypeError("validated DiskInventory is required")
    identity = {
        "model": disk.model,
        "path": disk.path,
        "serial": disk.serial,
        "size_bytes": disk.size_bytes,
        "wwn": disk.wwn,
    }
    canonical = json.dumps(
        identity, ensure_ascii=True, sort_keys=True, separators=(",", ":")
    ).encode("utf-8")
    return "sha256:" + sha256(canonical).hexdigest()
