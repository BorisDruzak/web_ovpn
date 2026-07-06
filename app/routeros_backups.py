from __future__ import annotations

from datetime import datetime, timezone
from pathlib import Path
from typing import Any

ALLOWED_SUFFIXES = {".backup", ".rsc"}


def _device_from_name(name: str) -> str:
    if name.startswith("sosn-"):
        return "sosn"
    if name.startswith("m-arhiv-"):
        return "m-arhiv"
    return name.split("-", 1)[0] if "-" in name else ""


def list_routeros_backups(root: Path, limit: int = 200) -> tuple[list[dict[str, Any]], str | None]:
    base = root.expanduser()
    if not base.exists():
        return [], f"Backup directory does not exist: {base}"
    if not base.is_dir():
        return [], f"Backup path is not a directory: {base}"

    rows: list[dict[str, Any]] = []
    for path in base.rglob("*"):
        if not path.is_file() or path.suffix not in ALLOWED_SUFFIXES:
            continue
        try:
            stat = path.stat()
            rel = path.relative_to(base).as_posix()
        except OSError:
            continue
        rows.append(
            {
                "name": path.name,
                "relative_path": rel,
                "device": _device_from_name(path.name),
                "type": path.suffix.removeprefix("."),
                "size": stat.st_size,
                "modified_at": datetime.fromtimestamp(stat.st_mtime, tz=timezone.utc).isoformat(),
            }
        )
    rows.sort(key=lambda item: str(item["modified_at"]), reverse=True)
    return rows[:limit], None
