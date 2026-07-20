from __future__ import annotations

import json
import os
from collections.abc import Mapping
from pathlib import Path
from typing import Any


def ensure_private_dir(path: Path) -> None:
    path.mkdir(parents=True, exist_ok=True)
    os.chmod(path, 0o700)


def read_json(path: Path) -> dict[str, Any]:
    payload = json.loads(path.read_text(encoding="utf-8"))

    if not isinstance(payload, dict):
        raise ValueError(f"Expected JSON object in {path}")

    return payload


def atomic_write_json(
    path: Path,
    payload: Mapping[str, object],
    mode: int = 0o600,
) -> None:
    ensure_private_dir(path.parent)

    temporary = (
        path.parent
        / f".{path.name}.{os.getpid()}.tmp"
    )

    try:
        temporary.write_text(
            json.dumps(
                dict(payload),
                ensure_ascii=False,
                indent=2,
            )
            + "\n",
            encoding="utf-8",
        )
        os.chmod(temporary, mode)
        os.replace(temporary, path)
    finally:
        temporary.unlink(missing_ok=True)
