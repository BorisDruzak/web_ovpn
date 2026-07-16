from __future__ import annotations

import json
import stat
from pathlib import Path

from alt_deploy.jsonio import (
    atomic_write_json,
    ensure_private_dir,
    read_json,
)


def test_atomic_write_json_replaces_file_and_sets_private_mode(
    tmp_path: Path,
) -> None:
    destination = tmp_path / "state" / "record.json"

    atomic_write_json(destination, {"status": "queued"})
    atomic_write_json(
        destination,
        {"status": "running", "count": 2},
    )

    assert read_json(destination) == {
        "status": "running",
        "count": 2,
    }
    assert stat.S_IMODE(destination.stat().st_mode) == 0o600
    assert list(destination.parent.glob(".*.tmp")) == []


def test_ensure_private_dir_uses_0700(tmp_path: Path) -> None:
    destination = tmp_path / "jobs"

    ensure_private_dir(destination)

    assert stat.S_IMODE(destination.stat().st_mode) == 0o700


def test_read_json_rejects_non_object(tmp_path: Path) -> None:
    path = tmp_path / "bad.json"
    path.write_text(
        json.dumps(["not", "an", "object"]),
        encoding="utf-8",
    )

    try:
        read_json(path)
    except ValueError as exc:
        assert "JSON object" in str(exc)
    else:
        raise AssertionError("read_json accepted a JSON array")
