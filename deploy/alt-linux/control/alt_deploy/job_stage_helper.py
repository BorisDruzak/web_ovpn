from __future__ import annotations

import argparse
import json
import sys
from collections.abc import Sequence
from typing import TextIO

from .config import Settings
from .errors import ControlError
from .job_stages import JobStageManager


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="alt-job-stage"
    )
    parser.add_argument("--job-id", required=True)
    parser.add_argument(
        "--stage",
        required=True,
    )
    return parser


def _write_json(
    stream: TextIO,
    payload: dict[str, object],
) -> None:
    stream.write(
        json.dumps(
            payload,
            ensure_ascii=False,
            separators=(",", ":"),
        )
        + "\n"
    )


def main(
    argv: Sequence[str] | None = None,
    *,
    settings: Settings | None = None,
    stdout: TextIO = sys.stdout,
    stderr: TextIO = sys.stderr,
) -> int:
    parsed = build_parser().parse_args(
        list(argv) if argv is not None else None
    )
    active_settings = settings or Settings.from_env()
    manager = JobStageManager(active_settings)

    try:
        before = manager.jobs.get(parsed.job_id)
        after = manager.advance(
            parsed.job_id,
            parsed.stage,
        )
    except ControlError as exc:
        _write_json(stdout, exc.to_dict())
        return exc.exit_code

    _write_json(
        stdout,
        {
            "status": "ok",
            "job_id": after.job_id,
            "stage": after.stage,
            "changed": before.status != after.status,
        },
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
