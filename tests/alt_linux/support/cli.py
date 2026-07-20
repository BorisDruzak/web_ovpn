from __future__ import annotations

import io
import json
from collections.abc import Sequence
from dataclasses import dataclass

from alt_deploy.cli import main
from alt_deploy.config import Settings


@dataclass(frozen=True)
class CliResult:
    exit_code: int
    stdout: str
    stderr: str
    payload: dict[str, object]


def run_json_cli(
    args: Sequence[str],
    *,
    settings: Settings,
) -> CliResult:
    stdout = io.StringIO()
    stderr = io.StringIO()
    exit_code = main(
        ["--json", *args],
        settings=settings,
        stdout=stdout,
        stderr=stderr,
    )
    stdout_text = stdout.getvalue()
    stderr_text = stderr.getvalue()

    try:
        raw_payload = json.loads(stdout_text)
    except json.JSONDecodeError as exc:
        raise AssertionError(
            "workstationctl did not emit one valid JSON document; "
            f"stdout={stdout_text!r}; stderr={stderr_text!r}"
        ) from exc

    if not isinstance(raw_payload, dict):
        raise AssertionError(
            "workstationctl JSON payload must be an object; "
            f"payload={raw_payload!r}"
        )

    return CliResult(
        exit_code=exit_code,
        stdout=stdout_text,
        stderr=stderr_text,
        payload=raw_payload,
    )
