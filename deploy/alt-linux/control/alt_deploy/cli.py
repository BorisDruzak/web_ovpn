from __future__ import annotations

import argparse
import json
import sys
from collections.abc import Sequence
from typing import TextIO

from .config import Settings
from .errors import ControlError
from .registry import MachineRepository


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="workstationctl"
    )

    parser.add_argument(
        "--json",
        action="store_true",
        dest="as_json",
    )

    commands = parser.add_subparsers(
        dest="command",
        required=True,
    )

    machines = commands.add_parser("machines")

    machine_commands = machines.add_subparsers(
        dest="machine_command",
        required=True,
    )

    machine_commands.add_parser("list")

    show = machine_commands.add_parser("show")
    show.add_argument("machine_uuid")

    return parser


def _write_json(
    stream: TextIO,
    payload: dict[str, object],
) -> None:
    stream.write(
        json.dumps(
            payload,
            ensure_ascii=False,
            indent=2,
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

    active_settings = (
        settings or Settings.from_env()
    )
    repository = MachineRepository(
        active_settings
    )

    try:
        if (
            parsed.command == "machines"
            and parsed.machine_command == "list"
        ):
            payload: dict[str, object] = {
                "status": "ok",
                "machines": [
                    machine.to_public_dict()
                    for machine in repository.list()
                ],
            }

        elif (
            parsed.command == "machines"
            and parsed.machine_command == "show"
        ):
            payload = {
                "status": "ok",
                "machine": repository.get(
                    parsed.machine_uuid
                ).to_public_dict(),
            }

        else:
            raise ControlError(
                code="unsupported_command",
                message="Unsupported command",
                exit_code=2,
            )

    except ControlError as exc:
        if parsed.as_json:
            _write_json(stdout, exc.to_dict())
        else:
            stderr.write(
                f"ERROR [{exc.code}]: "
                f"{exc.message}\n"
            )

        return exc.exit_code

    _write_json(stdout, payload)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
