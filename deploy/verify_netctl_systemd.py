#!/usr/bin/env python3
"""Verify installed netctl units on a Linux host with a running systemd manager.

Run this after the installer has copied the units and before treating the
timers as operational. It validates the staged unit files with
``systemd-analyze verify`` and then checks the argv that systemd actually
loaded through ``systemctl show --property=ExecStart --value``.

The verification mode exits 77 on Windows or any host without a running
systemd manager. ``--parse-exec-start`` is platform-independent so captured
systemctl output can be regression-tested outside Linux.
"""

from __future__ import annotations

import argparse
import json
from pathlib import Path
import re
import shlex
import shutil
import subprocess
import sys


EXPECTED_EXEC_STARTS = {
    "netctl-collect.service": [
        "/usr/local/sbin/netctl",
        "--json",
        "collect",
        "all",
        "--reconcile",
    ],
    "netctl-reconcile.service": ["/usr/local/sbin/netctl", "--json", "reconcile"],
}

_ARGV_PATTERN = re.compile(
    r"(?:^|\n)(?:ExecStart=)?\{\s*path=[^;]*;\s*argv\[\]=(?P<argv>.*?)\s*;\s*ignore_errors=",
    re.DOTALL,
)


def parse_exec_start(serialized: str) -> list[str]:
    """Return argv from real ``systemctl show`` ExecStart serialization."""

    match = _ARGV_PATTERN.search(serialized)
    if match is None:
        raise ValueError("systemctl show output has no serialized ExecStart argv")
    try:
        return shlex.split(match.group("argv"), posix=True)
    except ValueError as exc:
        raise ValueError("systemctl show returned an invalid ExecStart argv") from exc


def _has_running_systemd() -> bool:
    return sys.platform == "linux" and Path("/run/systemd/system").is_dir()


def _verify_installed_units(unit_directory: Path) -> None:
    if not _has_running_systemd():
        raise RuntimeError("Linux host with a running systemd manager is required")
    if shutil.which("systemd-analyze") is None or shutil.which("systemctl") is None:
        raise RuntimeError("Linux host with systemd-analyze and systemctl is required")

    unit_paths = [unit_directory / unit for unit in EXPECTED_EXEC_STARTS]
    missing = [str(path) for path in unit_paths if not path.is_file()]
    if missing:
        raise RuntimeError(f"installed netctl unit files are missing: {', '.join(missing)}")

    subprocess.run(["systemd-analyze", "verify", *(str(path) for path in unit_paths)], check=True)

    for unit, expected in EXPECTED_EXEC_STARTS.items():
        result = subprocess.run(
            ["systemctl", "show", "--property=ExecStart", "--value", unit],
            check=True,
            text=True,
            encoding="utf-8",
            errors="replace",
            capture_output=True,
        )
        actual = parse_exec_start(result.stdout)
        if actual != expected:
            raise RuntimeError(f"{unit} ExecStart mismatch: expected {expected!r}, got {actual!r}")


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--unit-directory",
        type=Path,
        default=Path("/etc/systemd/system"),
        help="directory containing installed netctl unit files (default: /etc/systemd/system)",
    )
    parser.add_argument(
        "--parse-exec-start",
        action="store_true",
        help="parse serialized ExecStart from stdin and print argv JSON",
    )
    args = parser.parse_args(argv)

    if args.parse_exec_start:
        try:
            print(json.dumps(parse_exec_start(sys.stdin.read())))
        except ValueError as exc:
            print(f"error: {exc}", file=sys.stderr)
            return 2
        return 0

    if not _has_running_systemd():
        print("skipped: Linux host with a running systemd manager is required", file=sys.stderr)
        return 77

    try:
        _verify_installed_units(args.unit_directory)
    except (OSError, RuntimeError, subprocess.CalledProcessError) as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 1
    print("verified netctl collection and recovery ExecStart argv through systemd")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
