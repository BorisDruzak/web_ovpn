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
    "netctl-retention.service": [
        "/usr/local/sbin/netctl",
        "--json",
        "retention",
        "cleanup",
        "--days",
        "30",
        "--apply",
    ],
    "netctl-availability.service": [
        "/usr/local/sbin/netctl",
        "--json",
        "availability",
        "collect",
    ],
}

EXPECTED_PROPERTIES = {
    "netctl-retention.service": {
        "User": "netctl",
        "Group": "netctl",
        "NoNewPrivileges": "yes",
        "PrivateTmp": "yes",
        "ProtectHome": "yes",
    },
    "netctl-retention.timer": {
        "TimersCalendar": "*-*-* 03:17:00",
        "Persistent": "yes",
        "Unit": "netctl-retention.service",
    },
    "netctl-availability.service": {
        "User": "netctl",
        "Group": "netctl",
        "NoNewPrivileges": "yes",
        "PrivateTmp": "yes",
        "ProtectHome": "yes",
    },
    "netctl-availability.timer": {
        "TimersMonotonic": ("OnBootSec=3min", "OnUnitActiveSec=5min"),
        "AccuracyUSec": "30s",
        "Persistent": "yes",
        "Unit": "netctl-availability.service",
    },
}

_ARGV_PATTERN = re.compile(
    r"(?:ExecStart=)?\{\s*path=[^;]*;\s*argv\[\]=(?P<argv>.*?)\s*;\s*ignore_errors=",
    re.DOTALL,
)
_ON_CALENDAR_ENTRY_PATTERN = re.compile(r"OnCalendar=(?P<calendar>[^;}]+?)\s*;")
_MONOTONIC_TIMER_ENTRY_PATTERN = re.compile(r"(?P<timer>On[A-Za-z]+Sec)=(?P<value>[^;}\s]+)")


def parse_exec_starts(serialized: str) -> list[list[str]]:
    """Return every argv serialized in real ``systemctl show`` ExecStart output."""

    matches = list(_ARGV_PATTERN.finditer(serialized))
    if not matches:
        raise ValueError("systemctl show output has no serialized ExecStart argv")
    try:
        return [shlex.split(match.group("argv"), posix=True) for match in matches]
    except ValueError as exc:
        raise ValueError("systemctl show returned an invalid ExecStart argv") from exc


def parse_exec_start(serialized: str) -> list[str]:
    """Return the one required ExecStart argv and reject multi-command units."""

    commands = parse_exec_starts(serialized)
    if len(commands) != 1:
        raise ValueError(f"expected exactly one ExecStart command, got {len(commands)}")
    return commands[0]


def parse_show_properties(serialized: str) -> dict[str, str]:
    """Parse key/value output returned by ``systemctl show``."""

    properties: dict[str, str] = {}
    for line in serialized.splitlines():
        key, separator, value = line.partition("=")
        if not separator or not key:
            raise ValueError("systemctl show output has an invalid property line")
        if key in properties:
            raise ValueError(f"systemctl show output repeated property {key}")
        properties[key] = value
    if not properties:
        raise ValueError("systemctl show output has no properties")
    return properties


def _on_calendar_entries(serialized: str) -> list[str]:
    """Return the calendar values from one loaded systemd timer property."""

    entries = [match.group("calendar").strip() for match in _ON_CALENDAR_ENTRY_PATTERN.finditer(serialized)]
    return entries if entries else [serialized.strip()]


def property_matches(property_name: str, actual_value: str, expected_value: str) -> bool:
    """Match loaded systemd values, requiring one exact retention calendar."""

    if property_name == "TimersCalendar":
        return _on_calendar_entries(actual_value) == [expected_value]
    if property_name == "TimersMonotonic":
        return tuple(
            f"{match.group('timer')}={match.group('value')}"
            for match in _MONOTONIC_TIMER_ENTRY_PATTERN.finditer(actual_value)
        ) == expected_value
    return actual_value == expected_value


def _has_running_systemd() -> bool:
    return sys.platform == "linux" and Path("/run/systemd/system").is_dir()


def _verify_installed_units(unit_directory: Path) -> None:
    if not _has_running_systemd():
        raise RuntimeError("Linux host with a running systemd manager is required")
    if shutil.which("systemd-analyze") is None or shutil.which("systemctl") is None:
        raise RuntimeError("Linux host with systemd-analyze and systemctl is required")

    unit_names = tuple(dict.fromkeys((*EXPECTED_EXEC_STARTS, *EXPECTED_PROPERTIES)))
    unit_paths = [unit_directory / unit for unit in unit_names]
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

    for unit, expected_properties in EXPECTED_PROPERTIES.items():
        result = subprocess.run(
            [
                "systemctl",
                "show",
                *(f"--property={property_name}" for property_name in expected_properties),
                unit,
            ],
            check=True,
            text=True,
            encoding="utf-8",
            errors="replace",
            capture_output=True,
        )
        actual_properties = parse_show_properties(result.stdout)
        for property_name, expected_value in expected_properties.items():
            actual_value = actual_properties.get(property_name)
            if actual_value is None:
                raise RuntimeError(f"{unit} is missing systemd property {property_name}")
            if not property_matches(property_name, actual_value, expected_value):
                raise RuntimeError(
                    f"{unit} {property_name} mismatch: expected {expected_value!r}, got {actual_value!r}"
                )


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
    parser.add_argument(
        "--parse-show-properties",
        action="store_true",
        help="parse key/value systemctl show output from stdin and print JSON",
    )
    args = parser.parse_args(argv)

    if args.parse_exec_start:
        try:
            print(json.dumps(parse_exec_start(sys.stdin.read())))
        except ValueError as exc:
            print(f"error: {exc}", file=sys.stderr)
            return 2
        return 0

    if args.parse_show_properties:
        try:
            print(json.dumps(parse_show_properties(sys.stdin.read()), sort_keys=True))
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
    print("verified netctl collection, reconciliation, retention, and availability units through systemd")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
