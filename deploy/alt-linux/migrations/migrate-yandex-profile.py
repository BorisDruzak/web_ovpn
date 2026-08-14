#!/usr/bin/env python3
"""Run collection and restore as one operator command without exposing its ID."""
from __future__ import annotations

import argparse
import re
import subprocess
import sys

MIGRATION_RE = re.compile(r"^Migration is ready: (migration-[0-9a-f-]{36})$", re.MULTILINE)


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--source-host", required=True)
    parser.add_argument("--source-user", required=True)
    parser.add_argument("--transport-user")
    parser.add_argument("--target", required=True)
    parser.add_argument("--target-user", required=True)
    args = parser.parse_args()

    collect = ["collect-yandex-profile", "--host", args.source_host, "--user", args.source_user]
    if args.transport_user:
        collect.extend(["--transport-user", args.transport_user])
    collection = subprocess.run(collect, text=True, stdout=subprocess.PIPE, check=False)
    print(collection.stdout, end="")
    if collection.returncode:
        return collection.returncode
    match = MIGRATION_RE.search(collection.stdout)
    if not match:
        print("Collector did not return a valid migration ID.", file=sys.stderr)
        return 1
    return subprocess.run([
        "restore-yandex-profile", "--migration-id", match.group(1),
        "--target", args.target, "--target-user", args.target_user, "--yes",
    ], check=False).returncode


if __name__ == "__main__":
    raise SystemExit(main())
