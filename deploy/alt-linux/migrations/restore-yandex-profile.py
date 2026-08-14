#!/usr/bin/env python3
"""Select a completed migration and invoke only the fixed restore playbook."""
from __future__ import annotations

import argparse
import json
import re
import subprocess
import sys
from pathlib import Path

DEFAULT_ROOT = Path("/var/lib/alt-deploy/migrations/yandex")
DEFAULT_ANSIBLE = Path("/home/altserver/ansible")
MIGRATION_RE = re.compile(r"^migration-[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$")
HOST_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9.-]{0,252}$")
USER_RE = re.compile(r"^[A-Za-z0-9._@-]{1,128}$")


def ready_migrations(root: Path) -> list[tuple[str, dict[str, object]]]:
    records: list[tuple[str, dict[str, object]]] = []
    if not root.is_dir():
        return records
    for candidate in sorted(root.iterdir()):
        if not candidate.is_dir() or not MIGRATION_RE.fullmatch(candidate.name):
            continue
        ready = candidate / "READY"
        manifest_file = candidate / "manifest.json"
        archive = candidate / "profile.tar.zst"
        checksums = candidate / "SHA256SUMS"
        if not all(item.is_file() and not item.is_symlink() for item in (ready, manifest_file, archive, checksums)):
            continue
        try:
            manifest = json.loads(manifest_file.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError):
            continue
        if manifest.get("schema_version") == 1 and manifest.get("migration_id") == candidate.name:
            records.append((candidate.name, manifest))
    return records


def choose(records: list[tuple[str, dict[str, object]]]) -> str:
    if not records:
        raise SystemExit("No READY Yandex Browser migrations are available.")
    for number, (migration_id, manifest) in enumerate(records, start=1):
        source = manifest.get("source", {})
        print(f"{number}. {migration_id}  source={source.get('user', '?')}@{source.get('host', '?')}")
    raw = input("Migration number: ").strip()
    try:
        return records[int(raw) - 1][0]
    except (ValueError, IndexError) as exc:
        raise SystemExit("Invalid migration selection.") from exc


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--migration-id")
    parser.add_argument("--target")
    parser.add_argument("--target-user")
    parser.add_argument("--migration-root", type=Path, default=DEFAULT_ROOT)
    parser.add_argument("--ansible-root", type=Path, default=DEFAULT_ANSIBLE)
    parser.add_argument("--yes", action="store_true", help="skip local confirmation")
    args = parser.parse_args()

    migration_id = args.migration_id or choose(ready_migrations(args.migration_root))
    target = args.target or input("Target host or IP: ").strip()
    target_user = args.target_user or input("Target domain user: ").strip()
    if not MIGRATION_RE.fullmatch(migration_id):
        raise SystemExit("Invalid migration_id.")
    if not HOST_RE.fullmatch(target) or not USER_RE.fullmatch(target_user):
        raise SystemExit("Invalid target or target_user.")
    migration_dir = args.migration_root / migration_id
    if not (migration_dir / "READY").is_file():
        raise SystemExit("Selected migration is not READY.")
    if not args.yes and input(f"Restore {migration_id} to {target} for {target_user}? [yes/NO] ").strip() != "yes":
        print("Cancelled.")
        return 0

    playbook = args.ansible_root / "playbooks" / "yandex-profile-restore.yml"
    if not playbook.is_file():
        raise SystemExit(f"Fixed playbook is unavailable: {playbook}")
    command = [
        "ansible-playbook", "-i", f"{target},", str(playbook),
        "-e", f"yandex_migration_root={args.migration_root}",
        "-e", f"migration_id={migration_id}",
        "-e", f"target_user={target_user}",
    ]
    return subprocess.run(command, cwd=args.ansible_root, check=False).returncode


if __name__ == "__main__":
    sys.exit(main())
