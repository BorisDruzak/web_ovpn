"""Run one redacted server-observer collection from the gateway."""

import argparse
import json
import subprocess
import sys
from datetime import datetime, timezone
from pathlib import Path
from typing import Sequence

from .server_observer import ALLOWED_ROLES, collect, load_runtime_config, write_snapshot


DEFAULT_CONFIG_PATH = Path("/etc/openvpn-web/server-observer.json")
DEFAULT_SNAPSHOT_PATH = Path("/var/lib/openvpn-web/server-observer/latest.json")


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="Collect redacted server health")
    parser.add_argument("--config", type=Path, default=DEFAULT_CONFIG_PATH)
    parser.add_argument("--snapshot", type=Path, default=DEFAULT_SNAPSHOT_PATH)
    parser.add_argument("--once", action="store_true", help=argparse.SUPPRESS)
    return parser


def _summary(snapshot: dict) -> dict:
    overall = snapshot.get("overall")
    if not isinstance(overall, str):
        raise ValueError("collector returned an invalid summary")

    targets = snapshot.get("targets")
    if not isinstance(targets, list):
        raise ValueError("collector returned an invalid summary")

    result_targets = []
    for target in targets:
        if not isinstance(target, dict):
            raise ValueError("collector returned an invalid summary")
        role = target.get("role")
        status = target.get("status")
        if role not in ALLOWED_ROLES or not isinstance(status, str):
            raise ValueError("collector returned an invalid summary")
        result_targets.append({"role": role, "status": status})
    return {"overall": overall, "targets": result_targets}


def main(argv: Sequence[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    try:
        config = load_runtime_config(args.config)
        snapshot = collect(config, runner=subprocess.run, now=datetime.now(timezone.utc))
        write_snapshot(args.snapshot, snapshot)
        print(json.dumps(_summary(snapshot), sort_keys=True))
        return 0
    except Exception:
        print(json.dumps({"status": "error", "message": "collector failed"}), file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
