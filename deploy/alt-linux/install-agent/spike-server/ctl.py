from __future__ import annotations

import argparse
from pathlib import Path

from repository import SpikeRepository


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--state", required=True, type=Path)
    parser.add_argument("command", choices=("approve", "cancel", "show", "list"))
    parser.add_argument("session", nargs="?")
    args = parser.parse_args()
    repository = SpikeRepository(args.state)
    if args.command == "list":
        for path in sorted(args.state.glob("spike-*/session.json")):
            print(path.parent.name)
        return 0
    if not args.session:
        parser.error("session is required")
    if args.command == "approve":
        print(repository.approve(args.session))
    elif args.command == "cancel":
        print(repository.cancel(args.session))
    else:
        print(repository.decision(args.session))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
