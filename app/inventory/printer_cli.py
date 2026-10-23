"""Explicit standalone printer planning; no mutation of inventory or target PCs."""

from __future__ import annotations

import argparse
import json
from pathlib import Path
import sys

from .printer_plan import build_plan, canonical, export_plan, PrinterPlanError


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    sub = parser.add_subparsers(dest="operation", required=True)
    plan = sub.add_parser("plan")
    plan.add_argument("--pc-asset-id", required=True)
    plan.add_argument("--target-uuid", required=True)
    plan.add_argument("--output", required=True, type=Path)
    export = sub.add_parser("export")
    export.add_argument("--plan", required=True, type=Path)
    export.add_argument("--driver-source", required=True, type=Path)
    export.add_argument("--destination", required=True, type=Path)
    args = parser.parse_args(argv)
    try:
        from app.db import get_sessionmaker
        from app.netctl_client import run_netctl
        from .printer_inventory import read_inventory

        with get_sessionmaker()() as db:
            snapshot = read_inventory(db)
        if args.operation == "plan":
            value = build_plan(snapshot, args.pc_asset_id, args.target_uuid, run_netctl)
            with args.output.open("xb") as stream:
                args.output.chmod(0o600)
                stream.write(canonical(value) + b"\n")
            result = {
                "status": "ok",
                "ready": value["ready"],
                "queues": len(value["printers"]),
                "excluded": value["excluded"],
                "sha256": value["sha256"],
            }
        else:
            if args.plan.stat().st_size > 1048576:
                raise PrinterPlanError("printer_plan_limit")
            value = json.loads(args.plan.read_text(encoding="utf-8"))
            result = export_plan(
                value, snapshot, run_netctl, args.driver_source, args.destination
            )
        print(json.dumps(result, ensure_ascii=True))
        return 0 if result.get("ready", True) else 2
    except (PrinterPlanError, ValueError, OSError, KeyError) as exc:
        code = (
            str(exc) if isinstance(exc, PrinterPlanError) else "printer_planning_failed"
        )
        print(json.dumps({"status": "blocked", "code": code}), file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
