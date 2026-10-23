"""Load exact local printer artifacts without shell expansion or target staging."""

from __future__ import annotations

import base64
import json
from pathlib import Path


def printer_payload(request, driver_dir, role_path):
    files = Path(role_path) / "files"
    catalog = json.loads((files / "driver_catalog.json").read_text(encoding="utf-8"))
    source = (files / "inventory_cups.py").read_text(encoding="utf-8")
    drivers = {}
    for row in request["printers"]:
        driver = catalog.get(row["model"])
        if (
            driver != row["driver"]
            or Path(driver["filename"]).name != driver["filename"]
        ):
            raise ValueError("printer_driver_catalog_mismatch")
        path = Path(driver_dir) / driver["filename"]
        if (
            any(p.is_symlink() for p in (path, *path.parents))
            or path.stat().st_size > 1048576
        ):
            raise ValueError("printer_driver_path_invalid")
        drivers[driver["filename"]] = base64.b64encode(path.read_bytes()).decode(
            "ascii"
        )
    return {
        "program": source
        + "\nraise SystemExit(main(json.loads("
        + repr(json.dumps(catalog))
        + ")))\n",
        "document": {"request": request, "drivers": drivers},
    }


class FilterModule:
    def filters(self):
        return {"inventory_printer_payload": printer_payload}
