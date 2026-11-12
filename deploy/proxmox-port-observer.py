#!/usr/bin/python3
"""Report physical NIC carrier and negotiated speed without privileges."""

import json
import socket
from pathlib import Path


def read_number(path: Path, base: int = 10) -> int | None:
    try:
        return int(path.read_text(encoding="ascii").strip(), base)
    except (OSError, ValueError):
        return None


def main() -> None:
    ports = {}
    for path in sorted(Path("/sys/class/net").iterdir()):
        if not (path / "device").is_symlink():
            continue
        flags = read_number(path / "flags", 16)
        if flags is None:
            continue
        if not flags & 1:
            ports[path.name] = {"state": "disabled"}
            continue
        carrier = read_number(path / "carrier")
        if carrier in (0, 1):
            ports[path.name] = {"state": "up", "speedMbps": read_number(path / "speed")} if carrier else {"state": "down"}
    print(json.dumps({"hostname": socket.gethostname().partition(".")[0], "ports": ports}))


if __name__ == "__main__":
    main()
