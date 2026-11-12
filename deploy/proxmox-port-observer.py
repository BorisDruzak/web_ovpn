#!/usr/bin/python3
"""Report physical NIC carrier, speed and bridge VLANs without privileges."""

import json
import socket
import subprocess
from pathlib import Path


def read_number(path: Path, base: int = 10) -> int | None:
    try:
        return int(path.read_text(encoding="ascii").strip(), base)
    except (OSError, ValueError):
        return None


def bridge_vlan_ranges(port: Path) -> list[list]:
    bridge = port / "master" / "bridge"
    if read_number(bridge / "vlan_filtering") != 1 or read_number(bridge / "vlan_protocol", 16) != 0x8100:
        return []
    try:
        data = subprocess.check_output(
            ["/usr/sbin/bridge", "-j", "vlan", "show", "dev", port.name],
            stderr=subprocess.DEVNULL, timeout=1,
        )
        if len(data) > 131_072:
            return []
        rows = json.loads(data)
    except (OSError, subprocess.SubprocessError, ValueError, RecursionError):
        return []
    if not isinstance(rows, list) or len(rows) != 1 or not isinstance(rows[0], dict):
        return []
    vlans = rows[0].get("vlans")
    if rows[0].get("ifname") != port.name or not isinstance(vlans, list) or len(vlans) > 4094:
        return []
    ranges = []
    for row in vlans:
        if not isinstance(row, dict):
            return []
        vlan, flags = row.get("vlan"), row.get("flags", [])
        if (type(vlan) is not int or not 1 <= vlan <= 4094 or (ranges and vlan <= ranges[-1][1])
                or not isinstance(flags, list) or any(flag not in ("PVID", "Egress Untagged") for flag in flags)):
            return []
        mode = "untagged" if "Egress Untagged" in flags else "tagged"
        pvid = "PVID" in flags
        if ranges and not pvid and ranges[-1][1] + 1 == vlan and ranges[-1][2:] == [mode, False]:
            ranges[-1][1] = vlan
        else:
            ranges.append([vlan, vlan, mode, pvid])
    return ranges


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
            if carrier and (ranges := bridge_vlan_ranges(path)):
                ports[path.name]["vlanRanges"] = ranges
    print(json.dumps({"hostname": socket.gethostname().partition(".")[0], "ports": ports}))


if __name__ == "__main__":
    main()
