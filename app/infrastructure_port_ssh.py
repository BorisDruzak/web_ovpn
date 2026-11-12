"""Read physical port states from the restricted Proxmox SSH exporter."""

from __future__ import annotations

import ipaddress
import json
import subprocess
from collections import defaultdict
from concurrent.futures import ThreadPoolExecutor
from datetime import datetime, timezone
from pathlib import Path


def _expected_port_vlans(context: dict) -> dict[tuple[str, str], set[int]]:
    expected = defaultdict(set)
    for link in context.get("links", []):
        vlans = link.get("vlans")
        state = link.get("state", {})
        if (link.get("relation") != "connected_to" or state.get("verified") is not True
                or state.get("intent") == "absent" or not isinstance(vlans, dict)):
            continue
        ids = {vid for mode in ("untagged", "tagged") for vid in vlans.get(mode, [])}
        for endpoint in (link["endpoint_a"], link["endpoint_b"]):
            if ids and endpoint.get("interface"):
                expected[(endpoint["device"], endpoint["interface"])].update(ids)
    return expected


def _observed_vlans(ranges: object, expected: set[int]) -> list[dict]:
    if not isinstance(ranges, list) or len(ranges) > 4094:
        return []
    observations, last = [], 0
    has_pvid = False
    for row in ranges:
        if not isinstance(row, list) or len(row) != 4:
            return []
        first, end, mode, pvid = row
        if (type(first) is not int or type(end) is not int or not last < first <= end <= 4094
                or mode not in ("untagged", "tagged") or type(pvid) is not bool
                or (pvid and (first != end or has_pvid))):
            return []
        last = end
        has_pvid |= pvid
        observations.extend({"id": vid, "egress": mode, "pvid": pvid} for vid in sorted(expected)
                            if first <= vid <= end)
    return observations


def collect_proxmox_port_states(context: dict, pve: dict, credentials: Path) -> None:
    identity = credentials / "pve-port-ssh-key"
    hosts = credentials / "pve-port-known-hosts"
    if not identity.is_file() or not hosts.is_file():
        return

    online = {node["node"] for node in pve.get("nodes", []) if node.get("status") == "online"}
    ports_by_node = pve.get("physicalPorts", {})
    expected_vlans = _expected_port_vlans(context)
    targets = []
    for device in context.get("devices", []):
        node = device["id"]
        if device.get("kind") == "hypervisor" and node in online and ports_by_node.get(node):
            try:
                address = ipaddress.IPv4Address(device.get("management_ip"))
            except ValueError:
                continue
            targets.append((node, address))

    def read(target):
        node, address = target
        args = [
            "/usr/bin/ssh", "-F", "/dev/null", "-nT", "-i", str(identity),
            "-o", f"UserKnownHostsFile={hosts}", "-o", "GlobalKnownHostsFile=/dev/null",
            "-o", "StrictHostKeyChecking=yes", "-o", "UpdateHostKeys=no", "-o", "BatchMode=yes",
            "-o", "IdentitiesOnly=yes", "-o", "ClearAllForwardings=yes", "-o", "ConnectTimeout=3",
            "--", f"ui-vpn-ports@{address}",
        ]
        try:
            response = subprocess.run(args, stdout=subprocess.PIPE, stderr=subprocess.DEVNULL, timeout=6, check=True)
            if len(response.stdout) > 32_768:
                return node, {}
            payload = json.loads(response.stdout)
        except (OSError, subprocess.SubprocessError, ValueError, RecursionError):
            return node, {}
        if not isinstance(payload, dict) or payload.get("hostname") != node or not isinstance(payload.get("ports"), dict):
            return node, {}
        return node, payload["ports"]

    with ThreadPoolExecutor(max_workers=6) as pool:
        for node, observations in pool.map(read, targets):
            checked_at = datetime.now(timezone.utc).isoformat()
            for port in ports_by_node[node]:
                sample = observations.get(port["name"])
                if not isinstance(sample, dict) or sample.get("state") not in ("up", "down", "disabled"):
                    continue
                speed = sample.get("speedMbps")
                port.update(source="Proxmox · sysfs", state=sample["state"], checkedAt=checked_at,
                            speedBps=speed * 10**6 if sample["state"] == "up" and type(speed) is int
                            and 1 <= speed <= 1_000_000 else None)
                port.pop("vlanMemberships", None)
                expected = expected_vlans.get((node, port["name"]))
                if sample["state"] == "up" and expected and (vlans := _observed_vlans(sample.get("vlanRanges"), expected)):
                    port["vlanMemberships"] = {"checkedAt": checked_at, "vlans": vlans}
