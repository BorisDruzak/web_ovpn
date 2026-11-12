"""Read physical port states from the restricted Proxmox SSH exporter."""

from __future__ import annotations

import ipaddress
import json
import subprocess
from concurrent.futures import ThreadPoolExecutor
from datetime import datetime, timezone
from pathlib import Path


def collect_proxmox_port_states(context: dict, pve: dict, credentials: Path) -> None:
    identity = credentials / "pve-port-ssh-key"
    hosts = credentials / "pve-port-known-hosts"
    if not identity.is_file() or not hosts.is_file():
        return

    online = {node["node"] for node in pve.get("nodes", []) if node.get("status") == "online"}
    ports_by_node = pve.get("physicalPorts", {})
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
