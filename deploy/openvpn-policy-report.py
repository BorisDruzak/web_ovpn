#!/usr/bin/python3
"""Publish a bounded report of ingress marks and WireGuard handshakes."""

import json
import os
import re
import shlex
import subprocess
import tempfile
from collections import Counter
from datetime import datetime, timezone
from pathlib import Path


def read(*args):
    try:
        result = subprocess.check_output(args, stderr=subprocess.DEVNULL, timeout=3, text=True)
    except (OSError, subprocess.SubprocessError):
        return None
    return result.splitlines()


def markers(prerouting, chain):
    if prerouting != ["-P PREROUTING ACCEPT", "-A PREROUTING -j VPN_POLICY_MARK"] or not chain:
        return None
    try:
        rules = [shlex.split(line) for line in chain if line != "-N VPN_POLICY_MARK"]
    except ValueError:
        return None
    if any(rule[:2] != ["-A", "VPN_POLICY_MARK"] or rule.count("-i") != 1 or "!" in rule
           or rule.index("-i") + 1 >= len(rule) for rule in rules):
        return None
    interfaces = Counter(rule[rule.index("-i") + 1] for rule in rules)
    if any(not re.fullmatch(r"[A-Za-z0-9_.-]{1,15}", name) for name in interfaces):
        return None
    result = {}
    for rule in rules:
        if len(rule) != 8 or rule[2:3] != ["-i"] or rule[4:7] != ["-j", "MARK", "--set-xmark"]:
            continue
        name = rule[3]
        if interfaces[name] == 1:
            mark = re.fullmatch(r"(0x[0-9a-fA-F]{1,8})/0xffffffff", rule[7])
            if mark:
                result[name] = int(mark[1], 16)
    return result


def handshakes(lines):
    if lines is None:
        return None
    result = {}
    for line in lines:
        fields = line.split()
        if len(fields) != 3 or not re.fullmatch(r"[A-Za-z0-9_.-]{1,15}", fields[0]) or not re.fullmatch(r"[0-9]{1,12}", fields[2]):
            return None
        name, _, epoch = fields
        entry = result.setdefault(name, {"peerCount": 0, "latestHandshake": 0})
        entry["peerCount"] += 1
        entry["latestHandshake"] = max(entry["latestHandshake"], int(epoch))
    return result


def main():
    prerouting = read("/usr/sbin/iptables", "-w", "1", "-t", "mangle", "-S", "PREROUTING")
    chain = read("/usr/sbin/iptables", "-w", "1", "-t", "mangle", "-S", "VPN_POLICY_MARK")
    observed = {"checkedAt": datetime.now(timezone.utc).isoformat(),
                "markers": markers(prerouting, chain),
                "wireguard": handshakes(read("/usr/bin/wg", "show", "all", "latest-handshakes"))}
    path = Path("/run/openvpn-policy-observer/latest.json")
    with tempfile.NamedTemporaryFile(mode="w", encoding="utf-8", dir=path.parent, delete=False) as handle:
        os.fchmod(handle.fileno(), 0o640)
        json.dump(observed, handle)
    os.replace(handle.name, path)


if __name__ == "__main__":
    main()
