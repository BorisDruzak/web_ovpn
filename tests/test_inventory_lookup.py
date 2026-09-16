from __future__ import annotations

from collections.abc import Callable

import pytest


def test_normalize_mac_accepts_common_physical_label_formats():
    """A separator-sensitive lookup would miss a MAC copied from equipment labels."""
    from app.inventory.lookup import normalize_mac

    assert normalize_mac("AA:bb:CC:dd:EE:ff") == "AA:BB:CC:DD:EE:FF"
    assert normalize_mac("aa-bb-cc-dd-ee-ff") == "AA:BB:CC:DD:EE:FF"
    assert normalize_mac("aabbccddeeff") == "AA:BB:CC:DD:EE:FF"


def test_ip_netctl_hit_returns_editable_suggestions_without_nmap():
    """A current netctl hit must not trigger an unnecessary active fingerprint."""
    from app.inventory.lookup import InventoryLookup

    calls: list[list[str]] = []

    def netctl(args: list[str], timeout: int | None = None):
        calls.append(args)
        return {
            "hosts": [
                {
                    "ip": "192.168.100.87",
                    "mac": "48:21:0B:AA:BB:CC",
                    "hostname": "C1-BUH-07",
                    "display_name": "C1-BUH-07",
                    "device_key": "ip:192.168.100.87",
                    "category": "local_device",
                    "site": "office",
                    "last_seen_at": "2026-09-16T08:30:00Z",
                    "last_source": "mikrotik_arp",
                }
            ]
        }

    result = InventoryLookup(netctl).lookup("192.168.100.87", actor="admin")

    assert result.status == "found"
    assert result.source == "netctl"
    assert result.suggestions["hostname"] == "C1-BUH-07"
    assert result.suggestions["ip"] == "192.168.100.87"
    assert calls == [["hosts", "list", "--q", "192.168.100.87", "--status", "current", "--limit", "25"]]


def test_ip_miss_uses_one_target_fingerprint_through_netctl_boundary():
    """A direct IP miss must use exactly one bounded CLI target and no shell-level scan."""
    from app.inventory.lookup import InventoryLookup

    calls: list[list[str]] = []

    def netctl(args: list[str], timeout: int | None = None):
        calls.append(args)
        if args[:2] == ["hosts", "list"]:
            return {"hosts": []}
        return {
            "fingerprint": {
                "nmap_version": "7.95",
                "ports": [{"protocol": "tcp", "port": 445, "state": "open", "service_name": "microsoft-ds"}],
                "os_matches": [{"name": "Windows 10", "accuracy": 92, "classes": []}],
            }
        }

    result = InventoryLookup(netctl).lookup("192.168.100.87", actor="admin")

    assert result.status == "found"
    assert result.source == "nmap"
    assert result.suggestions == {"ip": "192.168.100.87", "os_name": "Windows 10"}
    assert result.observation["target_ip"] == "192.168.100.87"
    assert calls[-1] == ["fingerprint", "inspect-ip", "--target", "192.168.100.87"]


@pytest.mark.parametrize("invalid", ["192.168.100.0/24", "192.168.100.1-10"])
def test_non_host_ip_is_rejected_without_network_actions(invalid):
    """CIDRs and ranges must not reach collection or fingerprint execution."""
    from app.inventory.lookup import InventoryLookup, InventoryLookupError

    calls: list[list[str]] = []

    with pytest.raises(InventoryLookupError, match="identifier"):
        InventoryLookup(lambda args, timeout=None: calls.append(args) or {}).lookup(invalid, actor="admin")

    assert calls == []


def test_mac_miss_refreshes_once_and_never_fingerprints_without_ip():
    """An unresolved MAC must not be converted into a speculative nmap target."""
    from app.inventory.lookup import InventoryLookup

    calls: list[list[str]] = []

    def netctl(args: list[str], timeout: int | None = None):
        calls.append(args)
        return {"hosts": []}

    result = InventoryLookup(netctl).lookup("aabbccddeeff", actor="admin")

    assert result.status == "not_found"
    assert calls == [
        ["hosts", "list", "--q", "AA:BB:CC:DD:EE:FF", "--status", "current", "--limit", "25"],
        ["hosts", "snapshot-refresh"],
        ["hosts", "list", "--q", "AA:BB:CC:DD:EE:FF", "--status", "current", "--limit", "25"],
    ]
