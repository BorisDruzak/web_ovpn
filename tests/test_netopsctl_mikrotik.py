from __future__ import annotations

import pytest


class FakeRouter:
    def __init__(self, rows):
        self.rows = rows
        self.calls = []

    def call(self, words):
        self.calls.append(words)
        if words[0] == "/ip/firewall/filter/print":
            return self.rows.get("anchors", [])
        if words[0] == "/ip/firewall/address-list/print":
            return self.rows.get("entries", [])
        return []


def _anchor():
    return {
        "chain": "forward", "action": "drop", "src-address-list": "WEBOVPN-INTERNET-DENY",
        "out-interface-list": "WAN", "disabled": "false", "log": "false",
        "comment": "web_ovpn:internet-policy-anchor:v1",
    }


def test_bounded_adapter_requires_exact_anchor_and_is_idempotent() -> None:
    from netopsctl.adapters.mikrotik import MikroTikPolicyAdapter

    router = FakeRouter({"anchors": [_anchor()], "entries": [{".id": "*1", "list": "WEBOVPN-INTERNET-DENY", "address": "192.0.2.10", "comment": "web_ovpn:policy:plan-1:asset:mac:AA:BB"}]})
    adapter = MikroTikPolicyAdapter("router-a", router)

    inspection = adapter.inspect_internet_policy_anchor()
    assert inspection["valid"] is True
    assert inspection["fingerprint"].startswith("sha256:")
    result = adapter.ensure_address_list_entry("router-a", "192.0.2.10", "plan-1", "mac:AA:BB")
    assert result["status"] == "already_present"
    assert all(call[0] in {"/ip/firewall/filter/print", "/ip/firewall/address-list/print"} for call in router.calls)


def test_bounded_adapter_rejects_wrong_target_invalid_ip_and_non_managed_removal() -> None:
    from netopsctl.adapters.mikrotik import MikroTikPolicyAdapter

    router = FakeRouter({"anchors": [_anchor()], "entries": [{".id": "*1", "list": "WEBOVPN-INTERNET-DENY", "address": "192.0.2.10", "comment": "operator-entry"}]})
    adapter = MikroTikPolicyAdapter("router-a", router)

    with pytest.raises(ValueError):
        adapter.ensure_address_list_entry("router-b", "192.0.2.10", "plan-1", "mac:AA:BB")
    with pytest.raises(ValueError):
        adapter.ensure_address_list_entry("router-a", "not-an-ip", "plan-1", "mac:AA:BB")
    with pytest.raises(ValueError):
        adapter.remove_address_list_entry("router-a", "192.0.2.10", "plan-1", "mac:AA:BB")


def test_bounded_adapter_refuses_missing_anchor_and_never_accepts_arbitrary_routeros_paths() -> None:
    from netopsctl.adapters.mikrotik import MikroTikPolicyAdapter

    router = FakeRouter({"anchors": [], "entries": []})
    adapter = MikroTikPolicyAdapter("router-a", router)
    with pytest.raises(ValueError, match="anchor"):
        adapter.ensure_address_list_entry("router-a", "192.0.2.10", "plan-1", "mac:AA:BB")
    with pytest.raises(AttributeError):
        getattr(adapter, "run_routeros_command")
