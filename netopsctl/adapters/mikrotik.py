from __future__ import annotations

import ipaddress
import re
from typing import Any, Protocol


ADDRESS_LIST_NAME = "WEBOVPN-INTERNET-DENY"
MANAGED_COMMENT_PREFIX = "web_ovpn:"
_PLAN_KEY_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]{0,127}$")


class RouterOSClient(Protocol):
    def call(self, words: list[str]) -> list[dict[str, str]]: ...


class MikroTikPolicyAdapter:
    """A deliberately small RouterOS surface: one anchor and one IPv4 list."""

    def __init__(self, enforcement_source: str, client: RouterOSClient) -> None:
        self._enforcement_source = enforcement_source
        self._client = client

    def _target(self, target: str) -> None:
        if target != self._enforcement_source:
            raise ValueError("target is not the configured MikroTik enforcement source")

    @staticmethod
    def _is_anchor(row: dict[str, str]) -> bool:
        return (
            str(row.get("chain") or "") == "forward"
            and str(row.get("action") or "") == "drop"
            and str(row.get("src-address-list") or "") == ADDRESS_LIST_NAME
            and str(row.get("out-interface-list") or "") == "WAN"
            and str(row.get("disabled") or "").lower() in {"false", "no", "0", ""}
        )

    def inspect_internet_policy_anchor(self) -> dict[str, Any]:
        rows = self._client.call([
            "/ip/firewall/filter/print",
            "=.proplist=.id,chain,action,src-address-list,out-interface-list,disabled",
        ])
        return {"valid": any(self._is_anchor(row) for row in rows), "anchor": ADDRESS_LIST_NAME}

    def _require_anchor(self) -> None:
        if not self.inspect_internet_policy_anchor()["valid"]:
            raise ValueError("required Internet policy anchor is missing or does not match the approved signature")

    @staticmethod
    def _ipv4(address: str) -> str:
        try:
            value = ipaddress.ip_address(address)
        except ValueError as exc:
            raise ValueError("only IPv4 addresses are allowed") from exc
        if value.version != 4:
            raise ValueError("only IPv4 addresses are allowed")
        return str(value)

    def _entries(self) -> list[dict[str, str]]:
        return self._client.call([
            "/ip/firewall/address-list/print",
            "=.proplist=.id,list,address,comment,disabled",
            f"?list={ADDRESS_LIST_NAME}",
        ])

    def list_managed_address_list_entries(self, target: str) -> list[dict[str, str]]:
        self._target(target)
        return [
            {"address": str(row.get("address") or ""), "comment": str(row.get("comment") or ""), "disabled": str(row.get("disabled") or "")}
            for row in self._entries()
            if str(row.get("list") or "") == ADDRESS_LIST_NAME and str(row.get("comment") or "").startswith(MANAGED_COMMENT_PREFIX)
        ]

    def ensure_address_list_entry(self, target: str, address: str, plan_key: str) -> dict[str, str]:
        self._target(target)
        address = self._ipv4(address)
        if not _PLAN_KEY_RE.fullmatch(plan_key):
            raise ValueError("invalid plan key")
        self._require_anchor()
        for row in self._entries():
            if str(row.get("list") or "") == ADDRESS_LIST_NAME and str(row.get("address") or "") == address:
                if not str(row.get("comment") or "").startswith(MANAGED_COMMENT_PREFIX):
                    raise ValueError("existing address-list entry is not managed by netopsctl")
                return {"status": "already_present", "address": address}
        self._client.call([
            "/ip/firewall/address-list/add",
            f"=list={ADDRESS_LIST_NAME}", f"=address={address}", f"=comment={MANAGED_COMMENT_PREFIX}{plan_key}",
        ])
        return {"status": "added", "address": address}

    def remove_address_list_entry(self, target: str, address: str) -> dict[str, str]:
        self._target(target)
        address = self._ipv4(address)
        self._require_anchor()
        for row in self._entries():
            if str(row.get("list") or "") != ADDRESS_LIST_NAME or str(row.get("address") or "") != address:
                continue
            if not str(row.get("comment") or "").startswith(MANAGED_COMMENT_PREFIX):
                raise ValueError("existing address-list entry is not managed by netopsctl")
            entry_id = str(row.get(".id") or "")
            if not entry_id:
                raise ValueError("managed address-list entry has no identifier")
            self._client.call(["/ip/firewall/address-list/remove", f"=.id={entry_id}"])
            return {"status": "removed", "address": address}
        return {"status": "already_absent", "address": address}
