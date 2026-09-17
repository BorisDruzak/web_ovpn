from __future__ import annotations

import re
import threading
from collections.abc import Callable, Mapping
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from typing import Any, Literal

from netctl.nmap.policy import FingerprintPolicyError, validate_target_ipv4

from .normalization import normalize_pc_details


NetctlCall = Callable[[list[str], int | None], dict[str, Any]]
_MAC_RE = re.compile(r"^[0-9A-Fa-f]{2}([:-]?[0-9A-Fa-f]{2}){5}$")
_HOSTNAME_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]{0,252}$")
STALE_HOST_GRACE = timedelta(minutes=20)


class InventoryLookupError(ValueError):
    """A lookup input is not a supported single physical-device identifier."""


@dataclass(frozen=True)
class LookupResult:
    status: Literal["found", "not_found", "unavailable"]
    source: str
    suggestions: dict[str, str]
    observation: dict[str, object]
    message: str = ""


def normalize_mac(value: str) -> str:
    raw = value.strip()
    if not _MAC_RE.fullmatch(raw):
        raise InventoryLookupError("invalid identifier")
    compact = raw.replace(":", "").replace("-", "").upper()
    return ":".join(compact[index : index + 2] for index in range(0, 12, 2))


def classify_identifier(value: str) -> tuple[Literal["ip", "mac", "hostname"], str]:
    raw = value.strip()
    if not raw:
        raise InventoryLookupError("invalid identifier")
    if "/" in raw or re.search(r"\d-\d", raw):
        raise InventoryLookupError("invalid identifier")
    try:
        return "ip", validate_target_ipv4(raw)
    except FingerprintPolicyError:
        pass
    try:
        return "mac", normalize_mac(raw)
    except InventoryLookupError:
        pass
    if _HOSTNAME_RE.fullmatch(raw):
        return "hostname", raw.lower()
    raise InventoryLookupError("invalid identifier")


class InventoryLookup:
    """Read netctl observations and request a single safe nmap fallback through netctl."""

    _locks_guard = threading.Lock()
    _mac_refresh_locks: dict[str, threading.Lock] = {}

    def __init__(
        self,
        netctl_call: NetctlCall,
        *,
        now: Callable[[], datetime] = lambda: datetime.now(UTC),
    ) -> None:
        self._netctl_call = netctl_call
        self._now = now

    def lookup(self, value: str, *, actor: str) -> LookupResult:
        del actor  # Audit ownership is recorded by the route that invokes this service.
        identifier_type, normalized = classify_identifier(value)
        try:
            hosts = self._search_hosts(normalized, status="current")
        except Exception:
            return LookupResult("unavailable", "netctl", {}, {}, "Автоматический поиск сейчас недоступен.")
        if hosts:
            return self._netctl_result(hosts[0], identifier_type, normalized)
        if identifier_type == "ip":
            try:
                stale_hosts = self._search_hosts(normalized, status="all")
            except Exception:
                return LookupResult("unavailable", "netctl", {}, {}, "Автоматический поиск сейчас недоступен.")
            for host in stale_hosts:
                if self._is_recent_exact_host(host, identifier_type, normalized):
                    return self._netctl_result(host, identifier_type, normalized)
        if identifier_type == "mac":
            try:
                self._refresh_for_mac(normalized)
                hosts = self._search_hosts(normalized, status="current")
            except Exception:
                return LookupResult("unavailable", "netctl", {}, {}, "Автоматический поиск сейчас недоступен.")
            if hosts:
                return self._netctl_result(hosts[0], identifier_type, normalized)
            return LookupResult("not_found", "netctl", {}, {"identifier": normalized}, "Устройство не найдено.")
        if identifier_type != "ip":
            return LookupResult("not_found", "netctl", {}, {"identifier": normalized}, "Устройство не найдено.")
        try:
            payload = self._netctl_call(["fingerprint", "inspect-ip", "--target", normalized], 30)
        except Exception:
            return LookupResult("unavailable", "nmap", {}, {"target_ip": normalized}, "Nmap fingerprint сейчас недоступен.")
        fingerprint = payload.get("fingerprint") if isinstance(payload, Mapping) else None
        if not isinstance(fingerprint, Mapping):
            return LookupResult("not_found", "nmap", {}, {"target_ip": normalized}, "Устройство не найдено.")
        suggestions = {"ip": normalized}
        os_matches = fingerprint.get("os_matches")
        if isinstance(os_matches, list):
            for match in os_matches:
                if not isinstance(match, Mapping):
                    continue
                os_name = str(match.get("name") or "").strip()
                if os_name:
                    normalized_details = normalize_pc_details({"os_name": os_name}, strict=False)
                    if normalized_details.get("os_name") in {"Windows", "Linux"}:
                        suggestions["os_name"] = normalized_details["os_name"]
                        if normalized_details.get("os_version"):
                            suggestions["os_version"] = normalized_details["os_version"]
                    break
        return LookupResult(
            "found",
            "nmap",
            suggestions,
            {"target_ip": normalized, "source": "nmap", "fingerprint": dict(fingerprint)},
        )

    def _search_hosts(self, query: str, *, status: str) -> list[dict[str, object]]:
        payload = self._netctl_call(["hosts", "list", "--q", query, "--status", status, "--limit", "25"], 60)
        hosts = payload.get("hosts", []) if isinstance(payload, Mapping) else []
        return [dict(host) for host in hosts if isinstance(host, Mapping)]

    def _is_recent_exact_host(
        self,
        host: Mapping[str, object],
        identifier_type: str,
        normalized: str,
    ) -> bool:
        value = str(host.get(identifier_type) or "").strip()
        if identifier_type == "mac":
            try:
                value = normalize_mac(value)
            except InventoryLookupError:
                return False
        elif identifier_type == "hostname":
            value = value.lower()
        if value != normalized:
            return False
        raw_seen = host.get("last_seen_at")
        try:
            seen_at = datetime.fromisoformat(str(raw_seen).replace("Z", "+00:00"))
        except (TypeError, ValueError):
            return False
        if seen_at.tzinfo is None:
            return False
        age = self._now().astimezone(UTC) - seen_at.astimezone(UTC)
        return timedelta(0) <= age <= STALE_HOST_GRACE

    def _refresh_for_mac(self, mac: str) -> None:
        with self._locks_guard:
            lock = self._mac_refresh_locks.setdefault(mac, threading.Lock())
        with lock:
            self._netctl_call(["hosts", "snapshot-refresh"], 180)

    @staticmethod
    def _netctl_result(host: Mapping[str, object], identifier_type: str, normalized: str) -> LookupResult:
        suggestions = {
            key: str(host[key])
            for key in ("ip", "mac", "hostname", "display_name")
            if host.get(key) not in (None, "")
        }
        return LookupResult(
            "found",
            "netctl",
            suggestions,
            {
                "source": "netctl",
                "identifier_type": identifier_type,
                "identifier": normalized,
                "asset_key": str(host.get("device_key") or ""),
                "ip": suggestions.get("ip"),
                "mac": suggestions.get("mac"),
                "hostname": suggestions.get("hostname"),
                "display_name": suggestions.get("display_name"),
                "kind": host.get("category"),
                "site": host.get("site"),
                "last_seen": host.get("last_seen_at"),
                "source_detail": host.get("last_source"),
            },
        )
