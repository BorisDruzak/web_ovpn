"""Bounded read-only SNMP identity lookup for one printer."""
from __future__ import annotations

from collections.abc import Callable, Mapping
from typing import Any

from .config import load_secrets, snmp_community_env_name
from .nmap.policy import validate_target_ipv4
from .snmp.models import CapabilityResult
from .snmp.oids import SYS_DESCR, numeric_oid
from .snmp.outcomes import SnmpOutcome
from .snmp.transport import SnmpTransport, collect_on_worker_loop


PRINTER_SNMP_SECRET_REF = "printer_snmp"
PRINTER_NAME = numeric_oid("1.3.6.1.2.1.43.5.1.1.16.1")
PRINTER_SERIAL = numeric_oid("1.3.6.1.2.1.43.5.1.1.17.1")
PRINTER_PAGE_COUNTER = numeric_oid("1.3.6.1.2.1.43.10.2.1.4.1.1")
_REQUESTS = (
    ("description", SYS_DESCR),
    ("custom_name", PRINTER_NAME),
    ("serial_number", PRINTER_SERIAL),
    ("page_counter", PRINTER_PAGE_COUNTER),
)
TransportFactory = Callable[..., SnmpTransport]


def _text(result: CapabilityResult) -> str:
    if result.outcome is not SnmpOutcome.SUCCESS_WITH_ROWS or not result.rows:
        return ""
    value = result.rows[0].value
    if isinstance(value, bytes):
        return value.decode("utf-8", errors="replace").strip()[:512]
    if isinstance(value, str):
        return value.strip()[:512]
    return ""


def _counter(result: CapabilityResult) -> int | None:
    if result.outcome is not SnmpOutcome.SUCCESS_WITH_ROWS or not result.rows:
        return None
    value = result.rows[0].value
    return value if isinstance(value, int) and not isinstance(value, bool) and value >= 0 else None


async def _probe(
    host: str,
    community: str,
    version: str,
    transport_factory: TransportFactory,
) -> tuple[dict[str, str], dict[str, int], tuple[CapabilityResult, ...]]:
    transport = transport_factory(
        host=host,
        community=community,
        snmp_version=version,
        timeout_seconds=2,
        retries=1,
        max_repetitions=1,
    )
    async with transport:
        results = []
        for name, oid in _REQUESTS:
            results.append(await transport.get(oid, capability=name))
    suggestions: dict[str, str] = {}
    details: dict[str, int] = {}
    result_values = tuple(results)
    for (name, _oid), result in zip(_REQUESTS, result_values, strict=True):
        if name == "page_counter":
            value = _counter(result)
            if value is not None:
                details[name] = value
            continue
        value = _text(result)
        if value:
            suggestions[name] = value
    return suggestions, details, result_values


def inspect_printer_snmp(
    target_ip: str,
    *,
    secrets: Mapping[str, str] | None = None,
    transport_factory: TransportFactory = SnmpTransport,
) -> dict[str, Any]:
    """Collect a printer's standard MIB identity through SNMPv2c then SNMPv1.

    The returned public object deliberately contains only parsed inventory
    fields and outcome codes.  It never includes the community or raw values.
    """
    target = validate_target_ipv4(target_ip)
    values = secrets if secrets is not None else load_secrets()
    community = values.get(snmp_community_env_name(PRINTER_SNMP_SECRET_REF))
    if not isinstance(community, str) or not community:
        return {"status": "unavailable", "message": "printer_snmp_secret_not_configured"}
    outcomes: list[str] = []
    for version in ("2c", "1"):
        try:
            suggestions, details, results = collect_on_worker_loop(
                lambda: _probe(target, community, version, transport_factory)
            )
        except Exception:
            outcomes.append("transport_error")
            continue
        outcomes.extend(result.outcome.value for result in results)
        if suggestions or details:
            return {
                "status": "found",
                "snmp_version": version,
                "suggestions": suggestions,
                "details": details,
            }
    return {"status": "not_found", "outcomes": outcomes[:8]}
