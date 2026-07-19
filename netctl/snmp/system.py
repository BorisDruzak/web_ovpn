from __future__ import annotations

from collections.abc import Iterable

from .models import CapabilityResult, SnmpVarBind, SwitchSystem
from .oids import SYS_DESCR, SYS_LOCATION, SYS_NAME, SYS_OBJECT_ID, SYS_UPTIME


_TEXT_TYPES = frozenset({"string", "octet_string"})
_INTEGER_TYPES = frozenset(
    {"integer", "counter32", "counter64", "gauge32", "unsigned32", "time_ticks"}
)


def _rows(values: Iterable[SnmpVarBind | CapabilityResult]) -> Iterable[SnmpVarBind]:
    for value in values:
        if isinstance(value, CapabilityResult):
            yield from value.rows
        elif isinstance(value, SnmpVarBind):
            yield value
        else:
            raise ValueError("system row is invalid")


def _text(row: SnmpVarBind, field: str) -> str:
    if row.value_type not in _TEXT_TYPES:
        raise ValueError(f"{field} has invalid type")
    if row.value_type == "string" and isinstance(row.value, str):
        return row.value
    if row.value_type == "octet_string" and isinstance(row.value, bytes):
        try:
            return row.value.decode("utf-8")
        except UnicodeDecodeError:
            raise ValueError(f"{field} has invalid text") from None
    raise ValueError(f"{field} has invalid type")


def _object_identifier(row: SnmpVarBind) -> str:
    if row.value_type != "object_identifier" or not isinstance(row.value, str):
        raise ValueError("sysObjectID has invalid type")
    parts = row.value.split(".")
    if not parts or any(not part.isascii() or not part.isdigit() for part in parts):
        raise ValueError("sysObjectID is invalid")
    return row.value


def _uptime(row: SnmpVarBind) -> int:
    if (
        row.value_type not in _INTEGER_TYPES
        or isinstance(row.value, bool)
        or not isinstance(row.value, int)
        or row.value < 0
    ):
        raise ValueError("sysUpTime has invalid type")
    return row.value


def parse_system(values: Iterable[SnmpVarBind | CapabilityResult]) -> SwitchSystem:
    parsed: dict[tuple[int, ...], str | int] = {}
    for row in _rows(values):
        if row.oid == SYS_DESCR:
            value: str | int = _text(row, "sysDescr")
        elif row.oid == SYS_OBJECT_ID:
            value = _object_identifier(row)
        elif row.oid == SYS_NAME:
            value = _text(row, "sysName")
        elif row.oid == SYS_LOCATION:
            value = _text(row, "sysLocation")
        elif row.oid == SYS_UPTIME:
            value = _uptime(row)
        else:
            continue
        if row.oid in parsed and parsed[row.oid] != value:
            raise ValueError("conflicting system scalar")
        parsed[row.oid] = value

    return SwitchSystem(
        sys_descr=str(parsed.get(SYS_DESCR, "")),
        sys_object_id=str(parsed.get(SYS_OBJECT_ID, "")),
        sys_name=str(parsed.get(SYS_NAME, "")),
        sys_location=str(parsed.get(SYS_LOCATION, "")),
        sys_uptime_ticks=int(parsed[SYS_UPTIME]) if SYS_UPTIME in parsed else None,
    )
