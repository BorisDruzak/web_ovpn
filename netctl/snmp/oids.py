from __future__ import annotations

from typing import TypeAlias


NumericOid: TypeAlias = tuple[int, ...]


def numeric_oid(value: str | tuple[int, ...]) -> NumericOid:
    if isinstance(value, str):
        if not value or value.startswith(".") or value.endswith("."):
            raise ValueError("numeric OID is invalid")
        parts = value.split(".")
        if any(not part.isascii() or not part.isdigit() for part in parts):
            raise ValueError("numeric OID is invalid")
        result = tuple(int(part) for part in parts)
    elif isinstance(value, tuple):
        result = value
    else:
        raise ValueError("numeric OID is invalid")

    if not result or any(
        isinstance(part, bool) or not isinstance(part, int) or part < 0
        for part in result
    ):
        raise ValueError("numeric OID is invalid")
    return result


def require_numeric_oid(value: object) -> NumericOid:
    if not isinstance(value, tuple):
        raise ValueError("SNMP requests require a numeric OID tuple")
    try:
        return numeric_oid(value)
    except ValueError:
        raise ValueError("SNMP requests require a numeric OID tuple") from None


def oid_text(value: tuple[int, ...]) -> str:
    return ".".join(str(part) for part in numeric_oid(value))


SYS_DESCR = numeric_oid("1.3.6.1.2.1.1.1.0")
SYS_OBJECT_ID = numeric_oid("1.3.6.1.2.1.1.2.0")
SYS_UPTIME = numeric_oid("1.3.6.1.2.1.1.3.0")
SYS_NAME = numeric_oid("1.3.6.1.2.1.1.5.0")
SYS_LOCATION = numeric_oid("1.3.6.1.2.1.1.6.0")

IF_INDEX = numeric_oid("1.3.6.1.2.1.2.2.1.1")
IF_DESCR = numeric_oid("1.3.6.1.2.1.2.2.1.2")
IF_TYPE = numeric_oid("1.3.6.1.2.1.2.2.1.3")
IF_SPEED = numeric_oid("1.3.6.1.2.1.2.2.1.5")
IF_PHYS_ADDRESS = numeric_oid("1.3.6.1.2.1.2.2.1.6")
IF_ADMIN_STATUS = numeric_oid("1.3.6.1.2.1.2.2.1.7")
IF_OPER_STATUS = numeric_oid("1.3.6.1.2.1.2.2.1.8")
IF_IN_DISCARDS = numeric_oid("1.3.6.1.2.1.2.2.1.13")
IF_IN_ERRORS = numeric_oid("1.3.6.1.2.1.2.2.1.14")
IF_OUT_DISCARDS = numeric_oid("1.3.6.1.2.1.2.2.1.19")
IF_OUT_ERRORS = numeric_oid("1.3.6.1.2.1.2.2.1.20")
IF_NAME = numeric_oid("1.3.6.1.2.1.31.1.1.1.1")
IF_HC_IN_OCTETS = numeric_oid("1.3.6.1.2.1.31.1.1.1.6")
IF_HC_OUT_OCTETS = numeric_oid("1.3.6.1.2.1.31.1.1.1.10")
IF_HIGH_SPEED = numeric_oid("1.3.6.1.2.1.31.1.1.1.15")
IF_ALIAS = numeric_oid("1.3.6.1.2.1.31.1.1.1.18")

DOT1D_BASE_PORT_IFINDEX = numeric_oid("1.3.6.1.2.1.17.1.4.1.2")
DOT1D_FDB_ADDRESS = numeric_oid("1.3.6.1.2.1.17.4.3.1.1")
DOT1D_FDB_PORT = numeric_oid("1.3.6.1.2.1.17.4.3.1.2")
DOT1D_FDB_STATUS = numeric_oid("1.3.6.1.2.1.17.4.3.1.3")

DOT1Q_FDB_PORT = numeric_oid("1.3.6.1.2.1.17.7.1.2.2.1.2")
DOT1Q_FDB_STATUS = numeric_oid("1.3.6.1.2.1.17.7.1.2.2.1.3")
DOT1Q_VLAN_FDB_ID = numeric_oid("1.3.6.1.2.1.17.7.1.4.2.1.3")
DOT1Q_VLAN_CURRENT_EGRESS = numeric_oid("1.3.6.1.2.1.17.7.1.4.2.1.4")
DOT1Q_VLAN_CURRENT_UNTAGGED = numeric_oid("1.3.6.1.2.1.17.7.1.4.2.1.5")
DOT1Q_VLAN_STATIC_NAME = numeric_oid("1.3.6.1.2.1.17.7.1.4.3.1.1")
DOT1Q_VLAN_STATIC_EGRESS = numeric_oid("1.3.6.1.2.1.17.7.1.4.3.1.2")
DOT1Q_VLAN_STATIC_UNTAGGED = numeric_oid("1.3.6.1.2.1.17.7.1.4.3.1.4")
DOT1Q_PVID = numeric_oid("1.3.6.1.2.1.17.7.1.4.5.1.1")

DOT1D_STP_PROTOCOL = numeric_oid("1.3.6.1.2.1.17.2.1.0")
DOT1D_STP_TOPOLOGY_CHANGES = numeric_oid("1.3.6.1.2.1.17.2.4.0")
DOT1D_STP_DESIGNATED_ROOT = numeric_oid("1.3.6.1.2.1.17.2.5.0")
DOT1D_STP_ROOT_COST = numeric_oid("1.3.6.1.2.1.17.2.6.0")
DOT1D_STP_ROOT_PORT = numeric_oid("1.3.6.1.2.1.17.2.7.0")
