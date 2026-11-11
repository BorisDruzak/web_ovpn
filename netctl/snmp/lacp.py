"""Read the live partner and forwarding state of known LACP member ports."""

from netctl.snmp.models import SnmpOutcome


_PORT_ENTRY = (1, 2, 840, 10006, 300, 43, 1, 2, 1, 1)
_PARTNER_SYSTEM = 9
_ATTACHED_AGGREGATE = 13
_PARTNER_PORT = 17
_ACTOR_STATE = 21
_PARTNER_STATE = 23


def _forwarding(state: object) -> bool:
    # BITS are numbered from the most significant bit. Require aggregation,
    # synchronization, collecting and distributing, without defaulted or expired.
    return isinstance(state, bytes) and len(state) == 1 and state[0] & 0x3F == 0x3C


async def read_lacp_members(transport, aggregate: int, members: dict[str, int]) -> list[dict]:
    async def value(column, index, value_type):
        oid = _PORT_ENTRY + (column, index)
        result = await transport.get(oid)
        if result.outcome is SnmpOutcome.SUCCESS_WITH_ROWS and len(result.rows) == 1:
            row = result.rows[0]
            if row.oid == oid and row.value_type == value_type:
                return row.value
        return None

    confirmed = []
    for port, index in members.items():
        if await value(_ATTACHED_AGGREGATE, index, "integer") != aggregate:
            continue
        actor = await value(_ACTOR_STATE, index, "octet_string")
        partner = await value(_PARTNER_STATE, index, "octet_string")
        if not (_forwarding(actor) and _forwarding(partner)):
            continue
        mac = await value(_PARTNER_SYSTEM, index, "octet_string")
        peer = await value(_PARTNER_PORT, index, "integer")
        if isinstance(mac, bytes) and len(mac) == 6 and any(mac) and not mac[0] & 1 and type(peer) is int and 1 <= peer <= 65535:
            confirmed.append({"port": port, "mac": mac.hex(":"), "partner_port": peer})
    return confirmed
