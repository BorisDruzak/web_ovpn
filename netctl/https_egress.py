"""Read-only RouterOS evidence for a single completed TCP flow."""

import ipaddress
import re

from .drivers.mikrotik_api import MikroTikApiDriver


def _matches(row: dict, field: str, address: str, port: int) -> bool:
    return row.get(f"{field}-address") == f"{address}:{port}" or (
        row.get(f"{field}-address") == address and row.get(f"{field}-port") == str(port)
    )


def observe_https_egress(
    driver: MikroTikApiDriver, local: str, source_port: int, peer: str, peer_port: int = 443
) -> dict:
    command = [
        "/ip/firewall/connection/print",
        "=.proplist=protocol,src-address,src-port,dst-address,dst-port,reply-dst-address,srcnat,seen-reply",
    ]
    filters = (
        [f"?src-address={local}:{source_port}"],
        [f"?src-address={local}", f"?src-port={source_port}"],
    )
    try:
        with driver._client() as api:
            for query in filters:
                matches = [
                    row for row in api.call([*command, *query])
                    if row.get("protocol") == "tcp"
                    and _matches(row, "src", local, source_port)
                    and _matches(row, "dst", peer, peer_port)
                ]
                if matches:
                    break
            if len(matches) != 1:
                return {"status": "unconfirmed", "reason": "no_unique_connection"}
            row = matches[0]
            if row.get("srcnat") not in ("true", "yes") or row.get("seen-reply") not in ("true", "yes"):
                return {"status": "unconfirmed", "reason": "no_nat_reply"}
            translated = ipaddress.IPv4Address(row["reply-dst-address"].split(":", 1)[0])
            addresses = api.call(["/ip/address/print", "=.proplist=address,interface,disabled"])
    except (KeyError, OSError, RuntimeError, ValueError):
        return {"status": "unavailable"}
    interfaces = set()
    for address in addresses:
        interface = address.get("interface", "")
        if address.get("disabled") in ("true", "yes") or not re.fullmatch(r"[A-Za-z0-9_.:@-]{1,64}", interface):
            continue
        try:
            if ipaddress.IPv4Interface(address.get("address", "")).ip == translated:
                interfaces.add(interface)
        except ValueError:
            continue
    if len(interfaces) != 1:
        return {"status": "unconfirmed", "reason": "no_unique_nat_interface"}
    return {"status": "confirmed", "nat_interface": interfaces.pop()}
