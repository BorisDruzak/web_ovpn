from __future__ import annotations

from dataclasses import dataclass


@dataclass(frozen=True)
class RouterRule:
    rule_key: str
    family: str
    chain: str
    position: int
    disabled: bool
    action: str
    src_cidr: str
    dst_cidr: str
    protocol: str
    dst_port: str
    in_interface: str
    out_interface: str
    src_address_list: str
    dst_address_list: str
    routing_mark: str
    connection_state: str
    comment: str
    unsupported_matchers: tuple[str, ...]


@dataclass(frozen=True)
class RouterRoutingRule:
    rule_key: str
    position: int
    disabled: bool
    action: str
    src_cidr: str
    dst_cidr: str
    routing_mark: str
    table_name: str
    comment: str
    unsupported_matchers: tuple[str, ...]


@dataclass(frozen=True)
class RouterAddressListEntry:
    rule_key: str
    list_name: str
    address: str
    disabled: bool
    comment: str
    unsupported_matchers: tuple[str, ...]


@dataclass(frozen=True)
class RouterIpsecPolicy:
    rule_key: str
    position: int
    disabled: bool
    action: str
    src_cidr: str
    dst_cidr: str
    protocol: str
    comment: str
    unsupported_matchers: tuple[str, ...]
