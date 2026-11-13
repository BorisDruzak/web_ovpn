from __future__ import annotations

import hashlib
import ipaddress
import json
import logging
import os
import stat
from pathlib import Path
from typing import Annotated, Literal

from pydantic import BaseModel, ConfigDict, Field, StringConstraints, ValidationError, field_validator, model_validator

from .network_https_speed import MAX_DOWNLOAD_BYTES, MAX_UPLOAD_BYTES, MIN_BYTES, validate_speed_peer
from .network_throughput import validate_throughput_profile

PROFILE_PATH = Path("/etc/openvpn-web/network-probes.json")
PROFILE_ID_PATTERN = r"^[a-zA-Z0-9][a-zA-Z0-9_-]{0,47}$"
ProfileId = Annotated[str, StringConstraints(pattern=PROFILE_ID_PATTERN)]
log = logging.getLogger(__name__)


class ProbeProfile(BaseModel):
    model_config = ConfigDict(extra="forbid", strict=True)

    label: str = Field(min_length=1, max_length=120)
    peer: str
    port: int = Field(ge=1, le=65535)

    @field_validator("peer")
    @classmethod
    def peer_is_canonical_unicast(cls, value: str) -> str:
        address = ipaddress.ip_address(value)
        if (value != str(address) or address.is_multicast or address.is_unspecified
                or value == "255.255.255.255" or "%" in value
                or isinstance(address, ipaddress.IPv6Address) and (address.ipv4_mapped or address.is_link_local)):
            raise ValueError("peer must be an unscoped unicast address")
        return value


class ThroughputProfile(ProbeProfile):
    duration_seconds: int = Field(ge=1, le=10)
    bitrate_mbps: int = Field(ge=1, le=50)
    source_address: str | None = None
    bind_interface: str | None = None
    router_source: str | None = Field(default=None, pattern=r"^[A-Za-z0-9][A-Za-z0-9._-]{0,127}$")
    expected_wan_interface: str | None = Field(default=None, pattern=r"^[A-Za-z0-9_][A-Za-z0-9_.:@-]{0,31}$")

    @model_validator(mode="after")
    def validate_binding(self):
        if self.source_address is not None or self.bind_interface is not None:
            validate_throughput_profile(
                self.peer, self.port, duration_seconds=self.duration_seconds,
                bitrate_mbps=self.bitrate_mbps, source_address=self.source_address,
                bind_interface=self.bind_interface,
            )
        if self.expected_wan_interface and not self.router_source:
            raise ValueError("expected WAN interface requires RouterOS observation")
        if self.router_source and (not self.source_address or ipaddress.ip_address(self.source_address).version != 4):
            raise ValueError("RouterOS observation requires a bound IPv4 source")
        return self

    def config_digest(self) -> str:
        return hashlib.sha256(self.model_dump_json(exclude_none=True).encode()).hexdigest()


class WanGatewayCheck(BaseModel):
    model_config = ConfigDict(extra="forbid", strict=True)

    profile: ProfileId
    probe: ProfileId


class HttpsSpeedProfile(ProbeProfile):
    port: Literal[443] = 443
    download_bytes: int = Field(ge=MIN_BYTES, le=MAX_DOWNLOAD_BYTES)
    upload_bytes: int = Field(ge=MIN_BYTES, le=MAX_UPLOAD_BYTES)
    router_source: str | None = Field(default=None, pattern=r"^[A-Za-z0-9][A-Za-z0-9._-]{0,127}$")
    source_address: str | None = None
    expected_wan_interface: str | None = Field(default=None, pattern=r"^[A-Za-z0-9_][A-Za-z0-9_.:@-]{0,31}$")
    gateway_check: WanGatewayCheck | None = None

    @field_validator("peer")
    @classmethod
    def peer_is_public_ipv4(cls, value: str) -> str:
        return validate_speed_peer(value)

    @model_validator(mode="after")
    def validate_router_observation(self):
        if bool(self.router_source) != (self.source_address is not None):
            raise ValueError("router_source and source_address are required together")
        if self.expected_wan_interface and not self.router_source:
            raise ValueError("expected WAN interface requires RouterOS observation")
        if self.gateway_check and not self.expected_wan_interface:
            raise ValueError("gateway check requires an expected WAN interface")
        if self.source_address is not None:
            address = ipaddress.IPv4Address(self.source_address)
            if address.is_unspecified or address.is_multicast:
                raise ValueError("source address must be unicast IPv4")
        return self

    def config_digest(self) -> str:
        exclude = {field for field in ("expected_wan_interface", "gateway_check") if getattr(self, field) is None}
        return hashlib.sha256(self.model_dump_json(exclude=exclude).encode()).hexdigest()


class CaptureProfile(ProbeProfile):
    interface: str = Field(pattern=r"^[A-Za-z][A-Za-z0-9_.-]{0,14}$")
    protocol: Literal["tcp", "udp"]
    duration_seconds: int = Field(ge=1, le=30)
    max_packets: int = Field(ge=1, le=10000)
    max_kib: int = Field(ge=1, le=2048)

    @field_validator("interface")
    @classmethod
    def interface_is_named(cls, value: str) -> str:
        if value == "any":
            raise ValueError("a single interface is required")
        return value


class RouteProbe(BaseModel):
    model_config = ConfigDict(extra="forbid", strict=True)

    id: ProfileId
    expected_path: str = Field(min_length=1, max_length=120)
    target: str
    protocol: Literal["icmp", "tcp", "tls", "http", "https", "dns"]
    router_source: str | None = Field(default=None, pattern=r"^[A-Za-z0-9][A-Za-z0-9._-]{0,127}$")
    agent_origin: ProfileId | None = None
    source_address: str | None = None
    interface: str | None = Field(default=None, pattern=r"^[A-Za-z0-9_][A-Za-z0-9_.-]{0,31}$")
    routing_table: str | None = Field(default=None, pattern=r"^[A-Za-z0-9_][A-Za-z0-9_.-]{0,31}$")
    expected_first_hop: str | None = None
    trace_hops: int | None = Field(default=None, ge=2, le=8)
    observe_neighbor: bool = False
    ipsec: bool = False
    mtu: int | None = Field(default=None, ge=68, le=9000)
    port: int | None = Field(default=None, ge=1, le=65535)
    server_name: str | None = Field(default=None, max_length=253, pattern=r"^[A-Za-z0-9][A-Za-z0-9.-]*$")
    tls_ca_file: str | None = Field(default=None, max_length=255, pattern=r"^/[A-Za-z0-9_.-]+(?:/[A-Za-z0-9_.-]+)*$")
    http_path: str | None = Field(default=None, max_length=160, pattern=r"^/(?:[A-Za-z0-9._-][A-Za-z0-9._/-]*)?$")
    expected_http_status: int | None = Field(default=None, ge=200, le=599)
    dns_name: str | None = Field(default=None, max_length=253, pattern=r"^[A-Za-z0-9_][A-Za-z0-9_.-]*$")
    dns_type: Literal["A", "AAAA", "CNAME", "SOA", "SRV", "TXT", "MX", "PTR"] | None = None
    dns_transport: Literal["udp", "tcp"] | None = None
    expected_dns_answers: list[Annotated[str, StringConstraints(min_length=1, max_length=255)]] = Field(
        default_factory=list, max_length=8,
    )
    openvpn_client: str | None = Field(default=None, pattern=r"^[A-Za-z0-9][A-Za-z0-9._-]{0,127}$")
    expected_kernel_interface: str | None = Field(default=None, pattern=r"^[A-Za-z0-9_][A-Za-z0-9_.:@-]{0,31}$")
    expected_kernel_gateway: str | None = None
    push_origin: ProfileId | None = None

    @field_validator("target", "source_address", "expected_first_hop", "expected_kernel_gateway")
    @classmethod
    def validate_ipv4(cls, value: str | None) -> str | None:
        if value is None:
            return None
        address = ipaddress.IPv4Address(value)
        if address.is_multicast or address.is_unspecified or int(address) == 0xFFFFFFFF:
            raise ValueError("route probes require IPv4 unicast")
        return value

    @model_validator(mode="after")
    def validate_parameters(self):
        if sum(origin is not None for origin in (self.router_source, self.agent_origin, self.push_origin)) > 1:
            raise ValueError("select one probe origin")
        if self.openvpn_client and (self.router_source or self.push_origin):
            raise ValueError("OpenVPN session guard requires a live host probe")
        if self.openvpn_client and self.agent_origin and not (self.source_address and self.expected_kernel_interface):
            raise ValueError("OpenVPN client probe requires its tunnel address and interface")
        if self.push_origin and not self.source_address:
            raise ValueError("pushed probe requires an explicit source address")
        if self.router_source and self.protocol != "icmp":
            raise ValueError("RouterOS route probes require ICMP")
        if self.router_source and (self.expected_kernel_interface or self.expected_kernel_gateway):
            raise ValueError("Expected kernel interface or gateway requires a host probe")
        if (self.interface or self.routing_table) and not self.router_source:
            raise ValueError("interface and table selectors require RouterOS")
        if self.expected_first_hop and (not self.router_source or self.expected_first_hop == self.target):
            raise ValueError("a distinct first hop requires a RouterOS probe")
        if self.trace_hops is not None and self.expected_first_hop is None:
            raise ValueError("router trace requires an expected first hop")
        if self.observe_neighbor and (not self.router_source or not self.interface or self.expected_first_hop):
            raise ValueError("gateway ARP requires a router, interface and direct gateway target")
        if self.ipsec and not (self.router_source and self.source_address):
            raise ValueError("IPsec evidence requires a router and explicit source address")
        if self.protocol == "icmp" and self.port is not None or self.mtu is not None and self.protocol != "icmp":
            raise ValueError("ICMP accepts MTU instead of a port")
        if self.protocol == "tcp" and self.port is None:
            raise ValueError("TCP requires a port")
        if self.server_name and self.protocol not in {"tls", "http", "https"}:
            raise ValueError("server name requires HTTP or TLS")
        if self.protocol == "https" and not self.server_name:
            raise ValueError("HTTPS requires a server name")
        if self.tls_ca_file and self.protocol not in {"tls", "https"}:
            raise ValueError("a CA file requires TLS")
        if (self.http_path is not None or self.expected_http_status is not None) and self.protocol not in {"http", "https"}:
            raise ValueError("HTTP parameters require HTTP or HTTPS")
        if self.protocol == "dns" and not self.dns_name:
            raise ValueError("DNS requires a query name")
        if (self.dns_name or self.dns_type or self.dns_transport or self.expected_dns_answers) and self.protocol != "dns":
            raise ValueError("DNS parameters require DNS")
        return self

    def local_arguments(self) -> dict:
        is_http = self.protocol in {"http", "https"}
        return {
            "target": self.target, "protocol": self.protocol, "source_address": self.source_address,
            "port": self.port or {"http": 80, "https": 443, "tls": 443, "dns": 53}.get(self.protocol),
            "server_name": self.server_name,
            "tls_ca_file": self.tls_ca_file,
            "http_path": (self.http_path or "/") if is_http else None,
            "expected_http_status": (self.expected_http_status or 200) if is_http else None,
            "dns_name": self.dns_name, "dns_type": (self.dns_type or "A") if self.protocol == "dns" else None,
            "expected_dns_answers": tuple(self.expected_dns_answers), "mtu": self.mtu,
            **({"dns_transport": self.dns_transport} if self.dns_transport is not None else {}),
            **({"expected_kernel_interface": self.expected_kernel_interface} if self.expected_kernel_interface else {}),
            **({"expected_kernel_gateway": self.expected_kernel_gateway} if self.expected_kernel_gateway else {}),
        }

    def config_digest(self) -> str:
        exclude = {
            field for field in (
                "openvpn_client", "dns_transport", "expected_kernel_interface", "expected_kernel_gateway", "push_origin",
            )
            if getattr(self, field) is None
        }
        return hashlib.sha256(self.model_dump_json(exclude=exclude).encode("utf-8")).hexdigest()


class RouteProfile(BaseModel):
    model_config = ConfigDict(extra="forbid", strict=True)

    label: str = Field(min_length=1, max_length=120)
    scheduled: bool = False
    probes: list[RouteProbe] = Field(min_length=1, max_length=8)

    @model_validator(mode="after")
    def unique_probe_ids(self):
        if len({probe.id for probe in self.probes}) != len(self.probes):
            raise ValueError("route profile has duplicate probe IDs")
        return self


class ProbeProfiles(BaseModel):
    model_config = ConfigDict(extra="forbid", strict=True)

    throughput: dict[ProfileId, ThroughputProfile] = Field(default_factory=dict, max_length=32)
    https_speed: dict[ProfileId, HttpsSpeedProfile] = Field(default_factory=dict, max_length=8)
    capture: dict[ProfileId, CaptureProfile] = Field(default_factory=dict, max_length=32)
    routes: dict[ProfileId, RouteProfile] = Field(default_factory=dict, max_length=16)

    @model_validator(mode="after")
    def validate_speed_gateways(self):
        for speed in self.https_speed.values():
            if check := speed.gateway_check:
                route = self.routes.get(check.profile)
                probe = next((probe for probe in route.probes if probe.id == check.probe), None) if route else None
                if (
                    probe is None or not probe.observe_neighbor or not probe.source_address
                    or probe.router_source != speed.router_source or probe.interface != speed.expected_wan_interface
                ):
                    raise ValueError("gateway check must reference a RouterOS gateway probe on the expected WAN")
        return self

    @model_validator(mode="after")
    def limit_scheduled_profiles(self):
        scheduled = [profile for profile in self.routes.values() if profile.scheduled]
        if len(scheduled) > 6:
            raise ValueError("at most six route profiles can be scheduled")
        if sum(any(probe.router_source or probe.agent_origin for probe in profile.probes) for profile in scheduled) > 4:
            raise ValueError("at most four scheduled route profiles can use RouterOS or SSH origins")
        return self


def _is_trusted_file(info: os.stat_result) -> bool:
    return stat.S_ISREG(info.st_mode) and (
        os.name == "nt" or (info.st_uid == 0 and info.st_mode & 0o022 == 0)
    )


def load_probe_profiles(*, routes_only: bool = False) -> ProbeProfiles:
    try:
        if PROFILE_PATH.is_symlink():
            raise ValueError("profile file must not be a symlink")
        with PROFILE_PATH.open("rb") as config:
            info = os.fstat(config.fileno())
            if not _is_trusted_file(info) or not 0 < info.st_size <= 32768:
                raise ValueError("profile file is not trusted")
            data = config.read(32769)
        if len(data) > 32768:
            raise ValueError("profile file exceeds byte budget")
        catalog = json.loads(data)
        if routes_only and isinstance(catalog, dict):
            catalog = {"routes": catalog.get("routes", {})}
        return ProbeProfiles.model_validate(catalog)
    except FileNotFoundError:
        return ProbeProfiles()
    except (OSError, ValueError, ValidationError):
        log.warning("Network probe profiles are unavailable")
        return ProbeProfiles()


def probe_catalog() -> dict:
    profiles = load_probe_profiles()
    return {
        "throughput": [{"id": key, **profile.model_dump(exclude_none=True)} for key, profile in profiles.throughput.items()],
        "https_speed": [{"id": key, **profile.model_dump(exclude_none=True)} for key, profile in profiles.https_speed.items()],
        "capture": [{"id": key, **profile.model_dump()} for key, profile in profiles.capture.items()],
        "routes": [
            {
                "id": key, **profile.model_dump(exclude={"probes"}),
                "probes": [
                    {
                        **probe.model_dump(exclude_none=True, exclude={"tls_ca_file"}),
                        "config_digest": probe.config_digest(),
                    }
                    for probe in profile.probes
                ],
            }
            for key, profile in profiles.routes.items()
        ],
    }
