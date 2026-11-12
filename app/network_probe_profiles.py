from __future__ import annotations

import ipaddress
import json
import logging
import os
import stat
from pathlib import Path
from typing import Annotated, Literal

from pydantic import BaseModel, ConfigDict, Field, StringConstraints, ValidationError, field_validator

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


class ProbeProfiles(BaseModel):
    model_config = ConfigDict(extra="forbid", strict=True)

    throughput: dict[ProfileId, ThroughputProfile] = Field(default_factory=dict, max_length=32)
    capture: dict[ProfileId, CaptureProfile] = Field(default_factory=dict, max_length=32)


def _is_trusted_file(info: os.stat_result) -> bool:
    return stat.S_ISREG(info.st_mode) and (
        os.name == "nt" or (info.st_uid == 0 and info.st_mode & 0o022 == 0)
    )


def load_probe_profiles() -> ProbeProfiles:
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
        return ProbeProfiles.model_validate(json.loads(data))
    except FileNotFoundError:
        return ProbeProfiles()
    except (OSError, ValueError, ValidationError):
        log.warning("Network probe profiles are unavailable")
        return ProbeProfiles()


def probe_catalog() -> dict:
    profiles = load_probe_profiles()
    return {
        "throughput": [{"id": key, **profile.model_dump()} for key, profile in profiles.throughput.items()],
        "capture": [{"id": key, **profile.model_dump()} for key, profile in profiles.capture.items()],
    }
