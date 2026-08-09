from __future__ import annotations

from dataclasses import dataclass


@dataclass(frozen=True, slots=True)
class FingerprintProfile:
    name: str
    ttl_seconds: int
    stale_running_seconds: int


@dataclass(frozen=True, slots=True)
class FingerprintTarget:
    asset_id: int
    asset_key: str
    ip: str


@dataclass(frozen=True, slots=True)
class NmapPort:
    protocol: str
    port: int
    state: str
    service_name: str
    product: str
    version: str
    extra_info: str
    tunnel: str
    method: str
    confidence: int | None
    cpes: tuple[str, ...]


@dataclass(frozen=True, slots=True)
class NmapOSClass:
    type: str
    vendor: str
    osfamily: str
    osgen: str
    accuracy: int | None
    cpes: tuple[str, ...]


@dataclass(frozen=True, slots=True)
class NmapOSMatch:
    name: str
    accuracy: int | None
    classes: tuple[NmapOSClass, ...]


@dataclass(frozen=True, slots=True)
class NmapFingerprint:
    nmap_version: str
    ports: tuple[NmapPort, ...]
    os_matches: tuple[NmapOSMatch, ...]
