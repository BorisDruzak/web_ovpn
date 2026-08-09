from __future__ import annotations

import xml.etree.ElementTree as ET

from .models import NmapFingerprint, NmapOSClass, NmapOSMatch, NmapPort


MAX_XML_BYTES = 2 * 1024 * 1024
MAX_FIELD_LENGTH = 512


class NmapParseError(ValueError):
    """Nmap returned output outside the normalized XML contract."""


def _text(value: object) -> str:
    return str(value or "").strip()[:MAX_FIELD_LENGTH]


def _bounded_int(value: object, lower: int, upper: int) -> int | None:
    try:
        parsed = int(str(value))
    except (TypeError, ValueError):
        return None
    return parsed if lower <= parsed <= upper else None


def _cpes(parent: ET.Element | None) -> tuple[str, ...]:
    if parent is None:
        return ()
    values: list[str] = []
    for node in parent.findall("cpe"):
        value = _text(node.text)
        if value and value not in values:
            values.append(value)
    return tuple(values)


def _port(node: ET.Element) -> NmapPort:
    port = _bounded_int(node.get("portid"), 1, 65535)
    if port is None:
        raise NmapParseError("invalid Nmap XML output")
    state_node = node.find("state")
    service = node.find("service")
    return NmapPort(
        protocol=_text(node.get("protocol")),
        port=port,
        state=_text(state_node.get("state") if state_node is not None else ""),
        service_name=_text(service.get("name") if service is not None else ""),
        product=_text(service.get("product") if service is not None else ""),
        version=_text(service.get("version") if service is not None else ""),
        extra_info=_text(service.get("extrainfo") if service is not None else ""),
        tunnel=_text(service.get("tunnel") if service is not None else ""),
        method=_text(service.get("method") if service is not None else ""),
        confidence=_bounded_int(
            service.get("conf") if service is not None else None, 0, 10
        ),
        cpes=_cpes(service),
    )


def _os_class(node: ET.Element) -> NmapOSClass:
    return NmapOSClass(
        type=_text(node.get("type")),
        vendor=_text(node.get("vendor")),
        osfamily=_text(node.get("osfamily")),
        osgen=_text(node.get("osgen")),
        accuracy=_bounded_int(node.get("accuracy"), 0, 100),
        cpes=_cpes(node),
    )


def _os_match(node: ET.Element) -> NmapOSMatch:
    return NmapOSMatch(
        name=_text(node.get("name")),
        accuracy=_bounded_int(node.get("accuracy"), 0, 100),
        classes=tuple(_os_class(item) for item in node.findall("osclass")),
    )


def parse_nmap_xml(value: bytes | str) -> NmapFingerprint:
    """Parse allowlisted fields from a one-host Nmap XML document."""
    encoded = value.encode("utf-8") if isinstance(value, str) else value
    if not isinstance(encoded, bytes) or len(encoded) > MAX_XML_BYTES:
        raise NmapParseError("invalid Nmap XML output")
    try:
        root = ET.fromstring(encoded)
    except (ET.ParseError, ValueError, TypeError):
        raise NmapParseError("invalid Nmap XML output") from None
    if root.tag != "nmaprun":
        raise NmapParseError("invalid Nmap XML output")
    hosts = root.findall("host")
    if len(hosts) > 1:
        raise NmapParseError("Nmap XML must contain at most one host")
    host = hosts[0] if hosts else None
    ports = (
        tuple(_port(node) for node in host.findall("./ports/port"))
        if host is not None
        else ()
    )
    os_matches = (
        tuple(_os_match(node) for node in host.findall("./os/osmatch"))
        if host is not None
        else ()
    )
    return NmapFingerprint(
        nmap_version=_text(root.get("version")),
        ports=ports,
        os_matches=os_matches,
    )
