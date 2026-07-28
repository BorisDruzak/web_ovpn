from __future__ import annotations

import ipaddress
import re
from typing import Any

import dns.reversename
import dns.resolver


MAX_PTR_HOSTNAME_LENGTH = 253
_HOSTNAME_LABEL = re.compile(r"[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\Z")


def normalize_ptr_hostname(value: Any) -> str | None:
    """Return a conservative canonical FQDN, or discard untrusted PTR text."""
    if not isinstance(value, str):
        return None
    hostname = value.strip().removesuffix(".").lower()
    if not hostname or len(hostname) > MAX_PTR_HOSTNAME_LENGTH:
        return None
    labels = hostname.split(".")
    if any(not _HOSTNAME_LABEL.fullmatch(label) for label in labels):
        return None
    return hostname


def resolve_ptr_hostname(
    ip: str, *, server: str, timeout_seconds: int
) -> str | None:
    """Perform one bounded, read-only PTR lookup without leaking DNS failures."""
    try:
        address = str(ipaddress.ip_address(ip))
        nameserver = str(ipaddress.ip_address(server))
        timeout = int(timeout_seconds)
        if not 1 <= timeout <= 10:
            return None
        resolver = dns.resolver.Resolver(configure=False)
        resolver.nameservers = [nameserver]
        resolver.timeout = timeout
        resolver.lifetime = timeout
        answer = resolver.resolve(
            dns.reversename.from_address(address),
            "PTR",
            search=False,
            raise_on_no_answer=False,
            lifetime=timeout,
        )
        if answer.rrset is None:
            return None
        for record in answer:
            hostname = normalize_ptr_hostname(str(record))
            if hostname is not None:
                return hostname
    except Exception:
        return None
    return None
