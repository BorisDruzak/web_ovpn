"""Profile-hint contract shared by switch configuration and runtime code."""

from __future__ import annotations


SUPPORTED_SNMP_PROFILE_HINTS = frozenset(
    {"generic", "dgs", "snr", "tplink", "css326"}
)
