from __future__ import annotations

from collections.abc import Mapping
from typing import Any


PC_OS_FAMILIES = frozenset({"Windows", "Linux"})
PC_CPU_VENDORS = frozenset({"Intel", "AMD"})
PC_RAM_TYPES = frozenset({"DDR3", "DDR4"})
PC_STORAGE_TYPES = frozenset({"SSD", "M.2"})


class PCDetailNormalizationError(ValueError):
    """A PC select value is not one of the supported mobile-card choices."""


def normalize_pc_details(fields: Mapping[str, Any], *, strict: bool) -> dict[str, Any]:
    """Return canonical PC values while preserving unknown legacy text when requested."""
    values = dict(fields)
    _normalize_split_cpu(values)
    _normalize_os(values, strict=strict)
    values["cpu_model"] = _normalize_choice(
        values.get("cpu_model"),
        aliases={"intrl": "Intel", "intel": "Intel", "amd": "AMD"},
        allowed=PC_CPU_VENDORS,
        strict=strict,
        field_label="процессора",
    )
    values["ram_type"] = _normalize_choice(
        values.get("ram_type"),
        aliases={"ddr3": "DDR3", "ddr4": "DDR4"},
        allowed=PC_RAM_TYPES,
        strict=strict,
        field_label="типа оперативной памяти",
    )
    values["storage_type"] = _normalize_choice(
        values.get("storage_type"),
        aliases={"ssd": "SSD", "m.2": "M.2", "m2": "M.2"},
        allowed=PC_STORAGE_TYPES,
        strict=strict,
        field_label="типа накопителя",
    )
    return values


def _normalize_split_cpu(values: dict[str, Any]) -> None:
    if _text(values.get("cpu_model")) == "11400" and (_text(values.get("cpu_generation")) or "").casefold() == "i5":
        values["cpu_model"] = "Intel"
        values["cpu_generation"] = "i5 11400"


def _normalize_os(values: dict[str, Any], *, strict: bool) -> None:
    raw_os = _text(values.get("os_name"))
    if raw_os is None:
        values["os_name"] = None
        return
    folded = raw_os.casefold()
    version = _text(values.get("os_version"))
    if folded in {"win7", "win10", "win11"}:
        values["os_name"] = "Windows"
        values["os_version"] = version or raw_os[-2:]
    elif folded.startswith("windows "):
        values["os_name"] = "Windows"
        values["os_version"] = version or raw_os[8:].strip()
    elif folded == "windows":
        values["os_name"] = "Windows"
        values["os_version"] = version
    elif folded == "linux":
        values["os_name"] = "Linux"
        values["os_version"] = version
    elif "linux" in folded:
        values["os_name"] = "Linux"
        values["os_version"] = version or raw_os
    elif strict:
        raise PCDetailNormalizationError("неверное значение операционной системы")


def _normalize_choice(
    value: Any,
    *,
    aliases: Mapping[str, str],
    allowed: frozenset[str],
    strict: bool,
    field_label: str,
) -> str | None:
    raw = _text(value)
    if raw is None:
        return None
    canonical = aliases.get(raw.casefold())
    if canonical is not None:
        return canonical
    if raw in allowed:
        return raw
    if strict:
        raise PCDetailNormalizationError(f"неверное значение {field_label}")
    return raw


def _text(value: Any) -> str | None:
    if not isinstance(value, str):
        return None
    stripped = value.strip()
    return stripped or None
