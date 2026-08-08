from __future__ import annotations

from .models import CapabilityResult, SwitchCounterSample, SwitchPort
from .oids import (
    IF_HC_IN_OCTETS,
    IF_HC_OUT_OCTETS,
    IF_IN_DISCARDS,
    IF_IN_ERRORS,
    IF_IN_OCTETS,
    IF_OUT_DISCARDS,
    IF_OUT_ERRORS,
    IF_OUT_OCTETS,
)


_COUNTER32_MAX = 2**32 - 1
_COUNTER64_MAX = 2**64 - 1


def _column(
    result: CapabilityResult,
    base: tuple[int, ...],
    *,
    field: str,
    value_type: str,
    maximum: int,
) -> dict[int, int]:
    values: dict[int, int] = {}
    for row in result.rows:
        suffix = row.oid[len(base) :] if row.oid[: len(base)] == base else ()
        if len(suffix) != 1 or not 0 < suffix[0] <= 2_147_483_647:
            raise ValueError(f"{field} OID index is invalid")
        if (
            row.value_type != value_type
            or isinstance(row.value, bool)
            or not isinstance(row.value, int)
            or not 0 <= row.value <= maximum
        ):
            raise ValueError(f"{field} has invalid type")
        if suffix[0] in values and values[suffix[0]] != row.value:
            raise ValueError(f"conflicting {field}")
        values[suffix[0]] = row.value
    return values


def parse_counter_samples(
    in_octets: CapabilityResult,
    out_octets: CapabilityResult,
    in_errors: CapabilityResult,
    out_errors: CapabilityResult,
    in_discards: CapabilityResult,
    out_discards: CapabilityResult,
    *,
    ports: tuple[SwitchPort, ...],
    sys_uptime_ticks: int | None,
    octet_counter_bits: int,
    fallback_in_octets: CapabilityResult | None = None,
    fallback_out_octets: CapabilityResult | None = None,
) -> tuple[SwitchCounterSample, ...]:
    if octet_counter_bits not in {32, 64}:
        raise ValueError("octet counter width is invalid")
    octet_type = "counter64" if octet_counter_bits == 64 else "counter32"
    octet_maximum = _COUNTER64_MAX if octet_counter_bits == 64 else _COUNTER32_MAX
    in_octet_values = _column(
        in_octets,
        IF_HC_IN_OCTETS if octet_counter_bits == 64 else IF_IN_OCTETS,
        field="input octets",
        value_type=octet_type,
        maximum=octet_maximum,
    )
    out_octet_values = _column(
        out_octets,
        IF_HC_OUT_OCTETS if octet_counter_bits == 64 else IF_OUT_OCTETS,
        field="output octets",
        value_type=octet_type,
        maximum=octet_maximum,
    )
    if (fallback_in_octets is None) != (fallback_out_octets is None):
        raise ValueError("octet fallback pair is incomplete")
    fallback_in_octet_values: dict[int, int] = {}
    fallback_out_octet_values: dict[int, int] = {}
    if fallback_in_octets is not None and fallback_out_octets is not None:
        if octet_counter_bits != 64:
            raise ValueError("octet fallback requires 64-bit primary counters")
        fallback_in_octet_values = _column(
            fallback_in_octets,
            IF_IN_OCTETS,
            field="fallback input octets",
            value_type="counter32",
            maximum=_COUNTER32_MAX,
        )
        fallback_out_octet_values = _column(
            fallback_out_octets,
            IF_OUT_OCTETS,
            field="fallback output octets",
            value_type="counter32",
            maximum=_COUNTER32_MAX,
        )
    in_error_values = _column(
        in_errors,
        IF_IN_ERRORS,
        field="input errors",
        value_type="counter32",
        maximum=_COUNTER32_MAX,
    )
    out_error_values = _column(
        out_errors,
        IF_OUT_ERRORS,
        field="output errors",
        value_type="counter32",
        maximum=_COUNTER32_MAX,
    )
    in_discard_values = _column(
        in_discards,
        IF_IN_DISCARDS,
        field="input discards",
        value_type="counter32",
        maximum=_COUNTER32_MAX,
    )
    out_discard_values = _column(
        out_discards,
        IF_OUT_DISCARDS,
        field="output discards",
        value_type="counter32",
        maximum=_COUNTER32_MAX,
    )
    observed_ifindexes = (
        set(in_octet_values) & set(out_octet_values)
    ) | (
        set(fallback_in_octet_values) & set(fallback_out_octet_values)
    )
    port_by_ifindex = {
        port.if_index: port
        for port in ports
        if port.if_index is not None
    }
    samples: list[SwitchCounterSample] = []
    for if_index in sorted(observed_ifindexes & set(port_by_ifindex)):
        port = port_by_ifindex[if_index]
        sample_in_octets = in_octet_values.get(if_index)
        sample_out_octets = out_octet_values.get(if_index)
        sample_octet_counter_bits = octet_counter_bits
        if (
            octet_counter_bits == 64
            and (sample_in_octets is None or sample_out_octets is None)
            and if_index in fallback_in_octet_values
            and if_index in fallback_out_octet_values
        ):
            sample_in_octets = fallback_in_octet_values[if_index]
            sample_out_octets = fallback_out_octet_values[if_index]
            sample_octet_counter_bits = 32
        samples.append(
            SwitchCounterSample(
                port_key=port.port_key,
                if_index=if_index,
                sys_uptime_ticks=sys_uptime_ticks,
                in_errors=in_error_values.get(if_index),
                in_discards=in_discard_values.get(if_index),
                out_errors=out_error_values.get(if_index),
                out_discards=out_discard_values.get(if_index),
                in_octets=sample_in_octets,
                out_octets=sample_out_octets,
                octet_counter_bits=sample_octet_counter_bits,
            )
        )
    return tuple(samples)
