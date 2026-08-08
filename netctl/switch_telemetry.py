from __future__ import annotations

from .snmp.models import SwitchCounterSample


def _empty_metrics(
    state: str, elapsed_seconds: float | None
) -> dict[str, object]:
    return {
        "sample_interval_seconds": elapsed_seconds,
        "rx_bps": None,
        "tx_bps": None,
        "rx_utilization_pct": None,
        "tx_utilization_pct": None,
        "in_errors_delta": None,
        "out_errors_delta": None,
        "in_discards_delta": None,
        "out_discards_delta": None,
        "telemetry_state": state,
    }


def _delta(current: int | None, previous: int | None) -> int | None:
    if current is None or previous is None:
        return None
    return current - previous


def derive_port_telemetry(
    current: SwitchCounterSample,
    previous: SwitchCounterSample | None,
    *,
    elapsed_seconds: float | None,
    port_speed_bps: int | None,
) -> dict[str, object]:
    if (
        current.octet_counter_bits not in {32, 64}
        or current.in_octets is None
        or current.out_octets is None
    ):
        return _empty_metrics("unsupported", elapsed_seconds)
    if previous is None:
        return _empty_metrics("insufficient_history", None)
    if elapsed_seconds is None or elapsed_seconds <= 0:
        return _empty_metrics("invalid_sample", elapsed_seconds)
    if (
        previous.octet_counter_bits != current.octet_counter_bits
        or previous.in_octets is None
        or previous.out_octets is None
    ):
        return _empty_metrics("insufficient_history", elapsed_seconds)
    if (
        current.sys_uptime_ticks is not None
        and previous.sys_uptime_ticks is not None
        and current.sys_uptime_ticks < previous.sys_uptime_ticks
    ):
        return _empty_metrics("counter_reset", elapsed_seconds)

    octet_deltas: list[int] = []
    used_wrap = False
    for current_value, previous_value in (
        (current.in_octets, previous.in_octets),
        (current.out_octets, previous.out_octets),
    ):
        if current_value >= previous_value:
            octet_deltas.append(current_value - previous_value)
            continue
        if current.octet_counter_bits == 64:
            return _empty_metrics("counter_reset", elapsed_seconds)
        used_wrap = True
        octet_deltas.append((2**32 - previous_value) + current_value)

    rx_bps = octet_deltas[0] * 8 / elapsed_seconds
    tx_bps = octet_deltas[1] * 8 / elapsed_seconds
    valid_speed = type(port_speed_bps) is int and port_speed_bps > 0
    if used_wrap and not valid_speed:
        return _empty_metrics("invalid_sample", elapsed_seconds)
    if valid_speed and (rx_bps > port_speed_bps or tx_bps > port_speed_bps):
        return _empty_metrics("invalid_sample", elapsed_seconds)

    counter_deltas = (
        _delta(current.in_errors, previous.in_errors),
        _delta(current.out_errors, previous.out_errors),
        _delta(current.in_discards, previous.in_discards),
        _delta(current.out_discards, previous.out_discards),
    )
    if any(value is not None and value < 0 for value in counter_deltas):
        return _empty_metrics("counter_reset", elapsed_seconds)
    return {
        "sample_interval_seconds": elapsed_seconds,
        "rx_bps": rx_bps,
        "tx_bps": tx_bps,
        "rx_utilization_pct": (
            round(rx_bps / port_speed_bps * 100, 6) if valid_speed else None
        ),
        "tx_utilization_pct": (
            round(tx_bps / port_speed_bps * 100, 6) if valid_speed else None
        ),
        "in_errors_delta": counter_deltas[0],
        "out_errors_delta": counter_deltas[1],
        "in_discards_delta": counter_deltas[2],
        "out_discards_delta": counter_deltas[3],
        "telemetry_state": "ok",
    }
