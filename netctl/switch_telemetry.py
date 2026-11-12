from __future__ import annotations

import sqlite3

from .snmp.models import SwitchCounterSample


def broadcast_counters_unreliable(profile_id: str | None, sys_descr: str | None) -> bool:
    # This firmware reported zero in both directions while its LLDP peer counted broadcasts.
    return profile_id == "dgs" and sys_descr == "WS6-DGS-1210-52/F1 6.20.007"


def _broadcast_delta(current: str | None, previous: str | None) -> int | None:
    if current is None or previous is None:
        return None
    try:
        after, before = int(current), int(previous)
    except ValueError:
        return None
    if not (0 <= after < 2**64 and 0 <= before < 2**64):
        return None
    return after - before


def derive_broadcast_rates(current: sqlite3.Row, previous: sqlite3.Row, elapsed: float) -> dict:
    if (
        not 0 < elapsed <= 900
        or "counter_discontinuity_ticks" not in current.keys()
        or current["if_index"] is None or current["if_index"] != previous["if_index"]
        or current["sys_uptime_ticks"] is None or previous["sys_uptime_ticks"] is None
        or current["sys_uptime_ticks"] <= previous["sys_uptime_ticks"]
        or current["counter_discontinuity_ticks"] is None
        or current["counter_discontinuity_ticks"] != previous["counter_discontinuity_ticks"]
    ):
        return {}
    in_delta, out_delta = (
        _broadcast_delta(current[key], previous[key])
        for key in ("in_broadcast_packets", "out_broadcast_packets")
    )
    deltas = [delta for delta in (in_delta, out_delta) if delta is not None]
    if not deltas or min(deltas) < 0:
        return {}
    return {
        "in_pps": in_delta / elapsed if in_delta is not None else None,
        "out_pps": out_delta / elapsed if out_delta is not None else None,
    }


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


def counter_sample_from_row(row: sqlite3.Row) -> SwitchCounterSample:
    return SwitchCounterSample(
        port_key=str(row["port_key"]),
        if_index=int(row["if_index"]) if row["if_index"] is not None else None,
        sys_uptime_ticks=(
            int(row["sys_uptime_ticks"])
            if row["sys_uptime_ticks"] is not None
            else None
        ),
        in_errors=int(row["in_errors"]) if row["in_errors"] is not None else None,
        in_discards=(
            int(row["in_discards"]) if row["in_discards"] is not None else None
        ),
        out_errors=(
            int(row["out_errors"]) if row["out_errors"] is not None else None
        ),
        out_discards=(
            int(row["out_discards"]) if row["out_discards"] is not None else None
        ),
        in_octets=int(row["in_octets"]) if row["in_octets"] is not None else None,
        out_octets=(
            int(row["out_octets"]) if row["out_octets"] is not None else None
        ),
        octet_counter_bits=(
            int(row["octet_counter_bits"])
            if row["octet_counter_bits"] is not None
            else None
        ),
    )
