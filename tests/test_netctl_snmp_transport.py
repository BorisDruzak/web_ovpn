from __future__ import annotations

import asyncio
from collections.abc import AsyncIterator
from dataclasses import asdict
from typing import Any

import pytest
from pysnmp.proto import errind, rfc1902, rfc1905


SECRET = "docs-only-community-marker"
BASE_OID = (1, 3, 6, 1, 2, 1, 1)


class FakeBackend:
    def __init__(
        self,
        responses: list[tuple[object, object, object, tuple[tuple[object, object], ...]]]
        | None = None,
        *,
        failure: Exception | None = None,
    ) -> None:
        self.responses = responses or []
        self.failure = failure
        self.closed = False
        self.requested_oids: list[tuple[int, ...]] = []

    async def get(
        self, oid: tuple[int, ...]
    ) -> tuple[object, object, object, tuple[tuple[object, object], ...]]:
        self.requested_oids.append(oid)
        if self.failure is not None:
            raise self.failure
        if not self.responses:
            return (None, 0, 0, ())
        return self.responses[0]

    async def walk(
        self, oid: tuple[int, ...]
    ) -> AsyncIterator[
        tuple[object, object, object, tuple[tuple[object, object], ...]]
    ]:
        self.requested_oids.append(oid)
        if self.failure is not None:
            raise self.failure
        for response in self.responses:
            yield response

    async def close(self) -> None:
        self.closed = True


def _transport(backend: FakeBackend, **overrides: object):
    from netctl.snmp.transport import SnmpTransport

    options: dict[str, Any] = {
        "host": "192.0.2.44",
        "port": 161,
        "community": SECRET,
        "timeout_seconds": 2,
        "retries": 1,
        "max_repetitions": 25,
        "backend_factory": lambda **_: backend,
    }
    options.update(overrides)
    return SnmpTransport(**options)


def _response(
    *var_binds: tuple[object, object],
    error_indication: object = None,
    error_status: object = 0,
) -> tuple[object, object, object, tuple[tuple[object, object], ...]]:
    return error_indication, error_status, 0, tuple(var_binds)


def test_numeric_oid_conversion_and_validation() -> None:
    from netctl.snmp.oids import numeric_oid, oid_text

    assert numeric_oid("1.3.6.1.2.1") == (1, 3, 6, 1, 2, 1)
    assert numeric_oid((1, 3, 6, 1, 2, 1)) == (1, 3, 6, 1, 2, 1)
    assert oid_text((1, 3, 6, 1, 2, 1)) == "1.3.6.1.2.1"

    for invalid in ("", ".1.3", "1.3.sysName", (), (1, True, 3), (1, -1, 3)):
        with pytest.raises(ValueError, match="numeric OID"):
            numeric_oid(invalid)


def test_walk_requires_numeric_oid_tuple_before_backend_use() -> None:
    backend = FakeBackend()
    transport = _transport(backend)

    with pytest.raises(ValueError, match="numeric OID tuple"):
        transport.walk_numeric("1.3.6.1")  # type: ignore[arg-type]

    assert backend.requested_oids == []


def test_successful_rows_preserve_numeric_types_and_raw_octets() -> None:
    from netctl.snmp import SnmpOutcome

    backend = FakeBackend(
        [
            _response(
                (rfc1902.ObjectName(BASE_OID + (1,)), rfc1902.Integer32(7)),
                (rfc1902.ObjectName(BASE_OID + (2,)), rfc1902.Counter64(2**40)),
                (
                    rfc1902.ObjectName(BASE_OID + (3,)),
                    rfc1902.OctetString(b"switch-name"),
                ),
                (
                    rfc1902.ObjectName(BASE_OID + (4,)),
                    rfc1902.OctetString(b"\x00\x11\x22\x80\xff\x7f"),
                ),
                (
                    rfc1902.ObjectName(BASE_OID + (5,)),
                    rfc1902.ObjectIdentifier((1, 3, 6, 1, 4, 1, 171)),
                ),
            )
        ]
    )

    result = asyncio.run(_transport(backend).walk(BASE_OID))

    assert result.outcome is SnmpOutcome.SUCCESS_WITH_ROWS
    assert [(row.value_type, row.value) for row in result.rows] == [
        ("integer", 7),
        ("counter64", 2**40),
        ("octet_string", b"switch-name"),
        ("octet_string", b"\x00\x11\x22\x80\xff\x7f"),
        ("object_identifier", "1.3.6.1.4.1.171"),
    ]
    assert all(isinstance(row.oid, tuple) for row in result.rows)


@pytest.mark.parametrize(
    "responses",
    [[], [_response((rfc1902.ObjectName(BASE_OID), rfc1905.EndOfMibView()))]],
)
def test_confirmed_empty_walk_is_distinct_from_unsupported(
    responses: list[tuple[object, object, object, tuple[tuple[object, object], ...]]],
) -> None:
    from netctl.snmp import SnmpOutcome

    result = asyncio.run(_transport(FakeBackend(responses)).walk(BASE_OID))

    assert result.outcome is SnmpOutcome.SUCCESS_EMPTY
    assert result.rows == ()
    assert result.error_code == ""


@pytest.mark.parametrize(
    ("sentinel", "error_code"),
    [
        (rfc1905.NoSuchObject(), "no_such_object"),
        (rfc1905.NoSuchInstance(), "no_such_instance"),
    ],
)
def test_no_such_values_are_explicitly_unsupported(
    sentinel: object, error_code: str
) -> None:
    from netctl.snmp import SnmpOutcome

    result = asyncio.run(
        _transport(
            FakeBackend([_response((rfc1902.ObjectName(BASE_OID), sentinel))])
        ).walk(BASE_OID)
    )

    assert result.outcome is SnmpOutcome.UNSUPPORTED_NO_SUCH_OBJECT
    assert result.error_code == error_code
    assert result.rows == ()


def test_timeout_is_not_inferred_as_auth_failure() -> None:
    from netctl.snmp import SnmpOutcome

    result = asyncio.run(
        _transport(
            FakeBackend([_response(error_indication=errind.requestTimedOut)])
        ).walk(BASE_OID)
    )

    assert result.outcome is SnmpOutcome.TIMEOUT
    assert result.error_code == "timeout"
    assert result.outcome is not SnmpOutcome.AUTH_OR_VIEW_FAILURE


def test_walk_stops_consuming_backend_after_first_timeout() -> None:
    from netctl.snmp import SnmpOutcome

    class TimeoutThenExplodeBackend(FakeBackend):
        async def walk(
            self, oid: tuple[int, ...]
        ) -> AsyncIterator[
            tuple[object, object, object, tuple[tuple[object, object], ...]]
        ]:
            self.requested_oids.append(oid)
            yield _response(error_indication=errind.requestTimedOut)
            raise RuntimeError(SECRET)

    result = asyncio.run(_transport(TimeoutThenExplodeBackend()).walk(BASE_OID))

    assert result.outcome is SnmpOutcome.TIMEOUT
    assert result.error_code == "timeout"


@pytest.mark.parametrize("error_status", ["authorizationError", "noAccess"])
def test_only_explicit_authorization_errors_are_classified_as_auth_failure(
    error_status: str,
) -> None:
    from netctl.snmp import SnmpOutcome

    result = asyncio.run(
        _transport(FakeBackend([_response(error_status=error_status)])).walk(BASE_OID)
    )

    assert result.outcome is SnmpOutcome.AUTH_OR_VIEW_FAILURE
    assert result.error_code == (
        "authorization_error" if error_status == "authorizationError" else "no_access"
    )


def test_malformed_values_have_a_sanitized_parse_error() -> None:
    from netctl.snmp import SnmpOutcome

    result = asyncio.run(
        _transport(
            FakeBackend(
                [_response((rfc1902.ObjectName(BASE_OID + (1,)), object()))]
            )
        ).walk(BASE_OID)
    )

    assert result.outcome is SnmpOutcome.PARSE_ERROR
    assert result.error_code == "malformed_value"
    assert result.rows == ()


@pytest.mark.parametrize(
    "failure",
    [
        RuntimeError(SECRET),
        ValueError(f"bad response carrying {SECRET}"),
        OSError(f"socket detail carrying {SECRET}"),
    ],
)
def test_backend_exceptions_never_leak_community(failure: Exception) -> None:
    from netctl.snmp import SnmpOutcome

    transport = _transport(FakeBackend(failure=failure))
    result = asyncio.run(transport.walk(BASE_OID))

    assert result.outcome is SnmpOutcome.PARSE_ERROR
    assert result.error_code == "transport_error"
    assert SECRET not in repr(transport)
    assert SECRET not in repr(result)
    assert SECRET not in str(asdict(result))


def test_backend_factory_exception_is_sanitized() -> None:
    from netctl.snmp.transport import SnmpTransport

    def fail_factory(**_: object) -> FakeBackend:
        raise RuntimeError(SECRET)

    with pytest.raises(RuntimeError) as error:
        SnmpTransport(
            host="192.0.2.44",
            port=161,
            community=SECRET,
            backend_factory=fail_factory,
        )

    assert error.value.args == ("SNMP transport could not be initialized",)
    assert SECRET not in repr(error.value)


def test_unsupported_version_is_rejected_before_backend_factory() -> None:
    from netctl.snmp.transport import SnmpTransport

    calls = 0

    def backend_factory(**_: object) -> FakeBackend:
        nonlocal calls
        calls += 1
        raise AssertionError("must not open transport")

    with pytest.raises(ValueError) as error:
        SnmpTransport(
            host="192.0.2.44",
            port=161,
            community=SECRET,
            snmp_version="3",
            backend_factory=backend_factory,
        )

    assert error.value.args == ("SNMP version is unsupported",)
    assert calls == 0


@pytest.mark.parametrize("failure", [None, RuntimeError(SECRET)])
def test_sync_walk_closes_backend_after_success_and_failure(
    failure: Exception | None,
) -> None:
    backend = FakeBackend(
        [_response((rfc1902.ObjectName(BASE_OID), rfc1902.Integer32(1)))],
        failure=failure,
    )

    result = _transport(backend).walk_numeric(BASE_OID)

    assert result.error_code == ("" if failure is None else "transport_error")
    assert backend.closed is True


def test_sync_walk_works_while_caller_thread_owns_an_event_loop() -> None:
    from netctl.snmp import SnmpOutcome

    backend = FakeBackend(
        [_response((rfc1902.ObjectName(BASE_OID), rfc1902.Integer32(1)))]
    )

    async def caller() -> object:
        return _transport(backend).walk_numeric(BASE_OID)

    result = asyncio.run(caller())

    assert result.outcome is SnmpOutcome.SUCCESS_WITH_ROWS
    assert backend.closed is True


def test_source_factory_uses_distinct_community_environment_name() -> None:
    from netctl.snmp.transport import SnmpTransport

    received: dict[str, object] = {}

    def backend_factory(**options: object) -> FakeBackend:
        received.update(options)
        return FakeBackend()

    transport = SnmpTransport.from_source(
        {
            "host": "192.0.2.44",
            "port": 161,
            "secret_ref": "switch-docs",
            "driver_options": {
                "snmp_version": "2c",
                "timeout_seconds": 2,
                "retries": 1,
                "max_repetitions": 25,
            },
        },
        secrets={"NETCTL_SECRET_SWITCH_DOCS_COMMUNITY": SECRET},
        backend_factory=backend_factory,
    )

    assert received["community"] == SECRET
    assert SECRET not in repr(transport)


def test_missing_community_has_fixed_secret_safe_error() -> None:
    from netctl.snmp.transport import SnmpTransport

    with pytest.raises(ValueError) as error:
        SnmpTransport.from_source(
            {
                "host": "192.0.2.44",
                "port": 161,
                "secret_ref": "switch-docs",
                "driver_options": {"snmp_version": "2c"},
            },
            secrets={},
        )

    assert error.value.args == ("SNMP community secret is not configured",)


def test_public_models_are_frozen_and_use_tuple_rows() -> None:
    from netctl.snmp import CapabilityResult, SnmpOutcome, SnmpTransport, SnmpVarBind

    row = SnmpVarBind(oid=BASE_OID, value_type="integer", value=1)
    result = CapabilityResult(
        capability="1.3.6.1.2.1.1",
        outcome=SnmpOutcome.SUCCESS_WITH_ROWS,
        rows=(row,),
    )

    assert result.rows == (row,)
    with pytest.raises(AttributeError):
        result.outcome = SnmpOutcome.TIMEOUT  # type: ignore[misc]
    assert SnmpTransport.__name__ == "SnmpTransport"


def test_get_returns_one_typed_result_without_closing_shared_backend() -> None:
    from netctl.snmp import SnmpOutcome

    backend = FakeBackend(
        [_response((rfc1902.ObjectName(BASE_OID), rfc1902.TimeTicks(123)))]
    )
    result = asyncio.run(_transport(backend).get(BASE_OID, capability="system_uptime"))

    assert result.capability == "system_uptime"
    assert result.outcome is SnmpOutcome.SUCCESS_WITH_ROWS
    assert result.rows[0].value_type == "time_ticks"
    assert result.rows[0].value == 123
    assert backend.closed is False


@pytest.mark.parametrize(
    "override",
    [
        {"timeout_seconds": 0},
        {"timeout_seconds": 61},
        {"retries": -1},
        {"retries": 11},
        {"max_repetitions": 0},
        {"max_repetitions": 101},
    ],
)
def test_bounds_are_rejected_before_backend_factory(override: dict[str, int]) -> None:
    from netctl.snmp.transport import SnmpTransport

    calls = 0

    def backend_factory(**_: object) -> FakeBackend:
        nonlocal calls
        calls += 1
        return FakeBackend()

    with pytest.raises(ValueError):
        SnmpTransport(
            host="192.0.2.44",
            community=SECRET,
            backend_factory=backend_factory,
            **override,
        )

    assert calls == 0
