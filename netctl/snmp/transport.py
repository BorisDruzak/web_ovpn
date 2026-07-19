from __future__ import annotations

import asyncio
from collections.abc import AsyncIterator, Awaitable, Callable, Mapping
from concurrent.futures import ThreadPoolExecutor
from typing import Any, Protocol, TypeVar

from pysnmp.hlapi.v3arch.asyncio import (
    CommunityData,
    ContextData,
    ObjectIdentity,
    ObjectType,
    SnmpEngine,
    UdpTransportTarget,
    bulk_walk_cmd,
    get_cmd,
)
from pysnmp.proto import errind, rfc1902, rfc1905

from netctl.config import load_secrets, snmp_community_env_name

from .models import CapabilityResult, SnmpVarBind
from .oids import NumericOid, oid_text, require_numeric_oid
from .outcomes import SnmpOutcome


T = TypeVar("T")
RawResponse = tuple[object, object, object, tuple[object, ...]]


class SnmpBackend(Protocol):
    async def get(self, oid: NumericOid) -> RawResponse: ...

    def walk(self, oid: NumericOid) -> AsyncIterator[RawResponse]: ...

    async def close(self) -> None: ...


BackendFactory = Callable[..., SnmpBackend]


def collect_on_worker_loop(factory: Callable[[], Awaitable[T]]) -> T:
    with ThreadPoolExecutor(max_workers=1, thread_name_prefix="netctl-snmp") as executor:
        return executor.submit(lambda: asyncio.run(factory())).result()


class _PySnmpBackend:
    def __init__(
        self,
        *,
        host: str,
        port: int,
        community: str,
        timeout_seconds: int,
        retries: int,
        max_repetitions: int,
    ) -> None:
        self._host = host
        self._port = port
        self._timeout_seconds = timeout_seconds
        self._retries = retries
        self._max_repetitions = max_repetitions
        self._engine = SnmpEngine()
        self._auth = CommunityData(community, mpModel=1)
        self._context = ContextData()
        self._target: object | None = None

    def __repr__(self) -> str:
        return (
            f"_PySnmpBackend(host={self._host!r}, port={self._port!r}, "
            "community=<redacted>)"
        )

    async def _transport_target(self) -> object:
        if self._target is None:
            self._target = await UdpTransportTarget.create(
                (self._host, self._port),
                timeout=self._timeout_seconds,
                retries=self._retries,
            )
        return self._target

    async def get(self, oid: NumericOid) -> RawResponse:
        target = await self._transport_target()
        return await get_cmd(
            self._engine,
            self._auth,
            target,
            self._context,
            ObjectType(ObjectIdentity(oid)),
            lookupMib=False,
        )

    async def walk(self, oid: NumericOid) -> AsyncIterator[RawResponse]:
        target = await self._transport_target()
        iterator = bulk_walk_cmd(
            self._engine,
            self._auth,
            target,
            self._context,
            0,
            self._max_repetitions,
            ObjectType(ObjectIdentity(oid)),
            lookupMib=False,
            lexicographicMode=False,
        )
        async for response in iterator:
            yield response

    async def close(self) -> None:
        self._engine.close_dispatcher()


def _bounded_int(
    value: object, *, field: str, minimum: int, maximum: int
) -> int:
    if isinstance(value, bool) or not isinstance(value, int):
        raise ValueError(f"{field} is invalid")
    if value < minimum or value > maximum:
        raise ValueError(f"{field} is invalid")
    return value


def _status_code(error_status: object) -> int | str:
    if error_status is None:
        return 0
    if isinstance(error_status, str):
        return error_status
    try:
        return int(error_status)
    except (TypeError, ValueError, OverflowError):
        return "unknown"


def _failure_result(
    capability: str,
    outcome: SnmpOutcome,
    error_code: str,
    error_message: str,
) -> CapabilityResult:
    return CapabilityResult(
        capability=capability,
        outcome=outcome,
        error_code=error_code,
        error_message=error_message,
    )


def _classify_response_error(
    capability: str, error_indication: object, error_status: object
) -> CapabilityResult | None:
    if error_indication is not None:
        if isinstance(error_indication, errind.RequestTimedOut):
            return _failure_result(
                capability,
                SnmpOutcome.TIMEOUT,
                "timeout",
                "SNMP request timed out",
            )
        return _failure_result(
            capability,
            SnmpOutcome.PARSE_ERROR,
            "transport_error",
            "SNMP transport failed",
        )

    status = _status_code(error_status)
    if status in (0, ""):
        return None
    if status in (16, "authorizationError"):
        return _failure_result(
            capability,
            SnmpOutcome.AUTH_OR_VIEW_FAILURE,
            "authorization_error",
            "SNMP request was not authorized",
        )
    if status in (6, "noAccess"):
        return _failure_result(
            capability,
            SnmpOutcome.AUTH_OR_VIEW_FAILURE,
            "no_access",
            "SNMP request was not authorized",
        )
    return _failure_result(
        capability,
        SnmpOutcome.PARSE_ERROR,
        "protocol_error",
        "SNMP agent returned a protocol error",
    )


_INTEGER_TYPES: tuple[type[Any], ...] = (
    rfc1902.Integer,
    rfc1902.Integer32,
    rfc1902.Counter32,
    rfc1902.Counter64,
    rfc1902.Gauge32,
    rfc1902.Unsigned32,
    rfc1902.TimeTicks,
)
_OCTET_TYPES: tuple[type[Any], ...] = (
    rfc1902.OctetString,
    rfc1902.Opaque,
    rfc1902.Bits,
)
_INTEGER_VALUE_TYPES = {
    "Counter32": "counter32",
    "Counter64": "counter64",
    "Gauge32": "gauge32",
    "Unsigned32": "unsigned32",
    "TimeTicks": "time_ticks",
}


def _convert_value(value: object) -> tuple[str, int | str | bytes]:
    if isinstance(value, rfc1902.ObjectIdentifier):
        return "object_identifier", ".".join(str(part) for part in tuple(value))
    if isinstance(value, rfc1902.IpAddress):
        return "ip_address", str(value)
    if isinstance(value, _OCTET_TYPES):
        return "octet_string", bytes(value.asOctets())
    if isinstance(value, _INTEGER_TYPES):
        value_type = _INTEGER_VALUE_TYPES.get(type(value).__name__, "integer")
        return value_type, int(value)
    if isinstance(value, bool):
        raise ValueError("unsupported SNMP value")
    if isinstance(value, int):
        return "integer", value
    if isinstance(value, bytes):
        return "octet_string", value
    if isinstance(value, str):
        return "string", value
    raise ValueError("unsupported SNMP value")


def _convert_var_bind(var_bind: object) -> SnmpVarBind:
    try:
        oid_value = var_bind[0]  # type: ignore[index]
        value = var_bind[1]  # type: ignore[index]
        oid = require_numeric_oid(tuple(int(part) for part in oid_value))
        value_type, converted = _convert_value(value)
    except Exception:
        raise ValueError("malformed SNMP varbind") from None
    return SnmpVarBind(oid=oid, value_type=value_type, value=converted)


class SnmpTransport:
    def __init__(
        self,
        *,
        host: str,
        port: int = 161,
        community: str,
        snmp_version: str = "2c",
        timeout_seconds: int = 2,
        retries: int = 1,
        max_repetitions: int = 25,
        backend_factory: BackendFactory | None = None,
    ) -> None:
        if snmp_version != "2c":
            raise ValueError("SNMP version is unsupported")
        if not isinstance(host, str) or not host.strip():
            raise ValueError("SNMP host is invalid")
        port = _bounded_int(port, field="SNMP port", minimum=1, maximum=65535)
        timeout_seconds = _bounded_int(
            timeout_seconds, field="SNMP timeout", minimum=1, maximum=60
        )
        retries = _bounded_int(retries, field="SNMP retries", minimum=0, maximum=10)
        max_repetitions = _bounded_int(
            max_repetitions,
            field="SNMP max repetitions",
            minimum=1,
            maximum=100,
        )
        if not isinstance(community, str) or not community:
            raise ValueError("SNMP community secret is not configured")

        self._host = host
        self._port = port
        self._snmp_version = snmp_version
        self._timeout_seconds = timeout_seconds
        self._retries = retries
        self._max_repetitions = max_repetitions
        factory = backend_factory or _PySnmpBackend
        try:
            self._backend = factory(
                host=host,
                port=port,
                community=community,
                timeout_seconds=timeout_seconds,
                retries=retries,
                max_repetitions=max_repetitions,
            )
        except Exception:
            raise RuntimeError("SNMP transport could not be initialized") from None

    def __repr__(self) -> str:
        return (
            f"SnmpTransport(host={self._host!r}, port={self._port!r}, "
            f"snmp_version={self._snmp_version!r}, "
            f"timeout_seconds={self._timeout_seconds!r}, retries={self._retries!r}, "
            f"max_repetitions={self._max_repetitions!r}, community=<redacted>)"
        )

    @classmethod
    def from_source(
        cls,
        source: Mapping[str, object],
        *,
        secrets: Mapping[str, str] | None = None,
        backend_factory: BackendFactory | None = None,
    ) -> SnmpTransport:
        options_value = source.get("driver_options", {})
        if not isinstance(options_value, Mapping):
            raise ValueError("SNMP driver options are invalid")
        version = options_value.get("snmp_version", "2c")
        if version != "2c":
            raise ValueError("SNMP version is unsupported")

        secret_ref = source.get("secret_ref")
        if not isinstance(secret_ref, str) or not secret_ref:
            raise ValueError("SNMP community secret is not configured")
        secret_values = secrets if secrets is not None else load_secrets()
        community = secret_values.get(snmp_community_env_name(secret_ref))
        if not isinstance(community, str) or not community:
            raise ValueError("SNMP community secret is not configured")

        return cls(
            host=source.get("host"),  # type: ignore[arg-type]
            port=source.get("port", 161),  # type: ignore[arg-type]
            community=community,
            snmp_version=version,
            timeout_seconds=options_value.get("timeout_seconds", 2),  # type: ignore[arg-type]
            retries=options_value.get("retries", 1),  # type: ignore[arg-type]
            max_repetitions=options_value.get("max_repetitions", 25),  # type: ignore[arg-type]
            backend_factory=backend_factory,
        )

    async def __aenter__(self) -> SnmpTransport:
        return self

    async def __aexit__(self, *exc_info: object) -> None:
        await self.close()

    async def close(self) -> None:
        try:
            await self._backend.close()
        except Exception:
            pass

    async def get(
        self, oid: tuple[int, ...], *, capability: str = ""
    ) -> CapabilityResult:
        numeric = require_numeric_oid(oid)
        name = capability or oid_text(numeric)
        try:
            response = await self._backend.get(numeric)
            return self._consume_responses(name, (response,))
        except Exception:
            return _failure_result(
                name,
                SnmpOutcome.PARSE_ERROR,
                "transport_error",
                "SNMP transport failed",
            )

    async def walk(
        self, oid: tuple[int, ...], *, capability: str = ""
    ) -> CapabilityResult:
        numeric = require_numeric_oid(oid)
        name = capability or oid_text(numeric)
        responses: list[RawResponse] = []
        try:
            async for response in self._backend.walk(numeric):
                responses.append(response)
                failure = _classify_response_error(name, response[0], response[1])
                if failure is not None:
                    return failure
        except Exception:
            return _failure_result(
                name,
                SnmpOutcome.PARSE_ERROR,
                "transport_error",
                "SNMP transport failed",
            )
        return self._consume_responses(name, responses)

    def walk_numeric(
        self, oid: tuple[int, ...], *, capability: str = ""
    ) -> CapabilityResult:
        numeric = require_numeric_oid(oid)

        async def collect() -> CapabilityResult:
            try:
                return await self.walk(numeric, capability=capability)
            finally:
                await self.close()

        return collect_on_worker_loop(collect)

    @staticmethod
    def _consume_responses(
        capability: str, responses: object
    ) -> CapabilityResult:
        rows: list[SnmpVarBind] = []
        try:
            for response in responses:  # type: ignore[union-attr]
                error_indication, error_status, _error_index, var_binds = response
                failure = _classify_response_error(
                    capability, error_indication, error_status
                )
                if failure is not None:
                    return failure
                for var_bind in var_binds:
                    value = var_bind[1]
                    if isinstance(value, rfc1905.EndOfMibView):
                        continue
                    if isinstance(value, rfc1905.NoSuchObject):
                        return _failure_result(
                            capability,
                            SnmpOutcome.UNSUPPORTED_NO_SUCH_OBJECT,
                            "no_such_object",
                            "SNMP object is unsupported",
                        )
                    if isinstance(value, rfc1905.NoSuchInstance):
                        return _failure_result(
                            capability,
                            SnmpOutcome.UNSUPPORTED_NO_SUCH_OBJECT,
                            "no_such_instance",
                            "SNMP object is unsupported",
                        )
                    rows.append(_convert_var_bind(var_bind))
        except Exception:
            return _failure_result(
                capability,
                SnmpOutcome.PARSE_ERROR,
                "malformed_value",
                "SNMP response value is malformed",
            )

        return CapabilityResult(
            capability=capability,
            outcome=(
                SnmpOutcome.SUCCESS_WITH_ROWS if rows else SnmpOutcome.SUCCESS_EMPTY
            ),
            rows=tuple(rows),
        )
