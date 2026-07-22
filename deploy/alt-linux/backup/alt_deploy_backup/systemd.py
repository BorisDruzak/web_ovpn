from __future__ import annotations

import re
import subprocess
from collections.abc import Sequence
from dataclasses import dataclass

from .errors import BackupError
from .settings import BackupSettings


MANAGED_UNITS = (
    "alt-deploy-http.service",
    "alt-deploy-register.service",
    "alt-deploy-process.path",
    "alt-deploy-process.service",
)
MAINTENANCE_STOP_ORDER = (
    "alt-deploy-process.path",
    "alt-deploy-register.service",
    "alt-deploy-http.service",
)
HEALTH_SERVICE_START_ORDER = (
    "alt-deploy-http.service",
    "alt-deploy-register.service",
)
PROCESSOR_UNIT = "alt-deploy-process.service"
PROCESS_PATH_UNIT = "alt-deploy-process.path"

_ENABLED_STATES = frozenset(
    {
        "enabled",
        "enabled-runtime",
        "disabled",
        "static",
        "indirect",
        "generated",
        "transient",
        "alias",
        "not-found",
    }
)
_ACTIVE_STATES = frozenset(
    {
        "active",
        "inactive",
        "failed",
        "activating",
        "deactivating",
        "reloading",
        "maintenance",
    }
)
_LOAD_STATES = frozenset({"loaded", "not-found"})
_SAFE_SUBSTATE = re.compile(r"^[A-Za-z0-9_.@:-]{1,100}$")
_TRANSIENT_UNIT = re.compile(
    r"^alt-provision-[A-Za-z0-9_.@:-]+\.service$"
)


@dataclass(frozen=True)
class UnitState:
    name: str
    load_state: str
    enabled_state: str
    active_state: str
    sub_state: str
    failed: bool


def _preflight(message: str) -> BackupError:
    return BackupError(
        code="backup_preflight_failed",
        message=message,
        exit_code=4,
    )


def _service_stop_failed(message: str) -> BackupError:
    return BackupError(
        code="backup_service_stop_failed",
        message=message,
        exit_code=4,
    )


def _service_restore_failed(message: str) -> BackupError:
    return BackupError(
        code="service_state_restore_failed",
        message=message,
        exit_code=4,
    )


class SystemdManager:
    def __init__(self, settings: BackupSettings):
        self.settings = settings

    def _run(
        self,
        arguments: Sequence[str],
        *,
        accepted_codes: frozenset[int],
        error: BackupError,
    ) -> subprocess.CompletedProcess[str]:
        try:
            result = subprocess.run(
                [str(self.settings.systemctl_path), *arguments],
                check=False,
                text=True,
                capture_output=True,
            )
        except OSError as exc:
            raise error from exc
        if result.returncode not in accepted_codes:
            raise error
        if len(result.stdout) > 64 * 1024 or len(result.stderr) > 64 * 1024:
            raise error
        return result

    def _query_unit(self, unit: str) -> UnitState:
        if unit not in MANAGED_UNITS:
            raise _preflight("Managed systemd unit is invalid")
        show = self._run(
            (
                "show",
                unit,
                "--property=LoadState",
                "--property=ActiveState",
                "--property=SubState",
                "--value",
            ),
            accepted_codes=frozenset({0}),
            error=_preflight("Systemd unit state cannot be inspected"),
        )
        values = show.stdout.splitlines()
        if len(values) != 3:
            raise _preflight("Systemd unit state output is malformed")
        load_state, active_state, sub_state = values
        if (
            load_state not in _LOAD_STATES
            or active_state not in _ACTIVE_STATES
            or not _SAFE_SUBSTATE.fullmatch(sub_state)
        ):
            raise _preflight("Systemd unit state values are malformed")

        enabled_result = self._run(
            ("is-enabled", unit),
            accepted_codes=frozenset({0, 1, 3, 4}),
            error=_preflight("Systemd enablement cannot be inspected"),
        )
        enabled_lines = enabled_result.stdout.splitlines()
        if len(enabled_lines) != 1 or enabled_lines[0] not in _ENABLED_STATES:
            raise _preflight("Systemd enablement output is malformed")
        enabled_state = enabled_lines[0]

        failed_result = self._run(
            ("is-failed", unit),
            accepted_codes=frozenset({0, 1, 3, 4}),
            error=_preflight("Systemd failure state cannot be inspected"),
        )
        failed_lines = failed_result.stdout.splitlines()
        if len(failed_lines) != 1:
            raise _preflight("Systemd failure output is malformed")
        failed_value = failed_lines[0]
        failed = failed_value == "failed"
        if failed != (active_state == "failed"):
            raise _preflight("Systemd failure state is inconsistent")

        if load_state == "not-found" and enabled_state != "not-found":
            raise _preflight("Missing systemd unit has invalid enablement")
        return UnitState(
            name=unit,
            load_state=load_state,
            enabled_state=enabled_state,
            active_state=active_state,
            sub_state=sub_state,
            failed=failed,
        )

    def capture(self) -> tuple[UnitState, ...]:
        return tuple(self._query_unit(unit) for unit in MANAGED_UNITS)

    def stop_maintenance(self) -> None:
        states = {state.name: state for state in self.capture()}
        for unit in MAINTENANCE_STOP_ORDER:
            if states[unit].load_state == "not-found":
                continue
            self._run(
                ("stop", unit),
                accepted_codes=frozenset({0}),
                error=_service_stop_failed(
                    "Maintenance systemd unit cannot be stopped"
                ),
            )
        after = {state.name: state for state in self.capture()}
        for unit in MAINTENANCE_STOP_ORDER:
            if after[unit].load_state == "not-found":
                continue
            if after[unit].active_state not in {"inactive", "failed"}:
                raise _service_stop_failed(
                    "Maintenance systemd unit remained active"
                )

    def _restore_enablement(self, state: UnitState) -> None:
        if state.load_state == "not-found":
            return
        if state.enabled_state == "enabled":
            arguments = ("enable", state.name)
        elif state.enabled_state == "enabled-runtime":
            arguments = ("enable", "--runtime", state.name)
        elif state.enabled_state == "disabled":
            arguments = ("disable", state.name)
        elif state.enabled_state in {
            "static",
            "indirect",
            "generated",
            "transient",
            "alias",
        }:
            return
        else:
            raise _service_restore_failed(
                "Systemd enablement cannot be reconstructed"
            )
        self._run(
            arguments,
            accepted_codes=frozenset({0}),
            error=_service_restore_failed(
                "Systemd enablement restoration failed"
            ),
        )

    def restore(
        self,
        states: Sequence[UnitState],
        *,
        activate_health_services: bool,
    ) -> None:
        by_name = {state.name: state for state in states}
        if len(by_name) != len(states) or set(by_name) != set(MANAGED_UNITS):
            raise _service_restore_failed("Systemd state set is invalid")
        if by_name[PROCESSOR_UNIT].active_state == "active":
            raise _service_restore_failed(
                "Pending processor must not be started by restore"
            )

        for unit in MANAGED_UNITS:
            self._restore_enablement(by_name[unit])

        for unit in (*HEALTH_SERVICE_START_ORDER, PROCESS_PATH_UNIT, PROCESSOR_UNIT):
            state = by_name[unit]
            if state.load_state == "not-found":
                continue
            if state.active_state != "active" or not activate_health_services:
                self._run(
                    ("stop", unit),
                    accepted_codes=frozenset({0}),
                    error=_service_restore_failed(
                        "Systemd inactive state restoration failed"
                    ),
                )

        if activate_health_services:
            for unit in HEALTH_SERVICE_START_ORDER:
                state = by_name[unit]
                if state.load_state != "not-found" and state.active_state == "active":
                    self._run(
                        ("start", unit),
                        accepted_codes=frozenset({0}),
                        error=_service_restore_failed(
                            "Systemd service activation failed"
                        ),
                    )
            path_state = by_name[PROCESS_PATH_UNIT]
            if (
                path_state.load_state != "not-found"
                and path_state.active_state == "active"
            ):
                self._run(
                    ("start", PROCESS_PATH_UNIT),
                    accepted_codes=frozenset({0}),
                    error=_service_restore_failed(
                        "Systemd path activation failed"
                    ),
                )

        current = {state.name: state for state in self.capture()}
        for unit, expected in by_name.items():
            actual = current[unit]
            if (
                actual.load_state != expected.load_state
                or actual.enabled_state != expected.enabled_state
                or actual.failed != expected.failed
            ):
                raise _service_restore_failed(
                    "Systemd final metadata does not match"
                )
            if activate_health_services and actual.active_state != expected.active_state:
                raise _service_restore_failed(
                    "Systemd final active state does not match"
                )
            if (
                not activate_health_services
                and expected.active_state != "active"
                and actual.active_state != expected.active_state
            ):
                raise _service_restore_failed(
                    "Systemd final inactive state does not match"
                )

    def active_transient_units(self) -> tuple[str, ...]:
        result = self._run(
            (
                "list-units",
                "alt-provision-*.service",
                "--type=service",
                "--state=active",
                "--no-legend",
                "--plain",
            ),
            accepted_codes=frozenset({0}),
            error=_preflight(
                "Transient provision units cannot be inspected"
            ),
        )
        units: list[str] = []
        for line in result.stdout.splitlines():
            if not line.strip():
                continue
            unit = line.split(maxsplit=1)[0]
            if not _TRANSIENT_UNIT.fullmatch(unit):
                raise _preflight("Transient unit output is malformed")
            units.append(unit)
        if len(set(units)) != len(units):
            raise _preflight("Transient unit output contains duplicates")
        return tuple(sorted(units))
