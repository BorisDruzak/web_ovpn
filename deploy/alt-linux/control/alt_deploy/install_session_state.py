from __future__ import annotations

import os
from collections.abc import Callable, Mapping
from contextlib import nullcontext
from copy import deepcopy
from datetime import datetime, timezone
import re

from .errors import ControlError
from .install_session_repository import InstallSessionRepository


INSTALL_SESSION_STAGES: tuple[str, ...] = (
    "session_created",
    "inventory_validated",
    "awaiting_approval",
    "plan_built",
    "plan_signed",
    "published",
)
_STAGE_INDEX = {
    stage: index for index, stage in enumerate(INSTALL_SESSION_STAGES)
}
_TERMINAL_STATES = frozenset({"cancelled", "expired"})
_SHA256_RE = re.compile(r"^[0-9a-f]{64}$")
_FINGERPRINT_RE = re.compile(r"^sha256:[0-9a-f]{64}$")
_DEVICE_RE = re.compile(r"^/dev/[A-Za-z0-9._+-]{1,63}$")
_IDENTIFIER_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._+-]{0,127}$")
EXECUTION_STATUS_KEYS = frozenset(
    {
        "schema_version",
        "revision",
        "state",
        "authorized_at",
        "expires_at",
        "plan_sha256",
        "inventory_sha256",
        "disk_fingerprint",
        "target_disk",
        "reason",
        "profile_id",
        "profile_version",
        "iso_id",
        "iso_sha256",
        "manifest_sha256",
        "claimed_at",
        "handoff_started_at",
        "installer_started_at",
        "installed_at",
        "failed_at",
        "failure_code",
        "cancelled_at",
        "cancel_reason",
        "expired_at",
    }
)
_EXECUTION_STATES = frozenset(
    {
        "authorized",
        "claimed",
        "handoff_started",
        "installer_started",
        "installed",
        "failed",
        "cancelled",
        "expired",
    }
)
_EXECUTION_TRANSITIONS = {
    "authorized": frozenset({"claimed", "cancelled", "expired"}),
    "claimed": frozenset({"handoff_started", "cancelled", "expired"}),
    "handoff_started": frozenset(
        {"installer_started", "cancelled", "expired"}
    ),
    "installer_started": frozenset({"installed", "failed"}),
    "installed": frozenset(),
    "failed": frozenset(),
    "cancelled": frozenset(),
    "expired": frozenset(),
}
_EXECUTION_BINDING_KEYS = frozenset(
    {
        "authorized_at",
        "expires_at",
        "plan_sha256",
        "inventory_sha256",
        "disk_fingerprint",
        "target_disk",
        "reason",
        "profile_id",
        "profile_version",
        "iso_id",
        "iso_sha256",
        "manifest_sha256",
    }
)
_EXECUTION_TIME_BY_STATE = {
    "authorized": "authorized_at",
    "claimed": "claimed_at",
    "handoff_started": "handoff_started_at",
    "installer_started": "installer_started_at",
    "installed": "installed_at",
    "failed": "failed_at",
    "cancelled": "cancelled_at",
    "expired": "expired_at",
}
_EXECUTION_TRANSITION_FIELDS = {
    ("authorized", "claimed"): frozenset({"state", "claimed_at"}),
    ("authorized", "cancelled"): frozenset(
        {"state", "cancelled_at", "cancel_reason"}
    ),
    ("authorized", "expired"): frozenset({"state", "expired_at"}),
    ("claimed", "handoff_started"): frozenset(
        {"state", "handoff_started_at"}
    ),
    ("claimed", "cancelled"): frozenset(
        {"state", "cancelled_at", "cancel_reason"}
    ),
    ("claimed", "expired"): frozenset({"state", "expired_at"}),
    ("handoff_started", "installer_started"): frozenset(
        {"state", "installer_started_at"}
    ),
    ("handoff_started", "cancelled"): frozenset(
        {"state", "cancelled_at", "cancel_reason"}
    ),
    ("handoff_started", "expired"): frozenset(
        {"state", "expired_at"}
    ),
    ("installer_started", "installed"): frozenset(
        {"state", "installed_at"}
    ),
    ("installer_started", "failed"): frozenset(
        {"state", "failed_at", "failure_code"}
    ),
}


def _execution_invalid(message: str) -> ControlError:
    return ControlError(
        code="install_execution_status_invalid",
        message=message,
        exit_code=4,
    )


def _execution_timestamp(value: object) -> datetime:
    if not isinstance(value, str):
        raise _execution_invalid("Install execution timestamp is invalid")
    try:
        parsed = datetime.fromisoformat(value)
    except ValueError as exc:
        raise _execution_invalid(
            "Install execution timestamp is invalid"
        ) from exc
    if parsed.tzinfo is None or parsed.utcoffset() is None:
        raise _execution_invalid(
            "Install execution timestamp is invalid"
        )
    return parsed.astimezone(timezone.utc)


def validate_execution_status(execution: Mapping[str, object]) -> None:
    if not isinstance(execution, Mapping) or set(execution) != EXECUTION_STATUS_KEYS:
        raise _execution_invalid("Install execution status fields are invalid")
    state = execution.get("state")
    if (
        type(execution.get("schema_version")) is not int
        or execution.get("schema_version") != 1
        or type(execution.get("revision")) is not int
        or execution.get("revision") != 1
        or state not in _EXECUTION_STATES
        or any(
            isinstance(value, str) and "$y$" in value
            for value in execution.values()
        )
    ):
        raise _execution_invalid("Install execution status is invalid")
    binding_present = all(
        execution.get(name) is not None for name in _EXECUTION_BINDING_KEYS
    )
    binding_absent = all(
        execution.get(name) is None for name in _EXECUTION_BINDING_KEYS
    )
    if state == "cancelled":
        if not (binding_present or binding_absent):
            raise _execution_invalid(
                "Install execution cancellation binding is invalid"
            )
    elif not binding_present:
        raise _execution_invalid("Install execution binding is invalid")
    if binding_present:
        if (
            not isinstance(execution["plan_sha256"], str)
            or not _SHA256_RE.fullmatch(execution["plan_sha256"])
            or not isinstance(execution["inventory_sha256"], str)
            or not _SHA256_RE.fullmatch(execution["inventory_sha256"])
            or not isinstance(execution["disk_fingerprint"], str)
            or not _FINGERPRINT_RE.fullmatch(
                execution["disk_fingerprint"]
            )
            or not isinstance(execution["target_disk"], str)
            or not _DEVICE_RE.fullmatch(execution["target_disk"])
            or not isinstance(execution["manifest_sha256"], str)
            or not _SHA256_RE.fullmatch(execution["manifest_sha256"])
            or not isinstance(execution["profile_id"], str)
            or not _IDENTIFIER_RE.fullmatch(execution["profile_id"])
            or type(execution["profile_version"]) is not int
            or execution["profile_version"] < 1
            or not isinstance(execution["iso_id"], str)
            or not _IDENTIFIER_RE.fullmatch(execution["iso_id"])
            or not isinstance(execution["iso_sha256"], str)
            or not _SHA256_RE.fullmatch(execution["iso_sha256"])
            or not isinstance(execution["reason"], str)
            or not 1 <= len(execution["reason"]) <= 256
        ):
            raise _execution_invalid("Install execution binding is invalid")
        authorized = _execution_timestamp(execution["authorized_at"])
        expires = _execution_timestamp(execution["expires_at"])
        if expires <= authorized:
            raise _execution_invalid("Install execution expiry is invalid")
    ordered_fields = (
        "claimed_at",
        "handoff_started_at",
        "installer_started_at",
        "installed_at",
        "failed_at",
        "cancelled_at",
        "expired_at",
    )
    parsed_times: dict[str, datetime] = {}
    for name in ordered_fields:
        value = execution.get(name)
        if value is not None:
            parsed_times[name] = _execution_timestamp(value)
            if binding_present and parsed_times[name] < authorized:
                raise _execution_invalid(
                    "Install execution timestamps move backwards"
                )
    required_time = _EXECUTION_TIME_BY_STATE[str(state)]
    if execution.get(required_time) is None:
        raise _execution_invalid("Install execution state timestamp is missing")
    reached = {
        "authorized": (),
        "claimed": ("claimed_at",),
        "handoff_started": ("claimed_at", "handoff_started_at"),
        "installer_started": (
            "claimed_at",
            "handoff_started_at",
            "installer_started_at",
        ),
        "installed": (
            "claimed_at",
            "handoff_started_at",
            "installer_started_at",
            "installed_at",
        ),
        "failed": (
            "claimed_at",
            "handoff_started_at",
            "installer_started_at",
            "failed_at",
        ),
        "cancelled": (
            "claimed_at",
            "handoff_started_at",
            "cancelled_at",
        ),
        "expired": (
            "claimed_at",
            "handoff_started_at",
            "expired_at",
        ),
    }[str(state)]
    allowed_times = set(reached)
    if any(
        execution.get(name) is not None
        for name in ordered_fields
        if name not in allowed_times
    ):
        raise _execution_invalid(
            "Install execution state timestamps are invalid"
        )
    if execution.get("handoff_started_at") is not None and execution.get(
        "claimed_at"
    ) is None:
        raise _execution_invalid(
            "Install execution state timestamps are invalid"
        )
    sequence = [
        parsed_times[name]
        for name in (
            "claimed_at",
            "handoff_started_at",
            "installer_started_at",
            "installed_at",
            "failed_at",
            "cancelled_at",
            "expired_at",
        )
        if name in parsed_times
    ]
    if any(later < earlier for earlier, later in zip(sequence, sequence[1:])):
        raise _execution_invalid(
            "Install execution timestamps move backwards"
        )
    if state == "failed":
        code = execution.get("failure_code")
        if (
            not isinstance(code, str)
            or not _IDENTIFIER_RE.fullmatch(code)
        ):
            raise _execution_invalid(
                "Install execution failure code is invalid"
            )
    elif execution.get("failure_code") is not None:
        raise _execution_invalid(
            "Install execution failure code is invalid"
        )
    if state == "cancelled":
        reason = execution.get("cancel_reason")
        if not isinstance(reason, str) or not 1 <= len(reason) <= 256:
            raise _execution_invalid(
                "Install execution cancellation reason is invalid"
            )
    elif execution.get("cancel_reason") is not None:
        raise _execution_invalid(
            "Install execution cancellation reason is invalid"
        )


def validate_execution_transition(
    before: object,
    after: object,
) -> None:
    if before is None:
        if not isinstance(after, Mapping):
            raise _execution_invalid("Install execution status is invalid")
        validate_execution_status(after)
        if after.get("state") not in {"authorized", "cancelled"}:
            raise _execution_invalid(
                "Install execution initial transition is invalid"
            )
        return
    if not isinstance(before, Mapping) or not isinstance(after, Mapping):
        raise _execution_invalid("Install execution status is invalid")
    validate_execution_status(before)
    validate_execution_status(after)
    if dict(before) == dict(after):
        return
    before_state = str(before["state"])
    after_state = str(after["state"])
    mutable = _EXECUTION_TRANSITION_FIELDS.get(
        (before_state, after_state), frozenset()
    )
    if (
        after_state not in _EXECUTION_TRANSITIONS[before_state]
        or any(
            before.get(name) != after.get(name)
            for name in EXECUTION_STATUS_KEYS
            if name not in mutable
        )
    ):
        raise _execution_invalid(
            "Install execution transition is invalid"
        )


class InstallSessionStageManager:
    def __init__(
        self,
        repository: InstallSessionRepository,
        *,
        clock: Callable[[], str],
    ) -> None:
        self.repository = repository
        self.clock = clock

    @staticmethod
    def _invalid(message: str) -> ControlError:
        return ControlError(
            code="install_session_stage_history_invalid",
            message=message,
            exit_code=4,
        )

    @staticmethod
    def _timestamp(value: object) -> str:
        if not isinstance(value, str):
            raise InstallSessionStageManager._invalid(
                "Install session stage timestamp is invalid"
            )
        try:
            parsed = datetime.fromisoformat(value)
        except ValueError as exc:
            raise InstallSessionStageManager._invalid(
                "Install session stage timestamp is invalid"
            ) from exc
        if parsed.tzinfo is None:
            raise InstallSessionStageManager._invalid(
                "Install session stage timestamp has no timezone"
            )
        return parsed.astimezone(timezone.utc).isoformat()

    def _validate(self, status: Mapping[str, object]) -> None:
        stage = status.get("stage")
        history = status.get("stage_history")
        if stage not in _STAGE_INDEX or not isinstance(history, list):
            raise self._invalid("Install session stage status is invalid")
        if not history or len(history) > len(INSTALL_SESSION_STAGES):
            raise self._invalid("Install session stage history is invalid")
        previous: datetime | None = None
        for index, item in enumerate(history):
            if not isinstance(item, dict) or set(item) != {
                "stage", "entered_at"
            }:
                raise self._invalid(
                    "Install session stage history item is invalid"
                )
            if item["stage"] != INSTALL_SESSION_STAGES[index]:
                raise self._invalid(
                    "Install session stage history is not contiguous"
                )
            timestamp = datetime.fromisoformat(
                self._timestamp(item["entered_at"])
            )
            if previous is not None and timestamp < previous:
                raise self._invalid(
                    "Install session stage timestamps move backwards"
                )
            previous = timestamp
        if stage != history[-1]["stage"]:
            raise self._invalid(
                "Install session stage does not match history"
            )
        state = status.get("state")
        if state == "awaiting_approval" and stage != "awaiting_approval":
            raise self._invalid(
                "Awaiting approval state has an invalid stage"
            )
        if state == "plan_published" and stage != "published":
            raise self._invalid(
                "Published plan state has an invalid stage"
            )
        if state == "approval_in_progress" and stage not in {
            "plan_built", "plan_signed", "published"
        }:
            raise self._invalid(
                "Approval in progress state has an invalid stage"
            )
        if state not in {
            "awaiting_approval", "approval_in_progress", "plan_published",
            "cancelled", "expired",
        }:
            raise self._invalid("Install session state is invalid")
        if "execution" in status:
            execution = status["execution"]
            if not isinstance(execution, Mapping):
                raise self._invalid(
                    "Install execution status is invalid"
                )
            validate_execution_status(execution)

    def validate_status(self, status: Mapping[str, object]) -> None:
        self._validate(status)

    def advance_status(
        self,
        status: Mapping[str, object],
        next_stage: str,
    ) -> dict[str, object]:
        """Validate and advance an in-memory status by exactly one stage."""
        self._validate(status)
        if status.get("state") in _TERMINAL_STATES:
            raise ControlError(
                code="install_session_stage_terminal",
                message="Cancelled install session cannot change stage",
                exit_code=4,
            )
        current_stage = str(status["stage"])
        if next_stage not in _STAGE_INDEX:
            raise ControlError(
                code="invalid_install_session_stage_transition",
                message="Install session next stage is unknown",
                exit_code=4,
            )
        if next_stage == current_stage:
            return deepcopy(dict(status))
        if _STAGE_INDEX[next_stage] != _STAGE_INDEX[current_stage] + 1:
            raise ControlError(
                code="invalid_install_session_stage_transition",
                message="Install session stage is not the immediate next step",
                exit_code=4,
            )
        entered_at = self._timestamp(self.clock())
        updated = deepcopy(dict(status))
        history = list(updated["stage_history"])
        history.append({"stage": next_stage, "entered_at": entered_at})
        updated["stage"] = next_stage
        if next_stage == "plan_built":
            updated["state"] = "approval_in_progress"
        updated["stage_history"] = history
        updated["updated_at"] = entered_at
        self._validate(updated)
        return updated

    def advance(
        self,
        session_id: str,
        next_stage: str,
    ) -> dict[str, object]:
        lock = (
            nullcontext()
            if os.name == "nt"
            else __import__("alt_deploy.locks", fromlist=["exclusive_lock"])
            .exclusive_lock(self.repository.settings.install_sessions_lock)
        )
        with lock:
            status = self.repository.load_status(session_id)
            updated = self.advance_status(status, next_stage)
            if updated == status:
                return status
            self.repository.replace_status(
                session_id, updated, allow_lifecycle=True
            )
            return updated
