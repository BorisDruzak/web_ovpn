from __future__ import annotations

import os
from collections.abc import Callable, Mapping
from contextlib import nullcontext
from copy import deepcopy
from datetime import datetime, timezone

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
