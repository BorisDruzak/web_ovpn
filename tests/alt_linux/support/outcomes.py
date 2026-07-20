from __future__ import annotations

from dataclasses import dataclass


@dataclass(frozen=True)
class OperationalOutcome:
    scenario_id: str
    boundary: str
    error_code: str | None
    command_exit_code: int
    job_state: str | None
    job_stage: str | None
    assignment_created: bool
    retryable: bool | None
    required_evidence: tuple[str, ...]


PROVEN_OPERATIONAL_OUTCOMES: tuple[OperationalOutcome, ...] = (
    OperationalOutcome(
        "provision-start-root-required",
        "authorization",
        "root_required",
        6,
        None,
        None,
        False,
        None,
        ("cli_error", "no_job_created", "no_assignment_created"),
    ),
    OperationalOutcome(
        "provision-start-launch-failed",
        "launcher",
        "job_launch_failed",
        6,
        "failed",
        "launching",
        False,
        None,
        (
            "cli_error",
            "finished_at",
            "stage_history_created_launching",
            "no_assignment_created",
        ),
    ),
    OperationalOutcome(
        "reconcile-worker-not-started-created",
        "reconciliation",
        "worker_not_started",
        0,
        "failed",
        "created",
        False,
        True,
        (
            "reconciliation_action_queued_recoverable",
            "finished_at",
            "stage_preserved",
            "no_assignment_created",
        ),
    ),
    OperationalOutcome(
        "reconcile-worker-lost-employee",
        "reconciliation",
        "worker_lost",
        0,
        "failed",
        "employee",
        False,
        None,
        (
            "reconciliation_action_worker_lost",
            "last_real_stage_preserved",
            "no_result_created",
            "no_assignment_created",
        ),
    ),
    OperationalOutcome(
        "reconcile-result-recovered",
        "result_recovery",
        None,
        0,
        "successful",
        "complete",
        True,
        None,
        (
            "reconciliation_action_result_recovered",
            "recording_complete_transition",
            "result_file_recorded",
            "server_assignment_matches_result",
        ),
    ),
)

_OUTCOMES_BY_ID = {
    item.scenario_id: item for item in PROVEN_OPERATIONAL_OUTCOMES
}


def get_outcome(scenario_id: str) -> OperationalOutcome:
    try:
        return _OUTCOMES_BY_ID[scenario_id]
    except KeyError as exc:
        raise KeyError(
            f"Unknown operational outcome: {scenario_id}"
        ) from exc
