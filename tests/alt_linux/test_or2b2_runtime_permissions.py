from __future__ import annotations

from support.outcomes import PROVEN_OPERATIONAL_OUTCOMES, get_outcome


OR2B2_SCENARIO_IDS = {
    "provision-stage-helper-missing",
    "provision-stage-helper-not-executable",
    "controller-permissions-unhealthy",
    "controller-permissions-repair-root-required",
    "controller-permissions-repair-blocked",
    "controller-permissions-repair-failed",
    "controller-permissions-repaired",
}


def test_or2b2_outcomes_are_registered() -> None:
    actual = {
        item.scenario_id for item in PROVEN_OPERATIONAL_OUTCOMES
    }
    assert OR2B2_SCENARIO_IDS <= actual


def test_catalog_contains_twenty_six_proven_outcomes() -> None:
    assert len(PROVEN_OPERATIONAL_OUTCOMES) == 26


def test_or2b2_outcome_contracts_are_exact() -> None:
    expected = {
        "provision-stage-helper-missing": (
            "worker_configuration",
            "provision_not_configured",
            1,
            "failed",
            "connecting",
            False,
            True,
        ),
        "provision-stage-helper-not-executable": (
            "worker_configuration",
            "provision_not_configured",
            1,
            "failed",
            "connecting",
            False,
            True,
        ),
        "controller-permissions-unhealthy": (
            "permission_audit",
            "controller_permissions_unhealthy",
            8,
            None,
            None,
            False,
            True,
        ),
        "controller-permissions-repair-root-required": (
            "permission_repair_authorization",
            "root_required",
            3,
            None,
            None,
            False,
            True,
        ),
        "controller-permissions-repair-blocked": (
            "permission_repair_safety",
            "controller_permissions_repair_blocked",
            9,
            None,
            None,
            False,
            True,
        ),
        "controller-permissions-repair-failed": (
            "permission_repair_execution",
            "controller_permissions_repair_failed",
            10,
            None,
            None,
            False,
            True,
        ),
        "controller-permissions-repaired": (
            "permission_repair",
            None,
            0,
            None,
            None,
            False,
            None,
        ),
    }

    for scenario_id, contract in expected.items():
        outcome = get_outcome(scenario_id)
        assert (
            outcome.boundary,
            outcome.error_code,
            outcome.command_exit_code,
            outcome.job_state,
            outcome.job_stage,
            outcome.assignment_created,
            outcome.retryable,
        ) == contract
        assert outcome.failure_kind is None
