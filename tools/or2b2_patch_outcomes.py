from pathlib import Path

OUTCOMES = Path("tests/alt_linux/support/outcomes.py")
CONTRACT = Path("tests/alt_linux/test_operational_reliability_contract.py")

outcomes = OUTCOMES.read_text(encoding="utf-8")
marker = ")\n\n_OUTCOMES_BY_ID = {"
if outcomes.count(marker) != 1:
    raise SystemExit("expected outcomes tuple terminator exactly once")

records = r'''    OperationalOutcome(
        scenario_id="provision-stage-helper-missing",
        boundary="worker_configuration",
        error_code="provision_not_configured",
        command_exit_code=1,
        job_state="failed",
        job_stage="connecting",
        assignment_created=False,
        retryable=True,
        required_evidence=(
            "structured_configuration_detail",
            "worker_exit_one",
            "failed_job_finished_at",
            "connecting_stage_preserved",
            "ansible_subprocess_not_called",
            "no_result_created",
            "no_assignment_created",
            "new_job_retry_after_fix",
        ),
    ),
    OperationalOutcome(
        scenario_id="provision-stage-helper-not-executable",
        boundary="worker_configuration",
        error_code="provision_not_configured",
        command_exit_code=1,
        job_state="failed",
        job_stage="connecting",
        assignment_created=False,
        retryable=True,
        required_evidence=(
            "structured_configuration_detail",
            "worker_exit_one",
            "failed_job_finished_at",
            "connecting_stage_preserved",
            "ansible_subprocess_not_called",
            "no_result_created",
            "no_assignment_created",
            "new_job_retry_after_fix",
        ),
    ),
    OperationalOutcome(
        scenario_id="controller-permissions-unhealthy",
        boundary="permission_audit",
        error_code="controller_permissions_unhealthy",
        command_exit_code=8,
        job_state=None,
        job_stage=None,
        assignment_created=False,
        retryable=True,
        required_evidence=(
            "safe_path_matrix",
            "sentinel_job_unchanged",
            "sentinel_assignment_unchanged",
        ),
    ),
    OperationalOutcome(
        scenario_id="controller-permissions-repair-root-required",
        boundary="permission_repair_authorization",
        error_code="root_required",
        command_exit_code=3,
        job_state=None,
        job_stage=None,
        assignment_created=False,
        retryable=True,
        required_evidence=(
            "authorization_before_mutation",
            "no_fchown",
            "no_fchmod",
            "sentinels_unchanged",
        ),
    ),
    OperationalOutcome(
        scenario_id="controller-permissions-repair-blocked",
        boundary="permission_repair_safety",
        error_code="controller_permissions_repair_blocked",
        command_exit_code=9,
        job_state=None,
        job_stage=None,
        assignment_created=False,
        retryable=True,
        required_evidence=(
            "safety_block_before_mutation",
            "no_fchown",
            "no_fchmod",
            "sentinels_unchanged",
        ),
    ),
    OperationalOutcome(
        scenario_id="controller-permissions-repair-failed",
        boundary="permission_repair_execution",
        error_code="controller_permissions_repair_failed",
        command_exit_code=10,
        job_state=None,
        job_stage=None,
        assignment_created=False,
        retryable=True,
        required_evidence=(
            "partial_mutation_possible",
            "safe_system_error_class_only",
            "file_descriptors_closed",
        ),
    ),
    OperationalOutcome(
        scenario_id="controller-permissions-repaired",
        boundary="permission_repair",
        error_code=None,
        command_exit_code=0,
        job_state=None,
        job_stage=None,
        assignment_created=False,
        retryable=None,
        required_evidence=(
            "changed_paths_exact",
            "post_repair_audit_ok",
            "second_repair_idempotent",
            "jobs_unchanged",
            "assignments_unchanged",
        ),
    ),
'''
outcomes = outcomes.replace(marker, records + marker, 1)
OUTCOMES.write_text(outcomes, encoding="utf-8")

contract = CONTRACT.read_text(encoding="utf-8")
old_ids = '''    "provision-vault-owner-invalid",\n}'''
new_ids = '''    "provision-vault-owner-invalid",
    "provision-stage-helper-missing",
    "provision-stage-helper-not-executable",
    "controller-permissions-unhealthy",
    "controller-permissions-repair-root-required",
    "controller-permissions-repair-blocked",
    "controller-permissions-repair-failed",
    "controller-permissions-repaired",
}'''
if contract.count(old_ids) != 1:
    raise SystemExit("expected scenario set tail exactly once")
contract = contract.replace(old_ids, new_ids, 1)

old_count = '''def test_catalog_contains_nineteen_proven_outcomes() -> None:\n    assert len(PROVEN_OPERATIONAL_OUTCOMES) == 19'''
new_count = '''def test_catalog_contains_twenty_six_proven_outcomes() -> None:
    assert len(PROVEN_OPERATIONAL_OUTCOMES) == 26'''
if contract.count(old_count) != 1:
    raise SystemExit("expected old catalog count exactly once")
contract = contract.replace(old_count, new_count, 1)

old_boundaries = '''            "preflight",\n            "vault_gate",\n        }'''
new_boundaries = '''            "preflight",
            "vault_gate",
            "worker_configuration",
            "permission_audit",
            "permission_repair_authorization",
            "permission_repair_safety",
            "permission_repair_execution",
            "permission_repair",
        }'''
if contract.count(old_boundaries) != 1:
    raise SystemExit("expected boundary set exactly once")
contract = contract.replace(old_boundaries, new_boundaries, 1)

old_tail = '''        elif item.boundary == "vault_gate":
            assert item.error_code == "vault_not_configured"
            assert item.command_exit_code == 4
            assert item.job_state is None
            assert item.job_stage is None
            assert item.assignment_created is False
            assert item.retryable is True
            assert item.failure_kind is None
        else:
            assert item.failure_kind is None'''
new_tail = '''        elif item.boundary == "vault_gate":
            assert item.error_code == "vault_not_configured"
            assert item.command_exit_code == 4
            assert item.job_state is None
            assert item.job_stage is None
            assert item.assignment_created is False
            assert item.retryable is True
            assert item.failure_kind is None
        elif item.boundary == "worker_configuration":
            assert item.error_code == "provision_not_configured"
            assert item.command_exit_code == 1
            assert item.job_state == "failed"
            assert item.job_stage == "connecting"
            assert item.assignment_created is False
            assert item.retryable is True
            assert item.failure_kind is None
        elif item.boundary in {
            "permission_audit",
            "permission_repair_authorization",
            "permission_repair_safety",
            "permission_repair_execution",
            "permission_repair",
        }:
            expected = {
                "permission_audit": (
                    "controller_permissions_unhealthy",
                    8,
                    True,
                ),
                "permission_repair_authorization": (
                    "root_required",
                    3,
                    True,
                ),
                "permission_repair_safety": (
                    "controller_permissions_repair_blocked",
                    9,
                    True,
                ),
                "permission_repair_execution": (
                    "controller_permissions_repair_failed",
                    10,
                    True,
                ),
                "permission_repair": (None, 0, None),
            }
            error_code, exit_code, retryable = expected[item.boundary]
            assert item.error_code == error_code
            assert item.command_exit_code == exit_code
            assert item.job_state is None
            assert item.job_stage is None
            assert item.assignment_created is False
            assert item.retryable is retryable
            assert item.failure_kind is None
        else:
            assert item.failure_kind is None'''
if contract.count(old_tail) != 1:
    raise SystemExit("expected consistency tail exactly once")
contract = contract.replace(old_tail, new_tail, 1)
CONTRACT.write_text(contract, encoding="utf-8")
