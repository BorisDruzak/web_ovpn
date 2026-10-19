"""An entered local claim blocks every ordinary execution/maintenance boundary."""
import copy
from types import SimpleNamespace

import pytest

from alt_deploy.errors import ControlError
from alt_deploy.setup_jobs import SetupJobRepository, legacy_setup_admission
from alt_deploy.setup_plans import SetupPlanStore
from alt_deploy.setup_worker import SetupWorker
from test_setup_partial_local_state import prepared
from test_setup_closed_failure import partial_failure, backend
from test_component_catalog import project
from test_component_setup import component_service


def entered(partial_failure):
    store, payload, closed, date = prepared(partial_failure)
    plan = store.create(payload); store.claim_once(plan)
    return store, plan, closed, date


def test_unknown_partial_attempt_blocks_worker_legacy_and_backup(partial_failure, monkeypatch):
    store, plan, closed, date = entered(partial_failure)
    settings = store.settings
    assert SetupWorker(settings, clock=lambda: date[0]).run_once() == {'status': 'blocked', 'code': 'setup_partial_local_unresolved'}
    with pytest.raises(ControlError) as error:
        with legacy_setup_admission(settings, '22222222-3333-4444-5555-666666666666', 'alt-t2-pc2'):
            pytest.fail('An entered recovery must block foreign legacy execution too')
    assert error.value.code == 'setup_partial_local_unresolved'
    fake = SimpleNamespace(exclusions=lambda sha: {'job_ids': {closed['job_id']}, 'lease_ids': set(closed['lease_ids'])})
    backend('setup_queue_review')  # Import its real base class before replacing the factory.
    from alt_deploy_backup import setup_maintenance_review, setup_compat
    monkeypatch.setattr(setup_maintenance_review, 'MaintenanceReview', lambda *a, **k: fake)
    from alt_deploy import setup_maintenance_review_bridge
    monkeypatch.setattr(setup_maintenance_review_bridge, 'review_service', lambda *a: fake)
    assert 'partial_local_execution_unresolved' in setup_compat.unresolved_jobs(settings.state_root, maintenance_review='a'*64)
    from alt_deploy.controller_readiness import ControllerReadinessChecker
    assert not ControllerReadinessChecker(settings, maintenance_review='a'*64).active_jobs_empty()


def test_maintenance_coverage_does_not_authorize_recovery(partial_failure):
    store, plan, closed, date = entered(partial_failure)
    coverage = backend('setup_maintenance_coverage').MaintenanceCoverage(store.settings,
        observer=lambda job: pytest.fail('Pending recovery must block before any observation'), clock=lambda: date[0])
    with pytest.raises(ControlError): coverage.plan()


def test_pending_claim_blocks_new_job_before_consuming_plan(partial_failure):
    store, recovery, closed, date = entered(partial_failure)
    payload = copy.deepcopy(partial_failure[1].request['plan']['payload'])
    payload['machine'].update(uuid='22222222-3333-4444-5555-666666666666', hostname='alt-t2-pc2')
    payload['request'].update(machine_uuid=payload['machine']['uuid'], final_hostname=payload['machine']['hostname'])
    plan = SetupPlanStore(store.settings.state_root, clock=lambda: date[0]).create(payload)
    jobs = SetupJobRepository(store.settings, clock=lambda: date[0])
    with pytest.raises(ControlError) as error: jobs.submit(plan, operation='full_setup')
    assert error.value.code == 'setup_partial_local_unresolved'
    assert not (jobs.claims/(plan['sha256']+'.json')).exists()


def test_partial_history_is_in_restore_fingerprint_and_needs_compatible_validator(partial_failure, monkeypatch):
    store, plan, closed, date = entered(partial_failure)
    from alt_deploy_backup import setup_compat
    fingerprint = setup_compat.history_fingerprint(store.settings.state_root)
    assert any(name.startswith('setup-partial-local-claims/') for name in fingerprint)
    original = setup_compat.control_module
    monkeypatch.setattr(setup_compat, 'control_module', lambda name: SimpleNamespace() if name == 'setup_partial_local_state' else original(name))
    with pytest.raises(ValueError): setup_compat.validate_ledger(store.settings.state_root)


def test_restore_cannot_erase_an_entered_original_failure_claim(partial_failure, tmp_path):
    import shutil
    from alt_deploy_backup.setup_compat import assert_restore_history
    from alt_deploy_backup.errors import BackupError
    store, plan, closed, date = entered(partial_failure)
    staged = tmp_path/'older-controller'
    shutil.copytree(store.settings.state_root, staged)
    for name in ('setup-partial-local-evidence','setup-partial-local-plans','setup-partial-local-claims','setup-partial-local-results'):
        path = staged/name
        if path.exists(): shutil.rmtree(path)  # Explicit synthetic older restore candidate only.
    with pytest.raises(BackupError) as error: assert_restore_history(store.settings.state_root, staged)
    assert error.value.code == 'setup_history_restore_conflict'


@pytest.mark.parametrize('two_failures', [False, True])
def test_completed_successor_can_be_backed_up_verified_and_rehearsed(partial_failure, tmp_path, two_failures):
    import shutil
    from support.backup_restore_sandbox import BackupSandbox
    from test_setup_partial_local_continuation import dispatch_followup, dispatch_after_two_failures
    from alt_deploy_backup.setup_compat import history_fingerprint
    if two_failures:
        plan, job, outcome = dispatch_after_two_failures(partial_failure)
    else:
        plan, job, outcome, before, computer = dispatch_followup(partial_failure)
    assert outcome['status'] == 'successful'
    sandbox = BackupSandbox.create(tmp_path)
    sandbox.seed_complete_controller()
    from alt_deploy.setup_partial_local_runtime import REHEARSAL_RECORD
    from alt_deploy_backup.components import component_specs
    rehearsal_path = sandbox.root/REHEARSAL_RECORD.relative_to('/')
    assert any(rehearsal_path.is_relative_to(path) for component in component_specs(sandbox.settings)
               for path in component.paths)
    rehearsal_path.parent.mkdir(parents=True, exist_ok=True)
    rehearsal_bytes = b'{"status":"passed","helper_sha256":"synthetic","native_sha256":"synthetic"}'
    rehearsal_path.write_bytes(rehearsal_bytes)
    root = sandbox.settings.controller_state_root
    shutil.copytree(partial_failure[0].settings.state_root, root, dirs_exist_ok=True)
    fingerprint = history_fingerprint(root)
    backup_id = sandbox.repository().create().backup_id
    sandbox.repository().verify(backup_id, write_evidence=True)
    sandbox.rehearsal_service().rehearse(backup_id)
    assert sandbox.restore_service().restore(backup_id).phase == 'committed'
    assert history_fingerprint(root) == fingerprint
    assert rehearsal_path.read_bytes() == rehearsal_bytes
