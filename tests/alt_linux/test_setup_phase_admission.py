"""Fresh phase-only native admission never extends the old Setup TTL."""
import copy
from datetime import timedelta

import pytest

from alt_deploy.errors import ControlError
from alt_deploy.locks import exclusive_lock
from test_setup_phases import phase_job
from test_full_workflow_binding import full_setup
from test_component_catalog import project


def test_native_phase_receipt_is_one_shot_and_not_the_initial_queue_receipt(phase_job,monkeypatch):
    from alt_deploy_backup.setup_phase_admission import PhaseAdmissionReview
    store,jobs,job,ready,identity,admissions,setup=phase_job
    now=setup.clock()+timedelta(days=1)
    review=PhaseAdmissionReview(setup.settings,clock=lambda:now,readiness=lambda j,p:copy.deepcopy(ready))
    with exclusive_lock(setup.settings.lock_file):
        store.enqueue(job,'user',ready)
        store.admission=review.admit_phase_candidate
        claim=store.claim(jobs.get(job.job_id),'user',identity)
        receipt=review.read(job.job_id,'user')
        assert claim['admission']['review_sha256']==receipt['sha256']
        assert receipt['created_at']==now.isoformat()
        assert receipt['purpose']=='post_login_phase_only'
        assert receipt['ticket_sha256']==claim['ticket_sha256']
        with pytest.raises(ControlError):review.admit_phase_candidate(job.job_id,'user',claim['ticket_sha256'])


def test_phase_admission_requires_the_real_kernel_lifecycle_lock(phase_job):
    from alt_deploy_backup.setup_phase_admission import PhaseAdmissionReview
    store,jobs,job,ready,identity,admissions,setup=phase_job
    with exclusive_lock(setup.settings.lock_file):ticket=store.enqueue(job,'user',ready)
    from alt_deploy.setup_plans import digest
    with pytest.raises(ControlError):PhaseAdmissionReview(setup.settings).admit_phase_candidate(job.job_id,'user',digest(ticket))
