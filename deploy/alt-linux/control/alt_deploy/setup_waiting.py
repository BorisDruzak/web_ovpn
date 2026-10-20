"""A bounded mutable waiting projection is never phase execution authority."""
from datetime import datetime,timezone
import os

from .wallet_codes import WALLET_CODES
from .krfb_program import TARGET_CODES
from .final_dns_policy import CODES as DNS_CODES
from .setup_plans import private_read
from .ad_directory import fail


WAIT_CODES=WALLET_CODES|TARGET_CODES|DNS_CODES|frozenset({
    'certificates_importer_active','workflow_package_manager_busy','workflow_target_processes_unverified',
    'workflow_readiness_unverified','workflow_identity_changed','workflow_source_changed',
    'vnc_policy_snapshot_changed','vnc_policy_external_blocker'})


def read(settings,job):
    from .setup_jobs import service_uid,timestamp
    path=job.job_dir/'workflow-readiness.json'
    if not path.exists() and not path.is_symlink():return None
    try:
        if path.lstat().st_nlink!=1:raise ValueError
        value=private_read(path,owner_uid=service_uid(settings))
        if (set(value)!={'schema_version','job_id','phase','code','since'} or type(value['schema_version']) is not int
                or value['schema_version']!=1 or value['job_id']!=job.job_id or 'workflow' not in job.request['plan']['payload']
                or value['phase'] not in ('user','final_dns') or value['code'] is not None and value['code'] not in WAIT_CODES):raise ValueError
        timestamp(value['since'])
        return value
    except Exception:raise fail('setup_workflow_waiting_invalid','Protected workflow waiting metadata is invalid') from None


def record(settings,job,phase,code,*,clock=None):
    from .locks import assert_owned
    from .setup_jobs import service_uid,SetupJobRepository,publish
    assert_owned(settings.lock_file)
    current=SetupJobRepository(settings).get(job.job_id)
    if (os.geteuid()!=service_uid(settings) or current.request!=job.request or 'workflow' not in current.status
            or current.status['workflow']['current_phase']!=phase
            or current.state not in ('waiting_reboot','waiting_first_login','queued')
            or code is not None and code not in WAIT_CODES):raise fail('setup_workflow_waiting_invalid','Waiting projection ownership differs')
    previous=read(settings,current)
    if previous is not None and previous['phase']==phase and previous['code']==code:return previous
    value={'schema_version':1,'job_id':job.job_id,'phase':phase,'code':code,
           'since':(clock or (lambda:datetime.now(timezone.utc)))().isoformat()}
    publish(job.job_dir/'workflow-readiness.json',value,create=previous is None)
    return value
