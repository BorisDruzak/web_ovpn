"""Immutable post-login phase tickets, claims and outcomes for one original job."""
from __future__ import annotations

import copy
from datetime import datetime,timezone
import os
from pathlib import Path
import re
import stat

from .ad_directory import fail
from .full_workflow import archived_workflow
from .locks import assert_owned
from .setup_jobs import SetupJobRepository,service_uid,valid_process,timestamp,publish
from .setup_plans import digest,private_directory,private_read
from .wallet_codes import WALLET_CODES
from .krfb_program import TARGET_CODES
from .krfb_runtime import RFB_CODES
from .final_dns_policy import CODES as DNS_CODES
from .setup_waiting import WAIT_CODES


PHASES=('system','user','final_dns')
DIRECTORIES={'ticket':'setup-phase-tickets','claim':'setup-phase-claims','result':'setup-phase-results'}
HEX=re.compile('[0-9a-f]{64}')
UUID=re.compile('[0-9a-f]{8}(?:-[0-9a-f]{4}){3}-[0-9a-f]{12}')
SID=re.compile('S-1-[0-9]+(?:-[0-9]+){1,15}')
REF_FIELDS={'ticket_sha256','claim_sha256','result_sha256','admission_sequence','process_identity'}
SCOPE_FIELDS={'machine_uuid','hostname','ip','registration_sha256','ssh_binding','login','upn','user_guid','user_sid',
              'uid','gid','home_sha256','computer_guid','computer_sid','ou_guid','ou_dn','connection_uuid','interface','backend'}
OBSERVATION_FIELDS={'boot_id','session_sha256','wallet_sha256','krfb_sha256','dns_sha256','certificates_sha256',
                    'package_health_sha256','helpers'}
HELPERS={'wallet','krfb','dns','vnc_policy','certificates'}
BASE_FIELDS={'schema_version','kind','job_id','phase','machine_uuid','plan_sha256','request_sha256',
             'source_sha256','catalog_sha256','workflow_policy_sha256','component_ids','budget_seconds','created_at'}
PHASE_CODES=WALLET_CODES|TARGET_CODES|RFB_CODES|DNS_CODES|WAIT_CODES|frozenset({
    'workflow_readiness_unverified','workflow_readiness_changed','workflow_source_changed','workflow_identity_changed',
    'workflow_phase_command_failed','workflow_phase_timeout','workflow_result_unverified','workflow_target_processes_unverified',
    'workflow_user_verification_failed','workflow_final_verification_failed','workflow_phase_outcome_unverified',
    'certificates_importer_active','certificates_import_failed'})


def denied(code='setup_phase_invalid'):
    return fail(code,'Original phase authority is missing, changed, consumed or unverified')


def sha(value):return isinstance(value,str) and HEX.fullmatch(value) is not None
def uuid(value):return isinstance(value,str) and UUID.fullmatch(value) is not None


def phase_spec(job,phase):
    if job.request['operation']!='full_setup' or phase not in PHASES:raise denied()
    workflow=archived_workflow(job.request['plan']['payload'])
    return next(p for p in workflow['phases'] if p['id']==phase)


def validate_workflow_status(request,status):
    """Pure validation; cross-file authority is checked separately under lock."""
    workflow=archived_workflow(request['plan']['payload'])
    value=status['workflow']
    if (request['operation']!='full_setup' or status['claimed'] is not True or not isinstance(value,dict)
            or set(value)!={'schema_version','kind','current_phase','phases','system_result_sha256'}
            or type(value['schema_version']) is not int or value['schema_version']!=1
            or value['kind']!=workflow['kind'] or value['current_phase'] not in ('user','final_dns')
            or not sha(value['system_result_sha256'])
            or not isinstance(value['phases'],dict) or not set(value['phases'])<={'user','final_dns'}):raise ValueError
    for phase,ref in value['phases'].items():
        if (not isinstance(ref,dict) or set(ref)!=REF_FIELDS or not sha(ref['ticket_sha256'])
                or type(ref['admission_sequence']) is not int or ref['admission_sequence']<=request['admission_sequence']
                or ref['claim_sha256'] is not None and not sha(ref['claim_sha256'])
                or ref['result_sha256'] is not None and not sha(ref['result_sha256'])
                or (ref['claim_sha256'] is None)!=(ref['process_identity'] is None)
                or ref['process_identity'] is not None and not valid_process(ref['process_identity'])
                or ref['result_sha256'] is not None and ref['claim_sha256'] is None):raise ValueError
    if 'final_dns' in value['phases'] and value['phases'].get('user',{}).get('result_sha256') is None:raise ValueError
    if status['state'] in ('successful','degraded') and (value['current_phase']!='final_dns'
            or any(value['phases'].get(p,{}).get('result_sha256') is None for p in ('user','final_dns'))):raise ValueError


def workflow_transition_allowed(request,status,previous,state,stage):
    try:
        validate_workflow_status(request,status)
        match=re.fullmatch(r'workflow\.(user|final_dns)\.(queued|preflight|apply|verify|waiting|complete|outcome_unverified)',stage)
        if not match:return False
        phase,step=match.groups();ref=status['workflow']['phases'].get(phase)
        if state=='queued' and previous in ('waiting_reboot','waiting_first_login','verifying','queued'):
            return step=='queued' and ref is not None
        if state=='preflight' and previous=='queued':return step=='preflight' and ref is not None and ref['claim_sha256'] is not None
        if state=='waiting_first_login' and previous=='preflight' and phase=='final_dns' and step=='waiting':
            return status['workflow']['phases'].get('user',{}).get('result_sha256') is not None
        return False
    except Exception:return False


def validate_ready(job,phase,ready,system):
    try:
        workflow=archived_workflow(job.request['plan']['payload']);payload=job.request['plan']['payload']
        if (phase not in ('user','final_dns') or not isinstance(ready,dict)
                or set(ready)!={'schema_version','status','job_id','phase','source_sha256','catalog_sha256',
                    'workflow_policy_sha256','scope','observation'}
                or type(ready['schema_version']) is not int or ready['schema_version']!=1
                or ready['status']!='ready' or ready['job_id']!=job.job_id or ready['phase']!=phase
                or ready['source_sha256']!=payload['source_sha256'] or ready['catalog_sha256']!=payload['catalog_sha256']
                or ready['workflow_policy_sha256']!=workflow['policy_sha256']):raise ValueError
        scope=ready['scope'];observed=ready['observation']
        if not isinstance(scope,dict) or set(scope)!=SCOPE_FIELDS or not isinstance(observed,dict) or set(observed)!=OBSERVATION_FIELDS:raise ValueError
        expected={'machine_uuid':job.machine_uuid,'hostname':payload['machine']['hostname'],'ip':payload['machine']['ip'],
            'registration_sha256':payload['machine']['registration_sha256'],'ssh_binding':payload['ssh_binding'],
            'login':payload['user']['login'],'upn':payload['user']['upn'],'user_guid':payload['user']['object_guid'],
            'user_sid':payload['user']['object_sid'],'ou_guid':payload['ou_identity']['object_guid'],'ou_dn':payload['computer_ou'],
            'computer_guid':system['result']['computer']['object_guid'],'computer_sid':system['result']['computer']['object_sid']}
        if any(scope[k]!=v for k,v in expected.items()):raise ValueError
        if (any(type(scope[k]) is not int or scope[k]<=0 for k in ('uid','gid')) or not sha(scope['home_sha256'])
                or not uuid(observed['boot_id']) or system['result']['reboot_required'] and observed['boot_id']==system['result']['original_boot_id']
                or scope['backend'] not in ('nm_etcnet','nm_keyfile','etcnet')
                or not isinstance(scope['interface'],str) or not re.fullmatch('[A-Za-z0-9][A-Za-z0-9_.-]{0,14}',scope['interface'])
                or scope['backend']=='etcnet' and scope['connection_uuid'] is not None
                or scope['backend']!='etcnet' and not uuid(scope['connection_uuid'])):raise ValueError
        if any(not sha(observed[k]) for k in OBSERVATION_FIELDS-{'boot_id','helpers'}):raise ValueError
        if (not isinstance(observed['helpers'],dict) or set(observed['helpers'])!=HELPERS
                or any(not sha(v) for v in observed['helpers'].values())):raise ValueError
        return copy.deepcopy(ready)
    except Exception:raise denied('setup_phase_readiness_unverified') from None


class WorkflowPhaseStore:
    def __init__(self,settings,*,clock=None,readiness=None,admission=None):
        self.settings=settings;self.jobs=SetupJobRepository(settings,clock=clock)
        self.clock=clock or (lambda:datetime.now(timezone.utc));self.readiness=readiness;self.admission=admission

    def _path(self,kind,job,phase):
        phase_spec(job,phase)
        return self.settings.state_root/DIRECTORIES[kind]/(job.job_id+'--'+phase+'.json')

    def _read(self,path):
        if path.lstat().st_nlink!=1:raise denied()
        return private_read(path,owner_uid=service_uid(self.settings))

    def _actor(self,job):
        assert_owned(self.settings.lock_file)
        if os.geteuid()!=service_uid(self.settings):raise denied()
        current=self.jobs.get(job.job_id)
        if current.request!=job.request or current.state=='unknown_requires_review':raise denied('setup_phase_consumed')
        from .component_catalog import ComponentCatalog
        from .setup_runtime import source_fingerprint
        payload=current.request['plan']['payload'];phase_spec(current,'system')
        if (payload['catalog_sha256']!=ComponentCatalog.load(self.settings.ansible_project_dir).fingerprint
                or payload['source_sha256']!=source_fingerprint(self.settings.ansible_project_dir,Path(__file__).parent)):
            raise denied('setup_phase_source_changed')
        return current

    def _directories(self):
        for name in DIRECTORIES.values():private_directory(self.settings.state_root/name)

    def _base(self,job,phase,kind):
        payload=job.request['plan']['payload'];spec=phase_spec(job,phase)
        return {'schema_version':1,'kind':'workstation_phase_'+kind,'job_id':job.job_id,'phase':phase,
            'machine_uuid':job.machine_uuid,'plan_sha256':job.status['plan_sha256'],'request_sha256':job.status['request_sha256'],
            'source_sha256':payload['source_sha256'],'catalog_sha256':payload['catalog_sha256'],
            'workflow_policy_sha256':payload['workflow']['policy_sha256'],'component_ids':spec['component_ids'],
            'budget_seconds':spec['budget_seconds'],'created_at':self.clock().isoformat()}

    def _validate(self,record,job,phase,kind):
        try:
            if not isinstance(record,dict) or type(record.get('schema_version')) is not int:raise ValueError
            expected=self._base(job,phase,kind)
            if any(record.get(k)!=v for k,v in expected.items() if k!='created_at'):raise ValueError
            timestamp(record['created_at'])
            if kind=='ticket':
                if set(record)!=BASE_FIELDS|{'admission_sequence','readiness','readiness_sha256'}:raise ValueError
                if type(record['admission_sequence']) is not int or record['admission_sequence']<=job.status['admission_sequence']:raise ValueError
            elif kind=='claim':
                if set(record)!=BASE_FIELDS|{'ticket_sha256','readiness','readiness_sha256','process_identity','admission'}:raise ValueError
                if not sha(record['ticket_sha256']) or not valid_process(record['process_identity']):raise ValueError
                self._validate_admission(record['admission'],job,phase,record['ticket_sha256'])
            elif kind=='result':
                if set(record)!=BASE_FIELDS|{'ticket_sha256','claim_sha256','process_identity','result'}:raise ValueError
                if not sha(record['claim_sha256']) or not valid_process(record['process_identity']):raise ValueError
                if phase!='system' and not sha(record['ticket_sha256']):raise ValueError
                if phase=='system' and record['ticket_sha256'] is not None:raise ValueError
                validate_result(job,phase,record['result'])
            if kind in ('ticket','claim') and digest(record['readiness'])!=record['readiness_sha256']:raise ValueError
            return record
        except Exception:raise denied() from None

    def _validate_admission(self,value,job,phase,ticket_sha):
        if (not isinstance(value,dict) or set(value)!={'schema_version','job_id','phase','ticket_sha256','review_sha256',
                'excluded_job_ids','excluded_lease_ids'} or type(value['schema_version']) is not int or value['schema_version']!=1
                or value['job_id']!=job.job_id or value['phase']!=phase or value['ticket_sha256']!=ticket_sha
                or not sha(value['review_sha256']) or not isinstance(value['excluded_job_ids'],list)
                or not isinstance(value['excluded_lease_ids'],list)
                or value['excluded_job_ids']!=sorted(set(value['excluded_job_ids']))
                or value['excluded_lease_ids']!=sorted(set(value['excluded_lease_ids']))
                or any(not isinstance(v,str) or not re.fullmatch('job-[0-9]{8}T[0-9]{6}Z-[0-9a-f]{8}',v) for v in value['excluded_job_ids'])
                or any(not isinstance(v,str) or not re.fullmatch('[0-9a-f]{32}',v) for v in value['excluded_lease_ids'])):raise denied()

    def records(self,job):
        phase_spec(job,'system');result={}
        for phase in PHASES:
            row={}
            for kind in DIRECTORIES:
                path=self._path(kind,job,phase)
                value=self._validate(self._read(path),job,phase,kind) if path.exists() or path.is_symlink() else None
                if phase=='system' and kind!='result' and value is not None:raise denied()
                row[kind]=value
            result[phase]=row
        system=result['system']['result']
        if 'workflow' in job.status and (system is None or job.status['workflow']['system_result_sha256']!=digest(system)):raise denied()
        if any(result[p]['ticket'] for p in ('user','final_dns')) and system is None:raise denied()
        original_claim=self.jobs._read(self.jobs.claims/(job.status['plan_sha256']+'.json'))
        self.jobs._check_claim(job,original_claim)
        if system is not None and (system['claim_sha256']!=digest(original_claim)
                or system['process_identity']!=job.status['process_identity']):raise denied()
        for phase in ('user','final_dns'):
            row=result[phase];ticket,claim,outcome=(row[k] for k in ('ticket','claim','result'))
            if ticket:validate_ready(job,phase,ticket['readiness'],system)
            if claim:
                if ticket is None or claim['ticket_sha256']!=digest(ticket) or claim['readiness']['scope']!=ticket['readiness']['scope']:raise denied()
                validate_ready(job,phase,claim['readiness'],system)
            if outcome and (claim is None or outcome['claim_sha256']!=digest(claim)
                    or outcome['ticket_sha256']!=digest(ticket) or outcome['process_identity']!=claim['process_identity']):raise denied()
        if result['final_dns']['ticket'] and (result['user']['result'] is None
                or result['user']['result']['result']['status']!='applied_verified'):raise denied()
        # A missing reference can be a create-before-status interruption. A
        # published but different reference is corruption, even after UNKNOWN.
        for phase,ref in job.status.get('workflow',{}).get('phases',{}).items():
            for key in ('ticket','claim','result'):
                recorded=ref[key+'_sha256'];actual=result[phase][key]
                if recorded is not None and (actual is None or recorded!=digest(actual)):raise denied()
            ticket=result[phase]['ticket'];claim=result[phase]['claim']
            if ticket is not None and ref['admission_sequence']!=ticket['admission_sequence']:raise denied()
            if ref['process_identity'] is not None and (claim is None or ref['process_identity']!=claim['process_identity']):raise denied()
        return result

    def _publish_status(self,job,state,stage,workflow,authority,*,waiting_reason=None):
        from .setup_jobs import validate_setup_record
        assert_owned(self.settings.lock_file)
        if waiting_reason not in (None,'workflow_final_verification_unavailable'):raise denied()
        kind=authority['kind'].removeprefix('workstation_phase_');phase=authority['phase']
        if (job.state=='unknown_requires_review' or kind not in DIRECTORIES
                or self._read(self._path(kind,job,phase))!=authority):raise denied()
        records=self.records(job)
        if workflow['system_result_sha256']!=digest(records['system']['result']):raise denied()
        for identifier,ref in workflow['phases'].items():
            for key in ('ticket','claim','result'):
                value=records[identifier][key]
                if ref[key+'_sha256']!=(digest(value) if value is not None else None):raise denied()
        status=copy.deepcopy(job.status);status['workflow']=workflow
        # Validate the proposed transition using its retained immutable authority.
        status.update(state=state,stage=stage,updated_at=self.clock().isoformat())
        status['stage_history'].append({'state':state,'stage':stage,'at':status['updated_at']})
        validate_setup_record(job.request,status,job_id=job.job_id)
        execution=self._read(job.job_dir/'execution.json')
        from .setup_events import SetupEventStore
        events=SetupEventStore(self.settings)._read(job)
        for identifier,component in execution['components'].items():
            if any(e['component_id']==identifier and e['changed'] for e in events):component['changed']=True
        execution.update(state=state,stage=stage,finished_at=None if state not in ('successful','degraded','unknown_requires_review') else status['updated_at'])
        execution['workflow']={'schema_version':1,'kind':'complete_workstation','phase':workflow['current_phase'],
            'waiting_reason':waiting_reason,'phases':copy.deepcopy(workflow['phases']),
            'system_result_sha256':workflow['system_result_sha256']}
        if authority['kind']=='workstation_phase_result' and authority['result']['status']=='outcome_unverified':
            execution['error_code']=authority['result']['code'];execution['operator_action_required']=True
        publish(job.job_dir/'execution.json',execution)
        publish(job.job_dir/'status.json',status)

    def enqueue(self,job,phase,ready_evidence):
        try:
            job=self._actor(job)
            if phase not in ('user','final_dns') or job.state not in ('waiting_reboot','waiting_first_login','queued'):raise denied()
            records=self.records(job);system=records['system']['result']
            if system is None or records[phase]['ticket'] is not None:raise denied('setup_phase_consumed')
            if phase=='final_dns' and (records['user']['result'] is None or records['user']['result']['result']['status']!='applied_verified'):raise denied()
            ready=validate_ready(job,phase,ready_evidence,system)
            with self.jobs.locked():
                self.jobs._check_admissions();self._directories()
                from .setup_jobs import next_admission_sequence
                ticket=dict(self._base(job,phase,'ticket'),admission_sequence=next_admission_sequence(self.settings),
                            readiness=ready,readiness_sha256=digest(ready))
                self._validate(ticket,job,phase,'ticket')
                publish(self._path('ticket',job,phase),ticket,create=True)
                workflow=copy.deepcopy(job.status['workflow']);workflow['current_phase']=phase
                workflow['phases'][phase]={'ticket_sha256':digest(ticket),'claim_sha256':None,'result_sha256':None,
                    'admission_sequence':ticket['admission_sequence'],'process_identity':None}
                self._publish_status(job,'queued','workflow.'+phase+'.queued',workflow,ticket)
                return ticket
        except Exception as error:
            if hasattr(error,'code'):raise
            raise denied('setup_phase_publication_unverified') from None

    def claim(self,job,phase,identity):
        try:
            from .setup_worker import process_identity
            job=self._actor(job);records=self.records(job);row=records[phase]
            if job.state!='queued' or row['ticket'] is None or row['claim'] is not None:raise denied('setup_phase_consumed')
            if identity!=process_identity(self.settings):raise denied('setup_phase_worker_unverified')
            observer=self.readiness
            if observer is None:
                from .setup_phase_probe import WorkflowReadinessProbe
                observer=WorkflowReadinessProbe(self.settings).observe
            ready=validate_ready(job,phase,observer(job,phase),records['system']['result'])
            if ready['scope']!=row['ticket']['readiness']['scope']:raise denied('setup_phase_readiness_unverified')
            candidates=eligible_candidates(self.settings,readiness=observer)
            if not candidates or candidates[0][1:]!=(job.job_id,phase):raise denied('setup_phase_not_queue_head')
            ticket_sha=digest(row['ticket']);admit=self.admission
            if admit is None:
                from .setup_maintenance_review_bridge import phase_admission_service
                admit=phase_admission_service(self.settings).admit_phase_candidate
            admission=dict(admit(job.job_id,phase,ticket_sha))
            ready=validate_ready(job,phase,admission.pop('readiness'),records['system']['result'])
            if ready['scope']!=row['ticket']['readiness']['scope']:raise denied('setup_phase_readiness_unverified')
            self._validate_admission(admission,job,phase,ticket_sha)
            with self.jobs.locked():
                self.jobs._check_admissions();current=self.jobs.get(job.job_id)
                if current.status!=job.status or self._path('claim',job,phase).exists():raise denied('setup_phase_consumed')
                claim=dict(self._base(job,phase,'claim'),ticket_sha256=ticket_sha,readiness=ready,
                    readiness_sha256=digest(ready),process_identity=copy.deepcopy(identity),admission=admission)
                self._validate(claim,job,phase,'claim');publish(self._path('claim',job,phase),claim,create=True)
                workflow=copy.deepcopy(job.status['workflow']);ref=workflow['phases'][phase]
                ref.update(claim_sha256=digest(claim),process_identity=copy.deepcopy(identity))
                self._publish_status(job,'preflight','workflow.'+phase+'.preflight',workflow,claim)
                return claim
        except Exception as error:
            if hasattr(error,'code'):raise
            raise denied('setup_phase_publication_unverified') from None

    def complete(self,job,phase,result):
        try:
            from .setup_worker import process_identity
            job=self._actor(job);validate_result(job,phase,result)
            records=self.records(job)
            if records[phase]['result'] is not None:raise denied('setup_phase_consumed')
            identity=process_identity(self.settings)
            if phase=='system':
                if job.state not in ('running','verifying') or identity!=job.status['process_identity']:raise denied()
                claim=self.jobs._read(self.jobs.claims/(job.status['plan_sha256']+'.json'));ticket_sha=None
                workflow={'schema_version':1,'kind':'complete_workstation','current_phase':'user','phases':{},'system_result_sha256':None}
                state='waiting_reboot' if result['reboot_required'] else 'waiting_first_login';stage=state
            else:
                claim=records[phase]['claim']
                if (claim is None or identity!=claim['process_identity'] or job.state not in ('preflight','running','verifying')):raise denied()
                ticket_sha=digest(records[phase]['ticket']);workflow=copy.deepcopy(job.status['workflow'])
                if result['status']=='outcome_unverified':state='unknown_requires_review';stage='workflow.'+phase+'.outcome_unverified'
                elif phase=='user':workflow['current_phase']='final_dns';state='waiting_first_login';stage='workflow.final_dns.waiting'
                else:state='verifying';stage='workflow.final_dns.verify'
            with self.jobs.locked():
                self._directories()
                record=dict(self._base(job,phase,'result'),ticket_sha256=ticket_sha,claim_sha256=digest(claim),
                    process_identity=copy.deepcopy(identity),result=copy.deepcopy(result))
                self._validate(record,job,phase,'result');publish(self._path('result',job,phase),record,create=True)
                if phase=='system':workflow['system_result_sha256']=digest(record)
                if phase!='system':workflow['phases'][phase]['result_sha256']=digest(record)
                self._publish_status(job,state,stage,workflow,record)
                return record
        except Exception as error:
            if hasattr(error,'code'):raise
            raise denied('setup_phase_publication_unverified') from None

    def start(self,job,phase,claim):
        from .setup_worker import process_identity
        job=self._actor(job);row=self.records(job)[phase]
        if (job.state!='preflight' or row['claim']!=claim or row['result'] is not None
                or claim['process_identity']!=process_identity(self.settings)):raise denied()
        with self.jobs.locked():
            self._publish_status(job,'running','workflow.'+phase+'.apply',copy.deepcopy(job.status['workflow']),claim)
        return self.jobs.get(job.job_id)

    def reconcile(self,job):
        assert_owned(self.settings.lock_file)
        records=self.records(job);workflow=job.status.get('workflow',{})
        uncertain=False
        if records['system']['result'] is not None and not workflow:uncertain=True
        for phase in ('user','final_dns'):
            row=records[phase];ref=workflow.get('phases',{}).get(phase,{})
            for key in ('ticket','claim','result'):
                expected=digest(row[key]) if row[key] is not None else None
                if ref.get(key+'_sha256')!=expected:uncertain=True
            if row['claim'] is not None and row['result'] is None:uncertain=True
            admission=self.settings.state_root/'setup-phase-admissions'/(job.job_id+'--'+phase+'.json')
            if (admission.exists() or admission.is_symlink()) and row['claim'] is None:uncertain=True
        if uncertain and job.state!='unknown_requires_review':
            self.jobs.transition(job.job_id,'unknown_requires_review',stage={'id':'workflow.publication_unverified'})
        return {'uncertain':uncertain}


def validate_result(job,phase,result):
    try:
        base={'status','changed','code','verification_sha256','target_processes_absent'}
        if phase=='system':base|={'computer','original_boot_id','reboot_required'}
        if (not isinstance(result,dict) or set(result)!=base
                or result['status'] not in ('applied_verified','rolled_back_verified','outcome_unverified')
                or result['changed'] is not None and type(result['changed']) is not bool
                or type(result['target_processes_absent']) is not bool
                or result['verification_sha256'] is not None and not sha(result['verification_sha256'])
                or result['code'] is not None and (not isinstance(result['code'],str) or result['code'] not in PHASE_CODES)):raise ValueError
        if result['status']!='outcome_unverified' and (result['target_processes_absent'] is not True
                or not sha(result['verification_sha256']) or type(result['changed']) is not bool):raise ValueError
        if result['status']=='rolled_back_verified' and phase!='final_dns':raise ValueError
        if ((result['status']=='applied_verified')!=(result['code'] is None)):
            raise ValueError
        if phase=='system':
            computer=result['computer'];payload=job.request['plan']['payload']
            if (result['status']!='applied_verified' or type(result['reboot_required']) is not bool or not uuid(result['original_boot_id'])
                    or not isinstance(computer,dict) or set(computer)!={'object_guid','object_sid','dn','dns_hostname'}
                    or not uuid(computer['object_guid']) or not isinstance(computer['object_sid'],str) or not SID.fullmatch(computer['object_sid'])
                    or computer['dn'].casefold()!=('CN='+payload['machine']['hostname']+','+payload['computer_ou']).casefold()
                    or computer['dns_hostname']!=payload['machine']['hostname']+'.sosnadmin.local'):raise ValueError
    except Exception:raise denied('setup_phase_result_unverified') from None


def validate_phase_artifacts(settings):
    """Read history only. Source drift and expiration do not corrupt receipts."""
    directories={kind:settings.state_root/name for kind,name in DIRECTORIES.items()}
    if not any(p.exists() or p.is_symlink() for p in directories.values()):return []
    uid=service_uid(settings);jobs=SetupJobRepository(settings);store=WorkflowPhaseStore(settings)
    identities=set();sequences=[]
    for kind,directory in directories.items():
        if not directory.exists() and not directory.is_symlink():continue
        info=directory.lstat()
        if not stat.S_ISDIR(info.st_mode) or info.st_uid!=uid or stat.S_IMODE(info.st_mode)!=0o700:raise denied()
        for path in directory.iterdir():
            match=re.fullmatch('(job-[0-9]{8}T[0-9]{6}Z-[0-9a-f]{8})--(system|user|final_dns)[.]json',path.name)
            if not match:raise denied()
            job=jobs.get(match[1]);record=store._validate(store._read(path),job,match[2],kind);identities.add(job.job_id)
            if kind=='ticket':sequences.append(record['admission_sequence'])
    if len(sequences)!=len(set(sequences)):raise denied()
    for identity in identities:store.records(jobs.get(identity))
    return sequences


def eligible_candidates(settings,*,readiness=None):
    """Common FIFO; absent/busy graphical sessions never head-block other PCs."""
    jobs=SetupJobRepository(settings);store=WorkflowPhaseStore(settings)
    candidates=[]
    for job in jobs.list():
        if job.state!='queued':continue
        if not job.status['claimed']:
            candidates.append((job.status['admission_sequence'],job.job_id,None));continue
        if 'workflow' not in job.status:continue
        phase=job.status['workflow']['current_phase'];records=store.records(job);row=records[phase]
        if row['ticket'] is None or row['claim'] is not None:continue
        try:
            if readiness is None:
                from .setup_phase_probe import WorkflowReadinessProbe
                readiness=WorkflowReadinessProbe(settings).observe
            ready=validate_ready(job,phase,readiness(job,phase),records['system']['result'])
            if ready['scope']!=row['ticket']['readiness']['scope']:continue
        except Exception:continue
        candidates.append((row['ticket']['admission_sequence'],job.job_id,phase))
    return sorted(candidates)


def effective_identity(settings,job):
    """Reserve the newly created AD GUID additively; never edit the old claim."""
    identity=copy.deepcopy(job.request['identities'])
    if 'workflow' in job.request['plan']['payload']:
        record=WorkflowPhaseStore(settings).records(job)['system']['result']
        if record is not None:identity['computer_guid']=record['result']['computer']['object_guid']
    return identity


def idle_workflow(settings,job):
    """Only proven idle new workflows yield to another PC's native admission."""
    if ('workflow' not in job.status or job.state not in ('waiting_reboot','waiting_first_login','queued')
            or job.status['claimed'] is not True):return False
    rows=WorkflowPhaseStore(settings).records(job);workflow=job.status['workflow']
    if rows['system']['result'] is None:return False
    for phase in ('user','final_dns'):
        row=rows[phase];ref=workflow['phases'].get(phase,{})
        for kind in ('ticket','claim','result'):
            if ref.get(kind+'_sha256')!=(digest(row[kind]) if row[kind] is not None else None):return False
        if row['claim'] is not None and row['result'] is None:return False
        if row['result'] is not None and row['result']['result']['status']=='outcome_unverified':return False
        admission=settings.state_root/'setup-phase-admissions'/(job.job_id+'--'+phase+'.json')
        if (admission.exists() or admission.is_symlink()) and row['claim'] is None:return False
    return True
