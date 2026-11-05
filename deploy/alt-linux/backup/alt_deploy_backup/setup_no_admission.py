"""Archival negative admission facts; no execution authority or callback replay."""
from datetime import datetime, timedelta, timezone
from types import SimpleNamespace
import hashlib
import os
import re
import stat

from .setup_compat import control_module
from .setup_maintenance_review import maintenance_lock

DIRECTORIES = ('workstations-gateway-receipts', 'setup-no-admission-plans', 'setup-no-admission-facts')
PREFIX = 'setup-no-admission-'
PURPOSE = 'historical_no_admission_only'


def denied():
    return control_module('ad_directory').fail('setup_no_admission_unverified',
        'Expired request, terminal receipt, absence of admission or fresh prejoin state cannot be proven')


def _date(value):
    result = datetime.fromisoformat(value)
    if result.tzinfo is None: raise denied()
    return result


def _read(root, path):
    return control_module('setup_plans').private_read(path, owner_uid=root.stat().st_uid)


def _hash(root, path):
    return hashlib.sha256(control_module('setup_plans').private_read_bytes(path, owner_uid=root.stat().st_uid)).hexdigest()


def _receipt(root, request_id):
    module = control_module('workstations_receipts')
    module.request_uuid(request_id)
    record = _read(root, root/DIRECTORIES[0]/(request_id+'.json'))
    io = control_module('setup_plans')
    if (set(record) != {'schema_version','request_id','intent','intent_sha256','state','data','error_code','created_at'}
            or type(record['schema_version']) is not int or record['schema_version'] != 1
            or record['request_id'] != request_id or not isinstance(record['intent'], dict)
            or set(record['intent']) != {'operation','parameters'}
            or not isinstance(record['intent']['operation'], str)
            or not re.fullmatch('[a-z][a-z_.]{0,63}', record['intent']['operation'])
            or not isinstance(record['intent']['parameters'], dict)
            or io.digest(record['intent']) != record['intent_sha256']
            or record['state'] not in ('pending','successful','error','unknown')
            or record['data'] is not None and not isinstance(record['data'], dict)
            or record['error_code'] is not None and not isinstance(record['error_code'], str)):
        raise denied()
    _date(record['created_at'])
    return record


def _review_plan(root, path):
    io = control_module('setup_plans'); value = _read(root, path)
    if (set(value) != {'schema_version','operation','created_at','expires_at','content_sha256','payload','plan_id','sha256'}
            or type(value['schema_version']) is not int or value['schema_version'] != 1
            or value['operation'] != 'setup_no_admission_plan' or not isinstance(value['sha256'], str)
            or not re.fullmatch('[0-9a-f]{64}', value['sha256'])
            or value['plan_id'] != PREFIX+value['sha256'] or path.name != value['plan_id']+'.json'
            or io.digest({k:v for k,v in value.items() if k not in ('plan_id','sha256')}) != value['sha256']
            or not isinstance(value['payload'],dict) or io.digest(value['payload']) != value['content_sha256']
            or _date(value['expires_at'])-_date(value['created_at']) != timedelta(minutes=30)):
        raise denied()
    p=value['payload']
    if set(p) != {'request_id','original_plan_id','original_plan_sha256','receipt_sha256','prejoin_retry','assignment_sha256','closed_history_sha256','live'}:
        raise denied()
    if (not isinstance(p['original_plan_sha256'],str) or not re.fullmatch('[0-9a-f]{64}',p['original_plan_sha256'])
            or p['original_plan_id']!='setup-'+p['original_plan_sha256']
            or not isinstance(p['closed_history_sha256'],str)
            or not re.fullmatch('[0-9a-f]{64}',p['closed_history_sha256'])): raise denied()
    receipt = _receipt(root,p['request_id'])
    original = _read(root,root/'setup-plans'/(p['original_plan_id']+'.json'))
    control_module('setup_jobs').validate_plan(original,'full_setup')
    if (p['original_plan_id'] != original['plan_id'] or p['original_plan_sha256'] != original['sha256']
            or _date(original['expires_at']) > _date(value['created_at'])
            or receipt['state'] != 'unknown' or receipt['data'] is not None
            or receipt['intent'] != dict(operation='plans.apply',parameters=dict(
                plan_id=original['plan_id'],sha256=original['sha256'],kind='full_setup'))
            or _hash(root,root/DIRECTORIES[0]/(p['request_id']+'.json')) != p['receipt_sha256']
            or original['payload'].get('engine_schema_version') != 2
            or original['payload'].get('prejoin_retry') != p['prejoin_retry']
            or 'result' not in p['prejoin_retry'].get('evidence_sha256',{})):
        raise denied()
    return value


def validate_artifacts(root):
    """Read only metadata from a backup; never import staged code or probe a target."""
    uid=root.stat().st_uid
    for name in DIRECTORIES:
        directory=root/name
        if not directory.exists() and not directory.is_symlink(): continue
        info=directory.lstat()
        if not stat.S_ISDIR(info.st_mode) or info.st_uid!=uid or stat.S_IMODE(info.st_mode)!=0o700: raise denied()
        for path in directory.iterdir():
            if name==DIRECTORIES[0]:
                if path.suffix=='.json': _receipt(root,path.stem)
                elif path.suffix=='.lock':
                    control_module('workstations_receipts').request_uuid(path.stem)
                    if control_module('setup_plans').private_read_bytes(path,owner_uid=uid)!=b'': raise denied()
                else: raise denied()
            elif name==DIRECTORIES[1]: _review_plan(root,path)
            else:
                value=_read(root,path)
                if (set(value)!={'schema_version','purpose','request_id','review_sha256','confirmed_at'}
                        or type(value['schema_version']) is not int or value['schema_version']!=1
                        or value['purpose']!=PURPOSE or not isinstance(value['review_sha256'],str)
                        or not re.fullmatch('[0-9a-f]{64}',value['review_sha256'])
                        or path.name!=value['review_sha256']+'.json'): raise denied()
                plan=_review_plan(root,root/DIRECTORIES[1]/(PREFIX+value['review_sha256']+'.json'))
                if (plan['payload']['request_id']!=value['request_id'] or not
                        _date(plan['created_at'])<=_date(value['confirmed_at'])<_date(plan['expires_at'])): raise denied()


class NoAdmissionReview:
    def __init__(self,settings,*,observer=None,clock=None):
        self.settings=settings; self.observer=observer
        self.clock=clock or (lambda:datetime.now(timezone.utc))
        self.io=control_module('setup_plans'); self.jobs=control_module('setup_jobs')
        class Plans(self.io.SetupPlanStore):
            prefix=PREFIX; directory=DIRECTORIES[1]; plan_operation='setup_no_admission_plan'
        self.plans=Plans(settings.state_root,clock=self.clock)

    def _snapshot(self,request_id):
        root=self.settings.state_root
        record=_receipt(root,request_id)
        intent=record['intent']; parameters=intent['parameters']
        if (record['state']!='unknown' or record['data'] is not None or not isinstance(record['error_code'],str)
                or intent['operation']!='plans.apply'
                or set(parameters)!={'plan_id','sha256','kind'} or parameters['kind']!='full_setup'
                or not isinstance(parameters['sha256'],str) or not re.fullmatch('[0-9a-f]{64}',parameters['sha256'])
                or parameters['plan_id']!='setup-'+parameters['sha256']): raise denied()
        plan=_read(root,root/'setup-plans'/(parameters['plan_id']+'.json'))
        self.jobs.validate_plan(plan,'full_setup')
        p=plan['payload']; proof=p.get('prejoin_retry',{})
        if (plan['sha256']!=parameters['sha256'] or p.get('engine_schema_version')!=2
                or 'result' not in proof.get('evidence_sha256',{}) or not p.get('predecessor_job')
                or _date(plan['expires_at'])>self.clock() or not
                _date(plan['created_at'])<=_date(record['created_at'])<=self.clock()): raise denied()
        repository=self.jobs.SetupJobRepository(self.settings)
        repository._check_admissions()
        for path in (repository.claims/(plan['sha256']+'.json'),root/'setup-plan-runs'/(plan['plan_id']+'.json')):
            if path.exists() or path.is_symlink(): raise denied()
        if any(j.status['plan_sha256']==plan['sha256'] for j in repository.list()): raise denied()
        # V2 execution cannot dispatch without its native claim. Check retained
        # legacy records too; absence of a single index is not sufficient.
        runs=root/'setup-runs'
        if runs.exists() or runs.is_symlink():
            for path in runs.iterdir():
                run=_read(root,path)
                if run.get('plan_id')==plan['plan_id'] or run.get('plan_sha256')==plan['sha256']: raise denied()
        assignment=control_module('setup_assignments').DomainAssignmentStore(root).get(p['machine']['uuid'])
        if assignment!=p.get('existing_assignment'): raise denied()
        historical=control_module('setup_prejoin_retry').historical_prejoin_retry_evidence(
            root,assignment,p['machine'],p['user'],p['ou_identity'],p['observed'],p['computer'])
        if historical!=proof: raise denied()
        predecessor_id=control_module('setup_retry').validate_predecessor(self.settings,plan)
        from .setup_closed_failure import ClosedFailureEvidence
        closed=ClosedFailureEvidence(self.settings,clock=self.clock).load(predecessor_id)
        if closed['predecessor_job']!=p['predecessor_job'] or closed['failed_run_id']!=proof['failed_run_id']: raise denied()
        from .setup_partial_observation import PrejoinCompatibilityHistory
        live=PrejoinCompatibilityHistory(self.settings,observer=self.observer).live(proof['failed_run_id'])
        return dict(request_id=request_id,original_plan_id=plan['plan_id'],original_plan_sha256=plan['sha256'],
            receipt_sha256=_hash(root,root/DIRECTORIES[0]/(request_id+'.json')),prejoin_retry=proof,
            assignment_sha256=self.io.digest(assignment),closed_history_sha256=closed['history_sha256'],live=live)

    def _locks(self,request_id):
        # Same receipt -> lifecycle -> queue order as native apply. A terminal
        # callback cannot remain in flight while its exact receipt lock is held.
        from contextlib import ExitStack
        control_module('workstations_receipts').request_uuid(request_id)
        if os.geteuid()!=self.jobs.service_uid(self.settings): raise denied()
        stack=ExitStack()
        try:
            stack.enter_context(maintenance_lock(SimpleNamespace(lock_file=self.settings.state_root/DIRECTORIES[0]/(request_id+'.lock'),
                service_user=self.settings.service_user)))
            stack.enter_context(maintenance_lock(self.settings))
            stack.enter_context(self.jobs.SetupJobRepository(self.settings).locked())
            return stack
        except BaseException:
            stack.close(); raise

    def plan(self,request_id):
        try:
            with self._locks(request_id): return self.plans.create(self._snapshot(request_id))
        except Exception:
            raise denied() from None

    def confirm(self,plan_id,sha256):
        try:
            protected=self.plans.load(plan_id,sha256)
            request_id=protected['payload']['request_id']
            with self._locks(request_id):
                if self.plans.load(plan_id,sha256)!=protected or self._snapshot(request_id)!=protected['payload']: raise denied()
                fact=dict(schema_version=1,purpose=PURPOSE,request_id=request_id,review_sha256=sha256,
                          confirmed_at=self.clock().isoformat())
                path=self.settings.state_root/DIRECTORIES[2]/(sha256+'.json')
                self.io.private_create(path,fact)
                self.jobs.fsync_directory(path.parent)
                return fact
        except Exception:
            raise denied() from None
