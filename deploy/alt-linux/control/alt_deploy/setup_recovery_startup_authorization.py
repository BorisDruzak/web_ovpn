"""Exact startup attachment and permanent approval-pair binding.

Internal preparation only. The future operator coordinator must obtain both
explicit SHA confirmations and call bind_once before reservation or mutation.
Creating an attachment does not approve it. Read-only authorization requires
the retained binding and genuine post-write continuity; it never opens Vault,
executes SSH, changes AD or controls services. No default ledger/approval exists.
"""
from __future__ import annotations

import copy
from pathlib import Path
import re

from .ad_directory import fail
from .locking import exclusive_lock
from .setup_plans import SetupPlanStore,canonical,digest,private_read
from .setup_recovery import _pair,_sync_directory
from .setup_recovery_controller_backup import RecoveryControllerBackup
from .setup_recovery_provider import PROVIDER
from .setup_recovery_runtime import _read_source
from .setup_runtime import source_fingerprint
from .setup_recovery_start_wire import NAMES
from .setup_recovery_sssd_start import START,validate_unit


def _same(left,right):return canonical(left)==canonical(right)


def _sha(value):
    return isinstance(value,str) and re.fullmatch('[0-9a-f]{64}',value) is not None


class StartupPlanStore(SetupPlanStore):
    prefix='recovery-startup-'
    directory='setup-recovery-startup-plans'


def _ledger(unit,ledger):
    fixed=dict(schema_version=1,operation='fixed_sssd_start_once',systemd_package='systemd 258.9-alt1',
        controller_start=START,unit_sha256=digest(unit),
        automatic_restart='stock_on_abnormal_with_temporary_sssd_policy',
        dependency_effects='conservative_inventory_not_transaction_prediction',
        manager_interference='observed_without_exclusive_manager_lease',
        temporary_policy='retained_until_separate_verified_restoration')
    if (not isinstance(ledger,dict) or set(ledger)!=set(fixed)|{'inventory_sha256','reviewed_effects','unresolved_effects'}
            or any(not _same(ledger[key],value) for key,value in fixed.items())
            or not _sha(ledger['inventory_sha256']) or len(canonical(ledger))>131072
            or not isinstance(ledger['reviewed_effects'],list) or not 1<=len(ledger['reviewed_effects'])<=128
            or not isinstance(ledger['unresolved_effects'],list) or len(ledger['unresolved_effects'])>128):raise ValueError
    for effect in ledger['reviewed_effects']:
        if (not isinstance(effect,dict) or set(effect)!={'unit','trigger','effect','source_sha256'}
                or not _sha(effect['source_sha256']) or any(not isinstance(effect[key],str)
                    or not 1<=len(effect[key].encode())<=4096 for key in ('unit','trigger','effect'))):raise ValueError
    if any(not isinstance(value,str) or not 1<=len(value.encode())<=4096 for value in ledger['unresolved_effects']):raise ValueError


class RecoveryStartupPlans:
    def __init__(self,planning,*,fingerprint=None):
        self.planning=planning;self.settings=planning.settings
        self.store=StartupPlanStore(self.settings.state_root,clock=planning.clock)
        self.fingerprint=fingerprint or (lambda:source_fingerprint(self.settings.ansible_project_dir,Path(__file__).parent))

    def _sources(self):
        directory=Path(__file__).parent;owner=Path(__file__).lstat().st_uid
        return [_read_source(directory/('setup_recovery_'+name+'.py'),owner=owner) for name in NAMES]

    def _native_sources(self):
        path=Path(__file__).with_name('setup_recovery_native_testjoin.py')
        return self._sources()+[_read_source(path,owner=Path(__file__).lstat().st_uid)]

    def _user_sources(self):
        path=Path(__file__).with_name('setup_recovery_user_check.py')
        return self._native_sources()+[_read_source(path,owner=Path(__file__).lstat().st_uid)]

    def _user_scope(self,base):
        from .setup_recovery_user_check import employee,TOOL,PACKAGE,NSS_MODULE,NSS_PACKAGE
        sources=self._user_sources();snapshot=base['plan']['payload']['snapshot'];user=snapshot['user']
        selected=employee({key:user[key] for key in ('object_guid','object_sid','login','upn')})
        if (user['state']!='enabled' or len(sources)!=14 or sources[:-1]!=self._native_sources()
                or digest(sources[:-2])!=base['source_sha256']
                or any(not isinstance(value,str) or len(value.encode())>131072 for value in sources)):raise ValueError
        tools=snapshot['workstation_facts']['snapshot']['tools']
        if not isinstance(tools,dict) or not {'getent','nss_sss'}<=set(tools):raise ValueError
        dependencies={key:copy.deepcopy(tools[key])
            for key in ('getent','nss_sss')}
        for key,package in (('getent',PACKAGE),('nss_sss',NSS_PACKAGE)):
            item=dependencies[key]
            if (not isinstance(item,dict) or set(item)!={'present','sha256','size','uid','gid','mode','package'}
                    or item['present'] is not True or not _sha(item['sha256']) or item['package']!=package
                    or any(type(item[field]) is not int for field in ('size','uid','gid','mode'))
                    or not 1<=item['size']<=67108864 or item['uid']!=0 or item['gid']<0
                    or not 0<=item['mode']<=0o7777 or item['mode'] & 0o022
                    or (key=='getent' and not item['mode'] & 0o111)
                    or (key=='nss_sss' and not item['mode'] & 0o400)):raise ValueError
        return dict(schema_version=1,operation='fixed_selected_user_nss_observation_once',
            source_sha256=digest(sources),employee=selected,dependencies=dependencies,
            paths={'getent':TOOL,'nss_sss':NSS_MODULE},argv=[TOOL,'-s','sss','passwd',selected['upn']],
            timeout_seconds=15,local_duplicate='reject_before_lookup',nss_cache='may_be_used',
            login_verified=False,online_user_authentication_verified=False,temporary_policy_retained=True)

    def _native_scope(self,base):
        from .setup_recovery_native_testjoin import TOOLS
        sources=self._native_sources();dc=base['identity']['dc']['dns_hostname']
        if (len(sources)!=13 or digest(sources[:-1])!=base['source_sha256']
                or any(not isinstance(value,str) or len(value.encode())>131072 for value in sources)
                or not isinstance(dc,str) or not re.fullmatch(r'[a-z0-9](?:[a-z0-9-]*[a-z0-9])?\.sosnadmin\.local',dc)):raise ValueError
        return dict(schema_version=1,operation='fixed_native_testjoin_once',source_sha256=digest(sources),
            computer_guid=base['identity']['computer_guid'],server_dns=dc,tools=copy.deepcopy(TOOLS),
            dc_address_source='protected_rehearsal_metadata',credentials='private_copy_of_imported_samba_secret',
            configuration='fixed_readonly_private_samba_nss_dns_kerberos',scratch='removed_before_verified_receipt',
            native_discovery='same_domain_peer_not_enforced',trust_verified=False,peer_pinning_verified=False,
            argv_template=['/usr/bin/net','-s','/work/smb.conf','-d','0','--use-kerberos=required',
                '-S',dc,'-I','<protected_dc_address>','ads','testjoin'])

    def _base(self,plan_id,confirmed_sha):
        plan=copy.deepcopy(self.planning.plans.load(plan_id,confirmed_sha));payload=plan['payload']
        fields={'failed_run_id','computer_guid','machine_uuid','computer_sid','evidence_sha256','execution_available','provider','snapshot'}
        if (set(payload)!=fields or payload['execution_available'] is not True or payload['provider']!=PROVIDER
                or payload['snapshot']['execution_available'] is not False
                or any(not _same(payload[key],payload['snapshot'][key]) for key in
                    ('failed_run_id','computer_guid','machine_uuid','computer_sid','evidence_sha256'))):raise ValueError
        pair=_pair(payload['failed_run_id'],payload['computer_guid']);snapshot=payload['snapshot']
        sources=self._sources()
        if (not isinstance(sources,list) or len(sources)!=12 or any(not isinstance(source,str) or len(source.encode())>131072 for source in sources)
                or self.fingerprint()!=snapshot['prerequisites']['source_sha256']):raise ValueError
        history=self.planning.history.load(pair['failed_run_id'])
        machine=self.planning.machines.resolve(payload['machine_uuid'])
        if (not _same(history['identity'],snapshot['historical_identity'])
                or history['identity']['evidence_sha256']!=payload['evidence_sha256']
                or machine.uuid!=payload['machine_uuid'] or machine.hostname!=snapshot['machine']['hostname']
                or machine.ip!=snapshot['machine']['ip'] or machine.registration_state!='ready' or machine.active_job or machine.assignment
                or digest(machine.raw)!=snapshot['machine']['registration_sha256']
                or not _same(self.planning.plans.load(plan_id,confirmed_sha),plan)):raise ValueError
        identity=dict(pair,machine_uuid=payload['machine_uuid'],computer_sid=payload['computer_sid'],
            evidence_sha256=payload['evidence_sha256'],registration_sha256=snapshot['machine']['registration_sha256'],
            employee_guid=snapshot['user']['object_guid'],employee_sid=snapshot['user']['object_sid'],
            computer_ou=snapshot['computer_ou'],ou_identity=snapshot['ou_identity'],dc=snapshot['computer']['dc'])
        return dict(plan=plan,identity=identity,source_sha256=digest(sources))

    def create(self,plan_id,confirmed_sha,*,sssd_unit,effects_ledger,native_check=False,user_check=False):
        try:
            if type(native_check) is not bool or type(user_check) is not bool or (user_check and not native_check):raise ValueError
            with exclusive_lock(self.settings.lock_file):
                base=self._base(plan_id,confirmed_sha);payload=base['plan']['payload'];pair=_pair(payload['failed_run_id'],payload['computer_guid'])
                claim=self.planning.attempts.claim_path(**pair)
                bindings=[self.planning.attempts._path(**pair,suffix=suffix) for suffix in
                    ('.execution-approval.json','.execution-approval-ready.json','.execution-approval-failed.json','.execution-approval-revoked.json')]
                if any(path.exists() or path.is_symlink() for path in (claim,*bindings)):raise ValueError
                unit=copy.deepcopy(sssd_unit);ledger=copy.deepcopy(effects_ledger)
                validate_unit(unit)
                if len(canonical(unit))>65536:raise ValueError
                _ledger(unit,ledger)
                scope=self._native_scope(base) if native_check else None
                user_scope=self._user_scope(base) if user_check else None
                if (not _same(self.planning.snapshot(**pair),payload['snapshot']) or not _same(self._base(plan_id,confirmed_sha),base)
                        or (native_check and not _same(self._native_scope(base),scope))
                        or (user_check and not _same(self._user_scope(base),user_scope))):raise ValueError
                attachment=dict(schema_version=1,scope='one_fixed_sssd_start_with_retained_temporary_policy',
                    recovery_plan_id=plan_id,recovery_plan_sha256=confirmed_sha,recovery_payload_sha256=digest(payload),
                    identity=base['identity'],source_sha256=base['source_sha256'],sssd_unit=unit,effects_ledger=ledger)
                if native_check:
                    attachment.update(scope='one_fixed_sssd_start_and_native_check_with_retained_temporary_policy',native_check=scope)
                if user_check:
                    attachment.update(scope='one_fixed_sssd_start_native_and_user_check_with_retained_temporary_policy',user_check=user_scope)
                return self.store.create(attachment)
        except Exception:raise fail('recovery_startup_plan_invalid','Exact startup scope and protected recovery provenance did not verify') from None

    def load(self,startup_id,startup_sha,plan_id,confirmed_sha):
        attachment=copy.deepcopy(self.store.load(startup_id,startup_sha));base=self._base(plan_id,confirmed_sha)
        approved=attachment['payload'];unit=approved['sssd_unit'];ledger=approved['effects_ledger']
        expected=dict(schema_version=1,scope='one_fixed_sssd_start_with_retained_temporary_policy',
            recovery_plan_id=plan_id,recovery_plan_sha256=confirmed_sha,recovery_payload_sha256=digest(base['plan']['payload']),
            identity=base['identity'],source_sha256=base['source_sha256'],sssd_unit=unit,effects_ledger=ledger)
        if 'native_check' in approved:
            expected.update(scope='one_fixed_sssd_start_and_native_check_with_retained_temporary_policy',native_check=self._native_scope(base))
        if 'user_check' in approved:
            if 'native_check' not in approved:raise ValueError
            expected.update(scope='one_fixed_sssd_start_native_and_user_check_with_retained_temporary_policy',user_check=self._user_scope(base))
        if (not _same(approved,expected) or attachment['created_at']<base['plan']['created_at']
                or len(canonical(unit))>65536):raise ValueError
        validate_unit(unit);_ledger(unit,ledger)
        return dict(attachment=attachment,base=base)


class RecoveryStartupAuthorization:
    def __init__(self,*,preparation,postwrite,startup_plan_id,confirmed_startup_sha,plans=None):
        self.preparation=preparation;self.postwrite=postwrite;self.settings=preparation.settings
        self.startup_plan_id=startup_plan_id;self.confirmed_startup_sha=confirmed_startup_sha
        self.plans=plans or RecoveryStartupPlans(preparation.planning,fingerprint=postwrite.fingerprint)
        self._binding_failed=False;self._binding_ambiguous=False

    @staticmethod
    def _pair(plan):return _pair(plan['payload']['failed_run_id'],plan['payload']['computer_guid'])

    def binding_path(self,plan):return self.preparation.attempts._path(**self._pair(plan),suffix='.execution-approval.json')

    def _marker(self,plan,suffix):return self.preparation.attempts._path(**self._pair(plan),suffix='.execution-approval-'+suffix+'.json')

    def _bound(self,plan,expected):
        failed=self._marker(plan,'failed')
        revoked=self._marker(plan,'revoked')
        if self._binding_failed or any(path.exists() or path.is_symlink() for path in (failed,revoked)):raise ValueError
        ready=dict(schema_version=1,status='approval_bound',binding_sha256=digest(expected))
        if (not _same(private_read(self.binding_path(plan)),expected)
                or not _same(private_read(self._marker(plan,'ready')),ready)):raise ValueError

    def _exclude_failed_binding(self,plan,expected):
        self._binding_failed=True
        failed=self._marker(plan,'failed');ready=self._marker(plan,'ready');revoked=self._marker(plan,'revoked')
        try:
            RecoveryControllerBackup._persist(failed,dict(schema_version=1,status='approval_failed'))
        except Exception:
            # Rename only this exact protected marker in its fixed directory.
            # Retain its bytes and the permanent binding; no new file/inode is
            # needed when creation of a failure record exhausted storage.
            try:
                if failed.exists() or failed.is_symlink() or revoked.exists() or revoked.is_symlink():
                    _sync_directory(ready.parent);return
                if not ready.exists() and not ready.is_symlink():return
                if not _same(private_read(ready),dict(schema_version=1,status='approval_bound',binding_sha256=digest(expected))):raise ValueError
                ready.rename(revoked);_sync_directory(ready.parent)
            except Exception:self._binding_ambiguous=True

    def _expected(self,loaded):
        attachment=loaded['attachment'];base=loaded['base'];plan=base['plan'];approved=attachment['payload']
        return dict(schema_version=1,recovery_plan_id=plan['plan_id'],recovery_plan_sha256=plan['sha256'],
            startup_plan_id=attachment['plan_id'],startup_plan_sha256=attachment['sha256'],identity=base['identity'],
            recovery_payload_sha256=digest(plan['payload']),startup_payload_sha256=digest(approved),
            source_sha256=base['source_sha256'],sssd_unit_sha256=digest(approved['sssd_unit']),
            effects_ledger_sha256=digest(approved['effects_ledger']))

    def _load(self,plan_id,confirmed_sha):
        return self.plans.load(self.startup_plan_id,self.confirmed_startup_sha,plan_id,confirmed_sha)

    def bind_once(self,plan_id,confirmed_sha):
        entered=False;plan=None
        try:
            with exclusive_lock(self.settings.lock_file):
                try:
                    loaded=self._load(plan_id,confirmed_sha);plan=loaded['base']['plan'];pair=self._pair(plan)
                    path=self.binding_path(plan);claim=self.preparation.attempts.claim_path(**pair)
                    if self._binding_failed or any(value.exists() or value.is_symlink() for value in
                            (path,claim,self._marker(plan,'ready'),self._marker(plan,'failed'),self._marker(plan,'revoked'))):raise ValueError
                    if not _same(self.preparation.planning.snapshot(**pair),plan['payload']['snapshot']):raise ValueError
                    if not _same(self._load(plan_id,confirmed_sha),loaded):raise ValueError
                    expected=self._expected(loaded);entered=True;RecoveryControllerBackup._persist(path,expected)
                    if (not _same(self.preparation.planning.snapshot(**pair),plan['payload']['snapshot'])
                            or not _same(self._load(plan_id,confirmed_sha),loaded) or not _same(private_read(path),expected)):raise ValueError
                    RecoveryControllerBackup._persist(self._marker(plan,'ready'),
                        dict(schema_version=1,status='approval_bound',binding_sha256=digest(expected)))
                    if (not _same(self.preparation.planning.snapshot(**pair),plan['payload']['snapshot'])
                            or not _same(self._load(plan_id,confirmed_sha),loaded)):raise ValueError
                    self._bound(plan,expected)
                    return copy.deepcopy(expected)
                except Exception:
                    # Exclude visible ready evidence before another coordinator
                    # can acquire this lifecycle lock after a late failure.
                    if entered and plan is not None:
                        self._exclude_failed_binding(plan,expected)
                    raise
        except Exception:
            if self._binding_ambiguous:
                raise fail('recovery_startup_approval_ambiguous','Approval exclusion could not persist; stop the workflow and require manual state recovery') from None
            raise fail('recovery_startup_approval_invalid','Exact recovery/startup SHA pair did not bind; retained bindings cannot be replaced') from None

    def __call__(self,plan_id,confirmed_sha,source_sha):
        # Called only under the runtime/coordinator lifecycle lock.
        try:
            loaded=self._load(plan_id,confirmed_sha);plan=loaded['base']['plan'];expected=self._expected(loaded)
            if source_sha!=expected['source_sha256']:raise ValueError
            self._bound(plan,expected)
            current=copy.deepcopy(self.postwrite.load(plan_id,confirmed_sha));current.pop('machine')
            claim_path=self.preparation.attempts.claim_path(**self._pair(plan))
            if (not _same(current['payload'],plan['payload']) or current['claim']['plan_id']!=plan_id
                    or current['claim']['plan_sha256']!=confirmed_sha or not _same(private_read(claim_path),current['claim'])):raise ValueError
            if not _same(self._load(plan_id,confirmed_sha),loaded):raise ValueError
            fresh=copy.deepcopy(self.postwrite.load(plan_id,confirmed_sha));fresh.pop('machine')
            if not _same(fresh,current) or not _same(private_read(claim_path),current['claim']):raise ValueError
            self._bound(plan,expected)
            if (not _same(self.plans.store.load(self.startup_plan_id,self.confirmed_startup_sha),loaded['attachment'])
                    or not _same(self.plans.planning.plans.load(plan_id,confirmed_sha),plan)):raise ValueError
            approved=loaded['attachment']['payload']
            return copy.deepcopy(dict(schema_version=1,plan_id=plan_id,plan_sha256=confirmed_sha,
                source_sha256=source_sha,sssd_unit=approved['sssd_unit'],effects_ledger_sha256=expected['effects_ledger_sha256'],
                approval_sha256=self.confirmed_startup_sha))
        except Exception:raise fail('recovery_startup_approval_invalid','Confirmed startup attachment and protected continuity must remain exact') from None
