"""Immutable operator envelope and exact one-object recovery composition."""
from __future__ import annotations
import copy,re
from datetime import datetime,timezone
from pathlib import Path
from .ad_directory import DOMAIN,fail
from .locking import exclusive_lock
from .setup_plans import SetupPlanStore,canonical,digest,private_read
from .setup_recovery import _pair
from .setup_recovery_planning import RecoveryPlanningService
from .setup_recovery_provider import PROVIDER
from .setup_recovery_startup_authorization import RecoveryStartupPlans
from .setup_recovery_policy_effects_runtime import RecoveryPolicyEffectsService
from .setup_recovery_policy_review_runtime import RecoveryPolicyReviewRuntime
from .setup_recovery_startup_inventory import RecoveryStartupInventoryRuntime,InventoryStore
from .setup_recovery_controller_backup import RecoveryControllerBackup
from .setup_recovery_execution import RecoveryExecutionCoordinator
from .setup_recovery_sssd_start import START,validate_unit

UNIT_HASHES={'sssd.service':'b26ae44bc2527d6f730b749a7202f1967544294802245c9ef2fd846fab18fe6f',
 'smb.service':'86641f1fb781dcf50872e5ac6a0e3dd4d422c4075f1e1c94fa7fb3f953d6856c',
 'nmb.service':'be2d54df9bedc1b6f7d970f95074edd980fff34ab9e0b0d5a7d3909226fee510'}
START_HASHES={'sssd.service':'eeb944db11721862dbb68de7060339531ac217fa389c01546d884af62feb1e6c',
 'smb.service':'72526322e17c0986f79626dd35c9a3261e813e5f39822c9d821a7badb58d5462',
 'nmb.service':'d5a515c417958ffd5981766fcf5166f5bf7abec6e15fde2228d592e257384b81'}
EMPTY_ARRAY='4f53cda18c2baa0c0354bb5f9a3ecbe5ed12ab4d8e11ba873c2f11161202b945'
EMPTY_STRING='12ae32cb1ec02d01eda3581b127c1fee3b0dc53572ed6baf239721a03d82e126'

def startup_ledger(inventory):
    for name in UNIT_HASHES:
        unit=inventory['units'][name];props=unit['properties'];source='/usr/lib/systemd/system/'+name
        package='sssd 2.9.8-alt3' if name=='sssd.service' else 'samba 4.21.9-alt4.p11.1'
        if (set(unit['sources'])!={source} or unit['sources'][source]['sha256']!=UNIT_HASHES[name]
                or unit['sources'][source].get('package')!=package or unit['sources'][source].get('origin')!='packaged'
                or props.get('FragmentPath')!=source or props.get('DropInPaths') or props.get('NeedDaemonReload')!='no'
                or props.get('Job') or any(props.get(key) for key in ('OnFailure','OnSuccess','TriggeredBy','UpheldBy','Triggers','Upholds'))
                or any(props.get(key)!='none' for key in ('SuccessAction','FailureAction','StartLimitAction'))):raise ValueError('Unreviewed seed behavior')
        opaque=unit['opaque_sha256'];env='01824c99134ec375e416b4b5e5eb82a12026c88b20deb2a6d8822c791ef3f3e0' if name=='sssd.service' else EMPTY_STRING
        envfiles='dca26afa70b2f1843a3a76b5ebeacc6b208a357a1763c0d44d55c2ea9c243fef' if name=='sssd.service' else '88ccde722581c707197444ca395b58a37f80385b1b54fae4cc0a15d578d72f44'
        reload=EMPTY_ARRAY if name=='sssd.service' else '63c2202947f05feec563c17f7231bbbe32f08e652b2f9bd96db3866bdbdf1fdc'
        if (opaque.get('ExecStart')!=START_HASHES[name] or opaque.get('Environment')!=env or opaque.get('EnvironmentFiles')!=envfiles
                or opaque.get('ExecReload')!=reload or any(opaque.get(key)!=EMPTY_ARRAY for key in ('ExecStartPre','ExecStartPost','ExecCondition','ExecStop','ExecStopPost'))
                or any(opaque.get(key)!=EMPTY_STRING for key in ('PassEnvironment','UnsetEnvironment'))):raise ValueError('Unreviewed seed command/environment')
    unit=inventory['units']['sssd.service'];validate_unit(unit)
    return dict(schema_version=1,operation='fixed_sssd_start_once',systemd_package='systemd 258.9-alt1',controller_start=START,
        inventory_sha256=digest(inventory),unit_sha256=digest(unit),automatic_restart='stock_on_abnormal_with_temporary_sssd_policy',
        dependency_effects='conservative_inventory_not_transaction_prediction',manager_interference='observed_without_exclusive_manager_lease',
        temporary_policy='retained_until_separate_verified_restoration',
        reviewed_effects=[dict(unit=name,trigger='fixed_manual_ignore_requirements_start_and_reviewed_stop',source_sha256=UNIT_HASHES[name],
            effect='Packaged fixed daemon invocation; empty extra Samba options; SSSD file logger and implicit PAC. Automatic restart may expand manager dependency jobs; full graph is diagnostic only.') for name in UNIT_HASHES],
        unresolved_effects=['Other manager clients can act between bounded observations; stock on-abnormal restart has native dependency effects.'])

class OperatorPlanStore(SetupPlanStore):
    prefix='recovery-operator-';directory='setup-recovery-operator-plans'

class TerminalPlanStore(SetupPlanStore):
    prefix='recovery-terminal-';directory='setup-recovery-terminal-plans'

def reviewed_projection(captured):
    selected=copy.deepcopy(captured)
    selected.pop('diagnostic_inventory',None)
    selected['ledger'].pop('inventory_sha256',None)
    return selected

class RecoveryOperatorService:
    def __init__(self,settings,*,planning=None,review=None,inventory=None,pipeline_factory=None):
        self.settings=settings;self.planning=planning or RecoveryPlanningService(settings)
        self.store=OperatorPlanStore(settings.state_root,clock=self.planning.clock)
        self.terminals=TerminalPlanStore(settings.state_root,clock=self.planning.clock)
        self.startup_plans=RecoveryStartupPlans(self.planning)
        self.review=review or RecoveryPolicyReviewRuntime(settings)
        self.inventory=inventory or RecoveryStartupInventoryRuntime(settings)
        self.pipeline_factory=pipeline_factory or RecoveryExecutionCoordinator

    def _path(self,pair,suffix):return self.planning.attempts._path(**pair,suffix='.operator-'+suffix+'.json')

    def _capture(self,snapshot):
        machine=self.planning.machines.resolve(snapshot['machine_uuid'])
        meta=RecoveryPolicyEffectsService(self.planning)._metadata(snapshot)
        inventory=self.inventory.capture(machine,snapshot['workstation_facts']['snapshot'])['inventory']
        ledger=startup_ledger(inventory);review=self.review.capture(machine,snapshot,meta)
        return dict(unit=inventory['units']['sssd.service'],ledger=ledger,review=review,
                    diagnostic_inventory=InventoryStore(self.settings.state_root).create(inventory),
                    terminal_units={name:inventory['units'][name] for name in ('smb.service','nmb.service')})

    def _pipeline(self,startup,terminal=None):
        def authority(plan_id,sha,source_sha):
            if terminal is None:raise ValueError('No terminal approval')
            self._operator_guard(startup,terminal)
            saved=self.terminals.load(terminal['plan_id'],terminal['sha256']);payload=saved['payload']
            pair=_pair(payload['failed_run_id'],payload['computer_guid'])
            intended=private_read(self._path(pair,'intent'));operator=self.store.load(intended['operator_plan_id'],intended['operator_plan_sha256'])
            if (operator['payload']['terminal']!=terminal or operator['payload']['startup']!=startup
                    or operator['payload']['recovery']!=dict(plan_id=plan_id,sha256=sha) or payload['source_sha256']!=source_sha
                    or self._path(pair,'failed').exists() or self._path(pair,'failed').is_symlink()):raise ValueError
            return dict(schema_version=1,plan_id=plan_id,plan_sha256=sha,source_sha256=source_sha,approval_sha256=saved['sha256'],
                baseline=payload['review']['baseline'],effects_sha256=payload['review']['effects_sha256'],terminal_units=payload['terminal_units'],
                runtime_dependencies=payload['review']['runtime_dependencies'],daemon_links=payload['review']['daemon_links'],environment_files=payload['review']['environment_files'],credential_cache=payload['review']['credential_cache'])
        return self.pipeline_factory(self.planning,startup_plan_id=startup['plan_id'],confirmed_startup_sha=startup['sha256'],
            terminal_authorization=authority,identity=self._identity,operator_guard=lambda:self._operator_guard(startup,terminal))

    def _operator_guard(self,startup,terminal):
        if terminal is None:raise ValueError('No terminal execution authority')
        saved=self.terminals.load(terminal['plan_id'],terminal['sha256']);pair=_pair(saved['payload']['failed_run_id'],saved['payload']['computer_guid'])
        intended=private_read(self._path(pair,'intent'));ready=private_read(self._path(pair,'ready'))
        expected=dict(schema_version=1,intent_sha256=digest(intended),operator_plan_id=intended['operator_plan_id'],operator_plan_sha256=intended['operator_plan_sha256'])
        if (canonical(ready)!=canonical(expected) or set(intended)!=set(pair)|{'schema_version','operator_plan_id','operator_plan_sha256','approved_at','status'}
                or type(intended['schema_version']) is not int or intended['schema_version']!=1 or intended['status']!='operator_execution_intended'
                or any(intended[key]!=value for key,value in pair.items())):raise ValueError('Changed operator approval intent')
        operator,base,current=self._load(intended['operator_plan_id'],intended['operator_plan_sha256'])
        if (operator['payload']['startup']!=startup or operator['payload']['terminal']!=terminal or canonical(current)!=canonical(saved)
                or self._path(pair,'failed').exists() or self._path(pair,'failed').is_symlink()
                or canonical(private_read(self._path(pair,'intent')))!=canonical(intended)
                or canonical(private_read(self._path(pair,'ready')))!=canonical(ready)):raise ValueError('Changed operator approval binding')
        return dict(operator_plan_id=operator['plan_id'],operator_plan_sha256=operator['sha256'],intent_sha256=digest(intended))

    def _identity(self,plan_id,sha):
        plan=self.planning.plans.load(plan_id,sha);payload=plan['payload'];snapshot=payload['snapshot']
        pair=_pair(payload['failed_run_id'],payload['computer_guid']);result=private_read(self.planning.attempts._path(**pair,suffix='.ad-write-result.json'))
        computer=self.planning.directory.inspect_computer(snapshot['machine']['hostname'],pair['computer_guid'])
        expected=dict(snapshot['computer'],kvno=result['kvno'],pwd_last_set=result['pwd_last_set'])
        user=self.planning.directory.user(snapshot['user']['login']);ous=[entry for entry in self.planning.directory.ous() if entry['dn'].casefold()==snapshot['computer_ou'].casefold()]
        if (canonical(computer)!=canonical(expected) or canonical(user)!=canonical(snapshot['user'])
                or canonical(ous)!=canonical([snapshot['ou_identity']]) or self.planning.plans.load(plan_id,sha)!=plan):raise ValueError('Recovery identity changed')
        return dict(computer=computer,employee=user,ou_identity=ous[0])

    def plan(self,failed_run_id,computer_guid):
        try:
            pair=_pair(failed_run_id,computer_guid)
            with exclusive_lock(self.settings.lock_file):
                if self._path(pair,'intent').exists() or self._path(pair,'intent').is_symlink():raise ValueError
                snapshot=copy.deepcopy(self.planning.snapshot(**pair));captured=self._capture(snapshot)
                if canonical(self.planning.snapshot(**pair))!=canonical(snapshot):raise ValueError
                payload={key:snapshot[key] for key in ('failed_run_id','computer_guid','machine_uuid','computer_sid','evidence_sha256')}
                payload.update(execution_available=True,provider=PROVIDER,snapshot=snapshot)
                base=self.planning.plans.create(payload)
            # Startup attachment owns its lifecycle lock; never recursively lock.
            startup=self.startup_plans.create(base['plan_id'],base['sha256'],sssd_unit=captured['unit'],effects_ledger=captured['ledger'],native_check=True,user_check=True)
            startup_ref=dict(plan_id=startup['plan_id'],sha256=startup['sha256'])
            pipeline=self._pipeline(startup_ref)
            terminal=self.terminals.create(dict(pair,recovery=dict(plan_id=base['plan_id'],sha256=base['sha256']),
                startup=startup_ref,source_sha256=digest(pipeline.terminal._sources()),review=captured['review'],terminal_units=captured['terminal_units']))
            with exclusive_lock(self.settings.lock_file):
                if canonical(self.planning.snapshot(**pair))!=canonical(snapshot):raise ValueError
                return self.store.create(dict(pair,operation='selected_recovery_then_normal_policy_once',execution_available=True,
                    machine=snapshot['machine'],computer_sid=snapshot['computer_sid'],computer_ou=snapshot['computer_ou'],
                    employee={key:snapshot['user'][key] for key in ('login','object_guid','object_sid','upn')},
                    recovery=dict(plan_id=base['plan_id'],sha256=base['sha256']),startup=startup_ref,
                    terminal=dict(plan_id=terminal['plan_id'],sha256=terminal['sha256']),snapshot_sha256=digest(snapshot),
                    review_sha256=digest(reviewed_projection(captured)),manual_password_writes=1,renewal_policy='any_change_UNKNOWN_no_retry',
                    setup_continuation='separate_fresh_normal_plan_after_current_terminal_proof'))
        except Exception:raise fail('recovery_operator_plan_failed','Exact source, identity, startup and normal-policy review must verify before execution can be proposed') from None

    def _load(self,operator_id,sha):
        operator=self.store.load(operator_id,sha);payload=operator['payload']
        fields={'failed_run_id','computer_guid','operation','execution_available','machine','computer_sid','computer_ou','employee','recovery','startup','terminal','snapshot_sha256','review_sha256','manual_password_writes','renewal_policy','setup_continuation'}
        if (set(payload)!=fields or payload['execution_available'] is not True or payload['operation']!='selected_recovery_then_normal_policy_once'
                or type(payload['manual_password_writes']) is not int or payload['manual_password_writes']!=1
                or payload['renewal_policy']!='any_change_UNKNOWN_no_retry'
                or payload['setup_continuation']!='separate_fresh_normal_plan_after_current_terminal_proof'):raise ValueError
        pair=_pair(payload['failed_run_id'],payload['computer_guid'])
        for ref in (payload['recovery'],payload['startup'],payload['terminal']):
            if not isinstance(ref,dict) or set(ref)!={'plan_id','sha256'}:raise ValueError
        base=self.planning.plans.load(payload['recovery']['plan_id'],payload['recovery']['sha256'])
        self.startup_plans.load(payload['startup']['plan_id'],payload['startup']['sha256'],base['plan_id'],base['sha256'])
        terminal=self.terminals.load(payload['terminal']['plan_id'],payload['terminal']['sha256'])
        if (terminal['payload']['recovery']!=payload['recovery'] or terminal['payload']['startup']!=payload['startup']
                or any(terminal['payload'][key]!=value or base['payload'][key]!=value for key,value in pair.items())
                or digest(base['payload']['snapshot'])!=payload['snapshot_sha256']):raise ValueError
        snapshot=base['payload']['snapshot']
        if (canonical(payload['machine'])!=canonical(snapshot['machine']) or payload['computer_sid']!=snapshot['computer_sid']
                or payload['computer_ou']!=snapshot['computer_ou'] or canonical(payload['employee'])!=canonical({key:snapshot['user'][key] for key in ('login','object_guid','object_sid','upn')})):raise ValueError
        return operator,base,terminal

    def apply(self,operator_id,confirmed_sha):
        entered=False;pair=None
        try:
            with exclusive_lock(self.settings.lock_file):
                operator,base,terminal=self._load(operator_id,confirmed_sha);payload=operator['payload'];pair=_pair(payload['failed_run_id'],payload['computer_guid'])
                path=self._path(pair,'intent')
                if path.exists() or path.is_symlink():raise ValueError('Recovery already intended')
                snapshot=self.planning.snapshot(**pair)
                if canonical(snapshot)!=canonical(base['payload']['snapshot']):raise ValueError
                captured=self._capture(snapshot)
                if (digest(reviewed_projection(captured))!=payload['review_sha256'] or canonical(self.planning.snapshot(**pair))!=canonical(snapshot)
                        or self._load(operator_id,confirmed_sha)!=(operator,base,terminal)):raise ValueError
                pipeline=self._pipeline(payload['startup'],payload['terminal'])
                if digest(pipeline.terminal._sources())!=terminal['payload']['source_sha256']:raise ValueError
                intended=dict(pair,schema_version=1,operator_plan_id=operator_id,operator_plan_sha256=confirmed_sha,
                    approved_at=self.planning.clock().isoformat(),status='operator_execution_intended')
                entered=True;RecoveryControllerBackup._persist(path,intended)
                RecoveryControllerBackup._persist(self._path(pair,'ready'),dict(schema_version=1,intent_sha256=digest(intended),
                    operator_plan_id=operator_id,operator_plan_sha256=confirmed_sha))
                self._operator_guard(payload['startup'],payload['terminal'])
            result=pipeline.execute(base['plan_id'],base['sha256'])
            RecoveryControllerBackup._persist(self._path(pair,'result'),dict(schema_version=1,operator_plan_id=operator_id,
                operator_plan_sha256=confirmed_sha,terminal_receipt_sha256=digest(result),status='successful'))
            return result
        except Exception:
            if entered and pair is not None:
                try:RecoveryControllerBackup._persist(self._path(pair,'failed'),dict(schema_version=1,status='UNKNOWN',error_code='recovery_operator_failed'))
                except Exception:pass
            raise fail('recovery_operator_failed','Recovery did not produce verified terminal evidence; entered attempts cannot be replayed') from None

    def verify_terminal(self,*,failed_run_id,computer_guid):
        with exclusive_lock(self.settings.lock_file):
            return self._verify_terminal_locked(failed_run_id=failed_run_id,computer_guid=computer_guid)

    def _verify_terminal_locked(self,*,failed_run_id,computer_guid):
        """Read-only continuation callback; Setup/continuation already owns lock."""
        pair=_pair(failed_run_id,computer_guid)
        intended=private_read(self._path(pair,'intent'));operator,base,terminal=self._load(intended['operator_plan_id'],intended['operator_plan_sha256'])
        payload=operator['payload'];result=private_read(self._path(pair,'result'))
        if self._path(pair,'failed').exists() or self._path(pair,'failed').is_symlink() or result['status']!='successful':raise ValueError
        current=self._pipeline(payload['startup'],payload['terminal']).terminal._operate('verify',base['plan_id'],base['sha256'])
        if digest(current)!=result['terminal_receipt_sha256']:raise ValueError
        # Finish the callback-bearing remote verification with only protected
        # local provenance/source/TTL reads. No stale result can authorize Setup.
        if (self._load(intended['operator_plan_id'],intended['operator_plan_sha256'])!=(operator,base,terminal)
                or canonical(private_read(self._path(pair,'intent')))!=canonical(intended)
                or canonical(private_read(self._path(pair,'result')))!=canonical(result)
                or self._path(pair,'failed').exists() or self._path(pair,'failed').is_symlink()):
            raise fail('recovery_operator_terminal_drift','Protected operator terminal provenance changed during verification')
        self._operator_guard(payload['startup'],payload['terminal'])
        if (canonical(private_read(self._path(pair,'intent')))!=canonical(intended)
                or canonical(private_read(self._path(pair,'result')))!=canonical(result)
                or self._path(pair,'failed').exists() or self._path(pair,'failed').is_symlink()):
            raise fail('recovery_operator_terminal_drift','Protected operator terminal provenance changed during final reads')
        snapshot=base['payload']['snapshot']
        return dict(pair,status='successful',terminal_id=payload['terminal']['plan_id'],terminal_receipt_sha256=digest(current),
            execution_plan_id=base['plan_id'],execution_plan_sha256=base['sha256'],evidence_sha256=base['payload']['evidence_sha256'],
            machine_uuid=base['payload']['machine_uuid'],computer_sid=base['payload']['computer_sid'],computer_ou=snapshot['computer_ou'],domain=DOMAIN,
            employee_guid=snapshot['user']['object_guid'],employee_sid=snapshot['user']['object_sid'],finished_at=self.planning.clock().isoformat())

    def status(self,failed_run_id,computer_guid):
        pair=_pair(failed_run_id,computer_guid)
        for suffix in ('failed','result','intent'):
            path=self._path(pair,suffix)
            if path.exists() or path.is_symlink():return private_read(path)
        return dict(pair,status='not_started')
