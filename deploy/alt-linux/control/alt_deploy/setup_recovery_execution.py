"""Production recovery composition and one-way execution; caller owns approval.

No plan creation or implicit authority. Each genuine component owns its lock,
protected inputs, fixed operation and permanent attempt exclusion. This layer
records phase progress and stops on the first failed/uncertain observation.
"""
from __future__ import annotations
from pathlib import Path
from .ad_directory import fail
from .locking import exclusive_lock
from .setup_plans import digest, private_read
from .setup_runtime import source_fingerprint
from .setup_recovery import _pair
from .setup_recovery_controller_backup import RecoveryControllerBackup
from .setup_recovery_prepare import RecoveryPreparationCoordinator
from .setup_recovery_services_runtime import RecoveryServicesRuntime
from .setup_recovery_service_gate import RecoveryServiceGate
from .setup_recovery_provider import RecoveryPasswordProvider
from .setup_recovery_postwrite import RecoveryPostwriteState
from .setup_recovery_import_runtime import RecoveryImportRuntime
from .setup_recovery_kerberos_runtime import RecoveryKerberosRuntime
from .setup_recovery_sssd_policy_runtime import RecoverySSSDPolicyRuntime
from .setup_recovery_startup_authorization import RecoveryStartupAuthorization
from .setup_recovery_sssd_start_runtime import RecoverySSSDStartRuntime
from .setup_recovery_native_authorization import RecoveryNativeAuthorization
from .setup_recovery_native_runtime import RecoveryNativeRuntime
from .setup_recovery_user_authorization import RecoveryUserAuthorization
from .setup_recovery_user_runtime import RecoveryUserRuntime
from .setup_recovery_terminal_runtime import RecoveryTerminalRuntime


class _GuardedObject:
    """Delegate existing stores/readers without changing their lock ownership."""
    def __init__(self,wrapped,guard,methods=()):
        self.wrapped=wrapped;self.guard=guard;self.methods=frozenset(methods)
    def __getattr__(self,name):
        value=getattr(self.wrapped,name)
        if name not in self.methods:return value
        def guarded(*args,**kwargs):
            self.guard();result=value(*args,**kwargs);self.guard();return result
        return guarded
    def __call__(self,*args,**kwargs):
        self.guard();result=self.wrapped(*args,**kwargs);self.guard();return result


class RecoveryExecutionCoordinator:
    def __init__(self,planning,*,startup_plan_id,confirmed_startup_sha,terminal_authorization,identity,operator_guard):
        if not callable(terminal_authorization) or not callable(identity) or not callable(operator_guard):
            raise ValueError('Explicit operator/terminal authority and fresh identity required')
        self.planning=planning;self.settings=planning.settings;self.operator_guard=operator_guard
        self.fingerprint=self._fingerprint
        self.preparation=RecoveryPreparationCoordinator(planning)
        preparation=self.preparation
        preparation.plans=_GuardedObject(preparation.plans,self._operator_check,('load',))
        preparation.gate.plans=preparation.plans
        preparation.attempts=_GuardedObject(preparation.attempts,self._operator_check,('reserve',))
        preparation.fresh_check=_GuardedObject(preparation.fresh_check,self._operator_check)
        preparation.gate.fresh_check=preparation.fresh_check
        preparation.controller.fresh_check=preparation.fresh_check
        credentials=_GuardedObject(preparation.credentials,self._operator_check,('create',))
        preparation.credentials=credentials
        preparation.gate.credentials=credentials
        preparation.controller.credentials=credentials
        preparation.runtime.credentials=credentials
        runtime=RecoveryServicesRuntime(self.settings,credentials=self.preparation.credentials)
        self.services=RecoveryServiceGate(self.settings,self.preparation.gate,runtime=runtime)
        self.provider=RecoveryPasswordProvider(self.settings,directory=planning.directory,
            credentials=self.preparation.credentials,fresh_check=self.preparation.fresh_check,
            prewrite=self.services,fingerprint=self.fingerprint,clock=planning.clock)
        self.postwrite=RecoveryPostwriteState(service_gate=self.services,directory=planning.directory,fingerprint=self.fingerprint)
        self.importer=RecoveryImportRuntime(self.settings,postwrite=self.postwrite)
        self.kerberos=RecoveryKerberosRuntime(import_runtime=self.importer)
        self.policy=RecoverySSSDPolicyRuntime(kerberos_runtime=self.kerberos)
        self.startup_authorization=RecoveryStartupAuthorization(preparation=self.preparation,postwrite=self.postwrite,
            startup_plan_id=startup_plan_id,confirmed_startup_sha=confirmed_startup_sha)
        self.startup=RecoverySSSDStartRuntime(policy_runtime=self.policy,authorization=self.startup_authorization)
        native_authority=RecoveryNativeAuthorization(startup_authorization=self.startup_authorization,startup_runtime=self.startup)
        self.native=RecoveryNativeRuntime(startup_runtime=self.startup,authorization=native_authority)
        user_authority=RecoveryUserAuthorization(native_runtime=self.native)
        self.user=RecoveryUserRuntime(native_runtime=self.native,authorization=user_authority)
        self.terminal=RecoveryTerminalRuntime(user_runtime=self.user,authorization=terminal_authorization,identity=identity)
        self.provider.plans=_GuardedObject(self.provider.plans,self._operator_check,('load',))
        # Check exact top-level authority at the final fixed process boundary,
        # including local controller backup and LDAP as well as SSH workers.
        for component in (preparation.controller,preparation.runtime,self.services.runtime,self.provider,
                self.importer,self.kerberos,self.policy,self.startup,self.native,self.user,self.terminal):
            component.runner=self._guarded_runner(component.runner)

    def _operator_check(self):
        if self.operator_guard() is False:
            raise fail('recovery_operator_approval_invalid','Exact operator approval is no longer valid')

    def _fingerprint(self):
        self._operator_check()
        result=source_fingerprint(self.settings.ansible_project_dir,Path(__file__).parent)
        self._operator_check()
        return result

    def _guarded_runner(self,runner):
        def guarded(*args,**kwargs):
            self._operator_check()
            result=runner(*args,**kwargs)
            self._operator_check()
            return result
        return guarded

    def _path(self,pair,suffix):
        return self.planning.attempts._path(**pair,suffix='.execution-coordinator-'+suffix+'.json')

    def _guard(self,plan):
        self._operator_check()
        if (self.planning.plans.load(plan['plan_id'],plan['sha256'])!=plan
                or self.fingerprint()!=plan['payload']['snapshot']['prerequisites']['source_sha256']):
            raise fail('recovery_execution_drift','Exact protected plan and deployed source must remain current')

    def _service_args(self,plan,pair):
        credentials=self.preparation.credentials;payload=plan['payload']
        with exclusive_lock(self.settings.lock_file):
            self._guard(plan)
            if self.preparation.fresh_check(payload)!=payload['snapshot']:raise ValueError
            claim=private_read(self.planning.attempts.claim_path(**pair))
            identity=credentials._reservation(**pair)
            document=private_read(credentials.path(**pair))
            ready=private_read(credentials._ready_path(**pair))
            sealed=dict(claim_sha256=digest(claim),sealed_sha256=document['sealed_sha256'])
            if (claim['plan_id']!=plan['plan_id'] or claim['plan_sha256']!=plan['sha256']
                    or identity['plan_sha256']!=plan['sha256'] or identity['claim_sha256']!=sealed['claim_sha256']
                    or ready!=dict(schema_version=1,claim_sha256=sealed['claim_sha256'],
                        sealed_sha256=sealed['sealed_sha256'],document_sha256=digest(document))):raise ValueError
            password=credentials.open(**pair)
            if (private_read(credentials.path(**pair))!=document or private_read(credentials._ready_path(**pair))!=ready
                    or credentials._reservation(**pair)!=identity
                    or self.preparation.fresh_check(payload)!=payload['snapshot']):raise ValueError
            self._guard(plan)
            return payload,claim,sealed,password

    def status(self,failed_run_id,computer_guid):
        pair=_pair(failed_run_id,computer_guid)
        for suffix in ('failed','successful'):
            path=self._path(pair,suffix)
            if path.exists() or path.is_symlink():return private_read(path)
        path=self._path(pair,'intent')
        return private_read(path)

    def execute(self,base_plan_id,confirmed_base_sha):
        pair=None;entered=False;phase='not_started';stage='not_started';password=None
        try:
            plan=self.planning.plans.load(base_plan_id,confirmed_base_sha)
            pair=_pair(plan['payload']['failed_run_id'],plan['payload']['computer_guid'])
            with exclusive_lock(self.settings.lock_file):
                self._guard(plan)
                path=self._path(pair,'intent')
                if path.exists() or path.is_symlink():
                    raise fail('recovery_execution_replay','Recovery execution already intended; replay is prohibited')
                RecoveryControllerBackup._persist(path,dict(pair,schema_version=1,plan_id=base_plan_id,
                    plan_sha256=confirmed_base_sha,status='execution_intended',last_verified_phase=phase))
                entered=True
            def completed(name,result):
                nonlocal phase
                # Components return safe receipts; persist their digest only.
                RecoveryControllerBackup._persist(self._path(pair,'phase-'+name),dict(schema_version=1,
                    phase=name,receipt_sha256=digest(result)))
                phase=name
            stage='bind';self._guard(plan)
            completed(stage,self.startup_authorization.bind_once(base_plan_id,confirmed_base_sha))
            stage='prepare';self._guard(plan)
            completed(stage,self.preparation.prepare(base_plan_id,confirmed_base_sha))
            stage='services_prepare'
            payload,claim,sealed,password=self._service_args(plan,pair)
            completed(stage,self.services.prepare(payload,claim,sealed,password))
            stage='quiesce';self._guard(plan)
            completed(stage,self.services.quiesce(payload,claim,sealed,password))
            # Plaintext belongs only to service preparation/quiescence. The
            # reviewed password provider opens the protected credential itself.
            password=None
            steps=(('password_write',self.provider.write_once),('import',self.importer.install_once),
                ('kerberos',self.kerberos.prove_once),('policy',self.policy.install_once),
                ('startup',self.startup.start_once),('native',self.native.testjoin_once),
                ('user',self.user.check_once),('terminal',self.terminal.handoff_once))
            for stage,operation in steps:
                self._guard(plan)
                result=operation(base_plan_id,confirmed_base_sha)
                completed(stage,result)
            self._guard(plan)
            RecoveryControllerBackup._persist(self._path(pair,'successful'),dict(pair,schema_version=1,
                status='successful',last_verified_phase=phase,terminal_receipt_sha256=digest(result)))
            return result
        except Exception:
            password=None
            if entered and pair is not None:
                try:RecoveryControllerBackup._persist(self._path(pair,'failed'),dict(pair,schema_version=1,
                    status='failed',failed_stage=stage,last_verified_phase=phase,error_code='recovery_execution_failed'))
                except Exception:pass
                try:self.planning.attempts.finish(**pair,status='failed',error_code='recovery_execution_failed')
                except Exception:pass
            raise fail('recovery_execution_failed','Recovery stopped; retained intent excludes replay and requires operator review') from None
