"""Fixed component execution, with fresh controller verification by its caller."""
from __future__ import annotations

import os
from pathlib import Path
import subprocess

from .ad_directory import fail
from .setup_events import SetupEventStore
from .setup_plans import private_create, private_read


class SetupExecutionEngine:
    """Worker-owned dispatch. Waiting continuations only collect fresh evidence."""
    def __init__(self, settings, *, setup=None, components=None, jobs=None, events=None,
                 component_executor=None,phase_executor=None,workflow_probe=None):
        from .setup_jobs import SetupJobRepository
        self.settings = settings
        self.setup = setup
        self.components = components
        self._setup_injected = setup is not None
        self._components_injected = components is not None
        self.jobs = jobs or SetupJobRepository(settings)
        self.events = events or SetupEventStore(settings)
        self.component_executor = component_executor
        self.phase_executor=phase_executor
        self.workflow_probe=workflow_probe

    def _services(self, operation):
        if operation == 'component' and not self._components_injected:
            from .component_setup import ComponentSetupService
            self.components = ComponentSetupService(self.settings, setup=self.setup if self._setup_injected else None)
        if operation == 'full_setup' and not self._setup_injected:
            from .setup import SetupService
            self.setup = SetupService(self.settings)

    def _persist(self, job, result, state, stage):
        from .setup_jobs import publish
        from .assignments import assert_safe_payload
        assert_safe_payload(result)
        result.update(state=state, stage=stage)
        publish(job.job_dir/'execution.json', result)
        self.jobs.transition(job.job_id, state, stage={'id': stage})
        return result

    def _post(self, job):
        if job.request['operation'] == 'component':
            return self.components.observe_result(job.request['plan'], own_job_id=job.job_id)
        return self.setup._observe_job_result(job.request['plan'], own_job_id=job.job_id)

    def _verified(self, job, result, observed, verification):
        from .component_verification import valid_evidence, package_health_ready
        if not valid_evidence(observed) or verification['machine_uuid'] != job.machine_uuid:
            raise fail('setup_post_verification_failed', 'Fresh workstation evidence is invalid')
        result['verification'] = verification
        selected = result['components']
        for identifier in selected:
            selected[identifier]['verification'] = verification['components'][identifier]
        outcomes = [verification['components'][i] for i in selected]
        reboot_unproven = result['reboot_required'] and result['original_boot_id'] is None
        result['reboot_required'] = bool(result['reboot_required'] and
            (reboot_unproven or observed['machine']['boot_id'] == result['original_boot_id']))
        if reboot_unproven or not package_health_ready(observed) or verification['overall_status'] == 'unknown_requires_review':
            state = 'unknown_requires_review'
        elif result['reboot_required']:
            state = 'waiting_reboot'
        elif (not observed['user']['home_exists'] and
              any(c.get('operator_action') == 'first_domain_login' for c in outcomes)):
            state = 'waiting_first_login'
        elif all(c['status'] == 'compliant' for c in outcomes):
            state = 'successful'
        else:
            state = 'degraded'
        result['operator_action_required'] = (state != 'successful' or verification['operator_action_required'])
        result['finished_at'] = self.jobs.clock().isoformat()
        return self._persist(job, result, state, state)

    def execute(self, job_id):
        from .setup_confirmations import confirmed_network
        job = self.jobs.get(job_id)
        with confirmed_network(job.request['plan']):
            return self._execute(job_id)

    def _execute(self, job_id):
        from .component_catalog import ComponentCatalog
        from .errors import ControlError
        job = self.jobs.get(job_id)
        if job.state != 'preflight' or not job.status['claimed']:
            if job.state in ('successful', 'degraded', 'failed', 'waiting_reboot',
                             'waiting_first_login', 'unknown_requires_review'):
                return private_read(job.job_dir/'execution.json')
            raise fail('setup_job_not_claimed', 'Dispatch requires the original worker preflight claim')
        plan = job.request['plan']
        payload = plan['payload']
        targets = [payload['component']] if job.request['operation'] == 'component' else payload['components']
        result = {'schema_version': 2, 'operation': 'setup_execution', 'job_id': job_id,
                  'machine_uuid': job.machine_uuid, 'plan_id': plan['plan_id'], 'plan_sha256': plan['sha256'],
                  'components': {c['id']: {'version': c['version'], 'changed': False,
                                          'verification': None} for c in targets},
                  'original_boot_id': None, 'reboot_required': False,
                  'operator_action_required': True, 'error_code': None,
                  'created_at': self.jobs.clock().isoformat(), 'finished_at': None}
        dispatched = False
        stage = 'preflight'
        try:
            self._services(job.request['operation'])
            if job.request['operation'] == 'component':
                current = self.components.validate(plan['plan_id'], plan['sha256'], own_job_id=job_id)
                result['original_boot_id'] = current['observed']['machine']['boot_id']
                if current['action'] == 'noop':
                    self.jobs.transition(job_id, 'verifying', stage={'id': 'verify'})
                else:
                    stage = payload['component']['id']+'.apply'
                    self.jobs.transition(job_id, 'running', stage={'id': stage})
                    dispatched = True
                    result['components'][payload['component']['id']]['changed'] = None
                    executor = self.component_executor or ComponentExecutor(self.settings,
                                  ComponentCatalog.load(self.settings.ansible_project_dir))
                    applied = executor.run(plan, job)
                    if (not isinstance(applied, dict) or applied.get('status') != 'applied'
                            or type(applied.get('changed')) is not bool
                            or type(applied.get('reboot_required')) is not bool):
                        raise fail('setup_component_result_invalid', 'Component result is invalid')
                    result['components'][payload['component']['id']]['changed'] = applied['changed']
                    result['reboot_required'] = applied['reboot_required']
                    self.jobs.transition(job_id, 'verifying', stage={'id': 'verify'})
            else:
                current = self.setup._validate_job_plan(plan, own_job_id=job_id)
                result['original_boot_id'] = current['component_observed']['machine']['boot_id']
                self.jobs.transition(job_id, 'running', stage={'id': 'full_setup.apply'})
                stage = 'full_setup.apply'
                dispatched = True
                for component in result['components'].values():
                    component['changed'] = None
                from .setup_jobs import setup_job_execution
                with setup_job_execution(self.settings, job_id, plan):
                    run = self.setup._execute_locked(plan['plan_id'], plan['sha256'], own_job_id=job_id)
                result['legacy_run'] = run
                result['reboot_required'] = run['reboot_required']
                events = self.events._read(job)
                for identifier, component in result['components'].items():
                    component['changed'] = any(e['component_id'] == identifier and e['changed'] for e in events)
                if 'workflow' in payload:
                    return self._complete_system(self.jobs.get(job_id),result,run)
                self.jobs.transition(job_id, 'verifying', stage={'id': 'verify'})
            stage = 'verify'
            observed, verification = self._post(job)
            return self._verified(job, result, observed, verification)
        except Exception as exc:
            code = exc.code if isinstance(exc, ControlError) else 'setup_execution_unverified'
            # Error messages/details and Ansible output never enter the safe projection.
            result['error_code'] = code
            try:
                journal = self.events._read(job)
                task_events = [e for e in journal if e['type'].startswith('task_')]
                if task_events:
                    failures = [e for e in task_events if e['type'] in ('task_failed', 'task_unreachable')]
                    # Preserve the originating failure, before generic rescue/finalizer tasks.
                    last = failures[0] if failures else task_events[-1]
                    stage = last['component_id']+'.'+last['stage']
                for identifier, component in result['components'].items():
                    if any(e['component_id'] == identifier and e['changed'] for e in journal):
                        component['changed'] = True
            except Exception:
                journal = []
            if isinstance(exc, ControlError) and job.request['operation'] == 'full_setup':
                from .setup import RUN_RE
                run_id = str(exc.details.get('run_id', ''))
                if RUN_RE.fullmatch(run_id):
                    result['legacy_error_run_id'] = run_id
            result['finished_at'] = self.jobs.clock().isoformat()
            no_change = not dispatched
            if dispatched and job.request['operation'] == 'component':
                tasks = [e for e in journal if e['type'].startswith('task_')]
                no_change = (bool(tasks) and tasks[-1]['code'] == 'component_preflight_failed'
                             and all(e['stage'] == 'preflight' and e['changed'] is False for e in tasks))
            if no_change:
                for component in result['components'].values():
                    component['changed'] = False
            if dispatched:
                # A timeout on the controller does not prove a remote transaction stopped.
                try:
                    if job.request['operation'] == 'component':
                        machine = self.components.setup.machines.resolve(job.machine_uuid)
                        facts = self.components.probe.observe(machine, payload['user'], payload['components'],
                                                              profile_id=payload['profile']['id'])
                    else:
                        from .component_probe import ComponentProbe
                        machine = self.setup.machines.resolve(job.machine_uuid)
                        facts = (self.setup.component_probe or ComponentProbe(self.settings)).observe(
                            machine, payload['user'], payload['components'], allow_unresolved=True,
                            profile_id=payload['profile']['id'])
                    result['post_error_package_manager'] = facts['package_manager']
                    from .component_verification import _package_status
                    from .component_catalog import ComponentCatalog
                    catalog = ComponentCatalog.load(self.settings.ansible_project_dir)
                    packages = {}
                    for identifier in result['components']:
                        artifact = catalog.artifact(identifier)
                        fact = facts['components'].get(identifier, {})
                        if artifact and _package_status(artifact, fact) != 'unknown':
                            packages[identifier] = fact['packages']
                    result['post_error_packages'] = packages
                except Exception:
                    result['post_error_package_manager'] = {'status': 'unavailable'}
            return self._persist(job, result, 'failed' if no_change else 'unknown_requires_review', stage)

    def verify_continuation(self, job_id):
        from .locks import exclusive_lock
        with exclusive_lock(self.settings.lock_file):
            job = self.jobs.get(job_id)
            if job.state not in ('waiting_reboot', 'waiting_first_login'):
                raise fail('setup_continuation_not_waiting', 'Read-only continuation requires a waiting job')
            result = private_read(job.job_dir/'execution.json')
            if 'workflow' in job.status:
                # Poll/explicit verify cannot enqueue, claim, execute a role,
                # or finish pending phases through the old verifier.
                from .setup_phases import WorkflowPhaseStore
                WorkflowPhaseStore(self.settings).records(job)
                return result
            payload = job.request['plan']['payload']
            original = payload['observed'] if job.request['operation'] == 'component' else payload['component_observed']
            if (result.get('schema_version') != 2 or result.get('job_id') != job_id
                    or result.get('plan_sha256') != job.status['plan_sha256']
                    or result.get('original_boot_id') != original['machine']['boot_id']
                    or job.state == 'waiting_reboot' and result.get('reboot_required') is not True
                    or result.get('state') != job.state):
                raise fail('setup_execution_result_invalid', 'Waiting execution evidence differs')
            self._services(job.request['operation'])
            # Observe before transitioning: an unavailable target preserves its waiting state.
            observed, verification = self._post(job)
            if job.state == 'waiting_reboot' and observed['machine']['boot_id'] == result['original_boot_id']:
                return result
            if job.state == 'waiting_first_login' and not observed['user']['home_exists']:
                return result
            self.jobs.transition(job_id, 'verifying', stage={'id': 'verify'})
            return self._verified(job, result, observed, verification)

    def _complete_system(self,job,result,run):
        from .full_workflow import validate_system_result
        from .component_verification import package_health_ready,_package_status
        from .component_catalog import ComponentCatalog
        from .setup_jobs import publish
        from .setup_plans import digest
        from .setup_phases import WorkflowPhaseStore
        workflow=job.request['plan']['payload']['workflow']
        validate_system_result(run['result'],workflow)
        observed,verification=self._post(job)
        identity=self.setup._verify_identity(job.machine_uuid)
        if identity['status']!='successful' or not package_health_ready(observed):raise ValueError
        catalog=ComponentCatalog.load(self.settings.ansible_project_dir)
        for identifier in workflow['phases'][0]['component_ids']:
            artifact=catalog.artifact(identifier)
            if artifact and _package_status(artifact,observed['components'][identifier])!='compliant':raise ValueError
            result['components'][identifier]['verification']=verification['components'][identifier]
        result.update(state=job.state,stage=job.stage)
        publish(job.job_dir/'execution.json',result)
        computer=identity['computer']['objects'][0]
        proof={'status':'applied_verified','changed':any(c['changed'] is True for c in result['components'].values()),
            'code':None,'verification_sha256':digest({'run':run,'fresh':observed,'identity':identity}),
            'target_processes_absent':True,'original_boot_id':result['original_boot_id'],
            'reboot_required':result['reboot_required'],
            'computer':{k:computer[k] for k in ('object_guid','object_sid','dn','dns_hostname')}}
        WorkflowPhaseStore(self.settings).complete(job,'system',proof)
        return private_read(job.job_dir/'execution.json')

    def execute_phase(self,job_id,phase):
        """Worker-only continuation; never call the protected Setup adapter."""
        from .locks import assert_owned
        from .setup_worker import process_identity
        from .setup_phases import WorkflowPhaseStore,validate_result,PHASE_CODES
        store=WorkflowPhaseStore(self.settings);assert_owned(self.settings.lock_file)
        job=store._actor(self.jobs.get(job_id));row=store.records(job)[phase];claim=row['claim']
        if (phase not in ('user','final_dns') or job.state!='preflight' or claim is None
                or row['result'] is not None or claim['process_identity']!=process_identity(self.settings)):
            raise fail('setup_phase_consumed','Only the current original phase worker may dispatch')
        try:
            job=store.start(job,phase,claim)
            if self.phase_executor is None:
                from .setup_phase_execution import WorkflowPhaseExecutor
                self.phase_executor=WorkflowPhaseExecutor(self.settings)
            result=self.phase_executor.run(job,phase,claim)
            validate_result(job,phase,result)
        except Exception as error:
            code=getattr(error,'code','')
            if code not in PHASE_CODES:code='workflow_phase_outcome_unverified'
            result={'status':'outcome_unverified','changed':None,'code':code,'verification_sha256':None,
                    'target_processes_absent':False}
        store.complete(self.jobs.get(job_id),phase,result)
        return private_read(job.job_dir/'execution.json')

    def finalize_workflow(self,job_id):
        """Only fresh read-only proof can publish the first full completion."""
        from .setup_phases import WorkflowPhaseStore
        from .setup_jobs import publish
        from .krfb_runtime import probe_krfb,DIRECT_POLICY
        store=WorkflowPhaseStore(self.settings);job=store._actor(self.jobs.get(job_id));records=store.records(job)
        if job.state not in ('verifying','waiting_first_login'):raise fail('setup_phase_consumed','The workflow is not awaiting final proof')
        if (any(records[p]['result'] is None for p in ('system','user','final_dns'))
                or records['user']['result']['result']['status']!='applied_verified'
                or records['final_dns']['result']['result']['status'] not in ('applied_verified','rolled_back_verified')):
            raise fail('workflow_result_unverified','All original phase outcomes are required before completion')
        outcome=records['final_dns']['result'];result=private_read(job.job_dir/'execution.json')
        if set(result['components'])!={c['id'] for c in job.request['plan']['payload']['components']}:
            raise fail('workflow_result_unverified','The original complete component result differs')
        self._services('full_setup')
        if self.workflow_probe is None:
            from .setup_phase_probe import WorkflowReadinessProbe
            self.workflow_probe=WorkflowReadinessProbe(self.settings,setup=self.setup)
        state='waiting_first_login';reason='workflow_final_verification_unavailable'
        try:
            ready,prepared=self.workflow_probe.prepare(job,'final_dns')
            if ready['scope']!=records['final_dns']['claim']['readiness']['scope']:raise ValueError
            verification=prepared['verification'];expected=set(result['components'])
            rollback=outcome['result']['status']=='rolled_back_verified'
            if rollback:expected.remove('network.final_dns')
            if any(verification['components'][i]['status']!='compliant' for i in expected):raise ValueError
            machine=self.setup.machines.resolve(job.machine_uuid)
            direct=probe_krfb(self.settings,machine,job.request['plan']['payload']['user'],DIRECT_POLICY)
            if direct['ready'] is not True:raise ValueError
            result['verification']=verification
            for identifier,component in result['components'].items():component['verification']=verification['components'][identifier]
            result['reboot_required']=False
            result['operator_action_required']=rollback or verification['operator_action_required']
            result['error_code']=outcome['result']['code'] if rollback else None
            state='degraded' if rollback else 'successful';reason=None
        except Exception:
            # No mutation is retried when a GUI/transport disappears between
            # the last known phase outcome and its fresh final observation.
            result['operator_action_required']=True
        if (reason is not None and job.state=='waiting_first_login' and job.stage=='workflow.final_dns.waiting'
                and result.get('workflow',{}).get('waiting_reason')==reason):
            return result
        publish(job.job_dir/'execution.json',result)
        with self.jobs.locked():
            store._publish_status(job,state,'workflow.final_dns.'+('complete' if reason is None else 'waiting'),
                                  job.status['workflow'],outcome,waiting_reason=reason)
        return private_read(job.job_dir/'execution.json')


def catalog_selection(catalog, *, profile='base', component_id=''):
    if component_id:
        components = [catalog.component(component_id)]
        if components[0]['execution'].get('adapter'):
            raise fail('component_protected', 'Critical domain roles cannot be independently executed')
    else:
        components = [catalog.component(i) for i in catalog.profile(profile)['components']]
    software = [c for c in components if c['execution']['operation'] == 'software']
    keys = [c['preflight']['artifact_key'] for c in software]
    profile_ids = catalog.profile(profile)['components']
    if component_id:
        required = catalog.ordered([component_id], os_id='alt-kworkstation-11')
        profile_ids = list(dict.fromkeys(profile_ids + [c['id'] for c in required]))
    return {'execution_components': components, 'selected_software_components': keys,
            'profile_component_ids': profile_ids,
            'software_component_role_map': {c['preflight']['artifact_key']: c['execution']['role'] for c in software}}


class ComponentExecutor:
    def __init__(self, settings, catalog, *, runner=None):
        self.settings = settings
        self.catalog = catalog
        self.runner = runner or subprocess.run

    def run(self, plan, job):
        payload = plan['payload']
        component = self.catalog.component(payload['component']['id'])
        if (component != payload['component'] or self.catalog.fingerprint != payload['catalog_sha256']
                or job.request['plan'] != plan or job.request['operation'] != 'component'):
            raise fail('component_plan_drift', 'Confirmed component or catalog differs')
        if payload['action'] == 'noop':
            return {'schema_version': 1, 'job_id': job.job_id, 'component_id': component['id'],
                    'component_version': component['version'], 'status': 'noop', 'changed': False,
                    'reboot_required': False}
        if payload['action'] not in ('install', 'repair') or component['execution'].get('adapter'):
            raise fail('component_plan_blocked', 'Component plan is not executable')
        if component['id']=='remote.krfb' and payload['profile']['id']=='workstation-full-v1':
            raise fail('full_workflow_required','Direct KRFB can execute only in its original complete-workstation phase')
        catalog_selection(self.catalog, component_id=component['id'])
        result_path = job.job_dir/'component-result.json'
        variables = {'setup_component_id': component['id'], 'setup_component_version': component['version'],
            'setup_job_id': job.job_id, 'setup_plan_sha256': plan['sha256'], 'machine_uuid': job.machine_uuid,
            'final_hostname': payload['machine']['hostname'], 'assigned_domain_user': payload['user']['upn'],
            'domain_test_user': payload['user']['upn'], 'software_profile': payload['profile']['id'],
            'remote_access_profile': payload['binding']['remote_access_profile'],
            'setup_component_result_file': str(result_path)}
        from .configure import KRFB_ANSIBLE_CONFIRMATION_VARIABLE, KRFB_NETWORK_CONFIRMATION_VARIABLE
        if component['id'] == 'remote.krfb':
            if os.environ.get(KRFB_NETWORK_CONFIRMATION_VARIABLE) != 'true':
                raise fail('remote_access_network_restriction_unconfirmed', 'Restricted KRFB access is not confirmed')
            variables['remote_access_profile'] = 'krfb'
            variables[KRFB_ANSIBLE_CONFIRMATION_VARIABLE] = True
        playbook='04-setup-component.yml'
        diagnostics={}
        if component['id']=='desktop.kwallet_repair':
            if job.status.get('claimed') is not True or job.state not in ('preflight','running'):
                raise fail('setup_job_not_claimed','Wallet repair requires its original worker claim')
            from .kwallet_runtime import specification,validate_observation,canonical
            import hashlib
            wanted=specification(self.settings.ansible_project_dir)
            request=dict(wanted,machine_uuid=job.machine_uuid,hostname=payload['machine']['hostname'],login=payload['user']['login'])
            try:
                readiness=validate_observation(payload['observed']['components'][component['id']]['wallet_readiness'],
                                               request,payload['observed']['machine']['boot_id'])
            except Exception:raise fail('kwallet_readiness_changed','Confirmed wallet readiness is unavailable') from None
            operation=hashlib.sha256(canonical({'schema_version':1,'job_id':job.job_id,'plan_sha256':plan['sha256'],
                'machine_uuid':job.machine_uuid,'component_id':component['id'],'source_sha256':payload['source_sha256']})).hexdigest()
            variables.update(kwallet_repair_user=payload['user']['upn'],kwallet_repair_new_name=wanted['wallet_name'],
                alt_setup_wallet_readiness=readiness,alt_setup_wallet_component_context={
                    'schema_version':1,'kind':'component_wallet_repair','job_id':job.job_id,'component_id':component['id'],
                    'plan_sha256':plan['sha256'],'machine_uuid':job.machine_uuid,'source_sha256':payload['source_sha256'],
                    'operation_sha256':operation})
            playbook='06-kwallet-empty-name-repair.yml'
            from .helper_diagnostics import binding
            diagnostics={component['id']:binding(job,component['id'],variables['alt_setup_wallet_component_context'],wanted['helper_sha256'])}
            variables['alt_setup_helper_diagnostics']=diagnostics
        # The playbook independently derives selection from the same published registry.
        private_create(job.job_dir/'component-vars.json', variables)
        command = [str(self.settings.ansible_playbook_path), '-i', payload['machine']['ip']+',', '-u', 'ansible',
                   '--private-key='+str(self.settings.private_key_file),
                   '--ssh-common-args=-o UserKnownHostsFile='+str(self.settings.known_hosts_file)
                   +' -o StrictHostKeyChecking=yes -o ProxyCommand=none -o IdentitiesOnly=yes -o ConnectTimeout=10',
                   '-e', '@'+str(job.job_dir/'component-vars.json'),
                   str(self.settings.ansible_project_dir/'playbooks'/playbook)]
        env = os.environ.copy()
        env['ANSIBLE_CONFIG'] = str(self.settings.ansible_project_dir/'ansible.cfg')
        env['ANSIBLE_STDOUT_CALLBACK'] = 'alt_setup_events'
        env['ANSIBLE_CALLBACK_PLUGINS'] = str(self.settings.ansible_project_dir/'callback_plugins')
        env['ANSIBLE_CALLBACKS_ENABLED'] = ''
        env['ALT_DEPLOY_STATE_ROOT'] = str(self.settings.state_root)
        env['ALT_DEPLOY_SERVICE_USER'] = self.settings.service_user
        env['ALT_SETUP_JOB_ID'] = job.job_id
        env['ALT_SETUP_COMPONENT_ID'] = component['id']
        env['ALT_SETUP_COMPONENT_VERSION'] = str(component['version'])
        env['PYTHONPATH'] = str(Path(__file__).resolve().parent.parent)
        env.pop(KRFB_NETWORK_CONFIRMATION_VARIABLE, None)
        env.pop('ALT_SETUP_HELPER_DIAGNOSTICS',None)
        if diagnostics:
            from .helper_diagnostics import callback_bindings
            import json
            env['ALT_SETUP_HELPER_DIAGNOSTICS']=json.dumps(callback_bindings(diagnostics),sort_keys=True)
        log = job.job_dir/'ansible.log'
        try:
            with log.open('x', encoding='utf-8') as output:
                os.chmod(log, 0o600)
                completed = self.runner(command, shell=False, stdout=output, stderr=subprocess.STDOUT,
                    text=True, timeout=payload['execution_budget_seconds'], check=False,
                    cwd=self.settings.ansible_project_dir, env=env)
        except subprocess.TimeoutExpired as exc:
            raise fail('setup_component_timeout', 'Component worker exceeded its execution budget') from exc
        except OSError as exc:
            raise fail('setup_component_execution_failed', 'Component worker could not execute') from exc
        if completed.returncode != 0:
            raise fail('setup_component_execution_failed', 'Component execution failed; inspect safe events')
        try:
            result = private_read(result_path)
            expected = {'schema_version': 1, 'job_id': job.job_id, 'plan_sha256': plan['sha256'],
                        'machine_uuid': job.machine_uuid, 'component_id': component['id'],
                        'component_version': component['version'], 'status': 'applied', 'reboot_required': False}
            if set(result) != set(expected) or any(result[k] != v for k, v in expected.items() if k != 'reboot_required'):
                raise ValueError
            if (type(result['reboot_required']) is not bool or type(result['component_version']) is not int
                    or type(result['schema_version']) is not int):
                raise ValueError
        except Exception as exc:
            raise fail('setup_component_result_invalid', 'Component worker has no valid completion evidence') from exc
        events = SetupEventStore(self.settings)._read(job)
        if (not events or events[0]['type'] != 'component_start' or events[-1]['type'] != 'component_completed'
                or any(e['type'] in ('task_failed', 'task_unreachable') for e in events)):
            raise fail('setup_component_result_invalid', 'Component completion journal is incomplete or failed')
        result['changed'] = any(e['changed'] for e in events)
        return result
