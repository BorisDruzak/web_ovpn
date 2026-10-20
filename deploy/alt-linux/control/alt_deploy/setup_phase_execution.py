"""One fixed Ansible boundary; no protected adapter in later phases."""
from __future__ import annotations

import copy
import hashlib
import os
import time
from pathlib import Path

from .ad_directory import fail
from .full_workflow import archived_workflow
from .setup_phases import WorkflowPhaseStore,PHASE_CODES
from .setup_plans import digest,private_create,private_read
from .setup_events import SetupEventStore
from .setup_phase_probe import WorkflowReadinessProbe
from .workflow_phase_process import run_claimed,child_quiet


class WorkflowPhaseExecutor:
    def __init__(self,settings,*,readiness=None,runner=None):
        self.settings=settings;self.readiness=readiness or WorkflowReadinessProbe(settings)
        self.runner=runner or run_claimed

    def run(self,job,phase,claim):
        from .setup_worker import process_identity
        from .krfb_program import target_program
        from .kwallet_runtime import specification
        from .final_dns_policy import CODES
        store=WorkflowPhaseStore(self.settings);job=store._actor(job);records=store.records(job)
        if (phase not in ('user','final_dns') or job.state not in ('preflight','running')
                or records[phase]['claim']!=claim or records[phase]['result'] is not None
                or claim['process_identity']!=process_identity(self.settings)):
            raise fail('workflow_readiness_unverified','The original phase authority differs')
        ready,prepared=self.readiness.prepare(job,phase)
        if digest(ready)!=claim['readiness_sha256']:
            raise fail('workflow_readiness_changed','The target changed after its one-shot phase claim')
        payload=job.request['plan']['payload'];workflow=archived_workflow(payload)
        spec=next(p for p in workflow['phases'] if p['id']==phase)
        context={'schema_version':1,'kind':'complete_workstation','phase':phase,'job_id':job.job_id,
            'claim_sha256':digest(claim),'plan_sha256':job.status['plan_sha256'],'machine_uuid':job.machine_uuid,
            'source_sha256':payload['source_sha256'],'workflow_policy_sha256':workflow['policy_sha256'],
            'policy_sha256':digest(workflow['policy']['vnc' if phase=='user' else 'final_dns'])}
        result_path=job.job_dir/('phase-'+phase+'-result.json')
        if result_path.exists() or result_path.is_symlink():raise fail('workflow_result_unverified','The phase already has a retained result')
        variables={'setup_job_id':job.job_id,'machine_uuid':job.machine_uuid,'final_hostname':payload['machine']['hostname'],
            'assigned_domain_user':payload['user']['upn'],'domain_test_user':payload['user']['upn'],
            'software_profile':'workstation-full-v1','remote_access_profile':'krfb','setup_workflow':workflow,
            'alt_setup_workflow_context':context,'setup_phase_result_file':str(result_path),
            'setup_phase_user_uid':ready['scope']['uid'],'setup_phase_user_gid':ready['scope']['gid'],
            'setup_phase_home_sha256':ready['scope']['home_sha256']}
        if phase=='user':
            request=copy.deepcopy(prepared['krfb_request']);observed=prepared['krfb_observation']
            request.update(context=context,expected_snapshot_sha256=observed['snapshot']['snapshot_sha256'],
                expected_policy_snapshot_sha256=observed['policy']['snapshot_sha256'],
                configuration_template_sha256=observed['configuration_template_sha256'],
                autostart_template_sha256=observed['autostart_template_sha256'])
            program=target_program(apply=True)
            if hashlib.sha256(program.encode()).hexdigest()!=ready['observation']['helpers']['krfb']:
                raise fail('workflow_readiness_changed','The fixed KRFB program changed')
            variables.update(kwallet_repair_user=payload['user']['upn'],
                kwallet_repair_new_name=specification(self.settings.ansible_project_dir)['wallet_name'],
                alt_setup_wallet_readiness=prepared['wallet'],
                alt_setup_krfb_runtime_evidence={'schema_version':1,'program':program,
                    'program_sha256':ready['observation']['helpers']['krfb'],'request':request},
                **prepared['private_krfb_variables'])
        else:
            variables.update(alt_setup_final_dns_request=dict(workflow['policy']['final_dns'],
                schema_version=1,machine_uuid=job.machine_uuid,hostname=payload['machine']['hostname']),
                alt_setup_final_dns_readiness=prepared['dns'])
        from .helper_diagnostics import binding,callback_bindings
        names={'desktop.kwallet_repair':'wallet','remote.krfb':'krfb'} if phase=='user' else {'network.final_dns':'dns'}
        diagnostics={name:binding(job,name,context,ready['observation']['helpers'][helper]) for name,helper in names.items()}
        variables['alt_setup_helper_diagnostics']=diagnostics
        variables_path=job.job_dir/('phase-'+phase+'-vars.json');private_create(variables_path,variables)
        command=[str(self.settings.ansible_playbook_path),'-i',payload['machine']['ip']+',','-u','ansible',
            '--private-key='+str(self.settings.private_key_file),
            '--ssh-common-args=-o UserKnownHostsFile='+str(self.settings.known_hosts_file)+
            ' -o StrictHostKeyChecking=yes -o ProxyCommand=none -o IdentitiesOnly=yes -o ConnectTimeout=10',
            '-e','@'+str(variables_path),str(self.settings.ansible_project_dir/'playbooks/05-setup-workflow-phase.yml')]
        env=os.environ.copy()
        from .configure import KRFB_NETWORK_CONFIRMATION_VARIABLE
        for name in ('ALT_SETUP_FIRST_JOIN_BINDING',KRFB_NETWORK_CONFIRMATION_VARIABLE):
            env.pop(name,None)
        first=next(c for c in payload['components'] if c['id']==spec['component_ids'][0])
        env.update(ANSIBLE_CONFIG=str(self.settings.ansible_project_dir/'ansible.cfg'),
            ANSIBLE_STDOUT_CALLBACK='alt_setup_events',ANSIBLE_CALLBACK_PLUGINS=str(self.settings.ansible_project_dir/'callback_plugins'),
            ANSIBLE_CALLBACKS_ENABLED='',ALT_DEPLOY_STATE_ROOT=str(self.settings.state_root),
            ALT_DEPLOY_SERVICE_USER=self.settings.service_user,ALT_SETUP_JOB_ID=job.job_id,
            ALT_SETUP_COMPONENT_ID=first['id'],ALT_SETUP_COMPONENT_VERSION=str(first['version']),
            ALT_SETUP_FULL_SETUP='true',PYTHONPATH=str(Path(__file__).resolve().parent.parent))
        import json
        env['ALT_SETUP_HELPER_DIAGNOSTICS']=json.dumps(callback_bindings(diagnostics),sort_keys=True)
        events=SetupEventStore(self.settings);cursor=len(events._read(job))
        rc=self.runner(self.settings,job,phase,claim,command,env=env,timeout=spec['budget_seconds'],cwd=self.settings.ansible_project_dir)
        if rc:raise fail('workflow_phase_command_failed','The original fixed phase did not complete')
        outcome=private_read(result_path)
        if (set(outcome)!={'schema_version','context','status','code'} or type(outcome['schema_version']) is not int
                or outcome['schema_version']!=1 or outcome['context']!=context
                or outcome['status'] not in ('applied_verified','rolled_back_verified')
                or phase=='user' and (outcome['status']!='applied_verified' or outcome['code'] is not None)
                or phase=='final_dns' and outcome['code'] not in CODES):
            raise fail('workflow_result_unverified','The original phase completion record differs')
        journal=events._read(job)[cursor:]
        completed={e['component_id'] for e in journal if e['type']=='component_completed'}
        if (not set(spec['component_ids'])<=completed or any(e['type'] in ('task_failed','task_unreachable') for e in journal)):
            raise fail('workflow_result_unverified','The original phase journal is incomplete')
        if not child_quiet(self.settings,job,phase,claim):
            raise fail('workflow_target_processes_unverified','The acknowledged phase child has not stopped')
        # Real independent read-only proof follows the mutator's exit. A lost
        # GUI/SSH reply here consumes the phase instead of rerunning any role.
        after,proof,direct=self._independent_proof(job,phase,claim,ready,payload)
        if outcome['status']=='applied_verified' and phase=='final_dns':
            if proof['verification']['components']['network.final_dns']['status']!='compliant':
                raise fail('workflow_final_verification_failed','Final active and persistent resolver verification failed')
        return {'status':outcome['status'],'changed':any(e['changed'] for e in journal),
            'code':None if outcome['status']=='applied_verified' else outcome['code'],
            'verification_sha256':digest({'readiness':after,'components':proof['verification'],'direct':direct,'outcome':outcome}),
            'target_processes_absent':True}

    def _independent_proof(self,job,phase,claim,ready,payload):
        """Recollect only a classified RFB timeout, never the original effects."""
        from .workflow_read_deadline import read_deadline,read_timeout
        from .krfb_runtime import DIRECT_POLICY,probe_krfb
        import json,sys
        started=time.monotonic()
        stages={'readiness','authority','components','directory','policy','wallet','dns','vnc_policy',
                'templates','graphical_session','helper_binding','binding','deadline','identity','components_result','direct_vnc'}
        def log(attempt,stage,code):
            # Fixed enums and existing authority digests only. Never exception
            # text, target output, private preparation or environment values.
            safe=code if code is None or code in PHASE_CODES else 'workflow_readiness_unverified'
            print(json.dumps({'kind':'workflow_independent_proof','job_id':job.job_id,'phase':phase,
                'claim_sha256':digest(claim),'plan_sha256':job.status['plan_sha256'],
                'source_sha256':payload['source_sha256'],'attempt':attempt,'stage':stage,
                'code':safe,'elapsed_seconds':round(time.monotonic()-started,3)}),file=sys.stderr,flush=True)
        with read_deadline(180):
            for attempt in range(1,4):
                stage='readiness';log(attempt,stage,None)
                try:
                    after,proof=self.readiness.prepare(job,phase)
                    stage='identity'
                    if (after['scope']!=ready['scope'] or any(after['observation'][k]!=ready['observation'][k]
                            for k in ('boot_id','session_sha256'))):
                        raise fail('workflow_identity_changed','The original phase identity or graphical session changed')
                    stage='components_result'
                    expected={c['id'] for c in payload['components']} - {'network.final_dns'}
                    rejected=False
                    for identifier in sorted(expected):
                        result=proof['verification']['components'].get(identifier)
                        status=result.get('status') if isinstance(result,dict) else None
                        if status=='compliant':continue
                        rejected=True
                        safe_status=status if status in ('unknown','missing','drifted','blocked','not_selected') else 'unknown'
                        print(json.dumps({'kind':'workflow_component_verification_rejected',
                            'job_id':job.job_id,'phase':phase,'component_id':identifier,'status':safe_status}),
                            file=sys.stderr,flush=True)
                    if rejected:
                        raise fail('workflow_user_verification_failed','Fresh user and system component verification failed')
                    stage='direct_vnc'
                    machine=self.readiness.setup.machines.resolve(job.machine_uuid)
                    direct=probe_krfb(self.settings,machine,payload['user'],DIRECT_POLICY,
                        expected_source=payload['source_sha256'],expected_ssh_binding=payload['ssh_binding'],
                        expected_boot_id=ready['observation']['boot_id'],
                        expected_session_sha256=ready['observation']['session_sha256'])
                    if direct['ready'] is not True:
                        raise fail('workflow_user_verification_failed','Direct selected-user VNC authentication is unverified')
                    read_timeout(1)
                    log(attempt,stage,None)
                    return after,proof,direct
                except Exception as error:
                    details=getattr(error,'details',{})
                    observed=details.get('readiness_stage') if isinstance(details,dict) else None
                    if stage=='readiness' and observed in stages:stage=observed
                    code=getattr(error,'code','workflow_readiness_unverified');log(attempt,stage,code)
                    if code!='krfb_probe_timeout' or stage not in ('vnc_policy','direct_vnc') or attempt==3:raise
                    # Discard the entire failed observation. No partial facts
                    # are accepted or combined across independent attempts.
                    time.sleep(read_timeout(1))
