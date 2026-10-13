"""Fixed component execution, with fresh controller verification by its caller."""
from __future__ import annotations

import os
from pathlib import Path
import subprocess

from .ad_directory import fail
from .setup_events import SetupEventStore
from .setup_plans import private_create, private_read


def catalog_selection(catalog, *, profile='base', component_id=''):
    if component_id:
        components = [catalog.component(component_id)]
        if components[0]['execution'].get('adapter'):
            raise fail('component_protected', 'Critical domain roles cannot be independently executed')
    else:
        components = [catalog.component(i) for i in catalog.profile(profile)['components']]
    software = [c for c in components if c['execution']['operation'] == 'software']
    keys = [c['preflight']['artifact_key'] for c in software]
    return {'execution_components': components, 'selected_software_components': keys,
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
        # The playbook independently derives selection from the same published registry.
        private_create(job.job_dir/'component-vars.json', variables)
        command = [str(self.settings.ansible_playbook_path), '-i', payload['machine']['ip']+',', '-u', 'ansible',
                   '--private-key='+str(self.settings.private_key_file),
                   '--ssh-common-args=-o UserKnownHostsFile='+str(self.settings.known_hosts_file)
                   +' -o StrictHostKeyChecking=yes -o ProxyCommand=none -o IdentitiesOnly=yes -o ConnectTimeout=10',
                   '-e', '@'+str(job.job_dir/'component-vars.json'),
                   str(self.settings.ansible_project_dir/'playbooks/04-setup-component.yml')]
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
