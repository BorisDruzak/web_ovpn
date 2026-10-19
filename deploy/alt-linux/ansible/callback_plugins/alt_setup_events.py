"""Safe stdout callback; raw results and Ansible task names are never displayed."""
import os
import json
from types import SimpleNamespace

from ansible.plugins.callback import CallbackBase

from alt_deploy.config import Settings
from alt_deploy.setup_events import SetupEventStore, safe_task_event

DOCUMENTATION = '''
name: alt_setup_events
type: stdout
short_description: Allowlisted durable Setup events
description: Records only identifiers, state codes and changed booleans.
'''


class CallbackModule(CallbackBase):
    CALLBACK_VERSION = 2.0
    CALLBACK_TYPE = 'stdout'
    CALLBACK_NAME = 'alt_setup_events'

    def __init__(self):
        super().__init__()
        self.store = SetupEventStore(Settings.from_env())
        self.job_id = os.environ['ALT_SETUP_JOB_ID']
        self.component = {'id': os.environ['ALT_SETUP_COMPONENT_ID'],
                          'version': int(os.environ['ALT_SETUP_COMPONENT_VERSION'])}
        self.failed = False
        self.full = os.environ.get('ALT_SETUP_FULL_SETUP') == 'true'
        self.started = {}
        self.role_components = {}
        self.diagnostic_binding = None
        try:
            raw = os.environ.get('ALT_SETUP_FIRST_JOIN_BINDING', '')
            if raw and len(raw) <= 4096:
                self.diagnostic_binding = json.loads(raw)
        except (ValueError, TypeError):
            pass
        if self.full:
            job = self.store.jobs.get(self.job_id)
            self.role_components = {c['execution']['role']: {'id': c['id'], 'version': c['version']}
                for c in job.request['plan']['payload']['components'] if 'role' in c['execution']}

    def v2_playbook_on_start(self, playbook):
        self._start(self.component)

    def _start(self, component):
        if component['id'] in self.started:
            return
        self.started[component['id']] = component
        self.store.append(self.job_id, {'schema_version': 1, 'component_id': component['id'],
            'component_version': component['version'], 'stage': 'apply', 'task_id': 'component',
            'type': 'component_start', 'changed': False, 'code': 'started'})

    def _event(self, result, event_type):
        # Callback exceptions alone do not make Ansible fail; its caller checks
        # the completion journal independently before trusting the result.
        component = self.component
        if self.full:
            role = getattr(result._task, '_role', None)
            if role is not None:
                component = self.role_components.get(role.get_name(), self.component)
        self._start(component)
        self.store.append(self.job_id, safe_task_event(result, component=component, event_type=event_type,
            diagnostic_binding=self.diagnostic_binding))

    def v2_playbook_on_task_start(self, task, is_conditional):
        self._event(SimpleNamespace(_task=task, _result={}), 'task_start')

    def v2_runner_on_ok(self, result):
        self._event(result, 'task_ok')

    def v2_runner_on_failed(self, result, ignore_errors=False):
        self.failed = True
        self._event(result, 'task_failed')

    def v2_runner_on_unreachable(self, result):
        self.failed = True
        self._event(result, 'task_unreachable')

    def v2_runner_on_skipped(self, result):
        self._event(result, 'task_skipped')

    def v2_playbook_on_stats(self, stats):
        if (self.full or not self.failed) and all(not stats.summarize(host)['failures'] and not stats.summarize(host)['unreachable']
                                   for host in stats.processed):
            for component in self.started.values():
                self.store.append(self.job_id, {'schema_version': 1, 'component_id': component['id'],
                    'component_version': component['version'], 'stage': 'complete', 'task_id': 'component',
                    'type': 'component_completed', 'changed': False, 'code': 'completed'})
