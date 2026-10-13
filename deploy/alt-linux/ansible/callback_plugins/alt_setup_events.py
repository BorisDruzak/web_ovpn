"""Safe stdout callback; raw results and Ansible task names are never displayed."""
import os
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

    def v2_playbook_on_start(self, playbook):
        self.store.append(self.job_id, {'schema_version': 1, 'component_id': self.component['id'],
            'component_version': self.component['version'], 'stage': 'apply', 'task_id': 'component',
            'type': 'component_start', 'changed': False, 'code': 'started'})

    def _event(self, result, event_type):
        # Callback exceptions alone do not make Ansible fail; its caller checks
        # the completion journal independently before trusting the result.
        self.store.append(self.job_id, safe_task_event(result, component=self.component, event_type=event_type))

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
        if not self.failed and all(not stats.summarize(host)['failures'] and not stats.summarize(host)['unreachable']
                                   for host in stats.processed):
            self.store.append(self.job_id, {'schema_version': 1, 'component_id': self.component['id'],
                'component_version': self.component['version'], 'stage': 'complete', 'task_id': 'component',
                'type': 'component_completed', 'changed': False, 'code': 'completed'})
