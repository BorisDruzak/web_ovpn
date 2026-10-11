"""Domain identity bindings are deliberately separate from local assignments."""
from __future__ import annotations

from pathlib import Path
from datetime import datetime
import re
import uuid

from .ad_directory import fail
from .configure import UUID_RE
from .setup_plans import private_read, private_replace


class DomainAssignmentStore:
    def __init__(self, state_root: Path):
        self.root = state_root / 'domain-assignments'

    def _path(self, machine_uuid):
        if not UUID_RE.fullmatch(machine_uuid):
            raise fail('invalid_machine_uuid', 'Domain assignment UUID is invalid')
        return self.root / (machine_uuid + '.json')

    def get(self, machine_uuid):
        path = self._path(machine_uuid)
        if not path.exists() and not path.is_symlink():
            return None
        document = private_read(path)
        try:
            fields = {'machine_uuid', 'object_guid', 'object_sid', 'login', 'computer_ou',
                      'software_profile', 'remote_access_profile', 'schema_version', 'revision', 'run_id', 'date', 'result'}
            if (set(document) != fields or document['machine_uuid'] != machine_uuid
                    or type(document['schema_version']) is not int or document['schema_version'] != 1
                    or type(document['revision']) is not int or document['revision'] < 1
                    or document['result'] not in ('running', 'successful', 'degraded', 'failed', 'interrupted')
                    or not re.fullmatch(r'setup-run-[0-9a-f]{32}', document['run_id'])
                    or str(uuid.UUID(document['object_guid'])) != document['object_guid']
                    or datetime.fromisoformat(document['date']).tzinfo is None):
                raise ValueError
        except (KeyError, TypeError, ValueError, AttributeError) as exc:
            raise fail('assignment_invalid', 'Protected domain assignment is malformed; manual review required') from exc
        return document

    @staticmethod
    def identity_binding(machine_uuid, user, ou, software, remote):
        return {'machine_uuid': machine_uuid, 'object_guid': user['object_guid'],
                'object_sid': user.get('object_sid'), 'login': user['login'],
                'computer_ou': ou, 'software_profile': software, 'remote_access_profile': remote}

    def check(self, binding):
        existing = self.get(binding['machine_uuid'])
        if existing is not None:
            if any(existing.get(key) != value for key, value in binding.items()):
                raise fail('assignment_conflict', 'A different domain assignment exists; employee changes require a separate procedure')
            if existing.get('result') in ('running', 'failed', 'interrupted'):
                raise fail('setup_previous_run_unresolved', 'Previous setup run requires manual review before any retry')
        return existing

    def write(self, binding, *, run_id, result, date, revision):
        record = dict(binding, schema_version=1, revision=revision, run_id=run_id, date=date, result=result)
        private_replace(self._path(binding['machine_uuid']), record)
        return record
