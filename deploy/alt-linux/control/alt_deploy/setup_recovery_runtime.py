"""Fixed recovery preparation reads; no workstation mutation runner."""
from __future__ import annotations

import hashlib
import ipaddress
import os
import re
import shlex
import stat
import uuid
from pathlib import Path

from .ad_directory import fail
from .errors import ControlError
from .setup_plans import decode_state_bytes, digest
from .setup_recovery_probe import (AUTH_FILES, INCOMPATIBLE, MAX_AUTH_BYTES, MAX_TOOL_BYTES,
                                   PARAMETERS, TOOLS, _signature)
from .setup_runtime import SetupRuntime


def _read_source(path, *, owner):
    try:
        if any(not stat.S_ISDIR(parent.lstat().st_mode) for parent in path.parents):
            raise ValueError
        before = path.lstat()
        if (not stat.S_ISREG(before.st_mode) or before.st_size > 131072
                or before.st_uid not in (0, owner) or before.st_mode & 0o022):
            raise ValueError
        fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW)
        with os.fdopen(fd, 'rb') as stream:
            opened = os.fstat(stream.fileno())
            if _signature(opened) != _signature(before):
                raise ValueError
            raw = stream.read(131073)
            if (len(raw) > 131072 or len(raw) != before.st_size
                    or _signature(os.fstat(stream.fileno())) != _signature(before)):
                raise ValueError
        if _signature(path.lstat()) != _signature(before):
            raise ValueError
        return raw.decode('utf-8')
    except (OSError, ValueError, UnicodeError):
        raise fail('recovery_source_unsafe', 'Fixed recovery probe source is unsafe or unavailable') from None


def _metadata(document, *, maximum, private=False, tool=False):
    if not isinstance(document, dict) or type(document.get('present')) is not bool:
        raise ValueError
    if document['present'] is False:
        if document != {'present': False}:
            raise ValueError
        return
    fields = {'present', 'sha256', 'size', 'uid', 'gid', 'mode'} | ({'package'} if tool else set())
    if (set(document) != fields or document['uid'] != 0
            or any(type(document[key]) is not int for key in ('size', 'uid', 'gid', 'mode'))
            or not 0 <= document['size'] <= maximum or not 0 <= document['gid'] < 2**32
            or not 0 <= document['mode'] <= 0o7777 or document['mode'] & 0o022
            or (private and document['mode'] != 0o600)
            or not isinstance(document['sha256'], str) or not re.fullmatch('[0-9a-f]{64}', document['sha256'])
            or (tool and (not isinstance(document['package'], str)
                or not re.fullmatch(r'[a-zA-Z0-9+_.-]{1,80} [a-zA-Z0-9+_.:~%-]{1,100}', document['package'])))):
        raise ValueError


class RecoveryPlanningRuntime(SetupRuntime):
    def facts(self, machine):
        try:
            address = str(ipaddress.ip_address(machine.ip))
        except (ValueError, TypeError):
            raise fail('machine_missing_ip', 'Recovery requires a valid registered address') from None
        path = Path(__file__).with_name('setup_recovery_probe.py')
        script = _read_source(path, owner=Path(__file__).lstat().st_uid)
        command = ['/usr/bin/ssh', '-o', 'BatchMode=yes', '-o', 'StrictHostKeyChecking=yes',
                   '-o', 'ProxyCommand=none', '-o', 'IdentitiesOnly=yes', '-o', 'ConnectTimeout=10',
                   '-o', 'UserKnownHostsFile=' + str(self.settings.known_hosts_file),
                   '-i', str(self.settings.private_key_file), 'ansible@' + address,
                   'sudo -n /usr/bin/python3 -I -B -c ' + shlex.quote(script)]
        rc, stdout, _ = self.runner(command, environment=dict(os.environ), timeout=180)
        if rc:
            raise fail('recovery_facts_failed', 'Read-only recovery state could not be verified')
        try:
            document = decode_state_bytes(stdout.encode('utf-8'))
            fields = {'schema_version', 'uuid', 'hostname', 'files', 'tools', 'samba_version', 'samba',
                      'keytab_present', 'clock_synchronized', 'incompatible_processes'}
            if (not isinstance(document, dict) or set(document) != fields
                    or type(document['schema_version']) is not int or document['schema_version'] != 1
                    or document['uuid'] != machine.uuid or str(uuid.UUID(document['uuid'])) != document['uuid']
                    or document['hostname'] != machine.hostname
                    or type(document['keytab_present']) is not bool or type(document['clock_synchronized']) is not bool
                    or set(document['files']) != set(AUTH_FILES) or set(document['tools']) != set(TOOLS)
                    or not isinstance(document['samba_version'], str)
                    or not re.fullmatch(r'[0-9]+\.[0-9]+\.[0-9]+[a-zA-Z0-9+_.-]*', document['samba_version'])
                    or not isinstance(document['incompatible_processes'], list)
                    or any(name not in INCOMPATIBLE for name in document['incompatible_processes'])
                    or document['incompatible_processes'] != sorted(set(document['incompatible_processes']))):
                raise ValueError
            for name, private in AUTH_FILES.items():
                _metadata(document['files'][name], maximum=MAX_AUTH_BYTES, private=private)
            for name in TOOLS:
                _metadata(document['tools'][name], maximum=MAX_TOOL_BYTES, tool=True)
                if name != 'ktutil' and document['tools'][name]['present'] is not True:
                    raise ValueError
            if document['keytab_present'] is not document['files']['/etc/krb5.keytab']['present']:
                raise ValueError
            samba = document['samba']
            if (not isinstance(samba, dict) or set(samba) != set(PARAMETERS) | {'sync_keytab_sha256', 'password_hook_empty'}
                    or samba['password_hook_empty'] is not True
                    or any(not isinstance(samba[key], str) or not samba[key] or len(samba[key]) > 4096
                        or any(ord(char) < 32 or ord(char) == 127 for char in samba[key]) for key in PARAMETERS)
                    or not isinstance(samba['sync_keytab_sha256'], str)
                    or not re.fullmatch('[0-9a-f]{64}', samba['sync_keytab_sha256'])):
                raise ValueError
            return {'snapshot': document, 'snapshot_sha256': digest(document),
                    'probe_source_sha256': hashlib.sha256(script.encode('utf-8')).hexdigest()}
        except (ControlError, ValueError, TypeError, KeyError, AttributeError):
            raise fail('recovery_facts_invalid', 'Recovery state identity or protected metadata is invalid') from None
