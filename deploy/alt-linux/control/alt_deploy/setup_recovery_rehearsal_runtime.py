"""Fixed strict SSH rehearsal transport, bound to a sealed reserved credential."""
from __future__ import annotations

import ipaddress
from pathlib import Path
import shlex

from .ad_directory import fail
from .setup_plans import canonical, decode_state_bytes, digest, private_read
from .setup_recovery import _pair
from .setup_recovery_backup_runtime import RecoveryWorkstationBackupRuntime
from .setup_recovery_runtime import _read_source
from . import setup_recovery_backup as backup
from . import setup_recovery_native as native
from . import setup_recovery_rehearsal as rehearsal


class RecoveryRehearsalRuntime(RecoveryWorkstationBackupRuntime):
    def create_rehearsal(self, machine, failed_run_id, computer_guid, backup_request, backup_receipt, metadata):
        return self._rehearsal('create', machine, failed_run_id, computer_guid, backup_request, backup_receipt, metadata)

    def verify_rehearsal(self, machine, failed_run_id, computer_guid, backup_request, backup_receipt, metadata):
        return self._rehearsal('verify', machine, failed_run_id, computer_guid, backup_request, backup_receipt, metadata)

    def _rehearsal(self, action, machine, failed_run_id, computer_guid, backup_request, backup_receipt, metadata):
        try:
            pair = _pair(failed_run_id, computer_guid)
            identity = self.credentials._reservation(**pair)
            address = str(ipaddress.ip_address(machine.ip))
            if identity['machine_uuid'] != machine.uuid or any(backup_request[key] != value for key, value in pair.items()):
                raise ValueError
            if (backup_request['machine_uuid'] != machine.uuid or backup_request['hostname'] != machine.hostname
                    or backup_request['claim_sha256'] != identity['claim_sha256']):
                raise ValueError
            expected_backup = {key: backup_request[key] for key in ('schema_version', 'failed_run_id', 'computer_guid',
                'claim_sha256', 'machine_uuid', 'snapshot_sha256', 'source_sha256')}
            expected_backup['backup_id'] = 'backup-' + digest(pair)
            expected_backup['manifest_sha256'] = digest({'schema_version': 1, 'request': backup_request,
                                                         'backup_id': expected_backup['backup_id']})
            if backup_receipt != expected_backup: raise ValueError
            directory = Path(__file__).parent
            owner = Path(__file__).lstat().st_uid
            names = ('probe', 'backup', 'native', 'process', 'rehearsal')
            sources = [_read_source(directory/('setup_recovery_' + name + '.py'), owner=owner) for name in names]
            sealed = private_read(self.credentials.path(**pair))
            password = self.credentials.open(**pair)
            if private_read(self.credentials.path(**pair)) != sealed: raise ValueError
            request = {'schema_version': 1, 'backup_request': backup_request, 'backup_receipt': backup_receipt,
                       'metadata': metadata, 'credential_sha256': sealed['sealed_sha256'], 'source_sha256': digest(sources)}
            rehearsal._request(request, backup=backup, native=native)
            wire = {'request': request}
            if action == 'create': wire['password'] = password
            wire = canonical(wire).decode('utf-8')
            if len(wire.encode('utf-8')) > 131072: raise ValueError
            script = 'import json, sys, types\n'
            for name, source in zip(names, sources):
                script += name + '_scope = {"__name__": "fixed_recovery_' + name + '", "__package__": None}\n'
                script += 'exec(compile(' + repr(source) + ', "fixed_recovery_' + name + '", "exec"), ' + name + '_scope)\n'
                script += name + ' = types.SimpleNamespace(**' + name + '_scope)\n'
            script += '''def unique(pairs):
    result = {}
    for key, value in pairs:
        if key in result: raise ValueError()
        result[key] = value
    return result
try:
    raw = sys.stdin.buffer.read(131073)
    if len(raw) > 131072: raise ValueError()
    wire = json.loads(raw, object_pairs_hook=unique)
'''
            script += '    if set(wire) != ' + repr({'request', 'password'} if action == 'create' else {'request'}) + ': raise ValueError()\n'
            script += '    request = wire["request"]\n'
            script += '    if request["source_sha256"] != ' + repr(request['source_sha256']) + ': raise ValueError()\n'
            if action == 'create':
                script += '    result = rehearsal.create(request, wire["password"], backup=backup, native=native, collect=probe.collect, runner=process.bounded_recovery_run)\n'
            else:
                script += '    result = rehearsal.verify(request, backup=backup, collect=probe.collect)\n'
            script += '''    print(json.dumps(result, sort_keys=True))
except Exception:
    print(json.dumps({"schema_version": 1, "error_code": "recovery_rehearsal_failed"}))
    sys.exit(1)
'''
            command = ['/usr/bin/ssh', '-F', '/dev/null', '-o', 'BatchMode=yes', '-o', 'StrictHostKeyChecking=yes',
                '-o', 'ProxyCommand=none', '-o', 'ProxyJump=none', '-o', 'IdentitiesOnly=yes', '-o', 'ConnectTimeout=10',
                '-o', 'UserKnownHostsFile=' + str(self.settings.known_hosts_file), '-i', str(self.settings.private_key_file),
                'ansible@' + address, 'sudo -n /usr/bin/python3 -I -B -c ' + shlex.quote(script)]
            if (self.credentials._reservation(**pair) != identity
                    or private_read(self.credentials.path(**pair)) != sealed):
                raise ValueError
            rc, stdout, _ = self.runner(command, environment={'PATH': '/usr/sbin:/usr/bin:/sbin:/bin', 'LC_ALL': 'C'},
                                       input_text=wire, timeout=360)
            if rc: raise ValueError
            result = decode_state_bytes(stdout.encode('utf-8'))
            if (result != rehearsal._receipt(request, backup=backup)
                    or self.credentials._reservation(**pair) != identity
                    or private_read(self.credentials.path(**pair)) != sealed
                    or self.credentials.open(**pair) != password
                    or private_read(self.credentials.path(**pair)) != sealed
                    or self.credentials._reservation(**pair) != identity):
                raise ValueError
            return result
        except Exception:
            raise fail('recovery_rehearsal_failed', 'Bound offline rehearsal did not produce verified protected evidence') from None
