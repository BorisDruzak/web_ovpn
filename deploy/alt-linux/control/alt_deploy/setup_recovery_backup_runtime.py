"""Fixed protected workstation backup transport; no operator command."""
from __future__ import annotations

import ipaddress
import shlex
from pathlib import Path

from .ad_directory import fail
from .errors import ControlError
from .setup_plans import canonical, decode_state_bytes, digest
from .setup_recovery import _pair
from .setup_recovery_backup import _request
from .setup_recovery_credential import RecoveryCredentialStore, RecoveryVaultCodec
from .setup_recovery_process import bounded_recovery_run
from .setup_recovery_runtime import RecoveryPlanningRuntime, _read_source


class RecoveryWorkstationBackupRuntime(RecoveryPlanningRuntime):
    def __init__(self, settings, *, runner=None, credentials=None):
        super().__init__(settings, runner=runner or bounded_recovery_run)
        self.credentials = credentials or RecoveryCredentialStore(settings.state_root, codec=RecoveryVaultCodec(settings))

    def create_backup(self, machine, failed_run_id, computer_guid, facts):
        return self._backup('create', machine, failed_run_id, computer_guid, facts)

    def verify_backup(self, machine, failed_run_id, computer_guid, facts):
        return self._backup('verify', machine, failed_run_id, computer_guid, facts)

    def backup_request(self, machine, failed_run_id, computer_guid, facts):
        pair = _pair(failed_run_id, computer_guid)
        identity = self.credentials._reservation(**pair)
        if identity['machine_uuid'] != machine.uuid: raise ValueError
        directory = Path(__file__).parent
        owner = Path(__file__).lstat().st_uid
        sources = [_read_source(directory/name, owner=owner)
            for name in ('setup_recovery_probe.py', 'setup_recovery_backup.py')]
        request = dict(pair, schema_version=1, claim_sha256=identity['claim_sha256'],
            machine_uuid=machine.uuid, hostname=machine.hostname, facts=facts,
            snapshot_sha256=digest(facts), source_sha256=digest(sources))
        _request(request)
        return request

    def _backup(self, action, machine, failed_run_id, computer_guid, facts):
        try:
            address = str(ipaddress.ip_address(machine.ip))
            pair = _pair(failed_run_id, computer_guid)
            identity = self.credentials._reservation(**pair)
            if identity['machine_uuid'] != machine.uuid: raise ValueError
            directory = Path(__file__).parent
            owner = Path(__file__).lstat().st_uid
            sources = [_read_source(directory/name, owner=owner)
                for name in ('setup_recovery_probe.py', 'setup_recovery_backup.py')]
            request = self.backup_request(machine, **pair, facts=facts)
            source_sha = digest(sources)
            if request['source_sha256'] != source_sha: raise ValueError
            wire = canonical(request).decode('utf-8')
            if len(wire) > 131072: raise ValueError
        except (ControlError, ValueError, TypeError, KeyError, AttributeError):
            raise fail('recovery_backup_invalid', 'Backup requires an unchanged reserved target and protected source') from None
        # Only these two protected fixed sources execute. The request is JSON
        # on stdin; it cannot select code, filesystem paths or an operation.
        script = 'import json, sys\n'
        script += 'probe = {"__name__": "fixed_recovery_probe"}\nbackup = {"__name__": "fixed_recovery_backup"}\n'
        script += 'exec(compile(' + repr(sources[0]) + ', "fixed_recovery_probe", "exec"), probe)\n'
        script += 'exec(compile(' + repr(sources[1]) + ', "fixed_recovery_backup", "exec"), backup)\n'
        script += '''def unique(pairs):
    result = {}
    for key, value in pairs:
        if key in result: raise ValueError()
        result[key] = value
    return result
try:
    raw = sys.stdin.buffer.read(131073)
    if len(raw) > 131072: raise ValueError()
    request = json.loads(raw, object_pairs_hook=unique)
'''
        script += '    if request["source_sha256"] != ' + repr(source_sha) + ': raise ValueError()\n'
        if action == 'create':
            script += '    result = backup["create"](request, collect=probe["collect"])\n'
        else:
            script += '    if probe["collect"]() != request["facts"]: raise ValueError()\n'
            script += '    result = backup["verify"](request)\n'
        script += '''    print(json.dumps(result, sort_keys=True))
except Exception:
    print(json.dumps({"schema_version": 1, "error_code": "recovery_backup_failed"}))
    sys.exit(1)
'''
        command = ['/usr/bin/ssh', '-F', '/dev/null', '-o', 'BatchMode=yes',
            '-o', 'StrictHostKeyChecking=yes', '-o', 'ProxyCommand=none', '-o', 'ProxyJump=none',
            '-o', 'IdentitiesOnly=yes', '-o', 'ConnectTimeout=10',
            '-o', 'UserKnownHostsFile=' + str(self.settings.known_hosts_file),
            '-i', str(self.settings.private_key_file), 'ansible@' + address,
            'sudo -n /usr/bin/python3 -I -B -c ' + shlex.quote(script)]
        try:
            rc, stdout, _ = self.runner(command, environment={'PATH': '/usr/sbin:/usr/bin:/sbin:/bin', 'LC_ALL': 'C'},
                input_text=wire, timeout=360)
            if rc: raise ValueError
            result = decode_state_bytes(stdout.encode('utf-8'))
            expected = {key: request[key] for key in ('schema_version', 'failed_run_id', 'computer_guid',
                'claim_sha256', 'machine_uuid', 'snapshot_sha256', 'source_sha256')}
            expected['backup_id'] = 'backup-' + digest(pair)
            expected['manifest_sha256'] = digest({'schema_version': 1, 'request': request, 'backup_id': expected['backup_id']})
            if result != expected or self.credentials._reservation(**pair) != identity: raise ValueError
            return result
        except Exception:
            raise fail('recovery_backup_failed', 'Private workstation backup did not produce verified bound evidence') from None
