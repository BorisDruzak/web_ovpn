"""Internal fixed SSH service transport; execution approval belongs to its caller.

The wire cannot select a command, source, path, service or alternate root.
No CLI execution route, directory write, authentication install or service start.
"""
from __future__ import annotations

import ipaddress
from pathlib import Path
import shlex

from .ad_directory import fail
from .setup_plans import canonical, decode_state_bytes, digest
from .setup_recovery import _pair
from .setup_recovery_backup_runtime import RecoveryWorkstationBackupRuntime
from .setup_recovery_runtime import _read_source
from . import setup_recovery_backup as backup
from . import setup_recovery_services as services


class RecoveryServicesRuntime(RecoveryWorkstationBackupRuntime):
    def capture_services(self, machine, failed_run_id, computer_guid, backup_request, backup_receipt):
        return self._services('capture', machine, failed_run_id, computer_guid, backup_request, backup_receipt)

    def quiesce_services(self, machine, failed_run_id, computer_guid, backup_request, backup_receipt, snapshot):
        return self._services('quiesce', machine, failed_run_id, computer_guid, backup_request, backup_receipt, snapshot)

    def verify_services(self, machine, failed_run_id, computer_guid, backup_request, backup_receipt, snapshot):
        return self._services('verify', machine, failed_run_id, computer_guid, backup_request, backup_receipt, snapshot)

    def _services(self, action, machine, failed_run_id, computer_guid, backup_request, backup_receipt, snapshot=None):
        try:
            pair = _pair(failed_run_id, computer_guid)
            identity = self.credentials._reservation(**pair)
            address = str(ipaddress.ip_address(machine.ip))
            if identity['machine_uuid'] != machine.uuid:
                raise ValueError
            expected = self.backup_request(machine, **pair, facts=backup_request['facts'])
            if backup_request != expected:
                raise ValueError
            expected_receipt = {key: expected[key] for key in ('schema_version', 'failed_run_id', 'computer_guid',
                'claim_sha256', 'machine_uuid', 'snapshot_sha256', 'source_sha256')}
            expected_receipt['backup_id'] = 'backup-' + digest(pair)
            expected_receipt['manifest_sha256'] = digest({'schema_version': 1, 'request': expected,
                'backup_id': expected_receipt['backup_id']})
            if backup_receipt != expected_receipt:
                raise ValueError
            directory = Path(__file__).parent
            owner = Path(__file__).lstat().st_uid
            names = ('probe', 'backup', 'process', 'import', 'services')
            sources = [_read_source(directory/('setup_recovery_' + name + '.py'), owner=owner) for name in names]
            source_sha = digest(sources)
            request = {'schema_version': 1, 'backup_request': expected, 'backup_receipt': expected_receipt,
                'services': snapshot, 'services_sha256': digest(snapshot), 'source_sha256': source_sha}
            if action == 'capture':
                wire = {'backup_request': expected, 'backup_receipt': expected_receipt, 'source_sha256': source_sha}
            else:
                services._request(request, backup=backup)
                wire = {'request': request}
            wire = canonical(wire).decode('utf-8')
            if len(wire.encode('utf-8')) > 131072:
                raise ValueError
            script = 'import json, sys, types\n'
            for name, source in zip(names, sources):
                alias = 'importer' if name == 'import' else name
                script += alias + '_scope = {"__name__": "fixed_recovery_' + name + '", "__package__": None}\n'
                script += 'exec(compile(' + repr(source) + ', "fixed_recovery_' + name + '", "exec"), ' + alias + '_scope)\n'
                script += alias + ' = types.SimpleNamespace(**' + alias + '_scope)\n'
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
            if action == 'capture':
                script += '    if set(wire) != {"backup_request", "backup_receipt", "source_sha256"}: raise ValueError()\n'
                script += '    if wire["source_sha256"] != ' + repr(source_sha) + ': raise ValueError()\n'
                script += '    if probe.collect() != wire["backup_request"]["facts"] or backup.verify(wire["backup_request"]) != wire["backup_receipt"]: raise ValueError()\n'
                script += '    result = services.snapshot(backup=backup, probe=probe, collect=probe.collect, runner=process.bounded_recovery_run)\n'
            else:
                script += '    if set(wire) != {"request"}: raise ValueError()\n'
                script += '    request = wire["request"]\n'
                script += '    if request["source_sha256"] != ' + repr(source_sha) + ': raise ValueError()\n'
                method = 'quiesce_once' if action == 'quiesce' else 'verify'
                extra = ', importer=importer' if action == 'quiesce' else ''
                script += '    result = services.' + method + '(request, backup=backup, probe=probe, collect=probe.collect, runner=process.bounded_recovery_run' + extra + ')\n'
            script += '''    print(json.dumps(result, sort_keys=True))
except Exception:
    print(json.dumps({"schema_version": 1, "error_code": "recovery_services_failed"}))
    sys.exit(1)
'''
            command = ['/usr/bin/ssh', '-F', '/dev/null', '-o', 'BatchMode=yes', '-o', 'StrictHostKeyChecking=yes',
                '-o', 'ProxyCommand=none', '-o', 'ProxyJump=none', '-o', 'IdentitiesOnly=yes', '-o', 'ConnectTimeout=10',
                '-o', 'UserKnownHostsFile=' + str(self.settings.known_hosts_file), '-i', str(self.settings.private_key_file),
                'ansible@' + address, 'sudo -n /usr/bin/python3 -I -B -c ' + shlex.quote(script)]
            if self.credentials._reservation(**pair) != identity or self.backup_request(machine, **pair, facts=expected['facts']) != expected:
                raise ValueError
            if [_read_source(directory/('setup_recovery_' + name + '.py'), owner=owner) for name in names] != sources:
                raise ValueError
            rc, stdout, _ = self.runner(command, environment={'PATH': '/usr/sbin:/usr/bin:/sbin:/bin', 'LC_ALL': 'C'},
                input_text=wire, timeout=360)
            if rc:
                raise ValueError
            result = decode_state_bytes(stdout.encode('utf-8'))
            if action == 'capture':
                check = dict(request, services=result, services_sha256=digest(result))
                services._request(check, backup=backup)
            elif result != services._receipt(request, backup=backup):
                raise ValueError
            if (self.credentials._reservation(**pair) != identity
                    or self.backup_request(machine, **pair, facts=expected['facts']) != expected
                    or [_read_source(directory/('setup_recovery_' + name + '.py'), owner=owner) for name in names] != sources):
                raise ValueError
            return result
        except Exception:
            raise fail('recovery_services_failed', 'Bound service operation did not produce verified protected evidence') from None
