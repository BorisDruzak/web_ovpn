"""Bound fixed target protocol, independent fresh local/SSH verification."""
import hashlib
import ipaddress
import json
import os
from pathlib import Path
import re
import shlex
import stat

from .ad_directory import fail
from .ad_transport import bounded_run
from .setup_plans import digest
from .component_verification import package_health_ready

# Existing root-owned deployment metadata is captured/restored by native backup.
REHEARSAL_RECORD = Path('/srv/alt-deploy/metadata/partial-local-rehearsal.json')


def denied():
    return fail('setup_partial_local_runtime_unverified', 'Fixed local recovery, rehearsal or fresh result cannot be verified')


def native_fingerprint(native):
    return digest({'tools': native['tools'], 'files': {name: record for name, record in native['files'].items()
        if name.startswith(('/etc/pam.d/', '/etc/rc.d/init.d/', '/usr/lib/systemd/system/', '/lib/systemd/system/'))
        and record.get('kind') != 'symlink'}, 'services': {name: service['fragment'] for name, service in native['services'].items()}})


def validate_local_after(payload, after):
    before = payload['evidence']
    for name in ('machine', 'user', 'ou_identity', 'ssh_binding', 'boot_id', 'user_runtime'):
        if after.get(name) != before[name]: raise denied()
    if (after['observed'].get('domain') != '' or after['observed'].get('trust') is not False
            or after['observed'].get('local_duplicate') is not False or after['observed'].get('computer_identity') is not None
            or after['computer'].get('exists') is not False or after['computer'].get('objects') != []
            or not package_health_ready(after)):
        raise denied()
    partial = after['partial_local']
    if (partial['mode'] != 'local' or partial['directory_uri'] != before['partial_local']['directory_uri']
            or partial['quiet'] != before['partial_local']['quiet'] or partial['collisions'] != {'complete': True, 'matches': 0}): raise denied()
    old, new = before['partial_local']['native'], partial['native']
    if new.get('auth_scheme') != 'local' or new.get('domain') != '' or new.get('clock_synchronized') is not True: raise denied()
    for key in ('schema_version', 'uuid', 'hostname', 'boot_id', 'tools', 'local_admin', 'local_accounts_sha256', 'goa', 'services'):
        if new.get(key) != old[key]: raise denied()
    if set(new['files']) != set(old['files']): raise denied()
    links = {'/etc/pam.d/'+name: name+'-local' for name in ('system-auth', 'system-auth-use_first_pass', 'system-policy')}
    for path, record in old['files'].items():
        if path in links:
            if new['files'][path] != dict(record, target=links[path]): raise denied()
        elif path != '/etc/nsswitch.conf' and new['files'][path] != record: raise denied()
    return after


def validate_target_result(plan, value):
    if (set(value) != {'schema_version', 'claim_key', 'plan_sha256', 'status', 'backup_sha256', 'before_sha256', 'after_sha256'}
            or type(value['schema_version']) is not int or value['schema_version'] != 1
            or value['claim_key'] != digest({k: plan['payload'][k] for k in ('job_id', 'failed_run_id')})
            or value['plan_sha256'] != plan['sha256']
            or value['status'] not in ('successful', 'unknown_requires_review')
            or any(value[k] is not None and not re.fullmatch('[0-9a-f]{64}', value[k])
                   for k in ('backup_sha256', 'before_sha256', 'after_sha256'))
            or value['before_sha256'] != digest(plan['payload']['evidence']['partial_local']['native'])
            or value['status'] == 'successful' and (value['backup_sha256'] is None or value['after_sha256'] is None)):
        raise denied()
    return value


class PartialLocalRuntime:
    def __init__(self, settings, *, observer=None, runner=None):
        self.settings = settings
        self.observer = observer
        self.runner = runner or bounded_run

    def _code(self):
        from .setup_maintenance_review_bridge import closed_failure_service
        # Resolve the probe through the same trusted root-owned native bridge.
        history = closed_failure_service(self.settings)
        import sys
        root = Path(sys.modules[history.__class__.__module__].__file__).parent
        paths = [root/'partial_local_probe.py', Path(__file__).with_name('partial_local_target.py')]
        result = []
        for path in paths:
            for parent in path.parents:
                info = parent.lstat()
                if not stat.S_ISDIR(info.st_mode) or info.st_uid != 0 or info.st_mode & 0o022: raise denied()
            info = path.lstat()
            if not stat.S_ISREG(info.st_mode) or info.st_uid != 0 or info.st_mode & 0o022 or info.st_size > 65536: raise denied()
            result.append(path.read_text(encoding='utf-8'))
        return result

    def helper_fingerprint(self):
        return digest([hashlib.sha256(source.encode()).hexdigest() for source in self._code()])

    def source(self):
        from .setup_runtime import source_fingerprint
        return digest({'controller': source_fingerprint(self.settings.ansible_project_dir, Path(__file__).parent),
                       'helper': self.helper_fingerprint()})

    def rehearsal(self, fresh):
        path = REHEARSAL_RECORD
        try:
            for parent in path.parents:
                info = parent.lstat()
                if not stat.S_ISDIR(info.st_mode) or info.st_uid != 0 or info.st_mode & 0o022: raise denied()
            info = path.lstat()
            if not stat.S_ISREG(info.st_mode) or info.st_uid != 0 or info.st_mode & 0o022 or info.st_size > 4096: raise denied()
            document = json.loads(path.read_text())
            expected = {'status': 'passed', 'helper_sha256': self.helper_fingerprint(),
                        'native_sha256': native_fingerprint(fresh['partial_local']['native'])}
            if document != expected: raise denied()
            return document
        except Exception: raise denied() from None

    def snapshot(self, closed, *, mode):
        from .setup_maintenance_review_bridge import partial_observer_service
        observer = self.observer or partial_observer_service(self.settings)
        return observer.observe(closed, mode=mode)

    def _target(self, plan, action):
        payload = plan['payload']
        before = payload['evidence']['partial_local']['native']
        request = {'schema_version': 1, 'claim_key': digest({k: payload[k] for k in ('job_id', 'failed_run_id')}),
            'plan_sha256': plan['sha256'], 'before': before,
            'machine': {'schema_version': 1, 'uuid': before['uuid'], 'hostname': before['hostname'],
                        'domain': before['domain'], 'workgroup': 'SOSNADM'}, 'action': action}
        probe, target = self._code()
        source = probe.split("if __name__ == '__main__':")[0]+'\n'+target+'''
import sys
try:
 raw=sys.stdin.buffer.read(524289)
 if len(raw)>524288: raise ValueError
 request=json.loads(raw)
 action=request.pop('action')
 if action not in ('execute','inspect'): raise ValueError
 result=execute(request) if action=='execute' else inspect(request)
 print(json.dumps(result))
except Exception:
 sys.exit(4)
'''
        address = str(ipaddress.ip_address(payload['machine']['ip']))
        command = ['/usr/bin/ssh', '-o', 'BatchMode=yes', '-o', 'StrictHostKeyChecking=yes',
            '-o', 'ProxyCommand=none', '-o', 'IdentitiesOnly=yes', '-o', 'ConnectTimeout=10',
            '-o', 'UserKnownHostsFile='+str(self.settings.known_hosts_file), '-i', str(self.settings.private_key_file),
            'ansible@'+address, 'sudo -n /usr/bin/python3 -I -B -c '+shlex.quote(source)]
        rc, output, _ = self.runner(command, environment=dict(os.environ), input_text=json.dumps(request), timeout=180)
        if rc or len(output.encode()) > 4096: raise denied()
        return validate_target_result(plan, json.loads(output))

    def apply(self, plan, claim):
        if claim['claim_key'] != digest({k: plan['payload'][k] for k in ('job_id', 'failed_run_id')}): raise denied()
        return self._target(plan, 'execute')

    def verify(self, plan, result):
        from .setup_maintenance_review_bridge import closed_failure_service
        validate_target_result(plan, result)
        if result['status'] != 'successful' or self._target(plan, 'inspect') != result: raise denied()
        closed = closed_failure_service(self.settings).load(plan['payload']['job_id'])
        after = validate_local_after(plan['payload'], self.snapshot(closed, mode='local'))
        if digest(after['partial_local']['native']) != result['after_sha256']: raise denied()
        return after
