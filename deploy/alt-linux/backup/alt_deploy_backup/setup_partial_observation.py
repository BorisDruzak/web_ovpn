"""Read-only admission evidence for a first join with no directory object."""
import ipaddress
import json
import os
from pathlib import Path
import re
import shlex

from .setup_compat import control_module

NATIVE_HASHES = {
    '/usr/sbin/system-auth': '0dbec9740439e08770c97f08d4a39535787d499538ac8b1b497f0e14627d7d9e',
    '/usr/sbin/control': '261d22ad03856fa8b6a041725e861dc80f7984be40163563393ce442687a9cd5',
    '/etc/control.d/facilities/system-auth': 'd3bf62ddaab8cf5d94f2341c4c4788b60a1cf81795dc81cbc51e81f6d5a87ef0',
    '/etc/control.d/functions': '662e9d26db9443d7cff29cebf6681ccfb74f6b387ccea9d62195f6ed939f96ae'}
LOCAL_TEMPLATES = {
    'system-auth-local': '962fabef9682f0ba7db5abe7bcc65c280f51514dfb3d8bea54bda3aa1478f7fd',
    'system-auth-use_first_pass-local': '233278bab33b730db765d6788ca3dfce2e3b327b00ca16f8366dc029ad65fcd0',
    'system-policy-local': '642826be8597811a1d6e2c7d6a77601676941df757eb9f8abe1cf13a99dede63'}
SYSV_HOOKS = {'sssd': '2eddd28fdd945c0db4ab0fe6c75d8f615e6c9bc64ad27824f74180a2f27abb85',
              'winbind': '8e1865d2b68392d0ce6f03b639e64be12485ea7e56acc7b813f9ddaf093eda64'}


def denied():
    return control_module('ad_directory').fail('setup_partial_state_unverified',
        'Partial local state, original identity or complete directory absence cannot be verified')


def directory_collisions(directory, hostname):
    ad = control_module('ad_directory')
    if not ad.HOST_RE.fullmatch(hostname): raise denied()
    short = ad.escape_filter(hostname)
    fqdn = ad.escape_filter(hostname+'.'+ad.DOMAIN)
    clauses = ['(sAMAccountName='+short+'$)', '(dNSHostName='+fqdn+')']
    clauses += ['(servicePrincipalName='+service+'/'+name+')'
                for service in ('HOST', 'RestrictedKrbHost') for name in (short, fqdn)]
    # LDAPTransport rejects nonzero/partial/budget responses; parse_ldif rejects
    # referrals and malformed records. Any returned object is a collision.
    entries = directory._query('(|'+''.join(clauses)+')', ('dn',))
    if any(set(entry) != {'dn'} or len(entry['dn']) != 1 for entry in entries): raise denied()
    for entry in entries: ad.text(entry, 'dn')
    return {'complete': True, 'matches': len(entries)}


def target_observe(settings, machine, request):
    probe = Path(__file__).with_name('partial_local_probe.py')
    from .fs import read_regular_bytes
    source = read_regular_bytes(probe, max_bytes=65536).decode('utf-8')
    address = str(ipaddress.ip_address(machine.ip))
    command = ['/usr/bin/ssh', '-o', 'BatchMode=yes', '-o', 'StrictHostKeyChecking=yes',
        '-o', 'ProxyCommand=none', '-o', 'IdentitiesOnly=yes', '-o', 'ConnectTimeout=10',
        '-o', 'UserKnownHostsFile='+str(settings.known_hosts_file), '-i', str(settings.private_key_file),
        'ansible@'+address, 'sudo -n /usr/bin/python3 -I -B -c '+shlex.quote(source)]
    rc, output, _ = control_module('ad_transport').bounded_run(command, environment=dict(os.environ),
        input_text=json.dumps(request), timeout=180)
    if rc: raise denied()
    return json.loads(output)


def validate_native(native, original, boot_id, mode):
    domain = control_module('ad_directory').DOMAIN
    expected_domain = domain if mode == 'partial_ad' else ''
    scheme = 'ad' if mode == 'partial_ad' else 'local'
    if (native.get('schema_version') != 1 or native.get('uuid') != original['machine']['uuid']
            or native.get('hostname') != original['machine']['hostname'] or native.get('boot_id') != boot_id
            or native.get('auth_scheme') != scheme or native.get('domain') != expected_domain
            or native.get('clock_synchronized') is not True or native.get('goa') != {'installed': False}
            or not re.fullmatch('[0-9a-f]{64}', native.get('local_accounts_sha256', ''))): raise denied()
    for path, sha in NATIVE_HASHES.items():
        record = native.get('tools', {}).get(path, {})
        if (record.get('present') is not True or record.get('kind') != 'file' or record.get('sha256') != sha
                or record.get('uid') != 0 or record.get('gid') != 0 or record.get('mode') != 0o755): raise denied()
    files = native['files']
    if files.get('/etc/krb5.keytab') != {'present': False}: raise denied()
    for name, sha in LOCAL_TEMPLATES.items():
        record = files.get('/etc/pam.d/'+name, {})
        if (record.get('present') is not True or record.get('kind') != 'file' or record.get('sha256') != sha
                or record.get('uid') != 0 or record.get('gid') != 0 or record.get('mode') != 0o644): raise denied()
    links = {'system-auth': 'system-auth-sss', 'system-auth-use_first_pass': 'system-auth-use_first_pass-sss',
             'system-policy': 'system-policy-remote'} if mode == 'partial_ad' else {
             'system-auth': 'system-auth-local', 'system-auth-use_first_pass': 'system-auth-use_first_pass-local',
             'system-policy': 'system-policy-local'}
    for name, target in links.items():
        record = files.get('/etc/pam.d/'+name, {})
        if (record.get('present') is not True or record.get('kind') != 'symlink'
                or record.get('uid') != 0 or record.get('target') != target): raise denied()
    admin = native.get('local_admin', {})
    if (admin.get('login') != 'ansible' or admin.get('sudo') is not True
            or any(type(admin.get(k)) is not int or admin[k] <= 0 for k in ('uid', 'gid'))): raise denied()
    if set(native.get('services', {})) != {'sssd', 'winbind'}: raise denied()
    for name, service in native['services'].items():
        if (service.get('load_state') != 'loaded' or service.get('active_state') != 'inactive'
                or service.get('unit_file_state') != 'disabled' or service.get('drop_ins') != []): raise denied()
        hook = files.get('/etc/rc.d/init.d/'+name, {'present': False})
        if hook.get('present') and (hook.get('kind') != 'file' or hook.get('uid') != 0 or hook.get('gid') != 0
                or hook.get('mode') != 0o755 or hook.get('sha256') != SYSV_HOOKS[name]): raise denied()
        # Only the packaged compatibility hook with an already disabled,
        # inactive native service is supported; sockets/timers remain excluded.
        if any(record.get('present') for path, record in files.items()
               if path.endswith(('/'+name+'.socket', '/'+name+'.timer'))): raise denied()


def validate_evidence(closed, fresh, *, mode):
    original = closed['original']
    if (fresh['machine'] != original['machine'] or fresh['ssh_binding'] != original['ssh_binding']
            or fresh['ou_identity'] != original['ou_identity'] or fresh['user'].get('state') != 'enabled'
            or any(fresh['user'].get(k) != original['user'].get(k) for k in ('object_guid', 'object_sid', 'upn', 'login'))
            or original['observed']['domain'] != '' or original['observed']['trust'] is not False
            or original['computer']['objects'] != [] or closed['result']['phase'] != 'domain_join'
            or fresh['computer'].get('exists') is not False or fresh['computer'].get('objects') != []
            or not control_module('component_verification').package_health_ready(fresh)
            or not control_module('setup_jobs').UUID.fullmatch(fresh['boot_id'])): raise denied()
    observed, partial = fresh['observed'], fresh['partial_local']
    if (partial['mode'] != mode or partial['directory_uri'] != original['prerequisites']['directory_uri']
            or observed.get('uuid') != original['machine']['uuid'] or observed.get('hostname') != original['machine']['hostname']
            or observed.get('domain') != (control_module('ad_directory').DOMAIN if mode == 'partial_ad' else '')
            or observed.get('trust') is not False or observed.get('local_duplicate') is not False
            or observed.get('computer_identity') is not None
            or partial['quiet'] != dict(uuid=original['machine']['uuid'], hostname=original['machine']['hostname'],
                                       credentials_absent=True, processes_absent=True)
            or any(partial['quiet'].get(k) is not True for k in ('credentials_absent', 'processes_absent'))
            or partial['collisions'] != {'complete': True, 'matches': 0}
            or partial['collisions']['complete'] is not True or type(partial['collisions']['matches']) is not int): raise denied()
    runtime = fresh['user_runtime']
    unresolved = (runtime.get('uid') is None and runtime.get('gid') is None
                  and runtime.get('home_exists') is False and runtime.get('home_safe') is False)
    if (set(runtime) != {'login', 'uid', 'gid', 'home_exists', 'home_safe'} or runtime['login'] != original['user']['login']
            or not unresolved and (any(type(runtime[k]) is not int or runtime[k] <= 0 for k in ('uid', 'gid'))
                                   or type(runtime['home_exists']) is not bool or runtime['home_safe'] is not True)): raise denied()
    validate_native(partial['native'], original, fresh['boot_id'], mode)
    return fresh


class PartialLocalObserver:
    def __init__(self, settings, *, setup=None, target_probe=None, quiet_probe=None, package_probe=None,
                 collision_query=None, directory_uri=None):
        self.settings = settings
        self.setup = setup or control_module('setup').SetupService(settings)
        runtime = control_module('setup_runtime').SetupRuntime(settings)
        self.target_probe = target_probe or (lambda machine, request: target_observe(settings, machine, request))
        self.quiet_probe = quiet_probe or runtime.probe_prejoin
        self.package_probe = package_probe or control_module('component_probe').ComponentProbe(settings)
        self.collision_query = collision_query or (lambda hostname: directory_collisions(self.setup.directory, hostname))
        self.directory_uri = directory_uri or control_module('ad_transport').DirectoryConfig.load().uri

    def observe(self, closed, *, mode):
        try:
            return self._observe(closed, mode)
        except Exception:
            raise denied() from None

    def _observe(self, closed, mode):
        if mode not in ('partial_ad', 'local'): raise denied()
        original = closed['original']
        if (original['observed']['domain'] != '' or original['observed']['trust'] is not False
                or original['computer']['exists'] is not False or original['computer']['objects'] != []
                or closed['result']['phase'] != 'domain_join'
                or self.directory_uri != original['prerequisites']['directory_uri']): raise denied()
        # Complete event validation occurred in ClosedFailureEvidence; require
        # that the recorded failure really reached the protected join stage.
        events = [json.loads(raw) for path, raw in closed['files'].items() if '/events/' in path]
        if not any(event.get('component_id') == 'domain.ready' and event.get('stage') == 'domain_join'
                   for event in events): raise denied()
        machine = self.setup.machines.resolve(original['machine']['uuid'])
        identity = {'uuid': machine.uuid, 'hostname': machine.hostname, 'ip': machine.ip,
                    'registration_sha256': control_module('setup_plans').digest(machine.raw)}
        if machine.registration_state != 'ready' or identity != original['machine']: raise denied()
        user = self.setup.directory.user(original['user']['login'])
        if user.get('state') != 'enabled' or any(user.get(k) != original['user'].get(k)
                for k in ('object_guid', 'object_sid', 'upn', 'login')): raise denied()
        ous = [entry for entry in self.setup.directory.ous() if entry['dn'].casefold() == original['computer_ou'].casefold()]
        if original['computer_ou'] not in self.setup.approved_ous or ous != [original['ou_identity']]: raise denied()
        binding = control_module('component_probe').ssh_binding(self.settings, machine)
        if binding != original['ssh_binding']: raise denied()
        collisions = self.collision_query(machine.hostname)
        if collisions != {'complete': True, 'matches': 0} or type(collisions['matches']) is not int: raise denied()
        computer = self.setup.directory.computer(machine.hostname)
        observed = self.setup.probe(machine, user)
        if (computer.get('exists') is not False or computer.get('objects') != []
                or observed.get('uuid') != machine.uuid or observed.get('hostname') != machine.hostname
                or observed.get('domain') != (control_module('ad_directory').DOMAIN if mode == 'partial_ad' else '')
                or observed.get('trust') is not False or observed.get('local_duplicate') is not False
                or observed.get('computer_identity') is not None): raise denied()
        quiet = self.quiet_probe(machine, closed['configuration_run_id'])
        if quiet != {'uuid': machine.uuid, 'hostname': machine.hostname,
                      'credentials_absent': True, 'processes_absent': True}: raise denied()
        facts = self.package_probe.observe(machine, user, original['components'],
            profile_id=original['profile']['id'], allow_unresolved=True)
        verification = control_module('component_verification')
        if (not verification.valid_evidence(facts, allow_unresolved=True) or not verification.package_health_ready(facts)
                or facts['machine']['uuid'] != machine.uuid or facts['machine']['hostname'] != machine.hostname
                or facts['machine']['os_id'] != 'alt-kworkstation-11' or facts['user']['login'] != user['login']
                or (facts['user']['uid'] is not None and facts['user']['home_safe'] is not True)): raise denied()
        request = {'schema_version': 1, 'uuid': machine.uuid, 'hostname': machine.hostname,
                   'domain': control_module('ad_directory').DOMAIN, 'workgroup': original['request']['workgroup']}
        native = self.target_probe(machine, request)
        validate_native(native, original, facts['machine']['boot_id'], mode)
        fresh = {'machine': identity, 'user': user, 'ou_identity': ous[0], 'computer': computer,
            'observed': observed, 'ssh_binding': binding, 'package_manager': facts['package_manager'],
            'boot_id': facts['machine']['boot_id'], 'user_runtime': facts['user'],
            'partial_local': {'mode': mode, 'quiet': quiet, 'native': native, 'collisions': collisions,
                              'directory_uri': self.directory_uri}}
        return validate_evidence(closed, fresh, mode=mode)
