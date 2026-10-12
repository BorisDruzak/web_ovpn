"""Fixed read-only workstation probe and controller component prerequisites."""
from __future__ import annotations

import hashlib
import ipaddress
import json
import os
import shlex
from pathlib import Path

from .ad_directory import DOMAIN, fail, normalize_login
from .ad_transport import bounded_run
from .configure import KRFB_NETWORK_CONFIRMATION_VARIABLE
from .setup_plans import digest
from .vault import VaultHealthChecker

# The operator supplies no script, shell fragment, or command selection.
PROBE_SCRIPT = r'''
import json, os, pathlib, re, subprocess, sys, uuid
login, upn = sys.argv[1:3]
dc = sys.argv[3] if len(sys.argv) == 4 else ''
if dc and not re.fullmatch(r'[a-zA-Z0-9.-]+', dc):
    raise RuntimeError('directory controller name invalid')
server = ['-S', dc] if dc else []
def read(args):
    result = subprocess.run(args, capture_output=True, text=True, timeout=10,
                            env=dict(os.environ, LC_ALL='C'))
    if len(result.stdout.encode('utf-8')) > 262144 or len(result.stderr.encode('utf-8')) > 262144:
        raise RuntimeError('probe output exceeds limit')
    return result.returncode, result.stdout.strip()
auth_rc, auth = read(['system-auth', 'status'])
if auth_rc != 0:
    raise RuntimeError('authentication scheme unavailable')
parts = auth.lower().split()
if not parts or parts[0] not in ('ad', 'local', 'local-users', 'ldap', 'krb5'):
    raise RuntimeError('unknown authentication scheme')
if parts[0] not in ('ad', 'local', 'local-users'):
    raise RuntimeError('incompatible authentication scheme')
domain = parts[1] if parts[0] == 'ad' and len(parts) > 1 else ''
hostname = read(['hostname', '-s'])[1].lower()
if not re.fullmatch(r'[a-z][a-z0-9]*(?:-[a-z0-9]+)*', hostname) or len(hostname) > 63:
    raise RuntimeError('machine hostname invalid')
trust_rc, _ = read(['net', *server, 'ads', 'testjoin'])
computer_identity = None
if trust_rc == 0:
    # Samba's status command has a fixed attribute list which omits GUID/DN.
    # Request exactly the attributes needed for immutable identity checks.
    status_rc, status = read(['net', '-P', *server, 'ads', 'search',
        '(&(objectClass=computer)(sAMAccountName=' + hostname + '$))',
        'objectGUID', 'objectSid', 'sAMAccountName', 'distinguishedName', 'dNSHostName'])
    if status_rc != 0:
        raise RuntimeError('machine account identity unavailable')
    if not status.splitlines() or status.splitlines()[0] != 'Got 1 replies':
        raise RuntimeError('machine account identity ambiguous')
    values = {}
    names = {'objectguid', 'objectsid', 'samaccountname', 'distinguishedname', 'dnshostname'}
    for line in status.splitlines():
        key, sep, value = line.partition(':')
        key = key.strip().lower()
        if sep and key in names:
            if key in values:
                raise RuntimeError('machine account identity ambiguous')
            values[key] = value.strip()
    if set(values) != names or not re.fullmatch(r'S-1-[0-9]+(?:-[0-9]+)+', values['objectsid']):
        raise RuntimeError('machine account identity invalid')
    computer_identity = dict(object_guid=str(uuid.UUID(values['objectguid'])), object_sid=values['objectsid'],
        sam_account_name=values['samaccountname'].lower(), dn=values['distinguishedname'],
        dns_hostname=values['dnshostname'].lower())
sssd_rc, sssd = read(['systemctl', 'is-active', 'sssd'])
user_rc, passwd = read(['getent', 'passwd', upn])
if user_rc not in (0, 2):
    raise RuntimeError('user lookup unavailable')
fields = passwd.split(':') if user_rc == 0 else []
if fields and (len(fields) != 7 or fields[0].lower() not in (login, upn)):
    raise RuntimeError('user lookup identity differs')
local_names = [line.split(':', 1)[0].lower() for line in pathlib.Path('/etc/passwd').read_text().splitlines()]
result = dict(uuid=pathlib.Path('/sys/class/dmi/id/product_uuid').read_text().strip().lower(),
              hostname=hostname, domain=domain,
              trust=trust_rc == 0, sssd=sssd_rc == 0 and sssd == 'active',
              user_lookup=user_rc == 0, local_duplicate=login in local_names or upn in local_names,
              home_exists=bool(fields and os.path.isdir(fields[5])), computer_identity=computer_identity)
print(json.dumps(result))
'''


def source_fingerprint(project, control):
    """Bind published role assets and source without reading local Vault secrets."""
    hashes = {}
    for path in sorted(project.rglob('*')):
        relative = path.relative_to(project).as_posix()
        if relative == 'group_vars/vault.yml':
            continue
        included = relative.startswith('roles/') or path.suffix in ('.yml', '.yaml', '.cfg')
        if not included:
            continue
        if path.is_symlink():
            raise fail('setup_source_unsafe', 'Controller Ansible source is unsafe')
        if path.is_dir():
            continue
        if not path.is_file() or path.stat().st_size > 1048576:
            raise fail('setup_source_unsafe', 'Controller Ansible source is unsafe')
        hashes[relative] = hashlib.sha256(path.read_bytes()).hexdigest()
    for path in sorted(control.glob('*.py')):
        if path.is_symlink() or not path.is_file() or path.stat().st_size > 1048576:
            raise fail('setup_source_unsafe', 'Controller Python source is unsafe')
        hashes['control/' + path.name] = hashlib.sha256(path.read_bytes()).hexdigest()
    return digest(hashes)


class SetupRuntime:
    def __init__(self, settings, *, runner=None):
        self.settings = settings
        self.runner = runner or bounded_run

    def probe(self, machine, user):
        try:
            address = str(ipaddress.ip_address(machine.ip))
        except ValueError as exc:
            raise fail('machine_missing_ip', 'Machine has no valid registered IP') from exc
        login = normalize_login(user['login'])
        if user['upn'] != login + '@' + DOMAIN:
            raise fail('ad_user_identity_invalid', 'Selected domain user name differs')
        from urllib.parse import urlsplit
        from .ad_transport import DirectoryConfig
        dc = urlsplit(DirectoryConfig.load().uri).hostname
        command = ['/usr/bin/ssh', '-o', 'BatchMode=yes', '-o', 'StrictHostKeyChecking=yes',
                   '-o', 'ProxyCommand=none', '-o', 'IdentitiesOnly=yes', '-o', 'ConnectTimeout=10',
                   '-o', 'UserKnownHostsFile=' + str(self.settings.known_hosts_file),
                   '-i', str(self.settings.private_key_file), 'ansible@' + address,
                   'sudo -n /usr/bin/python3 -I -B -c ' + shlex.quote(PROBE_SCRIPT) + ' ' + shlex.quote(login) + ' ' + shlex.quote(user['upn']) + ' ' + shlex.quote(dc)]
        rc, stdout, _ = self.runner(command, environment=dict(os.environ), timeout=90)
        if rc:
            raise fail('setup_probe_failed', 'Read-only SSH probe failed; check host key, SSH, sudo and domain tools')
        try:
            document = json.loads(stdout)
            if (not isinstance(document, dict) or set(document) != {'uuid', 'hostname', 'domain', 'trust', 'sssd', 'user_lookup', 'local_duplicate', 'home_exists', 'computer_identity'}
                    or any(type(document[key]) is not bool for key in ('trust', 'sssd', 'user_lookup', 'local_duplicate', 'home_exists'))
                    or any(not isinstance(document[key], str) for key in ('uuid', 'hostname', 'domain'))):
                raise ValueError
            return document
        except (ValueError, TypeError) as exc:
            raise fail('setup_probe_invalid', 'Read-only SSH probe returned invalid state') from exc

    def prerequisites(self, request):
        settings = self.settings
        fixed = settings.ansible_project_dir / 'playbooks/03-setup-controller-preflight.yml'
        required = [settings.ansible_playbook_path, settings.private_key_file, settings.known_hosts_file,
                    settings.ansible_project_dir / 'playbooks/03-configure-domain-workstation.yml', fixed,
                    settings.ansible_project_dir / 'ansible.cfg']
        if any(not path.is_file() or path.is_symlink() for path in required):
            raise fail('configure_not_configured', 'Required fixed controller playbooks, SSH files or Ansible runtime are missing')
        checker = VaultHealthChecker(settings)
        checker.check_ad_join()
        if request.remote_access_profile == 'krfb':
            checker.check_krfb()
            if os.environ.get(KRFB_NETWORK_CONFIRMATION_VARIABLE) != 'true':
                raise fail('remote_access_network_restriction_unconfirmed', 'Restricted TCP 5900 access must be explicitly confirmed')
        environment = dict(os.environ)
        environment['ANSIBLE_CONFIG'] = str(settings.ansible_project_dir / 'ansible.cfg')
        # No workstation inventory and no mutation role can be selected here.
        command = [str(settings.ansible_playbook_path), '-i', 'localhost,', '-c', 'local',
                   '-e', json.dumps({'software_profile': request.software_profile,
                                    'remote_access_profile': request.remote_access_profile}), str(fixed)]
        rc, _, _ = self.runner(command, environment=environment, timeout=120)
        if rc:
            raise fail('setup_component_prerequisites_failed', 'Controller component artifacts, catalog or required Vault values failed preflight')
        # Bind all published Ansible content to the plan; encrypted Vault and
        # local secret paths are excluded from the public source fingerprint.
        from .ad_transport import DirectoryConfig
        return {'ready': True, 'directory_uri': DirectoryConfig.load().uri,
                'source_sha256': source_fingerprint(settings.ansible_project_dir, Path(__file__).parent), 'ssh_files_present': True,
                'vault_ad_join_ready': True, 'component_preflight': True,
                'krfb_network_confirmed': request.remote_access_profile == 'krfb'}
