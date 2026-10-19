"""Fresh absence, UUID, SSH and package evidence are all required together."""
import copy
from types import SimpleNamespace

import pytest

from alt_deploy.errors import ControlError
from test_setup_closed_failure import backend, partial_failure
from test_component_catalog import project
from test_component_setup import component_service


def native_facts(machine):
    tools = {
        '/usr/sbin/system-auth': '0dbec9740439e08770c97f08d4a39535787d499538ac8b1b497f0e14627d7d9e',
        '/usr/sbin/control': '261d22ad03856fa8b6a041725e861dc80f7984be40163563393ce442687a9cd5',
        '/etc/control.d/facilities/system-auth': 'd3bf62ddaab8cf5d94f2341c4c4788b60a1cf81795dc81cbc51e81f6d5a87ef0',
        '/etc/control.d/functions': '662e9d26db9443d7cff29cebf6681ccfb74f6b387ccea9d62195f6ed939f96ae',
    }
    files = {'/etc/krb5.keytab': {'present': False}}
    for name, sha in {
        'system-auth-local': '962fabef9682f0ba7db5abe7bcc65c280f51514dfb3d8bea54bda3aa1478f7fd',
        'system-auth-use_first_pass-local': '233278bab33b730db765d6788ca3dfce2e3b327b00ca16f8366dc029ad65fcd0',
        'system-policy-local': '642826be8597811a1d6e2c7d6a77601676941df757eb9f8abe1cf13a99dede63',
    }.items():
        files['/etc/pam.d/'+name] = {'present': True, 'kind': 'file', 'sha256': sha,
                                     'size': 100, 'uid': 0, 'gid': 0, 'mode': 0o644}
    for name, target in [('system-auth', 'system-auth-sss'), ('system-auth-use_first_pass', 'system-auth-use_first_pass-sss'),
                         ('system-policy', 'system-policy-remote')]:
        files['/etc/pam.d/'+name] = {'present': True, 'kind': 'symlink', 'target': target, 'uid': 0, 'gid': 0, 'mode': 0o777}
    return {'schema_version': 1, 'uuid': machine.uuid, 'hostname': machine.hostname,
        'boot_id': 'bbbbbbbb-bbbb-cccc-dddd-eeeeeeeeeeee', 'auth_scheme': 'ad', 'domain': 'sosnadmin.local',
        'clock_synchronized': True, 'goa': {'installed': False},
        'tools': {p: {'present': True, 'kind': 'file', 'sha256': sha, 'size': 100, 'uid': 0, 'gid': 0, 'mode': 0o755} for p, sha in tools.items()},
        'files': files, 'services': {name: {'load_state': 'loaded', 'active_state': 'inactive', 'unit_file_state': 'disabled',
            'fragment': None, 'drop_ins': []} for name in ('sssd', 'winbind')},
        'local_admin': {'login': 'ansible', 'uid': 1001, 'gid': 1001, 'sudo': True},
        'local_accounts_sha256': 'd'*64}


def observer(partial_failure, *, collisions=None, quiet=None):
    setup, job, machine, user, state, current, date = partial_failure
    native = native_facts(machine)
    quiet = quiet or {'uuid': machine.uuid, 'hostname': machine.hostname,
                      'credentials_absent': True, 'processes_absent': True}
    collisions = collisions or {'complete': True, 'matches': 0}
    service = backend('setup_partial_observation').PartialLocalObserver(setup.settings,
        setup=setup, target_probe=lambda *a: copy.deepcopy(native),
        quiet_probe=lambda *a: copy.deepcopy(quiet), package_probe=SimpleNamespace(observe=lambda *a, **k: copy.deepcopy(state)),
        collision_query=lambda hostname: copy.deepcopy(collisions), directory_uri='ldap://dc.sosnadmin.local')
    return service, native, quiet, collisions


def test_fresh_partial_state_does_not_require_domain_nss_uid(partial_failure):
    setup, job, machine, user, state, current, date = partial_failure
    closed = backend('setup_closed_failure').ClosedFailureEvidence(setup.settings).load(job.job_id)
    service, *_ = observer(partial_failure)
    result = service.observe(closed, mode='partial_ad')
    assert result['partial_local']['quiet']['credentials_absent'] is True
    assert result['partial_local']['native']['auth_scheme'] == 'ad'
    assert result['user_runtime']['uid'] is None
    assert result['computer']['objects'] == []


@pytest.mark.parametrize('collision', ['account', 'dns', 'short_spn', 'fqdn_spn', 'incomplete'])
def test_dns_or_spn_collision_denies_absence(partial_failure, collision):
    setup, job, *_ = partial_failure
    closed = backend('setup_closed_failure').ClosedFailureEvidence(setup.settings).load(job.job_id)
    collisions = {'complete': collision != 'incomplete', 'matches': 0 if collision == 'incomplete' else 1}
    service, *_ = observer(partial_failure, collisions=collisions)
    with pytest.raises(ControlError): service.observe(closed, mode='partial_ad')


@pytest.mark.parametrize('raw,allowed', [('', True), ('dn: CN=collision,DC=sosnadmin,DC=local\n\n', False),
    ('dn: CN=one,DC=sosnadmin,DC=local\n\ndn: CN=two,DC=sosnadmin,DC=local\n\n', False),
    ('ref: ldap://other.example\n', False), ('result: 4 Size limit exceeded\n', False)])
def test_complete_collision_query_checks_all_fixed_aliases(raw, allowed):
    from alt_deploy.ad_directory import ADDirectory
    calls = []
    def transport(**kwargs):
        calls.append(kwargs)
        return raw
    module = backend('setup_partial_observation')
    try:
        result = module.directory_collisions(ADDirectory(transport), 'alt-a1-pc3')
    except ControlError:
        assert not allowed
    else:
        assert (result == {'complete': True, 'matches': 0}) is allowed
    assert len(calls) == 1
    query = calls[0]['ldap_filter']
    assert query.startswith('(|') and '(objectClass=computer)' not in query
    for clause in ('sAMAccountName=alt-a1-pc3$', 'dNSHostName=alt-a1-pc3.sosnadmin.local',
            'servicePrincipalName=HOST/alt-a1-pc3', 'servicePrincipalName=HOST/alt-a1-pc3.sosnadmin.local',
            'servicePrincipalName=RestrictedKrbHost/alt-a1-pc3',
            'servicePrincipalName=RestrictedKrbHost/alt-a1-pc3.sosnadmin.local'):
        assert '('+clause+')' in query


def test_collision_transport_failure_never_becomes_absence():
    from alt_deploy.ad_directory import ADDirectory
    def transport(**kwargs):
        raise ControlError('ad_limit', 'Synthetic exhausted query budget', 4)
    with pytest.raises(ControlError):
        backend('setup_partial_observation').directory_collisions(ADDirectory(transport), 'alt-a1-pc3')


@pytest.mark.parametrize('fault', ['credentials', 'processes', 'uuid', 'native_hash', 'sudo', 'clock', 'goa', 'boot', 'domain', 'pam_hash', 'sysv_hook'])
def test_unexpected_tdb_key_denies_partial_state(partial_failure, fault):
    setup, job, machine, *_ = partial_failure
    closed = backend('setup_closed_failure').ClosedFailureEvidence(setup.settings).load(job.job_id)
    service, native, quiet, _ = observer(partial_failure)
    if fault == 'credentials': quiet['credentials_absent'] = False
    elif fault == 'processes': quiet['processes_absent'] = False
    elif fault == 'uuid': quiet['uuid'] = 'e'*36
    elif fault == 'native_hash': native['tools']['/usr/sbin/system-auth']['sha256'] = 'e'*64
    elif fault == 'sudo': native['local_admin']['sudo'] = False
    elif fault == 'clock': native['clock_synchronized'] = False
    elif fault == 'goa': native['goa']['installed'] = True
    elif fault == 'domain': native['domain'] = 'other.example'
    elif fault == 'pam_hash': native['files']['/etc/pam.d/system-auth-local']['sha256'] = 'e'*64
    elif fault == 'sysv_hook': native['files']['/etc/rc.d/init.d/sssd'] = {'present': True, 'sha256': 'e'*64}
    else: native['boot_id'] = 'e'*36
    with pytest.raises(ControlError): service.observe(closed, mode='partial_ad')


def test_packaged_inactive_sysv_compatibility_hook_is_bound(partial_failure):
    setup, job, *_ = partial_failure
    closed = backend('setup_closed_failure').ClosedFailureEvidence(setup.settings).load(job.job_id)
    service, native, *_ = observer(partial_failure)
    native['files']['/etc/rc.d/init.d/sssd'] = {'present': True, 'kind': 'file', 'uid': 0, 'gid': 0,
        'mode': 0o755, 'size': 2355, 'sha256': '2eddd28fdd945c0db4ab0fe6c75d8f615e6c9bc64ad27824f74180a2f27abb85'}
    assert service.observe(closed, mode='partial_ad')['partial_local']['native']['files']['/etc/rc.d/init.d/sssd'] == native['files']['/etc/rc.d/init.d/sssd']
