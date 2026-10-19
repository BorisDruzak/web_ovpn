"""Admission must reject before any local auth or directory mutation is possible."""
import base64
from functools import lru_cache
import importlib.util
import subprocess
import uuid
import json
import sys
import time
import os
from contextlib import contextmanager
from pathlib import Path
from types import SimpleNamespace

import pytest


HELPER = (Path(__file__).resolve().parents[2] / 'deploy/alt-linux/ansible/roles/'
          'domain_join/files/first_join_preflight.py')
BASE = 'DC=sosnadmin,DC=local'
OU = 'OU=TEST,' + BASE
SCHEMA = 'CN=Schema,CN=Configuration,' + BASE
SID = bytes.fromhex('0105000000000005150000000100000002000000030000004c040000')


@lru_cache(maxsize=1)
def helper():
    assert HELPER.is_file(), 'No AD quota/effective-rights admission exists before first join'
    spec = importlib.util.spec_from_file_location('join_admission_fixture', HELPER)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def ldif(dn, **attributes):
    lines = ['dn: ' + dn]
    for name, value in attributes.items():
        if value is None:
            continue
        for item in value if isinstance(value, list) else [value]:
            if isinstance(item, bytes):
                lines.append(name + ':: ' + base64.b64encode(item).decode())
            else:
                lines.append(name + ': ' + str(item))
    return '\n'.join(lines) + '\n\n'


class DirectoryFixture:
    """Only controlled read-process boundaries; all parsing/decisions are real."""
    def __init__(self, *, quota=10, created=10, effective=('computer',),
                 principal='svc-test@SOSNADMIN.LOCAL', user_changes=None,
                 truncated=False, ldap_rc=0, ou_guid=True):
        self.quota, self.created, self.effective = quota, created, effective
        self.principal, self.user_changes = principal, user_changes or {}
        self.truncated, self.ldap_rc, self.ou_guid = truncated, ldap_rc, ou_guid
        self.calls = []

    def __call__(self, command):
        self.calls.append(command)
        if command == ['/usr/bin/klist']:
            return subprocess.CompletedProcess(command, 0,
                'Ticket cache: FILE:/private/cache\nDefault principal: ' + self.principal + '\n', '')
        assert command[0] == '/usr/bin/ldapsearch', 'Admission attempted a non-read operation'
        assert '-Y' in command and command[command.index('-Y') + 1] == 'GSSAPI'
        assert '-O' in command and 'minssf=56' in command
        assert '-w' not in command and '-W' not in command
        base = command[command.index('-b') + 1]
        scope = command[command.index('-s') + 1]
        if self.ldap_rc:
            return subprocess.CompletedProcess(command, self.ldap_rc, '', 'PRIVATE_SENTINEL')
        if base == '':
            raw = ldif('', dnsHostName='dc.sosnadmin.local', defaultNamingContext=BASE,
                       schemaNamingContext=SCHEMA)
        elif base == OU:
            values = dict(objectGUID=uuid.UUID('aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee').bytes_le
                          if self.ou_guid else None,
                          allowedChildClassesEffective=list(self.effective))
            raw = ldif(OU, **values)
        elif base == BASE and scope == 'base':
            raw = ldif(BASE, **{'ms-DS-MachineAccountQuota': self.quota})
        elif any('ms-DS-CreatorSID=' in x for x in command):
            raw = ''.join(ldif(f'CN=Fixture{i},' + OU, objectGUID=uuid.UUID(int=i+1).bytes_le)
                          for i in range(self.created))
            if self.truncated:
                return subprocess.CompletedProcess(command, 4, raw, 'Size limit exceeded PRIVATE_SENTINEL')
        else:
            values = dict(objectGUID=uuid.UUID('11111111-2222-3333-4444-555555555555').bytes_le,
                          objectSid=SID, userPrincipalName='svc-test@sosnadmin.local',
                          sAMAccountName='svc-test', userAccountControl='512',
                          **{'msDS-User-Account-Control-Computed': '0', 'accountExpires': '0'})
            values.update(self.user_changes)
            raw = ldif('CN=Service,' + BASE, **values)
        return subprocess.CompletedProcess(command, 0, raw, '')


def observe(fixture):
    return helper().check('ldap://sosnadmin.local', OU, 'svc-test@SOSNADMIN.LOCAL', fixture)


@pytest.mark.parametrize('quota,created', [(10, 10), (0, 10), (10, 0)])
def test_effective_delegation_is_quota_independent(quota, created):
    result = observe(DirectoryFixture(quota=quota, created=created))
    assert result['creation_mode'] == 'delegated'
    assert result['quota_applicable'] is False
    assert result['domain_quota'] == quota
    assert result['created_computers'] == created
    assert result['quota_remaining'] == max(0, quota-created)
    assert result['join_principal_sid'] == 'S-1-5-21-1-2-3-1100'
    assert result['ou_guid'] == 'aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee'
    assert result['dc'] == 'dc.sosnadmin.local'


@pytest.mark.parametrize('quota,created,code', [
    (10, 10, 'ad_join_quota_exhausted'),
    (0, 0, 'ad_join_quota_exhausted'),
    (10, 2, 'ad_join_create_rights_unproven'),
])
def test_no_effective_computer_right_stops_before_mutation(quota, created, code):
    api = helper()
    with pytest.raises(api.PreflightError) as caught:
        observe(DirectoryFixture(quota=quota, created=created, effective=('user',)))
    assert caught.value.code == code


@pytest.mark.parametrize('changes', [
    {'userAccountControl': '514'},
    {'msDS-User-Account-Control-Computed': '16'},
    {'msDS-User-Account-Control-Computed': '8388608'},
    {'accountExpires': '1'}, {'objectSid': None},
    {'userPrincipalName': 'other@sosnadmin.local'},
])
def test_join_identity_must_be_usable_and_complete(changes):
    api = helper()
    with pytest.raises(api.PreflightError):
        observe(DirectoryFixture(user_changes=changes))


@pytest.mark.parametrize('kwargs', [dict(truncated=True), dict(ou_guid=False),
    dict(ldap_rc=50), dict(ldap_rc=81), dict(principal='admin@SOSNADMIN.LOCAL')])
def test_missing_or_foreign_evidence_is_not_permission(kwargs):
    api = helper()
    with pytest.raises(api.PreflightError) as caught:
        observe(DirectoryFixture(**kwargs))
    assert 'PRIVATE_SENTINEL' not in str(caught.value)


@pytest.mark.parametrize('uri,ou', [
    ('ldap://example.org', OU), ('ldap://sosnadmin.local/anything', OU),
    ('ldap://sosnadmin.local', 'OU=TEST,DC=other,DC=local'),
    ('ldap://sosnadmin.local', OU + '\x00'),
])
def test_unapproved_input_cannot_reach_process(uri, ou):
    api = helper()
    def forbidden(command):
        pytest.fail('Unvalidated input reached a process')
    with pytest.raises(api.PreflightError):
        api.check(uri, ou, 'svc-test@SOSNADMIN.LOCAL', forbidden)


def controller_adapter():
    spec = importlib.util.find_spec('alt_deploy.ad_join_preflight')
    assert spec is not None, 'The controller cannot enforce AD admission yet'
    from alt_deploy.ad_join_preflight import ADJoinPreflight
    return ADJoinPreflight


class CredentialFixture:
    config = SimpleNamespace(uri='ldap://sosnadmin.local', credential_source='join-vault')

    @contextmanager
    def _credentials(self, environment):
        yield dict(environment, KRB5CCNAME='FILE:/private/fixture-cache'), []


def test_controller_propagates_safe_admission_not_raw_output(tmp_path):
    adapter = controller_adapter()
    from alt_deploy.errors import ControlError
    project = tmp_path / 'project'
    asset = project / 'roles/domain_join/files/first_join_preflight.py'
    asset.parent.mkdir(parents=True)
    asset.write_bytes(HELPER.read_bytes())
    def runner(command, **options):
        assert command[:3] == [sys.executable, '-I', '-B']
        assert options['environment']['KRB5CCNAME'] == 'FILE:/private/fixture-cache'
        return 4, json.dumps({'status': 'blocked', 'code': 'ad_join_quota_exhausted'}), 'PRIVATE_SENTINEL'
    with pytest.raises(ControlError) as caught:
        adapter(SimpleNamespace(ansible_project_dir=project), transport=CredentialFixture(),
                runner=runner).observe(SimpleNamespace(computer_ou=OU))
    assert caught.value.code == 'ad_join_quota_exhausted'
    assert 'PRIVATE_SENTINEL' not in str(caught.value)


@pytest.mark.parametrize('change', [{'quota_applicable': True}, {'created_computers': True},
    {'domain_quota': -1}, {'extra': 'PRIVATE_SENTINEL'}, {'ou_guid': 'not-a-guid'}])
def test_controller_rejects_forged_helper_evidence(tmp_path, change):
    adapter = controller_adapter()
    from alt_deploy.errors import ControlError
    project = tmp_path / 'project'
    asset = project / 'roles/domain_join/files/first_join_preflight.py'
    asset.parent.mkdir(parents=True)
    asset.write_bytes(HELPER.read_bytes())
    evidence = observe(DirectoryFixture())
    evidence.update(change)
    with pytest.raises(ControlError):
        adapter(SimpleNamespace(ansible_project_dir=project), transport=CredentialFixture(),
            runner=lambda *a, **k: (0, json.dumps({'status': 'ready', 'evidence': evidence}), '')
        ).observe(SimpleNamespace(computer_ou=OU))


@pytest.mark.parametrize('mode', ['timeout', 'output'])
def test_reader_reaps_child_on_timeout_or_excessive_output(tmp_path, mode):
    api = helper()
    assert callable(getattr(api, 'read_process', None)), 'No bounded/reaping AD reader exists'
    pidfile = tmp_path / 'child.pid'
    child = ('import os,pathlib,time;pathlib.Path(' + repr(str(pidfile)) +
             ').write_text(str(os.getpid()));' +
             ("print('x'*200000,flush=True);time.sleep(60)" if mode == 'output' else 'time.sleep(60)'))
    start = time.monotonic()
    with pytest.raises(api.PreflightError) as caught:
        api.read_process([sys.executable, '-c', child], timeout=0.5, max_bytes=128)
    assert caught.value.code in ('ad_join_results_incomplete', 'ad_join_timeout')
    assert time.monotonic() - start < 3
    if pidfile.exists():
        with pytest.raises(ProcessLookupError):
            os.kill(int(pidfile.read_text()), 0)


def test_ad_reader_uses_stable_locale_for_kerberos_identity(monkeypatch):
    api = helper()
    monkeypatch.setenv('LC_ALL', 'ru_RU.UTF-8')
    result = api.read_process([sys.executable, '-c', 'import os;print(os.environ["LC_ALL"])'])
    assert result.stdout.strip() == 'C'


def test_setup_planning_blocks_quota_before_any_configuration(tmp_path):
    from test_setup_service import scenario, OU as selected_ou
    from alt_deploy.errors import ControlError
    setup, machine, user, observed, computer, calls = scenario(tmp_path)
    def admission(request):
        raise ControlError('ad_join_quota_exhausted', 'AD admission blocked', 4)
    setup.join_admission = admission
    with pytest.raises(ControlError) as caught:
        setup.plan(machine.uuid, user['login'], selected_ou, 'base')
    assert caught.value.code == 'ad_join_quota_exhausted'
    assert calls == [] and observed['domain'] == '' and not computer['exists']


def test_setup_rechecks_admission_before_dispatch(tmp_path):
    from test_setup_service import scenario, OU as selected_ou
    from alt_deploy.errors import ControlError
    setup, machine, user, observed, computer, calls = scenario(tmp_path)
    evidence = observe(DirectoryFixture())
    evidence['ou_guid'] = 'bbbbbbbb-cccc-dddd-eeee-ffffffffffff'
    setup.join_admission = lambda request: evidence
    plan = setup.plan(machine.uuid, user['login'], selected_ou, 'base')
    assert plan['payload'].get('ad_join_admission') == evidence
    def revoked(request):
        raise ControlError('ad_join_create_rights_unproven', 'AD rights revoked', 4)
    setup.join_admission = revoked
    with pytest.raises(ControlError) as caught:
        setup._execute_locked(plan['plan_id'], plan['sha256'])
    assert caught.value.code == 'ad_join_create_rights_unproven'
    assert calls == [] and observed['domain'] == '' and not computer['exists']
