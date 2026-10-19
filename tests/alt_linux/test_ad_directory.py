from __future__ import annotations

import base64
import sys
import uuid
from datetime import datetime, timezone
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[2] / 'deploy/alt-linux/control'))
from alt_deploy.errors import ControlError


def directory_api():
    from alt_deploy import ad_directory
    return ad_directory


def user_ldif(**changes):
    values = {
        'dn': 'CN=Synthetic User,OU=Staff,DC=sosnadmin,DC=local',
        'objectClass': ['top', 'person', 'organizationalPerson', 'user'],
        'sAMAccountName': 'synthetic.user',
        'userPrincipalName': 'synthetic.user@sosnadmin.local',
        'displayName': 'Synthetic User',
        'objectGUID': uuid.UUID('11111111-2222-3333-4444-555555555555').bytes_le,
        'userAccountControl': '512',
        'msDS-User-Account-Control-Computed': '0',
        'accountExpires': '0',
    }
    values.update(changes)
    lines = []
    for key, value in values.items():
        if value is None:
            continue
        for item in value if isinstance(value, list) else [value]:
            if isinstance(item, bytes):
                lines.append(key + ':: ' + base64.b64encode(item).decode())
            else:
                lines.append(f'{key}: {item}')
    return '\n'.join(lines) + '\n\n'


def test_exact_search_uses_user_only_filter_and_no_writes():
    api = directory_api()
    calls = []
    directory = api.ADDirectory(lambda **kw: calls.append(kw) or user_ldif())
    result = directory.user('SYNTHETIC.USER@sosnadmin.local')
    assert result['login'] == 'synthetic.user'
    assert result['object_guid'] == '11111111-2222-3333-4444-555555555555'
    assert result['state'] == 'enabled'
    assert calls[0]['ldap_filter'] == '(&(objectCategory=person)(objectClass=user)(sAMAccountName=synthetic.user))'
    assert calls[0]['scope'] == 'sub'


@pytest.mark.parametrize('login', ['user*', 'user)(objectClass=*)', 'user@example.org', '-x', '', 'a' * 64])
def test_invalid_login_never_reaches_transport(login):
    api = directory_api()
    def forbidden(**kw):
        pytest.fail('invalid input reached LDAP')
    with pytest.raises(ControlError, match='login'):
        api.ADDirectory(forbidden).user(login)


@pytest.mark.parametrize('changes,code', [
    ({'userAccountControl': '514'}, 'ad_user_disabled'),
    ({'msDS-User-Account-Control-Computed': '16'}, 'ad_user_locked'),
    ({'accountExpires': '1'}, 'ad_user_expired'),
    ({'accountExpires': None}, 'ad_user_state_unknown'),
    ({'msDS-User-Account-Control-Computed': None}, 'ad_user_state_unknown'),
    ({'objectGUID': b'bad'}, 'ad_user_identity_invalid'),
    ({'objectClass': ['computer', 'user']}, 'ad_user_identity_invalid'),
    ({'userPrincipalName': 'other@sosnadmin.local'}, 'ad_user_identity_invalid'),
    ({'sAMAccountName': 'other'}, 'ad_user_identity_invalid'),
])
def test_unusable_account_fails_closed(changes, code):
    api = directory_api()
    with pytest.raises(ControlError) as caught:
        api.ADDirectory(lambda **kw: user_ldif(**changes)).user('synthetic.user')
    assert caught.value.code == code


@pytest.mark.parametrize('ldif,code', [('', 'ad_user_not_found'), (user_ldif() * 2, 'ad_user_ambiguous')])
def test_missing_or_ambiguous_user(ldif, code):
    api = directory_api()
    with pytest.raises(ControlError) as caught:
        api.ADDirectory(lambda **kw: ldif).user('synthetic.user')
    assert caught.value.code == code


def test_ldap_escape_and_bounded_strict_ldif():
    api = directory_api()
    assert api.escape_filter('a*(b)\\\x00') == r'a\2a\28b\29\5c\00'
    for invalid in ['dn: a\nobjectGUID:< file:///secret\n', 'dn: a\ndn: b\n', 'dn:: !!!!\n', 'x' * 262145]:
        with pytest.raises(ControlError):
            api.parse_ldif(invalid)


@pytest.mark.parametrize('hostname', ['alt-a1-pc3', 'alt-arh1-pc1', 'win-office-pc12'])
def test_computer_check_searches_whole_domain(hostname):
    api = directory_api()
    calls = []
    result = api.ADDirectory(lambda **kw: calls.append(kw) or '').computer(hostname)
    assert result == {'hostname': hostname, 'exists': False, 'objects': []}
    assert calls[0]['base'] == 'DC=sosnadmin,DC=local'
    assert calls[0]['ldap_filter'] == '(&(objectClass=computer)(sAMAccountName=' + hostname + '$))'


@pytest.mark.parametrize('hostname', ['alt-arh1-pc01', 'alt-arh11-pc1', 'alt-abcdefgh-pc12', 'alt-arh1-pc1.example', 'alt-arh1-pc1)(x=*)'])
def test_invalid_computer_name_never_reaches_directory(hostname):
    def forbidden(**kwargs):
        pytest.fail('invalid hostname reached LDAP')
    with pytest.raises(ControlError) as caught:
        directory_api().ADDirectory(forbidden).computer(hostname)
    assert caught.value.code == 'hostname_invalid'


def test_transport_gssapi_fixed_command_and_sealed_environment(tmp_path):
    from alt_deploy.ad_transport import DirectoryConfig, LDAPTransport
    calls = []
    config = DirectoryConfig(uri='ldap://sosnadmin.local', approved_ous=())
    transport = LDAPTransport(config, runner=lambda cmd, **kw: calls.append((cmd, kw)) or (0, 'dn: DC=sosnadmin,DC=local\n', ''))
    transport(ldap_filter='(objectClass=organizationalUnit)', attributes=('dn',), base='DC=sosnadmin,DC=local', scope='sub')
    command, options = calls[0]
    assert command[:7] == ['/usr/bin/ldapsearch', '-LLL', '-Q', '-Y', 'GSSAPI', '-O', 'minssf=56']
    assert '-w' not in command and '-x' not in command
    assert options['environment']['LDAPTLS_REQCERT'] == 'demand'
    assert '-z' in command and '-l' in command


@pytest.mark.parametrize('uri', ['http://dc', 'ldap://dc/secret', 'ldap://user:password@dc', 'ldap://dc?query', 'ldap://dc\n-x'])
def test_transport_rejects_unsafe_uri(uri):
    from alt_deploy.ad_transport import DirectoryConfig
    with pytest.raises(ControlError):
        DirectoryConfig(uri=uri, approved_ous=())


@pytest.mark.parametrize('rc,stderr,code', [(49, 'SECRET password', 'ad_authentication_failed'), (50, 'SECRET', 'ad_permission_denied'), (81, 'SECRET', 'ad_dc_unavailable'), (4, 'SECRET', 'ad_results_limit'), (1, 'TLS: peer certificate untrusted SECRET', 'ad_tls_failed'),
    (81, "ldap_sasl_interactive_bind_s: Can't contact LDAP server (-1)", 'ad_dc_unavailable'),
    (91, 'GSSAPI connection failed', 'ad_dc_unavailable'),
    (255, "ldap_sasl_interactive_bind_s: Can't contact LDAP server (-1)", 'ad_dc_unavailable'),
    (81, 'SASL TLS: peer certificate untrusted SECRET', 'ad_tls_failed'),
    (1, 'GSSAPI: credentials unavailable SECRET', 'ad_kerberos_failed'),
])
def test_transport_safe_errors(rc, stderr, code):
    from alt_deploy.ad_transport import DirectoryConfig, LDAPTransport
    transport = LDAPTransport(DirectoryConfig(uri='ldap://sosnadmin.local', approved_ous=()), runner=lambda cmd, **kw: (rc, '', stderr))
    with pytest.raises(ControlError) as caught:
        transport(ldap_filter='(objectClass=organizationalUnit)', attributes=('dn',), base='DC=sosnadmin,DC=local', scope='sub')
    assert caught.value.code == code
    assert 'SECRET' not in str(caught.value)
