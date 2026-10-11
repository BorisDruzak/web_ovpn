from __future__ import annotations

import base64
import uuid
from types import SimpleNamespace

import pytest

from alt_deploy.errors import ControlError

GUID = '11111111-2222-3333-4444-55555555555a'
DOMAIN_GUID = 'aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee'
SID = 'S-1-5-21-111-222-333'
BASE = 'DC=sosnadmin,DC=local'
HOST = 'alt-a1-pc3'
OU = 'OU=Synthetic,' + BASE
NTDS = 'CN=NTDS Settings,CN=synthetic-dc,CN=Servers,CN=Synthetic,CN=Sites,CN=Configuration,' + BASE
SPNS = ['HOST/' + HOST, 'HOST/' + HOST + '.sosnadmin.local',
        'RestrictedKrbHost/' + HOST, 'RestrictedKrbHost/' + HOST + '.sosnadmin.local']


def sid_bytes(rid=None):
    values = [21, 111, 222, 333] + ([] if rid is None else [rid])
    return bytes([1, len(values)]) + (5).to_bytes(6, 'big') + b''.join(x.to_bytes(4, 'little') for x in values)


def ldif(values):
    lines = []
    for key, value in values.items():
        if value is None:
            continue
        for item in value if isinstance(value, list) else [value]:
            if isinstance(item, bytes):
                lines.append(key + ':: ' + base64.b64encode(item).decode('ascii'))
            else:
                lines.append(key + ': ' + str(item))
    return '\n'.join(lines) + '\n\n'


def scenario(*, changes=None):
    values = {'dn': 'CN=' + HOST + ',' + OU, 'objectClass': ['top', 'user', 'computer'],
              'sAMAccountName': HOST + '$', 'dNSHostName': HOST + '.sosnadmin.local',
              'objectGUID': uuid.UUID(GUID).bytes_le, 'objectSid': sid_bytes(1001),
              'whenCreated': '20261011095453.0Z', 'pwdLastSet': '134046212930000000',
              'msDS-KeyVersionNumber': '2', 'userAccountControl': '4096', 'servicePrincipalName': SPNS}
    values.update(changes or {})
    domain = {'dn': BASE, 'objectClass': ['top', 'domain', 'domainDNS'],
              'objectGUID': uuid.UUID(DOMAIN_GUID).bytes_le, 'objectSid': sid_bytes()}
    root = {'dn': '', 'dnsHostName': 'synthetic-dc.sosnadmin.local', 'defaultNamingContext': BASE,
            'configurationNamingContext': 'CN=Configuration,' + BASE,
            'dsServiceName': NTDS, 'isSynchronized': 'TRUE'}
    ntds = {'dn': NTDS, 'objectClass': ['top', 'nTDSDSA'],
            'objectGUID': uuid.UUID('bbbbbbbb-cccc-dddd-eeee-ffffffffffff').bytes_le,
            'msDS-isRODC': 'FALSE'}
    collision = {'dn': values['dn'], 'objectClass': ['computer'], 'objectGUID': values['objectGUID']}
    calls = []
    class Transport:
        config = SimpleNamespace(uri='ldap://synthetic-dc.sosnadmin.local', auth='gssapi')
        minimum_ssf = 128
        def __call__(self, **kwargs):
            calls.append(kwargs)
            if kwargs['base'] == '':
                return ldif(root)
            if kwargs['base'] == NTDS:
                return ldif(ntds)
            if kwargs['base'].startswith('<GUID='):
                return ldif({key: values.get(key) for key in kwargs['attributes']})
            if kwargs['ldap_filter'] == '(objectClass=domainDNS)':
                return ldif(domain)
            if kwargs['ldap_filter'].startswith('(|'):
                return ldif(collision)
            return ldif({key: values.get(key) for key in kwargs['attributes']})
    return Transport(), calls, values, domain, root, ntds, collision


def inspect(transport, guid=GUID):
    from alt_deploy.setup_recovery_directory import RecoveryDirectory
    return RecoveryDirectory(transport).inspect_computer(HOST, guid)


def test_inspection_pins_guid_domain_writable_dc_and_exact_spns():
    transport, calls, *_ = scenario()
    result = inspect(transport)
    assert result['object_guid'] == GUID
    assert result['object_sid'] == SID + '-1001'
    assert result['when_created'] == '2026-10-11T09:54:53+00:00'
    assert result['kvno'] == 2 and result['pwd_last_set'] == 134046212930000000
    assert result['spns'] == sorted(SPNS, key=str.casefold)
    assert result['dc']['domain_sid'] == SID and result['dc']['domain_guid'] == DOMAIN_GUID
    assert result['dc']['is_writable'] is True
    assert any(call['base'] == '<GUID=' + GUID + '>' and call['scope'] == 'base' for call in calls)
    assert all('unicodePwd' not in call['attributes'] for call in calls)
    assert len(calls) == 6


@pytest.mark.parametrize('changes', [
    {'whenCreated': None}, {'whenCreated': 'invalid'}, {'whenCreated': '20260230000000.0Z'},
    {'pwdLastSet': '0'}, {'pwdLastSet': '-1'}, {'pwdLastSet': '9223372036854775808'},
    {'msDS-KeyVersionNumber': None}, {'msDS-KeyVersionNumber': '0'}, {'msDS-KeyVersionNumber': '2 '},
    {'userAccountControl': '4098'}, {'userAccountControl': '8192'}, {'userAccountControl': '2048'},
    {'objectSid': sid_bytes()}, {'objectGUID': uuid.UUID(DOMAIN_GUID).bytes_le},
    {'dNSHostName': 'other.sosnadmin.local'}, {'sAMAccountName': 'other$'},
    {'servicePrincipalName': SPNS[:-1]}, {'servicePrincipalName': SPNS + ['HOST/other']},
    {'servicePrincipalName': SPNS + [SPNS[0].lower()]}, {'servicePrincipalName': ['HOST/other']},
])
def test_incomplete_or_contradictory_computer_is_refused(changes):
    transport, *_ = scenario(changes=changes)
    with pytest.raises(ControlError):
        inspect(transport)


@pytest.mark.parametrize('section,key,value', [
    ('root', 'dnsHostName', 'other-dc.sosnadmin.local'),
    ('root', 'isSynchronized', 'FALSE'), ('root', 'defaultNamingContext', 'DC=other,DC=local'),
    ('root', 'dsServiceName', 'CN=Other,DC=other,DC=local'),
    ('root', 'dn', 'CN=Unexpected,' + BASE),
    ('ntds', 'msDS-isRODC', 'TRUE'), ('ntds', 'msDS-isRODC', None),
    ('ntds', 'objectClass', ['top', 'computer']),
    ('domain', 'objectSid', sid_bytes(1001)),
    ('domain', 'objectClass', ['top', 'computer']),
    ('collision', 'objectGUID', uuid.UUID(DOMAIN_GUID).bytes_le),
])
def test_rodc_endpoint_drift_domain_or_collision_refuses_recovery(section, key, value):
    transport, _, _, domain, root, ntds, collision = scenario()
    {'domain': domain, 'root': root, 'ntds': ntds, 'collision': collision}[section][key] = value
    with pytest.raises(ControlError):
        inspect(transport)


@pytest.mark.parametrize('guid', ['../outside', GUID.upper(), '00000000-0000-0000-0000-000000000000'])
def test_invalid_guid_never_reaches_transport(guid):
    transport, calls, *_ = scenario()
    with pytest.raises(ControlError):
        inspect(transport, guid)
    assert calls == []


def test_normal_directory_parser_still_refuses_repeated_spn_and_recovery_rejects_other_duplicates():
    from alt_deploy.ad_directory import parse_ldif
    raw = ldif({'dn': 'CN=Synthetic,' + BASE, 'servicePrincipalName': SPNS})
    with pytest.raises(ControlError):
        parse_ldif(raw)
    transport, *_ = scenario(changes={'pwdLastSet': ['1', '2']})
    with pytest.raises(ControlError):
        inspect(transport)


def test_recovery_transport_uses_minimum_128_and_refuses_other_authentication():
    from alt_deploy.ad_transport import DirectoryConfig
    from alt_deploy.setup_recovery_directory import RecoveryLDAPTransport
    calls = []
    config = DirectoryConfig(uri='ldap://synthetic-dc.sosnadmin.local', credential_source='ticket')
    transport = RecoveryLDAPTransport(config, runner=lambda argv, **kw: calls.append(argv) or (0, '', ''))
    transport(ldap_filter='(objectClass=*)', attributes=('dnsHostName',), base='', scope='base')
    assert 'minssf=128' in calls[0] and '-C' not in calls[0]
    with pytest.raises(ControlError):
        RecoveryLDAPTransport(DirectoryConfig(auth='starttls', credential_source='readonly-vault', ca_file='/synthetic/ca.pem'))
    from alt_deploy.ad_transport import LDAPTransport
    LDAPTransport(config, runner=lambda argv, **kw: calls.append(argv) or (0, '', ''))(
        ldap_filter='(objectClass=*)', attributes=('dnsHostName',), base='', scope='base')
    assert 'minssf=56' in calls[-1]


def test_authenticated_discovery_pins_dc_in_memory_without_changing_configuration():
    from alt_deploy.ad_transport import DirectoryConfig
    from alt_deploy.setup_recovery_directory import RecoveryDirectory
    _, _, _, _, root, _, _ = scenario()
    config = DirectoryConfig(uri='ldap://sosnadmin.local', credential_source='ticket')
    calls = []
    directory = RecoveryDirectory.from_controller_config(None, config=config,
        runner=lambda argv, **kw: calls.append(argv) or (0, ldif(root), ''))
    assert directory.transport.config.uri == 'ldap://synthetic-dc.sosnadmin.local'
    assert config.uri == 'ldap://sosnadmin.local'
    assert len(calls) == 1 and 'minssf=128' in calls[0]


@pytest.mark.parametrize('name', ['outside.example.org', 'invalid@host', 'sosnadmin.local'])
def test_discovery_refuses_untrusted_hostname_before_pinned_queries(name):
    from alt_deploy.ad_transport import DirectoryConfig
    from alt_deploy.setup_recovery_directory import RecoveryDirectory
    _, _, _, _, root, _, _ = scenario()
    root['dnsHostName'] = name
    calls = []
    with pytest.raises(ControlError):
        RecoveryDirectory.from_controller_config(None,
            config=DirectoryConfig(credential_source='ticket'),
            runner=lambda argv, **kw: calls.append(argv) or (0, ldif(root), ''))
    assert len(calls) == 1


@pytest.mark.parametrize('change', ['other_guid', 'other_sid', 'other_class', 'duplicate'])
def test_guid_base_response_cannot_replace_the_name_lookup_identity(change):
    transport, _, values, *_ = scenario()
    original = transport.__call__
    class ChangedTransport:
        config = transport.config
        minimum_ssf = 128
        def __call__(self, **kwargs):
            if kwargs['base'].startswith('<GUID='):
                entry = dict(values)
                if change == 'other_guid':
                    entry['objectGUID'] = uuid.UUID(DOMAIN_GUID).bytes_le
                elif change == 'other_sid':
                    entry['objectSid'] = sid_bytes(1002)
                elif change == 'other_class':
                    entry['objectClass'] = ['top', 'user']
                result = ldif(entry)
                return result * 2 if change == 'duplicate' else result
            return original(**kwargs)
    with pytest.raises(ControlError):
        inspect(ChangedTransport())
