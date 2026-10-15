from __future__ import annotations

import base64
import ipaddress
import struct

import pytest

from alt_deploy.errors import ControlError


def api():
    from alt_deploy import directory_dns
    return directory_dns


def record(kind, data, *, version=5, ttl=3600, timestamp=123):
    return struct.pack('<HHBBHI', len(data), kind, version, 0xF0, 0, 7) + struct.pack('!I', ttl) + struct.pack('<II', 0, timestamp) + data


def counted(name):
    labels = name.split('.')
    raw = b''.join(bytes([len(label)]) + label.encode('ascii') for label in labels) + b'\x00'
    return bytes([len(raw), len(labels)]) + raw


@pytest.mark.parametrize('kind,data,expected', [(1, ipaddress.ip_address('192.0.2.17').packed, '192.0.2.17'),
    (28, ipaddress.ip_address('2001:db8::17').packed, '2001:db8::17'),
    (5, counted('pc.example.invalid'), 'pc.example.invalid'), (12, counted('pc.example.invalid'), 'pc.example.invalid')])
def test_decode_a_aaaa_cname_ptr(kind, data, expected):
    row = api().decode_dns_record(record(kind, data), owner='pc', zone='example.invalid')
    assert row['value'] == expected
    assert row['name'] == 'pc.example.invalid'
    assert row['ttl'] == 3600 and row['timestamp'] == 123
    assert row['type'] == {1: 'A', 28: 'AAAA', 5: 'CNAME', 12: 'PTR'}[kind]


@pytest.mark.parametrize('raw', [b'', b'\x00' * 23, record(1, b'123'), record(1, b'1234', version=4),
    record(1, b'1234') + b'x', record(12, b'\x02\x01\x00\x00'), record(12, b'\x02\x01\xc0\x00')])
def test_reject_short_length_or_wrong_version(raw):
    with pytest.raises(ControlError) as exc:
        api().decode_dns_record(raw, owner='pc', zone='example.invalid')
    assert exc.value.code == 'directory_dns_record_invalid'


def config():
    from alt_deploy.directory_observer import DirectoryObserverConfig
    return DirectoryObserverConfig(domain_base='DC=example,DC=invalid', user_bases=('OU=Staff,DC=example,DC=invalid',),
        computer_bases=('OU=PCs,DC=example,DC=invalid',),
        dns_bases=('CN=MicrosoftDNS,DC=DomainDnsZones,DC=example,DC=invalid',), dns_zones=('example.invalid',))


def zone():
    return 'dn: DC=example.invalid,CN=MicrosoftDNS,DC=DomainDnsZones,DC=example,DC=invalid\nname: example.invalid\n\n'


def node(name='pc', records=None, tombstone=False):
    records = [record(1, ipaddress.ip_address('192.0.2.17').packed)] if records is None else records
    return (f'dn: DC={name},DC=example.invalid,CN=MicrosoftDNS,DC=DomainDnsZones,DC=example,DC=invalid\nname: {name}\n'
            + 'dNSTombstoned: ' + ('TRUE' if tombstone else 'FALSE') + '\n'
            + ''.join('dnsRecord:: ' + base64.b64encode(value).decode() + '\n' for value in records) + '\n')


def collect(raw):
    def read(**query):
        return {'ldif': zone() if 'objectClass=dnsZone' in query['ldap_filter'] else raw, 'truncated': False}
    return api().DirectoryDNS(config(), transport=read).collect()


def test_tombstone_is_not_live_dns():
    result = collect(node(tombstone=True))
    assert result['records'] == []
    assert result['tombstones'] == 1 and result['complete'] is True


def test_collects_multiple_records_and_counts_unsupported_types():
    result = collect(node(records=[record(1, ipaddress.ip_address('192.0.2.17').packed),
                                  record(1, ipaddress.ip_address('192.0.2.18').packed), record(16, b'text')]))
    assert len(result['records']) == 2
    assert result['unsupported_records'] == 1
    assert 'dn' not in result['records'][0]


@pytest.mark.parametrize('owner', ['*', '*.services'])
def test_valid_wildcard_owner_is_dns_evidence_and_does_not_abort_generation(owner):
    result = collect(node(owner))
    assert result['complete'] is True
    assert result['records'][0]['name'] == owner + '.example.invalid'
    assert result['records'][0]['type'] == 'A'


def test_unsupported_wildcard_record_is_counted_before_supported_owner_rules():
    result = collect(node('*', [record(16, b'synthetic TXT')]))
    assert result['complete'] is True and result['unsupported_records'] == 1 and result['records'] == []


def test_alias_loop_is_a_finding():
    raw = node('first', [record(5, counted('second.example.invalid'))]) + node('second', [record(5, counted('first.example.invalid'))])
    result = collect(raw)
    assert any(item['code'] == 'dns_alias_loop' for item in result['findings'])


def test_partition_failure_preserves_previous_complete_snapshot():
    calls = []
    def read(**query):
        calls.append(query)
        if len(calls) == 1:
            return {'ldif': zone(), 'truncated': False}
        raise ControlError('ad_permission_denied', 'private directory diagnostic')
    with pytest.raises(ControlError) as exc:
        api().DirectoryDNS(config(), transport=read).collect()
    assert 'private directory diagnostic' not in str(exc.value)


def test_never_marks_unconfigured_or_truncated_dns_complete():
    from alt_deploy.directory_observer import DirectoryObserverConfig
    with pytest.raises(ControlError):
        api().DirectoryDNS(DirectoryObserverConfig(), transport=lambda **kw: {}).collect()
    with pytest.raises(ControlError):
        api().DirectoryDNS(config(), transport=lambda **kw: {'ldif': zone(), 'truncated': True}).collect()


def test_collection_rejects_unapproved_zone_response():
    with pytest.raises(ControlError):
        api().DirectoryDNS(config(), transport=lambda **kw: {'ldif': zone().replace('example.invalid', 'other.invalid'), 'truncated': False}).collect()


def test_dns_query_classifies_timeout_nxdomain_and_no_answer():
    import dns.exception
    import dns.resolver
    class Resolver:
        nameservers = []
        def resolve(self, *args, **kwargs):
            raise self.problem
    for problem, code in [(dns.resolver.NXDOMAIN(), 'nxdomain'), (dns.exception.Timeout(), 'timeout'), (dns.resolver.NoAnswer(), 'no_answer')]:
        resolver = Resolver()
        resolver.problem = problem
        result = api().check_resolution('pc.example.invalid', 'A', server='192.0.2.53', resolver=resolver)
        assert result['state'] == code
        assert resolver.nameservers == ['192.0.2.53']


def test_dns_names_are_case_insensitive_for_identity_collisions():
    with pytest.raises(ControlError):
        collect(node('PC') + node('pc'))


@pytest.mark.parametrize('rc,code', [(49, 'directory_observer_authentication_failed'),
    (50, 'directory_observer_permission_denied'), (81, 'directory_observer_dc_unavailable'),
    (3, 'directory_observer_timeout')])
def test_source_errors_keep_actionable_safe_codes(rc, code):
    from alt_deploy.directory_observer import PagedLDAPTransport
    from contextlib import contextmanager
    @contextmanager
    def credentials(environment):
        yield environment, []
    source = PagedLDAPTransport(config(), runner=lambda *a, **k: (rc, '', 'private diagnostic'))
    source._credentials = credentials
    with pytest.raises(ControlError) as exc:
        source(ldap_filter='(objectClass=dnsZone)', attributes=('name',),
            base=config().dns_bases[0], deadline=source.monotonic() + 120)
    assert exc.value.code == code
    assert 'private diagnostic' not in str(exc.value)
