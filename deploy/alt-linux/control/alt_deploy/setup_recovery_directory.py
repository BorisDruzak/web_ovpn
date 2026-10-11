"""Fixed, read-only recovery identity queries; no LDAP mutation API."""
from __future__ import annotations

import re
import uuid
from dataclasses import replace
from datetime import datetime, timezone
from urllib.parse import urlsplit

from .ad_directory import (ADDirectory, BASE_DN, DOMAIN, _parse_ldif,
                           escape_filter, fail, identity, text)
from .ad_transport import DirectoryConfig, LDAPTransport

RECOVERY_ATTRIBUTES = ('dn', 'objectClass', 'sAMAccountName', 'dNSHostName',
                       'objectGUID', 'objectSid', 'whenCreated', 'pwdLastSet',
                       'msDS-KeyVersionNumber', 'userAccountControl', 'servicePrincipalName')


class RecoveryLDAPTransport(LDAPTransport):
    minimum_ssf = 128

    def __init__(self, config, **kwargs):
        if config.auth != 'gssapi':
            raise fail('recovery_directory_protection_required', 'Recovery requires a GSSAPI sealed directory connection')
        super().__init__(config, **kwargs)


def _one(entries):
    if len(entries) != 1:
        raise ValueError
    return entries[0]


def _has_class(entry, name):
    return name in {value.decode('ascii').lower() for value in entry.get('objectclass', [])}


def _number(entry, name, maximum):
    value = text(entry, name)
    if not re.fullmatch('[0-9]{1,19}', value) or not 1 <= int(value) <= maximum:
        raise ValueError
    return int(value)


def _created(entry):
    value = text(entry, 'whenCreated')
    if not re.fullmatch(r'[0-9]{14}(?:\.[0-9]{1,6})?Z', value):
        raise ValueError
    pattern = '%Y%m%d%H%M%S.%fZ' if '.' in value else '%Y%m%d%H%M%SZ'
    return datetime.strptime(value, pattern).replace(tzinfo=timezone.utc).isoformat()


class RecoveryDirectory(ADDirectory):
    @classmethod
    def from_controller_config(cls, settings, *, config=None, runner=None):
        config = config or DirectoryConfig.load()
        discovery = cls(RecoveryLDAPTransport(config, settings=settings, runner=runner))
        try:
            root = _one(discovery._query('(objectClass=*)', ('dnsHostName', 'defaultNamingContext'),
                                        base='', scope='base'))
            hostname = text(root, 'dnsHostName').lower()
            if (root.get('dn') != [b'']
                    or not re.fullmatch(r'[a-z0-9][a-z0-9-]{0,62}\.' + re.escape(DOMAIN), hostname)
                    or text(root, 'defaultNamingContext').casefold() != BASE_DN.casefold()):
                raise ValueError
            parsed = urlsplit(config.uri)
            pinned_uri = parsed.scheme + '://' + hostname + ((':' + str(parsed.port)) if parsed.port else '')
            # The authenticated discovery is read-only; configuration on disk
            # stays unchanged. All subsequent requests use this one DC URI.
            pinned = replace(config, uri=pinned_uri)
            return cls(RecoveryLDAPTransport(pinned, settings=settings, runner=runner))
        except (ValueError, KeyError, TypeError, AttributeError, UnicodeError) as exc:
            raise fail('recovery_dc_identity_invalid', 'Recovery could not pin one authenticated domain controller') from exc

    def _writable_dc(self):
        root = _one(self._query('(objectClass=*)', ('dnsHostName', 'defaultNamingContext',
                    'configurationNamingContext', 'dsServiceName', 'isSynchronized'), base='', scope='base'))
        hostname = text(root, 'dnsHostName').lower()
        configuration = 'CN=Configuration,' + BASE_DN
        ntds_dn = text(root, 'dsServiceName')
        if (root.get('dn') != [b'']
                or self.transport.config.auth != 'gssapi' or self.transport.minimum_ssf < 128
                or hostname != urlsplit(self.transport.config.uri).hostname
                or not re.fullmatch(r'[a-z0-9][a-z0-9-]{0,62}\.' + re.escape(DOMAIN), hostname)
                or text(root, 'defaultNamingContext').casefold() != BASE_DN.casefold()
                or text(root, 'configurationNamingContext').casefold() != configuration.casefold()
                or text(root, 'isSynchronized') != 'TRUE'
                or not ntds_dn.casefold().startswith('cn=ntds settings,')
                or not ntds_dn.casefold().endswith(',' + configuration.casefold())):
            raise ValueError
        ntds = _one(self._query('(objectClass=nTDSDSA)', ('dn', 'objectClass', 'objectGUID', 'msDS-isRODC'),
                                base=ntds_dn, scope='base'))
        if (not _has_class(ntds, 'ntdsdsa') or text(ntds, 'dn').casefold() != ntds_dn.casefold()
                or text(ntds, 'msDS-isRODC') != 'FALSE'):
            raise ValueError
        domain = _one(self._query('(objectClass=domainDNS)', ('dn', 'objectClass', 'objectGUID', 'objectSid'),
                                  base=BASE_DN, scope='base'))
        domain_identity = identity(domain)
        if (not _has_class(domain, 'domaindns') or text(domain, 'dn').casefold() != BASE_DN.casefold()
                or not re.fullmatch(r'S-1-5-21-[0-9]+-[0-9]+-[0-9]+', domain_identity.get('object_sid', ''))):
            raise ValueError
        return {'uri': self.transport.config.uri, 'dns_hostname': hostname,
                'ntds_guid': identity(ntds)['object_guid'], 'domain_guid': domain_identity['object_guid'],
                'domain_sid': domain_identity['object_sid'], 'is_writable': True}

    def inspect_computer(self, hostname, computer_guid):
        try:
            if (not isinstance(computer_guid, str) or str(uuid.UUID(computer_guid)) != computer_guid
                    or uuid.UUID(computer_guid).int == 0):
                raise ValueError
            found = self.computer(hostname)
            hostname = found['hostname']
            named = _one(found['objects'])
            if named['object_guid'] != computer_guid:
                raise ValueError
            raw = self.transport(ldap_filter='(objectClass=computer)', attributes=RECOVERY_ATTRIBUTES,
                                 base='<GUID=' + computer_guid + '>', scope='base')
            entry = _one(_parse_ldif(raw, multivalued=frozenset({'objectclass', 'serviceprincipalname'})))
            result = dict(identity(entry), dn=text(entry, 'dn'), dns_hostname=text(entry, 'dNSHostName').lower(),
                          sam_account_name=text(entry, 'sAMAccountName').lower(), when_created=_created(entry),
                          pwd_last_set=_number(entry, 'pwdLastSet', 9223372036854775807),
                          kvno=_number(entry, 'msDS-KeyVersionNumber', 2147483647),
                          uac=_number(entry, 'userAccountControl', 2147483647))
            if (not _has_class(entry, 'computer')
                    or result['object_guid'] != computer_guid or result['object_sid'] != named.get('object_sid')
                    or result['dn'].casefold() != named['dn'].casefold()
                    or result['dns_hostname'] != hostname + '.' + DOMAIN
                    or result['sam_account_name'] != hostname + '$'
                    or result['uac'] & 2 or result['uac'] & 0x3800 != 0x1000):
                raise ValueError
            spns = [value.decode('utf-8') for value in entry.get('serviceprincipalname', [])]
            expected = {prefix + name for prefix in ('host/', 'restrictedkrbhost/')
                        for name in (hostname, hostname + '.' + DOMAIN)}
            if len(spns) != 4 or {value.casefold() for value in spns} != expected:
                raise ValueError
            result['spns'] = sorted(spns, key=str.casefold)
            result['dc'] = self._writable_dc()
            if (not result['object_sid'].startswith(result['dc']['domain_sid'] + '-')
                    or not re.fullmatch(re.escape(result['dc']['domain_sid']) + r'-[0-9]+', result['object_sid'])):
                raise ValueError
            collision_filter = '(|(dNSHostName=' + escape_filter(result['dns_hostname']) + ')' + ''.join(
                '(servicePrincipalName=' + escape_filter(value) + ')' for value in result['spns']) + ')'
            collision = _one(self._query(collision_filter, ('dn', 'objectClass', 'objectGUID')))
            if (identity(collision)['object_guid'] != computer_guid
                    or text(collision, 'dn').casefold() != result['dn'].casefold()):
                raise ValueError
            return result
        except (ValueError, KeyError, TypeError, AttributeError, UnicodeError) as exc:
            raise fail('recovery_computer_identity_invalid', 'Recovery requires one unchanged computer identity, exact SPNs and a pinned writable DC') from exc
