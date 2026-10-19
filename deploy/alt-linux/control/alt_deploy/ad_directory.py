"""Read-only AD queries; transport receives fixed filters and attributes only."""
from __future__ import annotations

import base64
import re
import uuid
from datetime import datetime, timezone

from .errors import ControlError

DOMAIN = 'sosnadmin.local'
BASE_DN = 'DC=sosnadmin,DC=local'
MAX_BYTES = 262144
MAX_RESULTS = 256
LOGIN_RE = re.compile(r'^[a-z0-9][a-z0-9._-]{0,62}$')
HOST_RE = re.compile(r'^(?=.{1,15}$)(lin|alt|win|deb)-[a-z]+[0-9]?-(pc[1-9][0-9]*)$')
USER_ATTRIBUTES = ('dn', 'objectClass', 'sAMAccountName', 'userPrincipalName',
                   'displayName', 'department', 'objectGUID', 'objectSid',
                   'userAccountControl', 'msDS-User-Account-Control-Computed', 'accountExpires')
COMPUTER_ATTRIBUTES = ('dn', 'objectClass', 'sAMAccountName', 'dNSHostName', 'objectGUID', 'objectSid')


def fail(code: str, message: str) -> ControlError:
    return ControlError(code, message, 4)


def normalize_login(value: str) -> str:
    value = value.strip().lower()
    if '@' in value:
        login, realm = value.split('@', 1)
        if realm != DOMAIN:
            raise fail('ad_login_invalid', 'AD login domain is invalid')
        value = login
    if not LOGIN_RE.fullmatch(value):
        raise fail('ad_login_invalid', 'AD login is invalid')
    return value


def escape_filter(value: str) -> str:
    replacements = {'\\': r'\5c', '*': r'\2a', '(': r'\28', ')': r'\29', '\x00': r'\00'}
    return ''.join(replacements.get(char, char) for char in value)


def parse_ldif(raw: str) -> list[dict[str, list[bytes]]]:
    """Reject URL values, duplicate singleton attributes and incomplete data."""
    return _parse_ldif(raw, multivalued=frozenset({'objectclass'}))


def _parse_ldif(raw: str, *, multivalued: frozenset[str], max_bytes=None, max_results=None) -> list[dict[str, list[bytes]]]:
    try:
        if len(raw.encode('utf-8')) > (MAX_BYTES if max_bytes is None else max_bytes):
            raise ValueError
        unfolded: list[str] = []
        for line in raw.splitlines():
            if line.startswith(' '):
                if not unfolded or not unfolded[-1]:
                    raise ValueError
                unfolded[-1] += line[1:]
            else:
                unfolded.append(line)
        entries = []
        current: dict[str, list[bytes]] = {}
        for line in [*unfolded, '']:
            if not line:
                if current:
                    if 'dn' not in current or len(entries) >= (MAX_RESULTS if max_results is None else max_results):
                        raise ValueError
                    entries.append(current)
                    current = {}
                continue
            if line.startswith('#'):
                continue
            name, separator, value = line.partition(':')
            name = name.lower()
            if not separator or not re.fullmatch(r'[a-z][a-z0-9;-]*', name):
                raise ValueError
            if value.startswith('<'):
                raise ValueError
            if value.startswith(':'):
                decoded = base64.b64decode(value[1:].lstrip(' '), validate=True)
            else:
                decoded = value.lstrip(' ').encode('utf-8')
            if len(decoded) > 8192 or (name in current and name not in multivalued):
                raise ValueError
            current.setdefault(name, []).append(decoded)
        return entries
    except (ValueError, UnicodeError) as exc:
        raise fail('ad_response_invalid', 'AD response is invalid or exceeds limits') from exc


def text(entry, name: str, *, required: bool = True) -> str:
    values = entry.get(name.lower(), [])
    if not values and not required:
        return ''
    if len(values) != 1:
        raise ValueError
    result = values[0].decode('utf-8')
    if not result or any(ord(char) < 32 or ord(char) == 127 for char in result):
        raise ValueError
    return result


def identity(entry) -> dict[str, str]:
    raw_guid = entry.get('objectguid', [])
    if len(raw_guid) != 1 or len(raw_guid[0]) != 16:
        raise ValueError
    guid = uuid.UUID(bytes_le=raw_guid[0])
    if guid.int == 0:
        raise ValueError
    result = {'object_guid': str(guid)}
    if 'objectsid' in entry:
        sid = entry['objectsid'][0]
        if len(sid) < 12 or sid[0] != 1 or len(sid) != 8 + sid[1] * 4:
            raise ValueError
        authority = int.from_bytes(sid[2:8], 'big')
        parts = [str(int.from_bytes(sid[i:i+4], 'little')) for i in range(8, len(sid), 4)]
        result['object_sid'] = 'S-1-' + str(authority) + '-' + '-'.join(parts)
    return result


class ADDirectory:
    def __init__(self, transport, *, clock=None):
        self.transport = transport
        self.clock = clock or (lambda: datetime.now(timezone.utc))

    def _query(self, ldap_filter, attributes, *, base=BASE_DN, scope='sub'):
        return parse_ldif(self.transport(ldap_filter=ldap_filter, attributes=attributes, base=base, scope=scope))

    def user(self, login: str, *, require_usable: bool = True) -> dict[str, object]:
        login = normalize_login(login)
        entries = self._query('(&(objectCategory=person)(objectClass=user)(sAMAccountName=' + escape_filter(login) + '))', USER_ATTRIBUTES)
        if not entries:
            raise fail('ad_user_not_found', 'AD user was not found')
        if len(entries) != 1:
            raise fail('ad_user_ambiguous', 'AD user search is ambiguous; select an exact login')
        entry = entries[0]
        try:
            classes = {value.decode('ascii').lower() for value in entry.get('objectclass', [])}
            if 'user' not in classes or 'computer' in classes:
                raise ValueError
            found_login = text(entry, 'samaccountname').lower()
            upn = text(entry, 'userprincipalname').lower()
            if found_login != login or upn != login + '@' + DOMAIN:
                raise ValueError
            result = dict(identity(entry), login=login, upn=upn,
                          display_name=text(entry, 'displayname', required=False),
                          dn=text(entry, 'dn'), department=text(entry, 'department', required=False))
            if not result['dn'].casefold().endswith(',' + BASE_DN.casefold()):
                raise ValueError
        except (ValueError, UnicodeError) as exc:
            raise fail('ad_user_identity_invalid', 'AD user identity is missing or contradictory') from exc
        try:
            uac = int(text(entry, 'useraccountcontrol'))
            computed = int(text(entry, 'msds-user-account-control-computed'))
            expiry = int(text(entry, 'accountexpires'))
            if uac < 0 or computed < 0 or not 0 <= expiry <= 9223372036854775807:
                raise ValueError
            now = self.clock()
            windows_now = int((now.timestamp() + 11644473600) * 10000000)
            if uac & 2:
                state = 'disabled'
            elif computed & 16 or uac & 16:
                state = 'locked'
            elif expiry not in (0, 9223372036854775807) and expiry <= windows_now:
                state = 'expired'
            elif computed & 8388608:
                state = 'password_expired'
            else:
                state = 'enabled'
        except (ValueError, UnicodeError) as exc:
            raise fail('ad_user_state_unknown', 'AD user state cannot be verified') from exc
        result['state'] = state
        if require_usable and state != 'enabled':
            raise fail('ad_user_' + state, 'AD user account is ' + state.replace('_', ' '))
        return result

    def ous(self) -> list[dict[str, str]]:
        entries = self._query('(objectClass=organizationalUnit)', ('dn', 'ou', 'objectGUID'))
        try:
            return sorted([dict(identity(entry), dn=text(entry, 'dn'), name=text(entry, 'ou')) for entry in entries], key=lambda entry: entry['dn'].casefold())
        except (ValueError, UnicodeError) as exc:
            raise fail('ad_response_invalid', 'AD OU identity is invalid') from exc

    def computer(self, hostname: str) -> dict[str, object]:
        hostname = hostname.strip().lower()
        if not HOST_RE.fullmatch(hostname):
            raise fail('hostname_invalid', 'Computer hostname is invalid')
        entries = self._query('(&(objectClass=computer)(sAMAccountName=' + escape_filter(hostname) + '$))', COMPUTER_ATTRIBUTES)
        try:
            objects = []
            for entry in entries:
                classes = {value.decode('ascii').lower() for value in entry.get('objectclass', [])}
                if 'computer' not in classes or text(entry, 'samaccountname').lower() != hostname + '$':
                    raise ValueError
                objects.append(dict(identity(entry), dn=text(entry, 'dn'), dns_hostname=text(entry, 'dnshostname', required=False)))
        except (ValueError, UnicodeError) as exc:
            raise fail('ad_computer_identity_invalid', 'AD computer identity is invalid') from exc
        return {'hostname': hostname, 'exists': bool(objects), 'objects': objects}
