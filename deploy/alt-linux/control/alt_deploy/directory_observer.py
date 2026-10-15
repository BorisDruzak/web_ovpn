"""Restricted directory reads, independently configured from domain join.

OpenLDAP owns RFC2696 cookies. Critical automatic paging and a successful final
exit are mandatory: a late-page error never publishes a complete collection.
"""
from __future__ import annotations

import hashlib
import json
import os
import re
import stat
import time
from contextvars import ContextVar
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path

from .ad_directory import (BASE_DN, USER_ATTRIBUTES, COMPUTER_ATTRIBUTES,
                           _parse_ldif, escape_filter, fail, identity, text)
from .ad_transport import DirectoryConfig, LDAPTransport, bounded_run
from .errors import ControlError

MAX_OBJECTS = 10000
MAX_SOURCE_BYTES = 16 * 1024 * 1024
COLLECTION_SECONDS = 120


@dataclass(frozen=True)
class DirectoryObserverConfig:
    uri: str = DirectoryConfig().uri
    domain_base: str = BASE_DN
    user_bases: tuple[str, ...] = (BASE_DN,)
    computer_bases: tuple[str, ...] = (BASE_DN,)
    credential_source: str = 'readonly-vault'
    auth: str = 'gssapi'
    ca_file: str | None = None

    def __post_init__(self):
        try:
            if self.credential_source != 'readonly-vault':
                raise ValueError
            self.directory_config()
            if not re.fullmatch(r'DC=[a-zA-Z0-9-]+(?:,DC=[a-zA-Z0-9-]+)+', self.domain_base):
                raise ValueError
            for bases in (self.user_bases, self.computer_bases):
                if not isinstance(bases, tuple) or not 1 <= len(bases) <= 32:
                    raise ValueError
                known = []
                for base in bases:
                    if (not isinstance(base, str) or len(base) > 4096
                            or any(ord(c) < 32 or ord(c) == 127 for c in base)
                            or not (base.casefold() == self.domain_base.casefold()
                                    or base.casefold().endswith(',' + self.domain_base.casefold()))):
                        raise ValueError
                    folded = base.casefold()
                    if any(folded == old or folded.endswith(',' + old) or old.endswith(',' + folded) for old in known):
                        raise ValueError
                    known.append(folded)
        except (ValueError, TypeError, AttributeError, ControlError) as exc:
            raise fail('directory_observer_config_invalid', 'Read-only directory observer configuration is invalid') from exc

    def directory_config(self):
        return DirectoryConfig(uri=self.uri, credential_source=self.credential_source,
                               auth=self.auth, ca_file=self.ca_file)

    @classmethod
    def load(cls, path: Path):
        try:
            info = path.lstat()
            if (not stat.S_ISREG(info.st_mode) or info.st_size > 32768
                    or os.name != 'nt' and (info.st_uid != 0 or info.st_mode & 0o022)):
                raise ValueError
            document = json.loads(path.read_text(encoding='utf-8'))
            if not isinstance(document, dict) or set(document) - set(cls.__dataclass_fields__):
                raise ValueError
            for key in ('user_bases', 'computer_bases'):
                if key in document:
                    if not isinstance(document[key], list):
                        raise ValueError
                    document[key] = tuple(document[key])
            return cls(**document)
        except (OSError, ValueError, TypeError) as exc:
            raise fail('directory_observer_config_invalid', 'Read-only observer configuration cannot be read safely') from exc


class PagedLDAPTransport(LDAPTransport):
    def __init__(self, config, *, settings=None, runner=None, monotonic=time.monotonic):
        self.monotonic = monotonic
        self._deadline = ContextVar('directory_deadline', default=None)
        actual_runner = runner or bounded_run

        def limited_run(command, **options):
            remaining = self._remaining()
            options['timeout'] = min(options.get('timeout', 20), remaining)
            options['max_bytes'] = MAX_SOURCE_BYTES
            return actual_runner(command, **options)

        super().__init__(config.directory_config(), settings=settings, runner=limited_run)

    def _remaining(self):
        remaining = self._deadline.get() - self.monotonic()
        if remaining <= 0:
            raise fail('directory_observer_timeout', 'Directory collection deadline exceeded')
        return remaining

    def __call__(self, *, ldap_filter, attributes, base, deadline,
                 size_limit=MAX_OBJECTS + 1, allow_truncated=False):
        token = self._deadline.set(deadline)
        try:
            if type(size_limit) is not int or not 1 <= size_limit <= MAX_OBJECTS + 1:
                raise fail('directory_observer_query_invalid', 'Directory result bound is invalid')
            self._remaining()
            environment = {k: v for k, v in os.environ.items() if not k.startswith('LDAP')}
            environment.update(LC_ALL='C', LDAPTLS_REQCERT='demand', LDAPTLS_REQSAN='demand')
            if self.config.ca_file:
                environment['LDAPTLS_CACERT'] = self.config.ca_file
            command = ['/usr/bin/ldapsearch', '-LLL', '-E', '!pr=200/noprompt',
                       '-o', 'nettimeout=10', '-o', 'ldif-wrap=no', '-l', '120',
                       '-z', str(size_limit), '-H', self.config.uri, '-b', base, '-s', 'sub']
            if self.config.auth == 'gssapi':
                command += ['-Q', '-Y', 'GSSAPI', '-O', 'minssf=' + str(self.minimum_ssf)]
            elif self.config.auth == 'starttls':
                command += ['-ZZ']
            with self._credentials(environment) as (environment, authentication):
                rc, raw, _ = self.runner(command + authentication + [ldap_filter, *attributes],
                                         environment=environment, timeout=self._remaining())
            self._remaining()
            if rc and not (rc == 4 and allow_truncated):
                code = 'directory_observer_limit' if rc == 4 else 'directory_observer_query_failed'
                raise fail(code, 'Directory read failed; the source is incomplete')
            if not isinstance(raw, str) or len(raw.encode('utf-8')) > MAX_SOURCE_BYTES:
                raise fail('directory_observer_limit', 'Directory response exceeds the collection budget')
            return {'ldif': raw, 'truncated': rc == 4}
        finally:
            self._deadline.reset(token)


def _account_state(entry, now):
    try:
        uac = int(text(entry, 'useraccountcontrol'))
        computed = int(text(entry, 'msds-user-account-control-computed'))
        expiry = int(text(entry, 'accountexpires'))
        if uac < 0 or computed < 0 or not 0 <= expiry <= 9223372036854775807:
            return 'unknown'
        if uac & 2:
            return 'disabled'
        if computed & 16 or uac & 16:
            return 'locked'
        if expiry not in (0, 9223372036854775807) and expiry <= int((now.timestamp() + 11644473600) * 10000000):
            return 'expired'
        return 'password_expired' if computed & 8388608 else 'enabled'
    except (ValueError, UnicodeError):
        return 'unknown'


def project_entry(entry, *, kind, now):
    try:
        value = identity(entry)
        if not value.get('object_sid') or len(entry.get('objectsid', [])) != 1:
            raise ValueError
        classes = {v.decode('ascii').lower() for v in entry.get('objectclass', [])}
        if kind == 'user' and ('user' not in classes or 'computer' in classes) or kind == 'computer' and 'computer' not in classes:
            raise ValueError
        login = text(entry, 'samaccountname').lower()
        value.update(login=login, state=_account_state(entry, now))
        if kind == 'user':
            value.update(display_name=text(entry, 'displayname', required=False),
                         department=text(entry, 'department', required=False),
                         upn=text(entry, 'userprincipalname', required=False).lower())
        else:
            value['dns_hostname'] = text(entry, 'dnshostname', required=False).lower().rstrip('.')
        return value
    except (ValueError, UnicodeError, IndexError) as exc:
        raise fail('directory_observer_identity_invalid', 'Directory identity evidence is invalid') from exc


class DirectoryObserver:
    def __init__(self, config, *, settings=None, transport=None, monotonic=time.monotonic, clock=None):
        self.config, self.monotonic = config, monotonic
        self.transport = transport or PagedLDAPTransport(config, settings=settings, monotonic=monotonic)
        self.clock = clock or (lambda: datetime.now(timezone.utc))

    def _query(self, *, base, ldap_filter, attributes, deadline, size_limit=MAX_OBJECTS + 1, search=False):
        if self.monotonic() >= deadline:
            raise fail('directory_observer_timeout', 'Directory collection deadline exceeded')
        try:
            result = self.transport(base=base, ldap_filter=ldap_filter, attributes=attributes,
                                    deadline=deadline, size_limit=size_limit, allow_truncated=search)
            if (not isinstance(result, dict) or set(result) != {'ldif', 'truncated'}
                    or type(result['truncated']) is not bool or not isinstance(result['ldif'], str)):
                raise ValueError
            if self.monotonic() >= deadline:
                raise fail('directory_observer_timeout', 'Directory collection deadline exceeded')
            if result['truncated'] and not search:
                raise ValueError
            raw = result['ldif']
            entries = _parse_ldif(raw, multivalued=frozenset({'objectclass'}),
                                 max_bytes=MAX_SOURCE_BYTES, max_results=MAX_OBJECTS + 1)
            return entries, len(raw.encode('utf-8')), result['truncated']
        except (ControlError, ValueError, UnicodeError) as exc:
            code = exc.code if isinstance(exc, ControlError) and exc.code.startswith('directory_observer_') else 'directory_observer_incomplete'
            raise fail(code, 'Directory source is unavailable or incomplete; retain the last complete snapshot') from exc

    def search_users(self, query: str, *, limit: int = 50) -> dict:
        if (not isinstance(query, str) or not 2 <= len(query.strip()) <= 160
                or any(ord(c) < 32 or ord(c) == 127 or 0xD800 <= ord(c) <= 0xDFFF for c in query)
                or type(limit) is not int or not 1 <= limit <= 50):
            raise fail('directory_observer_search_invalid', 'Enter 2 to 160 characters and a result limit up to 50')
        tokens = query.strip().split()
        matches = ''.join('(|' + ''.join('(' + key + '=*' + escape_filter(token) + '*)'
                            for key in ('sAMAccountName', 'userPrincipalName', 'displayName', 'givenName', 'sn')) + ')' for token in tokens)
        ldap_filter = '(&(objectCategory=person)(objectClass=user)' + matches + ')'
        deadline, users, truncated = self.monotonic() + COLLECTION_SECONDS, {}, False
        byte_count = 0
        for base in self.config.user_bases:
            entries, size, partial = self._query(base=base, ldap_filter=ldap_filter, attributes=USER_ATTRIBUTES,
                                              deadline=deadline, size_limit=limit + 1, search=True)
            byte_count += size
            if byte_count > MAX_SOURCE_BYTES:
                raise fail('directory_observer_limit', 'Directory search exceeds its total budget')
            truncated |= partial
            for entry in entries:
                user = project_entry(entry, kind='user', now=self.clock())
                if user['object_guid'] in users and users[user['object_guid']] != user:
                    raise fail('directory_observer_identity_invalid', 'Contradictory directory identity in search results')
                users[user['object_guid']] = user
            if len(users) > limit:
                truncated = True
                break
        rows = sorted(users.values(), key=lambda row: (row['display_name'].casefold(), row['login'], row['object_guid']))
        return {'schema_version': 1, 'users': rows[:limit], 'truncated': truncated}

    def collect(self, *, deadline=None) -> dict:
        deadline = self.monotonic() + COLLECTION_SECONDS if deadline is None else deadline
        result = {'schema_version': 1, 'users': [], 'computers': []}
        objects, byte_count, identities = 0, 0, set()
        for kind, bases, ldap_filter, attributes in (
                ('user', self.config.user_bases, '(&(objectCategory=person)(objectClass=user))', USER_ATTRIBUTES),
                ('computer', self.config.computer_bases, '(objectClass=computer)', COMPUTER_ATTRIBUTES + ('userAccountControl',))):
            for base in bases:
                entries, size, _ = self._query(base=base, ldap_filter=ldap_filter, attributes=attributes, deadline=deadline)
                objects, byte_count = objects + len(entries), byte_count + size
                if objects > MAX_OBJECTS or byte_count > MAX_SOURCE_BYTES:
                    raise fail('directory_observer_limit', 'Directory collection exceeds its total budget')
                for entry in entries:
                    item = project_entry(entry, kind=kind, now=self.clock())
                    if item['object_guid'] in identities:
                        raise fail('directory_observer_identity_invalid', 'Duplicate directory identity in a collection')
                    identities.add(item['object_guid'])
                    result['users' if kind == 'user' else 'computers'].append(item)
        if self.monotonic() >= deadline:
            raise fail('directory_observer_timeout', 'Directory collection deadline exceeded')
        result.update(complete=True, generated_at=self.clock().isoformat(), object_count=objects)
        result['generation'] = hashlib.sha256(json.dumps(result, sort_keys=True).encode('utf-8')).hexdigest()
        return result
