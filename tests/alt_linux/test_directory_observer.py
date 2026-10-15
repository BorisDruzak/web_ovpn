from __future__ import annotations

import base64
import json
import uuid

import pytest

from alt_deploy.errors import ControlError


def api():
    from alt_deploy import directory_observer
    return directory_observer


def entry(number=1, **changes):
    values = {
        'dn': f'CN=Synthetic {number},OU=Staff,DC=example,DC=invalid',
        'objectClass': ['top', 'person', 'user'],
        'sAMAccountName': f'person{number}',
        'userPrincipalName': f'person{number}@example.invalid',
        'displayName': 'Synthetic Homonym',
        'department': 'Testing',
        'objectGUID': uuid.UUID(int=number).bytes_le,
        'objectSid': b'\x01\x02' + b'\x00' * 5 + b'\x05' + (21).to_bytes(4, 'little') + number.to_bytes(4, 'little'),
        'userAccountControl': '512',
        'msDS-User-Account-Control-Computed': '0',
        'accountExpires': '0',
    }
    values.update(changes)
    lines = []
    for name, value in values.items():
        if value is None:
            continue
        for item in value if isinstance(value, list) else [value]:
            lines.append(name + ':: ' + base64.b64encode(item).decode() if isinstance(item, bytes) else name + ': ' + item)
    return '\n'.join(lines) + '\n\n'


def configuration(**changes):
    return api().DirectoryObserverConfig(domain_base='DC=example,DC=invalid',
        user_bases=('OU=Staff,DC=example,DC=invalid',), computer_bases=('OU=PCs,DC=example,DC=invalid',), **changes)


class Source:
    def __init__(self, raw='', *, truncated=False):
        self.raw, self.truncated, self.calls = raw, truncated, []

    def __call__(self, **parameters):
        self.calls.append(parameters)
        return {'ldif': self.raw, 'truncated': self.truncated}


def test_exact_identity_lookup_uses_binary_guid_and_rejects_contradictory_result():
    source = Source(entry())
    observer = api().DirectoryObserver(configuration(), transport=source)
    result = observer.identity('user', str(uuid.UUID(int=1)))
    assert result['object_guid'] == str(uuid.UUID(int=1))
    assert '(objectGUID=' in source.calls[0]['ldap_filter'] and source.calls[0]['size_limit'] == 2
    source.raw = entry(2)
    with pytest.raises(ControlError): observer.identity('user', str(uuid.UUID(int=1)))


def test_name_search_escapes_filter_and_disambiguates_homonyms():
    source = Source(entry() + entry(2))
    result = api().DirectoryObserver(configuration(), transport=source).search_users('Syn*)(x=*)')
    assert [row['login'] for row in result['users']] == ['person1', 'person2']
    assert len({row['object_guid'] for row in result['users']}) == 2
    assert all(row['object_sid'] and row['state'] == 'enabled' for row in result['users'])
    assert '\\2a\\29\\28' in source.calls[0]['ldap_filter']
    assert '(objectCategory=person)' in source.calls[0]['ldap_filter']
    assert 'dn' not in result['users'][0]
    assert 'password' not in json.dumps(result).lower()


@pytest.mark.parametrize('source', ['ticket', 'join-vault', '', None])
def test_readonly_observer_rejects_join_vault(source):
    with pytest.raises(ControlError) as exc:
        configuration(credential_source=source)
    assert exc.value.code == 'directory_observer_config_invalid'


@pytest.mark.parametrize('query', ['a', '', 'x' * 161, 'ab\x00', 'ab\n', 'a\ud800b'])
def test_search_rejects_over_160_chars(query):
    source = Source()
    with pytest.raises(ControlError):
        api().DirectoryObserver(configuration(), transport=source).search_users(query)
    assert source.calls == []


def test_search_reports_51st_result_as_truncated():
    source = Source(''.join(entry(n) for n in range(1, 52)), truncated=True)
    result = api().DirectoryObserver(configuration(), transport=source).search_users('person')
    assert len(result['users']) == 50
    assert result['truncated'] is True
    assert source.calls[0]['size_limit'] == 51


def test_collects_more_than_old_256_result_limit():
    users = ''.join(entry(n) for n in range(1, 302))
    source = Source()
    def read(**parameters):
        return {'ldif': users if 'objectCategory=person' in parameters['ldap_filter'] else '', 'truncated': False}
    result = api().DirectoryObserver(configuration(), transport=read).collect()
    assert result['complete'] is True
    assert len(result['users']) == 301
    assert result['computers'] == []
    assert result['generated_at'].endswith('+00:00')


def test_last_page_failure_never_returns_complete():
    calls = []
    def read(**parameters):
        calls.append(parameters)
        if len(calls) == 1:
            return {'ldif': entry(), 'truncated': False}
        raise ControlError('ad_query_failed', 'protected source diagnostic')
    with pytest.raises(ControlError) as exc:
        api().DirectoryObserver(configuration(), transport=read).collect()
    assert 'protected source diagnostic' not in str(exc.value)


def test_collection_enforces_10000_objects_16mib_and_120_seconds():
    module = api()
    assert (module.MAX_OBJECTS, module.MAX_SOURCE_BYTES, module.COLLECTION_SECONDS) == (10000, 16 * 1024 * 1024, 120)
    ticks = iter([0, 121])
    source = Source(entry())
    with pytest.raises(ControlError) as exc:
        module.DirectoryObserver(configuration(), transport=source, monotonic=lambda: next(ticks)).collect()
    assert exc.value.code == 'directory_observer_timeout'
    assert source.calls == []


def test_rejects_partial_collection_and_duplicate_guid():
    for source in (Source(entry(), truncated=True), Source(entry() + entry())):
        with pytest.raises(ControlError):
            api().DirectoryObserver(configuration(), transport=source).collect()


@pytest.mark.parametrize('changes,state', [({'userAccountControl': '514'}, 'disabled'),
    ({'msDS-User-Account-Control-Computed': '16'}, 'locked'), ({'accountExpires': '1'}, 'expired'),
    ({'msDS-User-Account-Control-Computed': None}, 'unknown')])
def test_account_state_is_not_hidden_or_assumed_enabled(changes, state):
    result = api().DirectoryObserver(configuration(), transport=Source(entry(**changes))).search_users('person')
    assert result['users'][0]['state'] == state


def test_config_load_rejects_symlink_and_unapproved_fields(tmp_path):
    path = tmp_path / 'observer.json'
    path.write_text(json.dumps({'unexpected_command': 'id'}), encoding='utf-8')
    with pytest.raises(ControlError):
        api().DirectoryObserverConfig.load(path)
    link = tmp_path / 'link.json'
    link.symlink_to(path)
    with pytest.raises(ControlError):
        api().DirectoryObserverConfig.load(link)


def test_paged_transport_requires_critical_control_and_rejects_late_page_failure():
    module = api()
    calls = []
    def runner(command, **kwargs):
        calls.append((command, kwargs))
        return 4, entry(), 'private LDAP diagnostic'
    transport = module.PagedLDAPTransport(configuration(), runner=runner)
    from contextlib import contextmanager
    @contextmanager
    def credentials(environment):
        yield environment, []
    transport._credentials = credentials
    with pytest.raises(ControlError) as exc:
        transport(ldap_filter='(objectClass=computer)', attributes=('objectGUID',),
            base='OU=PCs,DC=example,DC=invalid', deadline=transport.monotonic() + 120)
    assert '!pr=200/noprompt' in calls[0][0]
    assert '-C' not in calls[0][0]  # Never chase referrals outside configured bases.
    assert 'private LDAP diagnostic' not in str(exc.value)


@pytest.mark.parametrize('budget', ['objects', 'bytes'])
def test_total_budget_is_actually_enforced(monkeypatch, budget):
    module = api()
    if budget == 'objects':
        monkeypatch.setattr(module, 'MAX_OBJECTS', 1)
        source = Source(entry() + entry(2))
    else:
        monkeypatch.setattr(module, 'MAX_SOURCE_BYTES', len(entry().encode()) - 1)
        source = Source(entry())
    with pytest.raises(ControlError):
        module.DirectoryObserver(configuration(), transport=source).collect()


def test_search_does_not_merge_contradictory_identity_evidence():
    with pytest.raises(ControlError):
        api().DirectoryObserver(configuration(), transport=Source(entry() + entry(sAMAccountName='other'))).search_users('person')


def test_computer_projection_supports_existing_non_alt_names():
    computer = entry(50, objectClass=['top', 'user', 'computer'], sAMAccountName='DESKTOP-EXAMPLE$',
                     dNSHostName='desktop-example.example.invalid')
    def read(**parameters):
        return {'ldif': '' if 'objectCategory=person' in parameters['ldap_filter'] else computer, 'truncated': False}
    result = api().DirectoryObserver(configuration(), transport=read).collect()
    assert result['computers'][0]['dns_hostname'] == 'desktop-example.example.invalid'
    assert result['computers'][0]['state'] == 'enabled'
