"""Selected-user network shortcuts: server-enforced access and optional failures."""
import importlib.util
from pathlib import Path
from types import SimpleNamespace

import pytest
import yaml


ROOT = Path(__file__).resolve().parents[1] / 'deploy/alt-linux'
HELPER = ROOT / 'ansible/roles/desktop_shortcuts/files/network_folders.py'


@pytest.fixture
def helper():
    spec = importlib.util.spec_from_file_location('network_folders', HELPER)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def request():
    return {'login': 'employee@example.test', 'domain': 'example.test',
            'ldap_uri': 'ldap://dc.example.test', 'server': 'fs.example.test',
            'share': 'Departments$', 'sid': '', 'desktop': 'Desktop'}


def directory_listing(*names):
    return ''.join(f'  {name}                 D        0  Mon Oct 19 10:00:00 2026\n'
                   for name in ('.', '..', *names)) + '\n  100 blocks of size 4096. 50 blocks available\n'


class Server:
    def __init__(self, *, who='u:EXAMPLE\\employee', ldap_error=False, timeout=False):
        self.calls = []
        self.who, self.ldap_error, self.timeout = who, ldap_error, timeout

    def __call__(self, argv, *, timeout):
        self.calls.append(argv)
        name = Path(argv[0]).name
        if self.timeout:
            raise TimeoutError
        if name == 'klist':
            return SimpleNamespace(returncode=0, stdout='Default principal: employee@EXAMPLE.TEST\n', stderr='')
        if name == 'ldapwhoami':
            return SimpleNamespace(returncode=0, stdout=self.who + '\n', stderr='')
        if name == 'ldapsearch':
            return SimpleNamespace(returncode=int(self.ldap_error), stderr='', stdout=(
                'dn: CN=Employee,DC=example,DC=test\nsAMAccountName: employee\n'
                'userPrincipalName: employee@example.test\nuserAccountControl: 512\n'
                'objectSid:: AQUAAAAAAAUVAAAAAQAAAAIAAAADAAAA6AMAAA==\n'))
        path = argv[argv.index('-D') + 1] if '-D' in argv else ''
        if path == '':
            output = directory_listing('Department A', 'Department B')
        elif path in ('Department A', 'Department B'):
            output = directory_listing('Рабочая', 'Сканы')
        elif path in ('Department A\\Рабочая', 'Department B\\Сканы'):
            output = directory_listing()
        else:
            # smbclient can print a failed command and still exit successfully.
            output = 'NT_STATUS_ACCESS_DENIED listing \\*\n'
        return SimpleNamespace(returncode=0, stdout=output, stderr='')


def test_only_folders_opened_by_the_selected_user_become_candidates(helper):
    server = Server()
    result = helper.probe(request(), runner=server)
    assert result['status'] == 'ok'
    assert {(i['department'], i['kind']) for i in result['folders']} == {
        ('Department A', 'Рабочая'), ('Department B', 'Сканы')}
    smb = [c for c in server.calls if Path(c[0]).name == 'smbclient']
    assert all('--use-kerberos=required' in c and '-N' in c for c in smb)
    assert all(c[c.index('-c') + 1] == 'ls' for c in smb)
    assert not any('password' in str(c).lower() for c in server.calls)


@pytest.mark.parametrize('options', [{'who': 'u:EXAMPLE\\administrator'}, {'ldap_error': True}, {'timeout': True}])
def test_unverified_ad_or_unavailable_source_never_grants_access(helper, options):
    server = Server(**options)
    result = helper.probe(request(), runner=server)
    assert result['status'] == 'unknown'
    assert result['folders'] == []
    assert not any(Path(c[0]).name == 'smbclient' for c in server.calls)


def test_selected_sid_must_match_ad(helper):
    data = request()
    data['sid'] = 'S-1-5-21-1-2-3-9999'
    result = helper.probe(data, runner=Server())
    assert result['status'] == 'unknown' and result['folders'] == []


@pytest.mark.parametrize('name', ['bad;quit', 'bad"name', '../escape', 'bad\\name', 'bad\nname'])
def test_smb_names_cannot_inject_commands_or_escape(helper, name):
    with pytest.raises(ValueError):
        helper.safe_name(name)


def test_listing_does_not_misread_files_as_directories(helper):
    text = directory_listing('Department A') + '  file.txt A 100 Mon Oct 19 10:00:00 2026\n'
    assert helper.directories(text) == ['Department A']


def test_link_file_is_a_url_and_never_an_executable(helper):
    text = helper.launcher('fs.example.test', 'Departments$', 'Отдел', 'Сканы')
    assert 'Type=Link\n' in text and 'Exec=' not in text
    assert 'URL=smb://fs.example.test/Departments%24/' in text
    assert '\nX-Alt-Setup-Network-Folder=true\n' in text


def test_optional_probe_cannot_record_a_native_task_failure():
    tasks = yaml.safe_load((ROOT / 'ansible/roles/desktop_shortcuts/tasks/network_folders.yml').read_text(encoding='utf-8'))
    command = next(t for t in tasks if 'ansible.builtin.command' in t)
    assert command['failed_when'] is False
    assert 'alt_network_folders_result' in command['changed_when']
    assert command['ansible.builtin.command']['argv'][:4] == [
        '/usr/bin/timeout', '--signal=TERM', '--kill-after=2s', '55s']
    defaults = yaml.safe_load((ROOT / 'ansible/roles/desktop_shortcuts/defaults/main.yml').read_text(encoding='utf-8'))
    assert all('Public' not in i['src'] for i in defaults['desktop_shortcuts_relative_links'])


def test_repeated_link_write_is_noop_and_preserves_user_owned_files(helper, tmp_path):
    content = helper.launcher('fs.example.test', 'Departments$', 'A', 'Рабочая')
    assert helper.write_launcher(tmp_path, 'network-work-test.desktop', content)
    assert not helper.write_launcher(tmp_path, 'network-work-test.desktop', content)
    user_file = tmp_path / 'network-work-user.desktop'
    user_file.write_text('user content')
    with pytest.raises(ValueError):
        helper.write_launcher(tmp_path, user_file.name, content)
    assert user_file.read_text() == 'user content'


def test_foreign_symlinks_are_preserved(helper, tmp_path):
    target = tmp_path / 'target'
    target.write_text('original')
    link = tmp_path / 'network-work-link.desktop'
    try:
        link.symlink_to(target)
    except OSError:
        pytest.skip('symlinks unavailable')
    with pytest.raises(ValueError):
        helper.write_launcher(tmp_path, link.name, 'new')
    assert target.read_text() == 'original'


def test_nested_subdepartment_is_discovered_without_recursing_into_employee_data(helper):
    server = Server()
    def nested(argv, *, timeout):
        if Path(argv[0]).name == 'smbclient' and '-D' in argv:
            path = argv[argv.index('-D') + 1]
            outputs = {'Department A': directory_listing('Subdepartment'),
                       'Department A\\Subdepartment': directory_listing('Рабочая'),
                       'Department A\\Subdepartment\\Рабочая': directory_listing('Personal data')}
            if path in outputs:
                server.calls.append(argv)
                return SimpleNamespace(returncode=0, stdout=outputs[path], stderr='')
        return server(argv, timeout=timeout)
    result = helper.probe(request(), runner=nested)
    assert any(f['parents'] == ['Department A', 'Subdepartment'] and f['kind'] == 'Рабочая'
               for f in result['folders'])
    assert not any('Personal data' in ' '.join(c) for c in server.calls)


@pytest.fixture
def filters():
    path = ROOT / 'ansible/filter_plugins/alt_network_folders.py'
    spec = importlib.util.spec_from_file_location('network_filters', path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


@pytest.mark.parametrize('value', [{}, {'rc': 1}, {'rc': 0, 'stdout': 'bad-json'},
    {'rc': 0, 'stdout': '[]'}, {'rc': 0, 'stdout': '{"status": "ok"}'},
    {'rc': 0, 'stdout': 'x' * 5000}])
def test_result_decoder_is_total_and_sanitized(filters, value):
    assert filters.result(value) == filters.unknown()


def test_published_probe_bundle_is_bounded_and_self_contained(filters):
    source = filters.program(ROOT / 'ansible/roles/desktop_shortcuts')
    assert 'discover_session' in source and 'PERSONAL_PROGRAM' in source
    assert len(source.encode()) < 120000
    compile(source, '<probe>', 'exec')
    compile(filters.program('missing-role'), '<fallback>', 'exec')


def test_only_the_exact_legacy_shortcut_is_retired(helper, tmp_path):
    link = tmp_path / 'Сетевая папка'
    try:
        link.symlink_to('../net.drives/Public')
    except OSError:
        pytest.skip('symlinks unavailable')
    assert helper.retire_legacy(tmp_path)
    link.symlink_to('../personal')
    assert not helper.retire_legacy(tmp_path) and link.is_symlink()


def test_ad_continuation_references_do_not_look_like_duplicate_users(helper):
    server = Server()
    def referral(argv, *, timeout):
        reply = server(argv, timeout=timeout)
        if Path(argv[0]).name == 'ldapsearch':
            reply.stdout += '\nref: ldap://DomainDnsZones.example.test\nref: ldap://ForestDnsZones.example.test\n'
        return reply
    assert helper.probe(request(), runner=referral)['status'] == 'ok'
