"""Fixed isolated original-policy inventory; no default/effect execution authority."""
from __future__ import annotations

import copy
import json
import os
from pathlib import Path
import re
import tempfile

KEYS = (
    'id_provider', 'auth_provider', 'access_provider', 'ad_domain', 'ad_hostname',
    'ad_server', 'ad_backup_server', 'ad_enabled_domains', 'ad_enable_dns_sites',
    'krb5_keytab', 'ldap_krb5_keytab', 'krb5_realm', 'ad_use_ldaps',
    'ad_maximum_machine_account_password_age', 'ad_machine_account_password_renewal_opts',
    'ad_update_samba_machine_account_password', 'dyndns_update', 'dyndns_refresh_interval',
    'dyndns_refresh_interval_offset', 'dyndns_update_ptr', 'dyndns_update_per_family',
    'dyndns_iface', 'dyndns_ttl', 'dyndns_force_tcp', 'dyndns_auth', 'dyndns_auth_ptr',
    'dyndns_server', 'dyndns_dot_cacert', 'dyndns_dot_cert', 'dyndns_dot_key',
)
DEPENDENCIES = {
    '/usr/libexec/sssd/sssd_be': 'sssd 2.9.8-alt3',
    '/usr/lib64/sssd/libsss_ad.so': 'sssd-ad 2.9.8-alt3',
    '/usr/sbin/adcli': 'adcli 0.9.2-alt1',
    '/usr/bin/nsupdate': 'bind-utils 9.18.49-alt1',
}
BOOLS = frozenset(('ad_enable_dns_sites', 'ad_use_ldaps', 'ad_update_samba_machine_account_password',
    'dyndns_update', 'dyndns_update_ptr', 'dyndns_update_per_family', 'dyndns_force_tcp'))
NUMBERS = frozenset(('ad_maximum_machine_account_password_age', 'dyndns_refresh_interval',
    'dyndns_refresh_interval_offset', 'dyndns_ttl'))


def _dependencies(*, probe, policy, runner, root, owner):
    result = {}
    for path, package in DEPENDENCIES.items():
        info = probe._file(root, path, maximum=probe.MAX_TOOL_BYTES, owner=owner)
        modes = (0o644, 0o755) if path.endswith('.so') else (0o755,)
        if not info['present'] or info['mode'] not in modes or info['gid'] != owner:
            raise ValueError('Unsafe fixed policy dependency')
        actual = policy._run(runner, ['/usr/bin/rpm', '-qf', path, '--qf', '%{NAME} %{VERSION}-%{RELEASE}\n']).strip()
        if actual != package: raise ValueError('Unreviewed fixed policy dependency package')
        result[path] = dict(info, package=package)
    return result


def _unchanged_dependencies(expected, *, probe, root, owner):
    for path in DEPENDENCIES:
        current = probe._file(root, path, maximum=probe.MAX_TOOL_BYTES, owner=owner)
        if current != {key: value for key, value in expected[path].items() if key != 'package'}:
            raise ValueError('Changed fixed policy dependency')


def _values(data, meta):
    domain = 'cn=' + meta['realm'].upper() + ',cn=domain,cn=config'
    if (not isinstance(data, dict) or set(data) != {'configured', 'key_inventory', 'domains'}
            or data['domains'] != meta['realm'].upper() or not isinstance(data['configured'], dict)
            or set(data['configured']) != set(KEYS) or not isinstance(data['key_inventory'], dict)
            or not {domain, 'cn=sssd,cn=config'} <= set(data['key_inventory']) or len(data['key_inventory']) > 32):
        raise ValueError('Invalid closed effect inventory')
    inventory = data['key_inventory']
    for section, keys in inventory.items():
        if (not isinstance(section, str) or not re.fullmatch(r'cn=[A-Za-z0-9_.-]+(?:,cn=domain)?,cn=config', section)
                or not isinstance(keys, list) or len(keys) > 128 or len(set(keys)) != len(keys)
                or keys != sorted(keys) or any(not isinstance(key, str) or not re.fullmatch('[a-z][a-z0-9_]{0,95}', key) for key in keys)):
            raise ValueError('Invalid configured key inventory')
    for key, record in data['configured'].items():
        if (not isinstance(record, dict) or set(record) != {'present', 'value'} or type(record['present']) is not bool
                or not isinstance(record['value'], str) or len(record['value']) > 1024
                or not re.fullmatch('[ -~]*', record['value']) or record['present'] != (key in inventory[domain])
                or (not record['present'] and record['value'])):
            raise ValueError('Invalid configured presence/value')
        value = record['value']
        if (value and ((key in BOOLS and value not in ('true', 'false'))
                or (key in NUMBERS and not re.fullmatch('[0-9]{1,10}', value))
                or (key == 'ad_machine_account_password_renewal_opts' and not re.fullmatch('[0-9]{1,10}:[0-9]{1,10}(?::[0-9]{1,10})?', value)))):
            raise ValueError('Invalid configured operative value')
    unknown = []
    for section, keys in inventory.items():
        allowed = set(KEYS) if section == domain else {'domains'} if section == 'cn=sssd,cn=config' else set()
        unknown.extend(section + ':' + key for key in keys if key not in allowed)
    return data, sorted(unknown)


def _commands(work, meta, *, policy, native, owner):
    commands = policy._commands(work, meta, native=native, owner=owner)
    domain = 'cn=' + meta['realm'].upper() + ',cn=domain,cn=config'
    code = '\n'.join((
        'import json,ldb',
        'db=ldb.Ldb("/var/lib/sss/db/config.ldb",flags=ldb.FLG_RDONLY)',
        'domain=' + repr(domain),
        'keys=' + repr(KEYS),
        'rows=db.search(base=domain,scope=ldb.SCOPE_BASE,attrs=list(keys))',
        'assert len(rows)==1',
        'row=rows[0]',
        'assert all(len(row[key])==1 for key in keys if key in row)',
        'configured={key:{"present":key in row,"value":bytes(row[key][0]).decode("ascii") if key in row else ""} for key in keys}',
        'inventory={}',
        'for entry in db.search(base="cn=config",scope=ldb.SCOPE_SUBTREE,attrs=["*"]):',
        ' section=str(entry.dn)',
        ' if section=="cn=config" or section=="cn=domain,cn=config": continue',
        ' inventory[section]=sorted(key.lower() for key in entry.keys() if key.lower() not in ("dn","cn","objectclass","distinguishedname"))',
        'sssd=db.search(base="cn=sssd,cn=config",scope=ldb.SCOPE_BASE,attrs=["domains"])',
        'assert len(sssd)==1 and len(sssd[0]["domains"])==1',
        'print(json.dumps({"configured":configured,"key_inventory":inventory,"domains":bytes(sssd[0]["domains"][0]).decode("ascii")},sort_keys=True))',
    ))
    commands[2][-1] = code
    return commands


def _parse(state, tools, dependencies, *, policy, backup, probe, native, runner, root, owner, leaf):
    work = leaf
    for path in ('config', 'config/conf.d', 'sss', 'sss/db', 'sss/pubconf', 'sss/pipes'):
        (work / path).mkdir(mode=0o700)
    files = {'/config/sssd.conf': state['content'], **policy.SANDBOX_NSS}
    for path, content in files.items(): backup._write(work / path.lstrip('/'), content)
    metadata = {path: probe._file(work, path, private=True, owner=owner) for path in files}
    def guard():
        if list((work / 'config/conf.d').iterdir()): raise ValueError('Unexpected isolated effect snippet')
        for path, content in files.items():
            if (probe._file(work, path, private=True, owner=owner) != metadata[path]
                    or backup._read(work / path.lstrip('/'), metadata[path], root=work, owner=owner) != content):
                raise ValueError('Changed isolated effect config')
        policy._unchanged_tools(tools, probe=probe, root=root, owner=owner)
        _unchanged_dependencies(dependencies, probe=probe, root=root, owner=owner)
    output = None; database = None
    for index, command in enumerate(_commands(work, state['meta'], policy=policy, native=native, owner=owner)):
        guard()
        if database is not None and probe._file(work, '/sss/db/config.ldb', private=True, owner=owner) != database:
            raise ValueError('Changed isolated effect database')
        output = policy._run(runner, command); guard()
        if index == 1:
            database = probe._file(work, '/sss/db/config.ldb', private=True, owner=owner)
            if not database['present'] or not database['size']: raise ValueError('Effect database missing')
        elif index == 2 and probe._file(work, '/sss/db/config.ldb', private=True, owner=owner) != database:
            raise ValueError('Changed effect database during read')
    def unique(pairs):
        result = {}
        for key, value in pairs:
            if key in result: raise ValueError('Duplicate effect field')
            result[key] = value
        return result
    return _values(json.loads(output, object_pairs_hook=unique,
        parse_constant=lambda _: (_ for _ in ()).throw(ValueError('Nonfinite effect field'))), state['meta'])


def observe(request, *, baseline, original, policy, backup, probe, native, collect, runner, root=Path('/'), owner=0):
    if os.geteuid() != owner or not root.is_absolute(): raise ValueError('Fixed root effect inventory required')
    bound = copy.deepcopy(request)
    if (not isinstance(bound, dict) or set(bound) != {'schema_version', 'baseline_request', 'baseline_receipt', 'source_sha256'}
            or type(bound['schema_version']) is not int or bound['schema_version'] != 1
            or not isinstance(bound['source_sha256'], str) or not re.fullmatch('[0-9a-f]{64}', bound['source_sha256'])):
        raise ValueError('Invalid fixed effect inventory request')
    base = bound['baseline_request']; meta = baseline._request(base, backup=backup, native=native)
    projection = baseline.projection(bound['baseline_receipt'], original=original, policy=policy, native=native, meta=meta)
    if (bound['baseline_receipt']['status'] != 'original_sssd_policy_baseline'
            or bound['baseline_receipt']['request_sha256'] != backup.digest(base)):
        raise ValueError('Unbound original baseline receipt')
    facts = base['backup_request']['facts']
    if backup.digest(collect()) != backup.digest(facts): raise ValueError('Stale effect inventory facts')
    args = dict(policy=policy, backup=backup, probe=probe, root=root, owner=owner)
    state = baseline._protected(facts, **args)
    tools = policy._tools(probe=probe, runner=runner, root=root, owner=owner)
    dependencies = _dependencies(probe=probe, policy=policy, runner=runner, root=root, owner=owner)
    if projection['original_sha256'] != backup.digest(state['main']) or projection['tools_sha256'] != backup.digest(tools):
        raise ValueError('Changed original effect baseline')
    if baseline._protected(facts, **args) != state: raise ValueError('Changed effect inventory during native read')
    parent = root / 'var/lib'; backup._ancestry(parent / 'effects-scratch', root, owner)
    with tempfile.TemporaryDirectory(prefix='alt-policy-effects-', dir=parent) as temporary:
        data, unknown = _parse(dict(state, meta=meta), tools, dependencies, policy=policy, backup=backup,
            probe=probe, native=native, runner=runner, root=root, owner=owner, leaf=Path(temporary))
    for key, value in projection['configured_values'].items():
        current = data['domains'] if key == 'domains' else data['configured'][key]['value']
        if current != value: raise ValueError('Effect inventory differs from original baseline')
    if backup.digest(collect()) != backup.digest(facts): raise ValueError('Changed final effect facts')
    policy._unchanged_tools(tools, probe=probe, root=root, owner=owner)
    _unchanged_dependencies(dependencies, probe=probe, root=root, owner=owner)
    if baseline._protected(facts, **args) != state or backup.digest(request) != backup.digest(bound):
        raise ValueError('Changed final effect input')
    return dict(schema_version=1, status='original_policy_effect_inventory', request_sha256=backup.digest(bound),
        baseline_projection_sha256=backup.digest(projection), source_sha256=bound['source_sha256'],
        runtime_dependencies=dependencies, configured=data['configured'], key_inventory=data['key_inventory'],
        unreviewed_keys=unknown, defaults_reviewed=False, effects_reviewed=False, execution_authorized=False)
