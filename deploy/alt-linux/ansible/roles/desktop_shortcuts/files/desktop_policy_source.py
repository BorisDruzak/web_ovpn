#!/usr/bin/python3
"""Read-only ownership and effective-file checks for an explicit desktop GPO handoff."""
import argparse
import ast
import configparser
import json
import os
from pathlib import Path
import re
import shlex
import shutil
import stat
import subprocess
import sys
import uuid

RECEIPT = Path('/etc/gpupdate/desktop-shortcuts-gpo.json')
CACHE = Path('/etc/dconf/db/policy.d/policy.ini')
HOME_LINK = 'Домашняя папка'
FLAGS = ('ShortcutsMerge', 'ShortcutsApplier', 'ShortcutsApplierUser')


def literal(value):
    for unused in range(2):
        if not isinstance(value, str):
            break
        try:
            value = ast.literal_eval(value)
        except (ValueError, SyntaxError):
            break
    return value


def destination(value):
    if not isinstance(value, str):
        raise ValueError('invalid shortcut destination')
    value = re.sub(r'%([^%]+)%', lambda m: '%'+m[1].upper()+'%', value)
    return re.sub(r'[\\/]+', '/', value).rstrip('/')


def select_policy(receipt, machine_uuid, cache_text, entries):
    if receipt is None:
        return {'source': 'ansible', 'shortcuts': []}
    if not isinstance(receipt, dict) or type(receipt.get('schema')) is not int or receipt['schema'] != 1:
        raise ValueError('invalid desktop GPO migration receipt')
    if not all(isinstance(receipt.get(k), str) for k in ('machine_uuid', 'gpo_id', 'gpo_name')):
        raise ValueError('invalid desktop GPO receipt identity')
    if uuid.UUID(receipt['machine_uuid']) != uuid.UUID(machine_uuid):
        raise ValueError('desktop GPO receipt belongs to another computer')
    gpo_id, name = str(uuid.UUID(receipt['gpo_id'])), receipt['gpo_name']
    if not name.strip() or not isinstance(entries, list) or not entries or len(entries) != len(set(entries)):
        raise ValueError('invalid selected desktop profile')
    if any(not isinstance(e, str) or not re.fullmatch(r'[A-Za-z0-9_.-]+\.desktop', e) for e in entries):
        raise ValueError('invalid selected launcher identity')
    cache = configparser.RawConfigParser(strict=False)
    cache.optionxform = str
    cache.read_string(cache_text)
    priorities = [cache[s] for s in cache.sections() if s.startswith('Software/BaseALT/Policies/GpoPriority/Machine/')]
    named = [p for p in priorities if literal(p.get('display_name', '')) == name]
    if len(named) != 1 or str(literal(named[0].get('name', ''))).strip('{}').lower() != gpo_id:
        raise ValueError('expected desktop GPO is missing or ambiguous')
    branch = 'Software/BaseALT/Policies/GPUpdate'
    for flag in FLAGS:
        value = literal(cache.get(branch, flag, fallback=''))
        source = literal(cache.get('Source/'+branch, flag, fallback=''))
        if type(value) is not int or value != 1 or not isinstance(source, dict) or source.get('policy_name') != name:
            raise ValueError('native machine-to-user shortcut application is not enabled by this GPO')
    rows = literal(cache.get('Software/BaseALT/Policies/Preferences/Machine', 'Shortcuts', fallback=''))
    if not isinstance(rows, list) or any(not isinstance(row, dict) for row in rows):
        raise ValueError('invalid machine shortcut policy cache')
    wanted = ['%DESKTOPDIR%/'+e.removesuffix('.desktop') for e in entries]
    wanted += ['%HOME%/.config/autostart/nextcloud-client', '%DESKTOPDIR%/'+HOME_LINK]
    selected = []
    for dest in wanted:
        matches = [row for row in rows if destination(row.get('dest')) == dest]
        if len(matches) != 1:
            raise ValueError('missing or conflicting managed shortcut')
        row = matches[0]
        if (str(row.get('policy_guid', '')).strip('{}').lower() != gpo_id or row.get('policy_name') != name
                or row.get('disabled', False) is not False or row.get('action') not in ('C', 'U', 'R')):
            raise ValueError('managed shortcut does not originate in the expected active GPO')
        identity = str(uuid.UUID(str(row.get('uid', '')).strip('{}')))
        if sum(str(r.get('uid', '')).strip('{}').lower() == identity for r in rows) != 1:
            raise ValueError('ambiguous shortcut lifecycle identity')
        if any(not isinstance(row.get(k), str) for k in ('path', 'arguments', 'name', 'icon')):
            raise ValueError('incomplete managed shortcut')
        if not row['name'] or not row['icon']:
            raise ValueError('managed shortcut lacks its name or icon')
        if dest.endswith('/'+HOME_LINK):
            if row.get('type') != 'URL' or row['path'] != 'file://%HOME%':
                raise ValueError('home-folder shortcut is not a per-user home link')
        elif row.get('type') != 'FILESYSTEM' or not row['path'].startswith('/'):
            raise ValueError('managed application target is not an absolute executable')
        if dest.startswith('%HOME%/') and row['path'] != '/usr/bin/nextcloud':
            raise ValueError('Nextcloud autostart points to another program')
        selected.append(dict(row, normalized_destination=dest))
    return {'source': 'gpo', 'gpo_id': gpo_id, 'shortcuts': selected}


def protected(path, uid, *, executable=False):
    if any(p.is_symlink() for p in (path, *path.parents)):
        raise ValueError('symlinked desktop policy evidence')
    try:
        info = path.stat()
    except OSError as exc:
        raise ValueError('missing desktop policy evidence') from exc
    mode = stat.S_IMODE(info.st_mode)
    if (not stat.S_ISREG(info.st_mode) or info.st_uid != uid or info.st_size > 8388608
            or mode & 0o7022 or not mode & 0o400 or executable and not mode & 0o100):
        raise ValueError('unsafe desktop policy evidence')


def verify_profile(policy, base, uid, desktop_name, *, skel=False):
    if not base.is_dir() or base.is_symlink() or base.stat().st_uid != uid:
        raise ValueError('unsafe desktop profile')
    desktop = base/desktop_name
    for row in policy['shortcuts']:
        dest = row['normalized_destination']
        target = (desktop/(dest.split('/')[-1]+'.desktop') if dest.startswith('%DESKTOPDIR%/')
                  else base/'.config/autostart/nextcloud-client.desktop')
        protected(target, uid, executable=dest.startswith('%DESKTOPDIR%/'))
        cfg = configparser.RawConfigParser(strict=False)
        cfg.optionxform = str
        cfg.read_string(target.read_text(encoding='utf-8'))
        actual = cfg['Desktop Entry']
        if actual.get('Name') != row['name'] or actual.get('Icon') != row['icon']:
            raise ValueError('desktop name or icon differs from its GPO')
        if actual.get('Hidden', 'false').lower() in ('true', '1'):
            raise ValueError('managed launcher is hidden')
        only = set(actual.get('OnlyShowIn', '').strip(';').split(';')) - {''}
        excluded = set(actual.get('NotShowIn', '').strip(';').split(';')) - {''}
        if only and 'KDE' not in only or 'KDE' in excluded:
            raise ValueError('managed launcher is excluded from KDE')
        attempt = actual.get('TryExec', '')
        if attempt and not (shutil.which(attempt, path='/usr/bin:/bin:/usr/sbin:/sbin')):
            raise ValueError('managed launcher TryExec is unavailable')
        if dest.startswith('%HOME%/'):
            if (actual.get('X-GNOME-Autostart-enabled', 'true').lower() in ('false', '0')
                    or actual.get('X-systemd-skip', 'false').lower() in ('true', '1')
                    or actual.get('X-KDE-autostart-disabled', 'false').lower() in ('true', '1')
                    or actual.get('AutostartCondition') or actual.get('X-KDE-autostart-condition')):
                raise ValueError('Nextcloud autostart is disabled or conditional')
        if row['type'] == 'URL':
            expected = row['path'] if skel else row['path'].replace('%HOME%', str(base).rstrip('/')+'/')
            if actual.get('Type') != 'Link' or actual.get('URL') != expected:
                raise ValueError('home link differs from its GPO')
        else:
            expected = shlex.split(row['path']+' '+row['arguments'])
            if actual.get('Type') != 'Application' or shlex.split(actual.get('Exec', '')) != expected:
                raise ValueError('desktop command differs from its GPO')
    legacy = desktop/HOME_LINK
    if legacy.exists() or legacy.is_symlink():
        if not legacy.is_symlink() or os.readlink(legacy) != '..' or legacy.lstat().st_uid != uid:
            raise ValueError('retain custom legacy home-folder entry for review')
        return [str(legacy)]
    return []


def parse_sss_account(username, output):
    lines = output.strip().splitlines()
    if len(lines) != 1 or len(lines[0].split(':')) != 7:
        raise ValueError('ambiguous domain profile identity')
    name, unused, uid, gid, gecos, home, shell = lines[0].split(':')
    if name.casefold().split('@')[0] != username.casefold().split('@')[0] or int(uid) <= 0 or int(gid) <= 0:
        raise ValueError('wrong domain profile identity')
    return {'name': name, 'uid': int(uid), 'gid': int(gid), 'home': home}


def profile_deferred(base, *, owner=0, root=Path('/')):
    if base.is_symlink():
        raise ValueError('symlinked domain profile')
    deferred = not base.exists()
    for parent in base.parents:
        if parent == root:
            break
        if parent.is_symlink():
            raise ValueError('unsafe domain profile parent')
        if not parent.exists() and deferred:
            continue
        info = parent.stat()
        if not stat.S_ISDIR(info.st_mode) or info.st_uid != owner or stat.S_IMODE(info.st_mode) & 0o022:
            raise ValueError('unsafe domain profile parent')
    return deferred


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--user', required=True)
    parser.add_argument('--entries-json', required=True)
    parser.add_argument('--desktop-name', default='Рабочий стол')
    args = parser.parse_args()
    if not RECEIPT.exists() and not RECEIPT.is_symlink():
        print(json.dumps({'source': 'ansible', 'home_deferred': False, 'legacy_home_links': []}))
        return
    protected(RECEIPT, 0)
    protected(CACHE, 0)
    receipt = json.loads(RECEIPT.read_text())
    if not isinstance(receipt, dict):
        raise ValueError('invalid desktop GPO receipt object')
    policy = select_policy(receipt, Path('/sys/class/dmi/id/product_uuid').read_text().strip(),
                           CACHE.read_text(), json.loads(args.entries_json))
    if not args.desktop_name or '/' in args.desktop_name or '\\' in args.desktop_name or args.desktop_name in ('.', '..'):
        raise ValueError('invalid desktop directory name')
    cleanup = verify_profile(policy, Path('/etc/skel'), 0, args.desktop_name, skel=True)
    resolved = subprocess.run(['getent', '-s', 'sss', 'passwd', args.user], capture_output=True,
                              text=True, check=True, timeout=10)
    account = parse_sss_account(args.user, resolved.stdout)
    import pwd
    effective = pwd.getpwnam(args.user)
    if (effective.pw_uid, effective.pw_gid, effective.pw_dir) != (account['uid'], account['gid'], account['home']):
        raise ValueError('domain profile is shadowed by another identity')
    base = Path(account['home'])
    if not base.is_absolute() or not base.is_relative_to('/home') or base == Path('/home') or '..' in base.parts:
        raise ValueError('invalid domain profile identity')
    deferred = profile_deferred(base)
    if not deferred:
        cleanup += verify_profile(policy, base, account['uid'], args.desktop_name)
    if cleanup:
        raise ValueError('legacy home-folder entry requires reviewed handoff before receipt activation')
    print(json.dumps({'source': 'gpo', 'gpo_id': policy['gpo_id'], 'verified': True,
                      'home_deferred': deferred, 'legacy_home_links': cleanup}))


if __name__ == '__main__':
    try:
        main()
    except (ValueError, OSError, KeyError, TypeError, configparser.Error, subprocess.SubprocessError) as exc:
        print('ALT_PREFLIGHT_FAILURE:desktop_gpo_unverified: '+str(exc), file=sys.stderr)
        sys.exit(2)
