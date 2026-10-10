"""Merge the approved desktop defaults without copying a personal profile."""
import json
import os
from pathlib import Path
import re
import subprocess
import sys

OFFICE_DESKTOP = 'onlyoffice-desktopeditors.desktop'
MIME_TYPES = (
    'application/pdf', 'text/plain', 'text/markdown', 'application/json',
    'application/x-yaml', 'application/x-docbook+xml', 'text/x-cmake',
    'application/msword',
    'application/vnd.openxmlformats-officedocument.wordprocessingml.document',
    'application/vnd.ms-excel',
    'application/vnd.openxmlformats-officedocument.spreadsheetml.sheet',
    'application/vnd.ms-powerpoint',
    'application/vnd.openxmlformats-officedocument.presentationml.presentation',
    'application/vnd.oasis.opendocument.text',
    'application/vnd.oasis.opendocument.spreadsheet',
    'application/vnd.oasis.opendocument.presentation',
    'application/rtf', 'text/rtf',
)
SETTINGS = (
    ('kdeglobals', 'KDE', 'SingleClick', 'false'),
    ('kcminputrc', 'Mouse', 'X11LibInputXAccelProfileFlat', 'true'),
    ('kwinrc', 'Windows', 'ElectricBorderMaximize', 'false'),
    ('kwinrc', 'Windows', 'ElectricBorderTiling', 'false'),
) + tuple(('filetypesrc', 'EmbedSettings', 'embed-' + mime, 'false') for mime in MIME_TYPES)


def run(argv, **kwargs):
    return subprocess.run(argv, capture_output=True, text=True, **kwargs)


def resolve_profile(username):
    if not re.fullmatch(r'[a-zA-Z0-9][a-zA-Z0-9._-]{0,62}(@[a-zA-Z0-9.-]+)?', username):
        raise ValueError('Invalid assigned domain account')
    result = run(['getent', '-s', 'sss', 'passwd', username], check=True)
    lines = result.stdout.strip().splitlines()
    if len(lines) != 1 or len(lines[0].split(':')) != 7:
        raise ValueError('Ambiguous domain account')
    name, _, uid, _, _, home, _ = lines[0].split(':')
    uid = int(uid)
    if uid <= 0 or name.lower().split('@')[0] in ('root', 'ansible', 'osn-admin'):
        raise ValueError('Administrative profile must not be configured')
    home = Path(home)
    if not home.is_absolute() or not home.is_relative_to('/home') or home == Path('/home'):
        raise ValueError('Unexpected domain home')
    for path in (home, *home.parents):
        if path.is_symlink():
            raise ValueError('Symlinked home is unsafe')
    if not home.exists():
        return None, [], uid
    if not home.is_dir() or home.stat().st_uid != uid:
        raise ValueError('Domain home ownership mismatch')
    # KBuildSycoca interprets inherited SUDO_UID/GID as the intended cache owner.
    # These belong to the Ansible administrator, not this domain user.
    prefix = ['runuser', '-u', name, '--', 'env',
              '-u', 'SUDO_UID', '-u', 'SUDO_GID', '-u', 'SUDO_USER',
              '-u', 'SUDO_COMMAND', '-u', 'LC_ALL']
    locale_file = home / '.config' / 'plasma-localerc'
    if (home / '.config').is_symlink() or locale_file.is_symlink():
        raise ValueError('Symlinked desktop locale is unsafe')
    locale = run(prefix + ['kreadconfig6', '--file', str(locale_file),
                          '--group', 'Formats', '--key', 'LANG',
                          '--default', 'C.UTF-8'], check=True).stdout.strip()
    if not re.fullmatch(r'[a-zA-Z0-9_.@-]+', locale):
        raise ValueError('Unexpected desktop locale')
    prefix += ['LANG=' + locale]
    runtime = Path('/run/user') / str(uid)
    if (runtime / 'bus').exists() and runtime.stat().st_uid == uid:
        prefix += ['XDG_RUNTIME_DIR=' + str(runtime),
                   'DBUS_SESSION_BUS_ADDRESS=unix:path=' + str(runtime / 'bus')]
    return home / '.config', prefix, uid


def apply_settings(config, prefix, call=run, expected_uid=None):
    files = {entry[0] for entry in SETTINGS} | {'mimeapps.list'}
    # Validate every destination before the first write; never follow a link.
    for path in (config, *config.parents, *(config / name for name in sorted(files))):
        if path.is_symlink():
            raise ValueError('Symlinked desktop configuration is unsafe')
    for path in (config, *(config / name for name in sorted(files))):
        if path.exists():
            if (path == config and not path.is_dir()) or (path != config and not path.is_file()):
                raise ValueError('Unexpected desktop configuration type')
            if expected_uid is not None and path.stat().st_uid != expected_uid:
                raise ValueError('Desktop configuration ownership mismatch')
    if not config.exists():
        if prefix:
            call(prefix + ['mkdir', '-m', '0700', '--', str(config)], check=True)
        else:
            config.mkdir(mode=0o755)
    changed_files = set()

    def merge(filename, group, key, desired, association=False):
        args = ['--file', str(config / filename), '--group', group, '--key', key]
        current = call(prefix + ['kreadconfig6'] + args + ['--default', '__ALT_MISSING__'], check=True).stdout.strip()
        if association:
            others = [] if current == '__ALT_MISSING__' else current.split(';')
            desired = ';'.join(dict.fromkeys([OFFICE_DESKTOP] + [item for item in others if item])) + ';'
        if current != desired:
            call(prefix + ['kwriteconfig6'] + args + ['--notify', '--', desired], check=True)
            verified = call(prefix + ['kreadconfig6'] + args, check=True).stdout.strip()
            if verified != desired:
                raise RuntimeError('Desktop setting did not persist')
            changed_files.add(filename)

    for filename, group, key, desired in SETTINGS:
        merge(filename, group, key, desired)
    for mime in MIME_TYPES:
        merge('mimeapps.list', 'Default Applications', mime, OFFICE_DESKTOP + ';')
        merge('mimeapps.list', 'Added Associations', mime, OFFICE_DESKTOP + ';', association=True)
    cache_refreshed = False
    if prefix:
        # Also retry after a previous run wrote MIME keys but failed to refresh.
        call(prefix + ['kbuildsycoca6'], check=True)
        cache_refreshed = True
    return {'changed': bool(changed_files), 'profile_exists': True,
            'changed_files': sorted(changed_files), 'cache_refreshed': cache_refreshed}


def apply(username):
    config, prefix, uid = resolve_profile(username)
    if config is None:
        return {'changed': False, 'profile_exists': False}
    return apply_settings(config, prefix, expected_uid=uid)


if __name__ == '__main__':
    if os.getuid() != 0:
        raise ValueError('Run the desktop baseline through the privileged playbook')
    if sys.argv[1] == '--skel':
        result = apply_settings(Path(sys.argv[2]), [], expected_uid=0)
    else:
        result = apply(sys.argv[1])
    print(json.dumps(result))
