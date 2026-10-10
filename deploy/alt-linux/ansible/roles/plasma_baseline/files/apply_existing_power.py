"""Apply only approved power keys; leave profile creation and screen lock alone."""
import json
import os
from pathlib import Path
import re
import subprocess
import sys

SETTINGS = (
    ('Display', 'DimDisplayWhenIdle', 'false'),
    ('Display', 'DimDisplayIdleTimeoutSec', '-1'),
    ('Display', 'TurnOffDisplayWhenIdle', 'false'),
    ('Display', 'TurnOffDisplayIdleTimeoutSec', '-1'),
    ('Display', 'TurnOffDisplayIdleTimeoutWhenLockedSec', '-1'),
    ('SuspendAndShutdown', 'AutoSuspendAction', '0'),
)


def run(argv, **kwargs):
    return subprocess.run(argv, text=True, capture_output=True, **kwargs)


def apply(username):
    if not re.fullmatch(r'[a-zA-Z0-9][a-zA-Z0-9._-]{0,62}(@[a-zA-Z0-9.-]+)?', username):
        raise ValueError('Invalid assigned domain account')
    entry = run(['getent', '-s', 'sss', 'passwd', username])
    if entry.returncode or not entry.stdout.strip():
        raise ValueError('Assigned domain account cannot be resolved')
    lines = entry.stdout.strip().splitlines()
    if len(lines) != 1 or len(lines[0].split(':')) != 7:
        raise ValueError('Ambiguous domain account')
    name, _, uid, gid, _, home, _ = lines[0].split(':')
    uid, gid = int(uid), int(gid)
    if uid <= 0 or name.lower().split('@')[0] in ('root', 'ansible', 'osn-admin'):
        raise ValueError('Administrative profile must not be configured')
    home = Path(home)
    if not home.is_absolute() or not home.is_relative_to('/home') or home == Path('/home'):
        raise ValueError('Unexpected domain home')
    for path in (home, *home.parents):
        if path.is_symlink():
            raise ValueError('Symlinked home is unsafe')
    if not home.exists():
        return {'changed': False, 'profile_exists': False}
    if not home.is_dir() or home.stat().st_uid != uid:
        raise ValueError('Domain home ownership mismatch')
    config = home / '.config'
    target = config / 'powerdevilrc'
    if config.is_symlink() or target.is_symlink():
        raise ValueError('Symlinked power configuration is unsafe')
    prefix = ['runuser', '-u', name, '--']
    changed = False
    for profile in ('AC', 'Battery', 'LowBattery'):
        for section, key, value in SETTINGS:
            args = ['--file', str(target), '--group', profile, '--group', section, '--key', key]
            current = run(prefix + ['kreadconfig6'] + args, check=True).stdout.strip()
            if current != value:
                if not config.exists():
                    config.mkdir(mode=0o700)
                    os.chown(config, uid, gid)
                if config.stat().st_uid != uid:
                    raise ValueError('Domain configuration ownership mismatch')
                run(prefix + ['kwriteconfig6'] + args + ['--', value], check=True)
                changed = True
    runtime = Path('/run/user') / str(uid)
    refreshed = False
    if changed and (runtime / 'bus').exists() and runtime.stat().st_uid == uid:
        env = prefix + ['env', 'XDG_RUNTIME_DIR=' + str(runtime),
                        'DBUS_SESSION_BUS_ADDRESS=unix:path=' + str(runtime / 'bus')]
        refresh = run(env + ['busctl', '--user', 'call', 'org.kde.Solid.PowerManagement',
                            '/org/kde/Solid/PowerManagement', 'org.kde.Solid.PowerManagement',
                            'reparseConfiguration'])
        refreshed = refresh.returncode == 0
        if refreshed:
            refreshed = run(env + ['busctl', '--user', 'call', 'org.kde.Solid.PowerManagement',
                                  '/org/kde/Solid/PowerManagement', 'org.kde.Solid.PowerManagement',
                                  'loadProfile', 'b', 'true']).returncode == 0
    return {'changed': changed, 'profile_exists': True, 'session_refreshed': refreshed}


if __name__ == '__main__':
    print(json.dumps(apply(sys.argv[1])))
