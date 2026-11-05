#!/usr/bin/python3
"""Read-only ownership/conflict gate for the dedicated CryptoPro browser policy."""
import json
import os
from pathlib import Path
import stat
import sys

EXTENSION_ID = 'epebfcehmdedogndhlcacafjaacknbcm'
UPDATE_URL = 'https://extension-updates.opera.com/api/omaha/update/'
MANAGED = Path('/etc/opt/yandex/browser/policies/managed')
OWNED_NAME = 'alt-cryptopro-cades.json'
POLICY = {'ExtensionSettings': {EXTENSION_ID: {
    'installation_mode': 'force_installed', 'update_url': UPDATE_URL}}}


def protected(info, *, directory, expected_uid):
    kind = stat.S_ISDIR if directory else stat.S_ISREG
    if not kind(info.st_mode) or info.st_uid != expected_uid or info.st_mode & 0o022:
        raise ValueError('unsafe browser policy metadata')


def unique_object(pairs):
    result = {}
    for key, value in pairs:
        if key in result:
            raise ValueError('duplicate browser policy key')
        result[key] = value
    return result


def read_policy(path, expected_uid):
    before = path.lstat()
    protected(before, directory=False, expected_uid=expected_uid)
    fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW)
    try:
        actual = os.fstat(fd)
        protected(actual, directory=False, expected_uid=expected_uid)
        if (actual.st_dev, actual.st_ino) != (before.st_dev, before.st_ino) or actual.st_size > 1048576:
            raise ValueError('unsafe browser policy input')
        with os.fdopen(fd, 'rb', closefd=False) as stream:
            raw = stream.read(1048577)
        if len(raw) > 1048576:
            raise ValueError('browser policy exceeds size limit')
        value = json.loads(raw, object_pairs_hook=unique_object)
        if not isinstance(value, dict):
            raise ValueError('browser policy must be an object')
        return value
    finally:
        os.close(fd)


def inspect_directory(root, *, expected_uid=0):
    """Return the fixed candidate, preserving every existing policy byte."""
    root = Path(root)
    try:
        info = root.lstat()
    except FileNotFoundError:
        paths = []
    else:
        protected(info, directory=True, expected_uid=expected_uid)
        paths = sorted(root.glob('*.json'))
    if len(paths) > 128:
        raise ValueError('too many browser policy inputs')
    for path in paths:
        value = read_policy(path, expected_uid)
        if path.name == OWNED_NAME:
            if value != POLICY:
                raise ValueError('custom CryptoPro policy requires review')
            continue
        # Multiple Linux JSON sources for the same dictionary have undefined
        # precedence. Do not shadow unrelated settings or an AD-owned policy.
        if 'ExtensionSettings' in value:
            raise ValueError('competing ExtensionSettings requires review')
        forced = value.get('ExtensionInstallForcelist', [])
        if not isinstance(forced, list):
            raise ValueError('invalid extension force-install list')
        for entry in forced:
            if isinstance(entry, str) and entry.split(';')[0] == EXTENSION_ID:
                if entry != EXTENSION_ID + ';' + UPDATE_URL:
                    raise ValueError('conflicting CryptoPro extension update source')
    return {'policy_path': str(root / OWNED_NAME), 'policy': POLICY}


def main():
    for parent in reversed(MANAGED.parents):
        try:
            info = parent.lstat()
        except FileNotFoundError:
            break
        protected(info, directory=True, expected_uid=0)
    print(json.dumps(inspect_directory(MANAGED)))


if __name__ == '__main__':
    try:
        main()
    except (ValueError, OSError) as error:
        print('ALT_PREFLIGHT_FAILURE:cryptopro_browser_policy_conflict: ' + str(error), file=sys.stderr)
        sys.exit(2)
