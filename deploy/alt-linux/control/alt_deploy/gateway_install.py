"""Root-only enrollment of two source-bound keys; preserve existing SSH access."""
from __future__ import annotations

import argparse
import base64
import hashlib
import ipaddress
import json
import os
import pwd
import re
import stat
import subprocess
import tempfile
from pathlib import Path

from .ad_directory import fail

KEY_FILE = Path('/etc/alt-deploy/workstations-authorized-keys')
START = '# BEGIN managed ALT workstation gateway\n'
END = '# END managed ALT workstation gateway\n'


def _key(value):
    if not isinstance(value, str) or not re.fullmatch(r'ssh-ed25519 [A-Za-z0-9+/]{68}={0,2}', value):
        raise ValueError
    raw = base64.b64decode(value.split()[1], validate=True)
    if len(raw) != 51 or raw[:19] != b'\x00\x00\x00\x0bssh-ed25519\x00\x00\x00\x20':
        raise ValueError
    return value


def render_configuration(document, *, authorized_key_files):
    try:
        if not isinstance(document, dict) or set(document) != {'client_address', 'read_public_key', 'execute_public_key'}:
            raise ValueError
        address = ipaddress.ip_address(document['client_address'])
        if address.is_unspecified or address.is_multicast or str(address) != document['client_address']:
            raise ValueError
        keys = [_key(document[name]) for name in ('read_public_key', 'execute_public_key')]
        if keys[0] == keys[1]:
            raise ValueError
        originals = []
        for value in authorized_key_files:
            if not isinstance(value, str) or not re.fullmatch(r'[a-zA-Z0-9_./%~-]{1,1024}', value):
                raise ValueError
            if value != str(KEY_FILE) and value not in originals:
                originals.append(value)
        if not originals:
            raise ValueError
        lines = [f'restrict,from="{address}",command="/opt/alt-deploy-control/alt-workstations-gateway --scope {scope}" {key}'
                 for scope, key in zip(('read', 'execute'), keys)]
        block = ('Match all\nMatch User altserver\n    AuthorizedKeysFile ' + ' '.join([*originals, str(KEY_FILE)]) + '\nMatch all\n')
        return {'authorized_keys': '\n'.join(lines) + '\n', 'sshd_config': block}
    except (ValueError, TypeError, KeyError) as exc:
        raise fail('workstations_gateway_enrollment_invalid', 'Gateway key enrollment configuration is invalid') from exc


def _root_file(path, *, maximum=1048576):
    for ancestor in path.parents:
        if ancestor.is_symlink():
            raise fail('workstations_gateway_enrollment_unsafe', 'Gateway enrollment path is redirected')
    info = path.lstat()
    if not stat.S_ISREG(info.st_mode) or info.st_uid != 0 or info.st_mode & 0o022 or info.st_size > maximum:
        raise fail('workstations_gateway_enrollment_unsafe', 'Gateway enrollment input must be root-owned and protected')
    return path.read_bytes(), info


def _replace(path, raw, *, mode, uid=0, gid=0):
    if path.is_symlink():
        raise fail('workstations_gateway_enrollment_unsafe', 'Gateway destination is redirected')
    descriptor, name = tempfile.mkstemp(prefix='.workstations-', dir=path.parent)
    temporary = Path(name)
    try:
        with os.fdopen(descriptor, 'wb') as stream:
            os.fchmod(stream.fileno(), mode)
            os.fchown(stream.fileno(), uid, gid)
            stream.write(raw)
            stream.flush()
            os.fsync(stream.fileno())
        os.replace(temporary, path)
        descriptor = os.open(path.parent, os.O_RDONLY | os.O_DIRECTORY)
        try:
            os.fsync(descriptor)
        finally:
            os.close(descriptor)
    finally:
        temporary.unlink(missing_ok=True)


def apply_configuration(document, *, check=False):
    if os.geteuid() != 0:
        raise fail('workstations_gateway_enrollment_actor', 'Gateway key enrollment requires protected administrator access')
    # The existing service account owns canonical controller state. Per-key
    # restrictions avoid changing its password policy or adding a sudo identity.
    account = pwd.getpwnam('altserver')
    config_path = Path('/etc/openssh/sshd_config')
    if not config_path.is_file():
        config_path = Path('/etc/ssh/sshd_config')
    original_config, metadata = _root_file(config_path)
    if KEY_FILE.exists() or KEY_FILE.is_symlink():
        original_keys, key_metadata = _root_file(KEY_FILE, maximum=32768)
    else:
        original_keys, key_metadata = None, None
    for parent in KEY_FILE.parents:
        if parent.is_symlink():
            raise fail('workstations_gateway_enrollment_unsafe', 'Gateway key directory is redirected')
    if not KEY_FILE.parent.is_dir():
        raise fail('workstations_gateway_enrollment_unsafe', 'Protected controller configuration directory is missing')
    launcher = Path('/opt/alt-deploy-control/alt-workstations-gateway')
    _, launcher_metadata = _root_file(launcher)
    if stat.S_IMODE(launcher_metadata.st_mode) != 0o755:
        raise fail('workstations_gateway_enrollment_unsafe', 'Install the guarded controller gateway before enrolling keys')
    sshd = '/usr/sbin/sshd'
    def run(args):
        return subprocess.run(args, check=True, capture_output=True, text=True, timeout=20)
    run([sshd, '-t', '-f', str(config_path)])
    client = document.get('client_address', '') if isinstance(document, dict) else ''
    # Validate the client before including it in the fixed sshd inspection argv.
    render_configuration(document, authorized_key_files=('.ssh/authorized_keys',))
    inspection = [sshd, '-T', '-f', str(config_path), '-C', 'user=altserver,host=localhost,addr=' + client]
    effective = run(inspection).stdout
    originals = next((line.split()[1:] for line in effective.splitlines() if line.startswith('authorizedkeysfile ')), [])
    rendered = render_configuration(document, authorized_key_files=originals)
    config_text = original_config.decode('utf-8')
    if START in config_text or END in config_text:
        if config_text.count(START) != 1 or config_text.count(END) != 1:
            raise fail('workstations_gateway_enrollment_unsafe', 'Managed SSH gateway block requires review')
        before, tail = config_text.split(START)
        previous, after = tail.split(END)
        config_text = before + after
    elif original_keys is not None:
        raise fail('workstations_gateway_enrollment_unsafe', 'Unmanaged gateway key file requires review')
    result = config_text.rstrip() + '\n\n' + START + rendered['sshd_config'] + END
    if check:
        return {'status': 'ok', 'operation': 'gateway_enrollment_check', 'existing_access_preserved': True}
    try:
        _replace(KEY_FILE, rendered['authorized_keys'].encode(), mode=0o640, gid=account.pw_gid)
        _replace(config_path, result.encode('utf-8'), mode=stat.S_IMODE(metadata.st_mode), gid=metadata.st_gid)
        run([sshd, '-t', '-f', str(config_path)])
        installed = run(inspection).stdout
        paths = next((line.split()[1:] for line in installed.splitlines() if line.startswith('authorizedkeysfile ')), [])
        if not set(originals + [str(KEY_FILE)]) <= set(paths):
            raise fail('workstations_gateway_enrollment_unsafe', 'SSH configuration did not preserve the required key sources')
        run(['/bin/systemctl', 'reload', 'sshd.service'])
    except BaseException:
        _replace(config_path, original_config, mode=stat.S_IMODE(metadata.st_mode), gid=metadata.st_gid)
        if original_keys is None:
            KEY_FILE.unlink(missing_ok=True)
        else:
            _replace(KEY_FILE, original_keys, mode=stat.S_IMODE(key_metadata.st_mode), gid=key_metadata.st_gid)
        run([sshd, '-t', '-f', str(config_path)])
        run(['/bin/systemctl', 'reload', 'sshd.service'])
        raise
    return {'status': 'ok', 'operation': 'gateway_enrollment', 'existing_access_preserved': True,
            'public_keys_sha256': hashlib.sha256(rendered['authorized_keys'].encode()).hexdigest()}


def main(argv=None):
    parser = argparse.ArgumentParser(allow_abbrev=False)
    parser.add_argument('--config', type=Path, required=True)
    parser.add_argument('--check', action='store_true')
    args = parser.parse_args(argv)
    try:
        raw, _ = _root_file(args.config, maximum=32768)
        result = apply_configuration(json.loads(raw), check=args.check)
        print(json.dumps(result))
        return 0
    except Exception:
        print(json.dumps({'status': 'error', 'code': 'workstations_gateway_enrollment_failed'}))
        return 1
