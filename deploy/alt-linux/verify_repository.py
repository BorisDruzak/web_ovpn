#!/usr/bin/python3
"""One serial test environment for ALT developers and the guarded installer."""
import argparse
import hashlib
import importlib
import importlib.metadata
import json
import os
from pathlib import Path
import pwd
import subprocess
import sys
import tempfile

ROOT = Path(__file__).resolve().parents[2]
DEFAULT_TARGET = 'tests/alt_linux'
POLICY = 1


def test_environment(workspace, home):
    workspace = Path(workspace)
    for name in ('cache', 'tmp'):
        (workspace/name).mkdir(mode=0o700, exist_ok=True)
    return {
        'PATH': '/usr/local/bin:/usr/bin:/bin:/usr/sbin:/sbin',
        'HOME': home, 'USER': 'altserver', 'LOGNAME': 'altserver',
        'LANG': 'C.UTF-8', 'LC_ALL': 'C.UTF-8',
        'PYTHONPYCACHEPREFIX': str(workspace/'cache'),
        'TMPDIR': str(workspace/'tmp'), 'PYTEST_ADDOPTS': '',
        'QT_QPA_PLATFORM': 'offscreen',
    }


def smoke_check():
    if sys.platform != 'linux' or sys.version_info[:2] != (3, 12):
        raise ValueError('ALT verification requires Linux Python 3.12')
    if os.geteuid() == 0 or os.geteuid() != pwd.getpwnam('altserver').pw_uid:
        raise ValueError('ALT verification must run as altserver, not root')
    for name in ('pytest', 'yaml', 'jinja2', 'jsonschema', 'ansible', 'pydantic'):
        importlib.import_module(name)
    if not (ROOT/'tests/alt_linux').is_dir():
        raise ValueError('ALT test sources are unavailable')


def describe():
    smoke_check()
    rpm = subprocess.run(['/usr/bin/rpm', '-qa', '--qf', '%{NAME}|%{VERSION}-%{RELEASE}|%{INSTALLTIME}\n'],
                         text=True, capture_output=True, timeout=30, check=True)
    packages = sorted((d.metadata['Name'], d.version, str(d.locate_file('')))
                      for d in importlib.metadata.distributions())
    return {'policy': POLICY, 'python': sys.version, 'executable': str(Path(sys.executable).resolve()),
            'executable_sha256': hashlib.sha256(Path(sys.executable).read_bytes()).hexdigest(),
            'uid': os.geteuid(), 'gid': os.getegid(), 'packages': packages,
            'rpm_sha256': hashlib.sha256('\n'.join(sorted(rpm.stdout.splitlines())).encode()).hexdigest(),
            'os_sha256': hashlib.sha256(Path('/etc/os-release').read_bytes()).hexdigest()}


def syntax_commands(root):
    alt = root/'deploy/alt-linux'
    files = sorted((alt/'control/alt_deploy').glob('*.py'))
    for directory in ('ansible/callback_plugins', 'ansible/filter_plugins'):
        files.extend(sorted((alt/directory).glob('*.py')))
    files.extend(alt/p for p in ('api/static_server.py', 'api/register_api.py', 'api/process_pending.py',
        'control/alt-job-stage', 'control/alt-setup-worker', 'control/alt-workstations-gateway', 'verify_repository.py'))
    if (alt/'verification_checkpoint.py').exists():
        files.append(alt/'verification_checkpoint.py')
    yield [sys.executable, '-m', 'py_compile', *map(str, files)]
    for script in ('install-control-plane.sh', 'install-control-plane-args.sh', 'install-control-plane-lib.sh',
                   'install-workstations-gateway.sh', 'bootstrap/bootstrap.sh',
                   'bootstrap/alt-bootstrap-register', 'run-tests.sh'):
        yield ['/bin/bash', '-n', str(alt/script)]


def verify(root, targets, *, run=subprocess.run):
    smoke_check()
    with tempfile.TemporaryDirectory(prefix='altv-', dir='/tmp') as temporary:
        environment = test_environment(temporary, pwd.getpwuid(os.geteuid()).pw_dir)
        previous = os.umask(0o022)
        try:
            for command in syntax_commands(root):
                result = run(command, cwd=root, env=environment, check=False)
                if result.returncode:
                    return result.returncode
            command = [sys.executable, '-m', 'pytest', '-q', '-p', 'no:cacheprovider',
                       '--basetemp', str(Path(temporary)/'pt'), *(targets or [DEFAULT_TARGET])]
            return run(command, cwd=root, env=environment, check=False).returncode
        finally:
            os.umask(previous)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--describe', action='store_true')
    parser.add_argument('--worker', action='store_true', help=argparse.SUPPRESS)
    parser.add_argument('targets', nargs='*')
    args = parser.parse_args()
    if not args.worker:
        # Re-exec before dependency imports and pytest plugin discovery. The
        # installer always enters here, never through the internal worker flag.
        with tempfile.TemporaryDirectory(prefix='altve-', dir='/tmp') as temporary:
            environment = test_environment(temporary, pwd.getpwuid(os.geteuid()).pw_dir)
            return subprocess.run([sys.executable, __file__, '--worker', *sys.argv[1:]],
                                  env=environment, cwd=ROOT, check=False).returncode
    if args.describe:
        print(json.dumps(describe(), sort_keys=True))
        return 0
    return verify(ROOT, args.targets)


if __name__ == '__main__':
    try:
        raise SystemExit(main())
    except (ValueError, KeyError, OSError, subprocess.SubprocessError) as exc:
        print(f'ALT verification refused: {exc}', file=sys.stderr)
        raise SystemExit(1)
