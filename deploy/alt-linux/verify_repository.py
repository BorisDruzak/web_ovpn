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


def runtime_digest(paths):
    """Hash executable import inputs, including unrecorded startup hooks.

    Distribution versions alone miss .pth/sitecustomize and same-version file
    edits. Follow directory links with inode cycle detection; ignore pyc caches.
    """
    rows = []
    def unreadable(error):
        raise error
    for root in sorted({Path(p).absolute() for p in paths}, key=str):
        if root == ROOT or (root.is_relative_to(ROOT) and not root.is_relative_to(ROOT/'.venv')):
            continue  # Already bound by the source receipt.
        if root == Path('/') or root == Path.home():
            raise ValueError('unbounded Python import root')
        if not root.exists():
            rows.append((str(root), None))
            continue
        if root.is_file():
            rows.append((str(root), hashlib.sha256(root.read_bytes()).hexdigest()))
            continue
        visited = set()
        for directory, names, files in os.walk(root, followlinks=True, onerror=unreadable):
            info = Path(directory).stat()
            identity = (info.st_dev, info.st_ino)
            if identity in visited:
                names[:] = []
                continue
            visited.add(identity)
            names[:] = sorted(n for n in names if n != '__pycache__')
            for name in sorted(files):
                path = Path(directory)/name
                if path.suffix not in ('.py', '.so', '.pth', '.zip', '.egg') and name not in ('METADATA', 'entry_points.txt', 'top_level.txt'):
                    continue
                with path.open('rb') as stream:
                    content = hashlib.file_digest(stream, 'sha256').hexdigest()
                rows.append((str(path), content))
                if len(rows) > 150000:
                    raise ValueError('Python import tree too large to verify')
    return hashlib.sha256(json.dumps(sorted(rows), separators=(',', ':')).encode()).hexdigest()


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
    packages = []
    for distribution in importlib.metadata.distributions():
        files = []
        for entry in distribution.files or ():
            path = distribution.locate_file(entry)
            if (path.suffix in ('.py', '.so', '.pth') or path.name in ('METADATA', 'entry_points.txt')) and path.is_file():
                info = path.stat()
                files.append((str(entry), info.st_size, info.st_mtime_ns, info.st_ino, info.st_mode))
        packages.append((distribution.metadata['Name'], distribution.version, str(distribution.locate_file('')),
                         hashlib.sha256(json.dumps(sorted(files)).encode()).hexdigest()))
    packages.sort()
    return {'policy': POLICY, 'python': sys.version, 'executable': str(Path(sys.executable).resolve()),
            'executable_sha256': hashlib.sha256(Path(sys.executable).read_bytes()).hexdigest(),
            'uid': os.geteuid(), 'gid': os.getegid(), 'packages': packages,
            'runtime_sha256': runtime_digest(sys.path),
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
        yield ['/bin/sh' if script == 'install-workstations-gateway.sh' else '/bin/bash', '-n', str(alt/script)]


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
