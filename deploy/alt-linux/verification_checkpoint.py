#!/usr/bin/python3
"""Root-private automatic ALT release verification, never rollout authorization."""
import argparse
import fcntl
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import stat
import subprocess
import sys
import tempfile
import time

MAX_AGE = 6 * 60 * 60
IGNORED = {'.git', '.venv', '.superpowers', '.pytest_cache', '__pycache__'}


def digest(value):
    return hashlib.sha256(json.dumps(value, sort_keys=True, separators=(',', ':')).encode()).hexdigest()


def checked(path, owner, *, directory=False, mode=None):
    info = path.lstat()
    regular = stat.S_ISDIR(info.st_mode) if directory else stat.S_ISREG(info.st_mode)
    if (not regular or info.st_uid != owner or info.st_mode & 0o022
            or (not directory and info.st_nlink != 1)
            or (mode is not None and stat.S_IMODE(info.st_mode) != mode)):
        raise ValueError('verification_path_unsafe')
    return info


def source_snapshot(root, owner):
    checked(root, owner, directory=True)
    rows = []
    directories = []
    def unreadable(error):
        raise error
    for directory, names, files in os.walk(root, followlinks=False, onerror=unreadable):
        names[:] = sorted(n for n in names if n not in IGNORED)
        parent = Path(directory)
        directory_info = checked(parent, owner, directory=True)
        directories.append((str(parent.relative_to(root)), stat.S_IMODE(directory_info.st_mode)))
        for name in names:
            checked(parent/name, owner, directory=True)
        for name in sorted(files):
            if name.endswith(('.pyc', '.pyo')) or name in IGNORED:
                continue
            path = parent/name
            info = checked(path, owner)
            with path.open('rb') as stream:
                content = hashlib.file_digest(stream, 'sha256').hexdigest()
            rows.append((str(path.relative_to(root)), stat.S_IMODE(info.st_mode), content))
    if not rows:
        raise ValueError('verification_source_empty')
    return {'files': sorted(rows), 'directories': sorted(directories)}


def source_manifest(root, owner):
    return source_snapshot(root, owner)['files']


def source_digest(root, owner):
    return digest(source_manifest(root, owner))


def verify(source, cache, environment, execute, *, resume=False, owner=0, now=None):
    """Callable environment is sampled before and after a fresh verification."""
    clock = time.time if now is None else lambda: now
    current_time = clock()
    env = environment if callable(environment) else lambda: environment
    identity = {'schema': 1, 'suite': 'alt-linux-full-v1',
                'source_sha256': source_digest(source, owner), 'environment_sha256': digest(env())}
    if not cache.exists():
        cache.mkdir(mode=0o700)
    checked(cache, owner, directory=True, mode=0o700)
    lock_path = cache/'.lock'
    fd = os.open(lock_path, os.O_CREAT | os.O_RDWR | os.O_NOFOLLOW | os.O_CLOEXEC, 0o600)
    try:
        checked(lock_path, owner, mode=0o600)
        fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
        receipt = cache/(digest(identity)+'.json')
        if resume:
            if not receipt.exists() and not receipt.is_symlink():
                raise ValueError('verification_receipt_missing')
            info = checked(receipt, owner, mode=0o600)
            if info.st_size > 8192:
                raise ValueError('verification_receipt_invalid')
            evidence = json.loads(receipt.read_text())
            if (not isinstance(evidence, dict) or set(evidence) != set(identity) | {'created_at', 'result'}
                    or any(evidence.get(k) != v for k, v in identity.items())
                    or evidence.get('result') != 'passed' or type(evidence.get('created_at')) not in (int, float)
                    or not 0 <= current_time-evidence['created_at'] <= MAX_AGE):
                raise ValueError('verification_receipt_invalid_or_expired')
            return 'reused'
        # A failed fresh run cannot fall back to a previous pass for this input.
        if receipt.exists() or receipt.is_symlink():
            checked(receipt, owner, mode=0o600)
            receipt.unlink()
        if execute() != 0:
            raise ValueError('verification_failed')
        if source_digest(source, owner) != identity['source_sha256'] or digest(env()) != identity['environment_sha256']:
            raise ValueError('verification_inputs_changed')
        evidence = dict(identity, result='passed', created_at=clock())
        # Explicit creation time reflects completion, not the start of a long run.
        if evidence['created_at'] <= 0:
            raise ValueError('verification_time_invalid')
        temporary = None
        try:
            with tempfile.NamedTemporaryFile(mode='w', dir=cache, prefix='.receipt-', delete=False) as stream:
                temporary = Path(stream.name)
                json.dump(evidence, stream, sort_keys=True)
                stream.flush()
                os.fsync(stream.fileno())
            os.replace(temporary, receipt)
            temporary = None
            directory_fd = os.open(cache, os.O_RDONLY | os.O_DIRECTORY)
            try:
                os.fsync(directory_fd)
            finally:
                os.close(directory_fd)
        finally:
            if temporary is not None:
                temporary.unlink(missing_ok=True)
        return 'verified'
    finally:
        os.close(fd)


def worker_command(source, python):
    return ['/usr/bin/sudo', '-n', '-H', '-u', 'altserver', '--', python,
            '-E', str(source/'deploy/alt-linux/verify_repository.py')]


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--source', type=Path, required=True)
    parser.add_argument('--cache', type=Path, required=True)
    parser.add_argument('--python', required=True)
    parser.add_argument('--resume', action='store_true')
    parser.add_argument('--full', action='store_true', help='Force full verification of the installer')
    parser.add_argument('--plan', action='store_true', help='Read-only preliminary test selection')
    args = parser.parse_args()
    if os.geteuid() != 0:
        raise ValueError('root_required')
    sys.dont_write_bytecode = True
    # The public CLI accepts only protected, canonical source/cache ancestry.
    for path in (args.source, args.cache.parent):
        if not path.is_absolute():
            raise ValueError('verification_path_unsafe')
        for parent in (path, *path.parents):
            checked(parent, 0, directory=True)
    if Path(__file__).resolve() != (args.source/'deploy/alt-linux/verification_checkpoint.py').resolve():
        raise ValueError('verification_source_entrypoint_mismatch')
    # -I intentionally excludes the script directory. Import only explicitly
    # protected source files, never the caller's module search path.
    source_manifest(args.source, 0)
    module_path = args.source/'deploy/alt-linux/release_verification.py'
    checked(module_path, 0)
    checked(module_path.with_name('verification_policy.py'), 0)
    spec = importlib.util.spec_from_file_location('alt_release_gate', module_path)
    release = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(release)
    command = worker_command(args.source, args.python)
    clean = {'PATH': '/usr/local/bin:/usr/bin:/bin:/usr/sbin:/sbin', 'LANG': 'C.UTF-8', 'LC_ALL': 'C.UTF-8'}
    def environment():
        result = subprocess.run([*command, '--describe'], cwd=args.source, env=clean,
                                capture_output=True, text=True, timeout=120, check=True)
        return json.loads(result.stdout)
    def execute(targets):
        return subprocess.run([*command, *targets], cwd=args.source, env=clean, check=False).returncode
    outcome = release.verify_release(args.source, args.cache, environment, execute,
        resume=args.resume, full=args.full, plan_only=args.plan)
    print(json.dumps(dict(outcome, status='ok')))


if __name__ == '__main__':
    try:
        main()
    except (ValueError, OSError, subprocess.SubprocessError) as exc:
        print(json.dumps({'status': 'error', 'code': str(exc), 'rollout_authorized': False}))
        raise SystemExit(1)
