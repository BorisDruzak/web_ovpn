"""Private first-join progress and allowlisted receipts; never retry authority."""
from contextlib import contextmanager
from datetime import datetime, timezone
import fcntl
import hashlib
import json
import os
from pathlib import Path
import re
import stat
import tempfile

ROOT = Path('/var/lib/alt-deploy-first-join')
PHASES = frozenset(('request', 'native_interface', 'preconditions', 'directory_observation', 'admission',
    'native_arguments', 'native_execution', 'offline_keytab', 'keytab_bind', 'trust_verify', 'machine_as'))
CODES = frozenset('first_join_' + value for value in (
    'request_invalid', 'native_interface_invalid', 'local_state_conflict', 'directory_unavailable',
    'native_arguments_invalid', 'native_failed', 'native_access_denied', 'native_kerberos_failed',
    'native_name_collision', 'native_cache_unavailable', 'keytab_create_failed', 'keytab_bind_failed',
    'trust_failed', 'machine_as_failed', 'timeout', 'output_limit', 'internal_error', 'ok',
    'ad_quota_exhausted', 'ad_rights_unproven', 'ad_principal_unusable',
    'ad_identity_changed', 'ad_preflight_failed', 'native_quota_exhausted'))
EFFECTS = frozenset(('not_dispatched', 'dispatch_entered', 'returned_success', 'returned_failure', 'uncertain'))
MAX_BYTES = 4096
MAX_TIMELINE_BYTES = 262144
NATIVE_STATUSES = frozenset(('WERR_DS_MACHINE_ACCOUNT_QUOTA_EXCEEDED',
    'ERROR_DS_MACHINE_ACCOUNT_QUOTA_EXCEEDED', 'NT_STATUS_QUOTA_EXCEEDED',
    'NT_STATUS_ACCESS_DENIED', 'WERR_ACCESS_DENIED', 'WERR_DS_INSUFF_ACCESS_RIGHTS',
    'NT_STATUS_LOGON_FAILURE', 'KRB5KDC_ERR_PREAUTH_FAILED', 'KRB5KDC_ERR_C_PRINCIPAL_UNKNOWN',
    'NT_STATUS_OBJECT_NAME_COLLISION', 'WERR_ALREADY_EXISTS'))


def binding(value):
    if (not isinstance(value, dict) or set(value) != {'schema_version', 'configuration_run_id', 'invocation_id', 'identity_sha256'}
            or type(value['schema_version']) is not int or value['schema_version'] != 1
            or any(not isinstance(value[k], str) or not re.fullmatch('[0-9a-f]{'+str(n)+'}', value[k])
                   for k, n in (('configuration_run_id', 32), ('invocation_id', 32), ('identity_sha256', 64)))):
        raise ValueError('Invalid diagnostic binding')
    return dict(value)


def _directory(path, *, create=False):
    for ancestor in path.parents:
        if not stat.S_ISDIR(ancestor.lstat().st_mode):
            raise ValueError('Unsafe diagnostic ancestry')
    if create:
        try: path.mkdir(mode=0o700)
        except FileExistsError: pass
    info = path.lstat()
    if not stat.S_ISDIR(info.st_mode) or info.st_uid != os.geteuid() or stat.S_IMODE(info.st_mode) != 0o700:
        raise ValueError('Unsafe diagnostic directory')


def _sync(path):
    fd = os.open(path, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
    try: os.fsync(fd)
    finally: os.close(fd)


def _read(path):
    fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW)
    with os.fdopen(fd, 'rb') as stream:
        info = os.fstat(stream.fileno())
        if (not stat.S_ISREG(info.st_mode) or info.st_uid != os.geteuid()
                or stat.S_IMODE(info.st_mode) != 0o600 or info.st_size > MAX_BYTES):
            raise ValueError('Unsafe diagnostic file')
        raw = stream.read(MAX_BYTES + 1)
    def unique(pairs):
        result = {}
        for key, value in pairs:
            if key in result: raise ValueError('Duplicate diagnostic field')
            result[key] = value
        return result
    if len(raw) > MAX_BYTES: raise ValueError('Oversized diagnostic file')
    return json.loads(raw, object_pairs_hook=unique)


def _validate(value, expected):
    if (not isinstance(value, dict) or set(value) != set(expected) | {'phase', 'code', 'directory_effect', 'returncode'}
            or any(value.get(k) != v or type(value.get(k)) is not type(v) for k, v in expected.items())
            or value['phase'] not in PHASES or value['code'] not in CODES
            or value['directory_effect'] not in EFFECTS
            or value['returncode'] is not None and (type(value['returncode']) is not int or not -255 <= value['returncode'] <= 65535)):
        raise ValueError('Invalid diagnostic receipt')
    return dict(value)


class Diagnostics:
    def __init__(self, value, *, root=ROOT):
        self.binding = binding(value)
        self.root = Path(root)
        _directory(self.root, create=True)
        self.directory = self.root / self.binding['configuration_run_id']
        _directory(self.directory, create=True)
        leaf = self.binding['invocation_id']
        self.path = self.directory / (leaf + '.json')
        self.progress = self.directory / (leaf + '.progress.json')
        self.lock = self.directory / (leaf + '.lock')
        self.timeline = self.directory / (leaf + '.timeline.jsonl')

    @contextmanager
    def _guard(self):
        _directory(self.root)
        _directory(self.directory)
        fd = os.open(self.lock, os.O_RDWR | os.O_CREAT | os.O_NOFOLLOW, 0o600)
        try:
            info = os.fstat(fd)
            if not stat.S_ISREG(info.st_mode) or info.st_uid != os.geteuid() or stat.S_IMODE(info.st_mode) != 0o600:
                raise ValueError('Unsafe diagnostic lock')
            fcntl.flock(fd, fcntl.LOCK_EX)
            yield
        finally: os.close(fd)

    def _current(self):
        if self.progress.exists() or self.progress.is_symlink():
            return _validate(_read(self.progress), self.binding)
        return dict(self.binding, phase='request', code='first_join_internal_error',
                    directory_effect='not_dispatched', returncode=None)

    def current(self):
        with self._guard(): return self._current()

    def _write(self, value, *, final=False):
        _validate(value, self.binding)
        raw = json.dumps(value, sort_keys=True, separators=(',', ':')).encode() + b'\n'
        if len(raw) > MAX_BYTES: raise ValueError('Oversized diagnostic receipt')
        if self.path.exists() or self.path.is_symlink(): raise ValueError('Diagnostic invocation is closed')
        self._append_timeline(dict(value, event='state'))
        fd, name = tempfile.mkstemp(prefix='.diagnostic-', dir=self.directory)
        try:
            with os.fdopen(fd, 'wb') as stream:
                stream.write(raw); stream.flush(); os.fsync(stream.fileno())
            if final: os.link(name, self.path, follow_symlinks=False)
            else: os.replace(name, self.progress)
            _sync(self.directory)
        finally:
            try: os.unlink(name)
            except FileNotFoundError: pass

    def _append_timeline(self, value):
        value = dict(value, observed_at=datetime.now(timezone.utc).isoformat())
        raw = json.dumps(value, sort_keys=True, separators=(',', ':')).encode() + b'\n'
        if len(raw) > MAX_BYTES:
            raise ValueError('Diagnostic timeline record exceeds its bound')
        fd = os.open(self.timeline, os.O_WRONLY | os.O_CREAT | os.O_APPEND | os.O_NOFOLLOW, 0o600)
        try:
            info = os.fstat(fd)
            if (not stat.S_ISREG(info.st_mode) or info.st_uid != os.geteuid()
                    or stat.S_IMODE(info.st_mode) != 0o600 or info.st_nlink != 1
                    or info.st_size + len(raw) > MAX_TIMELINE_BYTES):
                raise ValueError('Unsafe or oversized diagnostic timeline')
            if os.write(fd, raw) != len(raw):
                raise ValueError('Incomplete diagnostic timeline write')
            os.fsync(fd)
        finally:
            os.close(fd)

    def native_result(self, result):
        if (type(result.returncode) is not int or not -255 <= result.returncode <= 65535
                or not isinstance(result.stdout, str) or not isinstance(result.stderr, str)):
            raise ValueError('Invalid native diagnostic result')
        stdout, stderr = result.stdout.encode(), result.stderr.encode()
        if len(stdout) + len(stderr) > 65536:
            raise ValueError('Native diagnostic result exceeds its bound')
        output = result.stdout + '\n' + result.stderr
        statuses = sorted({token for token in re.findall(r'\b[A-Z][A-Z0-9_]{2,100}\b', output)
                           if token in NATIVE_STATUSES})
        ldap_codes = sorted({int(n) for n in re.findall(r'(?i)\bLDAP(?:\s+error|\s+result(?:\s+code)?)\s*[:=]?\s*([0-9]{1,3})\b', output)
                             if int(n) <= 255})
        with self._guard():
            if self.path.exists() or self.path.is_symlink():
                raise ValueError('Diagnostic invocation is closed')
            state = self._current()
            self._append_timeline(dict(self.binding, event='native_result',
                phase=state['phase'], returncode=result.returncode, statuses=statuses,
                ldap_result_codes=ldap_codes,
                stdout_bytes=len(stdout), stderr_bytes=len(stderr),
                stdout_sha256=hashlib.sha256(stdout).hexdigest(),
                stderr_sha256=hashlib.sha256(stderr).hexdigest()))

    def admission_result(self, value):
        numeric = ('domain_quota', 'created_computers', 'quota_remaining')
        if (not isinstance(value, dict) or value.get('creation_mode') != 'delegated'
                or value.get('quota_applicable') is not False
                or any(type(value.get(k)) is not int or not 0 <= value[k] <= 2147483647 for k in numeric)
                or value['quota_remaining'] != max(0, value['domain_quota']-value['created_computers'])):
            raise ValueError('Invalid AD admission diagnostic facts')
        with self._guard():
            if self.path.exists() or self.path.is_symlink():
                raise ValueError('Diagnostic invocation is closed')
            self._append_timeline(dict(self.binding, event='ad_admission', phase='admission',
                creation_mode='delegated', quota_applicable=False,
                **{k: value[k] for k in numeric}))

    def intent(self, phase):
        with self._guard():
            value = self._current()
            value.update(phase=phase, code='first_join_internal_error', returncode=None)
            if phase == 'native_execution': value['directory_effect'] = 'dispatch_entered'
            self._write(value)

    def result(self, phase, *, code, returncode):
        with self._guard():
            value = self._current()
            value.update(phase=phase, code=code, returncode=returncode)
            if phase == 'native_execution' and value['directory_effect'] == 'dispatch_entered':
                value['directory_effect'] = ('uncertain' if returncode is None else
                    'returned_success' if returncode == 0 else 'returned_failure')
            self._write(value)

    def publish(self):
        with self._guard():
            if self.path.exists() or self.path.is_symlink():
                return _validate(_read(self.path), self.binding)
            value = self._current()
            if value['directory_effect'] == 'dispatch_entered': value['directory_effect'] = 'uncertain'
            self._write(value, final=True)
            return value


def read_public(value, *, root=ROOT):
    try:
        expected = binding(value)
        root = Path(root)
        directory = root / expected['configuration_run_id']
        _directory(root); _directory(directory)
        result = _validate(_read(directory / (expected['invocation_id'] + '.json')), expected)
        return {k: v for k, v in result.items() if k != 'returncode'}
    except (OSError, TypeError, KeyError, ValueError) as exc:
        raise ValueError('Diagnostic receipt unavailable') from None


def native_failure_code(output):
    if not isinstance(output, str) or len(output) > 65536:
        return 'first_join_native_failed'
    for pattern, code in (
        (r'\b(?:WERR_DS_MACHINE_ACCOUNT_QUOTA_EXCEEDED|ERROR_DS_MACHINE_ACCOUNT_QUOTA_EXCEEDED|NT_STATUS_QUOTA_EXCEEDED)\b|maximum number of computer accounts.*exceeded', 'quota_exhausted'),
        (r'\b(?:NT_STATUS_ACCESS_DENIED|WERR_ACCESS_DENIED|WERR_DS_INSUFF_ACCESS_RIGHTS)\b', 'access_denied'),
        (r'\b(?:NT_STATUS_LOGON_FAILURE|KRB5KDC_ERR_PREAUTH_FAILED|KRB5KDC_ERR_C_PRINCIPAL_UNKNOWN)\b', 'kerberos_failed'),
        (r'\b(?:NT_STATUS_OBJECT_NAME_COLLISION|WERR_ALREADY_EXISTS)\b', 'name_collision'),
        (r'\b(?:No credentials cache found|Credentials cache file .* not found)\b', 'cache_unavailable'),
    ):
        if re.search(pattern, output, re.IGNORECASE): return 'first_join_native_' + code
    return 'first_join_native_failed'
