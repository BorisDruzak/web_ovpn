"""Bounded ldapsearch with GSSAPI sealing or certificate-verified TLS.

No password appears in argv or in error output. Credential files/caches live
only in private temporary directories and are removed on every exit path.
"""
from __future__ import annotations

import json
import os
import re
import stat
import subprocess
import tempfile
from contextlib import contextmanager
from dataclasses import dataclass
from pathlib import Path
from threading import Thread
from urllib.parse import urlsplit

from .ad_directory import BASE_DN, MAX_BYTES, MAX_RESULTS, fail
from .config import Settings
from .vault import VaultHealthChecker


@dataclass(frozen=True)
class DirectoryConfig:
    uri: str = 'ldap://sosnadmin.local'
    approved_ous: tuple[str, ...] = ()
    auth: str = 'gssapi'
    credential_source: str = 'ticket'
    ca_file: str | None = None

    def __post_init__(self):
        try:
            parsed = urlsplit(self.uri)
            if (parsed.scheme not in ('ldap', 'ldaps') or not parsed.hostname
                    or not re.fullmatch(r'[a-zA-Z0-9.-]+', parsed.hostname)
                    or parsed.username is not None or parsed.password is not None
                    or parsed.path or parsed.query or parsed.fragment
                    or any(ord(char) <= 32 for char in self.uri)
                    or parsed.port not in (None, 389, 636)):
                raise ValueError
            if self.auth not in ('gssapi', 'starttls', 'ldaps'):
                raise ValueError
            if self.credential_source not in ('ticket', 'join-vault', 'readonly-vault'):
                raise ValueError
            if self.auth != 'gssapi' and (self.credential_source != 'readonly-vault' or not self.ca_file):
                raise ValueError
            if self.auth == 'ldaps' and parsed.scheme != 'ldaps':
                raise ValueError
            if self.auth == 'starttls' and parsed.scheme != 'ldap':
                raise ValueError
            if not isinstance(self.approved_ous, tuple) or len(self.approved_ous) > MAX_RESULTS:
                raise ValueError
            for dn in self.approved_ous:
                if (not isinstance(dn, str) or len(dn) > 4096
                        or not re.fullmatch(r'(?:OU=[^,\\\x00-\x1f]+,)+DC=sosnadmin,DC=local', dn)):
                    raise ValueError
        except (ValueError, TypeError, AttributeError) as exc:
            raise fail('ad_directory_config_invalid', 'AD directory configuration is invalid') from exc

    @classmethod
    def load(cls, path: Path = Path('/etc/alt-deploy/ad-directory.json')):
        if not path.exists():
            # Existing delegated Vault identity may acquire a ticket; the
            # adapter has no write API. No OU is approved by this default.
            return cls(credential_source='join-vault')
        try:
            info = path.lstat()
            if (not stat.S_ISREG(info.st_mode) or info.st_size > 32768
                    or (os.name != 'nt' and (info.st_uid != 0 or info.st_mode & 0o022))):
                raise ValueError
            document = json.loads(path.read_text(encoding='utf-8'))
            if not isinstance(document, dict) or set(document) - {'uri', 'approved_ous', 'auth', 'credential_source', 'ca_file'}:
                raise ValueError
            if 'approved_ous' in document:
                if not isinstance(document['approved_ous'], list):
                    raise ValueError
                document['approved_ous'] = tuple(document['approved_ous'])
            return cls(**document)
        except (OSError, ValueError, TypeError) as exc:
            raise fail('ad_directory_config_invalid', 'AD directory configuration cannot be read safely') from exc


def bounded_run(command, *, environment, input_text=None, timeout=20):
    """Read at most MAX_BYTES+1 from each pipe; kill excessive producers."""
    try:
        process = subprocess.Popen(command, shell=False, env=environment,
                                   stdin=subprocess.PIPE if input_text is not None else subprocess.DEVNULL,
                                   stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        captured = [b'', b'']
        excessive = []

        def read_pipe(index, stream):
            captured[index] = stream.read(MAX_BYTES + 1)
            if len(captured[index]) > MAX_BYTES:
                excessive.append(True)
                process.kill()
            stream.close()

        readers = [Thread(target=read_pipe, args=(index, stream), daemon=True)
                   for index, stream in enumerate((process.stdout, process.stderr))]
        for reader in readers:
            reader.start()
        try:
            if input_text is not None:
                try:
                    process.stdin.write(input_text.encode('utf-8'))
                    process.stdin.close()
                except BrokenPipeError:
                    pass
            process.wait(timeout=timeout)
        except subprocess.TimeoutExpired as exc:
            process.kill()
            process.wait()
            raise fail('ad_timeout', 'AD operation timed out') from exc
        finally:
            for reader in readers:
                reader.join(timeout=2)
        if excessive:
            raise fail('ad_results_limit', 'AD response exceeds the size limit')
        return process.returncode, captured[0].decode('utf-8', errors='strict'), captured[1].decode('utf-8', errors='replace')
    except (OSError, UnicodeError) as exc:
        raise fail('ad_transport_unavailable', 'AD transport is unavailable') from exc


class LDAPTransport:
    def __init__(self, config: DirectoryConfig, *, settings: Settings | None = None, runner=None):
        self.config = config
        self.settings = settings
        self.runner = runner or bounded_run

    @contextmanager
    def _credentials(self, environment):
        source = self.config.credential_source
        if source == 'ticket':
            yield environment, []
            return
        if self.settings is None:
            raise fail('ad_credentials_unavailable', 'AD controller credentials are unavailable')
        checker = VaultHealthChecker(self.settings)
        if not all(checker._build_checks().values()):
            raise fail('ad_credentials_unavailable', 'AD Vault files do not satisfy the protected controller contract')
        if source == 'join-vault':
            checker.check_ad_join()
        # Decryption stays in memory; do not expose material or parser errors.
        try:
            import yaml
            document = yaml.safe_load(checker._decrypt())
            prefix = 'vault_ad_join_' if source == 'join-vault' else 'vault_ad_readonly_'
            principal = document[prefix + 'user']
            password = document[prefix + 'password']
            if (not isinstance(principal, str) or not isinstance(password, str)
                    or not password or len(password) > 4096
                    or '\n' in password or '\r' in password
                    or not re.fullmatch(r'[a-zA-Z0-9._@-]{1,192}', principal)):
                raise ValueError
        except Exception as exc:
            raise fail('ad_credentials_unavailable', 'Required AD Vault credentials are unavailable') from exc
        with tempfile.TemporaryDirectory(prefix='alt-ad-') as private_dir:
            os.chmod(private_dir, 0o700)
            if self.config.auth == 'gssapi':
                environment['KRB5CCNAME'] = 'FILE:' + private_dir + '/cache'
                if '@' not in principal:
                    principal += '@SOSNADMIN.LOCAL'
                rc, _, _ = self.runner(['/usr/bin/kinit', '-C', principal], environment=environment, input_text=password + '\n')
                if rc != 0:
                    raise fail('ad_kerberos_failed', 'AD Kerberos authentication failed')
                try:
                    yield environment, []
                finally:
                    try:
                        self.runner(['/usr/bin/kdestroy'], environment=environment, timeout=5)
                    except Exception:
                        pass  # Private cache is removed by TemporaryDirectory.
            else:
                path = Path(private_dir) / 'password'
                fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
                with os.fdopen(fd, 'w', encoding='utf-8') as stream:
                    stream.write(password)
                yield environment, ['-x', '-D', principal, '-y', str(path)]

    def __call__(self, *, ldap_filter, attributes, base, scope):
        environment = {key: value for key, value in os.environ.items()
                       if not key.startswith('LDAP')}
        environment.update(LC_ALL='C', LDAPTLS_REQCERT='demand', LDAPTLS_REQSAN='demand')
        if self.config.ca_file:
            environment['LDAPTLS_CACERT'] = self.config.ca_file
        command = ['/usr/bin/ldapsearch', '-LLL']
        if self.config.auth == 'gssapi':
            command += ['-Q', '-Y', 'GSSAPI', '-O', 'minssf=56']
        elif self.config.auth == 'starttls':
            command += ['-ZZ']
        command += ['-o', 'nettimeout=10', '-o', 'ldif-wrap=no', '-l', '10', '-z', str(MAX_RESULTS),
                    '-H', self.config.uri, '-b', base, '-s', scope]
        with self._credentials(environment) as (environment, authentication):
            rc, stdout, stderr = self.runner(command + authentication + [ldap_filter, *attributes], environment=environment)
        if rc:
            diagnostic = stderr.lower()
            code = {49: 'ad_authentication_failed', 50: 'ad_permission_denied',
                    81: 'ad_dc_unavailable', 91: 'ad_dc_unavailable',
                    3: 'ad_timeout', 4: 'ad_results_limit'}.get(rc, 'ad_query_failed')
            if 'tls' in diagnostic or 'certificate' in diagnostic:
                code = 'ad_tls_failed'
            elif rc in (81, 91) or "can't contact ldap server" in diagnostic:
                code = 'ad_dc_unavailable'
            elif 'gssapi' in diagnostic or 'kerberos' in diagnostic or 'sasl' in diagnostic:
                code = 'ad_kerberos_failed'
            raise fail(code, 'AD query failed; check controller directory connectivity and authentication')
        if len(stdout.encode('utf-8')) > MAX_BYTES:
            raise fail('ad_results_limit', 'AD response exceeds the size limit')
        return stdout
