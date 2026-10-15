"""Bounded SSH/JSON transport; target, keys and command are administrator-owned."""
from __future__ import annotations

import ipaddress
import json
import os
import re
import stat
import subprocess
import threading
import time
import uuid

from ..config import get_settings

MAX_INPUT = 32768
MAX_OUTPUT = 20 * 1024 * 1024


class WorkstationsTransportError(Exception):
    def __init__(self, code, request_id, *, uncertain=False):
        self.code, self.request_id, self.uncertain = code, request_id, uncertain
        super().__init__('Controller request could not be verified: ' + code)


def run_ssh(command, *, input_data, timeout):
    process = subprocess.Popen(command, stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE, shell=False)
    captured = [b'', b'']
    excessive = []
    def read(index, stream, limit):
        try:
            captured[index] = stream.read(limit + 1)
            if len(captured[index]) > limit:
                excessive.append(True)
                process.kill()
        finally:
            stream.close()
    def write():
        try:
            process.stdin.write(input_data)
        except (BrokenPipeError, OSError):
            pass
        finally:
            process.stdin.close()
    threads = [threading.Thread(target=read, args=(0, process.stdout, MAX_OUTPUT), daemon=True),
               threading.Thread(target=read, args=(1, process.stderr, 65536), daemon=True),
               threading.Thread(target=write, daemon=True)]
    for worker in threads:
        worker.start()
    try:
        process.wait(timeout=timeout)
    except BaseException:
        process.kill()
        process.wait()
        raise
    finally:
        for worker in threads:
            worker.join(timeout=2)
    if excessive or any(worker.is_alive() for worker in threads):
        raise ValueError('Transport response exceeds its bound')
    return process.returncode, captured[0], captured[1]


def _credential(path, *, private):
    for ancestor in path.parents:
        if ancestor.is_symlink():
            raise ValueError
    info = path.lstat()
    if not stat.S_ISREG(info.st_mode) or not 0 < info.st_size <= 65536 or any(c in str(path) for c in '\r\n\x00'):
        raise ValueError
    if os.name != 'nt':
        if info.st_uid not in (0, os.geteuid()) or stat.S_IMODE(info.st_mode) & (0o077 if private else 0o022):
            raise ValueError


class WorkstationsClient:
    def __init__(self, settings=None, *, runner=None, deadline=None):
        self.settings = settings or get_settings()
        self.runner = runner or run_ssh
        self.deadline = deadline

    def with_deadline(self, deadline):
        return type(self)(self.settings, runner=self.runner, deadline=deadline)

    def call(self, operation, parameters, *, request_id, scope='read'):
        uncertain = operation in ('plans.apply', 'jobs.cancel')
        submitted = False
        def error(code):
            return WorkstationsTransportError(code, request_id, uncertain=uncertain and submitted)
        settings = self.settings
        if not settings.workstations_enabled:
            raise error('workstations_not_configured')
        try:
            parsed = uuid.UUID(request_id)
            if str(parsed) != request_id or not parsed.int or scope not in ('read', 'execute'):
                raise ValueError
            host, user = settings.workstations_host, settings.workstations_ssh_user
            if not isinstance(host, str) or not re.fullmatch(r'[a-zA-Z0-9][a-zA-Z0-9.:-]{0,252}', host):
                raise ValueError
            if ':' in host:
                ipaddress.ip_address(host)
            if not isinstance(user, str) or not re.fullmatch(r'[a-z_][a-z0-9_-]{0,31}', user):
                raise ValueError
            if not isinstance(operation, str) or not re.fullmatch(r'[a-z][a-z_.]{0,63}', operation) or not isinstance(parameters, dict):
                raise ValueError
            key = settings.workstations_read_key if scope == 'read' else settings.workstations_execute_key
            known = settings.workstations_known_hosts
            _credential(key, private=True)
            _credential(known, private=False)
            raw = json.dumps({'schema_version': 1, 'request_id': request_id, 'operation': operation, 'parameters': parameters},
                             ensure_ascii=True, allow_nan=False).encode('utf-8')
            if len(raw) > MAX_INPUT:
                raise ValueError
        except (ValueError, TypeError, AttributeError, OSError, RecursionError):
            raise error('workstations_configuration_invalid') from None
        command = ['ssh', '-T', '-F', '/dev/null', '-o', 'BatchMode=yes', '-o', 'StrictHostKeyChecking=yes',
                   '-o', 'UserKnownHostsFile=' + str(known), '-o', 'GlobalKnownHostsFile=/dev/null',
                   '-o', 'IdentityFile=' + str(key), '-o', 'IdentitiesOnly=yes', '-o', 'ConnectTimeout=5',
                   '-o', 'ServerAliveInterval=5', '-o', 'ServerAliveCountMax=2', '-o', 'PasswordAuthentication=no',
                   '-o', 'KbdInteractiveAuthentication=no', '-o', 'ClearAllForwardings=yes', '-o', 'ForwardAgent=no',
                   '-o', 'PermitLocalCommand=no', '-o', 'ProxyCommand=none', '-l', user, '--', host, 'gateway']
        timeout = (310 if operation in ('plans.create', 'component_plans.create', 'jobs.verify') else
                   130 if operation == 'directory.snapshot' else 30 if operation in ('directory.search', 'plans.apply', 'jobs.cancel') else 15)
        if self.deadline is not None:
            timeout = min(timeout, self.deadline - time.monotonic())
            if timeout <= 0:
                raise error('workstations_transport_timeout')
        try:
            submitted = True
            rc, output, diagnostic = self.runner(command, input_data=raw, timeout=timeout)
        except subprocess.TimeoutExpired:
            raise error('workstations_transport_timeout') from None
        except (OSError, ValueError):
            raise error('workstations_transport_unavailable') from None
        try:
            if not isinstance(output, bytes) or len(output) > MAX_OUTPUT:
                raise ValueError
            def unique(pairs):
                result = {}
                for name, value in pairs:
                    if name in result:
                        raise ValueError
                    result[name] = value
                return result
            response = json.loads(output, object_pairs_hook=unique,
                                  parse_constant=lambda value: (_ for _ in ()).throw(ValueError()))
            if (not isinstance(response, dict) or set(response) != {'schema_version', 'request_id', 'status', 'data', 'error_code'}
                    or type(response['schema_version']) is not int or response['schema_version'] != 1
                    or response['request_id'] != request_id or response['status'] not in ('ok', 'error')):
                raise ValueError
            if response['status'] == 'error':
                code = response['error_code']
                if not isinstance(code, str) or not re.fullmatch(r'(?:ad|setup|component|workstations|directory)_[a-z0-9_]{1,90}', code):
                    raise ValueError
                raise error(code)
            if rc != 0 or response['error_code'] is not None or not isinstance(response['data'], dict):
                raise ValueError
            return response['data']
        except (ValueError, UnicodeError, RecursionError):
            code = ('workstations_host_key_rejected' if isinstance(diagnostic, bytes) and
                    (b'Host key verification failed' in diagnostic or b'REMOTE HOST IDENTIFICATION HAS CHANGED' in diagnostic)
                    else 'workstations_response_invalid')
            raise error(code) from None
