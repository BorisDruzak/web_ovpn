"""Controller admission uses the join identity and the same fixed target reader."""
from __future__ import annotations

from dataclasses import replace
import json
import os
import re
import stat
import sys
import uuid

from .ad_directory import fail
from .ad_transport import DirectoryConfig, LDAPTransport, bounded_run

CODES = frozenset('ad_join_' + value for value in (
    'request_invalid', 'kerberos_failed', 'principal_unproven', 'principal_changed',
    'directory_mismatch', 'principal_unusable', 'ou_changed', 'results_incomplete',
    'authentication_failed', 'read_denied', 'dc_unavailable', 'query_failed',
    'quota_exhausted', 'create_rights_unproven', 'evidence_invalid', 'timeout'))
FIELDS = {'schema_version', 'dc', 'join_principal_guid', 'join_principal_sid', 'ou_guid',
          'domain_quota', 'created_computers', 'quota_remaining', 'quota_applicable', 'creation_mode'}


def validate_evidence(value):
    try:
        if not isinstance(value, dict) or set(value) != FIELDS:
            raise ValueError
        if type(value['schema_version']) is not int or value['schema_version'] != 1:
            raise ValueError
        if value['creation_mode'] != 'delegated' or value['quota_applicable'] is not False:
            raise ValueError
        for name, maximum in [('domain_quota', 2147483647), ('created_computers', 4096),
                              ('quota_remaining', 2147483647)]:
            if type(value[name]) is not int or not 0 <= value[name] <= maximum:
                raise ValueError
        if value['quota_remaining'] != max(0, value['domain_quota']-value['created_computers']):
            raise ValueError
        for name in ('join_principal_guid', 'ou_guid'):
            if not isinstance(value[name], str) or str(uuid.UUID(value[name])) != value[name] or not uuid.UUID(value[name]).int:
                raise ValueError
        if (not isinstance(value['dc'], str) or
                not re.fullmatch(r'[a-z0-9.-]+\.sosnadmin\.local', value['dc']) or
                not re.fullmatch(r'S-1-[0-9]+(?:-[0-9]+){1,15}', value['join_principal_sid'])):
            raise ValueError
        return value
    except (ValueError, TypeError, KeyError, AttributeError):
        raise fail('ad_join_evidence_invalid', 'AD join admission evidence is invalid') from None


class ADJoinPreflight:
    def __init__(self, settings, *, transport=None, runner=None):
        self.settings = settings
        if transport is None:
            config = replace(DirectoryConfig.load(), credential_source='join-vault',
                             auth='gssapi', ca_file=None)
            transport = LDAPTransport(config, settings=settings)
        self.transport = transport
        self.runner = runner or bounded_run

    def observe(self, request):
        helper = self.settings.ansible_project_dir / 'roles/domain_join/files/first_join_preflight.py'
        try:
            info = helper.lstat()
            if (not stat.S_ISREG(info.st_mode) or info.st_uid not in (0, os.getuid())
                    or info.st_mode & 0o022):
                raise ValueError
        except (OSError, ValueError):
            raise fail('ad_join_helper_unavailable', 'The fixed AD admission helper is unavailable') from None
        if self.transport.config.credential_source != 'join-vault':
            raise fail('ad_join_principal_unproven', 'AD admission requires the actual join identity')
        environment = {k: v for k, v in os.environ.items() if not k.startswith('LDAP')}
        environment.update(LC_ALL='C', LDAPTLS_REQCERT='demand')
        with self.transport._credentials(environment) as (environment, _):
            rc, raw, _ = self.runner([sys.executable, '-I', '-B', str(helper),
                self.transport.config.uri, request.computer_ou, ''],
                environment=environment, timeout=100, max_bytes=32768)
        try:
            if not isinstance(raw, str) or len(raw.encode()) > 32768:
                raise ValueError
            def pairs(items):
                result = {}
                for key, value in items:
                    if key in result:
                        raise ValueError
                    result[key] = value
                return result
            document = json.loads(raw, object_pairs_hook=pairs)
            if rc:
                if set(document) == {'status', 'code'} and document['status'] == 'blocked' and document['code'] in CODES:
                    raise fail(document['code'], 'AD creation admission blocked before workstation mutation')
                raise ValueError
            if set(document) != {'status', 'evidence'} or document['status'] != 'ready':
                raise ValueError
            return validate_evidence(document['evidence'])
        except (ValueError, TypeError, KeyError):
            raise fail('ad_join_evidence_invalid', 'AD join admission returned invalid evidence') from None
