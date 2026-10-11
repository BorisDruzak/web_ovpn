"""Operator AD/Setup CLI; existing command implementations stay unchanged."""
from __future__ import annotations

import json

from .ad_directory import ADDirectory
from .ad_transport import DirectoryConfig, LDAPTransport
from .setup import SetupService


def add_parsers(commands):
    ad = commands.add_parser('ad', allow_abbrev=False, help='Read existing AD users, OUs and computer objects')
    areas = ad.add_subparsers(dest='ad_area', required=True)
    users = areas.add_parser('users', allow_abbrev=False)
    user_commands = users.add_subparsers(dest='ad_action', required=True)
    for name in ('search', 'show'):
        command = user_commands.add_parser(name, allow_abbrev=False, help='Exact sAMAccountName or domain UPN lookup')
        command.add_argument('--login', required=True)
    ous = areas.add_parser('ous', allow_abbrev=False)
    ous.add_subparsers(dest='ad_action', required=True).add_parser('list', help='List directory OUs; listing does not approve an OU')
    computers = areas.add_parser('computers', allow_abbrev=False)
    check = computers.add_subparsers(dest='ad_action', required=True).add_parser('check', allow_abbrev=False)
    check.add_argument('--hostname', required=True)

    setup = commands.add_parser('setup', allow_abbrev=False, help='Plan, confirm and verify existing-employee workstation setup')
    actions = setup.add_subparsers(dest='setup_action', required=True)
    plan = actions.add_parser('plan', allow_abbrev=False, help='Read-only AD/SSH inspection and protected 30-minute plan')
    plan.add_argument('--machine', required=True, help='Registered UUID or unique hostname; IP is not an identifier')
    plan.add_argument('--user', required=True, help='Existing employee sAMAccountName or sosnadmin.local UPN')
    plan.add_argument('--computer-ou', required=True, help='Exact existing OU from the controller approved_ous list')
    plan.add_argument('--software-profile', choices=('base', 'core-apps'), default='core-apps')
    plan.add_argument('--remote-access-profile', choices=('none', 'krfb'), default='none', help='KRFB requires separate TCP 5900 restriction confirmation')
    apply = actions.add_parser('apply', allow_abbrev=False, help='Revalidate and execute only the exact SHA-confirmed plan')
    apply.add_argument('plan_id')
    apply.add_argument('--confirm-sha256', required=True)
    status = actions.add_parser('status', allow_abbrev=False, help='Read protected run result; does not retry a failed run')
    status.add_argument('run_id')
    verify = actions.add_parser('verify', allow_abbrev=False, help='Read current AD/SSH state for the recorded domain assignment')
    verify.add_argument('--machine', required=True)


def directory_for_settings(settings):
    return ADDirectory(LDAPTransport(DirectoryConfig.load(), settings=settings))


def handle(parsed, settings):
    if parsed.command == 'ad':
        directory = directory_for_settings(settings)
        if parsed.ad_area == 'users':
            user = directory.user(parsed.login, require_usable=False)
            return {'status': 'ok', 'users': [user]} if parsed.ad_action == 'search' else {'status': 'ok', 'user': user}
        if parsed.ad_area == 'ous':
            ous = directory.ous()
            return {'status': 'ok', 'ous': ous, 'count': len(ous)}
        return dict(directory.computer(parsed.hostname), status='ok')
    if parsed.setup_action == 'status':
        from .setup import RUN_RE
        from .ad_directory import fail
        from .setup_plans import private_read
        if not RUN_RE.fullmatch(parsed.run_id):
            raise fail('setup_run_invalid', 'Setup run identifier is invalid')
        return private_read(settings.state_root / 'setup-runs' / (parsed.run_id + '.json'))
    service = SetupService(settings)
    if parsed.setup_action == 'plan':
        return service.plan(parsed.machine, parsed.user, parsed.computer_ou, parsed.software_profile, parsed.remote_access_profile)
    if parsed.setup_action == 'apply':
        return service.apply(parsed.plan_id, parsed.confirm_sha256)
    return service.verify(parsed.machine)


def write_text(stream, payload):
    if 'plan_id' in payload and 'payload' in payload:
        content = payload['payload']
        machine, user = content['machine'], content['user']
        stream.write(f"Plan: {payload['plan_id']}\nSHA-256: {payload['sha256']}\nExpires: {payload['expires_at']}\n")
        stream.write(f"Machine: {machine['uuid']} / {machine['hostname']} / {machine['ip']}\n")
        stream.write(f"Employee: {user['login']} / GUID {user['object_guid']}\nComputer OU: {content['computer_ou']}\n")
        stream.write(f"Profiles: {content['request']['software_profile']} / {content['request']['remote_access_profile']}\n")
        for label, key in [('Changes', 'changes'), ('Warnings', 'warnings'), ('Deferred', 'deferred_actions')]:
            stream.write(label + ': ' + ', '.join(content[key]) + '\n')
        stream.write(f"Apply after reviewing: workstationctl setup apply {payload['plan_id']} --confirm-sha256 {payload['sha256']}\n")
        return
    stream.write('Status: ' + str(payload.get('status', 'ok')) + '\n')
    for key, value in payload.items():
        if key == 'status':
            continue
        if isinstance(value, list):
            stream.write(key + ':\n')
            for item in value:
                stream.write('  ' + json.dumps(item, ensure_ascii=False, sort_keys=True) + '\n')
        else:
            stream.write(key + ': ' + (json.dumps(value, ensure_ascii=False, sort_keys=True) if isinstance(value, dict) else str(value)) + '\n')
