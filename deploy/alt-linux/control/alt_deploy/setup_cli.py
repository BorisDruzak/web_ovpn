"""Operator AD/Setup CLI; existing command implementations stay unchanged."""
from __future__ import annotations

import json

from .ad_directory import ADDirectory
from .ad_transport import DirectoryConfig, LDAPTransport
from .setup import SetupService
from .setup_recovery_planning import RecoveryPlanningService
from .setup_recovery_startup_inventory import RecoveryStartupInventoryService
from .setup_recovery_policy_baseline_runtime import RecoveryPolicyBaselineService
from .setup_recovery_policy_effects_runtime import RecoveryPolicyEffectsService
from .setup_recovery_operator import RecoveryOperatorService
from .setup_recovery_continuation import RecoveryContinuationService


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
    recovery = actions.add_parser('recovery', allow_abbrev=False, help='Exact reviewed recovery plans, one confirmed attempt and fresh Setup continuation')
    recovery_actions = recovery.add_subparsers(dest='recovery_action', required=True)
    recovery_plan = recovery_actions.add_parser('plan', allow_abbrev=False, help='Read current identities and preserve a non-executable recovery plan')
    recovery_plan.add_argument('--failed-run', required=True, help='Original initial failed Setup run; machine/user/OU come from its protected history')
    recovery_plan.add_argument('--computer-guid', required=True, help='Exact existing computer GUID to inspect; listing or planning does not approve a reset')
    inventory = recovery_actions.add_parser('startup-inventory', allow_abbrev=False,
        help='Read-only service graph evidence for later review; no reservation or execution permission')
    inventory.add_argument('--failed-run', required=True)
    inventory.add_argument('--computer-guid', required=True)
    baseline = recovery_actions.add_parser('policy-baseline', allow_abbrev=False,
        help='Read original configured SSSD policy into a non-executable baseline plan; no reservation')
    baseline.add_argument('--failed-run', required=True)
    baseline.add_argument('--computer-guid', required=True)
    effects = recovery_actions.add_parser('policy-effects', allow_abbrev=False,
        help='Read original operative options and dependency inventory into a non-executable review plan')
    effects.add_argument('--failed-run', required=True)
    effects.add_argument('--computer-guid', required=True)
    for name in ('execution-plan','continue-plan','status'):
        command=recovery_actions.add_parser(name,allow_abbrev=False,
            help='Fresh exact recovery execution envelope' if name=='execution-plan' else 'Fresh normal Setup plan after verified recovery' if name=='continue-plan' else 'Read retained recovery phase; never resume')
        command.add_argument('--failed-run',required=True)
        command.add_argument('--computer-guid',required=True)
    recovery_apply=recovery_actions.add_parser('apply',allow_abbrev=False,help='One exact SHA-confirmed operator recovery; no retry or automatic Setup apply')
    recovery_apply.add_argument('plan_id')
    recovery_apply.add_argument('--confirm-sha256',required=True)


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
    if parsed.setup_action == 'recovery':
        if parsed.recovery_action in ('execution-plan','apply','continue-plan','status'):
            operator=RecoveryOperatorService(settings)
            if parsed.recovery_action=='execution-plan':return operator.plan(parsed.failed_run,parsed.computer_guid)
            if parsed.recovery_action=='apply':return operator.apply(parsed.plan_id,parsed.confirm_sha256)
            if parsed.recovery_action=='status':return operator.status(parsed.failed_run,parsed.computer_guid)
            return RecoveryContinuationService(settings,terminal_verifier=operator._verify_terminal_locked).plan(parsed.failed_run,parsed.computer_guid)
        if parsed.recovery_action == 'policy-effects':
            return RecoveryPolicyEffectsService(RecoveryPlanningService(settings)).plan(parsed.failed_run, parsed.computer_guid)
        if parsed.recovery_action == 'policy-baseline':
            return RecoveryPolicyBaselineService(RecoveryPlanningService(settings)).plan(parsed.failed_run, parsed.computer_guid)
        if parsed.recovery_action == 'startup-inventory':
            return RecoveryStartupInventoryService(RecoveryPlanningService(settings)).plan(parsed.failed_run, parsed.computer_guid)
        return RecoveryPlanningService(settings).plan(parsed.failed_run, parsed.computer_guid)
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
        plan=service.plans.load(parsed.plan_id,parsed.confirm_sha256)
        if 'recovery_resolution' in plan['payload']:
            service.recovery_resolutions.verifier=RecoveryOperatorService(settings)._verify_terminal_locked
        return service.apply(parsed.plan_id, parsed.confirm_sha256)
    return service.verify(parsed.machine)


def write_text(stream, payload):
    if 'plan_id' in payload and 'payload' in payload:
        content = payload['payload']
        if payload['plan_id'].startswith('recovery-operator-'):
            stream.write(f"Recovery operator plan: {payload['plan_id']}\nSHA-256: {payload['sha256']}\nExpires: {payload['expires_at']}\n")
            stream.write(f"Machine: {content['machine']['uuid']} / {content['machine']['hostname']}\nOriginal failed run: {content['failed_run_id']}\n")
            stream.write(f"Computer GUID: {content['computer_guid']}\nComputer SID: {content['computer_sid']}\nComputer OU: {content['computer_ou']}\nEmployee: {content['employee']['login']}\n")
            stream.write('Manual machine password writes: 1. Identity/OU preserved. Ordinary SSSD policy may update AD attributes, Samba credentials and DNS RRsets.\n')
            stream.write('Any observed renewal or unknown outcome stops with UNKNOWN; no replay or automatic rollback. Original failed history is retained.\n')
            for name in ('recovery','startup','terminal'):stream.write(name+' SHA-256: '+content[name]['sha256']+'\n')
            stream.write(f"Apply only after explicit approval: workstationctl setup recovery apply {payload['plan_id']} --confirm-sha256 {payload['sha256']}\n")
            return
        if payload['plan_id'].startswith('recovery-policy-effects-'):
            stream.write(f"Original policy effect inventory plan: {payload['plan_id']}\nSHA-256: {payload['sha256']}\nExpires: {payload['expires_at']}\n")
            stream.write(f"Machine: {content['machine']['uuid']} / {content['machine']['hostname']}\nOriginal failed run: {content['failed_run_id']}\n")
            stream.write(f"Effect inventory SHA-256: {content['effect_inventory_sha256']}\nUnreviewed configured keys: {content['unreviewed_key_count']}\n")
            stream.write('Execution available: false\nDefaults reviewed: false\nEffects reviewed: false\n')
            stream.write('Required review: ' + ', '.join(content['review_requirements']) + '\n')
            return
        if payload['plan_id'].startswith('recovery-policy-baseline-'):
            stream.write(f"Original policy baseline plan: {payload['plan_id']}\nSHA-256: {payload['sha256']}\nExpires: {payload['expires_at']}\n")
            stream.write(f"Machine: {content['machine']['uuid']} / {content['machine']['hostname']}\nOriginal failed run: {content['failed_run_id']}\n")
            stream.write(f"Original configuration SHA-256: {content['projection']['original_sha256']}\nParser/tool SHA-256: {content['projection']['tools_sha256']}\n")
            stream.write('Execution available: false\nDefaults verified: false\n')
            stream.write('Required review: ' + ', '.join(content['review_requirements']) + '\n')
            return
        if payload['plan_id'].startswith('recovery-inventory-'):
            stream.write(f"Startup inventory plan: {payload['plan_id']}\nSHA-256: {payload['sha256']}\nExpires: {payload['expires_at']}\n")
            stream.write(f"Machine: {content['machine']['uuid']} / {content['machine']['hostname']}\n")
            stream.write(f"Inventory SHA-256: {content['inventory']['sha256']}\nUnits: {content['unit_count']} / Possible jobs: {content['possible_job_count']}\n")
            stream.write('Execution available: false\nInventory requires effects review before a separate execution plan.\n')
            return
        if payload['plan_id'].startswith('recovery-'):
            stream.write(f"Recovery plan: {payload['plan_id']}\nSHA-256: {payload['sha256']}\nExpires: {payload['expires_at']}\n")
            machine = content['machine']
            stream.write(f"Original failed run: {content['failed_run_id']}\nMachine: {machine['uuid']} / {machine['hostname']}\n")
            stream.write(f"Computer GUID: {content['computer_guid']}\nComputer SID: {content['computer_sid']}\nComputer OU: {content['computer_ou']}\n")
            stream.write(f"Proposed operation: {content['operation']}\nExecution available: false\n")
            stream.write('Required gates: ' + ', '.join(content['required_gates']) + '\n')
            stream.write('Warnings: ' + ', '.join(content['warnings']) + '\n')
            return
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
