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
from .setup_recovery_operator import RecoveryOperatorService,operator_for_plan,operator_for_execution_plan
from .setup_recovery_attempt_context import with_context
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
    for area, identifier in (('components', 'component_id'), ('profiles', 'profile_id')):
        parser = actions.add_parser(area, allow_abbrev=False, help='Inspect the published catalog without contacting AD')
        sub = parser.add_subparsers(dest='catalog_action', required=True)
        sub.add_parser('list', allow_abbrev=False)
        show = sub.add_parser('show', allow_abbrev=False)
        show.add_argument(identifier)
    component = actions.add_parser('component', allow_abbrev=False, help='Guarded individual component lifecycle')
    sub = component.add_subparsers(dest='component_action', required=True)
    for name in ('plan', 'verify'):
        command = sub.add_parser(name, allow_abbrev=False)
        command.add_argument('--machine', required=True)
        command.add_argument('--component', required=True)
        if name == 'plan':
            command.add_argument('--after-job', help='Review one unknown idempotent component using a new confirmed plan')
    component_apply = sub.add_parser('apply', allow_abbrev=False)
    component_apply.add_argument('plan_id')
    component_apply.add_argument('--confirm-sha256', required=True)
    acceptance = sub.add_parser('accept', allow_abbrev=False, help='Record an explicitly completed real user workflow against a fresh noop plan')
    acceptance.add_argument('plan_id')
    acceptance.add_argument('--confirm-sha256', required=True)
    acceptance.add_argument('--confirm-functional', action='store_true', required=True)
    plan = actions.add_parser('plan', allow_abbrev=False, help='Read-only AD/SSH inspection and protected 30-minute plan')
    plan.add_argument('--machine', required=True, help='Registered UUID or unique hostname; IP is not an identifier')
    plan.add_argument('--user', required=True, help='Existing employee sAMAccountName or sosnadmin.local UPN')
    plan.add_argument('--computer-ou', required=True, help='Exact existing OU from the controller approved_ous list')
    plan.add_argument('--software-profile', default='core-apps', help='Published catalog profile ID')
    plan.add_argument('--remote-access-profile', choices=('none', 'krfb'), default='none', help='KRFB requires separate TCP 5900 restriction confirmation')
    apply = actions.add_parser('apply', allow_abbrev=False, help='Revalidate and execute only the exact SHA-confirmed plan')
    apply.add_argument('plan_id')
    apply.add_argument('--confirm-sha256', required=True)
    apply.add_argument('--detach', action='store_true', help='Return durable job_id; the systemd worker performs Setup')
    jobs = actions.add_parser('jobs', allow_abbrev=False, help='Read durable Setup jobs and safe events')
    job_commands = jobs.add_subparsers(dest='setup_job_action', required=True)
    job_list = job_commands.add_parser('list', allow_abbrev=False)
    job_list.add_argument('--machine', help='Registered machine UUID')
    job_list.add_argument('--offset', type=int, default=0)
    job_list.add_argument('--limit', type=int, default=100)
    maintenance_plan = job_commands.add_parser('maintenance-plan', allow_abbrev=False,
        help='Read-only controller maintenance proof; UNKNOWN and target gates remain unchanged')
    maintenance_scope = maintenance_plan.add_mutually_exclusive_group(required=True)
    maintenance_scope.add_argument('job_id', nargs='?')
    maintenance_scope.add_argument('--all-closed', action='store_true')
    maintenance_confirm = job_commands.add_parser('maintenance-confirm', allow_abbrev=False)
    maintenance_confirm.add_argument('plan_id')
    maintenance_confirm.add_argument('--confirm-sha256', required=True)
    cancel = job_commands.add_parser('cancel', allow_abbrev=False, help='Cancel only an unclaimed queued job, preserving its used plan')
    cancel.add_argument('job_id')
    cancel.add_argument('--confirm-plan-sha256', required=True)
    queue_plan = job_commands.add_parser('queue-review-plan', allow_abbrev=False, help='Review one queued different machine after a closed full UNKNOWN')
    queue_plan.add_argument('job_id')
    queue_plan.add_argument('--candidate', required=True)
    queue_confirm = job_commands.add_parser('queue-review-confirm', allow_abbrev=False)
    queue_confirm.add_argument('plan_id')
    queue_confirm.add_argument('--confirm-sha256', required=True)
    for name in ('status', 'events', 'verify-continuation'):
        command = job_commands.add_parser(name, allow_abbrev=False)
        command.add_argument('job_id')
        if name == 'events':
            command.add_argument('--after', type=int, default=0)
            command.add_argument('--limit', type=int, default=100)
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
        if name in ('continue-plan','status'):
            command.add_argument('--operator-plan',help='Explicit protected successor operator plan; omitted selects legacy retained attempt')
    successor=recovery_actions.add_parser('successor-plan',allow_abbrev=False,help='One additive prewrite successor after complete closed-backup-failure admission')
    successor.add_argument('--failed-run',required=True)
    successor.add_argument('--computer-guid',required=True)
    successor.add_argument('--predecessor-sha256',required=True)
    corrective=recovery_actions.add_parser('rehearsal-failure-plan',allow_abbrev=False,help='One separate corrective plan after an exact closed locale-rehearsal failure; never replay')
    corrective.add_argument('--predecessor-operator',required=True)
    corrective.add_argument('--predecessor-sha256',required=True)
    recovery_apply=recovery_actions.add_parser('apply',allow_abbrev=False,help='One exact SHA-confirmed operator recovery; no retry or automatic Setup apply')
    recovery_apply.add_argument('plan_id')
    recovery_apply.add_argument('--confirm-sha256',required=True)


def directory_for_settings(settings):
    return ADDirectory(LDAPTransport(DirectoryConfig.load(), settings=settings))


def handle(parsed, settings):
    if parsed.command == 'setup' and parsed.setup_action == 'jobs':
        if parsed.setup_job_action in ('queue-review-plan', 'queue-review-confirm'):
            from .setup_maintenance_review_bridge import queue_review_service
            review = queue_review_service(settings)
            return (review.plan(parsed.job_id, parsed.candidate) if parsed.setup_job_action == 'queue-review-plan'
                    else review.confirm(parsed.plan_id, parsed.confirm_sha256))
        if parsed.setup_job_action in ('maintenance-plan', 'maintenance-confirm'):
            from .setup_maintenance_review_bridge import review_service
            review = review_service(settings)
            return ((review.plan_all_closed() if parsed.all_closed else review.plan(parsed.job_id)) if parsed.setup_job_action == 'maintenance-plan'
                    else review.confirm(parsed.plan_id, parsed.confirm_sha256))
        from .setup_jobs_view import SetupJobsService
        service = SetupJobsService(settings)
        if parsed.setup_job_action == 'cancel':
            return service.cancel(parsed.job_id, parsed.confirm_plan_sha256)
        if parsed.setup_job_action == 'list':
            return service.list(parsed.machine, offset=parsed.offset, limit=parsed.limit)
        if parsed.setup_job_action == 'events':
            return service.events_for(parsed.job_id, after=parsed.after, limit=parsed.limit)
        if parsed.setup_job_action == 'verify-continuation':
            return service.verify_continuation(parsed.job_id)
        return service.status(parsed.job_id)
    if parsed.command == 'setup' and parsed.setup_action in ('components', 'profiles'):
        from .component_catalog import ComponentCatalog
        catalog = ComponentCatalog.load(settings.ansible_project_dir)
        area = parsed.setup_action
        result = {'schema_version': 2, 'operation': area+'_'+parsed.catalog_action,
                  'catalog_version': catalog.version, 'catalog_sha256': catalog.fingerprint}
        if parsed.catalog_action == 'list':
            result[area] = catalog.components() if area == 'components' else catalog.profiles()
        elif area == 'components':
            result['component'] = catalog.component(parsed.component_id)
        else:
            result['profile'] = catalog.profile(parsed.profile_id)
        return result
    if parsed.command == 'setup' and parsed.setup_action == 'component':
        from .component_setup import ComponentSetupService
        service = ComponentSetupService(settings)
        if parsed.component_action == 'accept':
            return service.accept(parsed.plan_id, parsed.confirm_sha256, confirmed=parsed.confirm_functional)
        if parsed.component_action == 'apply':
            return service.apply(parsed.plan_id, parsed.confirm_sha256)
        if parsed.component_action == 'plan' and parsed.after_job:
            return service.plan(parsed.machine, parsed.component, after_job=parsed.after_job)
        return getattr(service, parsed.component_action)(parsed.machine, parsed.component)
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
        if parsed.recovery_action=='rehearsal-failure-plan':
            from .setup_recovery_rehearsal_admission import RecoveryRehearsalAdmissionService
            reference=RecoveryRehearsalAdmissionService(settings).prepare(parsed.predecessor_operator,parsed.predecessor_sha256)
            operator=RecoveryOperatorService(with_context(settings,reference))
            return operator.plan(reference['failed_run_id'],reference['computer_guid'])
        if parsed.recovery_action=='successor-plan':
            from .setup_recovery_successor import RecoverySuccessorService
            reference=RecoverySuccessorService(settings).prepare(parsed.failed_run,parsed.computer_guid,parsed.predecessor_sha256)
            return RecoveryOperatorService(with_context(settings,reference)).plan(parsed.failed_run,parsed.computer_guid)
        if parsed.recovery_action in ('execution-plan','apply','continue-plan','status'):
            if parsed.recovery_action=='apply':operator=operator_for_plan(settings,parsed.plan_id,parsed.confirm_sha256)
            elif getattr(parsed,'operator_plan',None):
                operator=operator_for_plan(settings,parsed.operator_plan,expected_pair=dict(failed_run_id=parsed.failed_run,computer_guid=parsed.computer_guid),archival=parsed.recovery_action=='status')
            else:operator=RecoveryOperatorService(settings)
            if parsed.recovery_action=='execution-plan':return operator.plan(parsed.failed_run,parsed.computer_guid)
            if parsed.recovery_action=='apply':return operator.apply(parsed.plan_id,parsed.confirm_sha256)
            if parsed.recovery_action=='status':return operator.status(parsed.failed_run,parsed.computer_guid)
            return RecoveryContinuationService(operator.settings,terminal_verifier=operator._verify_terminal_locked).plan(parsed.failed_run,parsed.computer_guid)
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
            reference=plan['payload']['recovery_resolution']
            resolution=service.recovery_resolutions.load(reference['failed_run_id'],reference['computer_guid'])
            terminal=resolution['terminal']
            service.recovery_resolutions.verifier=operator_for_execution_plan(settings,terminal['execution_plan_id'],terminal['execution_plan_sha256'])._verify_terminal_locked
        options = {'detach': True} if parsed.detach else {}
        return service.apply(parsed.plan_id, parsed.confirm_sha256, **options)
    return service.verify(parsed.machine)


def write_text(stream, payload):
    if payload.get('operation') in ('setup_apply', 'component_apply'):
        stream.write('Job: '+payload['job_id']+'\nState: '+payload['state']+'\n')
        stream.write('Inspect: workstationctl setup jobs status '+payload['job_id']+'\n')
        return
    if payload.get('operation') in ('setup_job_status', 'setup_job_continuation'):
        job = payload['job']
        stream.write('Job: '+job['job_id']+'\nState: '+job['state']+'\nStage: '+job['stage']+'\n')
        stream.write('Error code: '+str(job['error_code'])+'\nNext: '+job['recommended_action']+'\n')
        for identifier, component in job['components'].items():
            verification = component['verification'] or {}
            stream.write(identifier+': '+verification.get('status', 'unverified')+'; changed='+str(component['changed'])+'\n')
        return
    if payload.get('operation') == 'component' or (isinstance(payload.get('payload'), dict)
            and payload['payload'].get('operation') == 'component'):
        content = payload.get('payload', payload)
        stream.write('Component plan: '+payload['plan_id']+'\nSHA-256: '+payload['sha256']+'\n')
        stream.write('Component: '+content['component']['id']+'\nAction: '+content['action']+'\n')
        stream.write('Expires: '+payload['expires_at']+'\n')
        return
    if 'plan_id' in payload and 'payload' in payload:
        content = payload['payload']
        if payload['plan_id'].startswith('recovery-operator-'):
            stream.write(f"Recovery operator plan: {payload['plan_id']}\nSHA-256: {payload['sha256']}\nExpires: {payload['expires_at']}\n")
            stream.write(f"Machine: {content['machine']['uuid']} / {content['machine']['hostname']}\nOriginal failed run: {content['failed_run_id']}\n")
            stream.write(f"Computer GUID: {content['computer_guid']}\nComputer SID: {content['computer_sid']}\nComputer OU: {content['computer_ou']}\nEmployee: {content['employee']['login']}\n")
            if 'recovery_attempt_context' in content:
                context=content['recovery_attempt_context']
                stream.write(f"Successor attempt: {context['attempt_id']}\nAdmission SHA-256: {context['admission_sha256']}\nPredecessor remains closed and unchanged.\n")
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
        stream.write('Execution budget (seconds): ' + str(content.get('execution_budget_seconds', 5400)) + '\n')
        if 'prejoin_retry' in content:
            stream.write('Preserved pre-join failed run: ' + content['prejoin_retry']['failed_run_id'] + '\n')
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
