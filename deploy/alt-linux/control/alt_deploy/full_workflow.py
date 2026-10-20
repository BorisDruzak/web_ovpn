"""Versioned, registry-derived complete workstation plan and fixed phase policy."""
import copy

from .ad_directory import fail
from .final_dns_policy import validate
from .krfb_runtime import DIRECT_POLICY
from .setup_plans import digest


PROFILE='workstation-full-v1'
MARKER='complete_workstation_v1'
BUDGETS={'system':21600,'user':5400,'final_dns':300}


def is_full_profile(profile):
    return (isinstance(profile,dict) and profile.get('id')==PROFILE
            and profile.get('workflow')==MARKER and type(profile.get('version')) is int and profile['version']==1)


def build_workflow_plan(catalog,policy):
    try:
        if not isinstance(policy,dict) or set(policy)!={'servers'}:raise ValueError
        bound_policy={'final_dns':validate(policy['servers']),'vnc':copy.deepcopy(DIRECT_POLICY)}
        profile=catalog.profile(PROFILE)
        if not is_full_profile(profile) or profile['optional_components']:raise ValueError
        ordered=catalog.ordered(profile['components'],os_id='alt-kworkstation-11')
        if {c['id'] for c in ordered}!={c['id'] for c in catalog.components()}:raise ValueError
        phases={key:[] for key in BUDGETS};membership={}
        for component in ordered:
            identifier=component['id'];recipe=component['verification']['recipe']
            phase=('final_dns' if recipe=='final_dns' else 'user' if component['execution']['requires_user_home'] else 'system')
            if phase!='system' and 'adapter' in component['execution']:raise ValueError
            phases[phase].append(identifier);membership[identifier]=phase
        if (len(phases['final_dns'])!=1 or not phases['user'] or not phases['system']
                or catalog.component(phases['system'][0])['verification']['recipe']!='vnc_policy'):
            raise ValueError
        priority={key:index for index,key in enumerate(BUDGETS)}
        for component in ordered:
            if any(priority[membership[dependency]]>priority[membership[component['id']]] for dependency in component['dependencies']):
                raise ValueError
        return {'schema_version':1,'kind':'complete_workstation','profile_id':PROFILE,'policy':bound_policy,
                'policy_sha256':digest(bound_policy),'phases':[{'id':key,'component_ids':value,'budget_seconds':BUDGETS[key]}
                for key,value in phases.items()]}
    except Exception:raise fail('full_workflow_plan_invalid','The complete workstation policy or registry partition is invalid') from None


def validate_workflow_plan(workflow,catalog):
    try:
        if (not isinstance(workflow,dict) or type(workflow.get('schema_version')) is not int
                or workflow['schema_version']!=1):raise ValueError
        expected=build_workflow_plan(catalog,workflow['policy']['final_dns'])
        if workflow!=expected:raise ValueError
        return copy.deepcopy(expected)
    except Exception:raise fail('full_workflow_plan_invalid','The complete workstation plan changed or is invalid') from None


def equivalent_payload(current,confirmed):
    """Delegated creation does not consume quota; counts remain audit facts.

    Only a validated quota-inapplicable admission in the new workflow may
    differ in these three counters. Every actual identity and right stays bound.
    Legacy comparisons retain their exact previous contract.
    """
    if current==confirmed:return True
    try:
        if (not isinstance(current.get('workflow'),dict) or current['workflow']!=confirmed.get('workflow')
                or current['workflow'].get('kind')!='complete_workstation'):return False
        from .ad_join_preflight import validate_evidence
        left=copy.deepcopy(current);right=copy.deepcopy(confirmed)
        for value in (left,right):
            admission=validate_evidence(value['ad_join_admission'])
            for field in ('domain_quota','created_computers','quota_remaining'):admission.pop(field)
        return left==right
    except Exception:return False


def native_system_context(settings,request,workflow):
    """Only the original worker and its real flock may enter the adapter."""
    try:
        from pathlib import Path
        from .component_catalog import ComponentCatalog
        from .setup_jobs import current_setup_job,SetupJobRepository
        from .setup_worker import process_identity
        from .setup_runtime import source_fingerprint
        from .setup_plans import private_read
        from .locks import assert_owned
        from .vault import VaultHealthChecker
        assert_owned(settings.lock_file)
        catalog=ComponentCatalog.load(settings.ansible_project_dir)
        checked=validate_workflow_plan(workflow,catalog)
        job=current_setup_job(settings)
        if (job is None or job.state!='running' or job.status['claimed'] is not True
                or job.status['stage']!='full_setup.apply' or job.request['operation']!='full_setup'
                or job.status['process_identity']!=process_identity(settings)):raise ValueError
        plan=job.request['plan'];payload=plan['payload']
        if (request.software_profile!=PROFILE or request.remote_access_profile!='krfb'
                or request.machine_uuid!=job.machine_uuid or request.to_dict()!=payload['request']
                or payload.get('workflow')!=checked or payload['catalog_sha256']!=catalog.fingerprint
                or payload['source_sha256']!=source_fingerprint(settings.ansible_project_dir,Path(__file__).parent)
                or VaultHealthChecker(settings).full_workflow_policy()!=checked['policy']['final_dns']):raise ValueError
        jobs=SetupJobRepository(settings);claim=private_read(jobs.claims/(plan['sha256']+'.json'))
        jobs._check_claim(job,claim)
        return {'schema_version':1,'kind':'complete_workstation','phase':'system','job_id':job.job_id,
            'claim_sha256':digest(claim),'plan_sha256':plan['sha256'],'machine_uuid':job.machine_uuid,
            'source_sha256':payload['source_sha256'],'workflow_policy_sha256':checked['policy_sha256'],
            'policy_sha256':digest(checked['policy']['vnc'])}
    except Exception:raise fail('full_workflow_context_required','The original native system claim, source, policy and lifecycle ownership are required') from None


def deferred_system_result(workflow):
    return {'schema_version':1,'status':'deferred','user':list(workflow['phases'][1]['component_ids']),
            'final_dns':list(workflow['phases'][2]['component_ids'])}


def validate_system_result(result,workflow):
    marker=result.get('components',{}).get('workflow_deferred') if isinstance(result,dict) else None
    if (not isinstance(marker,dict) or type(marker.get('schema_version')) is not int
            or result.get('status')!='successful' or marker!=deferred_system_result(workflow)):
        raise ValueError('The complete system result must retain its original deferred phases')
