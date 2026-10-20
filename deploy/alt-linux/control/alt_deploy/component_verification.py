"""Compare fresh bounded probe evidence to the published desired state."""
from __future__ import annotations

import json
import re
from datetime import datetime

from .component_catalog import EVR_RE, PACKAGE_RE


def package_health_ready(evidence):
    manager = evidence.get('package_manager', {})
    return isinstance(manager, dict) and all(manager.get(k) is True for k in (
        'processes_absent', 'remote_execution_absent', 'locks_clear', 'database_readable', 'dependencies_healthy'))


def valid_evidence(evidence, *, allow_unresolved=False):
    try:
        if not isinstance(evidence, dict) or set(evidence) != {
            'schema_version', 'observed_at', 'machine', 'user', 'package_manager', 'components'}:
            return False
        if type(evidence['schema_version']) is not int or evidence['schema_version'] != 1:
            return False
        if len(json.dumps(evidence, allow_nan=False)) > 524288:
            return False
        if datetime.fromisoformat(evidence['observed_at']).tzinfo is None:
            return False
        machine = evidence['machine']
        if set(machine) != {'uuid', 'hostname', 'os_id', 'boot_id'}:
            return False
        if not all(isinstance(v, str) for v in machine.values()):
            return False
        if not re.fullmatch('[0-9a-f]{8}(?:-[0-9a-f]{4}){3}-[0-9a-f]{12}', machine['uuid']):
            return False
        if not re.fullmatch('[0-9a-f]{8}(?:-[0-9a-f]{4}){3}-[0-9a-f]{12}', machine['boot_id']):
            return False
        if not re.fullmatch('[a-z][a-z0-9-]{0,62}', machine['hostname']):
            return False
        user = evidence['user']
        if set(user) != {'login', 'uid', 'gid', 'home_exists', 'home_safe'}:
            return False
        if not isinstance(user['login'], str) or not re.fullmatch('[a-z0-9][a-z0-9._-]{0,62}', user['login']):
            return False
        if any(type(user[k]) is not bool for k in ('home_exists', 'home_safe')):
            return False
        unresolved = (allow_unresolved and user['uid'] is None and user['gid'] is None
                      and user['home_exists'] is False and user['home_safe'] is False)
        if not unresolved and any(type(user[k]) is not int or user[k] <= 0 for k in ('uid', 'gid')):
            return False
        if not isinstance(evidence['package_manager'], dict) or not isinstance(evidence['components'], dict):
            return False
        return True
    except (TypeError, ValueError, KeyError, AttributeError):
        return False


def _package_status(artifact, fact):
    packages = fact.get('packages')
    if not isinstance(packages, list) or len(packages) > 64 or type(fact.get('executable')) is not bool:
        return 'unknown'
    observed = {}
    for package in packages:
        if (not isinstance(package, dict) or set(package) != {'name', 'evr', 'architecture', 'epoch'}
                or not isinstance(package['name'], str) or not PACKAGE_RE.fullmatch(package['name'])
                or not isinstance(package['evr'], str) or not EVR_RE.fullmatch(package['evr'])
                or package['architecture'] not in ('x86_64', 'noarch')
                or type(package['epoch']) is not int or package['epoch'] < 0
                or package['name'] in observed):
            return 'unknown'
        observed[package['name']] = package
    if artifact['source'] == 'alt-repository':
        desired = [{'package_name': p} for p in artifact['packages']]
    elif artifact['source'] == 'archive':
        desired = artifact['packages']
    else:
        desired = [artifact]
    if any(p['package_name'] not in observed for p in desired):
        return 'missing'
    for package in desired:
        actual = observed[package['package_name']]
        if 'package_evr' in package and (actual['evr'] != package['package_evr']
                or actual['architecture'] != package['architecture']
                or actual['epoch'] != package.get('package_epoch', 0)):
            return 'drifted'
    return 'compliant' if fact['executable'] else 'drifted'


class VerificationEngine:
    def __init__(self, catalog):
        self.catalog = catalog

    def evaluate(self, evidence: dict, selected: list[str], *, reboot_required=False, original_boot_id=None) -> dict:
        # Resolve selection through the validated complete graph, even if evidence fails.
        ordered = self.catalog.ordered(selected, os_id='alt-kworkstation-11')
        selected_ids = {component['id'] for component in ordered}
        safe = valid_evidence(evidence)
        components = {}
        for component in self.catalog.components():
            identifier = component['id']
            components[identifier] = {'version': component['version'], 'status': 'not_selected'}
        for component in ordered:
            identifier = component['id']
            result = {'version': component['version'], 'status': 'unknown',
                      'installation_status': 'unverified', 'acceptance_status': 'unverified',
                      'operator_action': 'fresh_verification'}
            components[identifier] = result
            if not safe:
                continue
            fact = evidence['components'].get(identifier)
            if (not isinstance(fact, dict) or type(fact.get('schema_version')) is not int
                    or fact.get('schema_version') != 1 or fact.get('error_code') is not None
                    or not isinstance(fact.get('checks'), dict) or not fact['checks']
                    or any(type(value) is not bool for value in fact['checks'].values())):
                continue
            execution = component['execution']
            if evidence['machine']['os_id'] not in component['supported_os']:
                result.update(status='blocked', operator_action='supported_os_required')
                continue
            if execution['requires_domain'] and not evidence['user']['home_safe']:
                result.update(status='blocked', operator_action='review_user_identity')
                continue
            if (execution['requires_user_home'] or fact.get('deferred') is True) and not evidence['user']['home_exists']:
                result.update(status='blocked', operator_action='first_domain_login')
                continue
            if any(components[d]['status'] != 'compliant' for d in component['dependencies']):
                result.update(status='blocked', operator_action='verify_dependencies')
                continue
            if component['verification']['recipe'] == 'final_dns':
                try:
                    import hashlib
                    from types import SimpleNamespace
                    from .final_dns_policy import validate
                    from .final_dns_program import target_program
                    from .final_dns_runtime import validate_observation,canonical
                    policy=fact['policy']
                    if not isinstance(policy,dict) or set(policy)!={'servers'} or validate(policy['servers'])!=policy:raise ValueError
                    reply=fact['final_dns']
                    expected=hashlib.sha256(target_program(self.catalog._project).encode()).hexdigest()
                    if (not isinstance(reply,dict) or set(reply)!={'schema_version','status','helper_sha256','observation'}
                            or type(reply['schema_version']) is not int or reply['schema_version']!=1
                            or reply['status']!='ok' or reply['helper_sha256']!=expected
                            or fact['policy_sha256']!=hashlib.sha256(canonical(policy)).hexdigest()):raise ValueError
                    machine=SimpleNamespace(uuid=evidence['machine']['uuid'],hostname=evidence['machine']['hostname'])
                    value=validate_observation(reply['observation'],machine,expected_boot_id=evidence['machine']['boot_id'])
                    ready=value['servers']==policy['servers'] and value['persistent_servers']==policy['servers']
                    if fact['checks']!={'ready':ready}:raise ValueError
                except Exception:continue
            if component['verification']['recipe'] == 'kwallet':
                try:
                    from .kwallet_runtime import specification,validate_observation
                    request=dict(specification(self.catalog._project),machine_uuid=evidence['machine']['uuid'],
                                 hostname=evidence['machine']['hostname'],login=evidence['user']['login'])
                    value=validate_observation(fact['wallet_readiness'],request,evidence['machine']['boot_id'])
                    expected=(value['disposition']=='noop' and value['helper_installed']
                              and value['installed_helper_sha256']==request['helper_sha256'])
                    if (value['uid']!=evidence['user']['uid'] or value['gid']!=evidence['user']['gid']
                            or fact['checks']!={'ready':expected}):raise ValueError
                except Exception:continue
            if component['verification']['recipe'] == 'package':
                status = _package_status(self.catalog.artifact(identifier), fact)
            else:
                status = 'compliant'
            if status == 'compliant' and not all(fact['checks'].values()):
                status = 'drifted'
            result['status'] = status
            if status == 'compliant':
                functional = component['verification']['functional_verification_required']
                result.update(installation_status='installed_verified',
                              acceptance_status='functional_verification_required' if functional else 'technical_verified',
                              operator_action='functional_acceptance' if functional else None)
            elif status != 'unknown':
                result['operator_action'] = 'new_confirmed_plan'
        outcomes = [components[c]['status'] for c in selected_ids]
        pending_reboot = bool(reboot_required) and (not safe or original_boot_id is None
                            or evidence['machine']['boot_id'] == original_boot_id)
        overall = ('unknown_requires_review' if not safe or 'unknown' in outcomes else
                   'unknown_requires_review' if reboot_required and original_boot_id is None else
                   'waiting_reboot' if pending_reboot else
                   'successful' if outcomes and all(s == 'compliant' for s in outcomes) else 'degraded')
        return {'schema_version': 2, 'operation': 'component_verification',
                'machine_uuid': evidence['machine']['uuid'] if safe else None,
                'overall_status': overall, 'components': components,
                'reboot_required': pending_reboot,
                'operator_action_required': pending_reboot or any(components[c].get('operator_action') is not None for c in selected_ids)}
