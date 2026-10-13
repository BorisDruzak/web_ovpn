"""Compare fresh bounded probe evidence to the published desired state."""
from __future__ import annotations

import json
import re
from datetime import datetime

from .component_catalog import EVR_RE, PACKAGE_RE


def valid_evidence(evidence):
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
        if any(type(user[k]) is not int or user[k] <= 0 for k in ('uid', 'gid')):
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

    def evaluate(self, evidence: dict, selected: list[str]) -> dict:
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
        overall = ('unknown_requires_review' if not safe or 'unknown' in outcomes else
                   'successful' if outcomes and all(s == 'compliant' for s in outcomes) else 'degraded')
        return {'schema_version': 2, 'operation': 'component_verification',
                'machine_uuid': evidence['machine']['uuid'] if safe else None,
                'overall_status': overall, 'components': components,
                'reboot_required': False,
                'operator_action_required': any(components[c].get('operator_action') is not None for c in selected_ids)}
