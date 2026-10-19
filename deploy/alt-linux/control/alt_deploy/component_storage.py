"""Bound installation-only space evidence, independently of installed compliance."""

RESERVE_BYTES = 536870912
MAX_BYTES = 2**63 - 1


def installation_budget(artifact, observed):
    sizes = ('download_size_bytes', 'installed_size_bytes')
    if not any(key in artifact for key in sizes):
        return {'ready': True, 'required': False}
    invalid = {'ready': False, 'error_code': 'component_install_space_unverified'}
    if any(type(artifact.get(k)) is not int or not 0 < artifact[k] <= 2**50 for k in sizes):
        return invalid
    if not isinstance(observed, dict) or set(observed) != {'opt', 'staging'}:
        return invalid
    for location in observed.values():
        if not isinstance(location, dict) or set(location) != {'device', 'available_bytes'}:
            return invalid
        if any(type(location[k]) is not int or not 0 <= location[k] <= MAX_BYTES
               for k in ('device', 'available_bytes')):
            return invalid
    opt, staging = observed['opt'], observed['staging']
    download, installed = (artifact[k] for k in sizes)
    shared = opt['device'] == staging['device']
    required_opt = installed + RESERVE_BYTES + (download if shared else 0)
    required_stage = required_opt if shared else download + RESERVE_BYTES
    if opt['available_bytes'] < required_opt or staging['available_bytes'] < required_stage:
        return {'ready': False, 'error_code': 'component_install_space_insufficient'}
    return {'ready': True, 'required': True}


def bind_budget_evidence(artifact, fact):
    """Bind devices and sufficient capacity, not unrelated log-write fluctuations.

    The raw observation is always checked before capping. Available bytes below
    the bound are never promoted; crossing the threshold remains plan drift.
    Installed software needs no installation capacity or filesystem binding.
    """
    if 'download_size_bytes' not in artifact:
        return fact
    if not isinstance(fact, dict):
        return fact
    from .component_verification import _package_status
    checks = fact.get('checks', {})
    installed = (_package_status(artifact, fact) == 'compliant'
                 and fact.get('error_code') is None and isinstance(checks, dict) and bool(checks)
                 and all(value is True for value in checks.values()))
    result = dict(fact)
    if installed:
        result.pop('storage', None)
        return result
    observed = fact.get('storage')
    if installation_budget(artifact, observed).get('error_code') == 'component_install_space_unverified':
        return result
    opt, staging = observed['opt'], observed['staging']
    shared = opt['device'] == staging['device']
    download, installed = artifact['download_size_bytes'], artifact['installed_size_bytes']
    result['storage'] = {
        'opt': dict(opt, available_bytes=min(opt['available_bytes'], installed + RESERVE_BYTES
                                             + (download if shared else 0))),
        'staging': dict(staging, available_bytes=min(staging['available_bytes'], download + RESERVE_BYTES
                                                   + (installed if shared else 0)))}
    return result
