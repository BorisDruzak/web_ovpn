#!/usr/bin/python3
"""Conservative, explicit component ownership and release test coverage."""
import hashlib
import json
from pathlib import Path, PurePosixPath

ROLE_ROOT = 'deploy/alt-linux/ansible/roles/'
CRITICAL = (
    'deploy/alt-linux/verification_policy.py', 'deploy/alt-linux/release_verification.py',
    'deploy/alt-linux/verification_checkpoint.py', 'deploy/alt-linux/verify_repository.py',
    'deploy/alt-linux/run-tests.sh',
)
MANDATORY = tuple(sorted({
    'tests/alt_linux/test_verification_policy.py', 'tests/alt_linux/test_release_verification.py',
    'tests/alt_linux/test_verification_checkpoint.py', 'tests/alt_linux/test_repository_verification.py',
    'tests/alt_linux/test_release_cli_root.py',
    'tests/alt_linux/test_installer_verification_resume.py', 'tests/alt_linux/test_installer_selective_verification.py',
    'tests/alt_linux/test_install_assets.py', 'tests/alt_linux/test_complete_workflow_installer.py',
    'tests/alt_linux/test_component_catalog.py', 'tests/alt_linux/test_component_catalog_boundary.py',
    'tests/alt_linux/test_component_ansible_runtime.py', 'tests/alt_linux/test_component_verification.py',
    'tests/alt_linux/test_component_setup.py', 'tests/alt_linux/test_component_probe_script.py',
    'tests/alt_linux/test_full_workflow_system_role.py', 'tests/alt_linux/test_full_workflow_policy.py',
    'tests/alt_linux/test_setup_events.py', 'tests/alt_linux/test_setup_initial_components.py',
    'tests/alt_linux/test_setup_queue_review.py', 'tests/alt_linux/test_setup_runtime.py',
    'tests/alt_linux/test_workflow_backup_history.py', 'tests/alt_linux/test_workflow_phase_role.py',
    'tests/test_alt_component_preflight_contract.py', 'tests/test_alt_software_catalog.py',
    'tests/test_alt_clean_vm_setup.py', 'tests/test_alt_domain_resilience_assets.py',
    'tests/test_alt_domain_ansible_assets.py',
}))
GROUPS = {
    'browser-signing': {
        'roles': ('software_browser', 'software_cryptopro', 'software_cryptopro_cades', 'software_gosuslugi_plugin'),
        'tests': ('tests/alt_linux/test_cryptopro_browser_policy.py', 'tests/alt_linux/test_yandex_gpo_policy_runtime.py',
                  'tests/alt_linux/test_certificate_installation_order.py', 'tests/alt_linux/test_certificate_import_lock.py',
                  'tests/alt_linux/test_government_anchor_cleanup.py', 'tests/alt_linux/test_organization_ca.py',
                  'tests/test_alt_browser_repository_policy.py', 'tests/test_alt_signature_stage03.py',
                  'tests/test_alt_yandex_gpo_handoff.py', 'tests/test_alt_p11_mirror.py', 'tests/test_alt_government_ca.py'),
        'owned_tests': ('tests/alt_linux/test_cryptopro_browser_policy.py', 'tests/alt_linux/test_yandex_gpo_policy_runtime.py',
                        'tests/test_alt_browser_repository_policy.py', 'tests/test_alt_signature_stage03.py',
                        'tests/test_alt_yandex_gpo_handoff.py', 'tests/test_alt_p11_mirror.py'),
        'affects': ('desktop', 'directum'),
    },
    'office': {'roles': ('software_onlyoffice',), 'tests': (), 'owned_tests': (), 'affects': ('desktop',)},
    'nextcloud': {'roles': ('software_nextcloud_desktop',), 'tests': (), 'owned_tests': (), 'affects': ('desktop',)},
    'directum': {'roles': ('software_directum',), 'tests': ('tests/test_alt_directum_ansible.py',),
                 'owned_tests': ('tests/test_alt_directum_ansible.py',), 'affects': ('desktop',)},
    'vkworkspace': {'roles': ('software_vkworkspace',), 'tests': ('tests/alt_linux/test_software_vkworkspace.py',),
                    'owned_tests': ('tests/alt_linux/test_software_vkworkspace.py',), 'affects': ('desktop',)},
    'gpupdate': {
        'roles': ('alt_group_policy_compat',),
        'tests': ('tests/alt_linux/test_gpupdate_compat.py', 'tests/alt_linux/test_gpupdate_compat_0164.py',
                  'tests/alt_linux/test_gpupdate_compat_ansible.py', 'tests/alt_linux/test_prejoin_upgrade_compat.py',
                  'tests/alt_linux/test_setup_prejoin_compatibility.py', 'tests/test_alt_first_join_compat.py',
                  'tests/test_alt_first_join_diagnostics.py'),
        'owned_tests': ('tests/alt_linux/test_gpupdate_compat.py', 'tests/alt_linux/test_gpupdate_compat_0164.py',
                        'tests/alt_linux/test_gpupdate_compat_ansible.py'),
        'affects': ('browser-signing', 'desktop'),
    },
    'desktop': {
        'roles': ('desktop_shortcuts', 'kwallet_empty_name_repair'),
        'tests': ('tests/alt_linux/test_desktop_gpo_role_runtime.py', 'tests/alt_linux/test_shortcut_link_ownership.py',
                  'tests/alt_linux/test_software_vkworkspace.py',
                  'tests/alt_linux/test_network_folders_ansible.py', 'tests/alt_linux/test_kwallet_ansible_role.py',
                  'tests/alt_linux/test_kwallet_component.py', 'tests/alt_linux/test_kwallet_empty_name_repair.py',
                  'tests/alt_linux/test_kwallet_helper_contract.py', 'tests/alt_linux/test_kwallet_runtime.py',
                  'tests/test_alt_desktop_gpo_handoff.py', 'tests/test_alt_network_folders.py',
                  'tests/test_alt_plasma_existing_power.py', 'tests/test_alt_plasma_desktop.py'),
        'owned_tests': ('tests/alt_linux/test_desktop_gpo_role_runtime.py', 'tests/alt_linux/test_shortcut_link_ownership.py',
                        'tests/alt_linux/test_network_folders_ansible.py', 'tests/alt_linux/test_kwallet_ansible_role.py',
                        'tests/alt_linux/test_kwallet_component.py', 'tests/alt_linux/test_kwallet_empty_name_repair.py',
                        'tests/alt_linux/test_kwallet_helper_contract.py', 'tests/alt_linux/test_kwallet_runtime.py',
                        'tests/test_alt_desktop_gpo_handoff.py', 'tests/test_alt_network_folders.py'),
        'affects': (),
    },
    'krfb': {
        'roles': ('remote_access_krfb',),
        'tests': ('tests/alt_linux/test_complete_krfb_component_boundary.py', 'tests/alt_linux/test_krfb_managed_role.py',
                  'tests/alt_linux/test_krfb_managed_runtime.py', 'tests/alt_linux/test_krfb_runtime.py',
                  'tests/alt_linux/test_krfb_transaction.py', 'tests/alt_linux/test_krfb_user_session.py'),
        'owned_tests': ('tests/alt_linux/test_complete_krfb_component_boundary.py', 'tests/alt_linux/test_krfb_managed_role.py',
                        'tests/alt_linux/test_krfb_managed_runtime.py', 'tests/alt_linux/test_krfb_runtime.py',
                        'tests/alt_linux/test_krfb_transaction.py', 'tests/alt_linux/test_krfb_user_session.py'),
        'affects': ('desktop',),
    },
}


def full_targets():
    outside = {p for p in MANDATORY if not p.startswith('tests/alt_linux/')}
    for group in GROUPS.values():
        outside.update(p for p in group['tests'] if not p.startswith('tests/alt_linux/'))
    return [*sorted(outside), 'tests/alt_linux']


def signature(source):
    files = [(p, hashlib.sha256((source/p).read_bytes()).hexdigest()) for p in CRITICAL]
    import yaml
    package = Path(yaml.__file__).resolve().parent
    parser_files = [(str(p), hashlib.sha256(p.read_bytes()).hexdigest()) for p in sorted(package.rglob('*'))
                    if p.is_file() and p.suffix in ('.py', '.so') and '__pycache__' not in p.parts]
    value = {'version': 2, 'critical': files, 'mandatory': MANDATORY, 'groups': GROUPS,
             'full': full_targets(), 'yaml_parser': (yaml.__version__, parser_files)}
    return hashlib.sha256(json.dumps(value, sort_keys=True, separators=(',', ':')).encode()).hexdigest()


def owner(path):
    for name, group in GROUPS.items():
        if path in group['owned_tests']:
            return name
        for role in group['roles']:
            prefix = ROLE_ROOT+role+'/'
            if path.startswith(prefix) and path[len(prefix):].split('/', 1)[0] in ('tasks', 'files', 'templates', 'defaults', 'vars'):
                return name
    if path.startswith(('tests/alt_linux/fixtures/gpupdate-0.16.1/', 'tests/alt_linux/fixtures/gpupdate-0.16.4/')):
        return 'gpupdate'
    return None


def documentation(path):
    return (path in ('docs/WORKSTATIONS_WEB_GUIDE.md', 'docs/runbooks/alt-verification-resume.md',
                     'docs/runbooks/alt-selective-verification.md')
            or path.startswith(('docs/superpowers/plans/', 'docs/superpowers/specs/')) and path.endswith('.md'))


def affected(components):
    result = set(components)
    pending = list(result)
    while pending:
        for name in GROUPS[pending.pop()]['affects']:
            if name not in result:
                result.add(name); pending.append(name)
    return sorted(result)


def orchestration_safe(source):
    """Unknown role dependency/Ansible plugin graphs require a full release."""
    import yaml
    forbidden = {'include_role', 'import_role', 'import_playbook', 'include', 'roles', 'meta',
                 'add_host', 'group_by', 'action', 'local_action'}
    def walk(value, path, role):
        if isinstance(value, list):
            return all(walk(item, path, role) for item in value)
        if not isinstance(value, dict):
            return True
        for key, item in value.items():
            operation = str(key).rsplit('.', 1)[-1]
            if operation in forbidden or '{{' in str(key) or '{%' in str(key):
                return False
            if operation in ('include_tasks', 'import_tasks'):
                target = item.get('file') if isinstance(item, dict) else item
                if (not isinstance(target, str) or not target or any(c in target for c in '{}')
                        or PurePosixPath(target).is_absolute() or '..' in PurePosixPath(target).parts):
                    return False
                resolved = path.parent/target
                if not resolved.is_relative_to(role/'tasks') or not resolved.is_file():
                    return False
            if not walk(item, path, role): return False
        return True
    for group in GROUPS.values():
        for name in group['roles']:
            role = source/ROLE_ROOT/name
            if not role.exists(): continue
            for child in role.iterdir():
                if child.is_dir() and child.name not in ('tasks', 'files', 'templates', 'defaults', 'vars', '__pycache__'):
                    if any(p.is_file() for p in child.rglob('*')): return False
            for path in sorted((role/'tasks').rglob('*')):
                if path.is_file() and path.suffix in ('.yml', '.yaml'):
                    try: value = yaml.safe_load(path.read_text())
                    except (yaml.YAMLError, UnicodeError): return False
                    if value is not None and not isinstance(value, list): return False
                    if not walk(value, path, role): return False
    return True


def select(before, after, *, full=False, source=None, before_dirs=(), after_dirs=()):
    old = {p: (mode, sha) for p, mode, sha in before}
    new = {p: (mode, sha) for p, mode, sha in after}
    changed = sorted(p for p in old.keys() | new.keys() if old.get(p) != new.get(p))
    old_dirs, new_dirs = dict(before_dirs), dict(after_dirs)
    directory_changes = sorted(p for p in old_dirs.keys() | new_dirs.keys() if old_dirs.get(p) != new_dirs.get(p))
    changed = sorted([*changed, *(p+'/' for p in directory_changes)])
    def complete(reason):
        return {'mode': 'full', 'reason': reason, 'components': [], 'affected': [],
                'changed_paths': changed, 'targets': full_targets()}
    if full:
        return complete('forced_full')
    for path in directory_changes:
        if path not in new_dirs: return complete('removed_or_renamed_source')
        if path in old_dirs: return complete('source_permissions_changed')
    groups = set()
    for path in changed:
        if path.endswith('/'):
            component = owner(path)
            if component: groups.add(component)
            elif not documentation(path+'placeholder.md'): return complete('shared_or_unknown_source')
            continue
        if path not in new:
            return complete('removed_or_renamed_source')
        if path in old and old[path][0] != new[path][0]:
            return complete('source_permissions_changed')
        component = owner(path)
        if component:
            groups.add(component)
        elif not documentation(path):
            return complete('shared_or_unknown_source')
    if source is not None and not orchestration_safe(source):
        return complete('role_orchestration_dependency')
    closure = affected(groups)
    targets = set(MANDATORY)
    for group in closure:
        targets.update(GROUPS[group]['tests'])
    return {'mode': 'selective', 'reason': 'component_changes' if groups else 'unchanged_or_static_documentation',
            'components': sorted(groups), 'affected': closure, 'changed_paths': changed, 'targets': sorted(targets)}
