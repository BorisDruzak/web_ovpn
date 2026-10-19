"""The published declaration is the only component/profile/role registry."""
from __future__ import annotations

import copy
import hashlib
import json
import re
from pathlib import Path, PurePosixPath

import yaml
from yaml.events import AliasEvent, MappingEndEvent, MappingStartEvent, SequenceEndEvent, SequenceStartEvent

from .errors import ControlError

MAX_CATALOG_BYTES = 524288
SUPPORTED_OS = frozenset({'alt-kworkstation-11'})
PROTECTED_ROLES = frozenset({
    'domain_join', 'domain_verify', 'alt_group_policy_client', 'alt_group_policy_prerequisites',
    'domain_login_baseline', 'prejoin_upgrade', 'workstation_identity', 'workstation_network',
    'local_employee', 'provision_verify', 'lightdm_accounts', 'standard_software',
    'preflight', 'manual_preflight',
})
ID_RE = re.compile(r'^[a-z][a-z0-9]*(?:[._-][a-z0-9]+)*$')
ROLE_RE = re.compile(r'^[a-z][a-z0-9_]{0,95}$')
PACKAGE_RE = re.compile(r'^[A-Za-z0-9][A-Za-z0-9+_.-]{0,127}$')
EVR_RE = re.compile(r'^[A-Za-z0-9][A-Za-z0-9+_.:~%-]{0,127}$')
RECIPES = frozenset({'package', 'system_base', 'domain', 'plasma', 'government_ca', 'shortcuts', 'krfb'})
PREFLIGHTS = frozenset({'artifact', 'system', 'identity', 'government_ca', 'user_home', 'krfb'})


def invalid():
    return ControlError('component_catalog_invalid', 'Published component catalog is invalid', 4)


def require(condition):
    if not condition:
        raise invalid()


class _StrictLoader(yaml.SafeLoader):
    def construct_mapping(self, node, deep=False):
        require(isinstance(node, yaml.MappingNode))
        result = {}
        for key_node, value_node in node.value:
            key = self.construct_object(key_node, deep=deep)
            require(isinstance(key, str) and key not in result)
            result[key] = self.construct_object(value_node, deep=deep)
        return result


def _keys(value, required, optional=()):
    require(isinstance(value, dict) and set(required) <= set(value) <= set(required) | set(optional))


def _version(value):
    require(type(value) is int and 1 <= value <= 2147483647)


def _text(value, pattern=None):
    require(isinstance(value, str) and 0 < len(value) <= 256 and value.strip() == value)
    require(not any(ord(c) < 32 for c in value) and '{{' not in value and '{%' not in value)
    if pattern is not None:
        require(pattern.fullmatch(value) is not None)


def _ids(value, *, allow_empty=True):
    require(isinstance(value, list) and len(value) <= 256 and (allow_empty or bool(value)))
    for item in value:
        _text(item, ID_RE)
    require(len(set(value)) == len(value))


def _absolute(value):
    _text(value)
    require(value.startswith('/') and '//' not in value and '\\' not in value)
    require(all(part not in ('.', '..') for part in value.split('/')[1:]))
    require(PurePosixPath(value).is_absolute())


def _regular(path):
    require(all(not p.is_symlink() for p in (path, *path.parents)))
    require(path.is_file() and path.stat().st_size <= MAX_CATALOG_BYTES)


def _artifact(entry):
    _keys(entry, {'enabled', 'source', 'executable'}, {
        'artifact_path', 'sha256', 'package_name', 'package_evr', 'architecture',
        'package_epoch', 'packages', 'installer_filename', 'payload_filename',
        'download_size_bytes', 'installed_size_bytes', 'desktop_entry',
    })
    require(type(entry['enabled']) is bool and entry['enabled'])
    require(entry['source'] in ('rpm', 'alt-repository', 'archive', 'zip'))
    _absolute(entry['executable'])
    if 'desktop_entry' in entry:
        require(entry['source'] == 'rpm')
        _absolute(entry['desktop_entry'])
        require(entry['desktop_entry'].startswith('/usr/share/applications/')
                and entry['desktop_entry'].endswith('.desktop'))
    sizes = {'download_size_bytes', 'installed_size_bytes'}
    if sizes & entry.keys():
        require(sizes <= entry.keys() and entry['source'] == 'rpm')
        for key in sizes:
            require(type(entry[key]) is int and 0 < entry[key] <= 2**50)
    if entry['source'] != 'alt-repository':
        require({'artifact_path', 'sha256', 'package_evr'} <= entry.keys())
        _absolute(entry['artifact_path'])
        require(isinstance(entry['sha256'], str) and re.fullmatch('[0-9a-f]{64}', entry['sha256']))
        _text(entry['package_evr'], EVR_RE)
    if 'package_epoch' in entry:
        require(type(entry['package_epoch']) is int and 0 <= entry['package_epoch'] <= 2147483647)
    if entry['source'] in ('rpm', 'zip'):
        require({'package_name', 'architecture'} <= entry.keys())
        _text(entry['package_name'], PACKAGE_RE)
        require(entry['architecture'] in ('x86_64', 'noarch'))
    if entry['source'] in ('archive', 'alt-repository'):
        packages = entry.get('packages')
        require(isinstance(packages, list) and 0 < len(packages) <= 64)
        names = []
        for package in packages:
            if entry['source'] == 'alt-repository':
                _text(package, PACKAGE_RE)
                names.append(package)
            else:
                _keys(package, {'filename', 'package_name', 'package_evr', 'architecture'}, {'package_epoch'})
                for key in ('filename', 'package_name'):
                    _text(package[key], PACKAGE_RE)
                _text(package['package_evr'], EVR_RE)
                require(package['architecture'] in ('x86_64', 'noarch'))
                if 'package_epoch' in package:
                    require(type(package['package_epoch']) is int and package['package_epoch'] >= 0)
                names.append(package['package_name'])
        require(len(set(names)) == len(names))
    for key in ('installer_filename', 'payload_filename'):
        if key in entry:
            _text(entry[key], PACKAGE_RE)


class ComponentCatalog:
    """All validation completes before any declaration can be queried."""
    def __init__(self, project: Path, document: dict):
        self._project = project
        self._document = copy.deepcopy(document)
        _keys(document, {'software_catalog', 'setup_catalog'})
        artifacts = document['software_catalog']
        require(isinstance(artifacts, dict) and 0 < len(artifacts) <= 256)
        for key, entry in artifacts.items():
            _text(key, ROLE_RE)
            _artifact(entry)
        catalog = document['setup_catalog']
        _keys(catalog, {'schema_version', 'version', 'components', 'profiles'})
        require(type(catalog['schema_version']) is int and catalog['schema_version'] == 1)
        _version(catalog['version'])
        self.version = catalog['version']
        self._components = {}
        require(isinstance(catalog['components'], list) and 0 < len(catalog['components']) <= 256)
        for component in catalog['components']:
            self._validate_component(component, artifacts)
            require(component['id'] not in self._components)
            self._components[component['id']] = copy.deepcopy(component)
        # Validate closure for every component, not only the requested selection.
        for component in self._components.values():
            closure = self._ordered([component['id']])
            execution = component['execution']
            if execution['requires_domain']:
                require('domain.ready' in [c['id'] for c in closure[:-1]])
        self._profiles = {}
        require(isinstance(catalog['profiles'], list) and 0 < len(catalog['profiles']) <= 128)
        for profile in catalog['profiles']:
            self._validate_profile(profile)
            require(profile['id'] not in self._profiles)
            self._profiles[profile['id']] = copy.deepcopy(profile)
        raw = json.dumps(document, sort_keys=True, separators=(',', ':'), ensure_ascii=True, allow_nan=False).encode()
        self.fingerprint = hashlib.sha256(raw).hexdigest()

    @classmethod
    def load(cls, project: Path) -> ComponentCatalog:
        try:
            project = Path(project)
            path = project / 'group_vars/software_catalog.yml'
            _regular(path)
            # Do not follow a replaced final file between validation and opening.
            import os
            import stat
            before = path.lstat()
            descriptor = os.open(path, os.O_RDONLY | getattr(os, 'O_NOFOLLOW', 0))
            with os.fdopen(descriptor, 'rb') as stream:
                info = os.fstat(stream.fileno())
                require(stat.S_ISREG(info.st_mode) and (before.st_dev, before.st_ino) == (info.st_dev, info.st_ino))
                raw = stream.read(MAX_CATALOG_BYTES + 1)
            require(len(raw) <= MAX_CATALOG_BYTES)
            text = raw.decode('utf-8')
            depth = 0
            for count, event in enumerate(yaml.parse(text, Loader=_StrictLoader)):
                require(count < 20000 and not isinstance(event, AliasEvent))
                if isinstance(event, (MappingStartEvent, SequenceStartEvent)):
                    depth += 1
                    require(depth <= 32)
                elif isinstance(event, (MappingEndEvent, SequenceEndEvent)):
                    depth -= 1
            return cls(project, yaml.load(text, Loader=_StrictLoader))
        except (OSError, ValueError, TypeError, KeyError, RecursionError, yaml.YAMLError) as exc:
            raise invalid() from None

    def _validate_component(self, component, artifacts):
        _keys(component, {'id', 'version', 'name', 'category', 'supported_os',
                          'dependencies', 'execution', 'preflight', 'verification'})
        _text(component['id'], ID_RE)
        _version(component['version'])
        _text(component['name'])
        require(component['category'] in ('system', 'domain', 'desktop', 'certificates', 'applications', 'remote_access'))
        _ids(component['supported_os'], allow_empty=False)
        require(set(component['supported_os']) <= SUPPORTED_OS)
        _ids(component['dependencies'])
        execution = component['execution']
        _keys(execution, {'operation', 'scope', 'requires_domain', 'requires_user_home',
                          'requires_reboot', 'retry_policy'}, {'role', 'adapter'})
        require(('role' in execution) != ('adapter' in execution))
        require((component['id'] == 'domain.ready') == ('adapter' in execution))
        require(execution['operation'] in ('configure', 'software', 'protected_critical'))
        require(execution['scope'] in ('system', 'user', 'system_and_user'))
        require(execution['retry_policy'] in ('read_only', 'idempotent', 'guarded', 'non_replayable'))
        for key in ('requires_domain', 'requires_user_home', 'requires_reboot'):
            require(type(execution[key]) is bool)
        require(not execution['requires_user_home'] or execution['scope'] != 'system')
        if 'role' in execution:
            _text(execution['role'], ROLE_RE)
            require(execution['role'] not in PROTECTED_ROLES and execution['operation'] != 'protected_critical')
            _regular(self._project / 'roles' / execution['role'] / 'tasks/main.yml')
        else:
            require(component['id'] == 'domain.ready' and execution['adapter'] == 'legacy_domain_critical'
                    and execution['operation'] == 'protected_critical' and execution['retry_policy'] == 'non_replayable')
        preflight = component['preflight']
        _keys(preflight, {'recipe'}, {'artifact_key'})
        require(preflight['recipe'] in PREFLIGHTS)
        if 'artifact_key' in preflight:
            require(isinstance(preflight['artifact_key'], str) and preflight['artifact_key'] in artifacts)
        verification = component['verification']
        _keys(verification, {'recipe', 'functional_verification_required'}, {'services'})
        require(verification['recipe'] in RECIPES and type(verification['functional_verification_required']) is bool)
        if 'services' in verification:
            _ids(verification['services'])
        if execution['operation'] == 'software':
            require(preflight['recipe'] == 'artifact' and 'artifact_key' in preflight
                    and verification['recipe'] == 'package')
        else:
            require(verification['recipe'] != 'package')

    def _ordered(self, component_ids):
        visiting, done, result = set(), set(), []
        def visit(identifier):
            require(identifier in self._components and identifier not in visiting)
            if identifier in done:
                return
            visiting.add(identifier)
            component = self._components[identifier]
            for dependency in component['dependencies']:
                visit(dependency)
            visiting.remove(identifier)
            done.add(identifier)
            result.append(component)
        for identifier in component_ids:
            visit(identifier)
        return result

    def _validate_profile(self, profile):
        _keys(profile, {'id', 'version', 'name', 'components', 'optional_components', 'confirmation_policy'})
        _text(profile['id'], ID_RE)
        _text(profile['name'])
        _version(profile['version'])
        _ids(profile['components'], allow_empty=False)
        _ids(profile['optional_components'])
        require(profile['confirmation_policy'] == 'sha256')
        require(not set(profile['components']) & set(profile['optional_components']))
        order = [component['id'] for component in self._ordered(profile['components'])]
        require(order == profile['components'])
        for identifier in profile['optional_components']:
            closure = self._ordered([identifier])
            require(all(c['id'] in profile['components'] for c in closure[:-1]))

    def component(self, component_id: str) -> dict:
        if not isinstance(component_id, str) or component_id not in self._components:
            raise ControlError('component_unknown', 'Unknown published setup component', 4)
        return copy.deepcopy(self._components[component_id])

    def profile(self, profile_id: str) -> dict:
        if not isinstance(profile_id, str) or profile_id not in self._profiles:
            raise ControlError('profile_unknown', 'Unknown published setup profile', 4)
        return copy.deepcopy(self._profiles[profile_id])

    def components(self) -> list[dict]:
        return copy.deepcopy(list(self._components.values()))

    def profiles(self) -> list[dict]:
        return copy.deepcopy(list(self._profiles.values()))

    def artifact(self, component_id: str) -> dict | None:
        component = self.component(component_id)
        key = component['preflight'].get('artifact_key')
        return copy.deepcopy(self._document['software_catalog'][key]) if key is not None else None

    def ordered(self, component_ids: list[str], *, os_id: str) -> list[dict]:
        _ids(component_ids)
        result = self._ordered(component_ids)
        if any(os_id not in component['supported_os'] for component in result):
            raise ControlError('component_os_unsupported', 'Selected components do not support the observed OS', 4)
        return copy.deepcopy(result)
