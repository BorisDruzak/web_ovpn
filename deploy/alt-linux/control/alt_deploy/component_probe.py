"""Build validated read-only queries; the operator cannot supply commands."""
from __future__ import annotations

import ast
import base64
import hashlib
import hmac
import ipaddress
import json
import os
from pathlib import Path
import re
import shlex

import yaml

from .ad_directory import DOMAIN, fail, normalize_login
from .component_catalog import ComponentCatalog, _regular
from .component_verification import valid_evidence


def _yaml(path):
    _regular(path)
    return yaml.safe_load(path.read_text(encoding='utf-8'))


def _literal_constants(path):
    """Extract declared literals without importing/executing a role's apply helper."""
    _regular(path)
    result = {}
    def literal(node, names):
        if isinstance(node, ast.Constant):
            return node.value
        if isinstance(node, ast.Name) and node.id in names:
            return names[node.id]
        if isinstance(node, (ast.Tuple, ast.List)):
            values = [literal(item, names) for item in node.elts]
            return tuple(values) if isinstance(node, ast.Tuple) else values
        if isinstance(node, ast.BinOp) and isinstance(node.op, ast.Add):
            return literal(node.left, names) + literal(node.right, names)
        if (isinstance(node, ast.Call) and isinstance(node.func, ast.Name) and node.func.id == 'tuple'
                and len(node.args) == 1 and not node.keywords and isinstance(node.args[0], ast.GeneratorExp)):
            generator = node.args[0]
            if len(generator.generators) != 1:
                raise ValueError
            loop = generator.generators[0]
            if loop.ifs or loop.is_async or not isinstance(loop.target, ast.Name):
                raise ValueError
            values = literal(loop.iter, names)
            if not isinstance(values, (tuple, list)) or len(values) > 256:
                raise ValueError
            return tuple(literal(generator.elt, dict(names, **{loop.target.id: value})) for value in values)
        raise ValueError
    for node in ast.parse(path.read_text(encoding='utf-8')).body:
        if isinstance(node, ast.Assign) and len(node.targets) == 1 and isinstance(node.targets[0], ast.Name):
            name = node.targets[0].id
            try:
                result[name] = literal(node.value, result)
            except (ValueError, TypeError):
                pass
    return result


def _ini(text):
    pairs, groups = [], []
    for line in text.splitlines():
        line = line.strip()
        if not line or line.startswith(('#', ';')):
            continue
        if line.startswith('['):
            groups = re.findall(r'\[([^\]]+)\]', line)
        else:
            key, sep, value = line.partition('=')
            if sep:
                pairs.append([groups, key, value])
    return pairs


def _power_template(path):
    _regular(path)
    text = path.read_text(encoding='utf-8')
    match = re.search(r'{% for profile in (\[[^\n]+\]) %}(.*?){% endfor %}', text, re.S)
    if not match:
        raise fail('component_probe_source_invalid', 'Published desktop template is unsupported')
    profiles = ast.literal_eval(match[1])
    if not isinstance(profiles, list) or not all(isinstance(p, str) for p in profiles):
        raise fail('component_probe_source_invalid', 'Published desktop template is unsupported')
    return _ini(''.join(match[2].replace('{{ profile }}', p) for p in profiles) + text[match.end():])


def desired_queries(project, catalog, components):
    """Reuse package manifests, role defaults, templates and literal helper declarations."""
    project = Path(project)
    queries = []
    variables = _yaml(project/'group_vars/all.yml')
    roles = project/'roles'
    for selected in components:
        component = catalog.component(selected['id'])
        if component != selected:
            raise fail('component_probe_selection_invalid', 'Component differs from published catalog')
        recipe = component['verification']['recipe']
        query = {'id': component['id'], 'recipe': recipe}
        if recipe == 'package':
            query['artifact'] = catalog.artifact(component['id'])
            query['services'] = component['verification'].get('services', [])
        elif recipe == 'system_base':
            tasks = _yaml(roles/'workstation_base/tasks/main.yml')
            session_map = next(t['ansible.builtin.set_fact']['workstation_base_desktop_sessions'] for t in tasks
                               if 'workstation_base_desktop_sessions' in t.get('ansible.builtin.set_fact', {}))
            session = session_map[variables['workstation_desktop_session']]
            query.update(packages=variables['domain_prerequisite_packages'], session=session)
        elif recipe == 'plasma':
            path = roles/'plasma_baseline'
            desktop = _literal_constants(path/'files/apply_desktop_defaults.py')
            power = _literal_constants(path/'files/apply_existing_power.py')
            # MIME defaults come from the published literal MIME_TYPES list.
            desktop_settings = list(desktop['SETTINGS'])
            for mime in desktop['MIME_TYPES']:
                desktop_settings.extend([
                    ('mimeapps.list', 'Default Applications', mime, desktop['OFFICE_DESKTOP']+';'),
                    ('mimeapps.list', 'Added Associations', mime, desktop['OFFICE_DESKTOP']+';'),
                ])
            defaults = _yaml(path/'defaults/main.yml')
            query.update(skel=defaults['plasma_baseline_skel_config_dir'], desktop=desktop_settings,
                         power=power['SETTINGS'], skel_power=_power_template(path/'templates/powerdevilrc.j2'),
                         keyboard=_ini((path/'templates/kxkbrc.j2').read_text(encoding='utf-8')))
        elif recipe == 'government_ca':
            query['certificates'] = _yaml(roles/'government_ca/defaults/main.yml')['government_ca_certificates']
        elif recipe == 'shortcuts':
            query['defaults'] = _yaml(roles/'desktop_shortcuts/defaults/main.yml')
            query['signature_selected'] = any(c['id'] == 'software.cryptopro' for c in components)
        elif recipe == 'krfb':
            template = (roles/'remote_access_krfb/templates/krfbrc.j2').read_text(encoding='utf-8')
            template = template.replace("{{ 'xcb' if workstation_desktop_session | default('x11') == 'x11' else 'pw' }}",
                                        'xcb' if variables['workstation_desktop_session'] == 'x11' else 'pw')
            query['settings'] = [p for p in _ini(template) if p[1] not in ('desktopPassword', 'unattendedPassword')]
        queries.append(query)
    return queries


def ssh_binding(settings, machine, *, runner=None):
    from .ad_transport import bounded_run
    runner = runner or bounded_run
    try:
        address = str(ipaddress.ip_address(machine.ip))
        path = Path(settings.known_hosts_file)
        _regular(path)
        host_keys = []
        for line in path.read_text(encoding='utf-8').splitlines():
            fields = line.split()
            if not fields or fields[0].startswith('#'):
                continue
            marker = fields.pop(0) if fields[0].startswith('@') else ''
            if len(fields) < 3:
                continue
            names, algorithm, public = fields[:3]
            matches = address in names.split(',')
            if names.startswith('|1|'):
                _, _, salt, expected = names.split('|')
                matches = hmac.compare_digest(hmac.new(base64.b64decode(salt, validate=True), address.encode(), hashlib.sha1).digest(),
                                               base64.b64decode(expected, validate=True))
            if matches:
                if marker == '@revoked':
                    raise ValueError
                host_keys.append((marker, algorithm, base64.b64decode(public, validate=True).hex()))
        if not host_keys:
            raise ValueError
        rc, output, _ = runner(['/usr/bin/ssh-keygen', '-y', '-P', '', '-f', str(settings.private_key_file)],
                               environment=dict(os.environ), timeout=10)
        fields = output.split()
        if rc or len(fields) < 2:
            raise ValueError
        public = [fields[0], base64.b64decode(fields[1], validate=True).hex()]
        canonical = lambda value: json.dumps(value, sort_keys=True, separators=(',', ':')).encode()
        return {'host_public_sha256': hashlib.sha256(canonical(sorted(host_keys))).hexdigest(),
                'controller_public_sha256': hashlib.sha256(canonical(public)).hexdigest()}
    except Exception:
        raise fail('component_ssh_binding_unverified', 'Strict SSH public identity cannot be verified') from None


class ComponentProbe:
    def __init__(self, settings, *, runner=None):
        from .ad_transport import bounded_run
        self.settings = settings
        self.runner = runner or bounded_run

    def observe(self, machine, user: dict, components: list[dict]) -> dict:
        try:
            login = normalize_login(user['login'])
            if user['upn'] != login+'@'+DOMAIN:
                raise ValueError
            address = str(ipaddress.ip_address(machine.ip))
            if not re.fullmatch('[0-9a-f]{8}(?:-[0-9a-f]{4}){3}-[0-9a-f]{12}', machine.uuid):
                raise ValueError
            catalog = ComponentCatalog.load(self.settings.ansible_project_dir)
            query = {'schema_version': 1, 'machine_uuid': machine.uuid, 'hostname': machine.hostname,
                     'login': login, 'upn': user['upn'],
                     'components': desired_queries(self.settings.ansible_project_dir, catalog, components)}
            script = Path(__file__).with_name('component_probe_script.py')
            _regular(script)
            command = ['/usr/bin/ssh', '-o', 'BatchMode=yes', '-o', 'StrictHostKeyChecking=yes',
                       '-o', 'ProxyCommand=none', '-o', 'IdentitiesOnly=yes', '-o', 'ConnectTimeout=10',
                       '-o', 'UserKnownHostsFile='+str(self.settings.known_hosts_file),
                       '-i', str(self.settings.private_key_file), 'ansible@'+address,
                       'sudo -n /usr/bin/python3 -I -B -c '+shlex.quote(script.read_text(encoding='utf-8'))]
            rc, output, _ = self.runner(command, environment=dict(os.environ),
                                        input_text=json.dumps(query), timeout=180)
            document = json.loads(output)
            if (rc or not valid_evidence(document) or document['machine']['uuid'] != machine.uuid
                    or document['machine']['hostname'] != machine.hostname or document['user']['login'] != login):
                raise ValueError
            return document
        except Exception:
            raise fail('component_probe_unverified', 'Read-only component evidence cannot be verified') from None
