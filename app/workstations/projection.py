"""Pure evidence matching plus local inventory reads; never confirms relations."""
from __future__ import annotations

import hashlib
import ipaddress
import json
from collections import defaultdict

from sqlalchemy import select

from ..inventory.lookup import normalize_mac, InventoryLookupError
from ..inventory.models import InventoryAsset, InventoryNetctlBinding, InventoryExternalBindingStatus as Status
from ..inventory.network_projection import attach_network_projection
from .models import DirectoryLink


def fingerprint(value):
    return hashlib.sha256(json.dumps(value, sort_keys=True, ensure_ascii=True, allow_nan=False).encode()).hexdigest()


def mac_key(value):
    try:
        normalized = normalize_mac(value)
        if normalized in ('00:00:00:00:00:00', 'FF:FF:FF:FF:FF:FF') or int(normalized[:2], 16) & 1:
            return None
        return 'mac:' + normalized
    except (InventoryLookupError, ValueError, TypeError, AttributeError):
        return None


def build_projection(db, sources, now):
    findings = []
    def finding(code, key, **evidence):
        findings.append({'code': code, 'device_key': key, 'evidence': evidence})
    machines = sources['controller']['machines']
    by_mac, registered = defaultdict(list), {}
    for machine in machines:
        key = 'machine:' + machine['uuid']
        registered[key] = machine
        normalized = mac_key(machine.get('mac'))
        if normalized:
            by_mac[normalized].append(key)
    links, cards = defaultdict(list), {}
    for relation, card in db.execute(select(InventoryNetctlBinding, InventoryAsset)
            .join(InventoryAsset, InventoryAsset.id == InventoryNetctlBinding.asset_id)
            .where(InventoryNetctlBinding.ended_at.is_(None), InventoryNetctlBinding.status == Status.CONFIRMED)):
        if card.deleted_at is None:
            links[relation.network_key].append(card.id)
            cards[card.id] = card
        else:
            finding('inventory_deleted', relation.network_key)
    card_machines = defaultdict(set)
    for network_key, asset_ids in links.items():
        if len(asset_ids) == 1:
            card_machines[asset_ids[0]].update(by_mac.get(network_key, []))
    grouped, observations = {}, defaultdict(list)
    for host in sources['netctl']['hosts']:
        key = mac_key(host.get('mac'))
        if key:
            observations[key].append(host)
        else:
            finding('network_identity_unavailable', 'source:netctl')
    hosts = [dict(rows[0], device_key=key) for key, rows in observations.items()]
    attach_network_projection(db, hosts, now=now)
    endpoint = {mac_key(host.get('mac')): host.get('endpoint_agent', {}) for host in hosts}

    def device(key):
        if key not in grouped:
            machine = registered.get(key, {})
            grouped[key] = {'device_key': key, 'machine_uuid': machine.get('uuid'), 'hostname': machine.get('hostname', ''),
                'registration_state': machine.get('registration_state'), 'network_keys': [], 'ips': [], 'hostnames': [],
                'inventory_asset_id': None, 'inventory_revision': None, 'inventory_name': None,
                'inventory_employee_text': None, 'assigned_user': None, 'employee_binding_state': 'unbound',
                'ad_computer_state': 'unbound', 'ad_computer_candidates': [], 'endpoint': {},
                'native_assignment': machine.get('domain_assignment')}
        return grouped[key]
    for key in registered:
        device(key)
    for network_key, rows in sorted(observations.items()):
        asset_ids = links.get(network_key, [])
        candidates = by_mac.get(network_key, [])
        if not candidates and len(asset_ids) == 1:
            candidates = sorted(card_machines[asset_ids[0]])
        consistent = all(isinstance(host.get('device_key'), str) and host['device_key'].casefold() == network_key.casefold() for host in rows)
        ambiguous = not consistent or len(rows) != 1 or len(candidates) > 1 or len(asset_ids) > 1
        if len(candidates) == 1:
            key = candidates[0]
        elif len(asset_ids) == 1:
            key = 'inventory:' + asset_ids[0]
        else:
            key = network_key
        row = device(key)
        row['network_keys'].append(network_key)
        if ambiguous:
            finding('network_identity_ambiguous', key, network_key=network_key)
            row['identity_state'] = 'ambiguous'
        if len(asset_ids) == 1 and not ambiguous:
            card = cards[asset_ids[0]]
            if row['inventory_asset_id'] not in (None, card.id):
                finding('inventory_binding_ambiguous', key)
                row['identity_state'] = 'ambiguous'
            else:
                row.update(inventory_asset_id=card.id, inventory_revision=card.manual_revision,
                           inventory_name=card.custom_name, inventory_employee_text=card.assigned_person_name,
                           inventory_login_text=card.login_name)
        for host in rows:
            if isinstance(host.get('ip'), str) and host['ip'] not in row['ips']:
                row['ips'].append(host['ip'])
            if isinstance(host.get('hostname'), str) and host['hostname'] not in row['hostnames']:
                row['hostnames'].append(host['hostname'])
        row['endpoint'] = endpoint.get(network_key, {})
    ad = sources['ad']
    users = {row['object_guid']: row for row in ad['users']}
    computers = {row['object_guid']: row for row in ad['computers']}
    computer_names = defaultdict(set)
    for guid, computer in computers.items():
        fqdn = computer.get('dns_hostname', '').lower().rstrip('.')
        for name in (fqdn, fqdn.split('.')[0], computer.get('login', '').lower().removesuffix('$')):
            if name:
                computer_names[name].add(guid)
    forward = defaultdict(set)
    reverse = defaultdict(set)
    for record in sources['dns']['records']:
        if record['type'] in ('A', 'AAAA'):
            forward[record['name'].lower().rstrip('.')].add(record['value'])
        elif record['type'] == 'PTR':
            reverse[record['name'].lower().rstrip('.')].add(record['value'].lower().rstrip('.'))
    explicit = list(db.scalars(select(DirectoryLink).where(DirectoryLink.status == 'confirmed', DirectoryLink.ended_at.is_(None))))
    explicit_by_device = defaultdict(list)
    for link in explicit:
        explicit_by_device[link.device_key].append(link)
    used = set()
    for key, row in grouped.items():
        row.setdefault('identity_state', 'observed')
        names = {name.lower().rstrip('.') for name in [row['hostname'], *row['hostnames']] if name}
        matching_ids = set().union(*(computer_names[name] for name in names)) if names else set()
        matches = [computers[guid] for guid in sorted(matching_ids)]
        used.update(matching_ids)
        row['ad_computer_candidates'] = matches
        if matches:
            row['ad_computer_state'] = 'candidate' if len(matches) == 1 else 'ambiguous'
            if len(matches) > 1:
                finding('ad_computer_ambiguous', key)
            else:
                fqdn = matches[0].get('dns_hostname', '').lower().rstrip('.')
                if not forward.get(fqdn):
                    finding('dns_forward_missing', key)
                elif row['ips'] and not forward[fqdn] & set(row['ips']):
                    finding('dns_forward_mismatch', key)
                for address in row['ips']:
                    try:
                        pointer = ipaddress.ip_address(address).reverse_pointer
                    except ValueError:
                        finding('network_observation_invalid', key)
                        continue
                    if not reverse.get(pointer):
                        code = 'dns_reverse_missing' if any(pointer.endswith('.' + zone) for zone in sources['dns'].get('zones', [])) else 'dns_reverse_zone_unavailable'
                        finding(code, key, address=address)
                    elif fqdn not in reverse[pointer]:
                        finding('dns_reverse_mismatch', key, address=address)
        else:
            finding('network_only', key)
        aliases = {key, *row['network_keys']}
        if row['inventory_asset_id']:
            aliases.add('inventory:' + row['inventory_asset_id'])
        active = list({link.id: link for alias in aliases for link in explicit_by_device[alias]}.values())
        identities = {(link.user_guid, link.user_sid) for link in active}
        native = row.get('native_assignment')
        if native:
            identities.add((native['object_guid'], native['object_sid']))
        if len(identities) > 1:
            row['employee_binding_state'] = 'ambiguous'
            finding('employee_conflict', key)
        elif identities:
            guid, sid = next(iter(identities))
            user = users.get(guid)
            if user is None or user['object_sid'] != sid:
                row['employee_binding_state'] = 'unavailable'
                finding('employee_identity_changed', key)
            else:
                row['assigned_user'] = user
                row['employee_binding_state'] = 'confirmed' if not native or native.get('result') in ('successful', 'degraded') else 'unresolved'
                if user['state'] != 'enabled':
                    finding('employee_unusable', key, state=user['state'])
        selected_computers = {(link.computer_guid, link.computer_sid) for link in active if link.computer_guid}
        if len(selected_computers) == 1:
            guid, sid = next(iter(selected_computers))
            if guid in computers and computers[guid]['object_sid'] == sid and row['identity_state'] != 'ambiguous':
                row['ad_computer_state'], row['ad_computer_candidates'] = 'confirmed', [computers[guid]]
                used.add(guid)
            else:
                finding('ad_computer_identity_changed', key)
        if not row['inventory_asset_id']:
            finding('inventory_unconfirmed', key)
    for guid, computer in computers.items():
        if guid not in used:
            key = 'ad:' + guid
            row = device(key)
            row.update(hostname=computer.get('dns_hostname') or computer.get('login'),
                       ad_computer_state='only_directory', ad_computer_candidates=[computer], identity_state='directory_only')
            finding('ad_only', key)
    for item in sources['dns'].get('findings', []):
        if isinstance(item, dict) and item.get('code') in ('dns_alias_loop', 'dns_alias_ambiguous', 'dns_alias_depth'):
            finding(item['code'], 'source:dns', name=item.get('name'))
    for item in findings:
        item['id'] = fingerprint([item['device_key'], item['code'], item['evidence']])
    return {'devices': sorted(grouped.values(), key=lambda row: (str(row['hostname']).casefold(), row['device_key'])),
            'findings': list({row['id']: row for row in findings}.values()),
            'generations': {key: value['generation'] for key, value in sources.items()}}
