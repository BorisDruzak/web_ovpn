"""Read AD-integrated DNS evidence; no DNS or directory mutation primitives.

Directory dnsRecord uses a 24-byte header and DNS_COUNT_NAME rather than
DNS_RPC_NAME: MS-DNSP 2.3.2.2, 2.2.2.2.2 and 3.1.6.3.
"""
from __future__ import annotations

import hashlib
import ipaddress
import json
import re
import struct

from .ad_directory import escape_filter, fail, text
from .directory_observer import DirectoryObserver, COLLECTION_SECONDS, MAX_OBJECTS, MAX_SOURCE_BYTES


def dns_name(value):
    if not isinstance(value, str) or not value or len(value) > 253:
        raise ValueError
    labels = value.rstrip('.').lower().split('.')
    if any(not re.fullmatch(r'[a-z0-9_](?:[a-z0-9_-]{0,61}[a-z0-9_])?', label) for label in labels):
        raise ValueError
    return '.'.join(labels)


def dns_owner_name(value):
    """A wildcard owner is DNS evidence, never a physical host identity."""
    if isinstance(value, str) and value.startswith('*.'):
        normalized = '*.' + dns_name(value[2:])
        if len(normalized) > 253:
            raise ValueError
        return normalized
    return dns_name(value)


def _counted_name(data):
    if len(data) < 3 or data[0] != len(data) - 2 or data[-1] != 0:
        raise ValueError
    labels, offset = [], 2
    for _ in range(data[1]):
        if offset >= len(data) - 1:
            raise ValueError
        length = data[offset]
        offset += 1
        if not 1 <= length <= 63 or offset + length > len(data) - 1:
            raise ValueError
        labels.append(data[offset:offset + length].decode('ascii'))
        offset += length
    if offset != len(data) - 1:
        raise ValueError
    return dns_name('.'.join(labels))


def decode_dns_record(value: bytes, *, owner: str, zone: str) -> dict | None:
    try:
        if not isinstance(value, bytes) or not 24 <= len(value) <= 8192:
            raise ValueError
        size, kind, version, rank, flags, serial = struct.unpack('<HHBBHI', value[:12])
        ttl = struct.unpack('!I', value[12:16])[0]
        reserved, timestamp = struct.unpack('<II', value[16:24])
        if size != len(value) - 24 or version != 5 or flags != 0 or reserved != 0:
            raise ValueError
        if kind not in (1, 5, 12, 28):
            return None
        zone = dns_name(zone)
        name = zone if owner == '@' else dns_owner_name(owner + '.' + zone)
        data = value[24:]
        if kind in (1, 28):
            if len(data) != (4 if kind == 1 else 16):
                raise ValueError
            answer = str(ipaddress.ip_address(data))
        else:
            answer = _counted_name(data)
        return {'name': name, 'zone': zone, 'type': {1: 'A', 5: 'CNAME', 12: 'PTR', 28: 'AAAA'}[kind],
                'value': answer, 'ttl': ttl, 'timestamp': timestamp}
    except (ValueError, TypeError, UnicodeError, struct.error) as exc:
        raise fail('directory_dns_record_invalid', 'Directory DNS record format is invalid') from exc


def alias_findings(records):
    aliases = {}
    for row in records:
        if row['type'] == 'CNAME':
            aliases.setdefault(row['name'], set()).add(row['value'])
    findings = []
    for origin in sorted(aliases):
        node, visited = origin, set()
        for _ in range(32):
            if node in visited:
                findings.append({'code': 'dns_alias_loop', 'name': origin})
                break
            visited.add(node)
            targets = aliases.get(node)
            if not targets:
                break
            if len(targets) != 1:
                findings.append({'code': 'dns_alias_ambiguous', 'name': origin})
                break
            node = next(iter(targets))
        else:
            findings.append({'code': 'dns_alias_depth', 'name': origin})
    return findings


class DirectoryDNS(DirectoryObserver):
    def collect(self, *, deadline=None):
        if not self.config.dns_bases or not self.config.dns_zones:
            raise fail('directory_dns_not_configured', 'Approved directory DNS zones are not configured')
        deadline = self.monotonic() + COLLECTION_SECONDS if deadline is None else deadline
        approved = {dns_name(zone) for zone in self.config.dns_zones}
        zones, objects, byte_count, record_count = {}, 0, 0, 0
        records, unsupported, tombstones = [], 0, 0

        def query(**parameters):
            nonlocal objects, byte_count
            entries, size, _ = self._query(deadline=deadline, **parameters)
            objects, byte_count = objects + len(entries), byte_count + size
            if objects > MAX_OBJECTS or byte_count > MAX_SOURCE_BYTES:
                raise fail('directory_dns_limit', 'Directory DNS collection exceeds its total budget')
            return entries

        ldap_filter = '(&(objectClass=dnsZone)(|' + ''.join('(name=' + escape_filter(zone) + ')' for zone in sorted(approved)) + '))'
        for base in self.config.dns_bases:
            for zone in query(base=base, ldap_filter=ldap_filter, attributes=('dn', 'name')):
                try:
                    name = dns_name(text(zone, 'name'))
                    expected = 'DC=' + name + ',' + base
                    if name not in approved or text(zone, 'dn').casefold() != expected.casefold() or name in zones:
                        raise ValueError
                    zones[name] = expected
                except (ValueError, UnicodeError) as exc:
                    raise fail('directory_dns_zone_invalid', 'Directory returned an unapproved or ambiguous DNS zone') from exc
        if set(zones) != approved:
            raise fail('directory_dns_zone_unavailable', 'An approved DNS zone could not be enumerated')
        for name, base in sorted(zones.items()):
            nodes = query(base=base, ldap_filter='(objectClass=dnsNode)',
                          attributes=('dn', 'name', 'dnsRecord', 'dNSTombstoned'), multivalued=frozenset({'dnsrecord'}))
            seen = set()
            for node in nodes:
                try:
                    owner = text(node, 'name')
                    if owner.casefold() in seen or not text(node, 'dn').casefold().endswith(',' + base.casefold()):
                        raise ValueError
                    seen.add(owner.casefold())
                    deleted = text(node, 'dnstombstoned', required=False).upper()
                    if deleted not in ('', 'TRUE', 'FALSE'):
                        raise ValueError
                    if deleted == 'TRUE':
                        tombstones += 1
                        continue
                    for raw in node.get('dnsrecord', []):
                        record_count += 1
                        if record_count > MAX_OBJECTS:
                            raise fail('directory_dns_limit', 'Directory DNS record budget exceeded')
                        row = decode_dns_record(raw, owner=owner, zone=name)
                        if row is None:
                            unsupported += 1
                        else:
                            records.append(row)
                except (ValueError, UnicodeError) as exc:
                    raise fail('directory_dns_node_invalid', 'Directory DNS node evidence is invalid') from exc
        if self.monotonic() >= deadline:
            raise fail('directory_observer_timeout', 'Directory collection deadline exceeded')
        result = {'schema_version': 1, 'complete': True, 'generated_at': self.clock().isoformat(),
                  'records': records, 'zones': sorted(zones), 'object_count': objects,
                  'unsupported_records': unsupported, 'tombstones': tombstones, 'findings': alias_findings(records)}
        result['generation'] = hashlib.sha256(json.dumps(result, sort_keys=True).encode()).hexdigest()
        return result


def check_resolution(name, record_type, *, server, timeout=2, resolver=None):
    """One explicit bounded query; never changes DNS or follows OS search paths."""
    import dns.exception
    import dns.resolver
    try:
        if record_type not in ('A', 'AAAA', 'PTR') or type(timeout) not in (int, float) or not 0 < timeout <= 5:
            raise ValueError
        name = dns_name(name)
        server = str(ipaddress.ip_address(server))
        resolver = resolver or dns.resolver.Resolver(configure=False)
        resolver.nameservers, resolver.timeout, resolver.lifetime = [server], timeout, timeout
        answer = resolver.resolve(name + '.', record_type, search=False, raise_on_no_answer=False, lifetime=timeout)
        if answer.rrset is None:
            return {'state': 'no_answer', 'values': []}
        if len(answer) > 100:
            return {'state': 'limit', 'values': []}
        values = sorted({str(ipaddress.ip_address(str(row))) if record_type in ('A', 'AAAA') else dns_name(str(row)) for row in answer})
        return {'state': 'ok', 'values': values}
    except dns.resolver.NXDOMAIN:
        return {'state': 'nxdomain', 'values': []}
    except dns.resolver.NoAnswer:
        return {'state': 'no_answer', 'values': []}
    except dns.exception.Timeout:
        return {'state': 'timeout', 'values': []}
    except (ValueError, dns.exception.DNSException, OSError):
        return {'state': 'unavailable', 'values': []}
