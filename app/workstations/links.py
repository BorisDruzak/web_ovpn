"""Explicit, revision-bound directory links; never writes AD or native assignments."""
from __future__ import annotations

import copy
import uuid
from datetime import datetime, timedelta, timezone

from sqlalchemy import select, update
from sqlalchemy.exc import IntegrityError, OperationalError

from ..inventory.models import InventoryAsset, InventoryNetworkProjectionVersion
from ..inventory.network_projection import projection_epoch
from .client import WorkstationsClient
from .models import DirectoryLink, SourceSnapshot
from .projection import fingerprint, device_aliases
from .sources import MAX_AGE, valid_uuid, coherence_reasons


class LinkConflict(Exception):
    def __init__(self, code='workstations_link_conflict'):
        self.code = code
        super().__init__(code)


def _now(clock):
    return clock() if clock else datetime.now(timezone.utc)


def _reason(actor, reason):
    if (not isinstance(actor, str) or not 1 <= len(actor) <= 160 or not isinstance(reason, str)
            or not 1 <= len(reason.strip()) <= 2000 or any(ord(c) < 32 for c in actor + reason)):
        raise LinkConflict('workstations_link_reason_required')
    return reason.strip()


def _aliases(device):
    return device_aliases(device)


def _context(db, device_key, source_revision, now):
    snapshot = db.get(SourceSnapshot, 'reconciliation', populate_existing=True)
    if (snapshot is None or snapshot.generation != source_revision or not timedelta(0) <= now - snapshot.observed_at <= MAX_AGE
            or snapshot.inventory_revision != projection_epoch(db)):
        raise LinkConflict('workstations_link_source_changed')
    reasons = coherence_reasons(db, snapshot, now)
    if reasons:
        raise LinkConflict('workstations_link_source_unavailable' if any(code in reasons for code in
            ('source_unavailable', 'refresh_in_progress')) else 'workstations_link_source_changed')
    sources = {}
    for name, generation in snapshot.data_json['generations'].items():
        source = db.get(SourceSnapshot, name, populate_existing=True)
        sources[name] = source.data_json
    device = next((row for row in snapshot.data_json['devices'] if row['device_key'] == device_key), None)
    if device is None or device.get('identity_state') == 'ambiguous' or device.get('employee_binding_state') == 'ambiguous':
        raise LinkConflict('workstations_link_identity_ambiguous')
    if not device_key.startswith(('machine:', 'inventory:', 'mac:', 'ad:')):
        raise LinkConflict('workstations_link_identity_ambiguous')
    card = db.get(InventoryAsset, device['inventory_asset_id'], populate_existing=True) if device.get('inventory_asset_id') else None
    if device.get('inventory_asset_id') and (card is None or card.deleted_at is not None or card.manual_revision != device['inventory_revision']):
        raise LinkConflict('workstations_link_inventory_changed')
    return snapshot, device, sources


def _active(db, device):
    return list(db.scalars(select(DirectoryLink).where(DirectoryLink.device_key.in_(_aliases(device)),
        DirectoryLink.status == 'confirmed', DirectoryLink.ended_at.is_(None)).execution_options(populate_existing=True)))


def _relationship_revision(db, device):
    rows = db.execute(select(DirectoryLink.id, DirectoryLink.revision, DirectoryLink.status).where(
        DirectoryLink.device_key.in_(_aliases(device)), DirectoryLink.status.in_(('confirmed', 'ended'))).order_by(DirectoryLink.id))
    return fingerprint([list(row) for row in rows])


def _identity(rows, guid, *, usable=False):
    matches = [row for row in rows if row['object_guid'] == guid]
    if len(matches) != 1 or usable and matches[0]['state'] != 'enabled':
        raise LinkConflict('workstations_link_directory_changed')
    return matches[0]


def _native(assignment, user):
    if assignment and (assignment.get('object_guid') != user['object_guid'] or assignment.get('object_sid') != user['object_sid']
                       or assignment.get('result') not in ('successful', 'degraded')):
        raise LinkConflict('workstations_link_protected_assignment')


def public_link(row):
    return {'id': row.id, 'device_key': row.device_key, 'status': row.status, 'revision': row.revision,
        'source_revision': row.source_revision, 'expires_at': row.expires_at.isoformat() if row.expires_at else None,
        'user': copy.deepcopy(row.evidence_json.get('user')), 'computer': copy.deepcopy(row.evidence_json.get('computer')),
        'inventory_asset_id': row.inventory_asset_id, 'inventory_revision': row.expected_inventory_revision,
        'confirmed_at': row.confirmed_at.isoformat() if row.confirmed_at else None,
        'ended_at': row.ended_at.isoformat() if row.ended_at else None}


def preview_link(db, *, device_key, user_guid, computer_guid, source_revision, clock=None, actor=None):
    valid_uuid(user_guid)
    if computer_guid is not None:
        valid_uuid(computer_guid)
    snapshot, device, sources = _context(db, device_key, source_revision, _now(clock))
    user = _identity(sources['ad']['users'], user_guid, usable=True)
    computer = _identity(sources['ad']['computers'], computer_guid) if computer_guid else None
    if computer is not None and device.get('ad_computer_state') == 'ambiguous':
        raise LinkConflict('workstations_link_identity_ambiguous')
    _native(device.get('native_assignment'), user)
    if _active(db, device):
        raise LinkConflict('workstations_link_already_confirmed')
    row = DirectoryLink(device_key=device['device_key'], machine_uuid=device.get('machine_uuid'),
        inventory_asset_id=device.get('inventory_asset_id'), network_keys_json=device.get('network_keys', []),
        user_guid=user_guid, user_sid=user['object_sid'], user_login=user['login'],
        computer_guid=computer_guid, computer_sid=computer['object_sid'] if computer else None,
        source_revision=source_revision, expected_inventory_revision=device.get('inventory_revision'),
        created_by=actor, created_at=_now(clock), expires_at=_now(clock) + timedelta(minutes=5),
        evidence_json={'user': user, 'computer': computer, 'device': device,
                       'inventory_epoch': snapshot.inventory_revision, 'native': device.get('native_assignment'),
                       'relationship_revision': _relationship_revision(db, device)})
    db.add(row); db.flush()
    return public_link(row)


def _claim_epoch(db, epoch):
    result = db.execute(update(InventoryNetworkProjectionVersion).where(InventoryNetworkProjectionVersion.id == 1,
        InventoryNetworkProjectionVersion.version == epoch).values(version=epoch))
    if result.rowcount != 1:
        raise LinkConflict('workstations_link_inventory_changed')


def confirm_link(db, *, preview_id, expected_revision, actor, reason, client=None, clock=None):
    reason, now = _reason(actor, reason), _now(clock)
    row = db.get(DirectoryLink, valid_uuid(preview_id), populate_existing=True)
    if (row is None or row.status != 'preview' or type(expected_revision) is not int or row.revision != expected_revision
            or row.expires_at is None or now >= row.expires_at or row.created_by not in (None, actor)):
        raise LinkConflict('workstations_link_preview_changed')
    client = client or WorkstationsClient()
    for kind, guid, sid in (('user', row.user_guid, row.user_sid), ('computer', row.computer_guid, row.computer_sid)):
        if guid is None:
            continue
        live = client.call('directory.identity', {'kind': kind, 'object_guid': guid}, request_id=str(uuid.uuid4())).get('identity')
        if (not live or live.get('object_guid') != guid or live.get('object_sid') != sid
                or kind == 'user' and live.get('state') != 'enabled'):
            raise LinkConflict('workstations_link_directory_changed')
    native = client.call('assignments.show', {'machine_uuid': row.machine_uuid}, request_id=str(uuid.uuid4())).get('assignment') if row.machine_uuid else None
    _native(native, row.evidence_json['user'])
    if fingerprint(native) != fingerprint(row.evidence_json['native']):
        raise LinkConflict('workstations_link_protected_assignment')
    try:
        _claim_epoch(db, row.evidence_json['inventory_epoch'])
        if _now(clock) >= row.expires_at:
            raise LinkConflict('workstations_link_preview_changed')
        snapshot, device, sources = _context(db, row.device_key, row.source_revision, _now(clock))
        if fingerprint(device) != fingerprint(row.evidence_json['device']) or _active(db, device):
            raise LinkConflict('workstations_link_preview_changed')
        if row.evidence_json.get('relationship_revision') != _relationship_revision(db, device):
            raise LinkConflict('workstations_link_preview_changed')
        if row.computer_guid and db.scalar(select(DirectoryLink.id).where(DirectoryLink.computer_guid == row.computer_guid,
                DirectoryLink.status == 'confirmed', DirectoryLink.ended_at.is_(None)).limit(1)):
            raise LinkConflict('workstations_link_computer_already_confirmed')
        _identity(sources['ad']['users'], row.user_guid, usable=True)
        changed = db.execute(update(DirectoryLink).where(DirectoryLink.id == row.id, DirectoryLink.status == 'preview',
            DirectoryLink.revision == expected_revision).values(status='confirmed', revision=expected_revision + 1,
                confirmed_at=_now(clock), reason=reason).execution_options(synchronize_session=False)).rowcount
        if changed != 1:
            raise LinkConflict('workstations_link_preview_changed')
        db.flush(); db.refresh(row)
    except (IntegrityError, OperationalError):
        raise LinkConflict('workstations_link_concurrent_change') from None
    return public_link(row)


def end_link(db, *, link_id, expected_revision, actor, reason, clock=None):
    reason = _reason(actor, reason)
    if type(expected_revision) is not int or expected_revision < 1:
        raise LinkConflict('workstations_link_revision_required')
    _claim_epoch(db, projection_epoch(db))
    row = db.get(DirectoryLink, valid_uuid(link_id), populate_existing=True)
    if row is None or row.status != 'confirmed' or row.ended_at is not None or row.revision != expected_revision:
        raise LinkConflict('workstations_link_concurrent_change')
    changed = db.execute(update(DirectoryLink).where(DirectoryLink.id == row.id, DirectoryLink.status == 'confirmed',
        DirectoryLink.revision == expected_revision).values(status='ended', revision=expected_revision + 1,
            ended_at=_now(clock), ended_by=actor, end_reason=reason).execution_options(synchronize_session=False)).rowcount
    if changed != 1:
        raise LinkConflict('workstations_link_concurrent_change')
    db.flush(); db.refresh(row)
    return public_link(row)
