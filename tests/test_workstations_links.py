from __future__ import annotations

import copy
import uuid
from datetime import timedelta

import pytest
from sqlalchemy import select

from test_workstations_reconcile import database, run, Client, NOW, MACHINE, USER, COMPUTER


class Live(Client):
    def call(self, operation, parameters, **kwargs):
        if operation == 'directory.identity':
            rows = self.ad['users' if parameters['kind'] == 'user' else 'computers']
            return {'identity': next((copy.deepcopy(row) for row in rows if row['object_guid'] == parameters['object_guid']), None)}
        if operation == 'assignments.show':
            return {'assignment': self.machines[0].get('domain_assignment')}
        return super().call(operation, parameters, **kwargs)


@pytest.fixture
def ready(database, tmp_path):
    from app.workstations.models import SourceSnapshot
    assert run(database, tmp_path)['status'] == 'success'
    with database() as db:
        revision = db.get(SourceSnapshot, 'reconciliation').generation
    return database, revision


def preview(ready, **changes):
    from app.workstations.links import preview_link
    factory, revision = ready
    with factory() as db:
        result = preview_link(db, device_key='machine:' + MACHINE, user_guid=USER, computer_guid=COMPUTER,
                              source_revision=revision, clock=lambda: NOW, **changes)
        db.commit()
        return result


def confirm(ready, value, **changes):
    from app.workstations.links import confirm_link
    factory, _ = ready
    with factory() as db:
        result = confirm_link(db, preview_id=value['id'], expected_revision=value['revision'], actor='operator:synthetic',
            reason='Compared stable identities', clock=lambda: NOW, client=changes.pop('client', Live()), **changes)
        db.commit()
        return result


def test_explicit_confirmation_and_end_keep_history_without_controller_assignment(ready):
    from app.workstations.links import end_link
    from app.workstations.models import DirectoryLink
    value = preview(ready)
    assert value['status'] == 'preview' and value['user']['object_guid'] == USER
    confirmed = confirm(ready, value)
    assert confirmed['status'] == 'confirmed' and confirmed['revision'] == 2
    with ready[0]() as db:
        ended = end_link(db, link_id=value['id'], expected_revision=2, actor='operator:synthetic', reason='Retired link', clock=lambda: NOW)
        db.commit()
        assert ended['status'] == 'ended' and ended['revision'] == 3
        row = db.get(DirectoryLink, value['id'])
        assert row.confirmed_at and row.ended_at and row.reason and row.end_reason


@pytest.mark.parametrize('change', ['sid', 'deleted', 'disabled', 'computer_sid', 'native'])
def test_live_changed_identity_or_protected_assignment_refuses_confirmation(ready, change):
    from app.workstations.links import LinkConflict
    value, client = preview(ready), Live()
    if change == 'sid': client.ad['users'][0]['object_sid'] += '-99'
    if change == 'deleted': client.ad['users'] = []
    if change == 'disabled': client.ad['users'][0]['state'] = 'disabled'
    if change == 'computer_sid': client.ad['computers'][0]['object_sid'] += '-99'
    if change == 'native': client.machines[0]['domain_assignment'] = dict(object_guid=str(uuid.uuid4()), object_sid='S-1-5-21-9', result='successful')
    with pytest.raises(LinkConflict): confirm(ready, value, client=client)


def test_existing_employee_cannot_be_replaced_or_duplicate_confirmed(ready):
    from app.workstations.links import LinkConflict
    first, second = preview(ready), preview(ready)
    confirm(ready, first)
    with pytest.raises(LinkConflict): confirm(ready, second)
    with pytest.raises(LinkConflict): preview(ready)


@pytest.mark.parametrize('change', ['stale', 'generation', 'ambiguous', 'disabled', 'epoch'])
def test_changed_source_or_inventory_prevents_preview(ready, change):
    from app.workstations.links import LinkConflict
    from app.workstations.models import SourceSnapshot
    from app.inventory.models import InventoryNetworkProjectionVersion
    with ready[0]() as db:
        row = db.get(SourceSnapshot, 'reconciliation')
        payload = copy.deepcopy(row.data_json)
        if change == 'stale': row.observed_at = NOW - timedelta(minutes=16)
        if change == 'generation': row.generation = 'd' * 64
        if change == 'ambiguous': payload['devices'][0]['identity_state'] = 'ambiguous'
        if change == 'disabled':
            ad = db.get(SourceSnapshot, 'ad'); data = copy.deepcopy(ad.data_json)
            data['users'][0]['state'] = 'disabled'; ad.data_json = data
        if change == 'epoch': db.get(InventoryNetworkProjectionVersion, 1).version += 1
        row.data_json = payload
        db.commit()
    with pytest.raises(LinkConflict): preview(ready)


def test_preview_expiry_and_revision_are_required(ready):
    from app.workstations.links import confirm_link, LinkConflict
    value = preview(ready)
    with ready[0]() as db:
        with pytest.raises(LinkConflict):
            confirm_link(db, preview_id=value['id'], expected_revision=9, actor='synthetic', reason='Compare', client=Live(), clock=lambda: NOW)
    with ready[0]() as db:
        with pytest.raises(LinkConflict):
            confirm_link(db, preview_id=value['id'], expected_revision=1, actor='synthetic', reason='Compare', client=Live(), clock=lambda: NOW + timedelta(minutes=6))


def test_homonyms_are_selected_by_guid_and_one_employee_can_have_multiple_devices(database, tmp_path):
    from app.workstations.models import SourceSnapshot
    from app.workstations.links import preview_link
    client = Live()
    second = str(uuid.UUID(int=4444))
    client.ad['users'].append(dict(client.ad['users'][0], object_guid=second, object_sid='S-1-5-21-4', login='other'))
    client.machines.append(dict(client.machines[0], uuid=str(uuid.UUID(int=5555)), mac='02:00:00:00:00:55'))
    assert run(database, tmp_path, client=client)['status'] == 'success'
    with database() as db:
        revision = db.get(SourceSnapshot, 'reconciliation').generation
        result = preview_link(db, device_key='machine:' + MACHINE, user_guid=second, computer_guid=None, source_revision=revision, clock=lambda: NOW)
        assert result['user']['login'] == 'other'
        result2 = preview_link(db, device_key='machine:' + client.machines[1]['uuid'], user_guid=second, computer_guid=None, source_revision=revision, clock=lambda: NOW)
        assert result2['user']['object_guid'] == second


def test_refresh_preserves_confirmed_employee_and_records_disabled_discrepancy(ready, tmp_path):
    from app.workstations.models import DirectoryLink, SourceSnapshot
    value = preview(ready)
    confirm(ready, value)
    client = Live(); client.ad['users'][0]['state'] = 'disabled'
    assert run(ready[0], tmp_path, client=client)['status'] == 'success'
    with ready[0]() as db:
        assert db.get(DirectoryLink, value['id']).status == 'confirmed'
        assert any(row['code'] == 'employee_unusable' for row in db.get(SourceSnapshot, 'reconciliation').data_json['findings'])


def test_confirmation_cannot_finish_after_preview_expired_during_live_lookup(ready):
    from app.workstations.links import confirm_link, LinkConflict
    value, clock = preview(ready), [NOW]
    class Slow(Live):
        def call(self, *args, **kwargs):
            clock[0] = NOW + timedelta(minutes=6)
            return super().call(*args, **kwargs)
    with ready[0]() as db:
        with pytest.raises(LinkConflict):
            confirm_link(db, preview_id=value['id'], expected_revision=1, actor='synthetic', reason='Compared', client=Slow(), clock=lambda: clock[0])


def test_same_employee_several_pcs_but_one_computer_object_cannot_bind_twice(database, tmp_path):
    from app.workstations.links import preview_link, confirm_link, LinkConflict
    from app.workstations.models import SourceSnapshot
    client = Live(); other = str(uuid.UUID(int=5555))
    client.machines.append(dict(client.machines[0], uuid=other, mac='02:00:00:00:00:55'))
    assert run(database, tmp_path, client=client)['status'] == 'success'
    with database() as db:
        revision = db.get(SourceSnapshot, 'reconciliation').generation
        first = preview_link(db, device_key='machine:' + MACHINE, user_guid=USER, computer_guid=COMPUTER, source_revision=revision, clock=lambda: NOW)
        second = preview_link(db, device_key='machine:' + other, user_guid=USER, computer_guid=COMPUTER, source_revision=revision, clock=lambda: NOW)
        db.commit()
    confirm((database, revision), first, client=client)
    with pytest.raises(LinkConflict): confirm((database, revision), second, client=client)
    with database() as db:
        third = preview_link(db, device_key='machine:' + other, user_guid=USER, computer_guid=None, source_revision=revision, clock=lambda: NOW)
        db.commit()
    assert confirm((database, revision), third, client=client)['status'] == 'confirmed'


def test_deleted_inventory_card_refuses_pending_confirmation(database, tmp_path):
    from app.inventory.models import InventoryAsset, InventoryAssetType, InventoryNetctlBinding, InventoryExternalBindingStatus
    from app.workstations.links import preview_link, LinkConflict
    from app.workstations.models import SourceSnapshot
    from test_workstations_reconcile import MAC
    with database() as db:
        card = InventoryAsset(asset_type=InventoryAssetType.PC, custom_name='Synthetic')
        db.add(card); db.flush(); card_id = card.id
        db.add(InventoryNetctlBinding(asset_id=card.id, network_key='mac:' + MAC, status=InventoryExternalBindingStatus.CONFIRMED, created_by='synthetic'))
        db.commit()
    assert run(database, tmp_path)['status'] == 'success'
    with database() as db:
        revision = db.get(SourceSnapshot, 'reconciliation').generation
        value = preview_link(db, device_key='machine:' + MACHINE, user_guid=USER, computer_guid=None, source_revision=revision, clock=lambda: NOW)
        db.commit()
    with database() as db:
        db.get(InventoryAsset, card_id).deleted_at = NOW
        db.commit()
    with pytest.raises(LinkConflict): confirm((database, revision), value)


def test_preview_cannot_survive_an_intervening_confirmation_and_end(ready):
    from app.workstations.links import end_link, LinkConflict
    first, old_preview = preview(ready), preview(ready)
    confirm(ready, first)
    with ready[0]() as db:
        end_link(db, link_id=first['id'], expected_revision=2, actor='synthetic', reason='Compared again', clock=lambda: NOW)
        db.commit()
    with pytest.raises(LinkConflict): confirm(ready, old_preview)
