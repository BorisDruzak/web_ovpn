"""Historical deletion must preserve physical cards and block resurrection."""
from datetime import datetime, timezone

import pytest
from sqlalchemy import func, select
from sqlalchemy.exc import IntegrityError

from tests.test_inventory_api import _client


def workplace(tmp_path, monkeypatch):
    client, headers = _client(tmp_path, monkeypatch)
    location = client.post('/api/v1/inventory/locations', headers=headers, json={'name':'Synthetic'}).json()['data']
    result = client.post('/api/v1/inventory/workplaces', headers=headers, json={
        'location_id':location['id'], 'pc':{'custom_name':'Synthetic PC', 'details':{'ram_gb':8},
            'identifiers':[{'identifier_type':'mac','value':'02:00:00:00:00:11'}]},
        'children':[{'asset_type':'MONITOR'}, {'asset_type':'MONITOR'}, {'asset_type':'UPS'}]})
    assert result.status_code == 201, result.text
    return client, headers, result.json()['data']


def test_delete_restore_preserves_workplace_and_suppresses_reads(tmp_path, monkeypatch):
    client, headers, data = workplace(tmp_path, monkeypatch)
    from app.db import get_sessionmaker
    from app.inventory.service import InventoryService
    from app.inventory.models import InventoryAsset, InventoryAssetRelation, InventoryObservationSource
    from app.inventory.lifecycle import historical_asset, soft_delete, restore
    pc = data['pc']['id']
    with get_sessionmaker()() as db:
        asset = db.get(InventoryAsset, pc)
        InventoryService().record_observation(db, asset_id=pc, source=InventoryObservationSource.NETCTL, data={'synthetic':True})
        deleted, changed = soft_delete(db, pc, expected_revision=asset.manual_revision, actor='synthetic', reason='Duplicate entry')
        db.commit()
        assert changed and deleted.deleted_by == 'synthetic' and deleted.deletion_reason == 'Duplicate entry'
    with get_sessionmaker()() as db:
        assert db.get(InventoryAsset, pc) is None
        assert db.scalar(select(func.count()).select_from(InventoryAsset)) == 3
        assert len(InventoryService().location_tree(db, data['pc']['location_id'])['top_level_assets']) == 3
        original = historical_asset(db, pc)
        assert InventoryService().details_for(db, original)['ram_gb'] == 8
        relations = list(db.scalars(select(InventoryAssetRelation)))
        assert len(relations) == 3 and all(row.ended_at is not None for row in relations)
        restored, changed = restore(db, pc, expected_revision=original.manual_revision, actor='synthetic')
        db.commit()
        assert changed and restored.id == pc
    with get_sessionmaker()() as db:
        assert db.get(InventoryAsset, pc) is not None
        assert all(row.ended_at is not None for row in db.scalars(select(InventoryAssetRelation)))
    assert client.get(f'/api/v1/inventory/assets/{pc}', headers=headers).status_code == 200


def test_delete_is_idempotent_but_stale_edit_and_binding_are_rejected(tmp_path, monkeypatch):
    _, _, data = workplace(tmp_path, monkeypatch)
    from app.db import get_sessionmaker
    from app.inventory.models import InventoryAsset, InventoryAssetRelation
    from app.inventory.lifecycle import soft_delete
    from app.inventory.revision import claim_revision, InventoryRevisionConflict
    pc = data['pc']['id']
    with get_sessionmaker()() as stale, get_sessionmaker()() as winner:
        old = stale.get(InventoryAsset, pc)
        _, changed = soft_delete(winner, pc, expected_revision=old.manual_revision, actor='synthetic', reason='Duplicate')
        winner.commit()
        assert changed
        with pytest.raises(InventoryRevisionConflict):
            claim_revision(stale, old, old.manual_revision)
        stale.rollback()
        _, repeated = soft_delete(winner, pc, expected_revision=old.manual_revision, actor='synthetic', reason='Duplicate')
        assert not repeated
        winner.commit()
    with get_sessionmaker()() as db:
        db.add(InventoryAssetRelation(parent_asset_id=pc, child_asset_id=data['children'][0]['id'], created_by='late-writer'))
        with pytest.raises(IntegrityError):
            db.commit()
        db.rollback()


def test_netctl_sync_and_endpoint_matching_ignore_deleted_cards(tmp_path, monkeypatch):
    _, _, data = workplace(tmp_path, monkeypatch)
    from app.db import get_sessionmaker
    from app.inventory.lifecycle import soft_delete, historical_asset
    from app.inventory.models import InventoryAsset
    from app.inventory.service import InventoryService
    from app.inventory.endpoint import InventoryEndpointService
    pc = data['pc']['id']
    with get_sessionmaker()() as db:
        asset = db.get(InventoryAsset, pc)
        soft_delete(db, pc, expected_revision=asset.manual_revision, actor='synthetic', reason='Duplicate')
        db.commit()
    with get_sessionmaker()() as db:
        result = InventoryService().reconcile_netctl_identifiers(db,
            [{'mac':'02:00:00:00:00:11','ip':'192.0.2.99','hostname':'new-observation'}], observed_at=datetime.now(timezone.utc))
        assert result.matched_assets == result.updated_assets == 0
        assert pc not in InventoryEndpointService._anchors(db)
        db.commit()
        assert historical_asset(db, pc).deleted_at is not None


def test_api_lifecycle_requires_capability_csrf_revision_and_keeps_id(tmp_path, monkeypatch):
    monkeypatch.setenv('OPENVPN_WEB_API_PERMISSIONS', 'inventory:read,inventory:write,inventory:delete')
    client, headers, data = workplace(tmp_path, monkeypatch)
    pc = data['pc']['id']
    path = f'/api/v1/inventory/assets/{pc}'
    revision = client.get(path, headers=headers).json()['data']['manual_revision']
    assert client.request('DELETE', path, headers={'Authorization':headers['Authorization']},
        json={'expected_revision':revision,'reason':'Duplicate'}).status_code == 400
    assert client.request('DELETE', path, headers=headers, json={'reason':'Duplicate'}).status_code == 428
    assert client.request('DELETE', path, headers=headers,
        json={'expected_revision':revision-1,'reason':'Duplicate'}).status_code == 409
    response = client.request('DELETE', path, headers=headers,
        json={'expected_revision':revision,'reason':'Duplicate'})
    assert response.status_code == 200, response.text
    assert client.get(path, headers=headers).status_code == 404
    assert pc not in {row['id'] for row in client.get('/api/v1/inventory/assets', headers=headers).json()['data']}
    history = client.get(f'/api/v1/inventory/deleted/{pc}', headers=headers)
    assert history.status_code == 200 and history.json()['data']['deletion_reason'] == 'Duplicate'
    assert client.request('DELETE', path, headers=headers,
        json={'expected_revision':revision,'reason':'Duplicate'}).status_code == 200
    assert client.request('DELETE', path, headers=headers, json={'reason':'Duplicate'}).status_code == 428
    restored = client.post(path+'/restore', headers=headers,
        json={'expected_revision':history.json()['data']['manual_revision']})
    assert restored.status_code == 200 and restored.json()['data']['id'] == pc
    assert client.post(path+'/restore', headers=headers, json={'expected_revision':revision}).status_code == 200
    assert client.post(path+'/restore', headers=headers, json={}).status_code == 428
    assert client.get(path, headers=headers).status_code == 200


def test_html_delete_confirmation_owner_permissions_and_restore(tmp_path, monkeypatch):
    client, headers, data = workplace(tmp_path, monkeypatch)
    from tests.test_inventory_web import _csrf, _revision
    pc = data['pc']['id']
    page = client.get(f'/inventory/assets/{pc}')
    assert 'Удалить устройство' in page.text
    payload = {'csrf_token':_csrf(page.text), 'expected_revision':_revision(page.text), 'reason':'Synthetic duplicate'}
    assert client.post(f'/inventory/assets/{pc}/delete', data=payload, follow_redirects=False).status_code == 400
    payload['confirmation'] = pc
    assert client.post(f'/inventory/assets/{pc}/delete', data=payload, follow_redirects=False).status_code == 303
    assert client.get(f'/inventory/assets/{pc}').status_code == 404
    history = client.get(f'/inventory/deleted/{pc}')
    assert history.status_code == 200 and 'Synthetic duplicate' in history.text
    assert 'Связи не восстанавливаются автоматически' in history.text
    from tests.test_panel_permissions import login_operator
    login_operator(client, permissions=['inventory:write'])
    assert client.get('/inventory/deleted').status_code == 403
    assert client.get(f'/inventory/deleted/{pc}').status_code == 403


def test_deleted_card_renders_preserved_netctl_history_without_source_reads(tmp_path, monkeypatch):
    client, _, data = workplace(tmp_path, monkeypatch)
    from app.db import get_sessionmaker
    from app.inventory.models import InventoryAsset
    from app.inventory.netctl_bindings import confirm
    from app.inventory.lifecycle import soft_delete, historical_asset, restore
    import app.inventory.network_links as network_links

    def forbidden(*args, **kwargs):
        raise AssertionError('Historical card must not read Netctl')

    monkeypatch.setattr(network_links, 'run_netctl', forbidden)
    pc = data['pc']['id']
    host = {'device_key':'mac:02:00:00:00:00:11', 'mac':'02:00:00:00:00:11',
        'ip':'192.0.2.111', 'hostname':'historical-synthetic-interface'}
    with get_sessionmaker()() as db:
        asset = db.get(InventoryAsset, pc)
        confirm(db, host['device_key'], pc, expected_revision=asset.manual_revision,
            actor='synthetic-confirm-author', reason='Physical comparison', hosts=[host])
        db.refresh(asset)
        soft_delete(db, pc, expected_revision=asset.manual_revision,
            actor='synthetic-delete-author', reason='Historical duplicate')
        db.commit()
    page = client.get(f'/inventory/deleted/{pc}')
    assert page.status_code == 200
    for value in ('Сетевые связи Netctl', host['device_key'], host['ip'], host['hostname'],
            'synthetic-confirm-author', 'synthetic-delete-author', 'Завершено'):
        assert value in page.text
    assert '/inventory/network-links?' not in page.text
    with get_sessionmaker()() as db:
        deleted = historical_asset(db, pc)
        restore(db, pc, expected_revision=deleted.manual_revision, actor='synthetic')
        db.commit()
    restored_page = client.get(f'/inventory/assets/{pc}')
    assert restored_page.status_code == 200
    assert host['device_key'] in restored_page.text and 'Завершено' in restored_page.text


def test_repeatable_lifecycle_upgrade_retains_old_card(tmp_path, monkeypatch):
    _, _, data = workplace(tmp_path, monkeypatch)
    from app.db import get_engine, init_db, get_sessionmaker
    from app.inventory.models import InventoryAsset
    from sqlalchemy import text
    engine = get_engine()
    with engine.begin() as connection:
        triggers = list(connection.scalars(text("SELECT name FROM sqlite_master WHERE type='trigger' AND sql LIKE '%deleted_at%'")))
        for name in triggers:
            connection.exec_driver_sql('DROP TRIGGER "' + name.replace('"','""') + '"')
        connection.exec_driver_sql('DROP INDEX ix_inventory_assets_deleted_at')
        for column in ('deleted_at','deleted_by','deletion_reason','restored_at','restored_by'):
            connection.exec_driver_sql(f'ALTER TABLE inventory_assets DROP COLUMN {column}')
    init_db()
    init_db()
    with get_sessionmaker()() as db:
        asset = db.get(InventoryAsset, data['pc']['id'])
        assert asset.deleted_at is None and asset.custom_name == 'Synthetic PC'
        assert db.scalar(select(func.count()).select_from(InventoryAsset)) == 4


def test_deleted_photo_urls_require_history_permission_and_preserve_file(tmp_path, monkeypatch):
    monkeypatch.setenv('INVENTORY_PHOTO_ROOT', str(tmp_path/'photos'))
    client, headers, data = workplace(tmp_path, monkeypatch)
    from tests.test_inventory_api import PNG_BYTES
    from app.db import get_sessionmaker
    from app.inventory.models import InventoryAsset
    from app.inventory.lifecycle import soft_delete
    pc = data['pc']['id']
    photo = client.post(f'/api/v1/inventory/assets/{pc}/photos', headers=headers,
        files={'photo':('synthetic.png',PNG_BYTES,'image/png')}).json()['data']
    with get_sessionmaker()() as db:
        asset = db.get(InventoryAsset, pc)
        soft_delete(db, pc, expected_revision=asset.manual_revision, actor='synthetic', reason='Duplicate')
        db.commit()
    assert client.get(f'/api/v1/inventory/photos/{photo["id"]}', headers=headers).status_code == 404
    assert client.get(f'/inventory/photos/{photo["id"]}').status_code == 404
    historical_url = f'/inventory/deleted/{pc}/photos/{photo["id"]}'
    assert client.get(historical_url).content == PNG_BYTES
    from tests.test_panel_permissions import login_operator
    login_operator(client, permissions=['inventory:write'])
    assert client.get(historical_url).status_code == 403
    assert list((tmp_path/'photos').rglob('*.png'))


def test_restore_does_not_take_reassigned_endpoint_binding(tmp_path, monkeypatch):
    _, _, data = workplace(tmp_path, monkeypatch)
    from app.db import get_sessionmaker
    from app.inventory.models import InventoryAsset, InventoryAssetType, InventoryExternalBinding, InventoryExternalBindingStatus as Status
    from app.inventory.service import InventoryService
    from app.inventory.lifecycle import soft_delete, historical_asset, restore
    with get_sessionmaker()() as db:
        asset = db.get(InventoryAsset, data['pc']['id'])
        now = datetime.now(timezone.utc)
        old = InventoryExternalBinding(asset_id=asset.id, source='endpoint_platform', external_id='Synthetic-Device',
            status=Status.CONFIRMED,binding_method='manual',confidence=100,created_by='synthetic',first_seen_at=now)
        db.add(old)
        db.commit()
        db.refresh(asset)
        soft_delete(db, asset.id, expected_revision=asset.manual_revision, actor='synthetic', reason='Duplicate')
        db.commit()
        assert old.ended_at is not None
        second = InventoryService().create_asset(db, InventoryAssetType.PC)
        new = InventoryExternalBinding(asset_id=second.id, source='endpoint_platform', external_id='Synthetic-Device',
            status=Status.CONFIRMED,binding_method='manual',confidence=100,created_by='synthetic',first_seen_at=now)
        db.add(new)
        db.commit()
        deleted = historical_asset(db, asset.id)
        restore(db, asset.id, expected_revision=deleted.manual_revision, actor='synthetic')
        db.commit()
        assert old.ended_at is not None and new.ended_at is None and new.asset_id == second.id


def test_concurrent_binding_cannot_survive_deletion(tmp_path, monkeypatch):
    _, _, data = workplace(tmp_path, monkeypatch)
    from app.db import get_sessionmaker
    from app.inventory.models import InventoryAsset, InventoryExternalBinding, InventoryExternalBindingStatus as Status
    from app.inventory.lifecycle import soft_delete, historical_asset
    from app.inventory.revision import InventoryRevisionConflict
    from concurrent.futures import ThreadPoolExecutor
    from threading import Barrier
    barrier = Barrier(2)
    pc = data['pc']['id']
    def delete():
        with get_sessionmaker()() as db:
            asset = db.get(InventoryAsset, pc)
            barrier.wait(timeout=5)
            try:
                soft_delete(db, pc, expected_revision=asset.manual_revision, actor='synthetic', reason='Duplicate')
                db.commit()
            except InventoryRevisionConflict:
                # A winning manual binding invalidates the old delete form.
                db.rollback()
    def bind():
        with get_sessionmaker()() as db:
            db.get(InventoryAsset, pc)
            barrier.wait(timeout=5)
            db.add(InventoryExternalBinding(asset_id=pc, source='endpoint_platform', external_id='Late-Synthetic',
                status=Status.CONFIRMED,binding_method='manual',confidence=100,created_by='synthetic',first_seen_at=datetime.now(timezone.utc)))
            try:
                db.commit()
            except IntegrityError:
                db.rollback()
    with ThreadPoolExecutor(max_workers=2) as pool:
        futures = [pool.submit(delete), pool.submit(bind)]
        for future in futures:
            future.result(timeout=10)
    with get_sessionmaker()() as db:
        current = historical_asset(db, pc)
        if current.deleted_at is None:
            # Explicitly compare the latest card after the race; never replay
            # the stale revision automatically in the application.
            soft_delete(db, pc, expected_revision=current.manual_revision, actor='synthetic', reason='Rechecked after binding')
            db.commit()
        assert historical_asset(db, pc).deleted_at is not None
        assert db.scalar(select(func.count()).select_from(InventoryExternalBinding).where(
            InventoryExternalBinding.asset_id == pc, InventoryExternalBinding.ended_at.is_(None))) == 0


def test_failed_delete_audit_rolls_back_card_and_relation_endings(tmp_path, monkeypatch):
    client, headers, data = workplace(tmp_path, monkeypatch)
    from tests.test_inventory_web import _csrf, _revision
    pc = data['pc']['id']
    page = client.get(f'/inventory/assets/{pc}')
    def failed_audit(*args, **kwargs):
        raise RuntimeError('synthetic audit failure')
    monkeypatch.setattr('app.inventory.web.write_audit', failed_audit)
    with pytest.raises(RuntimeError, match='synthetic audit failure'):
        client.post(f'/inventory/assets/{pc}/delete', data={'csrf_token':_csrf(page.text),
            'expected_revision':_revision(page.text),'confirmation':pc,'reason':'Synthetic duplicate'})
    from app.db import get_sessionmaker
    from app.inventory.models import InventoryAsset, InventoryAssetRelation
    with get_sessionmaker()() as db:
        assert db.get(InventoryAsset, pc).deleted_at is None
        assert all(row.ended_at is None for row in db.scalars(select(InventoryAssetRelation)))


def test_restore_missing_location_preserves_deleted_card(tmp_path, monkeypatch):
    _, _, data = workplace(tmp_path, monkeypatch)
    from app.db import get_sessionmaker
    from app.inventory.models import InventoryAsset, InventoryLocation
    from app.inventory.lifecycle import soft_delete, historical_asset, restore
    with get_sessionmaker()() as db:
        asset = db.get(InventoryAsset, data['pc']['id'])
        soft_delete(db, asset.id, expected_revision=asset.manual_revision, actor='synthetic', reason='Duplicate')
        db.commit()
        db.delete(db.get(InventoryLocation, asset.location_id))
        db.commit()
        with pytest.raises(ValueError, match='Локация недоступна'):
            restore(db, asset.id, expected_revision=asset.manual_revision, actor='synthetic')
        db.rollback()
        assert historical_asset(db, asset.id).deleted_at is not None


def photo_fixture(tmp_path, monkeypatch):
    monkeypatch.setenv('INVENTORY_PHOTO_ROOT', str(tmp_path/'photos'))
    client, headers, data = workplace(tmp_path, monkeypatch)
    from tests.test_inventory_api import PNG_BYTES
    pc = data['pc']['id']
    photo = client.post(f'/api/v1/inventory/assets/{pc}/photos', headers=headers,
        files={'photo':('synthetic.png',PNG_BYTES,'image/png')}).json()['data']
    return client, headers, pc, photo


def test_photo_delete_after_card_delete_preserves_file_and_row(tmp_path, monkeypatch):
    client, headers, pc, photo = photo_fixture(tmp_path, monkeypatch)
    from app.db import get_sessionmaker
    from app.inventory.models import InventoryAsset, InventoryAssetPhoto
    from app.inventory.lifecycle import soft_delete
    from sqlalchemy.orm import Session
    original = Session.get
    fired = False
    def interleaved(db, entity, identifier, *args, **kwargs):
        nonlocal fired
        result = original(db, entity, identifier, *args, **kwargs)
        if entity is InventoryAsset and identifier == pc and not fired:
            fired = True
            with get_sessionmaker()() as winner:
                soft_delete(winner, pc, expected_revision=result.manual_revision, actor='synthetic', reason='Duplicate')
                winner.commit()
        return result
    monkeypatch.setattr(Session, 'get', interleaved)
    result = client.delete(f'/api/v1/inventory/photos/{photo["id"]}', headers=headers)
    assert result.status_code == 409
    assert list((tmp_path/'photos').rglob('*.png'))
    with get_sessionmaker()() as db:
        assert db.get(InventoryAssetPhoto, photo['id']) is not None


def test_failed_photo_delete_audit_preserves_file_and_row(tmp_path, monkeypatch):
    client, headers, pc, photo = photo_fixture(tmp_path, monkeypatch)
    def failed_audit(*args, **kwargs):
        raise RuntimeError('synthetic photo audit failure')
    monkeypatch.setattr('app.inventory.api.write_audit', failed_audit)
    with pytest.raises(RuntimeError, match='synthetic photo audit failure'):
        client.delete(f'/api/v1/inventory/photos/{photo["id"]}', headers=headers)
    assert list((tmp_path/'photos').rglob('*.png'))
    from app.db import get_sessionmaker
    from app.inventory.models import InventoryAssetPhoto
    with get_sessionmaker()() as db:
        assert db.get(InventoryAssetPhoto, photo['id']) is not None
