from datetime import datetime, timezone

import pytest
from tests.test_inventory_api import _client


def fixture(tmp_path, monkeypatch):
    client, headers = _client(tmp_path, monkeypatch)
    card = client.post('/api/v1/inventory/assets', headers=headers, json={'asset_type':'PC',
        'identifiers':[{'identifier_type':'mac','value':'02:00:00:00:00:11'}]}).json()['data']
    return card


def host(mac='02:00:00:00:00:11', ip='192.0.2.11'):
    return {'device_key':'mac:'+mac,'mac':mac,'ip':ip,'hostname':'synthetic','status':'online'}


def test_confirmed_network_identity_survives_ip_change_and_reuse(tmp_path, monkeypatch):
    card = fixture(tmp_path, monkeypatch)
    from app.db import get_sessionmaker
    from app.inventory.netctl_bindings import refresh_candidates, confirm, active_for_key
    from app.inventory.models import InventoryAsset
    now = datetime.now(timezone.utc)
    with get_sessionmaker()() as db:
        refresh_candidates(db,[host()],snapshot_id=1,observed_at=now)
        assert active_for_key(db,host()['device_key']) is None
        asset = db.get(InventoryAsset, card['id'])
        row = confirm(db, host()['device_key'], asset.id, expected_revision=asset.manual_revision,
            actor='synthetic', reason='Compared physical card', hosts=[host()])
        db.commit()
        original = row.id
        refresh_candidates(db,[host(ip='192.0.2.22'),host('02:00:00:00:00:99')],snapshot_id=2,observed_at=now)
        db.commit()
        linked = active_for_key(db,host()['device_key'])
        assert linked.id == original and linked.asset_id == card['id']
        assert linked.observation_json['ip'] == '192.0.2.22'
        assert active_for_key(db,host('02:00:00:00:00:99')['device_key']) is None


def test_multiple_interfaces_allowed_but_network_key_cannot_have_two_cards(tmp_path, monkeypatch):
    card = fixture(tmp_path, monkeypatch)
    from app.db import get_sessionmaker
    from app.inventory.models import InventoryAsset, InventoryAssetType
    from app.inventory.service import InventoryService
    from app.inventory.netctl_bindings import confirm, NetctlBindingConflict
    hosts = [host(),host('02:00:00:00:00:22',ip='192.0.2.22')]
    with get_sessionmaker()() as db:
        asset = db.get(InventoryAsset, card['id'])
        for row in hosts:
            db.refresh(asset)
            confirm(db,row['device_key'],asset.id,expected_revision=asset.manual_revision,actor='synthetic',reason='Compared second interface',hosts=hosts)
        db.commit()
        second = InventoryService().create_asset(db,InventoryAssetType.PC)
        db.commit()
        with pytest.raises(NetctlBindingConflict):
            confirm(db,hosts[0]['device_key'],second.id,expected_revision=second.manual_revision,actor='synthetic',reason='Another card',hosts=hosts)
        db.rollback()


@pytest.mark.parametrize('row',[
    {'device_key':'ip:192.0.2.11','ip':'192.0.2.11'},
    {'device_key':'legacy-host:1','ip':'192.0.2.11'},
    {'device_key':'mac:02:00:00:00:00:11','mac':'02:00:00:00:00:99','ip':'192.0.2.11'},
])
def test_weak_or_inconsistent_identity_cannot_be_confirmed(tmp_path, monkeypatch, row):
    card = fixture(tmp_path, monkeypatch)
    from app.db import get_sessionmaker
    from app.inventory.netctl_bindings import confirm, NetctlBindingConflict
    with get_sessionmaker()() as db:
        with pytest.raises(NetctlBindingConflict):
            confirm(db,row['device_key'],card['id'],expected_revision=card['manual_revision'],
                actor='synthetic',reason='Compare',hosts=[row])


def test_delete_ends_network_binding_restore_does_not_resurrect(tmp_path, monkeypatch):
    card = fixture(tmp_path, monkeypatch)
    from app.db import get_sessionmaker
    from app.inventory.models import InventoryAsset, InventoryNetctlBinding, InventoryExternalBindingStatus as Status
    from app.inventory.netctl_bindings import confirm, active_for_key
    from app.inventory.lifecycle import soft_delete, restore
    from sqlalchemy import text
    from sqlalchemy.exc import IntegrityError
    with get_sessionmaker()() as db:
        asset = db.get(InventoryAsset, card['id'])
        binding = confirm(db,host()['device_key'],asset.id,expected_revision=asset.manual_revision,
            actor='synthetic',reason='Physical comparison',hosts=[host()])
        db.commit()
        db.refresh(asset)
        soft_delete(db,asset.id,expected_revision=asset.manual_revision,actor='synthetic',reason='Retired')
        db.commit()
        assert binding.status == Status.ENDED and binding.end_reason == 'inventory_deleted'
        assert active_for_key(db,host()['device_key']) is None
        with pytest.raises(IntegrityError):
            db.execute(text("UPDATE inventory_netctl_bindings SET ended_at=NULL,status='confirmed' WHERE id=:id"), {'id':binding.id})
        db.rollback()
        db.refresh(asset)
        restore(db,asset.id,expected_revision=asset.manual_revision,actor='synthetic')
        db.commit()
        assert active_for_key(db,host()['device_key']) is None
        assert db.get(InventoryNetctlBinding,binding.id).ended_at is not None


def test_rejection_is_not_reoffered_on_ip_change_and_requires_explicit_reconsideration(tmp_path, monkeypatch):
    card = fixture(tmp_path, monkeypatch)
    from app.db import get_sessionmaker
    from app.inventory.models import InventoryAsset
    from app.inventory.netctl_bindings import refresh_candidates, confirm, end, NetctlBindingConflict
    now = datetime.now(timezone.utc)
    with get_sessionmaker()() as db:
        asset = db.get(InventoryAsset,card['id'])
        candidate = refresh_candidates(db,[host()],snapshot_id=1,observed_at=now)[0]
        db.commit()
        db.refresh(asset)
        end(db,candidate.id,expected_revision=asset.manual_revision,actor='synthetic',reason='Different physical device',reject=True)
        db.commit()
        assert refresh_candidates(db,[host(ip='192.0.2.22')],snapshot_id=2,observed_at=now) == []
        db.refresh(asset)
        with pytest.raises(NetctlBindingConflict):
            confirm(db,host()['device_key'],asset.id,expected_revision=asset.manual_revision,
                actor='synthetic',reason='Compare again',hosts=[host()])
        db.rollback()
        db.refresh(asset)
        row = confirm(db,host()['device_key'],asset.id,expected_revision=asset.manual_revision,
            actor='synthetic',reason='Explicit physical reinspection',hosts=[host()],reconsider=True)
        db.commit()
        assert row.id != candidate.id


def test_observations_do_not_change_manual_revision_but_binding_decisions_do(tmp_path, monkeypatch):
    card = fixture(tmp_path, monkeypatch)
    from app.db import get_sessionmaker
    from app.inventory.models import InventoryAsset
    from app.inventory.netctl_bindings import refresh_candidates, confirm
    from app.inventory.revision import InventoryRevisionRequired
    now = datetime.now(timezone.utc)
    with get_sessionmaker()() as db:
        asset = db.get(InventoryAsset,card['id'])
        before = asset.manual_revision
        refresh_candidates(db,[host()],snapshot_id=1,observed_at=now)
        db.commit()
        db.refresh(asset)
        assert asset.manual_revision == before
        confirm(db,host()['device_key'],asset.id,expected_revision=before,actor='synthetic',reason='Compare',hosts=[host()])
        db.commit()
        db.refresh(asset)
        decided = asset.manual_revision
        assert decided > before
        refresh_candidates(db,[host(ip='192.0.2.22')],snapshot_id=2,observed_at=now)
        db.commit()
        db.refresh(asset)
        assert asset.manual_revision == decided
        with pytest.raises(InventoryRevisionRequired):
            confirm(db,host()['device_key'],asset.id,expected_revision=None,actor='synthetic',reason='Repeat',hosts=[host()])


def test_duplicate_mac_cards_and_source_collisions_cannot_be_confirmed(tmp_path, monkeypatch):
    card = fixture(tmp_path, monkeypatch)
    from app.db import get_sessionmaker
    from app.inventory.models import InventoryAsset, InventoryAssetType
    from app.inventory.service import InventoryService
    from app.inventory.netctl_bindings import confirm, NetctlBindingConflict
    with get_sessionmaker()() as db:
        asset = db.get(InventoryAsset,card['id'])
        with pytest.raises(NetctlBindingConflict):
            confirm(db,host()['device_key'],asset.id,expected_revision=asset.manual_revision,
                actor='synthetic',reason='Compare',hosts=[host()],conflict_keys=[host()['device_key']])
        second = InventoryService().create_asset(db,InventoryAssetType.PC)
        from app.inventory.models import InventoryAssetIdentifier, InventoryIdentifierType, InventoryObservationSource
        db.add(InventoryAssetIdentifier(asset_id=second.id,identifier_type=InventoryIdentifierType.MAC,
            value=host()['mac'],normalized_value=host()['mac'],source=InventoryObservationSource.MANUAL,is_current=True))
        db.commit()
        with pytest.raises(NetctlBindingConflict):
            confirm(db,host()['device_key'],asset.id,expected_revision=asset.manual_revision,
                actor='synthetic',reason='Compare',hosts=[host()])


def test_concurrent_confirmation_has_one_winner(tmp_path, monkeypatch):
    card = fixture(tmp_path, monkeypatch)
    from app.db import get_sessionmaker
    from app.inventory.models import InventoryAsset, InventoryAssetType, InventoryNetctlBinding, InventoryExternalBindingStatus as Status
    from app.inventory.service import InventoryService
    from app.inventory.netctl_bindings import confirm, NetctlBindingConflict
    from concurrent.futures import ThreadPoolExecutor
    from threading import Barrier
    from sqlalchemy import select, func
    with get_sessionmaker()() as db:
        second = InventoryService().create_asset(db,InventoryAssetType.PC)
        db.commit()
        second_id = second.id
    barrier = Barrier(2)
    def bind(asset_id):
        with get_sessionmaker()() as db:
            asset = db.get(InventoryAsset,asset_id)
            barrier.wait(timeout=5)
            try:
                confirm(db,host()['device_key'],asset.id,expected_revision=asset.manual_revision,
                    actor='synthetic',reason='Compared physical interface',hosts=[host()])
                db.commit()
                return 'confirmed'
            except NetctlBindingConflict:
                db.rollback()
                return 'conflict'
    with ThreadPoolExecutor(max_workers=2) as pool:
        outcomes = list(pool.map(bind,[card['id'],second_id]))
    assert sorted(outcomes) == ['confirmed','conflict']
    with get_sessionmaker()() as db:
        assert db.scalar(select(func.count()).select_from(InventoryNetctlBinding).where(
            InventoryNetctlBinding.status == Status.CONFIRMED,InventoryNetctlBinding.ended_at.is_(None))) == 1


def test_manual_end_is_not_automatically_reoffered(tmp_path, monkeypatch):
    card = fixture(tmp_path, monkeypatch)
    from app.db import get_sessionmaker
    from app.inventory.models import InventoryAsset
    from app.inventory.netctl_bindings import refresh_candidates, confirm, end
    now = datetime.now(timezone.utc)
    with get_sessionmaker()() as db:
        asset = db.get(InventoryAsset,card['id'])
        row = confirm(db,host()['device_key'],asset.id,expected_revision=asset.manual_revision,
            actor='synthetic',reason='Compare',hosts=[host()])
        db.commit()
        db.refresh(asset)
        end(db,row.id,expected_revision=asset.manual_revision,actor='synthetic',reason='Manual detach')
        db.commit()
        assert refresh_candidates(db,[host()],snapshot_id=2,observed_at=now) == []


def test_stale_session_does_not_refresh_deleted_card_history(tmp_path, monkeypatch):
    card = fixture(tmp_path, monkeypatch)
    from app.db import get_sessionmaker
    from app.inventory.models import InventoryAsset, InventoryNetctlBinding
    from app.inventory.netctl_bindings import refresh_candidates, confirm
    from app.inventory.lifecycle import soft_delete
    now = datetime.now(timezone.utc)
    with get_sessionmaker()() as stale:
        asset = stale.get(InventoryAsset,card['id'])
        row = confirm(stale,host()['device_key'],asset.id,expected_revision=asset.manual_revision,
            actor='synthetic',reason='Compare',hosts=[host()],snapshot_id=1,observed_at=now)
        stale.commit()
        binding_id = row.id
        with get_sessionmaker()() as fresh:
            current = fresh.get(InventoryAsset,card['id'])
            soft_delete(fresh,current.id,expected_revision=current.manual_revision,actor='synthetic',reason='Retired')
            fresh.commit()
        refresh_candidates(stale,[host(ip='192.0.2.55')],snapshot_id=3,observed_at=now)
        stale.commit()
    with get_sessionmaker()() as db:
        ended = db.get(InventoryNetctlBinding,binding_id)
        assert ended.ended_at is not None and ended.observed_snapshot_id == 1
        assert ended.observation_json['ip'] == '192.0.2.11'


def test_delete_between_refresh_read_and_flush_preserves_ended_observation(tmp_path, monkeypatch):
    card = fixture(tmp_path, monkeypatch)
    from app.db import get_sessionmaker
    from app.inventory.models import InventoryAsset, InventoryNetctlBinding
    from app.inventory.netctl_bindings import refresh_candidates, confirm
    from app.inventory.lifecycle import soft_delete
    from sqlalchemy.exc import IntegrityError
    now = datetime.now(timezone.utc)
    with get_sessionmaker()() as db:
        asset = db.get(InventoryAsset,card['id'])
        row = confirm(db,host()['device_key'],asset.id,expected_revision=asset.manual_revision,
            actor='synthetic',reason='Compare',hosts=[host()],snapshot_id=1,observed_at=now)
        db.commit()
        binding_id = row.id
        original_flush = db.flush
        raced = False
        def flush(*args, **kwargs):
            nonlocal raced
            if not raced and any(isinstance(item,InventoryNetctlBinding) for item in db.dirty):
                raced = True
                with get_sessionmaker()() as winner:
                    current = winner.get(InventoryAsset,card['id'])
                    soft_delete(winner,current.id,expected_revision=current.manual_revision,actor='synthetic',reason='Retired')
                    winner.commit()
            return original_flush(*args, **kwargs)
        monkeypatch.setattr(db,'flush',flush)
        with pytest.raises(IntegrityError,match='historical'):
            refresh_candidates(db,[host(ip='192.0.2.66')],snapshot_id=8,observed_at=now)
        db.rollback()
        assert raced
    with get_sessionmaker()() as db:
        ended = db.get(InventoryNetctlBinding,binding_id)
        assert ended.ended_at is not None and ended.observed_snapshot_id == 1
        assert ended.observation_json['ip'] == '192.0.2.11'
