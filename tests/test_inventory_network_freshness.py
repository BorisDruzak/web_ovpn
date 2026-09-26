from datetime import datetime,timedelta,timezone

import pytest
from sqlalchemy import event
from tests.test_inventory_netctl_bindings import fixture,host

NOW=datetime(2026,9,26,12,tzinfo=timezone.utc)


def setup_card(tmp_path,monkeypatch):
    card=fixture(tmp_path,monkeypatch)
    from app.db import get_sessionmaker
    from app.inventory.models import InventoryAsset,InventoryIdentifierSyncRun
    from app.inventory.netctl_bindings import confirm
    db=get_sessionmaker()()
    asset=db.get(InventoryAsset,card['id'])
    observed={**host(),'last_seen_at':NOW.isoformat(),'sources':['mikrotik_arp'],
        'availability':{'state':'seen','passive_evidence':['mikrotik_arp'],'reason':'passive_evidence','checked_at':NOW.isoformat()},'private':'DO_NOT_STORE'}
    binding=confirm(db,observed['device_key'],asset.id,expected_revision=asset.manual_revision,actor='synthetic',reason='Compared',hosts=[observed],snapshot_id=1,observed_at=NOW)
    db.add(InventoryIdentifierSyncRun(snapshot_id=1,snapshot_generated_at=NOW,status='success',started_at=NOW,finished_at=NOW))
    db.commit();db.refresh(asset)
    return db,asset,binding,observed


def test_saved_projection_source_available_and_query_count_no_live_call(tmp_path,monkeypatch):
    db,asset,binding,observed=setup_card(tmp_path,monkeypatch)
    from app.inventory.network_freshness import card_network_projection
    monkeypatch.setattr('app.netctl_client.run_netctl',lambda *a,**k:pytest.fail('No live read'))
    statements=[]
    event.listen(db.bind,'before_cursor_execute',lambda *args:statements.append(args[2]))
    projection=card_network_projection(db,asset.id,enabled=True,now=NOW)
    assert len([sql for sql in statements if sql.lstrip().upper().startswith("SELECT")])==4
    view=projection['links'][0]
    assert projection['source']['state']=='available'
    assert view['presence']=='current' and view['freshness']=='fresh'
    assert view['availability']=='seen' and view['sources']==['mikrotik_arp']
    assert 'private' not in binding.observation_json
    db.close()


@pytest.mark.parametrize('enabled,run,age,state,presence',[
    (False,None,0,'disabled','unknown'),
    (True,'failed',0,'unavailable','unknown'),
    (True,None,60,'stale','unknown'),
    (True,'success',0,'available','missing'),
])
def test_saved_source_states_keep_observations_without_false_offline(tmp_path,monkeypatch,enabled,run,age,state,presence):
    db,asset,binding,observed=setup_card(tmp_path,monkeypatch)
    from app.inventory.models import InventoryIdentifierSyncRun
    from app.inventory.network_freshness import card_network_projection
    if run:
        db.add(InventoryIdentifierSyncRun(snapshot_id=2 if run=='success' else None,snapshot_generated_at=NOW if run=='success' else None,status=run,started_at=NOW+timedelta(seconds=1),finished_at=NOW+timedelta(seconds=1),failure_reason='netctl snapshot unavailable' if run=='failed' else None));db.commit()
    view=card_network_projection(db,asset.id,enabled=enabled,now=NOW+timedelta(minutes=age))
    assert view['source']['state']==state
    assert view['links'][0]['presence']==presence
    assert view['links'][0]['observation']['ip']==observed['ip']
    assert view['links'][0]['availability']=='seen'
    db.close()


def test_new_snapshot_updates_safe_facts_without_revision_and_ended_history_retained(tmp_path,monkeypatch):
    db,asset,binding,observed=setup_card(tmp_path,monkeypatch)
    from app.inventory.netctl_bindings import refresh_candidates,end
    from app.inventory.models import InventoryIdentifierSyncRun
    from app.inventory.network_freshness import card_network_projection
    revision=asset.manual_revision
    newer={**observed,'ip':'192.0.2.22','availability':{'state':'offline','reason':'active_negative_no_passive_evidence'}}
    refresh_candidates(db,[newer],snapshot_id=2,observed_at=NOW+timedelta(minutes=1))
    db.add(InventoryIdentifierSyncRun(snapshot_id=2,snapshot_generated_at=NOW+timedelta(minutes=1),status='success',started_at=NOW+timedelta(minutes=1),finished_at=NOW+timedelta(minutes=1)));db.commit();db.refresh(asset)
    assert asset.manual_revision==revision
    view=card_network_projection(db,asset.id,enabled=True,now=NOW+timedelta(minutes=2))['links'][0]
    assert view['availability']=='offline' and view['presence']=='current'
    end(db,binding.id,expected_revision=asset.manual_revision,actor='synthetic',reason='End');db.commit()
    refresh_candidates(db,[{**newer,'ip':'192.0.2.99'}],snapshot_id=3,observed_at=NOW+timedelta(minutes=3));db.commit()
    view=card_network_projection(db,asset.id,enabled=True,now=NOW+timedelta(minutes=3))['links'][0]
    assert view['presence']=='historical' and view['observation']['ip']=='192.0.2.22'
    db.close()


def test_large_legacy_observation_is_not_decoded_or_lost(tmp_path,monkeypatch):
    db,asset,binding,observed=setup_card(tmp_path,monkeypatch)
    from sqlalchemy import text
    from app.inventory.network_freshness import card_network_projection
    db.execute(text('UPDATE inventory_netctl_bindings SET observation_json=:value WHERE id=:id'),
        {'value':'{"ip":"192.0.2.11","legacy":"'+('x'*1_100_000)+'"}','id':binding.id});db.commit()
    projection=card_network_projection(db,asset.id,enabled=True,now=NOW)
    assert projection['details_limited'] is True
    assert len(projection['links'])==1 and projection['links'][0]['binding'].id==binding.id
    assert projection['links'][0]['observation']=={}
    db.close()


def test_restore_and_reassignment_keep_historical_network_owner(tmp_path,monkeypatch):
    db,asset,binding,observed=setup_card(tmp_path,monkeypatch)
    from app.inventory.lifecycle import soft_delete,restore,historical_asset
    from app.inventory.models import InventoryAssetType
    from app.inventory.service import InventoryService
    from app.inventory.netctl_bindings import confirm,active_for_key
    from app.inventory.network_freshness import card_network_projection
    original=asset.id
    soft_delete(db,original,expected_revision=asset.manual_revision,actor='synthetic',reason='Duplicate');db.commit()
    other=InventoryService().create_asset(db,InventoryAssetType.PC);db.commit()
    confirm(db,observed['device_key'],other.id,expected_revision=other.manual_revision,actor='synthetic',reason='Compared rightful card',hosts=[observed],snapshot_id=1,observed_at=NOW);db.commit()
    deleted=historical_asset(db,original)
    restore(db,original,expected_revision=deleted.manual_revision,actor='synthetic');db.commit()
    assert active_for_key(db,observed['device_key']).asset_id==other.id
    old=card_network_projection(db,original,enabled=True,now=NOW)['links'][0]
    current=card_network_projection(db,other.id,enabled=True,now=NOW)['links'][0]
    assert old['presence']=='historical' and old['observation']['ip']==observed['ip']
    assert current['presence']=='current'
    db.close()


def test_legacy_runtime_and_unproven_online_are_unknown(tmp_path,monkeypatch):
    db,asset,binding,observed=setup_card(tmp_path,monkeypatch)
    from app.inventory.network_freshness import card_network_projection
    binding.observed_snapshot_id=0
    binding.observation_json={'ip':observed['ip'],'status':'online','last_seen_at':NOW.isoformat()};db.commit()
    view=card_network_projection(db,asset.id,enabled=True,now=NOW)['links'][0]
    assert view['presence']=='unknown' and view['availability']=='unknown'
    db.close()


def test_html_card_explains_missing_source_and_saved_seen_without_commands(tmp_path,monkeypatch):
    from tests.test_inventory_network_links_web import setup
    client,headers,card,calls=setup(tmp_path,monkeypatch)
    from app.db import get_sessionmaker
    from app.inventory.models import InventoryAsset,InventoryIdentifierSyncRun
    from app.inventory.netctl_bindings import confirm
    now=datetime.now(timezone.utc)
    observation={**host(),'last_seen_at':now.isoformat(),'sources':['mikrotik_arp'],'availability':{'state':'seen'}}
    with get_sessionmaker()() as db:
        asset=db.get(InventoryAsset,card['id'])
        confirm(db,observation['device_key'],asset.id,expected_revision=asset.manual_revision,actor='synthetic',reason='Compared',hosts=[observation],snapshot_id=1,observed_at=now)
        db.add(InventoryIdentifierSyncRun(snapshot_id=2,snapshot_generated_at=now,status='success',started_at=now,finished_at=now));db.commit()
    page=client.get('/inventory/assets/'+card['id'],follow_redirects=True)
    assert page.status_code==200
    assert 'Нет в последнем сохранённом снимке; связь сохранена' in page.text
    assert 'Наблюдался; доступность не доказана' in page.text and 'mikrotik_arp' in page.text
    assert calls==[]


def test_rejected_stale_snapshot_is_stale_not_unavailable(tmp_path,monkeypatch):
    db,asset,binding,observed=setup_card(tmp_path,monkeypatch)
    from app.inventory.models import InventoryIdentifierSyncRun
    from app.inventory.network_freshness import card_network_projection
    db.add(InventoryIdentifierSyncRun(snapshot_id=2,snapshot_generated_at=NOW-timedelta(hours=1),status='failed',started_at=NOW+timedelta(seconds=1),failure_reason='stale netctl snapshot'));db.commit()
    assert card_network_projection(db,asset.id,enabled=True,now=NOW)['source']['state']=='stale'
    db.close()


def test_projection_read_is_one_saved_sqlite_snapshot(tmp_path,monkeypatch):
    db,asset,binding,observed=setup_card(tmp_path,monkeypatch)
    from app.db import get_sessionmaker
    from sqlalchemy import text
    from app.inventory.models import InventoryIdentifierSyncRun
    from app.inventory.netctl_bindings import refresh_candidates
    from app.inventory.network_freshness import card_network_projection
    db.execute(text('PRAGMA journal_mode=WAL'));db.commit()
    published=False
    def publish(conn,cursor,sql,*args):
        nonlocal published
        if not published and 'sum(' in sql:
            published=True
            with get_sessionmaker()() as writer:
                refresh_candidates(writer,[{**observed,'ip':'192.0.2.22'}],snapshot_id=2,observed_at=NOW+timedelta(minutes=1))
                writer.add(InventoryIdentifierSyncRun(snapshot_id=2,snapshot_generated_at=NOW+timedelta(minutes=1),status='success',started_at=NOW+timedelta(minutes=1)));writer.commit()
    event.listen(db.bind,'before_cursor_execute',publish)
    result=card_network_projection(db,asset.id,enabled=True,now=NOW+timedelta(minutes=2))
    assert published and result['source']['snapshot_id']==1
    assert result['links'][0]['observation']['ip']==observed['ip'] and result['links'][0]['presence']=='current'
    next_result=card_network_projection(db,asset.id,enabled=True,now=NOW+timedelta(minutes=2))
    assert next_result['source']['snapshot_id']==2 and next_result['links'][0]['observation']['ip']=='192.0.2.22'
    db.close()


def test_projection_bounds_history_and_keeps_active_binding_first(tmp_path,monkeypatch):
    db,asset,binding,observed=setup_card(tmp_path,monkeypatch)
    from app.inventory.models import InventoryNetctlBinding,InventoryExternalBindingStatus as Status
    from app.inventory.network_freshness import card_network_projection
    for number in range(105):
        db.add(InventoryNetctlBinding(asset_id=asset.id,network_key='mac:02:00:00:00:01:'+f'{number:02X}',status=Status.ENDED,created_by='synthetic',created_at=NOW+timedelta(minutes=1),ended_at=NOW))
    db.commit()
    result=card_network_projection(db,asset.id,enabled=True,now=NOW)
    assert len(result['links'])==100 and result['truncated'] is True
    assert result['links'][0]['binding'].id==binding.id
    db.close()
