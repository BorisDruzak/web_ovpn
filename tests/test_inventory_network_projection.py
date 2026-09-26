from datetime import datetime, timezone, timedelta

from tests.test_inventory_netctl_bindings import fixture, host


def test_complete_filter_projection_matches_local_rows_without_card_details(tmp_path,monkeypatch):
    card = fixture(tmp_path,monkeypatch)
    from app.db import get_sessionmaker
    from app.inventory.models import InventoryAsset
    from app.inventory.netctl_bindings import confirm,end
    from app.inventory.network_projection import filter_projection,attach_network_projection
    with get_sessionmaker()() as db:
        asset = db.get(InventoryAsset,card['id'])
        binding = confirm(db,host()['device_key'],asset.id,expected_revision=asset.manual_revision,
            actor='synthetic',reason='Physical comparison',hosts=[host()])
        db.commit()
        value = filter_projection(db)
        rows = [host()]
        attach_network_projection(db,rows)
        assert value['states'] == {host()['device_key']:rows[0]['inventory']['state']}
        assert asset.id not in str(value) and 'Physical comparison' not in str(value)
        db.refresh(asset)
        end(db,binding.id,expected_revision=asset.manual_revision,actor='synthetic',reason='Ended fixture')
        db.commit()
        updated = filter_projection(db)
        assert updated['states'] == {} and updated['revision'] != value['revision']


def test_projection_uses_confirmed_relations_and_keeps_freshness_separate(tmp_path,monkeypatch):
    card = fixture(tmp_path,monkeypatch)
    from app.db import get_sessionmaker
    from app.config import get_settings
    from app.inventory.models import InventoryAsset, InventoryExternalBinding, InventoryEndpointState, InventoryExternalBindingStatus as Status, InventoryEndpointSyncControl
    from app.inventory.netctl_bindings import confirm, end
    from app.inventory.network_projection import attach_network_projection
    now = datetime.now(timezone.utc)
    monkeypatch.setenv('ENDPOINT_PLATFORM_ENABLED','true')
    get_settings.cache_clear()
    with get_sessionmaker()() as db:
        asset = db.get(InventoryAsset,card['id'])
        network = confirm(db,host()['device_key'],asset.id,expected_revision=asset.manual_revision,actor='synthetic',reason='Compare',hosts=[host()])
        endpoint = InventoryExternalBinding(asset_id=asset.id,source='endpoint_platform',external_id='Synthetic-agent',
            status=Status.CONFIRMED,binding_method='manual',confidence=100,created_by='synthetic',first_seen_at=now)
        db.add(endpoint)
        db.flush()
        db.add(InventoryEndpointState(binding_id=endpoint.id,asset_id=asset.id,endpoint_device_id=endpoint.external_id,
            last_success_at=now,online=False,safe_context_json={'profile_status':{'baseline_v1':'available'},
                'profile_collected_at':{'baseline_v1':(now-timedelta(days=1)).isoformat()},
                'profile_checked_at':{'baseline_v1':now.isoformat()}}))
        db.commit()
        rows = [host()]
        version = attach_network_projection(db,rows,now=now)
        assert rows[0]['inventory']['state'] == 'linked'
        assert rows[0]['endpoint_agent']['state'] == 'confirmed'
        assert rows[0]['endpoint_agent']['freshness'] == 'stale'
        assert rows[0]['endpoint_agent']['device_id'] == 'Synthetic-agent'
        db.add(InventoryEndpointSyncControl(id=1,last_safe_error_code='upstream_unavailable'))
        db.commit()
        assert attach_network_projection(db,rows,now=now) != version
        assert rows[0]['endpoint_agent']['state'] == 'confirmed'
        assert rows[0]['endpoint_agent']['freshness'] == 'unavailable'
        db.refresh(asset)
        end(db,network.id,expected_revision=asset.manual_revision,actor='synthetic',reason='Detach')
        db.commit()
        assert attach_network_projection(db,rows,now=now) != version
        assert rows[0]['inventory']['state'] == 'unlinked'
        assert rows[0]['endpoint_agent']['state'] == 'unbound'


def test_disabled_and_deleted_are_not_false_agent_absence(tmp_path,monkeypatch):
    card = fixture(tmp_path,monkeypatch)
    from app.db import get_sessionmaker
    from app.inventory.models import InventoryAsset
    from app.inventory.netctl_bindings import confirm
    from app.inventory.lifecycle import soft_delete
    from app.inventory.network_projection import attach_network_projection
    with get_sessionmaker()() as db:
        asset = db.get(InventoryAsset,card['id'])
        confirm(db,host()['device_key'],asset.id,expected_revision=asset.manual_revision,actor='synthetic',reason='Compare',hosts=[host()])
        db.commit()
        rows = [host()]
        attach_network_projection(db,rows)
        assert rows[0]['endpoint_agent']['state'] == 'disabled'
        assert rows[0]['inventory']['asset']['id'] == asset.id
        db.refresh(asset)
        soft_delete(db,asset.id,expected_revision=asset.manual_revision,actor='synthetic',reason='Retired')
        db.commit()
        attach_network_projection(db,rows)
        assert rows[0]['inventory']['asset'] is None
        assert rows[0]['inventory']['state'] == 'unlinked'


def test_ssr_and_refresh_share_projection_and_meta_version(tmp_path,monkeypatch):
    from tests.test_inventory_api import _client
    client,headers = _client(tmp_path,monkeypatch)
    import app.main as main
    import app.api as api
    import app.inventory.network_projection as projection
    frozen = datetime.now(timezone.utc)
    class Clock(datetime):
        @classmethod
        def now(cls, tz=None):
            return frozen
    monkeypatch.setattr(projection,'datetime',Clock)
    payload = {'hosts':[host()], 'pagination':{'page':1,'limit':100,'pages':1,'total':1},
        'snapshot':{'snapshot_id':12,'generated_at':datetime.now(timezone.utc).isoformat(),
            'total_hosts':1,'duration_ms':1,'stale':False},'sources':[]}
    monkeypatch.setattr(main,'net_cli_call',lambda *args,**kwargs:(payload,None))
    monkeypatch.setattr(api,'run_netctl',lambda *args,**kwargs:payload)
    page = client.get('/network/hosts')
    assert page.status_code == 200 and 'Интеграция отключена' in page.text
    response = client.get('/api/v1/network/hosts',headers=headers)
    assert response.status_code == 200
    data = response.json()['data']
    assert data['hosts'][0]['endpoint_agent']['state'] == 'disabled'
    assert f'data-projection-version="{data["projection_version"]}"' in page.text
    meta = client.get('/api/v1/network/hosts/meta',headers=headers).json()['data']
    assert meta['projection_version'] == data['projection_version']


def test_candidates_are_not_confirmed_and_bearer_scope_redacts_card_details(tmp_path,monkeypatch):
    from tests.test_inventory_api import _client
    client,headers = _client(tmp_path,monkeypatch)
    card = client.post('/api/v1/inventory/assets',headers=headers,json={'asset_type':'PC',
        'custom_name':'Private synthetic card','identifiers':[{'identifier_type':'mac','value':host()['mac']}]}).json()['data']
    from app.db import get_sessionmaker
    from app.config import get_settings
    from app.inventory.models import InventoryAsset
    from app.inventory.netctl_bindings import refresh_candidates, confirm
    from app.inventory.network_projection import attach_network_projection
    now = datetime.now(timezone.utc)
    monkeypatch.setenv('ENDPOINT_PLATFORM_ENABLED','true')
    get_settings.cache_clear()
    with get_sessionmaker()() as db:
        refresh_candidates(db,[host()],snapshot_id=1,observed_at=now)
        db.commit()
        rows = [host()]
        attach_network_projection(db,rows,now=now)
        assert rows[0]['inventory']['state'] == 'candidate'
        assert rows[0]['endpoint_agent']['state'] == 'candidate'
        assert rows[0]['endpoint_agent']['device_id'] is None
        asset = db.get(InventoryAsset,card['id'])
        confirm(db,host()['device_key'],asset.id,expected_revision=asset.manual_revision,actor='synthetic',reason='Compare',hosts=[host()])
        db.commit()
    import app.api as api
    monkeypatch.setattr(api,'run_netctl',lambda *a,**kw:{'hosts':[host()],
        'pagination':{'page':1,'limit':100,'total':1,'pages':1},'snapshot':{'snapshot_id':1}})
    monkeypatch.setenv('OPENVPN_WEB_API_PERMISSIONS','network:read')
    get_settings.cache_clear()
    result = client.get('/api/v1/network/hosts',headers=headers)
    assert result.status_code == 200
    projected = result.json()['data']['hosts'][0]
    assert projected['inventory'] == {'state':'linked'}
    assert 'Private synthetic card' not in result.text and card['id'] not in result.text


def test_epoch_changes_for_evidence_and_location_and_rolls_back_with_facts(tmp_path,monkeypatch):
    card = fixture(tmp_path,monkeypatch)
    from app.db import get_sessionmaker, init_db
    from app.inventory.models import InventoryLocation
    from app.inventory.netctl_bindings import refresh_candidates
    from app.inventory.network_projection import projection_version
    now = datetime.now(timezone.utc)
    init_db()
    init_db()
    with get_sessionmaker()() as db:
        row = refresh_candidates(db,[host()],snapshot_id=1,observed_at=now)[0]
        location = InventoryLocation(name='Synthetic room')
        db.add(location)
        db.commit()
        before = projection_version(db,now=now)
        row.evidence_json = {**row.evidence_json,'ambiguous':True}
        db.flush()
        assert projection_version(db,now=now) != before
        db.rollback()
        assert projection_version(db,now=now) == before
        from app.inventory.models import InventoryEndpointSyncControl
        control = InventoryEndpointSyncControl(id=1)
        db.add(control)
        db.commit()
        before = projection_version(db,now=now)
        control.lease_owner = 'Synthetic-worker'
        control.lease_expires_at = now + timedelta(seconds=60)
        db.commit()
        assert projection_version(db,now=now) == before
        location.name = 'Renamed synthetic room'
        db.commit()
        assert projection_version(db,now=now) != before
