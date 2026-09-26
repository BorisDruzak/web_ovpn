from sqlalchemy import select
import pytest

from tests.test_inventory_api import _client

KEY = 'mac:02:00:00:00:00:11'


def setup(tmp_path,monkeypatch):
    client,headers = _client(tmp_path,monkeypatch)
    card = client.post('/api/v1/inventory/assets',headers=headers,json={'asset_type':'PC',
        'custom_name':'Synthetic physical PC','identifiers':[{'identifier_type':'mac','value':KEY[4:]}]}).json()['data']
    calls = []
    def runtime(args,**kwargs):
        calls.append(args)
        from netctl.cli import build_parser
        parsed = build_parser().parse_args(args)
        assert parsed.asset_key == KEY
        return {'runtime_asset':{'asset':{'asset_key':KEY,'provisional':0},'interfaces':[{'mac':KEY[4:]}],
            'current_ip_observations':[{'ip':'192.0.2.11','last_seen_at':'2026-09-26T12:00:00Z'}],
            'current_hostname_observations':[{'hostname':'Synthetic-PC'}],'findings':[]}}
    monkeypatch.setattr('app.inventory.network_links.run_netctl',runtime)
    return client,headers,card,calls


def values(headers,card):
    return {'network_key':KEY,'asset_id':card['id'],'expected_revision':card['manual_revision'],
        'csrf_token':headers['X-CSRF-Token'],'reason':'Compared label and physical interface','confirmation':card['id']}


def test_identifier_search_filters_before_count_and_page_without_duplicate_cards(tmp_path,monkeypatch):
    client,headers,card,_ = setup(tmp_path,monkeypatch)
    from app.db import get_sessionmaker
    from app.inventory.models import InventoryAsset, InventoryAssetIdentifier, InventoryIdentifierType, InventoryObservationSource as Source
    with get_sessionmaker()() as db:
        for number in range(27):
            row = InventoryAsset(asset_type='PC', custom_name=f'Search distractor {number:02d}')
            db.add(row)
        db.add_all([
            InventoryAssetIdentifier(asset_id=card['id'],identifier_type=InventoryIdentifierType.IP,
                value='192.0.2.11',normalized_value='192.0.2.11',source=Source.MANUAL),
            InventoryAssetIdentifier(asset_id=card['id'],identifier_type=InventoryIdentifierType.IP,
                value='192.0.2.11',normalized_value='192.0.2.11',source=Source.NETCTL),
            InventoryAssetIdentifier(asset_id=card['id'],identifier_type=InventoryIdentifierType.HOSTNAME,
                value='search-old-name',normalized_value='search-old-name',source=Source.NETCTL,is_current=False),
            InventoryAssetIdentifier(asset_id=card['id'],identifier_type=InventoryIdentifierType.HOSTNAME,
                value='search-current-name',normalized_value='search-current-name',source=Source.NETCTL),
        ])
        db.commit()
    for query in ('192.0.2.11',KEY[4:],'020000000011','02-00-00-00-00-11',KEY,'search-current-name'):
        response = client.get('/inventory/network-links',params={'network_key':KEY,'q':query,'page':9})
        assert response.status_code == 200
        assert '1 карточек · Страница 1 из 1' in response.text
        assert 'Synthetic physical PC' in response.text and 'Search distractor' not in response.text
    for query in ('search-old-name','%','_'):
        response = client.get('/inventory/network-links',params={'network_key':KEY,'q':query})
        assert '0 карточек' in response.text
    from app.inventory.lifecycle import soft_delete
    with get_sessionmaker()() as db:
        asset = db.get(InventoryAsset,card['id'])
        soft_delete(db,asset.id,expected_revision=asset.manual_revision,actor='synthetic',reason='Search lifecycle fixture')
        db.commit()
    hidden = client.get('/inventory/network-links',params={'network_key':KEY,'q':'192.0.2.11'})
    assert '0 карточек' in hidden.text and 'Synthetic physical PC' not in hidden.text


def test_compare_confirm_and_end_are_owned_local_decisions(tmp_path,monkeypatch):
    client,headers,card,calls = setup(tmp_path,monkeypatch)
    page = client.get('/inventory/network-links',params={'network_key':KEY,'asset_id':card['id']})
    assert page.status_code == 200 and 'Synthetic physical PC' in page.text and '192.0.2.11' in page.text
    from app.db import get_sessionmaker
    from app.inventory.models import InventoryNetctlBinding, InventoryAsset
    with get_sessionmaker()() as db:
        assert db.scalar(select(InventoryNetctlBinding)) is None
    response = client.post('/inventory/network-links/confirm',data=values(headers,card),follow_redirects=False)
    assert response.status_code == 303
    with get_sessionmaker()() as db:
        row = db.scalar(select(InventoryNetctlBinding))
        assert row.status.value == 'confirmed' and row.confirmed_by == 'admin'
        assert row.observation_json['ip'] == '192.0.2.11'
        binding_id = row.id
        revision = db.get(InventoryAsset,card['id']).manual_revision
    response = client.post(f'/inventory/network-links/{binding_id}/end',data={
        'expected_revision':revision,'reason':'Explicit detach','csrf_token':headers['X-CSRF-Token']},follow_redirects=False)
    assert response.status_code == 303
    with get_sessionmaker()() as db:
        row = db.get(InventoryNetctlBinding,binding_id)
        assert row.status.value == 'ended' and row.ended_by == 'admin'
        assert db.get(InventoryAsset,card['id']) is not None
    assert all(call[:2] == ['runtime-assets','inspect'] for call in calls)


def test_permission_csrf_and_confirmation_fail_before_mutation(tmp_path,monkeypatch):
    client,headers,card,calls = setup(tmp_path,monkeypatch)
    assert client.post('/inventory/network-links/confirm',data={**values(headers,card),'csrf_token':'wrong'}).status_code == 400
    assert calls == []
    response = client.post('/inventory/network-links/confirm',data={**values(headers,card),'confirmation':''})
    assert response.status_code == 409
    from tests.test_panel_permissions import login_operator
    csrf = login_operator(client)
    calls.clear()
    assert client.post('/inventory/network-links/confirm',data={**values(headers,card),'csrf_token':csrf}).status_code == 403
    assert calls == []


def test_stale_revision_retains_reason_and_does_not_confirm(tmp_path,monkeypatch):
    client,headers,card,_ = setup(tmp_path,monkeypatch)
    from app.db import get_sessionmaker
    from app.inventory.models import InventoryAsset, InventoryNetctlBinding
    with get_sessionmaker()() as db:
        db.get(InventoryAsset,card['id']).custom_name = 'Newer physical facts'
        db.commit()
    response = client.post('/inventory/network-links/confirm',data=values(headers,card))
    assert response.status_code == 409 and 'Compared label and physical interface' in response.text
    assert 'Обновить сравнение' in response.text
    with get_sessionmaker()() as db:
        assert db.scalar(select(InventoryNetctlBinding)) is None


def test_audit_failure_rolls_back_confirmed_relation(tmp_path,monkeypatch):
    client,headers,card,_ = setup(tmp_path,monkeypatch)
    def failure(*args,**kwargs):
        raise RuntimeError('Synthetic audit failure')
    monkeypatch.setattr('app.inventory.network_links.write_audit',failure)
    with pytest.raises(RuntimeError,match='Synthetic audit failure'):
        client.post('/inventory/network-links/confirm',data=values(headers,card))
    from app.db import get_sessionmaker
    from app.inventory.models import InventoryNetctlBinding
    with get_sessionmaker()() as db:
        assert db.scalar(select(InventoryNetctlBinding)) is None


def test_runtime_collision_and_provisional_keys_cannot_confirm(tmp_path,monkeypatch):
    client,headers,card,_ = setup(tmp_path,monkeypatch)
    monkeypatch.setattr('app.inventory.network_links.run_netctl',lambda *a,**kw:{'runtime_asset':{
        'asset':{'asset_key':KEY,'provisional':0},'interfaces':[{'mac':KEY[4:]}],
        'findings':[{'finding_type':'mac_identity_collision','status':'open'}]}})
    assert client.post('/inventory/network-links/confirm',data=values(headers,card)).status_code == 409
    assert client.post('/inventory/network-links/confirm',data={**values(headers,card),'network_key':'legacy-host:11'}).status_code == 409
