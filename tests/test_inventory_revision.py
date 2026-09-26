"""Full-card compare-and-write must guard child facts and retain stale input."""
from tests.test_inventory_api import _client
from tests.test_inventory_web import _draft_id


def test_api_requires_revision_and_rejects_repeated_stale_edit(tmp_path, monkeypatch):
    client, headers = _client(tmp_path, monkeypatch)
    asset = client.post("/api/v1/inventory/assets", headers=headers,
        json={"asset_type":"PC", "custom_name":"Original"}).json()["data"]
    path = f"/api/v1/inventory/assets/{asset['id']}"
    assert client.patch(path, headers=headers, json={"custom_name":"unguarded"}).status_code == 428
    base = asset["manual_revision"]
    saved = client.patch(path, headers=headers, json={"expected_revision":base, "details":{"ram_gb":32}})
    assert saved.status_code == 200
    assert saved.json()["data"]["manual_revision"] > base
    for _ in range(2):
        assert client.patch(path, headers=headers, json={"expected_revision":base,"custom_name":"stale"}).status_code == 409
    assert client.get(path, headers=headers).json()["data"]["custom_name"] == "Original"


def test_child_fact_changes_revision_but_observation_does_not(tmp_path, monkeypatch):
    _client(tmp_path, monkeypatch)
    from app.db import get_sessionmaker
    from app.inventory.models import InventoryAsset, InventoryAssetType, InventoryPCDetails, InventoryObservation, InventoryObservationSource
    from app.inventory.service import InventoryService
    from datetime import datetime, timezone
    with get_sessionmaker()() as db:
        asset = InventoryService().create_asset(db, InventoryAssetType.PC)
        InventoryService().update_details(db, asset, {"ram_gb":8})
        db.commit()
        asset_id = asset.id
        db.refresh(asset)
        revision = asset.manual_revision
    with get_sessionmaker()() as db:
        db.get(InventoryPCDetails, asset_id).ram_gb = 16
        db.commit()
    with get_sessionmaker()() as db:
        changed = db.get(InventoryAsset, asset_id).manual_revision
        assert changed > revision
        InventoryService().claim_revision(db, db.get(InventoryAsset, asset_id), changed)
        db.rollback()
    with get_sessionmaker()() as db:
        db.add(InventoryObservation(asset_id=asset_id, source=InventoryObservationSource.NETCTL,
            observed_at=datetime.now(timezone.utc), data_json={"synthetic":True}))
        db.commit()
    with get_sessionmaker()() as db:
        assert db.get(InventoryAsset, asset_id).manual_revision == changed


def test_html_stale_input_retains_original_revision(tmp_path, monkeypatch):
    client, headers = _client(tmp_path, monkeypatch)
    asset = client.post("/api/v1/inventory/assets", headers=headers,
        json={"asset_type":"PC", "custom_name":"Original"}).json()["data"]
    path = f"/inventory/assets/{asset['id']}"
    page = client.get(path)
    assert f'name="expected_revision" value="{asset["manual_revision"]}"' in page.text
    client.patch(f"/api/v1/inventory/assets/{asset['id']}", headers=headers,
        json={"expected_revision":asset["manual_revision"],"custom_name":"Newer"})
    response = client.post(path, data={"csrf_token":headers["X-CSRF-Token"],
        "draft_id":_draft_id(page.text),
        "expected_revision":asset["manual_revision"],"custom_name":"Unsaved"}, follow_redirects=False)
    assert response.status_code == 303
    restored = client.get(response.headers["location"])
    assert 'value="Unsaved"' in restored.text
    assert "Newer" in restored.text
    assert f'name="expected_revision" value="{asset["manual_revision"]}"' in restored.text


def test_compare_and_write_is_atomic_between_sessions(tmp_path, monkeypatch):
    client, headers = _client(tmp_path, monkeypatch)
    asset = client.post("/api/v1/inventory/assets", headers=headers, json={"asset_type":"PC"}).json()["data"]
    from app.db import get_sessionmaker
    from app.inventory.models import InventoryAsset
    from app.inventory.revision import claim_revision, InventoryRevisionConflict
    from concurrent.futures import ThreadPoolExecutor
    from threading import Barrier
    barrier = Barrier(2)
    def writer(name):
        with get_sessionmaker()() as db:
            loaded = db.get(InventoryAsset, asset["id"])
            barrier.wait(timeout=5)
            try:
                claim_revision(db, loaded, asset["manual_revision"])
                loaded.custom_name = name
                db.commit()
                return "saved"
            except InventoryRevisionConflict:
                db.rollback()
                return "conflict"
    with ThreadPoolExecutor(max_workers=2) as pool:
        assert sorted(pool.map(writer, ["one", "two"])) == ["conflict", "saved"]


def test_relation_requires_both_revisions_and_stale_detach_rolls_back(tmp_path, monkeypatch):
    client, headers = _client(tmp_path, monkeypatch)
    def create(kind):
        return client.post("/api/v1/inventory/assets", headers=headers, json={"asset_type":kind}).json()["data"]
    parent, child = create("PC"), create("MONITOR")
    payload = {"parent_asset_id":parent["id"], "child_asset_id":child["id"]}
    assert client.post("/api/v1/inventory/relations", headers=headers, json=payload).status_code == 428
    payload.update(parent_revision=parent["manual_revision"], child_revision=child["manual_revision"])
    linked = client.post("/api/v1/inventory/relations", headers=headers, json=payload)
    assert linked.status_code == 201
    relation_id = linked.json()["data"]["id"]
    assert client.delete(f"/api/v1/inventory/relations/{relation_id}", headers=headers,
        params={"parent_revision":parent["manual_revision"],"child_revision":child["manual_revision"]}).status_code == 409
    from app.db import get_sessionmaker
    from app.inventory.models import InventoryAssetRelation
    with get_sessionmaker()() as db:
        assert db.get(InventoryAssetRelation, relation_id).ended_at is None

def test_captured_manual_form_survives_new_observation_and_api_preserves_provider(tmp_path, monkeypatch):
    from datetime import datetime, timezone
    from sqlalchemy import select
    from app.db import get_sessionmaker
    from app.inventory.models import InventoryAsset, InventoryAssetIdentifier, InventoryObservationSource
    from app.inventory.service import InventoryService
    client, headers = _client(tmp_path, monkeypatch)
    created = client.post('/api/v1/inventory/assets', headers=headers, json={'asset_type':'PC','identifiers':[
        {'identifier_type':'mac','value':'02:00:00:00:00:77'}, {'identifier_type':'ip','value':'192.0.2.7'},
        {'identifier_type':'hostname','value':'manual-host'}, {'identifier_type':'ip','value':'192.0.2.88','source':'nmap'}]})
    assert created.status_code == 201
    asset = created.json()['data']
    page = client.get(f"/inventory/assets/{asset['id']}")
    assert 'name="ip_address" inputmode="decimal" value="192.0.2.7"' in page.text
    with get_sessionmaker()() as db:
        InventoryService().reconcile_netctl_identifiers(db,[{'mac':'02:00:00:00:00:77','ip':'192.0.2.99','hostname':'observed-host'}],observed_at=datetime(2026,9,26,tzinfo=timezone.utc))
        db.commit()
        assert db.get(InventoryAsset,asset['id']).manual_revision == asset['manual_revision']
    refreshed = client.get(str(page.url))
    assert 'name="ip_address" inputmode="decimal" value="192.0.2.7"' in refreshed.text
    assert '192.0.2.99' in refreshed.text
    response = client.post(f"/inventory/assets/{asset['id']}", data={'csrf_token':headers['X-CSRF-Token'], 'draft_id':_draft_id(page.text), 'expected_revision':asset['manual_revision'], 'custom_name':'Saved', 'ip_address':'192.0.2.7','mac_address':'02:00:00:00:00:77','hostname':'manual-host'},follow_redirects=False)
    assert response.status_code == 303
    current = client.get(f"/api/v1/inventory/assets/{asset['id']}",headers=headers).json()['data']
    assert current['custom_name'] == 'Saved'
    response = client.patch(f"/api/v1/inventory/assets/{asset['id']}",headers=headers,json={'expected_revision':current['manual_revision'],'identifiers':[{'identifier_type':'ip','value':'192.0.2.8'}]})
    assert response.status_code == 200
    with get_sessionmaker()() as db:
        rows = list(db.scalars(select(InventoryAssetIdentifier).where(InventoryAssetIdentifier.asset_id == asset['id'],InventoryAssetIdentifier.is_current.is_(True))))
        assert {(r.source.value,r.value) for r in rows} >= {('manual','192.0.2.8'),('netctl','192.0.2.99'),('nmap','192.0.2.88')}
    response = client.patch(f"/api/v1/inventory/assets/{asset['id']}",headers=headers,json={'expected_revision':response.json()['data']['manual_revision'],'identifiers':[{'identifier_type':'ip','value':'192.0.2.100','source':'netctl'}]})
    assert response.status_code == 400

def test_provider_only_form_has_empty_manual_defaults_and_no_implicit_promotion(tmp_path, monkeypatch):
    from datetime import datetime, timezone
    from sqlalchemy import select
    from app.db import get_sessionmaker
    from app.inventory.models import InventoryAssetIdentifier, InventoryObservationSource
    from app.inventory.service import InventoryService
    client, headers = _client(tmp_path, monkeypatch)
    asset = client.post('/api/v1/inventory/assets', headers=headers,json={'asset_type':'PC','identifiers':[{'identifier_type':'mac','value':'02:00:00:00:00:78','source':'netctl'}]}).json()['data']
    with get_sessionmaker()() as db:
        InventoryService().reconcile_netctl_identifiers(db,[{'mac':'02:00:00:00:00:78','ip':'192.0.2.78'}],observed_at=datetime(2026,9,26,tzinfo=timezone.utc))
        db.commit()
    path = f"/inventory/assets/{asset['id']}"
    page = client.get(path)
    assert 'name="ip_address" inputmode="decimal" value=""' in page.text
    assert 'name="mac_address" value=""' in page.text
    assert '192.0.2.78' in page.text
    response = client.post(path,data={'csrf_token':headers['X-CSRF-Token'],'draft_id':_draft_id(page.text),'expected_revision':asset['manual_revision'],'custom_name':'Unrelated'},follow_redirects=False)
    assert response.status_code == 303
    with get_sessionmaker()() as db:
        rows=list(db.scalars(select(InventoryAssetIdentifier).where(InventoryAssetIdentifier.asset_id==asset['id'],InventoryAssetIdentifier.is_current.is_(True))))
        assert len(rows)==2
        assert all(row.source == InventoryObservationSource.NETCTL for row in rows)
