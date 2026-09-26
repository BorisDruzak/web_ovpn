"""Full-card compare-and-write must guard child facts and retain stale input."""
from tests.test_inventory_api import _client


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
