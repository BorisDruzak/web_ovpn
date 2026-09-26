import re
from tests.test_inventory_web import _client, _csrf


def draft_id(page):
    return re.search(r'name="draft_id" value="([^"]+)"', page.text).group(1)


def test_same_type_tabs_have_owned_server_drafts_and_small_cookie(tmp_path, monkeypatch):
    client, csrf = _client(tmp_path, monkeypatch)
    client.post("/inventory/locations", data={"csrf_token":csrf,"name":"Synthetic"})
    url = "/inventory/assets/new?asset_type=MONITOR&manual=1"
    first, second = client.get(url), client.get(url)
    one, two = draft_id(first), draft_id(second)
    assert one != two
    long_text = "Synthetic long description " * 4000
    response = client.post(f"/inventory/drafts/{one}", headers={"X-CSRF-Token":_csrf(first.text)},
        json={"fields":{"custom_name":"One","description":long_text},"draft_revision":1})
    assert response.status_code == 200
    assert len(response.headers.get("set-cookie", "")) < 2000
    restored = client.get(url + f"&draft_id={one}")
    assert "One" in restored.text and long_text in restored.text
    assert "One" not in client.get(url + f"&draft_id={two}").text


def test_draft_owner_expiry_and_discard(tmp_path, monkeypatch):
    client, csrf = _client(tmp_path, monkeypatch)
    client.post("/inventory/locations", data={"csrf_token":csrf,"name":"Synthetic"})
    page = client.get("/inventory/assets/new?asset_type=MONITOR&manual=1")
    identifier = draft_id(page)
    from tests.test_panel_permissions import login_operator
    login_operator(client, permissions=["inventory:write"])
    assert client.get(f"/inventory/assets/new?asset_type=MONITOR&manual=1&draft_id={identifier}").status_code == 404
    assert client.post(f"/inventory/drafts/{identifier}/discard", data={"csrf_token":_csrf(client.get('/inventory').text)}).status_code == 404


def test_expired_draft_and_explicit_discard_end_lifecycle(tmp_path, monkeypatch):
    client, csrf = _client(tmp_path, monkeypatch)
    client.post("/inventory/locations", data={"csrf_token":csrf,"name":"Synthetic"})
    url = "/inventory/assets/new?asset_type=MONITOR&manual=1"
    page = client.get(url)
    identifier = draft_id(page)
    from app.db import get_sessionmaker
    from app.inventory.models import InventoryFormDraft
    from app.models import utcnow
    from datetime import timedelta
    with get_sessionmaker()() as db:
        db.get(InventoryFormDraft, identifier).expires_at = utcnow() - timedelta(seconds=1)
        db.commit()
    assert client.get(url + f"&draft_id={identifier}").status_code == 410
    assert client.post(f"/inventory/drafts/{identifier}", headers={"X-CSRF-Token":_csrf(page.text)},
        json={"fields":{},"draft_revision":1}).status_code == 410
    fresh = client.get(url)
    new_id = draft_id(fresh)
    assert client.post(f"/inventory/drafts/{new_id}/discard", data={"csrf_token":_csrf(fresh.text)}, follow_redirects=False).status_code == 303
    assert client.get(url + f"&draft_id={new_id}").status_code == 404
    with get_sessionmaker()() as db:
        assert db.get(InventoryFormDraft, identifier) is None


def test_draft_autosave_is_cas_and_requires_csrf(tmp_path, monkeypatch):
    client, csrf = _client(tmp_path, monkeypatch)
    client.post("/inventory/locations", data={"csrf_token":csrf,"name":"Synthetic"})
    page = client.get("/inventory/assets/new?asset_type=MONITOR&manual=1")
    identifier = draft_id(page)
    route = f"/inventory/drafts/{identifier}"
    payload = {"fields":{"custom_name":"Current"}, "draft_revision":1}
    assert client.post(route, json=payload).status_code == 400
    headers = {"X-CSRF-Token":_csrf(page.text)}
    assert client.post(route, headers=headers, json=payload).status_code == 200
    payload["fields"]["custom_name"] = "Stale"
    assert client.post(route, headers=headers, json=payload).status_code == 409
    assert "Current" in client.get(str(page.url)).text


def test_successful_card_save_removes_draft_without_cookie_fields(tmp_path, monkeypatch):
    client, csrf = _client(tmp_path, monkeypatch)
    client.post("/inventory/locations", data={"csrf_token":csrf,"name":"Synthetic"})
    page = client.get("/inventory/assets/new?asset_type=MONITOR&manual=1")
    identifier = draft_id(page)
    response = client.post("/inventory/assets", data={"csrf_token":_csrf(page.text), "draft_id":identifier,
        "asset_type":"MONITOR", "manual_mode":"1", "custom_name":"Saved"}, follow_redirects=False)
    assert response.status_code == 303
    from app.db import get_sessionmaker
    from app.inventory.models import InventoryFormDraft, InventoryAsset
    with get_sessionmaker()() as db:
        assert db.get(InventoryFormDraft, identifier) is None
        assert db.query(InventoryAsset).one().custom_name == "Saved"


def test_two_new_pc_failures_retain_independent_input(tmp_path, monkeypatch):
    from tests.test_inventory_web import _prepare_manual_asset_form
    client, csrf = _client(tmp_path, monkeypatch)
    client.post("/inventory/locations", data={"csrf_token":csrf,"name":"Synthetic"})
    one = _prepare_manual_asset_form(client, monkeypatch, "PC")
    two = _prepare_manual_asset_form(client, monkeypatch, "PC")
    assert draft_id(one) != draft_id(two)
    for page, name in ((one,"First draft"),(two,"Second draft")):
        response = client.post("/inventory/assets", data={"csrf_token":_csrf(page.text),
            "draft_id":draft_id(page),"asset_type":"PC","custom_name":name,"ram_gb":"bad"}, follow_redirects=False)
        assert response.status_code == 303
        assert name in client.get(response.headers["location"]).text
    assert "First draft" in client.get(str(one.url)).text
    assert "Second draft" not in client.get(str(one.url)).text


def test_cleanup_is_bounded(tmp_path, monkeypatch):
    _client(tmp_path, monkeypatch)
    from app.db import get_sessionmaker
    from app.inventory.models import InventoryFormDraft
    from app.inventory.form_drafts import cleanup_expired
    from app.models import utcnow
    from datetime import timedelta
    with get_sessionmaker()() as db:
        db.add_all([InventoryFormDraft(owner_id=1, purpose="synthetic", expires_at=utcnow()-timedelta(hours=1)) for _ in range(105)])
        db.commit()
        assert cleanup_expired(db, batch_size=1000) == 100
        db.commit()
        assert db.query(InventoryFormDraft).count() == 5


def test_same_process_cannot_create_two_cards_concurrently(tmp_path, monkeypatch):
    client, csrf = _client(tmp_path, monkeypatch)
    client.post("/inventory/locations", data={"csrf_token":csrf,"name":"Synthetic"})
    page = client.get("/inventory/assets/new?asset_type=MONITOR&manual=1")
    identifier = draft_id(page)
    from app.inventory import form_drafts
    from threading import Barrier
    from concurrent.futures import ThreadPoolExecutor
    barrier = Barrier(2)
    original = form_drafts.owned
    def synchronized(*args, **kwargs):
        result = original(*args, **kwargs)
        if kwargs.get("purpose", "").startswith("inventory_new_asset_flow:"):
            barrier.wait(timeout=5)
        return result
    monkeypatch.setattr(form_drafts, "owned", synchronized)
    payload = {"csrf_token":_csrf(page.text), "draft_id":identifier, "asset_type":"MONITOR", "manual_mode":"1", "custom_name":"Only one"}
    with ThreadPoolExecutor(max_workers=2) as pool:
        results = list(pool.map(lambda _:client.post("/inventory/assets", data=payload, follow_redirects=False).status_code, range(2)))
    assert sorted(results) == [303,409]
    from app.db import get_sessionmaker
    from app.inventory.models import InventoryAsset
    with get_sessionmaker()() as db:
        assert db.query(InventoryAsset).count() == 1


def test_discovery_identifier_restores_and_invalid_lookup_preserves_process(tmp_path, monkeypatch):
    client, csrf = _client(tmp_path, monkeypatch)
    client.post("/inventory/locations", data={"csrf_token":csrf,"name":"Synthetic"})
    page = client.get("/inventory/assets/new?asset_type=PC")
    identifier = draft_id(page)
    assert client.post(f"/inventory/drafts/{identifier}", headers={"X-CSRF-Token":_csrf(page.text)},
        json={"fields":{"identifier":"192.0.2.40"},"draft_revision":1}).status_code == 200
    assert 'value="192.0.2.40"' in client.get(str(page.url)).text
    response = client.post("/inventory/assets/new/lookup", data={"csrf_token":_csrf(page.text),
        "draft_id":identifier,"asset_type":"PC","identifier":"invalid identifier !"}, follow_redirects=False)
    assert response.status_code == 303 and f"draft_id={identifier}" in response.headers["location"]
    assert 'value="invalid identifier !"' in client.get(response.headers["location"]).text
