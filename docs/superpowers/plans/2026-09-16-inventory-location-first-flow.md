# Inventory Location-First Flow Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (- [ ]) syntax for tracking.

**Goal:** Make mobile inventory navigation progress from a location list to a location tree and then to one device card, preserving inventory data and API v1.

**Architecture:** HTML routes carry an explicit location_id instead of deriving every screen from the session-selected location. The existing InventoryService.location_tree remains the tree source, and the data model remains two-level. Device forms accept a return location and optional parent ID, so a related device is rendered and edited alone.

**Tech Stack:** FastAPI, Jinja2, SQLAlchemy, pytest/TestClient, HTML/CSS/vanilla JavaScript.

**Spec:** docs/superpowers/specs/2026-09-16-inventory-location-first-flow-design.md

## Global Constraints

- Do not migrate, delete, or re-parent existing inventory data.
- Keep API v1 and history tables; remove only the inventory-session controls from HTML.
- Only PC can be a related-device parent; call InventoryService.attach_existing_asset for server-side validation.
- Photo access remains bound to InventoryAssetPhoto.asset_id; enforce the size cap and reject unknown signatures.
- Accept a correct JPEG, PNG, or WEBP signature when browser Content-Type is empty or inaccurate, then store the detected MIME.
- Preserve CSRF checks and audit records for all mutations.
- Run the focused test suite before each commit and use backup-first production deployment.

---

### Task 1: Add location-first screens

**Files:**
- Modify: app/inventory/web.py:96-278
- Modify: app/templates/inventory.html
- Create: app/templates/inventory_location_form.html
- Create: app/templates/inventory_location_detail.html
- Modify: tests/test_inventory_web.py:68-205

**Interfaces:**
- Consumes: InventoryService.location_tree(db, location_id) -> dict[str, Any].
- Produces: GET /inventory/locations/new, GET /inventory/locations/{location_id}, POST /inventory/locations/{location_id}.

- [ ] **Step 1: Write failing route tests**

~~~python
def test_inventory_home_lists_locations_without_walk_or_selector(tmp_path, monkeypatch):
    client, csrf = _client(tmp_path, monkeypatch)
    client.post("/inventory/locations", data={"csrf_token": csrf, "name": "ИТ отдел", "comment": "Подвал"})
    page = client.get("/inventory")
    assert 'href="/inventory/locations/' in page.text
    assert "+ ДОБАВИТЬ ЛОКАЦИЮ" in page.text
    assert "НАЧАТЬ ОБХОД" not in page.text
    assert '<select id="location_id"' not in page.text

def test_location_detail_edits_location_on_tree_screen(tmp_path, monkeypatch):
    client, csrf = _client(tmp_path, monkeypatch)
    created = client.post("/inventory/locations", data={"csrf_token": csrf, "name": "ИТ отдел"}, follow_redirects=False)
    location_id = created.headers["location"].rsplit("/", 1)[-1]
    page = client.get(f"/inventory/locations/{location_id}")
    response = client.post(f"/inventory/locations/{location_id}", data={"csrf_token": _csrf(page.text), "name": "ИТ-отдел", "comment": "Подвал"}, follow_redirects=False)
    assert response.headers["location"] == f"/inventory/locations/{location_id}"
    assert "ИТ-отдел" in client.get(response.headers["location"]).text
~~~

- [ ] **Step 2: Run test to verify it fails**

Run: .venv\Scripts\python.exe -m pytest tests/test_inventory_web.py -q -k "home_lists_locations or location_detail_edits"

Expected: FAIL because the explicit location routes and location-only home page do not exist.

- [ ] **Step 3: Implement minimal location routes**

~~~python
@router.get("/inventory/locations/{location_id}", response_class=HTMLResponse)
def inventory_location_detail(location_id: str, request: Request, db: Session = Depends(get_db)) -> HTMLResponse:
    require_user(request, db)
    tree = service.location_tree(db, location_id)
    if tree["location"] is None:
        raise HTTPException(status_code=404, detail="inventory location not found")
    return _render(request, "inventory_location_detail.html", {"location": tree["location"], "tree": tree, "asset_labels": ASSET_LABELS}, db)
~~~

Add a separate new-location page. Make POST /inventory/locations redirect to its newly created location. Add a CSRF-protected location update POST that rejects blank names, calls service.update_location, writes inventory.location.update, and returns to that same location.

- [ ] **Step 4: Implement templates**

Render /inventory as location cards plus + ДОБАВИТЬ ЛОКАЦИЮ. Render a location screen with К СПИСКУ ЛОКАЦИЙ, a same-screen edit form, top_level_assets, nested related_by_parent, and + ДОБАВИТЬ УСТРОЙСТВО. Do not render session forms, the selector, or device forms on these screens.

- [ ] **Step 5: Verify and commit**

Run: .venv\Scripts\python.exe -m pytest tests/test_inventory_web.py -q

Expected: PASS.

~~~powershell
git add app/inventory/web.py app/templates/inventory.html app/templates/inventory_location_form.html app/templates/inventory_location_detail.html tests/test_inventory_web.py
git commit -m "feat(inventory): add location-first navigation"
~~~

### Task 2: Scope device and relation forms to the selected location

**Files:**
- Modify: app/inventory/web.py:106-500
- Modify: app/templates/inventory_asset_discovery.html
- Modify: app/templates/inventory_asset_form.html
- Modify: app/templates/inventory_related_asset_picker.html
- Modify: app/templates/inventory_location_detail.html
- Modify: tests/test_inventory_web.py:40-465

**Interfaces:**
- Consumes: explicit location_id and existing asset create/update/attach methods.
- Produces: _location_url(location_id) -> str, location-aware _new_asset_url(...), and template context key return_location_id.

- [ ] **Step 1: Write failing form-flow tests**

~~~python
def test_related_device_form_shows_only_child_and_returns_to_location(tmp_path, monkeypatch):
    client, location_id, pc_id = _create_location_and_pc(tmp_path, monkeypatch)
    picker = client.get(f"/inventory/assets/{pc_id}/related/new?location_id={location_id}")
    assert "ПК:" not in picker.text
    assert f"location_id={location_id}" in picker.text
    form = client.get(f"/inventory/assets/new?asset_type=MONITOR&location_id={location_id}&parent_asset_id={pc_id}&manual=1")
    assert "ПК:" not in form.text
    assert "Локация: ИТ отдел" in form.text

def test_location_tree_puts_related_action_next_to_pc(tmp_path, monkeypatch):
    client, location_id, pc_id = _create_location_and_pc(tmp_path, monkeypatch)
    page = client.get(f"/inventory/locations/{location_id}")
    assert f'/inventory/assets/{pc_id}/related/new?location_id={location_id}' in page.text
~~~

- [ ] **Step 2: Run test to verify it fails**

Run: .venv\Scripts\python.exe -m pytest tests/test_inventory_web.py -q -k "related_device_form_shows_only or related_action_next"

Expected: FAIL because forms derive location from session and render parent-card summaries.

- [ ] **Step 3: Add explicit location validation and redirects**

Implement _location_or_error(db, location_id). Use the requested location when supplied and _current_location only for legacy unparameterized URLs. Check that a parent asset belongs to the requested location. Pass location_id through lookup, manual continuation, create, update, detail, photo and all return links. A successful create/update/photo from this flow returns /inventory/locations/{location_id}.

- [ ] **Step 4: Remove parent visuals and place one relation action**

Remove inventory-parent-card from picker, discovery and asset-form templates. Keep parent ID only in hidden request data. In inventory_location_detail.html, render the only relation action next to each PC:

~~~jinja2
<a class="button secondary" href="/inventory/assets/{{ asset.id }}/related/new?location_id={{ location.id }}">+ ДОБАВИТЬ СВЯЗАННОЕ УСТРОЙСТВО</a>
~~~

Do not render it on non-PC cards or inside the device editor.

- [ ] **Step 5: Verify and commit**

Run: .venv\Scripts\python.exe -m pytest tests/test_inventory_web.py -q

Expected: PASS.

~~~powershell
git add app/inventory/web.py app/templates/inventory_asset_discovery.html app/templates/inventory_asset_form.html app/templates/inventory_related_asset_picker.html app/templates/inventory_location_detail.html tests/test_inventory_web.py
git commit -m "feat(inventory): keep device forms location-scoped"
~~~

### Task 3: Make camera uploads content-authoritative

**Files:**
- Modify: app/inventory/storage.py:26-48
- Modify: app/inventory/web.py:495-523
- Modify: app/templates/inventory_asset_form.html
- Create: tests/test_inventory_storage.py
- Modify: tests/test_inventory_web.py:226-248

**Interfaces:**
- Consumes: InventoryPhotoStorage.save(original_filename, declared_mime, content) -> StoredPhoto.
- Produces: signature-authoritative photo MIME, with flash errors returned to the owner card.

- [ ] **Step 1: Write failing storage and upload tests**

~~~python
@pytest.mark.parametrize(("content", "reported_mime", "expected_mime"), [
    (PNG_BYTES, "application/octet-stream", "image/png"),
    (JPEG_BYTES, "", "image/jpeg"),
    (WEBP_BYTES, "image/jpeg", "image/webp"),
])
def test_photo_storage_uses_signature_not_browser_mime(tmp_path, content, reported_mime, expected_mime):
    stored = InventoryPhotoStorage(tmp_path, max_bytes=1024).save("camera-image", reported_mime, content)
    assert stored.mime_type == expected_mime
~~~

- [ ] **Step 2: Run test to verify it fails**

Run: .venv\Scripts\python.exe -m pytest tests/test_inventory_storage.py tests/test_inventory_web.py -q -k "photo"

Expected: FAIL because save rejects a correct signature when declared MIME differs.

- [ ] **Step 3: Implement content-authoritative storage**

Keep byte-size validation, _detect_image, safe path resolution and cleanup. Remove only the declared-MIME equality rejection; store mime_type from _detect_image. Keep the multipart form within the saved asset form, capture="environment", photo type choice and list of photos selected by asset.id.

- [ ] **Step 4: Verify and commit**

Run: .venv\Scripts\python.exe -m pytest tests/test_inventory_storage.py tests/test_inventory_web.py -q

Expected: PASS.

~~~powershell
git add app/inventory/storage.py app/inventory/web.py app/templates/inventory_asset_form.html tests/test_inventory_storage.py tests/test_inventory_web.py
git commit -m "fix(inventory): accept camera photo MIME mismatches"
~~~

### Task 4: Document, release, and verify

**Files:**
- Modify: docs/INVENTORY_V1.md
- Test: tests/test_inventory_web.py
- Test: tests/test_inventory_storage.py

**Interfaces:**
- Consumes: completed routes, templates, photo storage and openvpn-web.service.
- Produces: current operator instructions and deployment evidence.

- [ ] **Step 1: Update operator documentation**

Replace the walk step in docs/INVENTORY_V1.md with list of locations → location tree → device card. State that the related-device action is beside a PC in the location tree, forms show a single device, and a correct JPEG/PNG/WEBP signature is accepted.

- [ ] **Step 2: Run complete local verification**

~~~powershell
.venv\Scripts\python.exe -m pytest tests/test_inventory_web.py tests/test_inventory_storage.py -q
git diff --check
~~~

Expected: every test passes and git diff --check prints no errors.

- [ ] **Step 3: Commit documentation**

~~~powershell
git add docs/INVENTORY_V1.md
git commit -m "docs(inventory): document location-first workflow"
~~~

- [ ] **Step 4: Deploy backup-first and perform mobile acceptance**

Create /opt/openvpn-web/.deploy-backups/pre-inventory-location-flow-<timestamp>/files.tgz with every changed deployment file. Preserve file owners/groups, restart openvpn-web.service, wait for readiness, verify /login is 200 and anonymous /inventory is 303, and compare local/remote SHA-256 values. On a 797 px browser viewport check that the location list has no walk button, location tree has nesting and a relation action beside a PC, a related form has no parent summary, and the saved-device photo form remains on the owning card.
