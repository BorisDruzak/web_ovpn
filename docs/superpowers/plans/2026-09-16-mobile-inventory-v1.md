# Mobile Inventory v1 Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Deliver the complete, standalone mobile-first physical-equipment inventory v1 at `/inventory` and `/api/v1/inventory/` without changing existing OpenVPN or Network Observer domains.

**Architecture:** Add a focused `app.inventory` domain that owns SQLAlchemy models, hierarchy and lookup services, storage, API router, and web routes/templates. Reuse the application's session auth, CSRF, audit, SQLAlchemy `Base.metadata.create_all` startup convention, and `netctl` CLI boundary; never read `netctl` SQLite directly or call Endpoint Platform modules.

**Tech Stack:** Python 3, FastAPI, Pydantic, SQLAlchemy, Jinja2, pytest/TestClient, existing `netctl` CLI and nmap fingerprint runner, vanilla HTML/CSS/JavaScript.

**Spec:** `docs/superpowers/specs/2026-09-16-mobile-inventory-v1-design.md`

## Global Constraints

- Every new persistence table begins with `inventory_`; do not alter the semantics of existing `assets`, `network_hosts`, or runtime asset tables.
- Only technical IDs, asset type, and timestamps are required. All user-entered asset and location fields stay nullable.
- An active workplace relation is only `PC -> MONITOR|PRINTER|PHONE|UPS|OTHER`; it cannot be recursive or cyclic.
- The web layer uses the existing `netctl` CLI/API boundary, never a direct `netctl` database connection.
- nmap accepts exactly one canonical unicast IPv4 address and no user-supplied scan flags.
- Inventory must not import or invoke Endpoint Platform/Agent modules.
- Browser mutations require the existing session CSRF protection; API mutations require existing bearer auth plus `X-CSRF-Token`.
- No deployment is part of this plan.

---

## File structure

- `app/inventory/models.py`: inventory SQLAlchemy entities and enums.
- `app/inventory/service.py`: transactional location/asset/relation/workplace operations and projection.
- `app/inventory/lookup.py`: identifier classification, netctl result normalization, collection retry and safe nmap fallback.
- `app/inventory/storage.py`: upload validation and server-controlled photo lifecycle.
- `app/inventory/schemas.py`: Pydantic request/response contracts.
- `app/inventory/api.py`: authenticated JSON API router.
- `app/inventory/web.py`: authenticated HTML routes, form actions, flashes and CSRF verification.
- `app/templates/inventory.html`, `inventory_asset_form.html`: mobile-facing screens.
- `app/static/inventory.css`, `inventory.js`: responsive layout and client-side draft editor.
- `tests/test_inventory_models.py`, `test_inventory_service.py`, `test_inventory_lookup.py`, `test_inventory_api.py`, `test_inventory_photos.py`, `test_inventory_web.py`: isolated behavior coverage.
- `docs/INVENTORY_V1.md`: operational architecture, storage/backup and limitations.

### Task 1: Inventory schema and startup registration

**Files:**
- Create: `app/inventory/__init__.py`, `app/inventory/models.py`, `tests/test_inventory_models.py`
- Modify: `app/db.py`

**Interfaces:**
- Produces `InventoryLocation`, `InventoryAsset`, `InventoryAssetIdentifier`, `InventoryAssetRelation`, detail entities, `InventoryObservation`, `InventorySession`, `InventoryCheck`, and photo entities.
- Uses the existing `app.db.Base` and `utcnow` convention from `app.models`.

```python
class InventoryAsset(Base):
    __tablename__ = "inventory_assets"
    id: Mapped[str] = mapped_column(String(36), primary_key=True)
    asset_type: Mapped[InventoryAssetType]
    location_id: Mapped[str | None] = mapped_column(ForeignKey("inventory_locations.id"))
```

- [ ] Write failing tests that initialize a temporary application database, create an empty location, empty PC, and empty Monitor, then assert nullable user fields and `inventory_` table names.
- [ ] Run `pytest tests/test_inventory_models.py -v` and confirm collection fails because `app.inventory.models` does not exist.
- [ ] Implement models with UUID-string primary keys, explicit foreign keys, timestamps, nullable user fields, `asset_type` and `status` validation enums, plus one-to-one type-detail records.
- [ ] Import inventory models in `init_db()` before `Base.metadata.create_all()` so the project's existing idempotent schema creation creates all new tables.
- [ ] Re-run `pytest tests/test_inventory_models.py -v` and confirm PASS.
- [ ] Commit schema-only files with `feat(inventory): add inventory persistence models`.

### Task 2: Asset hierarchy service and transactional workplace creation

**Files:**
- Create: `app/inventory/service.py`, `tests/test_inventory_service.py`
- Modify: `app/inventory/models.py`

**Interfaces:**
- Produces `InventoryService.create_location`, `create_asset`, `create_workplace`, `attach_existing_asset`, `detach_relation`, `location_tree`.
- `create_workplace(db, location_id, pc_payload, child_payloads, actor)` returns one persisted PC with child assets and active relations.

```python
def detach_relation(db: Session, relation_id: str, actor: str) -> InventoryAssetRelation:
    """Set ended_at and preserve the child asset and its location."""
```

- [ ] Write failing service tests for all five allowed PC child types, reject `PC -> PC` and every leaf parent, reject location mismatch on attach, and verify detach ends a relation without deleting the child or its location.
- [ ] Run `pytest tests/test_inventory_service.py -v` and confirm failures name missing service methods.
- [ ] Implement a service transaction that validates types before writing, assigns child location from the PC, and rolls back all database rows on any exception.
- [ ] Implement a location projection that excludes currently related children from top-level assets and nests them under their active PC.
- [ ] Re-run `pytest tests/test_inventory_service.py -v` and confirm PASS.
- [ ] Commit with `feat(inventory): add asset hierarchy service`.

### Task 3: Identifiers, observations, and safe network lookup

**Files:**
- Create: `app/inventory/lookup.py`, `tests/test_inventory_lookup.py`
- Modify: `app/inventory/service.py`, `app/netctl_client.py` only if an existing safe wrapper needs a new read-only command, `netctl/cli.py` only if a read-only `fingerprint inspect-ip` command is absent.

**Interfaces:**
- Produces `normalize_mac(value) -> str`, `classify_identifier(value) -> Literal['ip','mac','hostname']`, `InventoryLookup.lookup(value, actor) -> LookupResult`.
- `LookupResult` carries source status, editable suggestions, and normalized observation data; no inventory canonical field is overwritten automatically.

```python
def normalize_mac(value: str) -> str:
    return ":".join(re.findall(r"[0-9a-fA-F]{2}", value)).upper()
```

- [ ] Write failing tests: colon/dash/compact MAC values normalize identically; IP/MAC/hostname netctl hits return suggestions; IP miss invokes `run_nmap_fingerprint` once with the same canonical host; CIDR/range values never invoke nmap; MAC miss requests one collection/retry and never calls nmap without a resolved IP.
- [ ] Run `pytest tests/test_inventory_lookup.py -v` and confirm missing lookup implementation failures.
- [ ] Implement the adapter with dependency-injected netctl calls, a bounded in-process per-identifier lock/throttle, and a dedicated `nmap` call only after `validate_target_ipv4` accepts the original direct IP.
- [ ] Add an architecture regression assertion that inventory module source contains no Endpoint Platform imports or client calls.
- [ ] Re-run `pytest tests/test_inventory_lookup.py -v` and confirm PASS.
- [ ] Commit with `feat(inventory): add bounded network lookup`.

### Task 4: Secure photo storage and transaction compensation

**Files:**
- Create: `app/inventory/storage.py`, `tests/test_inventory_photos.py`
- Modify: `app/config.py`, `app/inventory/service.py`

**Interfaces:**
- Produces `InventoryPhotoStorage.save(upload, kind) -> StoredPhoto`, `delete(stored)`, `cleanup_many(stored)`.
- Configuration adds inventory photo root and maximum upload bytes with safe defaults outside static paths.

```python
@dataclass(frozen=True)
class StoredPhoto:
    storage_path: str
    mime_type: str
    size_bytes: int
```

- [ ] Write failing tests for a valid PNG/JPEG, invalid MIME/content, oversized upload, traversal-shaped original filename, authenticated metadata deletion, and service exception cleanup of created server files.
- [ ] Run `pytest tests/test_inventory_photos.py -v` and confirm failure because photo storage is absent.
- [ ] Implement generated UUID filenames, content-based image verification, capped streamed writes, a resolved-path containment check, metadata-only database records, and cleanup when a DB workflow fails.
- [ ] Re-run `pytest tests/test_inventory_photos.py -v` and confirm PASS.
- [ ] Commit with `feat(inventory): add secure photo storage`.

### Task 5: Authenticated inventory JSON API

**Files:**
- Create: `app/inventory/schemas.py`, `app/inventory/api.py`, `tests/test_inventory_api.py`
- Modify: `app/main.py`

**Interfaces:**
- Produces router prefix `/api/v1/inventory` and endpoints for location list/create/get/update, asset list/create/get/update/delete, workplace projection, lookup, attach/detach, session start/finish, and asset photo add/delete/read metadata.
- Each mutating endpoint accepts `X-CSRF-Token`, uses `require_api_actor`, and emits a named inventory audit event.

```python
@router.post("/locations")
def create_location(payload: LocationCreate, request: Request,
                    csrf_token_header: str | None = Header(alias="X-CSRF-Token"),
                    actor: str = Depends(require_api_actor), db: Session = Depends(get_db)) -> LocationResponse:
    verify_api_csrf(request, csrf_token_header)
```

- [ ] Write failing API tests that reject unauthenticated requests, reject invalid CSRF before writes, create an empty asset, create/retrieve a workplace projection, detach a child, and verify audit actions `inventory.asset.create`, `inventory.relation.create`, and `inventory.relation.end`.
- [ ] Run `pytest tests/test_inventory_api.py -v` and confirm the inventory router is unavailable.
- [ ] Implement Pydantic schemas and route handlers that delegate to the service, use existing `verify_api_csrf`, and map domain validation errors to safe 400/404 responses.
- [ ] Mount the router from `app.main` without changing the existing API prefix or other routers.
- [ ] Re-run `pytest tests/test_inventory_api.py -v` and confirm PASS.
- [ ] Commit with `feat(inventory): add authenticated inventory api`.

### Task 6: Mobile web routes and responsive inventory screen

**Files:**
- Create: `app/inventory/web.py`, `app/templates/inventory.html`, `app/templates/inventory_asset_form.html`, `app/static/inventory.css`, `app/static/inventory.js`, `tests/test_inventory_web.py`
- Modify: `app/main.py`, `app/templates/base.html`, `app/static/app.css`

**Interfaces:**
- Produces `GET /inventory`, location/asset form routes, and CSRF-protected post actions that call `InventoryService`.
- Keeps selected location in the authenticated session under `inventory_current_location_id`.

```python
@router.get("/inventory", response_class=HTMLResponse)
def inventory_home(request: Request, db: Session = Depends(get_db)) -> HTMLResponse:
    user = require_user(request, db)
    return render_inventory(request, db, user)
```

- [ ] Write failing route tests for login redirect, page content with a mobile inventory heading, location-comment save, create-PC-with-Monitor-and-UPS flow, standalone Printer flow, and detach rendering the Monitor once at top level.
- [ ] Run `pytest tests/test_inventory_web.py -v` and confirm `/inventory` is absent.
- [ ] Implement one-column templates, 44px-or-larger touch targets, `accept="image/*" capture="environment"`, readable labels, no horizontal overflow rules, and a session-backed `Save and next` action.
- [ ] Add a single Inventory navigation entry without rewriting unrelated base layout or styles.
- [ ] Re-run `pytest tests/test_inventory_web.py -v` and confirm PASS.
- [ ] Commit with `feat(inventory): add mobile inventory interface`.

### Task 7: Browser/mobile validation and regression coverage

**Files:**
- Modify: `tests/test_inventory_web.py`, `tests/test_routes_smoke.py` only if the expected authenticated route list is explicit.

**Interfaces:**
- Verifies the user path `/inventory -> location -> PC + Monitor + UPS -> standalone Printer -> detach`.

```python
def test_detached_monitor_is_rendered_once_at_location_level(client):
    response = client.get("/inventory")
    assert response.text.count("AOC 24B2X") == 1
```

- [ ] Write one failing rendered-flow assertion for the device tree and no duplicate detached child output.
- [ ] Run the narrowed test first and observe its expected failure.
- [ ] Make only the smallest template/service correction needed for that expectation.
- [ ] Run `pytest tests/test_inventory_*.py tests/test_routes_smoke.py -v` and confirm all inventory and affected route tests pass.
- [ ] Start the local app using its existing launch command and validate `/inventory` in desktop and mobile-sized browser viewports, including page identity, no framework error, console health, screenshot, and one create/detach interaction.
- [ ] Commit any QA-driven correction with `fix(inventory): correct mobile inventory flow`.

### Task 8: Documentation and final verification

**Files:**
- Create: `docs/INVENTORY_V1.md`
- Modify: `README.md` only if its route/API index is maintained manually.

**Interfaces:**
- Documents schema, relation constraints, lookup and nmap policy, photo storage backup/restore requirements, API namespace, manual fallback, and v1 exclusions.

```text
Backup scope: application database + INVENTORY_PHOTO_ROOT.
Restore order: restore files, restore database, then validate each stored path remains under INVENTORY_PHOTO_ROOT.
```

- [ ] Write documentation tests or assertions only where the repository already validates docs/route indexes; otherwise keep this task documentation-only.
- [ ] Add the operational document with exact backup scope: database plus configured inventory photo root, and note that no automatic deletion of asset files occurs on relation detach.
- [ ] Run `git diff --check`, targeted inventory suite, relevant `netctl` nmap suite, application API/route tests, and the repository's full `pytest` suite when feasible.
- [ ] Inspect `git status`, complete staged diff, and `git diff --check`; stage only inventory files and documentation.
- [ ] Commit with `docs(inventory): document inventory v1 operations`.
