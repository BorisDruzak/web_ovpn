# Inventory Card Blocks and PC Detail Migration Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Group mobile inventory-card fields, migrate legacy asset comments and PC values safely, and expose canonical PC OS/CPU/RAM data through the web and REST interfaces.

**Architecture:** Keep the physical legacy `inventory_assets.notes` SQLite column for backwards-compatible files, but migrate its non-empty values into `description` during idempotent startup maintenance and remove it from the application model and asset API. Add `inventory_pc_details.os_version` through an in-place SQLite migration, then centralize PC value normalization in a dependency-free inventory module so startup backfill, Nmap prefill, API writes, and web forms use the same canonical representation without a service/lookup import cycle.

**Tech Stack:** Python 3, FastAPI, SQLAlchemy, SQLite, Jinja2, pytest, Ruff.

**Spec:** `docs/superpowers/specs/2026-09-17-inventory-card-blocks-design.md`

## Global Constraints

- Do not remove Serial from device records.
- Do not alter inventory-session check notes.
- Do not infer hardware values not supported by existing data or collection evidence.
- Do not rebuild the SQLite table solely to physically drop the deprecated `notes` column.
- Preserve invalid-form drafts and show the existing validation error flow.
- Back up the production SQLite database before the first deployed schema/data migration.
- Never print or commit secrets.

---

## File Structure

- `app/inventory/models.py` — removes the deprecated asset `notes` mapping and adds PC `os_version`.
- `app/inventory/normalization.py` — normalizes and validates PC operating-system, processor-vendor, and RAM-type values without database or web dependencies.
- `app/inventory/service.py` — declares the PC detail contract and canonicalizes safe OS/CPU/RAM inputs.
- `app/db.py` — applies in-place SQLite column migration and idempotent legacy-data backfill before normal inventory integrity repair.
- `app/inventory/lookup.py` — converts Nmap OS fingerprints into canonical OS family/version suggestions.
- `app/inventory/schemas.py` and `app/inventory/api.py` — remove deprecated asset note I/O and serialize the expanded PC detail dictionary.
- `app/inventory/web.py` — accepts, preserves, and supplies grouped-card fields without accepting asset comments.
- `app/templates/inventory_asset_form.html` and `app/static/inventory.css` — render accessible mobile field groups and place the location return control outside the collapsible card.
- `tests/test_inventory_models.py`, `tests/test_inventory_details.py`, `tests/test_inventory_lookup.py`, `tests/test_inventory_api.py`, `tests/test_inventory_web.py` — regression coverage for schema, migration, normalizers, contracts, and responsive HTML structure.

### Task 1: Define and test canonical PC detail normalization

**Files:**
- Modify: `app/inventory/models.py:137-149`
- Create: `app/inventory/normalization.py`
- Modify: `app/inventory/service.py:45-147`
- Test: `tests/test_inventory_details.py`

**Interfaces:**
- Produces `normalize_pc_details(fields: Mapping[str, Any], *, strict: bool) -> dict[str, Any]` from `app.inventory.normalization`.
- Produces a PC `DETAIL_MODELS` contract containing `os_name`, `os_version`, `cpu_model`, `cpu_generation`, `ram_type`, `ram_gb`, `storage_type`, and `storage_gb`.
- Consumes no database state; later startup migration, lookup, API, and web paths use the normalizer.

- [ ] **Step 1: Write failing service tests for new detail shape and canonical values**

```python
def test_pc_detail_normalizes_safe_select_values(db):
    from app.inventory.models import InventoryAssetType
    from app.inventory.service import InventoryService

    service = InventoryService()
    asset = service.create_asset(db, InventoryAssetType.PC)
    details = service.update_details(
        db,
        asset,
        {
            "os_name": "Windows 11",
            "os_version": "",
            "cpu_model": "intrl",
            "cpu_generation": "11400",
            "ram_type": "Ddr4",
            "ram_gb": 16,
        },
    )

    assert details["os_name"] == "Windows"
    assert details["os_version"] == "11"
    assert details["cpu_model"] == "Intel"
    assert details["cpu_generation"] == "11400"
    assert details["ram_type"] == "DDR4"


def test_pc_detail_rejects_unapproved_select_values(db):
    from app.inventory.models import InventoryAssetType
    from app.inventory.service import InventoryService, InventoryValidationError

    asset = InventoryService().create_asset(db, InventoryAssetType.PC)
    with pytest.raises(InventoryValidationError, match="операционной системы"):
        InventoryService().update_details(db, asset, {"os_name": "macOS"})
```

- [ ] **Step 2: Run the new service tests and verify they fail**

Run: `python -m pytest tests/test_inventory_details.py -q`

Expected: FAIL because `os_version` is not a permitted PC detail and no canonical validation exists.

- [ ] **Step 3: Add the detail column and minimal pure normalization functions**

In `InventoryPCDetails`, add:

```python
os_version: Mapped[str | None] = mapped_column(String(255))
```

Create `app/inventory/normalization.py` with canonical choice constants and a pure normalizer:

```python
PC_OS_FAMILIES = frozenset({"Windows", "Linux"})
PC_CPU_VENDORS = frozenset({"Intel", "AMD"})
PC_RAM_TYPES = frozenset({"DDR3", "DDR4"})

class PCDetailNormalizationError(ValueError):
    pass

def normalize_pc_details(fields: Mapping[str, Any], *, strict: bool) -> dict[str, Any]:
    values = dict(fields)
    if _text(values.get("cpu_model")) == "11400" and _text(values.get("cpu_generation")).casefold() == "i5":
        values["cpu_model"], values["cpu_generation"] = "Intel", "i5 11400"
    raw_os = _text(values.get("os_name"))
    if raw_os.casefold() in {"win7", "win10", "win11"}:
        values["os_name"], values["os_version"] = "Windows", raw_os[-2:]
    elif raw_os.casefold().startswith("windows "):
        values["os_name"], values["os_version"] = "Windows", raw_os[8:].strip()
    elif raw_os.casefold() in {"windows", "linux"}:
        values["os_name"] = raw_os.title()
    elif "linux" in raw_os.casefold():
        values["os_name"], values["os_version"] = "Linux", raw_os
    elif raw_os and strict:
        raise PCDetailNormalizationError("неверное значение операционной системы")
    values["cpu_model"] = _normalize_choice(values.get("cpu_model"), {"intrl": "Intel", "intel": "Intel", "amd": "AMD"}, PC_CPU_VENDORS, strict, "процессора")
    values["ram_type"] = _normalize_choice(values.get("ram_type"), {"ddr3": "DDR3", "ddr4": "DDR4"}, PC_RAM_TYPES, strict, "типа оперативной памяти")
    return values
```

`_text` returns stripped text or `None`; `_normalize_choice` preserves an unrecognized value when `strict=False` and raises `PCDetailNormalizationError` when `strict=True`. Import the normalizer in `service.py`. Add `os_version` to the PC `DETAIL_MODELS` allowed set. In `update_details`, invoke `normalize_pc_details(values, strict=True)` only for a PC and translate `PCDetailNormalizationError` into `InventoryValidationError`. Keep numeric/date conversions and printer connection validation unchanged. Change `infer_printer_connection_type` to accept only `description`; it must not read the retired asset field.

- [ ] **Step 4: Extend tests for documented legacy repairs and printer inference**

```python
@pytest.mark.parametrize(
    ("raw", "expected"),
    [
        ({"os_name": "Win10"}, {"os_name": "Windows", "os_version": "10"}),
        ({"os_name": "Alt Linux KDE 11.4"}, {"os_name": "Linux", "os_version": "Alt Linux KDE 11.4"}),
        ({"cpu_model": "11400", "cpu_generation": "I5"}, {"cpu_model": "Intel", "cpu_generation": "i5 11400"}),
        ({"ram_type": "ddr3"}, {"ram_type": "DDR3"}),
    ],
)
def test_normalize_pc_details_repairs_known_legacy_values(raw, expected):
    from app.inventory.normalization import normalize_pc_details
    normalized = normalize_pc_details(raw, strict=False)
    assert {key: normalized[key] for key in expected} == expected
```

Update `test_infers_printer_connection_type_from_current_ip_or_comment` so it passes only `has_current_ip` and `description`, including the existing `USB` and `ЮСБ` assertions.

- [ ] **Step 5: Run the focused tests and commit**

Run: `python -m pytest tests/test_inventory_details.py -q`

Expected: PASS.

```bash
git add app/inventory/models.py app/inventory/normalization.py app/inventory/service.py tests/test_inventory_details.py
git commit -m "feat(inventory): normalize pc detail values"
```

### Task 2: Migrate legacy SQLite schema and inventory data idempotently

**Files:**
- Modify: `app/db.py:37-58`
- Test: `tests/test_inventory_models.py`

**Interfaces:**
- Consumes `normalize_pc_details(..., strict=False)` from `app.inventory.normalization`.
- Produces `init_db()` support for old databases where `inventory_pc_details` lacks `os_version` and assets retain `notes`.
- Produces a database where transferred `inventory_assets.notes` is `NULL` and PC rows use canonical fields where the mapping is unambiguous.

- [ ] **Step 1: Write legacy SQLite migration tests**

```python
def test_init_db_adds_os_version_and_transfers_asset_notes(tmp_path, monkeypatch):
    monkeypatch.setenv("DATABASE_URL", f"sqlite:///{tmp_path / 'legacy.sqlite'}")
    from app.db import Base, get_engine, init_db, reset_engine_cache
    from app.inventory.models import InventoryAsset

    reset_engine_cache()
    with get_engine().begin() as connection:
        Base.metadata.create_all(bind=connection, tables=[InventoryAsset.__table__])
        connection.execute(text("ALTER TABLE inventory_assets ADD COLUMN notes TEXT"))
        connection.execute(text("CREATE TABLE inventory_pc_details (asset_id VARCHAR(36) PRIMARY KEY, os_name VARCHAR(255), cpu_model VARCHAR(255), cpu_generation VARCHAR(100), ram_type VARCHAR(100), ram_gb INTEGER, storage_type VARCHAR(100), storage_gb INTEGER)"))
        connection.execute(text("INSERT INTO inventory_assets (id, asset_type, description, notes, created_at, updated_at) VALUES ('a', 'PC', 'Основное описание', 'Старый комментарий', CURRENT_TIMESTAMP, CURRENT_TIMESTAMP)"))

    init_db()

    with get_engine().connect() as connection:
        columns = {item["name"] for item in inspect(get_engine()).get_columns("inventory_pc_details")}
        row = connection.execute(text("SELECT description, notes FROM inventory_assets WHERE id = 'a'")).mappings().one()
    assert "os_version" in columns
    assert row == {"description": "Основное описание\\n\\nКомментарий: Старый комментарий", "notes": None}
```

Create a second fixture row with blank `description` and assert its `description` becomes exactly the old comment. Call `init_db()` twice and assert the text is not duplicated.

- [ ] **Step 2: Run the schema tests and verify they fail**

Run: `python -m pytest tests/test_inventory_models.py -q`

Expected: FAIL because `init_db()` neither adds `os_version` nor transfers asset comments.

- [ ] **Step 3: Implement ordered, transactional startup maintenance**

Add a migration helper in `app/db.py` that inspects physical table columns before each legacy operation:

```python
def _migrate_inventory_schema(engine) -> None:
    inspector = inspect(engine)
    if "inventory_pc_details" in inspector.get_table_names():
        columns = {column["name"] for column in inspector.get_columns("inventory_pc_details")}
        if "os_version" not in columns:
            with engine.begin() as connection:
                connection.execute(text("ALTER TABLE inventory_pc_details ADD COLUMN os_version VARCHAR(255)"))
    if "inventory_assets" in inspector.get_table_names():
        asset_columns = {column["name"] for column in inspector.get_columns("inventory_assets")}
        if "notes" in asset_columns:
            with engine.begin() as connection:
                connection.execute(_TRANSFER_ASSET_NOTES)
```

In the same controlled startup flow, use raw SQL against the physical legacy column before ORM usage:

```sql
UPDATE inventory_assets
SET description = CASE
    WHEN description IS NULL OR trim(description) = '' THEN notes
    ELSE description || char(10) || char(10) || 'Комментарий: ' || notes
END,
notes = NULL
WHERE notes IS NOT NULL AND trim(notes) <> ''
```

After this raw transfer, open `session_scope()` and call `InventoryService.normalize_existing_pc_details(db)` before `repair_detail_integrity(db)`:

```python
def normalize_existing_pc_details(self, db: Session) -> int:
    changed = 0
    for detail in db.scalars(select(InventoryPCDetails)).all():
        fields = {name: getattr(detail, name) for name in PC_DETAIL_FIELDS}
        normalized = normalize_pc_details(fields, strict=False)
        for name, value in normalized.items():
            if fields.get(name) != value:
                setattr(detail, name, value)
                changed += 1
    db.flush()
    return changed
```

`PC_DETAIL_FIELDS` is the exact tuple `("os_name", "os_version", "cpu_model", "cpu_generation", "ram_type", "ram_gb", "storage_type", "storage_gb")`. Thus unknown historic values remain untouched, while only documented aliases/splits are changed.

- [ ] **Step 4: Run all model/schema tests and inspect migration idempotence**

Run: `python -m pytest tests/test_inventory_models.py tests/test_inventory_details.py -q`

Expected: PASS, including two calls to `init_db()` without a duplicate comment suffix.

- [ ] **Step 5: Commit the migration unit**

```bash
git add app/db.py app/inventory/service.py tests/test_inventory_models.py tests/test_inventory_details.py
git commit -m "feat(inventory): migrate legacy card data"
```

### Task 3: Align lookup, REST schemas, and API serialization with the new contract

**Files:**
- Modify: `app/inventory/lookup.py:75-115`
- Modify: `app/inventory/schemas.py:27-62`
- Modify: `app/inventory/api.py:25-50`
- Test: `tests/test_inventory_lookup.py`
- Test: `tests/test_inventory_api.py`

**Interfaces:**
- Consumes `normalize_pc_details(..., strict=False)` from `app.inventory.normalization`.
- Produces Nmap suggestions shaped as `{"ip": ..., "os_name": "Windows", "os_version": "10"}` when the fingerprint is recognizable.
- Produces REST PC detail objects containing `os_version` and asset objects without `notes`.

- [ ] **Step 1: Write failing API and lookup contract tests**

```python
def test_nmap_lookup_splits_windows_family_and_version():
    result = InventoryLookup(fake_netctl).lookup("192.168.100.87", actor="tester")
    assert result.suggestions == {"ip": "192.168.100.87", "os_name": "Windows", "os_version": "10"}


def test_asset_api_omits_deprecated_notes_and_includes_os_version(client, headers):
    created = client.post(
        "/api/v1/inventory/assets",
        headers=headers,
        json={"asset_type": "PC", "custom_name": "PC-01", "details": {"os_name": "Windows", "os_version": "11"}},
    )
    data = created.json()["data"]
    assert "notes" not in data
    assert data["details"]["os_version"] == "11"
```

Add an API negative test posting `{"notes": "legacy"}` and assert FastAPI rejects it with HTTP 422. Retain the existing `SessionCheckCreate.notes` test, which proves inventory-session notes remain accepted.

- [ ] **Step 2: Run the contract tests and verify they fail**

Run: `python -m pytest tests/test_inventory_lookup.py tests/test_inventory_api.py -q`

Expected: FAIL because lookup emits a single `os_name`, API emits asset notes, and details omit `os_version`.

- [ ] **Step 3: Implement contract alignment**

In `InventoryLookup.lookup`, import the dependency-free normalizer and convert the first OS fingerprint through `normalize_pc_details({"os_name": os_match}, strict=False)`. Merge only a canonical `os_name`/`os_version` result into suggestions; emit neither for an unrecognized fingerprint. This preserves the existing `service -> lookup` import direction and prevents a circular import.

Remove `notes` from `AssetPayload` and `AssetUpdate`; add `model_config = ConfigDict(extra="forbid")` to `AssetPayload` and import `ConfigDict` so a deprecated asset note is rejected instead of silently ignored. Do not alter `SessionCheckCreate`. Remove `"notes": asset.notes` from `_asset_dict`. Rely on the Task 1 PC detail contract so `details_for` includes `os_version` for an empty as well as populated PC row.

- [ ] **Step 4: Run API and lookup tests**

Run: `python -m pytest tests/test_inventory_lookup.py tests/test_inventory_api.py -q`

Expected: PASS; session checks retain their independent note field.

- [ ] **Step 5: Commit the contract unit**

```bash
git add app/inventory/lookup.py app/inventory/schemas.py app/inventory/api.py tests/test_inventory_lookup.py tests/test_inventory_api.py
git commit -m "feat(inventory): expose canonical pc details"
```

### Task 4: Preserve new fields in web flows and remove card comments

**Files:**
- Modify: `app/inventory/web.py:69-81, 188-228, 288-307, 535-650`
- Test: `tests/test_inventory_web.py`

**Interfaces:**
- Consumes `DETAIL_FIELD_NAMES` with `os_version`.
- Produces create/update form values with no `notes` field and draft dictionaries that retain `os_version` after validation errors.
- Produces Nmap-backed new PC form context containing normalized `os_name` and `os_version` suggestions.

- [ ] **Step 1: Write failing form round-trip and draft tests**

```python
def test_pc_web_form_persists_os_version_and_drops_card_notes(tmp_path, monkeypatch):
    client, csrf = _client(tmp_path, monkeypatch)
    page = _prepare_manual_asset_form(client, monkeypatch, "PC")
    created = client.post(
        "/inventory/assets",
        data={
            "csrf_token": _csrf(page.text), "asset_type": "PC", "custom_name": "PC-01",
            "os_name": "Windows", "os_version": "11", "cpu_model": "Intel",
            "cpu_generation": "i5-11400", "ram_type": "DDR4", "ram_gb": "16",
        },
        follow_redirects=False,
    )
    detail = client.get(created.headers["location"])
    assert 'name="os_version" value="11"' in detail.text
    assert 'name="notes"' not in detail.text


def test_pc_web_form_keeps_os_version_when_identifier_is_invalid(tmp_path, monkeypatch):
    client, csrf = _client(tmp_path, monkeypatch)
    page = _prepare_manual_asset_form(client, monkeypatch, "PC")
    response = client.post(
        "/inventory/assets",
        data={"csrf_token": _csrf(page.text), "asset_type": "PC", "os_name": "Linux", "os_version": "Astra Linux", "mac_address": "bad"},
        follow_redirects=True,
    )
    assert 'name="os_version" value="Astra Linux"' in response.text
```

- [ ] **Step 2: Run the focused web tests and verify they fail**

Run: `python -m pytest tests/test_inventory_web.py -q`

Expected: FAIL because drafts omit `os_version` and form processing still accepts/uses `notes`.

- [ ] **Step 3: Update form field plumbing**

Make these exact changes in `web.py`:

```python
DETAIL_FIELD_NAMES[InventoryAssetType.PC] = (
    "os_name", "os_version", "cpu_model", "cpu_generation", "ram_type",
    "ram_gb", "storage_type", "storage_gb",
)
```

- Remove `notes` from `NEW_ASSET_FORM_FIELDS`, prefill value construction, asset-detail `form_values`, and both FastAPI web route signatures.
- Remove `notes` from each `common_fields`/`service.update_asset` dictionary.
- Keep `notes` only in the separate inventory-session confirmation route.
- Leave `_detail_form` generic, relying on the expanded tuple to retain `os_version`; retain its existing numeric/date parsing.
- When Nmap provides `os_name` or `os_version`, copy both to the detail flow, not just `os_name`.

- [ ] **Step 4: Run all web tests**

Run: `python -m pytest tests/test_inventory_web.py -q`

Expected: PASS, including existing manual-mode, photo, relation, and validation-draft tests.

- [ ] **Step 5: Commit the web-flow unit**

```bash
git add app/inventory/web.py tests/test_inventory_web.py
git commit -m "fix(inventory): preserve grouped card drafts"
```

### Task 5: Render mobile field blocks and detach location navigation from card collapse

**Files:**
- Modify: `app/templates/inventory_asset_form.html`
- Modify: `app/static/inventory.css`
- Test: `tests/test_inventory_web.py`

**Interfaces:**
- Consumes `form_values`, `details`, `identifiers`, and the Task 4 field names.
- Produces semantic `<fieldset class="inventory-field-group">` blocks and a location return link outside `details.inventory-asset-card`.

- [ ] **Step 1: Write failing HTML structure assertions**

```python
def test_pc_card_renders_grouped_controls_and_navigation_outside_details(tmp_path, monkeypatch):
    client, csrf = _client(tmp_path, monkeypatch)
    asset_id = _create_pc(client, csrf)
    page = client.get(f"/inventory/assets/{asset_id}")

    assert "<legend>Идентификация устройства</legend>" in page.text
    assert "<legend>Операционная система</legend>" in page.text
    assert '<select name="os_name">' in page.text
    assert '<option value="Windows">Windows</option>' in page.text
    assert '<select name="cpu_model">' in page.text
    assert '<option value="Intel">Intel</option>' in page.text
    assert '<select name="ram_type">' in page.text
    assert page.text.index("</details>") < page.text.index(">К ЛОКАЦИИ</a>")
```

Add a non-PC assertion that monitor forms render only core, identification, type-specific, and description groups; they must not render the network, OS, CPU, or RAM fields.

- [ ] **Step 2: Run the rendering tests and verify they fail**

Run: `python -m pytest tests/test_inventory_web.py -q`

Expected: FAIL because the current template uses a flat label list, text inputs for PC selects, and locates the return link inside `<details>`.

- [ ] **Step 3: Replace the flat template controls with semantic groups**

Use fieldsets in this order:

```html
<fieldset class="inventory-field-group">
  <legend>Основные данные</legend>
  <!-- Название, Инвентарный номер, Статус -->
</fieldset>
<fieldset class="inventory-field-group">
  <legend>Идентификация устройства</legend>
  <!-- Производитель, Модель, Serial -->
</fieldset>
```

Conditionally render a `Сеть` group only for PC, printer, phone, and other; `Операционная система`, `Процессор`, `Оперативная память`, and `Накопитель` only for PC; `Параметры устройства` only when the type owns an existing detail control; and `Пользователь` only for PC and phone. Render `Описание` as the final standalone group. Use empty option first in each PC select and select only canonical values:

```html
<label>ОС
  <select name="os_name">
    <option value="">Не указана</option>
    <option value="Windows"{% if details.get('os_name') == 'Windows' %} selected{% endif %}>Windows</option>
    <option value="Linux"{% if details.get('os_name') == 'Linux' %} selected{% endif %}>Linux</option>
  </select>
</label>
<label>Версия ОС<input name="os_version" value="{{ details.get('os_version') or '' }}"></label>
```

Close the asset `<details>` immediately after its forms/photo section, then render the `К ЛОКАЦИИ` anchor as a sibling in the outer section.

Add CSS only for the new grouping:

```css
.inventory-field-group { display: grid; gap: 10px; margin: 0; padding: 14px; border: 1px solid #d7dde7; border-radius: 10px; }
.inventory-field-group legend { padding: 0 6px; font-weight: 700; }
.inventory-form > .button.secondary { width: 100%; }
```

Keep existing layout, mobile button, photo, and collapse styling intact.

- [ ] **Step 4: Run the rendering and broader inventory test set**

Run: `python -m pytest tests/test_inventory_web.py tests/test_inventory_api.py tests/test_inventory_details.py tests/test_inventory_models.py tests/test_inventory_lookup.py -q`

Expected: PASS.

- [ ] **Step 5: Run static checks and commit UI implementation**

Run: `python -m ruff check app/inventory app/db.py tests/test_inventory_models.py tests/test_inventory_details.py tests/test_inventory_lookup.py tests/test_inventory_api.py tests/test_inventory_web.py`

Expected: PASS.

```bash
git add app/templates/inventory_asset_form.html app/static/inventory.css tests/test_inventory_web.py
git commit -m "feat(inventory): group mobile card fields"
```

### Task 6: Review, deploy, migrate production, and verify live behavior

**Files:**
- Modify: no additional source files expected
- Verify: local repository, `ssh ui-vpn-deploy`, production `/opt/openvpn-web`, production SQLite database, authenticated inventory page

**Interfaces:**
- Consumes the five committed code units and the existing `openvpn-web.service` deployment workflow.
- Produces a deployed service with backups, successful in-place migration, and verified live form layout.

- [ ] **Step 1: Verify the complete local change set before deployment**

Run:

```bash
git status --short
git diff --check main~5..HEAD
python -m pytest tests/test_inventory_web.py tests/test_inventory_api.py tests/test_inventory_details.py tests/test_inventory_models.py tests/test_inventory_lookup.py -q
python -m ruff check app/inventory app/db.py tests/test_inventory_models.py tests/test_inventory_details.py tests/test_inventory_lookup.py tests/test_inventory_api.py tests/test_inventory_web.py
```

Expected: working tree has no unrelated changes; all tests and Ruff pass.

- [ ] **Step 2: Back up production before touching service code or data**

Run one narrow remote command that creates a timestamped directory under `/var/backups/openvpn-web/`, copies `/var/lib/openvpn-web/openvpn-web.sqlite` into it, and records its SHA-256. Do not include environment files, passwords, or secrets in the backup command output.

Expected: backup file exists and has non-zero length before deployment.

- [ ] **Step 3: Deploy only tracked task files and restart once**

Sync the changed `app/`, `tests/` only if production test layout requires it, and `docs/` only if deployment policy carries documentation; never sync ignored env/config files. Confirm the deployed source file hashes match local task files, then run `sudo systemctl restart openvpn-web.service`.

Expected: `systemctl is-active openvpn-web.service` returns `active`.

- [ ] **Step 4: Verify production migration and no data loss**

As the application database user, query:

```sql
PRAGMA table_info(inventory_pc_details);
SELECT count(*) AS remaining_notes FROM inventory_assets WHERE notes IS NOT NULL AND trim(notes) <> '';
SELECT os_name, ram_type, cpu_model, count(*) FROM inventory_pc_details GROUP BY os_name, ram_type, cpu_model ORDER BY 4 DESC;
```

Expected: `os_version` column exists, `remaining_notes` is zero, and only canonical non-null select values remain for successfully recognized historic values. Inspect the three originally non-empty legacy descriptions to verify their content moved once.

- [ ] **Step 5: Verify live web/API behavior**

Check `/login` health, sign in through the existing safe browser session, then inspect one PC edit card and one monitor card. Confirm:

- the PC shows visible groups, canonical selects, OS version, and no `Комментарий` field;
- the monitor excludes network/PC-only fields;
- collapsing the PC card does not hide `К ЛОКАЦИИ`;
- an invalid MAC submission retains typed OS version and shows the validation error;
- a REST asset response has `os_version` in PC details but no asset-level `notes` key;
- inventory session check note behavior remains available.

- [ ] **Step 6: Record deployment evidence and publish**

Run:

```bash
git status --short
git log --oneline -5
git push origin main
git ls-remote origin refs/heads/main
```

Expected: local `main`, remote `main`, and deployed source identify the same completed commits. Report the backup path, service state, tests, and migration counts without exposing sensitive information.
