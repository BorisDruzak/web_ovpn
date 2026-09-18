# Inventory Endpoint Platform Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Add canonical Inventory-to-Endpoint bindings, local Endpoint state, safe synchronization, local context API/UI, and fail-closed deployment support without changing Endpoint Platform.

**Architecture:** Inventory owns durable bindings and cached Endpoint state; the existing SDK client and adapter remain the sole outbound boundary. A one-shot worker is the only automatic writer, while Network Observer consumes a derived safe projection rather than independently correlating an Endpoint UUID.

**Tech Stack:** Python 3, FastAPI, SQLAlchemy, Jinja2, systemd, pytest, published `endpoint-platform-client` wheel.

**Spec:** `docs/superpowers/specs/2026-09-18-inventory-endpoint-platform-design.md`

## Global Constraints

- Modify only `web_ovpn`; do not change `endpoint_platform`.
- Agent traffic is only Agent WSS to Endpoint Platform; `web_ovpn` uses only published SDK HTTPS through `EndpointPlatformServiceClient → EndpointContextAdapter`.
- Do not add direct Endpoint HTTP, Endpoint DB access, Agent runtime imports, WSS routes, or device credentials.
- Keep `ENDPOINT_PLATFORM_ENABLED=0` by default and fail closed on missing SDK, CA, token, TLS, scope, or smoke checks.
- Manual Inventory retains authority for location, inventory number, person, status, photos, relations, notes, and verified serial.
- An Endpoint UUID is opaque and is the stable reference only after binding confirmation.
- Worker failure preserves confirmed bindings and last good local Endpoint state.
- Never expose raw Endpoint payload, token, current OS username, or serial to Netctl; only safe agent presence, OS family, and device type cross that boundary.
- No production deployment belongs to this implementation plan.

---

## File structure

| File | Responsibility |
| --- | --- |
| `app/inventory/models.py` | Binding/status/source enums and Inventory-owned binding, state, sync-control models. |
| `app/db.py` | Additive schema migration and partial-index preparation for the new Inventory tables. |
| `app/endpoint_platform_client.py` | Redacted distinction between disabled, unavailable, and denied-scope SDK outcomes. |
| `app/endpoint_context_adapter.py` | Allow-listed profile/state projections, capability-aware reads, and collection request contract. |
| `app/inventory/endpoint.py` | Binding lifecycle, deterministic effective context, discrepancy resolution, and UUID lookup. |
| `app/inventory/endpoint_sync.py` | Lease-controlled reconciliation, normalized Endpoint state, semantic-hash history, and derived Netctl projection. |
| `app/endpoint_agent_network.py` | Compatibility-only projection from canonical Inventory state; retain legacy cache reads during rollback. |
| `app/inventory/api.py`, `app/inventory/schemas.py` | Local context/read and audited binding, refresh, and discrepancy APIs. |
| `app/inventory/web.py`, `app/templates/inventory_asset_form.html`, `app/static/inventory.{js,css}` | PC card’s local Agent block, candidates, state, and discrepancy controls. |
| `.env.example`, `requirements.txt`, `deploy/*` | Immutable SDK lock/wheel install, environment, verifier, and systemd unit/timer. |
| `tests/test_inventory_endpoint_*.py`, `tests/test_endpoint_*.py`, `tests/test_install_*.py` | Unit, API/UI, boundary, worker, and deployment regression coverage. |

### Task 1: SDK boundary, configuration, and architecture assertions

**Files:**
- Modify: `app/config.py:Settings and get_settings`
- Modify: `app/endpoint_platform_client.py:EndpointPlatformServiceClient`
- Modify: `app/endpoint_context_adapter.py:EndpointContextAdapter`
- Modify: `.env.example`
- Create: `tests/test_inventory_endpoint_boundary.py`
- Modify: `tests/test_endpoint_platform_client.py`

**Interfaces:**
- Produces `EndpointPlatformServiceScopeDenied`, a redacted service error.
- Produces `EndpointContextAdapter.read_profiles(device_id: UUID) -> dict[str, dict[str, Any] | None]`.
- Produces `EndpointContextAdapter.request_collection(device_id: UUID, profile: SafeProfile, idempotency_key: str) -> dict[str, Any]`.
- Consumed by Tasks 3, 4, 5, and 7.

- [ ] **Step 1: Write failing boundary and configuration tests**

```python
def test_inventory_endpoint_boundary_has_no_agent_transport_or_direct_http() -> None:
    forbidden = ("websocket", "websockets", "requests.", "httpx.", "endpoint_server", "pc_agent")
    sources = "\n".join(path.read_text(encoding="utf-8") for path in INVENTORY_SOURCES)
    assert not any(token in sources for token in forbidden)

def test_scope_denial_is_redacted_and_distinct_from_outage() -> None:
    assert str(EndpointPlatformServiceScopeDenied()) == "endpoint_platform_scope_denied"
```

Include settings assertions for default disabled state, absolute token/CA paths,
positive timeout, and `ENDPOINT_PLATFORM_SMOKE_DEVICE_ID` parsing only when
the smoke verifier is invoked.

- [ ] **Step 2: Run the focused tests to verify failure**

Run: `pytest tests/test_inventory_endpoint_boundary.py tests/test_endpoint_platform_client.py -q`

Expected: FAIL because scope-denial class, smoke-device setting, and architecture scan do not yet exist.

- [ ] **Step 3: Implement minimal boundary changes**

Add a redacted error code without preserving SDK exception text. Keep every SDK
method routed through `EndpointPlatformServiceClient._call`; classify
authorization/forbidden SDK errors to scope denied and all other upstream/local
errors to unavailable. Add only immutable configuration values:

```python
endpoint_platform_smoke_device_id: UUID | None

def read_profiles(self, device_id: UUID) -> dict[str, dict[str, Any] | None]:
    return {profile: self.get_latest_context(device_id, profile) for profile in SAFE_PROFILES}
```

Projection must allow-list snapshots and their known sections; missing profiles
return `None`, never a fabricated response.

- [ ] **Step 4: Run focused tests to verify pass**

Run: `pytest tests/test_inventory_endpoint_boundary.py tests/test_endpoint_platform_client.py tests/test_endpoint_context_api.py -q`

Expected: PASS; existing external Endpoint routes preserve their redacted
degraded behavior.

- [ ] **Step 5: Commit**

```bash
git add app/config.py app/endpoint_platform_client.py app/endpoint_context_adapter.py .env.example tests/test_inventory_endpoint_boundary.py tests/test_endpoint_platform_client.py
git commit -m "feat(inventory): harden Endpoint SDK boundary"
```

### Task 2: Persistent binding, state, and schema migration

**Files:**
- Modify: `app/inventory/models.py:InventoryObservationSource and new models`
- Modify: `app/db.py:_migrate_inventory_schema and additive index helpers`
- Create: `tests/test_inventory_endpoint_models.py`

**Interfaces:**
- Produces `InventoryExternalBindingStatus`, `InventoryExternalBinding`, `InventoryEndpointState`, and `InventoryEndpointSyncControl`.
- Produces `init_inventory_endpoint_schema() -> None` for the worker’s narrow startup path.
- Consumed by Tasks 3 through 6.

- [ ] **Step 1: Write failing model and migration tests**

```python
def test_confirmed_endpoint_binding_is_unique_per_pc_and_device(session: Session) -> None:
    first = confirmed_binding(asset_id="pc-1", external_id=DEVICE_A)
    session.add(first); session.flush()
    session.add(confirmed_binding(asset_id="pc-1", external_id=DEVICE_B))
    with pytest.raises(IntegrityError):
        session.flush()

def test_endpoint_observation_source_and_state_keep_hash_freshness_separate() -> None:
    assert InventoryObservationSource.ENDPOINT.value == "endpoint"
    assert {"baseline_semantic_hash", "last_checked_at", "safe_context_json"} <= state_columns
```

Cover non-PC rejection, active candidate de-duplication, ended-history reuse,
and migration from a database created before the new models.

- [ ] **Step 2: Run model tests to verify failure**

Run: `pytest tests/test_inventory_endpoint_models.py -q`

Expected: FAIL because models, partial indexes, and narrow initialization do not exist.

- [ ] **Step 3: Implement additive models and migration**

Use `Base.metadata` only for new-table creation in
`init_inventory_endpoint_schema`; do not call broad `init_db()` from a
worker. In `_migrate_inventory_schema`, add only missing nullable columns and
create SQLite partial indexes after normalizing no data beyond the new tables.
Use a single `binding_id` FK for state, with indexed `asset_id` and
`endpoint_device_id` copies. Make evidence/state JSON default to an empty
mapping and preserve timestamps as timezone-aware UTC.

- [ ] **Step 4: Run model tests to verify pass**

Run: `pytest tests/test_inventory_endpoint_models.py tests/test_inventory_models.py tests/test_inventory_storage.py -q`

Expected: PASS with schema creation and existing Inventory models unaffected.

- [ ] **Step 5: Commit**

```bash
git add app/inventory/models.py app/db.py tests/test_inventory_endpoint_models.py
git commit -m "feat(inventory): persist Endpoint bindings and state"
```

### Task 3: Binding lifecycle and effective-context service

**Files:**
- Create: `app/inventory/endpoint.py`
- Modify: `app/inventory/service.py:InventoryService facade`
- Create: `tests/test_inventory_endpoint_service.py`

**Interfaces:**
- Produces `InventoryEndpointService.reconcile_candidates(db, identities, now) -> list[InventoryExternalBinding]`.
- Produces `confirm_binding(db, asset_id, binding_id, actor, now)`, `reject_binding(...)`, `detach_binding(...)`, and `replace_binding(...)`.
- Produces `asset_context(db, asset_id, now) -> dict[str, Any]` and `lookup_confirmed_endpoint(db, endpoint_device_id) -> InventoryAsset | None`.
- Consumed by Tasks 4, 5, and 6.

- [ ] **Step 1: Write failing lifecycle and projection tests**

```python
def test_exact_one_to_one_mac_auto_confirms_and_uuid_becomes_stable(session):
    binding = endpoint_service.reconcile_candidates(session, [IDENTITY_A], NOW)[0]
    assert (binding.status, binding.binding_method, binding.external_id) == (
        CONFIRMED, "mac_exact", str(DEVICE_A)
    )

def test_context_prefers_endpoint_technical_values_without_overwriting_manual(session):
    context = endpoint_service.asset_context(session, PC_ID, NOW)
    assert context["effective"]["ram_gb"]["source"] == "endpoint"
    assert context["manual"]["details"]["ram_gb"] == 8
    assert context["discrepancies"][0]["field"] == "ram_gb"
```

Also cover duplicate MAC ambiguity, IP/hostname no-bind, serial/product UUID
candidate-only behavior, manual confirm/reject, detach, UUID replacement
history, non-PC rejection, and the three discrepancy dispositions.

- [ ] **Step 2: Run lifecycle tests to verify failure**

Run: `pytest tests/test_inventory_endpoint_service.py -q`

Expected: FAIL because the endpoint Inventory service does not exist.

- [ ] **Step 3: Implement deterministic service behavior**

Normalize identifiers with existing Inventory normalizers. Auto-confirm only an
exact MAC with one PC, one Endpoint identity, and neither active unique
conflict. Persist opaque UUIDs unchanged. Generate a local projection:

```python
{
    "asset": ..., "location": ..., "related_devices": ...,
    "sources": {"manual": ..., "netctl": ..., "endpoint": ...},
    "effective": {"ram_gb": {"value": 16, "source": "endpoint", "observed_at": ...}},
    "discrepancies": [...], "freshness": {...},
}
```

Discrepancy resolution writes an audit-ready disposition record/evidence; it
never alters location or assigned person.

- [ ] **Step 4: Run lifecycle tests to verify pass**

Run: `pytest tests/test_inventory_endpoint_service.py tests/test_inventory_service.py tests/test_inventory_details.py -q`

Expected: PASS with current hierarchy and manual-detail tests unchanged.

- [ ] **Step 5: Commit**

```bash
git add app/inventory/endpoint.py app/inventory/service.py tests/test_inventory_endpoint_service.py
git commit -m "feat(inventory): add Endpoint binding lifecycle"
```

### Task 4: Lease-controlled worker and compatibility projection

**Files:**
- Create: `app/inventory/endpoint_sync.py`
- Modify: `app/endpoint_agent_network.py:compatibility projection`
- Create: `tests/test_inventory_endpoint_sync.py`
- Modify: `tests/test_endpoint_agent_network.py`

**Interfaces:**
- Produces `run_inventory_endpoint_sync(now: datetime | None = None) -> int`.
- Produces `acquire_endpoint_sync_lease(db, now) -> bool`.
- Produces `sync_confirmed_bindings(db, adapter, now) -> SyncResult`.
- Produces `rebuild_endpoint_agent_network_cache(db, now) -> None`.
- Consumed by Task 7 systemd unit and Task 6 local reads.

- [ ] **Step 1: Write failing worker tests**

```python
def test_same_hash_updates_freshness_without_second_observation(monkeypatch, session):
    run_sync_with_snapshot(session, semantic_hash="a")
    run_sync_with_snapshot(session, semantic_hash="a")
    assert endpoint_observation_count(session) == 1
    assert state.last_checked_at == NOW_2

def test_outage_and_scope_denial_preserve_confirmed_binding_and_state(monkeypatch, session):
    run_sync_raising(EndpointPlatformServiceScopeDenied())
    assert confirmed_binding(session).ended_at is None
    assert endpoint_state(session).safe_context_json == LAST_GOOD_STATE
```

Cover lease exclusion, one-minute presence/five-minute full pass, profile
absence, changed hash, Netctl payload allow-list, and no remote work during
context rendering.

- [ ] **Step 2: Run worker tests to verify failure**

Run: `pytest tests/test_inventory_endpoint_sync.py tests/test_endpoint_agent_network.py -q`

Expected: FAIL because no Inventory Endpoint worker or derived cache exists.

- [ ] **Step 3: Implement the worker**

Worker startup calls only `init_inventory_endpoint_schema()`. It obtains the
adapter, reconciles unbound candidates, reads confirmed UUIDs, updates
allow-listed state, records changed hashes, and then calls the existing Netctl
fingerprint command with only:

```python
{"asset_key": key, "state": "confirmed", "os_family": "windows", "device_type": "pc"}
```

Rebuild `EndpointAgentNetworkLink` from canonical confirmed bindings/state;
do not use it to establish a binding. Catch disabled, unavailable, and
scope-denied errors separately as redacted control codes and retain cache.

- [ ] **Step 4: Run worker tests to verify pass**

Run: `pytest tests/test_inventory_endpoint_sync.py tests/test_endpoint_agent_network.py tests/test_inventory_netctl_sync.py -q`

Expected: PASS and Network Observer cache remains readable.

- [ ] **Step 5: Commit**

```bash
git add app/inventory/endpoint_sync.py app/endpoint_agent_network.py tests/test_inventory_endpoint_sync.py tests/test_endpoint_agent_network.py
git commit -m "feat(inventory): synchronize Endpoint state safely"
```

### Task 5: Aggregated local API and audited actions

**Files:**
- Modify: `app/inventory/api.py:Inventory router handlers`
- Modify: `app/inventory/schemas.py:request models`
- Create: `tests/test_inventory_endpoint_api.py`

**Interfaces:**
- Produces the exact local endpoints from the design:
  `/assets/{id}/context`, `/by-endpoint/{uuid}`, candidates, confirmation,
  rejection, detach, refresh, and discrepancy resolution.
- Consumes `InventoryEndpointService` and adapter collection request.
- Consumed by Task 6 UI and future Helpdesk service consumers.

- [ ] **Step 1: Write failing API tests**

```python
def test_context_is_local_and_preserves_last_good_endpoint_state(client, auth):
    response = client.get(f"/api/v1/inventory/assets/{PC_ID}/context", headers=auth)
    assert response.json()["data"]["effective"]["ram_gb"]["source"] == "endpoint"

def test_by_endpoint_returns_only_active_confirmed_binding(client, auth):
    assert client.get(f"/api/v1/inventory/by-endpoint/{DEVICE_A}", headers=auth).status_code == 200
    assert client.get(f"/api/v1/inventory/by-endpoint/{ENDED_DEVICE}", headers=auth).status_code == 404
```

Test API authentication, CSRF/audit for mutations, non-PC rejection, stale
responses, collection idempotency generation, and no adapter use during GET
context/candidate reads.

- [ ] **Step 2: Run API tests to verify failure**

Run: `pytest tests/test_inventory_endpoint_api.py -q`

Expected: FAIL with missing routes.

- [ ] **Step 3: Implement routes and schemas**

Use existing `require_api_actor`, `verify_api_csrf`, `write_audit`, and
Inventory error mapping. A refresh route calls only
`get_endpoint_context_adapter().request_collection`, closes it in `finally`,
and returns the redacted queued response. All GET projections are database-only.

- [ ] **Step 4: Run API tests to verify pass**

Run: `pytest tests/test_inventory_endpoint_api.py tests/test_inventory_api.py tests/test_endpoint_context_api.py -q`

Expected: PASS and existing API routes remain compatible.

- [ ] **Step 5: Commit**

```bash
git add app/inventory/api.py app/inventory/schemas.py tests/test_inventory_endpoint_api.py
git commit -m "feat(inventory): expose Endpoint asset context"
```

### Task 6: PC card presentation and browser behavior

**Files:**
- Modify: `app/inventory/web.py:inventory_asset_detail and PC actions`
- Modify: `app/templates/inventory_asset_form.html:PC card blocks`
- Modify: `app/static/inventory.js`
- Modify: `app/static/inventory.css`
- Create: `tests/test_inventory_endpoint_web.py`

**Interfaces:**
- Consumes the local context API and local candidate/action routes from Task 5.
- Produces an Agent block only for PC assets and no server-side remote Endpoint call during render.

- [ ] **Step 1: Write failing web tests**

```python
def test_pc_detail_shows_provenance_discrepancy_and_distinct_people(client):
    page = client.get(f"/inventory/assets/{PC_ID}")
    assert "Текущий пользователь ОС" in page.text
    assert "Закреплённый человек" in page.text
    assert "РАСХОЖДЕНИЯ" in page.text

def test_non_pc_detail_has_no_endpoint_binding_controls(client):
    assert "Найти агент" not in client.get(f"/inventory/assets/{MONITOR_ID}").text
```

Also cover no-binding, candidate, confirmed online/offline, stale/outage,
refresh action, CSRF, and safe escaping of Endpoint display values.

- [ ] **Step 2: Run web tests to verify failure**

Run: `pytest tests/test_inventory_endpoint_web.py -q`

Expected: FAIL because the Agent card and controls do not exist.

- [ ] **Step 3: Implement local card and actions**

`inventory_asset_detail` loads only local service context. Render Agent state,
provenance/freshness badges, candidate confirm/reject, detach, refresh, and
discrepancy controls only for PC. JavaScript calls local Inventory endpoints
with existing CSRF token handling; it never contacts Endpoint directly.

- [ ] **Step 4: Run web tests to verify pass**

Run: `pytest tests/test_inventory_endpoint_web.py tests/test_inventory_web.py tests/test_inventory_photos.py -q`

Expected: PASS with the mobile one-column Inventory flow retained.

- [ ] **Step 5: Commit**

```bash
git add app/inventory/web.py app/templates/inventory_asset_form.html app/static/inventory.js app/static/inventory.css tests/test_inventory_endpoint_web.py
git commit -m "feat(inventory): show Endpoint context on PC cards"
```

### Task 7: Immutable SDK deployment, verifier, and scheduled worker

**Files:**
- Modify: `requirements.txt`
- Create: `deploy/endpoint-platform-client.lock`
- Create: `deploy/verify_endpoint_platform.py`
- Create: `deploy/inventory-endpoint-sync.service`
- Create: `deploy/inventory-endpoint-sync.timer`
- Modify: `deploy/install-openvpn-web.sh`
- Create: `tests/test_inventory_endpoint_deploy.py`
- Modify: `tests/test_install_execution_secrets.py`

**Interfaces:**
- Produces a lock manifest containing immutable wheel filename, distribution
  version, and SHA-256; installer refuses a missing/mismatched artifact.
- Produces `verify-endpoint-platform` exit zero only after SDK, CA, token,
  required reads, and approved-device collection succeed.
- Consumes `run_inventory_endpoint_sync` from Task 4.

- [ ] **Step 1: Write failing deployment verifier tests**

```python
def test_verifier_refuses_scope_denial_and_does_not_enable_timer(sandbox):
    result = sandbox.run_verifier(scope_error=True)
    assert result.returncode != 0
    assert not sandbox.timer_enabled("inventory-endpoint-sync.timer")

def test_sdk_lock_requires_exact_installed_version_and_sha256(sandbox):
    assert sandbox.verify_lock(version="1.2.3", digest="bad").returncode != 0
```

Cover SDK import, immutable hash/version, root-managed token/group readability,
CA readability, redirect/TLS failure, all three exact scopes, no secret output,
and systemd verification-before-enable.

- [ ] **Step 2: Run deployment tests to verify failure**

Run: `pytest tests/test_inventory_endpoint_deploy.py tests/test_install_execution_secrets.py -q`

Expected: FAIL because lock/verifier/unit files are absent.

- [ ] **Step 3: Implement installer and verifier**

The lock must name the released wheel supplied with the source artifact and its
SHA-256. Installer verifies it before `pip --no-index --no-deps`, validates
the installed distribution and import, installs the verifier/units, and adds
the default-disabled Endpoint settings without emitting secret values. Verifier
runs as `openvpn-web`, uses the existing client/adapter, verifies reads and
one idempotent `baseline_v1` collection against
`ENDPOINT_PLATFORM_SMOKE_DEVICE_ID`, and emits redacted codes. Enable the
timer only after verifier exit zero; otherwise leave it disabled.

- [ ] **Step 4: Run deployment tests to verify pass**

Run: `pytest tests/test_inventory_endpoint_deploy.py tests/test_install_execution_tls.py tests/test_install_execution_secrets.py tests/test_inventory_endpoint_boundary.py -q`

Expected: PASS; no moving branch or unpinned SDK installation path remains.

- [ ] **Step 5: Commit**

```bash
git add requirements.txt deploy/endpoint-platform-client.lock deploy/verify_endpoint_platform.py deploy/inventory-endpoint-sync.service deploy/inventory-endpoint-sync.timer deploy/install-openvpn-web.sh tests/test_inventory_endpoint_deploy.py tests/test_install_execution_secrets.py
git commit -m "feat(inventory): deploy Endpoint synchronization safely"
```

### Task 8: End-to-end regression, documentation, and release evidence

**Files:**
- Modify: `docs/superpowers/specs/2026-09-18-inventory-endpoint-platform-design.md` only if implementation uncovered an actual public-contract blocker
- Create: `docs/runbooks/inventory-endpoint-platform-service-client.md`
- Modify: `README.md`
- Create: `tests/test_inventory_endpoint_regression.py`

**Interfaces:**
- Produces administrator instructions for exact service-client scopes, token/CA placement, lock artifact verification, smoke-device approval, enablement, rollback, and blocker escalation.
- Produces full cross-domain regression evidence without deployment.

- [ ] **Step 1: Write the cross-domain regression test**

```python
def test_endpoint_outage_keeps_inventory_netctl_and_last_endpoint_context_usable(client, seeded_state):
    disable_remote_adapter()
    assert client.get(f"/api/v1/inventory/assets/{PC_ID}/context").status_code == 200
    assert client.get("/inventory").status_code == 200
    assert endpoint_value_is_marked_stale(client, PC_ID)
```

Include manual Inventory editing, Netctl synchronization, Endpoint state cache,
active confirmed UUID lookup, and Network Observer compatibility read.

- [ ] **Step 2: Run the regression test to verify failure**

Run: `pytest tests/test_inventory_endpoint_regression.py -q`

Expected: FAIL until all prior pieces are connected.

- [ ] **Step 3: Write operations documentation and repair integration defects**

Document the exact external administrative action, three scopes, file paths,
permissions, immutable wheel/manifest check, verifier invocation, timer
enablement, disabled default, rollback, and concrete `endpoint_platform`
blocker template. Make only implementation-required fixes revealed by the
cross-domain test; do not broaden scope to production rollout.

- [ ] **Step 4: Run full relevant regression**

Run: `pytest tests/test_inventory_endpoint_*.py tests/test_inventory_*.py tests/test_endpoint_agent_network.py tests/test_endpoint_platform_client.py tests/test_endpoint_context_api.py tests/test_web_network_observer.py tests/test_install_execution_tls.py tests/test_install_execution_secrets.py -q`

Expected: PASS. Also run `ruff check app tests deploy` if the repository has
Ruff available, and `git diff --check`.

- [ ] **Step 5: Commit**

```bash
git add docs/runbooks/inventory-endpoint-platform-service-client.md README.md tests/test_inventory_endpoint_regression.py
git commit -m "docs(inventory): document Endpoint service client setup"
```

## Plan self-review

- Spec coverage: Tasks 1 and 7 cover the exclusive published-SDK boundary,
  scopes, configuration, immutable deployment, smoke gate, feature flag, and
  rollback. Tasks 2–4 cover separate canonical binding/state tables, history,
  migration, resilience, profiles, deduplicated observations, and derived
  Network Observer projection. Tasks 5–6 cover context/UUID APIs, local UI,
  provenance, freshness, manual actions, and discrepancies. Task 8 covers
  operations documentation and full non-production verification.
- No-placeholder scan: the only operator-supplied values are intentionally
  external prerequisites (released wheel metadata and approved smoke UUID);
  code verifies their presence and refuses enablement otherwise.
- Type consistency: Task 2 defines the models used by Task 3; Task 3 provides
  the service read/mutation interfaces used by Tasks 4–6; Task 4 provides the
  worker entrypoint installed by Task 7.
