# Client Form Modes Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Make `/clients/new` show and submit only fields relevant to one user, one router, or batch client creation.

**Architecture:** Keep the existing FastAPI request contract intact. Add stable `data-mode-*` markers and one inline controller in the Jinja template that toggles `hidden`, `disabled`, and `required` state whenever the workflow selection changes.

**Tech Stack:** FastAPI, Jinja2, browser-native JavaScript, pytest/TestClient, Playwright browser smoke check.

## Global Constraints

- Do not change OpenVPN generation, networking, CIDR catalog management, router validation, or download behavior.
- Hidden controls must be disabled so they are absent from submitted form data.
- Batch creation always submits `client_type=user`.
- Existing direct POST handling remains the validation boundary.

---

### Task 1: Add the mode-controller contract to the client form

**Files:**
- Modify: `app/templates/client_new.html`
- Modify: `tests/test_routes_smoke.py`

**Interfaces:**
- Consumes: existing controls named `creation_mode`, `client_type`, `access_mode`, `profile`, `client`, `client_names`, `clients_csv`, `custom_cidrs`, `dns`, `vpn_ip`, `remote_lan_cidr`, and `create_server_route`.
- Produces: form sections selected by `data-mode-section` and a `syncClientFormModes()` browser function that applies the selected workflow.

- [ ] **Step 1: Write the failing template contract test**

Add this assertion to the existing `GET /clients/new` smoke test:

```python
assert 'data-mode-section="batch-input"' in form.text
assert 'data-mode-section="router-options"' in form.text
assert 'function syncClientFormModes()' in form.text
assert 'clientType.value = "user"' in form.text
```

- [ ] **Step 2: Run the test to verify it fails**

Run: `python -m pytest tests/test_routes_smoke.py::test_generate_batch_from_csv_runs_sync_after_success -q`

Expected: FAIL because the page has no mode-section markers or controller function.

- [ ] **Step 3: Mark the form sections and add the controller**

Wrap groups with the markers below and use one controller to update all dependent fields:

```html
<label data-mode-section="batch-input">...</label>
<div data-mode-section="router-options">...</div>
<script>
function syncClientFormModes() {
  const isBatch = creationMode.value === 'bulk';
  const isRouter = !isBatch && clientType.value !== 'user';
  const usesCustomRoutes = !isRouter && accessMode.value === 'custom';
  clientType.value = isBatch ? 'user' : clientType.value;
  setSection('batch-input', isBatch);
  setSection('single-input', !isBatch);
  setSection('router-options', isRouter);
  setSection('access-options', !isRouter);
  setSection('template-options', !isRouter && !usesCustomRoutes);
  setSection('custom-options', !isRouter && usesCustomRoutes);
}
</script>
```

`setSection` must set `section.hidden`, disable descendant form elements when hidden, and remove `required` from disabled controls. The profile select is required only in template and router flows; the single client name is required only outside batch mode.

- [ ] **Step 4: Run the test to verify it passes**

Run: `python -m pytest tests/test_routes_smoke.py::test_generate_batch_from_csv_runs_sync_after_success -q`

Expected: PASS.

- [ ] **Step 5: Run the focused regression suite**

Run: `python -m pytest tests/test_routes_smoke.py tests/test_client_batch.py tests/test_api_routes.py -q`

Expected: PASS; router preview, single client generation, CSV batch generation, and API routes remain covered.

- [ ] **Step 6: Commit**

```bash
git add app/templates/client_new.html tests/test_routes_smoke.py
git commit -m "feat: show client creation fields by mode"
```

### Task 2: Verify the three workflows in a browser

**Files:**
- Verify: `app/templates/client_new.html`

**Interfaces:**
- Consumes: `syncClientFormModes()` and every `data-mode-section` marker from Task 1.
- Produces: browser evidence that the visible fields and enabled submission controls match the selected workflow.

- [ ] **Step 1: Open the authenticated client creation page in the local test server**

Run the application with test credentials, authenticate, and open `/clients/new` through Playwright.

- [ ] **Step 2: Check one ordinary user**

Set `creation_mode=single` and `client_type=user`.

Expected: `single-input`, `access-options`, and `template-options` are visible; `batch-input` and `router-options` are hidden; `client` is enabled and required.

- [ ] **Step 3: Check one router**

Set `client_type=router_site_to_site`.

Expected: `single-input` and `router-options` are visible; `batch-input`, `access-options`, `template-options`, and `custom-options` are hidden and disabled; `remote_lan_cidr` is enabled.

- [ ] **Step 4: Check batch creation with custom routes**

Set `creation_mode=bulk` and `access_mode=custom`.

Expected: `batch-input` and `custom-options` are visible; `single-input` and `router-options` are hidden and disabled; `client_type` is `user`; `custom_cidrs` and `dns` are enabled; profile selection is disabled.

- [ ] **Step 5: Record the verification result in the implementation handoff**

Report the three observed states and any browser-console errors. Do not create VPN clients during this check.

## Self-review

- Spec coverage: Task 1 implements all three workflows, access-mode exclusivity, and disabled hidden values. Task 2 verifies each workflow in a real browser.
- Placeholder scan: no placeholders or deferred implementation language remain.
- Type consistency: selector names in Task 2 are produced by Task 1; no server-side interface changes are introduced.
