# Web UI Latency Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Make the initial dashboard HTML independent from live OpenVPN CLI work and remove expensive synchronization from the clients GET path.

**Architecture:** Keep FastAPI and Jinja rendering. A session-only JSON endpoint hydrates dashboard metric placeholders after HTML returns. A thread-safe in-process snapshot cache coalesces read refreshes, protects last-good data, and calls one new read-only `vpnctl web-summary` command with a short timeout.

**Tech Stack:** Python 3.14, FastAPI, Jinja2, vanilla JavaScript, nginx, pytest.

## Global Constraints

- Do not modify OpenVPN, MikroTik, DNS, DHCP, firewall, or other network configuration.
- Keep all mutations explicit POST actions with current CSRF, sudo, and audit behavior.
- Do not use bearer-token API authentication from browser JavaScript.
- Use `time.monotonic()` for TTL; never cache mutation results or CLI stdout/stderr.
- Keep cache process-local; document the per-worker limitation.
- Read-only UI commands use explicit five-second limits; sync and mutation limits stay unchanged.
- No SPA framework, Redis, Celery, or worker-count change.

---

## File Structure

- Create: `app/ui_snapshot_cache.py` — generic single-flight, last-good TTL cache.
- Modify: `deploy/vpnctl` — one `web-summary` read-only CLI subcommand.
- Modify: `app/vpnctl_client.py`, `app/netctl_client.py` — safe duration/outcome logging.
- Modify: `app/main.py` — dashboard collector, session endpoint, UI timeouts, and clients GET behavior.
- Modify: `app/templates/dashboard.html`, `app/static/app.js` — placeholders, hydration, and non-overlapping polling.
- Modify: `deploy/nginx-openvpn-web.conf` — direct static serving with one-hour non-immutable caching.
- Modify: `tests/test_routes_smoke.py`, `tests/test_vpnctl_client.py` — route and CLI contract tests.
- Create: `tests/test_ui_snapshot_cache.py` — cache behavior tests.

### Task 1: Remove automatic synchronization from clients GET

**Files:**
- Modify: `app/main.py:869-895`
- Modify: `tests/test_routes_smoke.py:92-155`

**Interfaces:**
- `GET /clients` consumes only `vpnctl list` and `vpnctl profiles`.
- `POST /clients/sync` continues to call `force_client_sync(..., action="manual-sync")`.

- [ ] **Step 1: Write failing route assertions**

After `client.get("/clients")`, parse the fake CLI JSON-lines log and assert no command has `call[1] == "sync"`. Submit `POST /clients/sync` with the rendered CSRF token and assert a `sync` command is present.

- [ ] **Step 2: Run RED**

Run: `py -m pytest -q tests/test_routes_smoke.py -k "dashboard_and_clients_smoke"`

Expected: FAIL because the current GET invokes `maybe_client_sync`.

- [ ] **Step 3: Implement the smallest route change**

Remove only:

```python
sync_error = maybe_client_sync(db, request, user, "clients page")
```

from `clients()`, stop importing `maybe_client_sync`, and return the list error alone. Keep all mutation `force_client_sync` calls untouched.

- [ ] **Step 4: Verify GREEN**

Run: `py -m pytest -q tests/test_routes_smoke.py -k "dashboard_and_clients_smoke"`

Expected: PASS.

### Task 2: Add the single read-only dashboard summary command

**Files:**
- Modify: `deploy/vpnctl:2790-3150`
- Modify: `tests/test_vpnctl_client.py`

**Interfaces:**
- `vpnctl --json web-summary` returns `{ "status": "ok", "data": {"openvpn": str, "nat": str, "clients_count": int, "connected_count": int} }`.
- It combines `service_status()` and `list_clients()`; `connected_count` derives from each list row’s `connected` flag.

- [ ] **Step 1: Write the failing CLI contract test**

Build a temporary vpnctl environment with active/inactive service stubs and one connected list row. Invoke `web-summary` and assert its four public fields; assert no `connected` command is spawned externally.

- [ ] **Step 2: Run RED**

Run: `py -m pytest -q tests/test_vpnctl_client.py -k web_summary`

Expected: FAIL because the parser has no `web-summary` command.

- [ ] **Step 3: Implement the command**

Add parser registration and dispatch:

```python
if args.cmd == "web-summary":
    services = service_status()
    clients = list_clients()
    data = {
        "status": "ok",
        "data": {
            "openvpn": str(services.get("openvpn", {}).get("active", "unknown")),
            "nat": str(services.get("nat", {}).get("active", "unknown")),
            "clients_count": len(clients),
            "connected_count": sum(bool(client.get("connected")) for client in clients),
        },
    }
    emit(data, args)
    return 0
```

- [ ] **Step 4: Verify GREEN**

Run: `py -m pytest -q tests/test_vpnctl_client.py -k web_summary`

Expected: PASS.

### Task 3: Build and test the snapshot cache

**Files:**
- Create: `app/ui_snapshot_cache.py`
- Create: `tests/test_ui_snapshot_cache.py`

**Interfaces:**
- `SnapshotCache.get(key: str, ttl_seconds: float, loader: Callable[[], SnapshotResult]) -> SnapshotResult`.
- `SnapshotResult` holds `data: dict[str, Any]`, `generated_at: datetime`, `stale: bool`, and `errors: list[str]`.

- [ ] **Step 1: Write failing cache tests**

Test a cache hit calls the loader once, expiry calls it twice, a failed loader returns prior data with `stale=True`, and two threads sharing a blocked loader cause exactly one loader execution.

- [ ] **Step 2: Run RED**

Run: `py -m pytest -q tests/test_ui_snapshot_cache.py`

Expected: FAIL because the module does not exist.

- [ ] **Step 3: Implement cache with condition-protected entries**

Use `threading.Condition(threading.RLock())`, `time.monotonic()`, and a per-key `refreshing` flag. Store immutable/deep-copied JSON-compatible data. When a refresh fails, retain old data and return a normalized safe error code instead of exception output.

- [ ] **Step 4: Verify GREEN**

Run: `py -m pytest -q tests/test_ui_snapshot_cache.py`

Expected: PASS.

### Task 4: Decouple and hydrate dashboard

**Files:**
- Modify: `app/main.py:852-868`
- Modify: `app/templates/dashboard.html`
- Modify: `app/static/app.js`
- Modify: `tests/test_routes_smoke.py`

**Interfaces:**
- `GET /` renders loading placeholders and never calls `run_vpnctl` or `run_netctl`.
- `GET /dashboard/data` requires the existing session and returns `{status, generated_at, stale, data, errors}`.

- [ ] **Step 1: Write failing slow-CLI tests**

Extend fake vpnctl with an optional `FAKE_VPNCTL_DELAY_SECONDS`. Log calls. Assert a signed-in `GET /` returns HTML without a CLI log line when the fake would sleep. Assert `/dashboard/data` returns the four-field contract and unauthenticated access receives the existing 303 login redirect.

- [ ] **Step 2: Run RED**

Run: `py -m pytest -q tests/test_routes_smoke.py -k "dashboard_initial or dashboard_data"`

Expected: FAIL because dashboard GET currently runs three CLI commands and no endpoint exists.

- [ ] **Step 3: Implement HTML, collector, and endpoint**

Make `dashboard()` call only `require_user` and `render`. Add a collector that calls `run_vpnctl(["web-summary"], timeout=5)` through `SnapshotCache`. Return only normalized metrics and safe errors; attach `Server-Timing: vpnctl;dur=<milliseconds>` to JSON. Template metric values begin as `Loading…`, use `data-dashboard-*` selectors, and JS fetches same-origin JSON after DOM ready.

- [ ] **Step 4: Verify GREEN**

Run: `py -m pytest -q tests/test_routes_smoke.py -k "dashboard_initial or dashboard_data"`

Expected: PASS.

### Task 5: Bound UI reads, instrument commands, and fix polling

**Files:**
- Modify: `app/main.py`, `app/vpnctl_client.py`, `app/netctl_client.py`, `app/static/app.js`
- Modify: `tests/test_routes_smoke.py`, `tests/test_vpnctl_client.py`

**Interfaces:**
- CLI logging emits command name, integer duration milliseconds, outcome, and optional request ID; no raw output or sensitive args.
- Clients list/profiles reads use five seconds, while sync/mutation behavior remains unchanged.

- [ ] **Step 1: Write failing behavior tests**

Assert a delayed `list` or `profiles` returns the controlled page error within the explicit timeout path. Unit-test timeout logging contains `timeout` and duration. Add JS source assertions for `AbortController`, `document.hidden`, and no `setInterval`.

- [ ] **Step 2: Run RED**

Run: `py -m pytest -q tests/test_routes_smoke.py tests/test_vpnctl_client.py`

Expected: FAIL until UI-specific timeout and polling code exists.

- [ ] **Step 3: Implement bounded calls and serialized polling**

Pass `timeout=5` from dashboard/client read callers; retain existing explicit longer mutation timeouts. Time `subprocess.run` with `time.monotonic()` and log only command verb/outcome/duration. Replace `setInterval` with a self-scheduling completion callback, guard one request in flight, abort after five seconds, and refresh only while visible.

- [ ] **Step 4: Verify GREEN**

Run: `py -m pytest -q tests/test_routes_smoke.py tests/test_vpnctl_client.py`

Expected: PASS.

### Task 6: Serve assets directly and verify/release

**Files:**
- Modify: `deploy/nginx-openvpn-web.conf`
- Modify: `docs/DEPLOYMENT.md`

- [ ] **Step 1: Add direct static location**

Add a `location /static/` using `alias /opt/openvpn-web/app/static/`, `try_files $uri =404`, and `Cache-Control: public, max-age=3600`. Do not use `immutable` because URLs are not fingerprinted.

- [ ] **Step 2: Run local full verification**

Run: `py -m pytest -q`

Expected: all tests pass.

- [ ] **Step 3: Record before/after CLI and authenticated HTTP timings**

On deploy host, use only read-only `vpnctl status`, `list`, `connected`, `profiles`, `web-summary`, and authenticated `curl` requests. Record five-run p50 TTFB/total and CLI durations; do not benchmark `sync`.

- [ ] **Step 4: Merge, deploy, restart, and smoke-check**

Merge the verified branch into `main`, sync only tracked application files to `/opt/openvpn-web`, validate nginx configuration, reload nginx, restart `openvpn-web`, and use read-only MCP/HTTP checks. Confirm `GET /` has no live CLI and endpoint cache behavior through logs/timing headers.
