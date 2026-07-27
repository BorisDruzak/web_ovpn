# Server Health Web Page Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Restore trustworthy, read-only server-health collection and expose the redacted status on `/network/server-health` and its authenticated API.

**Architecture:** Keep the collector as the sole component that contacts monitored hosts. Extend its persisted snapshot with a strictly allow-listed collector failure record, then derive a validated read-only view for the web/API layer. The HTML page is server-rendered and uses native disclosure controls, so viewing it never starts collection or accesses runtime topology.

**Tech Stack:** Python 3, FastAPI, Jinja2, pytest, systemd, existing OpenVPN Web deployment scripts.

## Global Constraints

- Do not modify MikroTik, OpenVPN, DNS, DHCP, IPsec, firewall rules, or monitored-server configuration.
- Do not commit `/etc/openvpn-web/server-observer.json`, keys, pinned host keys, addresses, SSH users, passwords, commands, raw stdout/stderr, or journal output.
- `server-observer.service` remains isolated, runs as `openvpm:openvpn-web`, and preserves its current ownership, permissions, timer, and filesystem hardening.
- Browser and API reads must not invoke SSH, shell commands, `netctl`, `vpnctl`, or the collector.
- Any snapshot key not explicitly allow-listed is rejected or discarded before it can reach HTTP.
- Use `STALE_AFTER` and `FUTURE_TOLERANCE` from `app.server_observer` as the only freshness policy.

---

## File structure

- Modify `app/server_observer.py`: validate and atomically persist an optional redacted collector record; expose a structured snapshot-load result without changing `load_snapshot()` consumers.
- Modify `app/server_observer_cli.py`: classify top-level collection failures and attempt to persist a redacted failure snapshot.
- Create `app/server_health_view.py`: transform validated snapshot data into the page/API contract and dashboard-card summary.
- Modify `app/main.py`, `app/api.py`, `app/templates/base.html`, and `app/templates/network_dashboard.html`: add authenticated routes, navigation, and the dashboard link.
- Create `app/templates/network_server_health.html`: render freshness, collector state, counters, and per-role expandable checks.
- Optionally modify `app/static/app.css` only for page-specific disclosure/banner layout; preserve global status colours.
- Modify `tests/test_server_observer.py`, `tests/test_deploy_server_observer.py`, and `tests/test_web_network_observer.py`; create `tests/test_server_health_view.py`.
- Update `docs/DEPLOYMENT.md` with the scoped verification and rollback sequence.

### Task 0: Identify the production collector failure before changing its configuration

**Files:**
- Read: `/etc/openvpn-web/server-observer.json`, service metadata, protected journal, and snapshot on `ui-vpn-deploy`.
- Modify: none until a specific cause is demonstrated.

**Interfaces:**
- Consumes: `server-observer.service`, `server-observer.timer`, the redacted collector CLI result.
- Produces: a dated, local operator note stating the proven failure class and the exact recovery action; no sensitive data is copied into Git or the web panel.

- [ ] **Step 1: Capture read-only service and snapshot evidence via the OpenVPN diagnostic tools first.**

  Record timer scheduling, last service result, snapshot modification time, `collected_at`, and whether the snapshot is stale. Do not treat the five-day-old snapshot as current health.

- [ ] **Step 2: Run the collector once under its service account and inspect only the protected journal.**

  Run:

  ```powershell
  ssh ui-vpn-deploy "sudo -u openvpm -g openvpn-web /usr/local/sbin/server-observer --once; sudo journalctl -u server-observer.service -n 80 --no-pager"
  ```

  Expected: a non-zero result reproduces the failure and the journal identifies one category: runtime configuration, SSH/pinned-host-key connectivity, an allow-listed probe, or snapshot persistence.

- [ ] **Step 3: Apply only the demonstrated runtime repair outside Git.**

  Examples: repair file ownership/mode for an existing observer file, correct a pre-approved pinned host key, or correct a known configuration entry. Do not create a target, change a remote service, or replace credentials as a guess.

- [ ] **Step 4: Re-run the one-shot collection and verify fresh evidence.**

  Expected: exit code `0`, `latest.json` has a new UTC `collected_at`, is redacted, and `systemctl list-timers server-observer.timer` shows the next five-minute run.

### Task 1: Make collector failures safe, structured, and persistable

**Files:**
- Modify: `app/server_observer.py: public_snapshot(), load_snapshot()`.
- Modify: `app/server_observer_cli.py: main()`.
- Test: `tests/test_server_observer.py` and `tests/test_deploy_server_observer.py`.

**Interfaces:**
- Consumes: current success snapshots with `collected_at`, `overall`, and `targets`.
- Produces: optional persisted `collector` mapping with exactly `status`, `failure_class`, and `message`; `load_snapshot_result(path, now) -> dict[str, Any]` with `snapshot` and `freshness` fields.

- [ ] **Step 1: Write failing contract tests for the collector record and snapshot state.**

  ```python
  def test_failure_snapshot_redacts_exception_and_allows_only_safe_collector_fields(tmp_path):
      path = tmp_path / "latest.json"
      write_snapshot(path, {
          "collected_at": "2026-07-27T12:00:00Z", "overall": "error", "targets": [],
          "collector": {"status": "error", "failure_class": "ssh", "message": "SSH connection failed"},
      })
      assert load_snapshot(path, parse_utc("2026-07-27T12:01:00Z"))["collector"]["failure_class"] == "ssh"
      assert "192.168." not in path.read_text(encoding="utf-8")
  ```

  Add tests that reject a collector `host`, `command`, traceback, arbitrary status, unknown failure class, and overlong message; add `missing`, `invalid`, `stale`, and future-dated assertions for `load_snapshot_result`.

- [ ] **Step 2: Run the focused tests and confirm the new API is absent.**

  Run: `pytest tests/test_server_observer.py tests/test_deploy_server_observer.py -k "failure_snapshot or snapshot_result" -v`  
  Expected: FAIL because `collector` and `load_snapshot_result` are not supported.

- [ ] **Step 3: Implement the allow-listed snapshot extension.**

  In `app/server_observer.py`, add constants for the five stable classes `config`, `ssh`, `probe`, `snapshot_write`, and `internal`. Add `public_collector()` that accepts only a short fixed-message mapping. Extend `public_snapshot()` to retain only this public record. Add `load_snapshot_result()` that returns one of `current`, `stale`, `missing`, or `invalid`; retain `load_snapshot()` as the compatibility wrapper returning its validated snapshot with existing `overall` semantics for `network_paths_adapter.py`.

- [ ] **Step 4: Implement safe top-level CLI failure handling.**

  In `app/server_observer_cli.py`, add `classify_collection_failure(exc) -> tuple[str, str]`; it maps known validation errors to `config`, SSH timeout/transport boundaries to `ssh`, probe result boundaries to `probe`, persistence failures to `snapshot_write`, and all remaining exceptions to `internal`. Do not derive a public message from `str(exc)`.

  On a failure after argument parsing, construct:

  ```python
  failure_snapshot = {
      "collected_at": now.isoformat().replace("+00:00", "Z"),
      "overall": "error", "targets": [],
      "collector": {"status": "error", "failure_class": failure_class, "message": safe_message},
  }
  ```

  Attempt `write_snapshot()` once. If persistence itself fails, return `1` and emit only the fixed JSON stderr message; the protected journal remains the diagnostic source.

- [ ] **Step 5: Run focused and regression tests.**

  Run:

  ```powershell
  pytest tests/test_server_observer.py tests/test_deploy_server_observer.py -v
  pytest tests/test_network_paths.py -k "server_health" -v
  ```

  Expected: PASS; existing VPN-path freshness assertions keep their current behavior.

- [ ] **Step 6: Commit the isolated collector change.**

  ```powershell
  git add app/server_observer.py app/server_observer_cli.py tests/test_server_observer.py tests/test_deploy_server_observer.py
  git commit -m "fix: record redacted server observer failures"
  ```

### Task 2: Build the read-only Server Health view model

**Files:**
- Create: `app/server_health_view.py`.
- Test: `tests/test_server_health_view.py`.

**Interfaces:**
- Consumes: `load_snapshot_result(path: Path, now: datetime) -> dict[str, Any]`.
- Produces: `build_server_health_view(path: Path, now: datetime) -> dict[str, Any]` with `freshness`, `collected_at`, `age_seconds`, `collector`, `summary`, and `targets`.

- [ ] **Step 1: Write failing pure-view tests.**

  ```python
  def test_view_summarizes_current_role_checks_without_topology(tmp_path):
      view = build_server_health_view(snapshot_path, parse_utc("2026-07-27T12:01:00Z"))
      assert view["freshness"] == "current"
      assert view["summary"] == {"ok": 1, "warn": 0, "critical": 1, "error": 0}
      assert set(view["targets"][0]) == {"role", "status", "problem_count", "observed_at", "checks"}
  ```

  Cover current collector failure, missing/invalid/stale/future data, empty targets, all four target statuses, and a hostile snapshot containing an address or command string.

- [ ] **Step 2: Run the new test module.**

  Run: `pytest tests/test_server_health_view.py -v`  
  Expected: FAIL because the module and function do not exist.

- [ ] **Step 3: Implement `build_server_health_view`.**

  Use `load_snapshot_result()` once. Derive `age_seconds` only from validated UTC data and return `None` otherwise. Normalize missing `collector` to `{"status": "ok", "failure_class": "", "message": ""}`. Copy only role, status, allowed check name/status/observed/expected/latency/error fields already validated by `public_snapshot`; turn each safe check error into the rendered `message`. Count `warn`, `critical`, and `error` checks as role problems. Do not return raw snapshot mappings.

- [ ] **Step 4: Run the view and snapshot suites.**

  Run: `pytest tests/test_server_health_view.py tests/test_server_observer.py -v`  
  Expected: PASS with no filesystem or subprocess mocks beyond reading the supplied snapshot.

- [ ] **Step 5: Commit the view-model boundary.**

  ```powershell
  git add app/server_health_view.py tests/test_server_health_view.py
  git commit -m "feat: add redacted server health view"
  ```

### Task 3: Add authenticated API, routes, navigation, and rendered page

**Files:**
- Modify: `app/main.py`, `app/api.py`, `app/templates/base.html`, `app/templates/network_dashboard.html`.
- Create: `app/templates/network_server_health.html`.
- Modify: `app/static/app.css` only if required for `.health-banner` and disclosure spacing.
- Test: `tests/test_web_network_observer.py`.

**Interfaces:**
- Consumes: `build_server_health_view(settings.server_observer_snapshot_path, datetime.now(timezone.utc))`.
- Produces: `GET /network/server-health`, `GET /api/v1/network/server-health`, and dashboard card data using the same view contract.

- [ ] **Step 1: Write failing HTTP and rendering tests.**

  ```python
  def test_server_health_requires_login_and_api_token_and_redacts_snapshot(tmp_path, monkeypatch):
      client, headers = make_client(tmp_path, monkeypatch)
      assert client.get("/network/server-health", follow_redirects=False).status_code == 303
      assert client.get("/api/v1/network/server-health").status_code == 401
      login(client)
      assert client.get("/network/server-health").status_code == 200
      response = client.get("/api/v1/network/server-health", headers=headers)
      assert response.json()["data"]["freshness"] == "current"
      assert "192.168." not in response.text
  ```

  Add tests for counters, `details`/`summary` check expansion, stale and collector-failure banners, sidebar link, dashboard link/count, and a marker proving no collection command is invoked.

- [ ] **Step 2: Run the new web tests.**

  Run: `pytest tests/test_web_network_observer.py -k "server_health" -v`  
  Expected: FAIL because neither route exists.

- [ ] **Step 3: Add the server and API routes.**

  Import the view builder in `app/main.py` and `app/api.py`. The browser route calls `require_user()` then renders `network_server_health.html`; the API route uses `require_api_actor()` and returns `api_response({"server_health": view})`. Both read only `settings.server_observer_snapshot_path`; neither accepts a path from the request.

- [ ] **Step 4: Render the page without client-side data fetching.**

  Add a `Server health` sidebar link active for `/network/server-health`. Replace the static dashboard card with a link and a derived current/stale/error text. In the new template, use a status banner, four metrics, and a table whose detail column contains native `<details><summary>Checks</summary>…</details>`. Escape all Jinja values normally; do not use `|safe` or `innerHTML`.

- [ ] **Step 5: Run full web regression tests and browser smoke checks.**

  Run:

  ```powershell
  pytest tests/test_web_network_observer.py -v
  python -m pytest tests/test_network_paths.py -v
  ```

  Then sign in locally, open `/network/server-health`, confirm all rows collapse/expand, and inspect the API response for forbidden topology strings.

- [ ] **Step 6: Commit the web surface.**

  ```powershell
  git add app/main.py app/api.py app/templates/base.html app/templates/network_dashboard.html app/templates/network_server_health.html app/static/app.css tests/test_web_network_observer.py
  git commit -m "feat: show server health in network panel"
  ```

### Task 4: Deploy safely and verify the production page

**Files:**
- Modify: `docs/DEPLOYMENT.md`.
- Test: deployment commands on `ui-vpn-deploy`; authenticated production page/API checks.

**Interfaces:**
- Consumes: verified local commit sequence, existing `deploy/backup-server-observer.sh`, `deploy/install-server-observer.sh`, and web installer.
- Produces: a fresh production snapshot and functioning authenticated Server Health page, or a documented rollback to the prior scoped observer runtime.

- [ ] **Step 1: Add the deployment runbook checks.**

  Document: back up observer assets first; deploy only the verified source directory; one-shot collector; validate snapshot freshness and JSON redaction; check timer; log in to the page; call bearer API; and roll back with the backup path if any acceptance check fails.

- [ ] **Step 2: Verify all local gates before transferring files.**

  Run:

  ```powershell
  pytest tests/test_server_observer.py tests/test_deploy_server_observer.py tests/test_server_health_view.py tests/test_web_network_observer.py tests/test_network_paths.py -v
  git diff --check
  ```

  Expected: PASS and no whitespace errors. Stop if unrelated uncommitted changes would be included in the transfer.

- [ ] **Step 3: Create a scoped production backup and deploy both observer runtime and web application.**

  Use the existing backup script on `ui-vpn-deploy`, record the printed backup path, copy the exact reviewed source tree to a unique `/tmp/openvpn-web-src-<timestamp>` directory, then invoke `deploy/install-server-observer.sh` and the web installer with `SRC` explicitly set to that unique path. Never let an installer silently select an older `/tmp/openvpn-web-src` tree.

- [ ] **Step 4: Perform production acceptance checks.**

  Run one observer collection as `openvpm:openvpn-web`; confirm the snapshot has a current UTC timestamp, only allowed JSON keys, and no address/key/command text. Confirm `server-observer.timer` is enabled and scheduled. In an authenticated browser open `http://192.168.100.30:8088/network/server-health`; call `GET /api/v1/network/server-health` with the configured token; verify the dashboard link and stale/failure banners behave from a controlled stale fixture only, not by falsifying production data.

- [ ] **Step 5: Roll back immediately if a production acceptance check fails.**

  Stop the deployment, use the recorded `BACKUP_ROOT` with `deploy/rollback-server-observer.sh`, restore the prior web release through the established web rollback path, verify the timer state, and report the exact failed acceptance check. Do not attempt repeated runtime configuration changes without a new demonstrated cause.

- [ ] **Step 6: Commit the deployment documentation.**

  ```powershell
  git add docs/DEPLOYMENT.md
  git commit -m "docs: verify server health deployment"
  ```

## Plan self-review

- Spec coverage: Task 1 implements redacted collector diagnostics and freshness; Task 2 isolates the validated display model; Task 3 implements page, API, disclosure table, summary and dashboard entry; Task 4 implements the production restore/deploy/rollback sequence.
- Sensitive-data boundary: every task preserves allow-list validation and prohibits runtime configuration and raw diagnostics in Git/HTTP.
- Compatibility: `load_snapshot()` remains the interface used by `network_paths_adapter.py`; its freshness semantics are regression-tested before the web surface is deployed.
- Operational condition: Task 0 proves the current failure before repair; Tasks 1–3 do not claim that stale Directum results are live health.
