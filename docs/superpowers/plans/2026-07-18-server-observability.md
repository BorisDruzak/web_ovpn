# Server Observability Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Add read-only, gateway-originated server health monitoring to the OpenVPN web panel.

**Architecture:** A `server-observer` process runs as the existing gateway account that owns the dedicated observer SSH key. It executes an allow-listed role-specific probe set, including source-bound VPN-path probes, and atomically writes a redacted snapshot. The web application serves and renders that snapshot without executing remote commands in response to browser requests.

**Tech Stack:** Python standard library, existing FastAPI/Jinja/vanilla JavaScript web application, OpenSSH client, systemd, pytest.

## Global Constraints

- The observer runs on the OpenVPN gateway; browser requests never initiate SSH.
- The implementation is read-only: no restart, cleanup, route, DNS, firewall, VPN, or target configuration action is allowed.
- SSH private key material remains in the gateway account's restricted `.ssh` directory; no secret enters Git, snapshot, API, journal message, or web page.
- Runtime topology belongs only in the local `/etc/openvpn-web/server-observer.json`; repository files use target role identifiers and placeholders only.
- Snapshot output contains roles and health results, never target IP addresses, hostnames, command strings, raw command output, or credentials.
- Collection interval is five minutes; a snapshot is stale after fifteen minutes.
- Capacity status is `warn` below 15% free and `critical` below 10%; Directum log volume is `warn` at 20 GiB and `critical` at 30 GiB.

---

## File Structure

- Create `app/server_observer.py`: configuration validation, SSH execution boundary, role allow-list, result normalization, thresholds, snapshot I/O, stale calculation.
- Create `app/server_observer_cli.py`: minimal executable module that loads runtime config, collects, writes the snapshot, and exits non-zero only for collector-level failure.
- Modify `app/config.py`: add the snapshot path setting.
- Modify `app/main.py`: authenticated `/network/server-health` endpoint and dashboard context.
- Modify `app/api.py`: token-authenticated `/api/v1/network/server-health` endpoint.
- Modify `app/templates/network_dashboard.html`: Infrastructure Health card and status table markup.
- Modify `app/static/app.js`: safe DOM-only rendering and 30-second refresh of the health card.
- Create `deploy/server-observer`: gateway wrapper for `python -m app.server_observer_cli`.
- Create `deploy/server-observer.service` and `deploy/server-observer.timer`: locked-down five-minute systemd collection.
- Create `deploy/server-observer.json.sample`: role-only, address-free runtime configuration template.
- Modify `deploy/install-openvpn-web.sh`: install wrapper/units, create snapshot directory with gateway write and web read access, install the sample only when runtime config is absent.
- Create `tests/test_server_observer.py`: collector/parser/threshold/snapshot tests.
- Modify `tests/test_web_network_observer.py`: authenticated web/API/card tests and redaction assertions.
- Modify `tests/test_deploy_vpn_runtime_health_timer.py` or create `tests/test_deploy_server_observer.py`: installer and systemd hardening assertions.

### Task 1: Define the server-observer data contract and snapshot helpers

**Files:**
- Create: `app/server_observer.py`
- Test: `tests/test_server_observer.py`

**Interfaces:**
- Produces `load_runtime_config(path: Path) -> dict[str, Any]`, `classify_disk(free_percent: float) -> str`, `classify_directum_logs(size_bytes: int) -> str`, `snapshot_status(snapshot: dict[str, Any], now: datetime) -> str`, `write_snapshot(path: Path, snapshot: dict[str, Any]) -> None`, and `load_snapshot(path: Path, now: datetime) -> dict[str, Any]`.
- Consumes a JSON runtime configuration whose target entries expose only `role`, `host`, `user`, and `checks`; `host` is removed before a result leaves the collector.

- [ ] **Step 1: Write failing contract tests**

```python
def test_capacity_thresholds_and_directum_log_thresholds():
    assert classify_disk(15.0) == "ok"
    assert classify_disk(14.99) == "warn"
    assert classify_disk(9.99) == "critical"
    assert classify_directum_logs(20 * 1024**3) == "warn"
    assert classify_directum_logs(30 * 1024**3) == "critical"


def test_snapshot_write_is_atomic_and_loaded_snapshot_is_redacted(tmp_path):
    path = tmp_path / "latest.json"
    write_snapshot(path, {"collected_at": "2026-07-18T20:00:00Z", "targets": [{"role": "directum", "host": "hidden", "checks": []}]})
    loaded = load_snapshot(path, now=parse_utc("2026-07-18T20:01:00Z"))
    assert loaded["overall"] == "ok"
    assert "host" not in loaded["targets"][0]
```

- [ ] **Step 2: Run the test to verify it fails**

Run: `pytest tests/test_server_observer.py -v`

Expected: import failure because `app.server_observer` does not exist.

- [ ] **Step 3: Implement the value-only helpers and strict config validation**

Implement immutable allowed roles (`file_server`, `directum`, `active_directory`, `nextcloud`, `onlyoffice`, `opnsense_dns`), allowed source values (`gateway`, `vpn_path`, `target`), ISO-8601 UTC timestamps, atomic write through `path.with_suffix(".tmp")` plus `Path.replace`, and no raw host/output fields in `public_snapshot`.

```python
def classify_disk(free_percent: float) -> str:
    if free_percent < 10:
        return "critical"
    if free_percent < 15:
        return "warn"
    return "ok"


def public_target(target: dict[str, Any]) -> dict[str, Any]:
    return {"role": target["role"], "checks": target["checks"], "status": target["status"]}
```

- [ ] **Step 4: Run focused tests**

Run: `pytest tests/test_server_observer.py -v`

Expected: all contract tests pass; no network process is executed.

- [ ] **Step 5: Commit the isolated data-contract change**

```bash
git add app/server_observer.py tests/test_server_observer.py
git commit -m "feat: add server observer snapshot contract"
```

### Task 2: Implement allow-listed gateway and VPN-path probes

**Files:**
- Modify: `app/server_observer.py`
- Test: `tests/test_server_observer.py`

**Interfaces:**
- Consumes `collect(config: dict[str, Any], runner: Callable[..., CompletedProcess[str]], now: datetime) -> dict[str, Any]`.
- Produces target rows with `role`, `status`, and checks containing `name`, `source`, `status`, `observed`, `expected`, `latency_ms`, and a redacted error category.

- [ ] **Step 1: Add failing runner tests**

```python
def test_collect_binds_vpn_path_probe_and_continues_after_target_error():
    calls = []
    def runner(command, **kwargs):
        calls.append(command)
        if "nextcloud" in command[-1]:
            raise subprocess.TimeoutExpired(command, 8)
        return subprocess.CompletedProcess(command, 0, '{"free_percent": 34}', "")

    snapshot = collect(runtime_config(), runner=runner, now=parse_utc("2026-07-18T20:00:00Z"))
    assert any(command[:3] == ["ssh", "-b", "198.51.100.50"] for command in calls)
    assert target(snapshot, "nextcloud")["status"] == "error"
    assert target(snapshot, "directum")["status"] in {"ok", "warn", "critical"}
```

- [ ] **Step 2: Run the test to verify it fails**

Run: `pytest tests/test_server_observer.py::test_collect_binds_vpn_path_probe_and_continues_after_target_error -v`

Expected: FAIL because `collect` is not implemented.

- [ ] **Step 3: Implement the command allow-list and JSON-only parsers**

Build SSH commands as argument lists, never `shell=True`. Use `ssh -n -i <configured-key> -o BatchMode=yes -o ConnectTimeout=8`; add `-b <tunnel_source>` only for `vpn_path`. Each role command must emit a compact JSON object with only metrics/status booleans. Parse exact expected JSON fields and map timeout, SSH failure, invalid JSON, and unexpected endpoint output to generic categories (`timeout`, `transport`, `parse`, `unexpected_response`).

Implement these role-level checks:

```text
file_server: sshd active; data disk percent free
directum: C percent free; rxdata log bytes; DirectumRX/Mongo/Rabbit/Redis/IIS/DNS active
active_directory: C percent free; DNS/NTDS/ADWS active; local internal/external DNS success
nextcloud: status.php installed/maintenance/needsDbUpgrade; root/data percent free; nginx/php/postgresql/redis active
onlyoffice: HTTPS healthcheck exactly true; docker/containerd active; root percent free
opnsense_dns: AdGuard listener/query success; Unbound status; internal and external query success
```

- [ ] **Step 4: Add redaction and no-write tests**

```python
def test_public_collection_never_contains_host_command_or_raw_output():
    snapshot = collect(runtime_config(), runner=healthy_runner, now=parse_utc("2026-07-18T20:00:00Z"))
    encoded = json.dumps(snapshot)
    assert "192.168." not in encoded
    assert "ssh " not in encoded
    assert "authorized_keys" not in encoded
```

- [ ] **Step 5: Run collector tests**

Run: `pytest tests/test_server_observer.py -v`

Expected: all tests pass, including source binding, target isolation, thresholds, and redaction.

- [ ] **Step 6: Commit the collector**

```bash
git add app/server_observer.py tests/test_server_observer.py
git commit -m "feat: collect gateway server health"
```

### Task 3: Add the collector CLI and hardened systemd deployment

**Files:**
- Create: `app/server_observer_cli.py`
- Create: `deploy/server-observer`
- Create: `deploy/server-observer.service`
- Create: `deploy/server-observer.timer`
- Create: `deploy/server-observer.json.sample`
- Modify: `deploy/install-openvpn-web.sh`
- Create: `tests/test_deploy_server_observer.py`

**Interfaces:**
- CLI is invoked as `python -m app.server_observer_cli --config PATH --snapshot PATH`.
- Systemd invokes `/usr/local/sbin/server-observer` every five minutes as the gateway observer account.
- The web user receives read-only access to the snapshot directory through its group.

- [ ] **Step 1: Write failing deployment tests**

```python
def test_server_observer_service_is_read_only_and_runs_as_gateway_account():
    service = Path("deploy/server-observer.service").read_text(encoding="utf-8")
    assert "User=openvpm" in service
    assert "NoNewPrivileges=true" in service
    assert "PrivateTmp=true" in service
    assert "ProtectSystem=strict" in service
    assert "ReadWritePaths=/var/lib/openvpn-web/server-observer" in service
    assert "ExecStart=/usr/local/sbin/server-observer" in service


def test_install_script_installs_observer_without_runtime_topology():
    installer = Path("deploy/install-openvpn-web.sh").read_text(encoding="utf-8")
    assert "server-observer.service" in installer
    assert "server-observer.timer" in installer
    assert "192.168." not in Path("deploy/server-observer.json.sample").read_text(encoding="utf-8")
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `pytest tests/test_deploy_server_observer.py -v`

Expected: FAIL because observer deployment files do not exist.

- [ ] **Step 3: Implement CLI, wrapper, units, and runtime config template**

The CLI loads the config, invokes `collect`, writes the atomic snapshot, and prints only a role/status summary. Its failure output must not include a host or raw SSH response.

```ini
# deploy/server-observer.timer
[Timer]
OnBootSec=2min
OnUnitActiveSec=5min
Persistent=true
```

```ini
# deploy/server-observer.service
[Service]
Type=oneshot
User=openvpm
Group=openvpn-web
NoNewPrivileges=true
PrivateTmp=true
ProtectHome=read-only
ProtectSystem=strict
ReadWritePaths=/var/lib/openvpn-web/server-observer
ExecStart=/usr/local/sbin/server-observer
```

The installer must create `/var/lib/openvpn-web/server-observer` owned by `openvpm:openvpn-web` with mode `0750`; it installs the JSON sample only if the runtime config is absent, then enables the timer. It does not synthesize target IPs or modify target machines.

- [ ] **Step 4: Run deployment and CLI unit tests**

Run: `pytest tests/test_server_observer.py tests/test_deploy_server_observer.py -v`

Expected: all tests pass.

- [ ] **Step 5: Commit deployment support**

```bash
git add app/server_observer_cli.py deploy/server-observer deploy/server-observer.service deploy/server-observer.timer deploy/server-observer.json.sample deploy/install-openvpn-web.sh tests/test_deploy_server_observer.py
git commit -m "feat: deploy server health collector"
```

### Task 4: Serve and render Infrastructure Health in the web panel

**Files:**
- Modify: `app/config.py`
- Modify: `app/main.py`
- Modify: `app/api.py`
- Modify: `app/templates/network_dashboard.html`
- Modify: `app/static/app.js`
- Modify: `tests/test_web_network_observer.py`

**Interfaces:**
- `GET /network/server-health` requires a browser session and returns the sanitized snapshot.
- `GET /api/v1/network/server-health` requires the existing API token and returns `api_response(snapshot)`.
- The dashboard fetches `/network/server-health` every 30 seconds and creates DOM nodes with `textContent`; it does not inject untrusted strings via `innerHTML`.

- [ ] **Step 1: Add failing authenticated endpoint and card tests**

```python
def test_server_health_requires_session_and_returns_snapshot(tmp_path, monkeypatch):
    snapshot = tmp_path / "server-health.json"
    snapshot.write_text(json.dumps({"overall": "warn", "targets": [{"role": "directum", "status": "warn", "checks": []}]}), encoding="utf-8")
    monkeypatch.setenv("SERVER_OBSERVER_SNAPSHOT_PATH", str(snapshot))
    client, headers = make_client(tmp_path, monkeypatch)
    assert client.get("/network/server-health", follow_redirects=False).status_code == 303
    login(client)
    assert client.get("/network/server-health").json()["overall"] == "warn"
    assert client.get("/api/v1/network/server-health", headers=headers).status_code == 200


def test_network_dashboard_contains_server_health_card_and_safe_renderer(tmp_path, monkeypatch):
    client, _ = make_client(tmp_path, monkeypatch)
    login(client)
    assert 'id="server-health-card"' in client.get("/network/dashboard").text
    script = Path("app/static/app.js").read_text(encoding="utf-8")
    assert 'fetch("/network/server-health", {credentials: "same-origin"})' in script
    assert "function serverHealthRows" in script
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `pytest tests/test_web_network_observer.py -k "server_health" -v`

Expected: FAIL because endpoint and dashboard card do not exist.

- [ ] **Step 3: Implement settings, routes, and safe UI rendering**

Add `server_observer_snapshot_path` to `Settings`, defaulting to `/var/lib/openvpn-web/server-observer/latest.json`. `load_snapshot` must return a synthetic `stale`/`error` result if the file is missing, invalid, or too old; routes must never return filesystem exception text.

Render target role, overall status, source, check name, observed value, expected value, and collection time. Browser code creates each `tr`, `td`, `dt`, and `dd` with `document.createElement` and assigns `textContent`.

- [ ] **Step 4: Run focused web tests**

Run: `pytest tests/test_web_network_observer.py -k "server_health or dashboard_contains_runtime" -v`

Expected: PASS; unauthenticated browser access redirects and API access stays token-protected.

- [ ] **Step 5: Commit the web surface**

```bash
git add app/config.py app/main.py app/api.py app/templates/network_dashboard.html app/static/app.js tests/test_web_network_observer.py
git commit -m "feat: show infrastructure health dashboard"
```

### Task 5: Integration deployment and read-only verification from the gateway

**Files:**
- Create: `docs/verification/server-observability-2026-07-18.md`
- Modify: runtime-only `/etc/openvpn-web/server-observer.json` on the gateway; do not add it to Git.

**Interfaces:**
- Uses the deployed wrapper, unit, timer, runtime config, observer key, and web endpoint from Tasks 1-4.
- Produces a verification record with timestamps, target roles, source labels, and redacted statuses only.

- [ ] **Step 1: Write the runtime config outside the repository**

Create `/etc/openvpn-web/server-observer.json` on the gateway with role identifiers, runtime host addresses, per-role SSH users, the existing observer key path, and tunnel source. Set ownership to `root:openvpn-web` and mode `0640`; ensure `openvpm` can read only the specific key file and config through the service group arrangement. Do not include a password or private key value.

- [ ] **Step 2: Run one manual collection before enabling the timer**

Run: `sudo -u openvpm -g openvpn-web /usr/local/sbin/server-observer --once`

Expected: JSON summary with every configured role, both `gateway` and `vpn_path` sources where configured, and no IP address or raw SSH output.

- [ ] **Step 3: Verify no target-side write occurred**

Confirm from the collector unit, allow-listed command definitions, and collector journal that no service restart, configuration mutation, cleanup, route, DNS, firewall, or VPN command is present. Verify the installed observer configuration and key are read-only to the collector process, and that the snapshot directory is its only declared write path.

- [ ] **Step 4: Enable timer and verify stale behavior boundary**

Run:

```bash
sudo systemctl enable --now server-observer.timer
systemctl list-timers server-observer.timer
sudo systemctl start server-observer.service
sudo journalctl -u server-observer.service -n 50 --no-pager
```

Expected: timer is enabled, collection completes, journal contains only role/status summaries, and snapshot modification time is current.

- [ ] **Step 5: Verify web and API surfaces**

Run authenticated browser checks for `/network/dashboard` and token-authenticated checks for `/api/v1/network/server-health`. Verify critical current capacity states appear as `critical`, probe source is visible, target hosts/IPs are absent from browser response, and stale snapshot becomes `stale` after the configured interval in a controlled test fixture.

- [ ] **Step 6: Run full regression suite and record evidence**

Run: `pytest -q`

Expected: all tests pass with existing skips only. Record commands, timestamps, and redacted results in `docs/verification/server-observability-2026-07-18.md`.

- [ ] **Step 7: Commit verification documentation**

```bash
git add docs/verification/server-observability-2026-07-18.md
git commit -m "docs: verify server observability deployment"
```

## Plan self-review

- **Spec coverage:** Tasks 1-2 cover result model, thresholds, target checks, source binding, failure isolation, redaction, and read-only command boundaries. Task 3 covers the gateway service, five-minute interval, security boundaries, and atomic snapshot delivery. Task 4 covers authenticated web/API rendering and stale/error presentation. Task 5 covers deployment and target-side non-mutation verification.
- **Placeholder scan:** No task uses TBD/TODO or defers unspecified behavior. Runtime addresses are intentionally external to Git by a stated security constraint.
- **Type consistency:** Task 1 defines the snapshot functions and status vocabulary consumed by Tasks 2-4. Task 2 produces the normalized snapshot written by Task 3 and loaded by Task 4. Task 5 invokes the Task 3 CLI and checks Task 4 routes.
