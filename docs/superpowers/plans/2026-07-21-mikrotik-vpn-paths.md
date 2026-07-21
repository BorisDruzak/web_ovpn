# MikroTik VPN Path Visibility Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Render read-only OpenVPN → MikroTik → registered-server path checks and RouterOS update posture in the web panel.

**Architecture:** `netctl` persists allow-listed RouterOS snapshots and reports the local collector timer. `app.network_paths` validates local-only path definitions and evaluates them against OpenVPN runtime, netctl, and Server Health snapshots; FastAPI only reads that result.

**Tech Stack:** Python standard library, SQLite, existing netctl CLI, FastAPI/Jinja, systemd, pytest.

## Global Constraints

- Browser/API requests never execute RouterOS mutation, OpenVPN change, server SSH command, or systemd change.
- RouterOS collection permits only explicit `print` paths and never invokes `check-for-updates`.
- Production topology belongs in `/etc/openvpn-web/network-paths.json`; repository fixtures and samples contain no production IPs, CIDRs, credentials, or keys.
- Only registered Server Health roles may have a displayed path.
- A path cannot be `ok` if its MikroTik snapshot or Server Health result is stale/missing, or the collector timer is inactive.

---

## File Structure

- Modify `netctl/drivers/mikrotik_api.py` and `netctl/drivers/mikrotik_ssh.py`: fixed read-only RouterOS resources.
- Modify `netctl/db.py`, `netctl/store.py`, and `netctl/cli.py`: current address-list/policy/update tables and collector status.
- Create `app/network_paths.py`: local config validation and pure path evaluation.
- Modify `app/config.py`, `app/main.py`, `app/api.py`, and existing navigation/dashboard templates.
- Create `app/templates/network_paths.html`, `app/templates/network_path_detail.html`, and `deploy/network-paths.json.sample`.
- Modify `deploy/install-openvpn-web.sh`; create tests in `tests/test_network_paths.py` and `tests/test_deploy_network_paths.py`.

### Task 1: Persist only allow-listed RouterOS evidence

**Files:**
- Modify: `netctl/drivers/mikrotik_api.py`, `netctl/drivers/mikrotik_ssh.py`, `netctl/db.py`, `netctl/store.py`, `netctl/cli.py`
- Test: `tests/test_netctl_cli.py`

**Interfaces:**
- Produces snapshot fields `firewall_address_lists`, `firewall_filter_rules`, `firewall_nat_rules`, `firewall_mangle_rules`, and `update_posture`.
- Produces CLI commands `address-lists list`, `firewall-rules list --table TABLE`, `update-posture list`, and `collector-status`.

- [ ] **Step 1: Write a failing persistence test**

```python
def test_mikrotik_snapshot_persists_address_lists_rules_and_update_posture(tmp_path):
    snapshot = {
        "firewall_address_lists": [{"list": "vpn", "address": "198.51.100.9", "disabled": False}],
        "firewall_filter_rules": [{"chain": "forward", "action": "accept", "disabled": False, "packets": 7}],
        "update_posture": {"channel": "stable", "installed_version": "7.19.4", "latest_version": "", "schedulers": []},
    }
    # Save through the current source collection boundary, then assert normalized CLI rows.
```

- [ ] **Step 2: Verify RED**

Run: `python -m pytest tests/test_netctl_cli.py -k "persists_address_lists" -v`

Expected: FAIL because the snapshot fields/tables/CLI command do not exist.

- [ ] **Step 3: Implement the minimal allow-list and storage**

Add only print paths. Normalize rule identity, table, chain, action, disabled, source/destination address/list, protocol, comment, packets, and bytes. Store current rows per source and never scheduler `on-event` text.

```python
"firewall_filter_rules": (
    "/ip/firewall/filter/print",
    [".id", "chain", "action", "disabled", "src-address", "dst-address",
     "src-address-list", "dst-address-list", "protocol", "comment", "packets", "bytes"],
)
```

Implement `collector-status` with the fixed command `systemctl show netctl-collect.timer`; return only `enabled`, `active`, `next_run`, and normalized status.

- [ ] **Step 4: Verify GREEN and commit**

Run: `python -m pytest tests/test_netctl_cli.py -k "mikrotik or collector" -v`

Expected: PASS.

```powershell
git add netctl/drivers/mikrotik_api.py netctl/drivers/mikrotik_ssh.py netctl/db.py netctl/store.py netctl/cli.py tests/test_netctl_cli.py
git commit -m "feat: persist read-only MikroTik policy evidence"
```

### Task 2: Build the registered-role path evaluator

**Files:**
- Create: `app/network_paths.py`, `deploy/network-paths.json.sample`
- Test: `tests/test_network_paths.py`

**Interfaces:**
- Produces `load_path_config(path: Path, roles: set[str]) -> dict[str, PathDefinition]`.
- Produces `evaluate_paths(definitions, runtime, collector, router_rows, server_health, now) -> list[dict[str, Any]]`.
- A public row contains `role`, `status`, `collected_at`, and ordered checks with `name`, `status`, `observed`, `expected`, and `message`.

- [ ] **Step 1: Write a failing missing-return-route test**

```python
def test_path_is_critical_when_expected_return_route_is_absent():
    result = evaluate_paths(
        definitions={"directum": definition("directum")},
        runtime={"overall": "ok", "sections": {"openvpn": {"service_active": True}}},
        collector={"enabled": True, "active": True},
        router_rows={"routes": []},
        server_health={"targets": [{"role": "directum", "status": "ok"}]},
        now=parse_utc("2026-07-21T18:00:00Z"),
    )
    assert result[0]["status"] == "critical"
    assert check(result[0], "return_route")["status"] == "critical"
```

- [ ] **Step 2: Verify RED**

Run: `python -m pytest tests/test_network_paths.py -v`

Expected: FAIL because `app.network_paths` does not exist.

- [ ] **Step 3: Implement strict local-config validation and pure evaluation**

Reject unregistered roles. Match routes/rules/lists by normalized declarative attributes; never match command text. Let stale timestamps and inactive timers override positive route evidence.

```python
def worst_status(checks: list[dict[str, str]]) -> str:
    order = {"ok": 0, "unknown": 1, "warn": 2, "stale": 3, "critical": 4, "error": 5}
    return max((item["status"] for item in checks), key=order.__getitem__, default="unknown")
```

- [ ] **Step 4: Add edge-case tests and verify GREEN**

Cover disabled rule, missing list membership, zero counter as warn, no matcher as unknown, stale router/Server Health evidence, inactive timer, and unknown role validation.

Run: `python -m pytest tests/test_network_paths.py -v`

Expected: PASS.

- [ ] **Step 5: Commit**

```powershell
git add app/network_paths.py deploy/network-paths.json.sample tests/test_network_paths.py
git commit -m "feat: evaluate registered VPN network paths"
```

### Task 3: Serve paths safely in HTML and API

**Files:**
- Modify: `app/config.py`, `app/main.py`, `app/api.py`, `app/templates/base.html`, `app/templates/network_dashboard.html`
- Create: `app/templates/network_paths.html`, `app/templates/network_path_detail.html`
- Test: `tests/test_web_network_observer.py`

**Interfaces:**
- `GET /network/paths` and `GET /network/paths/{role}` require browser login.
- `GET /api/v1/network/paths` and `GET /api/v1/network/paths/{role}` require the existing bearer token.

- [ ] **Step 1: Write failing authenticated route tests**

```python
def test_network_paths_require_login_and_show_existing_server_roles(tmp_path, monkeypatch):
    client, headers = make_client(tmp_path, monkeypatch)
    assert client.get("/network/paths", follow_redirects=False).status_code == 303
    login(client)
    assert "directum" in client.get("/network/paths").text
    assert client.get("/api/v1/network/paths", headers=headers).status_code == 200
```

- [ ] **Step 2: Verify RED**

Run: `python -m pytest tests/test_web_network_observer.py -k "network_paths" -v`

Expected: FAIL with 404 or absent path data.

- [ ] **Step 3: Add read-only settings, endpoints, templates, and navigation**

Load local configuration from `NETWORK_PATHS_CONFIG_PATH`. GET handlers call only loaders/evaluation. They must not call `collect`, `sources test`, or a POST handler. Render status badges and safe Jinja text; link from the Server Health card.

- [ ] **Step 4: Add no-side-effect/redaction tests, verify GREEN, and commit**

Assert browser/API responses omit credentials, SSH paths, command text, and raw exceptions. Assert a GET never invokes the fake `netctl collect` branch.

Run: `python -m pytest tests/test_web_network_observer.py -k "network_paths or server_health" -v`

Expected: PASS.

```powershell
git add app/config.py app/main.py app/api.py app/templates/base.html app/templates/network_dashboard.html app/templates/network_paths.html app/templates/network_path_detail.html tests/test_web_network_observer.py
git commit -m "feat: show VPN to server network paths"
```

### Task 4: Install and verify without changing network state

**Files:**
- Modify: `deploy/install-openvpn-web.sh`, `docs/DEPLOYMENT.md`
- Create: `tests/test_deploy_network_paths.py`, `docs/verification/mikrotik-vpn-paths-2026-07-21.md`

- [ ] **Step 1: Write a failing installer-boundary test**

```python
def test_installer_only_installs_role_only_path_sample_when_absent():
    installer = Path("deploy/install-openvpn-web.sh").read_text(encoding="utf-8")
    sample = Path("deploy/network-paths.json.sample").read_text(encoding="utf-8")
    assert "network-paths.json.sample" in installer
    assert "192.168." not in sample
```

- [ ] **Step 2: Verify RED**

Run: `python -m pytest tests/test_deploy_network_paths.py -v`

Expected: FAIL because installer support does not exist.

- [ ] **Step 3: Implement minimal install/docs support**

Install the sample only if the operational file is absent. Document that enabling `netctl-collect.timer`, collecting, or changing RouterOS is a separately approved operator action.

- [ ] **Step 4: Verify GREEN, full suite, and commit**

Run: `python -m pytest tests/test_deploy_network_paths.py -v`

Expected: PASS.

Run: `python -m pytest -q`

Expected: all tests pass with only pre-existing skips.

```powershell
git add deploy/install-openvpn-web.sh docs/DEPLOYMENT.md tests/test_deploy_network_paths.py docs/verification/mikrotik-vpn-paths-2026-07-21.md
git commit -m "docs: verify read-only MikroTik path visibility"
```

## Plan self-review

- **Spec coverage:** Task 1 creates missing evidence, Task 2 is extensible role evaluation, Task 3 supplies read-only authenticated visibility, and Task 4 preserves the production no-change boundary.
- **Placeholder scan:** Each task identifies files, interfaces, test/verification commands, expected outcomes, and commit scope.
- **Type consistency:** Task 1 output is Task 2 input; Task 2 output is Task 3 data; Task 4 installs Task 2's local configuration sample.
