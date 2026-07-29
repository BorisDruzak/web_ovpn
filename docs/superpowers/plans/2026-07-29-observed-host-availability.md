# Observed Host Availability Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Monitor only observed or explicitly forced hosts, provide historical-list periods and per-host force-monitor actions, and make 192.168.100.0/24 and 192.168.101.0/24 canonical selectable segments.

**Architecture:** `netctl` stores force-monitor intent and builds a target set from fresh `network_hosts`, canonical management IPs and force entries before ICMP/TCP. FastAPI validates period and force actions, while the canonical context repository splits the central /23 into two stable /24 segments. No layer accepts a browser supplied CIDR, port or arbitrary target IP.

**Tech Stack:** Python 3.14, SQLite, argparse, FastAPI/Jinja, PyYAML/JSON Schema, pytest.

## Global Constraints

- Only active IPv4 segments from the current canonical context can be enabled; do not persist or accept arbitrary CIDRs.
- Scheduled targets are fresh observed hosts, canonical management IPs, or explicitly forced existing hosts; never enumerate a CIDR.
- Active probes are ICMP first, then configured TCP fallback; `online` requires active evidence.
- A stale historical record is not `online` or `offline` without fresh active evidence.
- Force-monitor may be enabled only for an existing host inside an enabled canonical segment; it persists until explicit disable.
- Force actions, probe and refresh require authentication, CSRF, audit logging, per-actor/action five-minute throttles and the existing collection lock for refresh.
- Preserve the user’s existing unstaged IPsec/CLI/test/image changes and do not modify router, DHCP, switch or firewall configuration.

---

## File Structure

- `C:\Users\admin-2\Documents\network_configuration\config\network-context.yaml` — split central segment and rebind canonical devices.
- `netctl/migrations.py` — force-monitor persistence migration and target lookup index.
- `netctl/availability.py` — observed/static/forced target resolver, force-state APIs and bounded run persistence.
- `netctl/cli.py` — fixed `availability force` command surface.
- `app/main.py`, `app/network_observer.py`, templates — validated list-period and force-monitor presentation/actions.
- `tests/test_netctl_availability.py`, `tests/test_netctl_cli.py`, `tests/test_web_network_observer.py` — TDD regression coverage.

### Task 1: Split the canonical central LAN safely

**Files:**
- Modify: `C:\Users\admin-2\Documents\network_configuration\config\network-context.yaml`
- Test: `C:\Users\admin-2\Documents\network_configuration\scripts\validate_context.py`

**Interfaces:**
- Produces active stable IDs `central-lan-100` / `central-lan-101`, with `192.168.100.0/24` / `192.168.101.0/24`.

- [ ] **Step 1: Create an isolated worktree for `network_configuration` and write a failing semantic fixture**

Add the two segment IDs and update every `management_segment: central-lan` reference according to its `management_ip`; no reference may remain to the removed ID.

- [ ] **Step 2: Run validation before completing all rebinding**

Run: `python scripts/validate_context.py`

Expected: FAIL with a missing segment reference while a device still references `central-lan`.

- [ ] **Step 3: Complete the split**

Replace the original segment with:

```yaml
- id: central-lan-100
  name: Central LAN 192.168.100.0/24
  site: central
  cidr: 192.168.100.0/24
  role: main_flat_lan
  observer_category: local_device
  status: active
- id: central-lan-101
  name: Central LAN 192.168.101.0/24
  site: central
  cidr: 192.168.101.0/24
  role: main_flat_lan
  observer_category: local_device
  status: active
```

- [ ] **Step 4: Verify and commit the canonical revision**

Run: `python scripts/validate_context.py`

Expected: PASS. Commit with `git commit -m "feat: split central LAN monitoring segments"`.

### Task 2: Persist force-monitor intent and resolve observed targets

**Files:**
- Modify: `netctl/migrations.py`
- Modify: `netctl/availability.py`
- Test: `tests/test_netctl_availability.py`
- Test: `tests/test_netctl_context_migrations.py`

**Interfaces:**
- Produces `set_force_monitor(conn, ip, enabled, now) -> ForceMonitorState` and `availability_targets(conn, segments, now) -> tuple[ProbeTarget, ...]`.
- `availability_targets` returns unique targets with `ip`, canonical `cidr` and segment TCP ports.

- [ ] **Step 1: Write failing target-resolution tests**

```python
def test_availability_targets_include_recent_hosts_static_management_and_forced_history(conn):
    # Seed one last_seen_at within 24h, one old forced host, one old unforced host,
    # and one canonical management IP in an enabled segment.
    assert [target.ip for target in availability_targets(conn, rules, NOW)] == [
        "192.0.2.1", "192.0.2.3", "192.0.2.9"
    ]

def test_availability_targets_never_expand_every_usable_address(conn):
    assert len(availability_targets(conn, rules_for("192.0.2.0/24"), NOW)) == 1
```

- [ ] **Step 2: Run the new tests and verify RED**

Run: `pytest -q tests/test_netctl_availability.py -k 'availability_targets'`

Expected: FAIL because the current scheduler uses `network.hosts()`.

- [ ] **Step 3: Add migration and minimal resolver**

Create `availability_force_monitors` with `ip TEXT PRIMARY KEY`, `enabled INTEGER`, `enabled_at TEXT`, `updated_at TEXT`; add an index on `network_hosts(last_seen_at, ip)`. Query `network_hosts.last_seen_at >= now - 24h`, union enabled force rows, and add canonical management IPs from the active imported context. Validate every candidate with `ipaddress.ip_address`, assign it only to an enabled canonical segment, then deduplicate by IP.

- [ ] **Step 4: Replace CIDR expansion only in scheduled collection**

Change `_collect_availability_segments` to call `availability_targets(conn, segments, now)`; keep `probe_one_availability` one-host semantics unchanged. A zero-target due run is successful and persists no fabricated offline targets.

- [ ] **Step 5: Verify GREEN and commit**

Run: `pytest -q tests/test_netctl_availability.py tests/test_netctl_context_migrations.py`

Expected: PASS. Commit with `git commit -m "feat: target observed hosts for availability"`.

### Task 3: Expose safe force-monitor CLI and web actions

**Files:**
- Modify: `netctl/cli.py`
- Modify: `app/main.py`
- Modify: `app/network_actions.py`
- Modify: `app/templates/network_host_detail.html`
- Test: `tests/test_netctl_cli.py`
- Test: `tests/test_web_network_observer.py`

**Interfaces:**
- Produces `netctl availability force --ip <validated-existing-host> --enabled true|false`.
- Produces `POST /network/hosts/{ip}/force-monitor` and `POST /network/hosts/{ip}/force-monitor/disable`.

- [ ] **Step 1: Write failing CLI and route tests**

```python
def test_force_monitor_rejects_absent_or_unmonitored_host_and_never_probes(monkeypatch):
    assert cli.dispatch(force_args("192.0.2.44"))[0] == 1

def test_force_monitor_route_persists_then_probes_and_refreshes(monkeypatch):
    response = client.post("/network/hosts/192.168.100.11/force-monitor", data={"csrf_token": csrf})
    assert response.status_code == 303
    assert fixed_commands == [
        ["availability", "force", "--ip", "192.168.100.11", "--enabled", "true"],
        ["availability", "probe", "--ip", "192.168.100.11"],
        ["observations", "refresh"],
    ]
```

- [ ] **Step 2: Run the tests and verify RED**

Run: `pytest -q tests/test_netctl_cli.py tests/test_web_network_observer.py -k 'force_monitor'`

Expected: FAIL because parser, routes and template controls do not yet exist.

- [ ] **Step 3: Implement fixed command and handlers**

`cmd_availability` must resolve the host record server-side, verify it belongs to an enabled segment, call `set_force_monitor`, and return only public state. The enable route acquires a distinct five-minute action budget, calls force → one-IP probe → observations refresh with fixed commands, audits all outcomes, and preserves force intent when refresh is busy. The disable route only clears force intent and audits it.

- [ ] **Step 4: Render truthful controls**

For a historical existing host show the force state, enabled timestamp, last active evidence and an enable/disable form containing only CSRF. Never display a force action for a missing, invalid, or out-of-segment IP.

- [ ] **Step 5: Verify GREEN and commit**

Run: `pytest -q tests/test_netctl_cli.py tests/test_web_network_observer.py`

Expected: PASS. Commit with `git commit -m "feat: add force monitoring for historical hosts"`.

### Task 4: Add observed-history filters to the host list

**Files:**
- Modify: `app/main.py`
- Modify: `app/network_observer.py`
- Modify: `app/templates/network_hosts.html`
- Test: `tests/test_web_network_observer.py`

**Interfaces:**
- Produces validated `seen_within` values `1h`, `24h`, `7d`, `30d`, `all`; default is `24h`.

- [ ] **Step 1: Write failing list-filter tests**

```python
def test_hosts_default_to_last_24_hours_and_allows_historical_periods(tmp_path, monkeypatch):
    page = client.get("/network/hosts")
    assert "fresh device" in page.text
    assert "old device" not in page.text
    history = client.get("/network/hosts?seen_within=7d")
    assert "old device" in history.text

def test_historical_host_renders_stale_not_online(tmp_path, monkeypatch):
    assert "данные устарели" in client.get("/network/hosts?seen_within=all").text
```

- [ ] **Step 2: Run tests and verify RED**

Run: `pytest -q tests/test_web_network_observer.py -k 'seen_within or historical_host'`

Expected: FAIL because no period parser or default freshness filter exists.

- [ ] **Step 3: Implement a server-side period filter**

Parse only the five values above. Compare parsed UTC `last_seen_at` against request time in `filter_unified_hosts`; malformed timestamps are historical only and appear solely for `all`. Preserve other filters and query parameters. Map inactive availability to the public stale label rather than `online`/`offline`.

- [ ] **Step 4: Update the template**

Add a named `seen_within` select to the existing GET toolbar. Retain it in all list navigation and display the selected period in readable Russian.

- [ ] **Step 5: Verify GREEN and commit**

Run: `pytest -q tests/test_web_network_observer.py`

Expected: PASS. Commit with `git commit -m "feat: filter network hosts by observation age"`.

### Task 5: Integrate the canonical revision and release safely

**Files:**
- Modify: deployment runbook only if the validated context-import command needs documentation.
- Test: `tests/test_netctl_context_classifier.py`, `tests/test_netctl_availability.py`, `tests/test_netctl_cli.py`, `tests/test_web_network_observer.py`

- [ ] **Step 1: Run focused regression groups**

Run: `pytest -q tests/test_netctl_context_classifier.py tests/test_netctl_context_migrations.py tests/test_netctl_availability.py tests/test_netctl_cli.py tests/test_web_network_observer.py`

Expected: PASS.

- [ ] **Step 2: Run full local verification**

Run: `pytest -q && git diff --check`

Expected: no failures and no whitespace errors.

- [ ] **Step 3: Import canonical context on production after code deployment**

Run: `sudo -n /usr/local/sbin/netctl --json context validate --path <approved-context-path>` then `sudo -n /usr/local/sbin/netctl --json context import --path <approved-context-path> --git-sha <canonical-commit>`.

Expected: active context exposes `central-lan-100` and `central-lan-101`.

- [ ] **Step 4: Enable the two new canonical segments and run one collection**

Run fixed `availability set-segment` commands with ICMP/TCP ports 22 and 443 at five minutes, then `netctl --json collect all --reconcile`.

Expected: metrics count observed/static/forced targets rather than every usable address in a CIDR.

- [ ] **Step 5: Verify the running service and commit**

Verify `openvpn-web.service`, `netctl-availability.timer`, `/network/hosts?seen_within=24h`, one forced historical host, and the audit trail. Commit any runbook edit with `git commit -m "docs: document observed availability rollout"`.

## Plan Self-Review

- Spec coverage: Task 1 supplies the canonical /24 IDs; Task 2 removes full CIDR expansion; Task 3 adds permanent secure force-monitor; Task 4 provides historical filtering; Task 5 validates, imports and releases.
- Placeholder scan: no TBD/TODO items; all commands and state contracts are explicit.
- Type consistency: all scheduled target paths use `ProbeTarget`; force state is persisted before web actions consume it; only CLI fixed commands bridge FastAPI and netctl.
