# WG Reconciler and Dashboard Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Keep VLAN50 fail-closed and self-reconcile the existing WG policy, while showing sanitized runtime health in the web dashboard.

**Architecture:** `vpn-policy.sh reconcile` remains the sole writer of table 123, mark 0x1 and the two managed iptables-nft chains. A root systemd timer invokes that command every minute but never starts or restarts WG. It first verifies the appropriate active or fail-closed state and writes only when that state has drifted; it must not flush and recreate healthy chains on every tick. `vpnctl runtime-health` remains a read-only source; an API Bearer endpoint and a session-authenticated dashboard endpoint expose its sanitized JSON to the existing network dashboard.

**Tech Stack:** Bash, systemd, iproute2, iptables-nft, Python 3 stdlib, FastAPI, Jinja2, browser Fetch API, pytest.

## Global Constraints

- Preserve `Table = off`; never create a global WireGuard default route.
- Reconciler writes only priority `1000`, mark `0x1/0xffffffff`, table `123`, `VPN_POLICY_MARK`, and `VPN_POLICY_NAT`.
- Reconciler must not start, restart, stop, or modify `wg-quick@wg0.service`, OpenVPN, DNS, OPNsense, MikroTik, profiles, MSS, or MTU.
- With no `wg0`, VLAN50 remains marked and table `123` contains `unreachable default`.
- API/UI must never emit WG private, preshared, or public keys; health data is read-only.
- `/api/v1/runtime-health` uses Bearer auth; browser polling uses a separate session-authenticated `/network/runtime-health` endpoint because browser sessions do not contain the API Bearer token.

---

### Task 1: Make policy reconciliation executable and scheduled

**Files:**
- Modify: `deploy/vpn-policy.sh`
- Create: `deploy/vpn-policy-reconcile.service`
- Create: `deploy/vpn-policy-reconcile.timer`
- Modify: `deploy/install-openvpn-web.sh`
- Modify: `tests/test_deploy_vpn_policy_assets.py`
- Modify: `tests/test_deploy_vpn_runtime_health_timer.py`

**Interfaces:** `/usr/local/sbin/vpn-policy.sh reconcile` exits 0 after applying either the active-WG state or fail-closed state. `vpn-policy-reconcile.timer` invokes it one minute after boot and every minute thereafter.

**Reconciliation invariant:** With `wg0` present, `reconcile` returns without writes if `status` already succeeds; otherwise it calls `start`. With `wg0` absent, it returns without writes if the mark/rule, mangle chain, unreachable table-123 default, and absence of the NAT chain/hook already form the fail-closed state; otherwise it calls `stop`.

- [ ] **Step 1: Write failing asset tests**

```python
def test_policy_script_exposes_reconcile_command():
    text = (ROOT / "deploy" / "vpn-policy.sh").read_text(encoding="utf-8")
    assert "reconcile) reconcile ;;" in text
    assert 'usage: $0 {start|stop|reconcile|status}' in text


def test_reconcile_does_not_rebuild_a_healthy_active_policy(tmp_path):
    # Run against mocked ip/iptables commands and assert `reconcile` only
    # probes a healthy active state; it must not flush or recreate chains.
    ...


def test_reconcile_repairs_only_a_drifted_policy_or_fail_closed_state(tmp_path):
    # Mock a missing managed object, then assert `reconcile` calls `start` or
    # `stop` respectively; no WireGuard/OpenVPN lifecycle command is allowed.
    ...


def test_reconcile_timer_is_root_scoped_and_does_not_manage_wg_service():
    service = (ROOT / "deploy" / "vpn-policy-reconcile.service").read_text(encoding="utf-8")
    timer = (ROOT / "deploy" / "vpn-policy-reconcile.timer").read_text(encoding="utf-8")
    assert "User=root" in service
    assert "ExecStart=/usr/local/sbin/vpn-policy.sh reconcile" in service
    assert "wg-quick" not in service
    assert "OnBootSec=1min" in timer
    assert "OnUnitActiveSec=1min" in timer
    assert "Persistent=true" in timer


def test_installer_enables_reconcile_timer_without_tunnel_restart():
    text = (ROOT / "deploy" / "install-openvpn-web.sh").read_text(encoding="utf-8")
    assert 'install -m 0644 "$SRC/deploy/vpn-policy-reconcile.service" /etc/systemd/system/vpn-policy-reconcile.service' in text
    assert 'install -m 0644 "$SRC/deploy/vpn-policy-reconcile.timer" /etc/systemd/system/vpn-policy-reconcile.timer' in text
    assert "systemctl enable --now vpn-policy-reconcile.timer" in text
    assert "restart wg-quick@wg0.service" not in text
    assert "restart openvpn-server@server.service" not in text
```

- [ ] **Step 2: Verify tests fail**

Run: `pytest -q tests/test_deploy_vpn_policy_assets.py tests/test_deploy_vpn_runtime_health_timer.py`

Expected: failures for the missing reconcile command and timer assets.

- [ ] **Step 3: Add the idempotent reconciler command and systemd assets**

```bash
fail_closed_status() {
  ! ip link show dev "$WG_IF" >/dev/null
  ip rule show | grep -Eq "^${PBR_PRIORITY}:.*fwmark ${PBR_MARK}.*lookup ${PBR_TABLE}"
  ip route show table "$PBR_TABLE" | grep -Eq "^unreachable default"
  iptables -w -t mangle -C PREROUTING -j "$MANGLE_CHAIN"
  iptables -w -t mangle -C "$MANGLE_CHAIN" -i "$PBR_IN_IF" -j MARK --set-xmark "$PBR_MARK/$PBR_MASK"
  ! iptables -w -t nat -C POSTROUTING -j "$NAT_CHAIN"
  ! iptables -w -t nat -S "$NAT_CHAIN" >/dev/null 2>&1
}

reconcile() {
  if ip link show dev "$WG_IF" >/dev/null; then
    status || start
  else
    fail_closed_status || stop
  fi
}

case "${1:-}" in
  start) start ;;
  stop) stop ;;
  reconcile) reconcile ;;
  status) status ;;
  *) usage ;;
esac
```

```ini
# deploy/vpn-policy-reconcile.service
[Unit]
Description=Reconcile VLAN50 policy routing through WireGuard

[Service]
Type=oneshot
User=root
ExecStart=/usr/local/sbin/vpn-policy.sh reconcile
StandardOutput=journal
StandardError=journal

# deploy/vpn-policy-reconcile.timer
[Unit]
Description=Reconcile VLAN50 policy routing every minute

[Timer]
OnBootSec=1min
OnUnitActiveSec=1min
Persistent=true
Unit=vpn-policy-reconcile.service

[Install]
WantedBy=timers.target
```

Install both units, reload systemd and enable only the reconciler timer; do not add a WG/OpenVPN systemctl command to the installer.

- [ ] **Step 4: Verify assets and shell syntax**

Run: `pytest -q tests/test_deploy_vpn_policy_assets.py tests/test_deploy_vpn_runtime_health_timer.py`

Run: `bash -n deploy/vpn-policy.sh`

Expected: all selected tests pass and Bash returns 0.

- [ ] **Step 5: Commit**

```bash
git add deploy/vpn-policy.sh deploy/vpn-policy-reconcile.service deploy/vpn-policy-reconcile.timer deploy/install-openvpn-web.sh tests/test_deploy_vpn_policy_assets.py tests/test_deploy_vpn_runtime_health_timer.py
git commit -m "feat: reconcile WG policy routing"
```

### Task 2: Expose read-only runtime health to authenticated callers

**Files:**
- Modify: `app/api.py`
- Modify: `app/main.py`
- Modify: `tests/test_api_routes.py`
- Modify: `tests/test_web_network_observer.py`

**Interfaces:**
- `GET /api/v1/runtime-health` returns `{"status":"ok","data": <vpnctl health>}` with Bearer auth.
- `GET /network/runtime-health` returns `<vpnctl health>` for an authenticated web session.
- Both invoke `vpnctl --json runtime-health` without `--strict`; `overall=error` remains HTTP 200.

- [ ] **Step 1: Extend fake vpnctl output and write failing API/session tests**

```python
# In the existing fake vpnctl command dispatcher.
elif cmd == "runtime-health":
    print(json.dumps({
        "status": "error", "overall": "error",
        "sections": {
            "openvpn": {"service_active": True, "management_available": True},
            "wireguard": {"service_active": True, "link_present": True, "mtu": 1420, "handshake_age_seconds": 25, "handshake_fresh": True},
            "policy_routing": {"rule_present": True, "table_123_default": True, "mangle_chain_present": True, "nat_chain_present": True, "legacy_51820_rule_present": False},
        },
        "warnings": [], "errors": ["VPN_POLICY_NAT chain or hook is missing"],
    }))

def test_runtime_health_api_returns_error_shaped_health_as_http_200(tmp_path, monkeypatch):
    client, headers = make_client(tmp_path, monkeypatch)
    response = client.get("/api/v1/runtime-health", headers=headers)
    assert response.status_code == 200
    assert response.json()["data"]["overall"] == "error"
    assert response.json()["data"]["errors"] == ["VPN_POLICY_NAT chain or hook is missing"]

def test_network_runtime_health_requires_session_and_is_read_only(tmp_path, monkeypatch):
    client, _ = make_client(tmp_path, monkeypatch)
    assert client.get("/network/runtime-health").status_code == 401
    login(client)
    response = client.get("/network/runtime-health")
    assert response.status_code == 200
    assert response.json()["overall"] == "error"
```

- [ ] **Step 2: Verify tests fail**

Run: `pytest -q tests/test_api_routes.py tests/test_web_network_observer.py -k runtime_health`

Expected: 404 responses or missing fake command support.

- [ ] **Step 3: Implement one read-only health helper and both endpoints**

```python
# app/api.py
@router.get("/runtime-health")
def api_runtime_health(actor: str = Depends(require_api_actor)):
    return api_response(call_vpnctl(["runtime-health"], timeout=15))

# app/main.py
@app.get("/network/runtime-health")
def network_runtime_health(request: Request, db: Session = Depends(get_db)):
    require_user(request, db)
    try:
        return run_vpnctl(["runtime-health"], timeout=15)
    except VpnctlError as exc:
        raise HTTPException(status_code=502, detail=str(exc.message)) from exc
```

Do not add `--strict` to either route and do not write audit records for these GET requests.

- [ ] **Step 4: Verify endpoint behavior**

Run: `pytest -q tests/test_api_routes.py tests/test_web_network_observer.py -k runtime_health`

Expected: all selected tests pass; health `overall=error` still has HTTP 200.

- [ ] **Step 5: Commit**

```bash
git add app/api.py app/main.py tests/test_api_routes.py tests/test_web_network_observer.py
git commit -m "feat: expose VPN runtime health"
```

### Task 3: Render and poll the VPN Runtime dashboard card

**Files:**
- Modify: `app/templates/network_dashboard.html`
- Modify: `app/static/app.js`
- Modify: `tests/test_web_network_observer.py`

**Interfaces:** `#vpn-runtime-card` loads `/network/runtime-health` on page load and every 30 seconds. The card renders only `sections`, `warnings`, and `errors` fields from the sanitized health response.

- [ ] **Step 1: Write failing render and static-poll tests**

```python
def test_network_dashboard_contains_runtime_health_card_and_polling(tmp_path, monkeypatch):
    client, _ = make_client(tmp_path, monkeypatch)
    login(client)
    page = client.get("/network/dashboard")
    assert page.status_code == 200
    assert 'id="vpn-runtime-card"' in page.text
    assert "VPN Runtime" in page.text

    script = (Path(__file__).resolve().parents[1] / "app" / "static" / "app.js").read_text(encoding="utf-8")
    assert 'fetch("/network/runtime-health")' in script
    assert "setInterval(loadVpnRuntimeHealth, 30000)" in script
```

- [ ] **Step 2: Verify tests fail**

Run: `pytest -q tests/test_web_network_observer.py -k runtime_health_card`

Expected: failure because no card or polling function exists.

- [ ] **Step 3: Add safe card markup and rendering function**

```html
<section id="vpn-runtime-card" class="table-wrap" data-runtime-health-url="/network/runtime-health">
  <h2>VPN Runtime</h2>
  <p class="muted" data-runtime-health-state>Загрузка статуса…</p>
  <dl data-runtime-health-details></dl>
  <ul class="alert bad" data-runtime-health-errors hidden></ul>
</section>
```

```javascript
async function loadVpnRuntimeHealth() {
  const card = document.querySelector("#vpn-runtime-card");
  if (!card) return;
  const state = card.querySelector("[data-runtime-health-state]");
  const details = card.querySelector("[data-runtime-health-details]");
  const errors = card.querySelector("[data-runtime-health-errors]");
  try {
    const response = await fetch("/network/runtime-health", {credentials: "same-origin"});
    if (!response.ok) throw new Error("runtime status unavailable");
    const health = await response.json();
    state.textContent = health.overall === "ok" ? "OK" : "Ошибка";
    details.replaceChildren(...runtimeHealthRows(health.sections || {}));
    errors.replaceChildren(...(health.errors || []).map((message) => {
      const item = document.createElement("li");
      item.textContent = message;
      return item;
    }));
    errors.hidden = !(health.errors || []).length;
  } catch (_) {
    state.textContent = "Статус недоступен";
    details.replaceChildren();
    errors.hidden = true;
  }
}
```

Implement `runtimeHealthRows` with `document.createElement` and `textContent`, never `innerHTML`; include only OpenVPN service/management, WG service/link/handshake age/MTU, and policy table/chains/legacy-51820 booleans. Call it on `DOMContentLoaded` and every 30 seconds.

- [ ] **Step 4: Verify dashboard tests**

Run: `pytest -q tests/test_web_network_observer.py -k "runtime_health or network_pages"`

Expected: all selected tests pass.

- [ ] **Step 5: Commit**

```bash
git add app/templates/network_dashboard.html app/static/app.js tests/test_web_network_observer.py
git commit -m "feat: show VPN runtime health dashboard"
```

### Task 4: Document and verify the active reconciler

**Files:**
- Modify: `docs/DEPLOYMENT.md`
- Modify: `docs/runbooks/wg-policy-resilience-deploy-rollback.md`
- Modify: `docs/superpowers/specs/2026-07-18-wg-reconcile-dashboard-design.md`

**Interfaces:** Operators use `vpn-policy-reconcile.timer` for automatic scoped reconciliation, `vpn-runtime-health.timer` for alarm-only checks, `/api/v1/runtime-health` for Bearer integrations, and `/network/dashboard` for session UI.

- [ ] **Step 1: Add exact acceptance and rollback commands**

```bash
sudo systemctl status vpn-policy-reconcile.timer vpn-runtime-health.timer --no-pager
sudo systemctl start vpn-policy-reconcile.service
sudo /usr/local/sbin/vpnctl --json runtime-health --strict
curl -fsS -H "Authorization: Bearer $OPENVPN_WEB_API_TOKEN" http://127.0.0.1:8088/api/v1/runtime-health
```

State explicitly that the reconciler never starts WG: a failed peer remains fail-closed until an operator or normal service lifecycle restores `wg0`.

- [ ] **Step 2: Run complete local verification**

Run: `git diff --check && pytest -q`

Expected: no whitespace errors and all tests pass.

- [ ] **Step 3: Commit**

```bash
git add docs/DEPLOYMENT.md docs/runbooks/wg-policy-resilience-deploy-rollback.md docs/superpowers/specs/2026-07-18-wg-reconcile-dashboard-design.md
git commit -m "docs: document WG reconciliation runtime"
```

## Self-review

- Task 1 covers missing-WG fail-closed reconciliation and does not touch WG/OpenVPN lifecycle.
- Task 2 separates external Bearer API from browser session authentication.
- Task 3 uses text nodes only and never exposes key material.
- Task 4 documents the non-restart boundary and verifies the full suite.
- No task changes peer configuration, OpenVPN routing/MSS, OPNsense, MikroTik, or DNS.

## Execution Handoff

Plan complete. Two execution options:

1. **Subagent-Driven (recommended)** — I dispatch a fresh subagent per task and review each task before continuing.
2. **Inline Execution** — Execute tasks in this session with review checkpoints.
