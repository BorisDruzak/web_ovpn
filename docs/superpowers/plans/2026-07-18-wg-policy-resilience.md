# WG Policy-Routing Resilience Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Recover the existing `ens18.50 -> wg0` policy route after WG restart, boot DNS delay or managed-chain loss, and expose read-only runtime health through `vpnctl`.

**Architecture:** A version-controlled Bash reconciler owns only table 123, mark `0x1` and its two iptables-nft chains. Its oneshot systemd service follows `wg-quick@wg0`. The existing root-run `vpnctl` becomes the read-only inspector; a minute timer records strict failures in journald.

**Tech Stack:** Bash, systemd, iproute2, WireGuard, iptables-nft, Python 3 stdlib, pytest.

## Global Constraints

- Keep `Table = off`; do not add a global WireGuard default route.
- Only manage `fwmark 0x1/0xffffffff`, priority 1000, table 123, `VPN_POLICY_MARK`, and `VPN_POLICY_NAT`.
- Do not change OpenVPN profiles, forwarding, MSS/MTU, OPNsense, MikroTik, web, API or MCP.
- Never return WireGuard private, preshared or public key material.
- If `wg0` is absent, marked VLAN50 traffic remains fail-closed.

---

### Task 1: Track and lifecycle-manage policy routing

**Files:**
- Create: `deploy/vpn-policy.sh`
- Create: `deploy/vpn-policy.service`
- Create: `tests/test_deploy_vpn_policy_assets.py`

**Interfaces:** `/usr/local/sbin/vpn-policy.sh {start|stop|status}` and `vpn-policy.service` bound to `wg-quick@wg0.service`.

- [ ] **Step 1: Write the failing tests**

```python
def test_policy_unit_follows_wg_lifecycle():
    text = (ROOT / "deploy" / "vpn-policy.service").read_text(encoding="utf-8")
    assert "Requires=wg-quick@wg0.service" in text
    assert "BindsTo=wg-quick@wg0.service" in text
    assert "PartOf=wg-quick@wg0.service" in text
    assert "ExecStart=/usr/local/sbin/vpn-policy.sh start" in text
    assert "ExecStop=/usr/local/sbin/vpn-policy.sh stop" in text

def test_policy_script_uses_only_managed_objects():
    text = (ROOT / "deploy" / "vpn-policy.sh").read_text(encoding="utf-8")
    assert 'PBR_IN_IF="ens18.50"' in text
    assert 'PBR_TABLE="123"' in text
    assert 'PBR_MARK="0x1"' in text
    assert "ip route replace default dev" in text
    assert "ip rule add fwmark" in text
```

- [ ] **Step 2: Verify red**

Run: `pytest -q tests/test_deploy_vpn_policy_assets.py`

Expected: FAIL because the files do not exist.

- [ ] **Step 3: Implement the reconciler**

```bash
start() {
  stop || true
  ip route replace default dev "$WG_IF" table "$PBR_TABLE"
  ip rule add fwmark "$PBR_MARK/$PBR_MASK" lookup "$PBR_TABLE" priority "$PBR_PRIORITY"
  iptables -t mangle -N "$MANGLE_CHAIN" 2>/dev/null || true
  iptables -t mangle -A "$MANGLE_CHAIN" -i "$PBR_IN_IF" -j MARK --set-xmark "$PBR_MARK/$PBR_MASK"
  iptables -t nat -N "$NAT_CHAIN" 2>/dev/null || true
  iptables -t nat -A "$NAT_CHAIN" -o "$WG_IF" -m mark --mark "$PBR_MARK/$PBR_MASK" -j MASQUERADE
}
stop() {
  ip rule del fwmark "$PBR_MARK/$PBR_MASK" lookup "$PBR_TABLE" priority "$PBR_PRIORITY" 2>/dev/null || true
  ip route del default dev "$WG_IF" table "$PBR_TABLE" 2>/dev/null || true
  iptables -t mangle -D PREROUTING -j "$MANGLE_CHAIN" 2>/dev/null || true
  iptables -t mangle -F "$MANGLE_CHAIN" 2>/dev/null || true
  iptables -t mangle -X "$MANGLE_CHAIN" 2>/dev/null || true
  iptables -t nat -D POSTROUTING -j "$NAT_CHAIN" 2>/dev/null || true
  iptables -t nat -F "$NAT_CHAIN" 2>/dev/null || true
  iptables -t nat -X "$NAT_CHAIN" 2>/dev/null || true
}
```

`status` only tests link/rule/route/chain presence and never calls `start` or `stop`.

- [ ] **Step 4: Implement the service**

```ini
[Unit]
Description=Policy routing for VLAN50 through WireGuard
Requires=wg-quick@wg0.service
After=network-online.target wg-quick@wg0.service
BindsTo=wg-quick@wg0.service
PartOf=wg-quick@wg0.service
[Service]
Type=oneshot
ExecStart=/usr/local/sbin/vpn-policy.sh start
ExecStop=/usr/local/sbin/vpn-policy.sh stop
RemainAfterExit=yes
[Install]
WantedBy=multi-user.target
```

- [ ] **Step 5: Verify green and commit**

Run: `pytest -q tests/test_deploy_vpn_policy_assets.py`

Expected: PASS.

Run: `git add deploy/vpn-policy.sh deploy/vpn-policy.service tests/test_deploy_vpn_policy_assets.py && git commit -m "feat: manage WG policy routing lifecycle"`

### Task 2: Add read-only `vpnctl runtime-health`

**Files:**
- Modify: `deploy/vpnctl`
- Modify: `deploy/vpnctl.env.sample`
- Create: `tests/test_vpnctl_runtime_health.py`

**Interfaces:** `vpnctl --json runtime-health [--strict]` returns `{status, overall, sections, warnings, errors}`; strict mode exits 2 when `overall=error`.

- [ ] **Step 1: Write failing command-stub tests**

Use temporary `PATH` stubs for `systemctl`, `ip`, `wg`, and `iptables`; record every invocation.

```python
def test_runtime_health_reports_healthy_state(tmp_path):
    data, proc, calls = run_runtime_health(tmp_path, scenario="healthy")
    assert proc.returncode == 0
    assert data["overall"] == "ok"
    assert data["sections"]["policy_routing"]["table_123_default"] is True
    assert not any(" add " in call or " replace " in call for call in calls)

def test_runtime_health_strict_fails_for_missing_route(tmp_path):
    data, proc, _ = run_runtime_health(tmp_path, scenario="missing-table-route", strict=True)
    assert proc.returncode == 2
    assert "table 123 default route is missing" in data["errors"]

def test_runtime_health_rejects_legacy_51820(tmp_path):
    data, _, _ = run_runtime_health(tmp_path, scenario="legacy-51820")
    assert data["overall"] == "error"
    assert any("51820" in message for message in data["errors"])
```

Also add missing-WG and stale-handshake cases.

- [ ] **Step 2: Verify red**

Run: `pytest -q tests/test_vpnctl_runtime_health.py`

Expected: FAIL because the parser has no `runtime-health` command.

- [ ] **Step 3: Implement defaults, inspection and parser**

Add defaults and matching env sample values:

```python
"WG_INTERFACE": "wg0", "WG_SERVICE": "wg-quick@wg0.service",
"PBR_IN_IF": "ens18.50", "PBR_TABLE": "123", "PBR_MARK": "0x1",
"PBR_PRIORITY": "1000", "WG_HANDSHAKE_MAX_AGE_SECONDS": "180",
```

Use only existing `run([...], check=False)` to inspect OpenVPN service and `management_test()`, WG service/link/handshake/MTU/transfer, `ip rule show`, `ip route show table 123`, and named-chain output from `iptables -S`. Parse `wg show wg0 latest-handshakes` but discard the first public-key column.

```python
p = sub.add_parser("runtime-health", help="inspect OpenVPN, WireGuard and policy-routing runtime health")
p.add_argument("--strict", action="store_true", help="exit non-zero when health has errors")
```

Emit JSON before returning; non-strict always returns 0 and strict returns 2 only for errors.

- [ ] **Step 4: Verify green and commit**

Run: `pytest -q tests/test_vpnctl_runtime_health.py tests/test_vpnctl_management.py`

Expected: PASS.

Run: `git add deploy/vpnctl deploy/vpnctl.env.sample tests/test_vpnctl_runtime_health.py && git commit -m "feat: report WG policy runtime health"`

### Task 3: Install a one-minute read-only health timer

**Files:**
- Create: `deploy/vpn-runtime-health.service`
- Create: `deploy/vpn-runtime-health.timer`
- Modify: `deploy/install-openvpn-web.sh`
- Create: `tests/test_deploy_vpn_runtime_health_timer.py`

**Interfaces:** root service invokes `vpnctl --json runtime-health --strict`; timer starts after one minute and runs every minute.

- [ ] **Step 1: Write failing asset tests**

```python
def test_runtime_health_service_is_strict_and_root_owned():
    text = (ROOT / "deploy" / "vpn-runtime-health.service").read_text(encoding="utf-8")
    assert "User=root" in text
    assert "ExecStart=/usr/local/sbin/vpnctl --json runtime-health --strict" in text

def test_runtime_health_timer_runs_every_minute():
    text = (ROOT / "deploy" / "vpn-runtime-health.timer").read_text(encoding="utf-8")
    assert "OnBootSec=1min" in text
    assert "OnUnitActiveSec=1min" in text
    assert "Persistent=true" in text
```

Also assert that the installer installs both units, enables the timer, and does not restart WireGuard or OpenVPN.

- [ ] **Step 2: Verify red**

Run: `pytest -q tests/test_deploy_vpn_runtime_health_timer.py`

Expected: FAIL because assets and installer wiring are absent.

- [ ] **Step 3: Implement assets and installation wiring**

```ini
# vpn-runtime-health.service
[Service]
Type=oneshot
User=root
ExecStart=/usr/local/sbin/vpnctl --json runtime-health --strict
StandardOutput=journal
StandardError=journal

# vpn-runtime-health.timer
[Timer]
OnBootSec=1min
OnUnitActiveSec=1min
Persistent=true
```

Install policy and health assets, run `systemctl daemon-reload`, then `systemctl enable --now vpn-runtime-health.timer`. Do not restart WireGuard or OpenVPN in the installer.

- [ ] **Step 4: Verify green and commit**

Run: `pytest -q tests/test_deploy_vpn_policy_assets.py tests/test_deploy_vpn_runtime_health_timer.py`

Expected: PASS.

Run: `git add deploy/vpn-runtime-health.service deploy/vpn-runtime-health.timer deploy/install-openvpn-web.sh tests/test_deploy_vpn_runtime_health_timer.py && git commit -m "feat: schedule WG runtime health checks"`

### Task 4: Document deployment, rollback and controlled restart verification

**Files:**
- Modify: `docs/DEPLOYMENT.md`
- Create: `docs/runbooks/wg-policy-resilience-deploy-rollback.md`

- [ ] **Step 1: Document non-mutating acceptance commands**

```bash
sudo /usr/local/sbin/vpnctl --json runtime-health --strict
sudo systemctl status wg-quick@wg0.service vpn-policy.service vpn-runtime-health.timer
sudo ip rule show
sudo ip route show table 123
sudo journalctl -u vpn-runtime-health.service -n 20 --no-pager
```

- [ ] **Step 2: Document the maintenance-window restart and rollback**

```bash
sudo systemctl restart wg-quick@wg0.service
sudo systemctl status vpn-policy.service --no-pager
sudo /usr/local/sbin/vpnctl --json runtime-health --strict
sudo /usr/local/sbin/vpnctl --json management test
```

Rollback restores timestamped `vpn-policy.sh` and unit/timer assets, reloads systemd, starts WG/policy, then reruns strict health.

- [ ] **Step 3: Verify and commit**

Run: `git diff --check && pytest -q`

Expected: no whitespace errors and all tests pass.

Run: `git add docs/DEPLOYMENT.md docs/runbooks/wg-policy-resilience-deploy-rollback.md && git commit -m "docs: add WG policy resilience runbook"`

## Self-review

- Tasks 1-3 cover self-healing, CLI health and timer; Task 4 provides safe deployment and rollback.
- No task changes OpenVPN MSS, client routing, OPNsense/MikroTik or web/API/MCP.
- `runtime-health --strict` is defined in Task 2, scheduled in Task 3 and verified in Task 4.

## Execution Handoff

Plan complete. Two execution options:

1. **Subagent-Driven** — dispatch a fresh subagent per task and review each task before continuing.
2. **Inline Execution** — execute this plan in the current session with review checkpoints.
