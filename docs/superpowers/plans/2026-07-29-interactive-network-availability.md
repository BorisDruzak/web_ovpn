# Interactive Network Availability Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Let authenticated users select canonical IPv4 segments for availability monitoring, inspect truthful evidence, actively check one allowed host, and refresh passive observations from the host profile.

**Architecture:** netctl owns segment overrides, due-schedule calculation, active probe persistence, and bounded collection. FastAPI owns authenticated/CSRF-protected forms, per-user rate limiting, audit records, and templates. The web layer never supplies a CIDR, port, or command to netctl; it passes a validated segment identifier or resolves the target IP from the host record.

**Tech Stack:** Python 3, SQLite, argparse, FastAPI, Jinja, SQLAlchemy, pytest.

## Global Constraints

- Only active IPv4 segments from the current canonical context can be enabled; do not persist or accept arbitrary CIDRs.
- Keep canonical configuration as the source for CIDR, site and category; overrides persist only segment_id, enabled state, ports and interval.
- Active probes are ICMP first, then configured TCP fallback; one successful method is sufficient for online.
- A not-monitored host must never render as online.
- Manual probe and full observation refresh require authentication, CSRF validation, audit logging and one accepted action per actor/action in five minutes.
- Do not modify router, DHCP, switch or firewall configuration.
- Preserve the user’s existing unstaged IPsec/CLI/test/image changes.

---

## File Structure

- Create netctl/availability_settings.py: validate, persist and resolve canonical-segment monitoring overrides and due intervals.
- Modify netctl/migrations.py: migration 17 for override and manual-result tables.
- Modify netctl/context_classifier.py: effective availability rule and interval fields.
- Modify netctl/availability.py: due collection, one-host probe, manual evidence and truthful unmonitored projection.
- Modify netctl/cli.py: settings list/set, availability probe and observation refresh commands.
- Modify netctl/context_query.py: attachment candidate explanations.
- Modify app/models.py and create app/network_actions.py: atomic five-minute action throttle.
- Modify app/main.py and templates: monitoring settings and device actions.
- Modify tests/test_netctl_context_classifier.py, tests/test_netctl_availability.py, tests/test_netctl_cli.py and tests/test_web_network_observer.py.

## Task 1: Segment override persistence and effective canonical rules

**Files:**
- Create: netctl/availability_settings.py
- Modify: netctl/migrations.py:1716-1732
- Modify: netctl/context_classifier.py:22-147
- Test: tests/test_netctl_context_classifier.py
- Test: tests/test_netctl_availability.py

**Interfaces:**
- Consumes: load_active_segment_rules(conn) and active canonical segment stable IDs.
- Produces: AvailabilitySegmentSetting; list_availability_settings(conn); set_availability_setting(conn, segment_id, *, enabled, tcp_ports, interval_minutes); effective load_active_availability_segments(conn).

- [ ] **Step 1: Write failing migration and resolution tests**

~~~python
def test_setting_enables_only_known_ipv4_segment_without_storing_cidr(conn):
    seed_active_context(conn, [
        {"id": "office", "cidr": "192.0.2.0/24"},
        {"id": "vpn", "cidr": "2001:db8::/64"},
    ])
    setting = set_availability_setting(
        conn, "office", enabled=True, tcp_ports=(443,), interval_minutes=10
    )
    assert setting["segment_id"] == "office"
    assert "cidr" not in setting
    assert [(str(rule.network), rule.availability_tcp_ports,
             rule.availability_interval_minutes)
            for rule in load_active_availability_segments(conn)] == [
        ("192.0.2.0/24", (443,), 10)
    ]


def test_setting_rejects_unknown_ipv6_and_invalid_interval(conn):
    seed_active_context(conn, [{"id": "ipv6", "cidr": "2001:db8::/64"}])
    with pytest.raises(ValueError, match="active IPv4 segment"):
        set_availability_setting(
            conn, "ipv6", enabled=True, tcp_ports=(), interval_minutes=5
        )
    with pytest.raises(ValueError, match="interval"):
        set_availability_setting(
            conn, "missing", enabled=True, tcp_ports=(), interval_minutes=7
        )
~~~

- [ ] **Step 2: Run the tests and verify RED**

Run: pytest tests/test_netctl_context_classifier.py tests/test_netctl_availability.py -q

Expected: import errors or failures because migration 17, settings and effective intervals do not exist.

- [ ] **Step 3: Implement migration and settings resolver**

Add migration 17:

~~~python
CREATE TABLE availability_segment_settings (
  segment_id TEXT PRIMARY KEY,
  enabled INTEGER NOT NULL CHECK (enabled IN (0, 1)),
  tcp_ports_json TEXT NOT NULL DEFAULT '[]',
  interval_minutes INTEGER NOT NULL CHECK (
    interval_minutes IN (5, 10, 15, 30, 60)
  ),
  updated_at TEXT NOT NULL
);
CREATE TABLE availability_manual_results (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  segment_id TEXT NOT NULL,
  ip TEXT NOT NULL,
  requested_at TEXT NOT NULL,
  checked_at TEXT NOT NULL,
  active_state TEXT NOT NULL CHECK (
    active_state IN ('reachable', 'unreachable')
  ),
  active_method TEXT NOT NULL DEFAULT '',
  failure_class TEXT NOT NULL DEFAULT ''
);
~~~

Set ALLOWED_INTERVAL_MINUTES to (5, 10, 15, 30, 60). Validate active segment existence, IPv4, at most three unique ports and 1..65535. Add availability_interval_minutes: int = 5 to SegmentRule. Resolve an override when one exists; where no override exists, retain the current canonical availability_monitoring values so migration does not silently disable the deployed 192.168.99.0/24 setting. The override stores no CIDR.

- [ ] **Step 4: Run focused tests and verify GREEN**

Run: pytest tests/test_netctl_context_classifier.py tests/test_netctl_availability.py -q

Expected: PASS; overrides change ports/interval without a duplicate CIDR column.

- [ ] **Step 5: Commit**

~~~bash
git add netctl/migrations.py netctl/availability_settings.py netctl/context_classifier.py tests/test_netctl_context_classifier.py tests/test_netctl_availability.py
git commit -m "feat: configure canonical availability segments"
~~~

## Task 2: Scheduled and one-host availability execution

**Files:**
- Modify: netctl/availability.py:85-225, 486-687
- Modify: netctl/cli.py:435-535, 1416-1423, 1669-1674
- Test: tests/test_netctl_availability.py
- Test: tests/test_netctl_cli.py

**Interfaces:**
- Consumes: effective SegmentRule from Task 1.
- Produces: collect_due_availability(conn, executor, now); probe_one_availability(conn, ip, executor, now); availability settings/set-segment/probe commands; observations refresh command.

- [ ] **Step 1: Write failing collection and probe tests**

~~~python
def test_due_collection_skips_segment_until_selected_interval_expires(conn):
    enable_segment(conn, "office", interval_minutes=15)
    save_successful_run(conn, cidr="192.0.2.0/24",
                        finished_at="2026-07-29T12:00:00Z")
    result = collect_due_availability(
        conn, executor=never_called_executor(),
        now=lambda: "2026-07-29T12:10:00Z",
    )
    assert result.summary == {"targets": 0, "completed": 0}


def test_manual_probe_rejects_unmonitored_ip_without_ping(conn):
    with pytest.raises(ValueError, match="not monitored"):
        probe_one_availability(
            conn, "192.0.2.33", executor=never_called_executor(),
            now="2026-07-29T12:00:00Z",
        )


def test_manual_tcp_fallback_is_saved_without_replacing_cidr_results(conn):
    enable_segment(conn, "office", tcp_ports=(443,))
    result = probe_one_availability(
        conn, "192.0.2.33", executor=ping_false_tcp_443_true(),
        now="2026-07-29T12:00:00Z",
    )
    assert (result.state, result.method) == ("reachable", "tcp:443")
    assert current_availability_results(conn, "192.0.2.0/24") == {}
~~~

- [ ] **Step 2: Run tests and verify RED**

Run: pytest tests/test_netctl_availability.py tests/test_netctl_cli.py -q

Expected: failures because due scheduling, one-host persistence and parsers do not exist.

- [ ] **Step 3: Implement safe execution and CLI**

Use existing probe_target to preserve one-second ICMP and TCP bounds. Scheduled collection selects only enabled segments whose newest complete success is older than interval_minutes. It does not delete a current result for an omitted segment. A manual result goes only to availability_manual_results.

~~~python
def probe_one_availability(conn, ip, executor, now):
    rule = monitored_rule_for_ip(conn, ip)
    if rule is None:
        raise ValueError("not monitored")
    result = probe_target(
        ProbeTarget(ip, rule.availability_tcp_ports, str(rule.network)),
        executor,
    )
    save_manual_result(
        conn, segment_id=rule.segment_id, result=result, checked_at=now
    )
    return result
~~~

Add CLI parsers:

~~~python
availability_sub.add_parser("settings")
set_segment = availability_sub.add_parser("set-segment")
set_segment.add_argument("--segment-id", required=True)
set_segment.add_argument("--enabled", choices=("true", "false"), required=True)
set_segment.add_argument("--tcp-port", action="append", type=int, default=[])
set_segment.add_argument("--interval-minutes", type=int, required=True)
probe = availability_sub.add_parser("probe")
probe.add_argument("--ip", required=True)
observations_sub.add_parser("refresh")
~~~

observations refresh runs the existing collect-all plus reconcile flow under CollectLock and accepts no browser-selected source.

- [ ] **Step 4: Make projection truthful**

For an IP without an enabled segment, replace inherited collector online with seen if current passive data exists, otherwise stale, and emit state/reason not_monitored. Consult a fresh manual result before the scheduled CIDR result and add check_origin manual or scheduled to the public payload. Add not_monitored to the safe public-reason allowlist.

- [ ] **Step 5: Run focused tests and verify GREEN**

Run: pytest tests/test_netctl_availability.py tests/test_netctl_cli.py -q

Expected: PASS; no one-host action expands scanning, manual evidence leaves CIDR results intact, and unmonitored hosts do not render online.

- [ ] **Step 6: Commit**

~~~bash
git add netctl/availability.py netctl/cli.py tests/test_netctl_availability.py tests/test_netctl_cli.py
git commit -m "feat: add safe manual availability probes"
~~~

## Task 3: Web settings, rate limit and device actions

**Files:**
- Create: app/network_actions.py
- Modify: app/models.py
- Modify: app/main.py:1518-1705
- Create: app/templates/network_monitoring.html
- Modify: app/templates/base.html
- Modify: app/templates/network_hosts.html
- Modify: app/templates/network_host_detail.html
- Test: tests/test_web_network_observer.py

**Interfaces:**
- Consumes: CLI payloads from Task 2 and authenticated WebUser/write_audit.
- Produces: GET /network/monitoring; POST /network/monitoring/{segment_id}; POST /network/hosts/{ip}/availability-check; POST /network/hosts/{ip}/refresh-observations; acquire_network_action(db, actor, action, now).

- [ ] **Step 1: Write failing page and POST contract tests**

~~~python
def test_monitoring_settings_posts_only_canonical_segment_and_audits(tmp_path, monkeypatch):
    client, _ = make_client(tmp_path, monkeypatch)
    csrf = login(client)
    response = client.post(
        "/network/monitoring/office",
        data={"enabled": "true", "tcp_ports": "443",
              "interval_minutes": "10", "csrf_token": csrf},
        follow_redirects=False,
    )
    assert response.status_code == 303
    assert invoked_netctl() == [
        "availability", "set-segment", "--segment-id", "office",
        "--enabled", "true", "--tcp-port", "443",
        "--interval-minutes", "10",
    ]


def test_manual_check_uses_server_ip_and_rate_limits(tmp_path, monkeypatch):
    client, _ = make_client(tmp_path, monkeypatch)
    csrf = login(client)
    first = client.post(
        "/network/hosts/192.168.99.44/availability-check",
        data={"csrf_token": csrf},
    )
    second = client.post(
        "/network/hosts/192.168.99.44/availability-check",
        data={"csrf_token": csrf},
    )
    assert first.status_code == 303
    assert "через 5 минут" in second.text
~~~

- [ ] **Step 2: Run tests and verify RED**

Run: pytest tests/test_web_network_observer.py -q

Expected: 404 responses or missing CLI-call assertions for the new routes.

- [ ] **Step 3: Implement throttle and routes**

Add public-only NetworkActionThrottle with a unique (actor, action) and last_accepted_at. acquire_network_action uses one transaction and rejects less than 300 seconds with a retry message. Every route calls require_user, verify_csrf, throttle, fixed CLI arguments, write_audit, Russian flash and encoded redirect.

~~~python
@app.post("/network/hosts/{ip}/availability-check")
async def network_host_availability_check(ip, request, db=Depends(get_db)):
    user = require_user(request, db)
    await verify_csrf(request)
    permit = acquire_network_action(
        db, user.username, "network-host-availability", utcnow()
    )
    if not permit.accepted:
        add_flash(request, "bad", permit.message)
        return redirect(f"/network/hosts/{quote(ip, safe='')}")
    _, error = net_cli_call(
        request, ["availability", "probe", "--ip", ip], timeout=60
    )
    write_audit(
        db, request, user, "network-host-availability",
        "error" if error else "ok", error or ip, target_client=ip,
    )
    add_flash(request, "bad" if error else "ok",
              error or "Проверка доступности завершена")
    return redirect(f"/network/hosts/{quote(ip, safe='')}")
~~~

The refresh route uses action network-host-observation-refresh, fixed command observations refresh and timeout=300. The settings route uses availability settings and set-segment; template values for CIDR/site/category are read-only.

- [ ] **Step 4: Render status evidence and actions**

Make status in network_hosts.html a link to /network/hosts/{ip}; label online · ICMP, online · TCP:443, seen · ARP/DHCP/bridge, offline or не мониторится. Add «Доступность» and «Свежесть наблюдений» panels to network_host_detail.html with CSRF forms. Show CIDR, method, checked time, check origin, passive evidence and safe reason. Do not put IP, CIDR or ports in editable action fields. Add readable Russian sidebar navigation.

- [ ] **Step 5: Run focused web tests and verify GREEN**

Run: pytest tests/test_web_network_observer.py -q

Expected: PASS; authentication, CSRF, audit, rate-limit and visible evidence contracts all hold.

- [ ] **Step 6: Commit**

~~~bash
git add app/models.py app/network_actions.py app/main.py app/templates/base.html app/templates/network_monitoring.html app/templates/network_hosts.html app/templates/network_host_detail.html tests/test_web_network_observer.py
git commit -m "feat: add interactive host availability controls"
~~~

## Task 4: Explain attachment ambiguity in the asset profile

**Files:**
- Modify: netctl/context_query.py
- Modify: app/templates/network_asset_detail.html
- Test: tests/test_netctl_cli.py
- Test: tests/test_web_network_observer.py

**Interfaces:**
- Consumes: asset_attachment_resolutions.evidence_json and asset_attachment_candidates.
- Produces: context attachment alternatives with source, port_key, vlan_id, candidate_class, score and safe reason.

- [ ] **Step 1: Write a failing explanation test**

~~~python
def test_asset_context_exposes_safe_reasons_for_ambiguous_attachment(conn):
    seed_attachment_candidates(conn, [
        candidate(source="tplink-ito-15", port="physical:2", score=50,
                  candidate_class="unknown", reason="oper_status_unknown"),
        candidate(source="tplink-ito-14", port="physical:47", score=50,
                  candidate_class="unknown", reason="competing_fdb"),
    ])
    context = inspect_asset_context(conn, "mac:C0:9B:F4:62:54:E5")
    assert context["attachment"]["status"] == "ambiguous"
    assert context["attachment"]["alternatives"][0]["reason"] == (
        "статус порта не получен"
    )
~~~

- [ ] **Step 2: Run tests and verify RED**

Run: pytest tests/test_netctl_cli.py tests/test_web_network_observer.py -q

Expected: alternatives lack score/class/reason and the card cannot explain its decision.

- [ ] **Step 3: Project and render safe candidate evidence**

Map only known internal reasons:

~~~python
ATTACHMENT_REASON_LABELS = {
    "oper_status_unknown": "статус порта не получен",
    "competing_fdb": "есть конкурирующая FDB-запись",
    "verified_backbone_port": "это подтверждённый uplink",
    "partial_collection": "сбор коммутатора неполный",
}
~~~

Render source, port, VLAN, score and reason for every candidate. Confirmed cards keep the concise confirmation panel; candidates are an explanation, not a second connection claim.

- [ ] **Step 4: Run tests and verify GREEN**

Run: pytest tests/test_netctl_cli.py tests/test_web_network_observer.py -q

Expected: PASS; tplink-ito-15 / physical:2 can be likely while confidence remains explicitly ambiguous.

- [ ] **Step 5: Commit**

~~~bash
git add netctl/context_query.py app/templates/network_asset_detail.html tests/test_netctl_cli.py tests/test_web_network_observer.py
git commit -m "feat: explain attachment candidates"
~~~

## Task 5: Full verification and release handoff

**Files:**
- Modify: only files required by test-driven fixes from Tasks 1-4
- Test: full tests/ suite

**Interfaces:**
- Consumes: all delivered CLI, persistence and UI interfaces.
- Produces: verified local branch ready for a separate deployment authorization.

- [ ] **Step 1: Run targeted regression groups**

Run:

~~~bash
pytest tests/test_netctl_context_classifier.py tests/test_netctl_availability.py tests/test_netctl_cli.py tests/test_web_network_observer.py -q
~~~

Expected: PASS with no new failures.

- [ ] **Step 2: Run the full suite**

Run: pytest -q

Expected: all tests pass; record exact passed/skipped/failed totals.

- [ ] **Step 3: Perform rendered UI verification**

Flow under test: authenticated user opens /network/monitoring → enables a canonical CIDR → opens /network/hosts → opens a status proof → submits manual check or sees not monitored → submits Last Seen refresh.

Use Browser first. Confirm page identity, meaningful DOM, no framework overlay, relevant console health, desktop screenshot and button/result state. If authentication is unavailable, report that limitation and retain route/template test evidence.

- [ ] **Step 4: Inspect release scope**

Run:

~~~bash
git status --short
git diff --check
git log --oneline --decorate -8
~~~

Expected: only implementation commits are part of the release; pre-existing dirty IPsec/CLI/test/image changes remain outside scope.

- [ ] **Step 5: Request deployment decision**

Report commits, test totals, browser evidence and exact changed files. Do not deploy to 192.168.100.30 until the user explicitly authorizes this new feature.

## Plan Self-Review

- Spec coverage: Tasks 1-2 implement canonical selection, intervals, ICMP/TCP evidence and one-IP probes. Task 3 implements UI, CSRF, audit, throttling and passive refresh. Task 4 explains ambiguous ports. Task 5 verifies and gates deployment.
- Placeholder scan: interfaces, tables, commands, tests and acceptance behavior are defined.
- Type consistency: segment_id, availability_interval_minutes, AvailabilitySegmentSetting, probe_one_availability, NetworkActionThrottle and each HTTP route are introduced before consumers.
