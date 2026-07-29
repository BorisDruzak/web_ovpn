# Network Host Availability Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Make Network Observer status show current ICMP/TCP reachability for every explicitly enabled canonical CIDR, while keeping ARP/DHCP/bridge/SNMP data as passive evidence only.

**Architecture:** The canonical network-context revision declares the CIDRs and TCP fallback ports. Netctl expands that immutable target set, executes a bounded read-only availability run, atomically persists current results, and projects host status from active results plus valid passive evidence. The web/API layer consumes that projection and defaults to only currently confirmed devices; history remains an explicit filter.

**Tech Stack:** Python 3 standard library (`ipaddress`, `subprocess`, `socket`, `concurrent.futures`), SQLite, FastAPI/Jinja, systemd, pytest.

## Global Constraints

- The canonical `BorisDruzak/network_configuration` context is the only source of monitored CIDRs and TCP port policy; do not add a duplicate CIDR list to `ui_vpn`.
- Probes contact only IPv4 addresses expanded from active `availability_monitoring: true` context segments; the API and UI accept no probe targets, ports, commands, or credentials.
- ICMP uses a fixed numeric-address ping argv; TCP uses `socket.connect_ex()` with no payload or authentication; no Nmap, port enumeration, SNMP SET, RouterOS write, or endpoint configuration action is permitted.
- `online` requires ICMP or allowed-TCP success in a complete current run. Valid-MAC ARP/DHCP/bridge/FDB can yield only `seen`. Empty or malformed MAC evidence never yields `online` or `seen`.
- A failed, incomplete, unavailable-context, or stale availability run yields `stale`; it must never publish a partial negative result as `offline`.
- A bare scan target does not create a `network_hosts` row. The default hosts view contains only `online`, `seen`, and `connected`; `offline`/`stale` history requires an explicit status filter.
- Availability history is retained for 30 days through the existing transactional retention path. All public responses and logs are sanitized.
- Existing unrelated worktree changes are user-owned. Stage and commit only files created or changed by the task being executed.

---

## File Structure

| File | Responsibility |
| --- | --- |
| `BorisDruzak/network_configuration/schemas/network-context.schema.json` | Upstream validation contract for enabled availability segments and TCP port policy. |
| `BorisDruzak/network_configuration/config/network-context.yaml` | Canonical, reviewed declaration of the initially enabled `192.168.99.0/24` segment. |
| `netctl/context_classifier.py` | Loads the approved availability policy from imported active segment JSON. |
| `netctl/migrations.py` | Migration 14 for current availability state and retained run/event history. |
| `netctl/availability.py` | Target expansion, bounded ICMP/TCP execution, atomic persistence, passive-evidence evaluation, and host-status projection. |
| `netctl/store.py` | Delegates host list/detail/dashboard presentation to the availability projection. |
| `netctl/cli.py` | Exposes `availability collect` and invokes it only after successful `collect all`. |
| `netctl/retention.py` | Retains 30 days of availability history without deleting current results or the latest successful run per CIDR. |
| `app/network_observer.py`, `app/main.py`, `app/api.py`, `app/templates/network_hosts.html` | Preserves availability fields, default current-device filtering, and renders evidence/freshness. |
| `deploy/netctl-availability.service`, `deploy/netctl-availability.timer`, installer/verifier files | Hardened recovery scheduling and installed-unit verification. |
| `tests/test_netctl_availability.py` | Unit, storage, projection, and CLI integration tests using injected probe functions only. |
| `tests/test_netctl_context_classifier.py`, `tests/test_netctl_retention.py`, `tests/test_web_network_observer.py`, `tests/test_deploy_netctl.py` | Context policy, retention, API/UI, and systemd installer regression coverage. |
| `docs/runbooks/netctl-host-availability-rollout.md` | Backup, staged deployment, live proof, rollback, and operational diagnostics. |

## Task 1: Publish and import the canonical availability policy

**Files:**

- Modify in `BorisDruzak/network_configuration`: `schemas/network-context.schema.json`, `config/network-context.yaml`, and that repository's schema fixtures/tests.
- Modify: `netctl/context_classifier.py:20-83`
- Test: `tests/test_netctl_context_classifier.py`

**Interfaces:**

- Consumes: an imported active `intent_segments.canonical_json` object containing `id`, `cidr`, `observer_category`, optional `site`, `availability_monitoring`, and `availability_tcp_ports`.
- Produces: `SegmentRule(segment_id, network, observer_category, site, availability_monitoring, availability_tcp_ports)` and `load_active_availability_segments(conn) -> tuple[SegmentRule, ...]`.

- [ ] **Step 1: Add failing context-policy tests.**

```python
def test_active_availability_segments_are_ipv4_and_have_bounded_tcp_ports(tmp_path):
    conn = connect(f"sqlite:///{(tmp_path / 'netctl.sqlite').as_posix()}")
    _activate_segments(conn, [{
        "id": "m-arhiv-lan", "cidr": "192.168.99.0/24",
        "observer_category": "site_device", "availability_monitoring": True,
        "availability_tcp_ports": [443, 22, 443],
    }])
    assert [(rule.network.with_prefixlen, rule.availability_tcp_ports)
            for rule in load_active_availability_segments(conn)] == [
                ("192.168.99.0/24", (22, 443))]


@pytest.mark.parametrize("segment", [
    {"id": "v6", "cidr": "2001:db8::/64", "availability_monitoring": True},
    {"id": "too-many", "cidr": "192.0.2.0/24", "availability_monitoring": True,
     "availability_tcp_ports": [22, 80, 443, 8443]},
])
def test_invalid_availability_segment_fails_closed(segment, tmp_path):
    ...
```

- [ ] **Step 2: Run the focused test and confirm RED.**

Run: `pytest tests/test_netctl_context_classifier.py -q -k availability`

Expected: FAIL because `SegmentRule` has no availability fields and `load_active_availability_segments` is absent.

- [ ] **Step 3: Change the upstream schema and canonical data.**

Add to the upstream segment schema:

```json
"availability_monitoring": {"type": "boolean"},
"availability_tcp_ports": {
  "type": "array", "maxItems": 3, "uniqueItems": true,
  "items": {"type": "integer", "minimum": 1, "maximum": 65535}
}
```

Permit `availability_tcp_ports` only when `availability_monitoring` is true;
allow it to be omitted for ICMP-only monitoring. Add the approved fields only
to the intended `192.168.99.0/24` segment in the canonical YAML, validate the
upstream repository, commit it there, and import the validated revision into
Netctl before testing this repository's live integration.

- [ ] **Step 4: Implement strict Netctl loading.**

Extend `SegmentRule` with `availability_monitoring: bool = False` and
`availability_tcp_ports: tuple[int, ...] = ()`. In `load_active_segment_rules`, reject non-boolean monitoring values, non-list ports, duplicate ports, non-integers, ports outside `1..65535`, more than three ports, and IPv6 monitoring. Implement:

```python
def load_active_availability_segments(conn: sqlite3.Connection) -> tuple[SegmentRule, ...]:
    rules = load_active_segment_rules(conn)
    return tuple(rule for rule in rules if rule.availability_monitoring)
```

Do not add monitoring defaults to `legacy_segment_rules`; absent validated
context means no target set and therefore `stale`, not an inferred scan.

- [ ] **Step 5: Run focused tests and commit the Netctl consumer.**

Run: `pytest tests/test_netctl_context_classifier.py -q -k 'availability or active_context'`

Expected: PASS, including malformed-policy rejection and longest-prefix ordering.

Commit: `git add netctl/context_classifier.py tests/test_netctl_context_classifier.py && git commit -m "feat: load canonical availability segments"`

## Task 2: Add availability state storage and retention protection

**Files:**

- Create: `netctl/availability.py`
- Modify: `netctl/migrations.py:1652-1669`
- Modify: `netctl/retention.py:8-181`
- Test: `tests/test_netctl_availability.py`
- Test: `tests/test_netctl_retention.py`

**Interfaces:**

- Consumes: `SegmentRule`, UTC timestamps, and one completed `AvailabilityRun` result.
- Produces: `save_availability_run(conn, run: AvailabilityRun) -> int`, `current_availability_results(conn, cidr: str) -> dict[str, AvailabilityResult]`, and retention report/delete keys `availability_runs` and `availability_result_events`.

- [ ] **Step 1: Write migration, atomicity, and retention RED tests.**

```python
def test_successful_run_replaces_only_its_cidr_current_results(conn):
    first = AvailabilityRun.success("192.0.2.0/30", started=OLD, finished=OLD,
        results=[AvailabilityResult("192.0.2.1", "reachable", "icmp"),
                 AvailabilityResult("192.0.2.2", "unreachable", None)])
    save_availability_run(conn, first)
    failed = AvailabilityRun.failed("192.0.2.0/30", started=NEW, error_class="deadline_exceeded")
    save_availability_run(conn, failed)
    assert current_availability_results(conn, "192.0.2.0/30")["192.0.2.1"].method == "icmp"


def test_retention_keeps_current_and_latest_successful_availability_run(conn):
    report = retention_report(conn, CUTOFF)
    assert report["keep"]["availability_runs_current_reference"] == 1
    assert report["delete"]["availability_result_events"] == 1
```

- [ ] **Step 2: Run the focused tests and confirm RED.**

Run: `pytest tests/test_netctl_availability.py tests/test_netctl_retention.py -q -k 'availability or retention'`

Expected: FAIL because availability types, tables, and retention keys are absent.

- [ ] **Step 3: Add migration 14 and typed storage primitives.**

Append `_migration_14` and `(14, _migration_14)` to `MIGRATIONS`. Create:

```sql
CREATE TABLE availability_runs (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  context_revision_id INTEGER NOT NULL REFERENCES context_revisions(id) ON DELETE RESTRICT,
  cidr TEXT NOT NULL,
  started_at TEXT NOT NULL,
  finished_at TEXT,
  status TEXT NOT NULL CHECK (status IN ('success', 'failed')),
  target_count INTEGER NOT NULL CHECK (target_count >= 0),
  completed_target_count INTEGER NOT NULL CHECK (completed_target_count >= 0),
  error_class TEXT NOT NULL DEFAULT ''
);
CREATE TABLE availability_results (
  cidr TEXT NOT NULL,
  ip TEXT NOT NULL,
  run_id INTEGER NOT NULL REFERENCES availability_runs(id) ON DELETE RESTRICT,
  active_state TEXT NOT NULL CHECK (active_state IN ('reachable', 'unreachable')),
  active_method TEXT NOT NULL DEFAULT '',
  checked_at TEXT NOT NULL,
  failure_class TEXT NOT NULL DEFAULT '',
  PRIMARY KEY (cidr, ip)
);
```

Add `availability_result_events` with `id`, `run_id`, `ip`, old/new active
state, old/new method, `observed_at`, and a sanitized `reason`. In one
transaction, insert every run; replace `availability_results` only for a
`success` run whose completed count equals target count; calculate and insert
compact change events; rollback all writes if any invariant fails.

- [ ] **Step 4: Extend retention without weakening recovery protection.**

In `netctl/retention.py`, add helpers that protect each CIDR's latest
successful availability run plus every run referenced by
`availability_results`. Include 30-day deletion counts and deletes for old
`availability_result_events` and unprotected old `availability_runs`, inside
the existing single `BEGIN IMMEDIATE` transaction. Run foreign-key and
integrity checks after deletion.

- [ ] **Step 5: Run tests, migration regression, and commit.**

Run: `pytest tests/test_netctl_availability.py tests/test_netctl_retention.py tests/test_netctl_context_migrations.py -q`

Expected: PASS; a failed run leaves the prior complete run current, and a
retention failure rolls back all availability deletions.

Commit: `git add netctl/availability.py netctl/migrations.py netctl/retention.py tests/test_netctl_availability.py tests/test_netctl_retention.py && git commit -m "feat: persist network availability runs"`

## Task 3: Implement bounded ICMP/TCP collection and CLI lifecycle

**Files:**

- Modify: `netctl/availability.py`
- Modify: `netctl/cli.py:35, 505-517, 1564-1585`
- Test: `tests/test_netctl_availability.py`
- Test: `tests/test_netctl_cli.py`

**Interfaces:**

- Consumes: `load_active_availability_segments(conn)` and injectable
  `ProbeExecutor(ping, connect, now)`.
- Produces: `expand_targets(segments) -> tuple[ProbeTarget, ...]`,
  `collect_availability(conn, executor, *, now) -> AvailabilityCollection`, and
  CLI `netctl --json availability collect`.

- [ ] **Step 1: Write failing target-expansion and probe-order tests.**

```python
def test_target_expansion_deduplicates_overlap_and_excludes_ipv4_network_and_broadcast():
    targets = expand_targets((segment("192.0.2.0/30", ports=(443,)),
                              segment("192.0.2.2/31", ports=(22,))))
    assert [(target.ip, target.tcp_ports) for target in targets] == [
        ("192.0.2.1", (443,)), ("192.0.2.2", (22,)), ("192.0.2.3", (22,))]


def test_tcp_is_attempted_only_after_icmp_failure_and_first_success_wins():
    executor = FakeExecutor(icmp={"192.0.2.1": False}, tcp={("192.0.2.1", 22): False,
                                                              ("192.0.2.1", 443): True})
    assert probe_target(target("192.0.2.1", (22, 443)), executor).active_method == "tcp:443"
```

- [ ] **Step 2: Run the focused tests and confirm RED.**

Run: `pytest tests/test_netctl_availability.py tests/test_netctl_cli.py -q -k 'target_expansion or probe_order or availability_collect'`

Expected: FAIL because no executor or availability command exists.

- [ ] **Step 3: Implement the safe executor and collection service.**

Use a `ThreadPoolExecutor(max_workers=64)`. `SubprocessPing` calls a fixed
argv equivalent to `ping -n -c 1 -W 1 <numeric-ip>` on Linux; construct the
argv list directly, set `shell=False`, `timeout=2`, capture output, and map
exit/result only to the normalized outcome. `SocketConnector` calls
`socket.create_connection((ip, port), timeout=1)` and closes immediately.

`collect_availability` must:

1. load only validated active IPv4 availability segments;
2. resolve overlaps by the most-specific segment policy;
3. submit at most 64 address jobs and enforce 90 seconds per `/24` equivalent;
4. persist a `success` run only when every target completed;
5. persist a `failed` run with `deadline_exceeded`, `context_unavailable`, or
   a fixed executor error class otherwise; and
6. never create a `network_hosts` row from a probe-only target.

- [ ] **Step 4: Wire the command after successful normal collection only.**

Add the `availability` parser with subcommand `collect`. The command opens the
existing Netctl database and returns a sanitized `{status, runs, summary}`
object. In `collect all`, call availability only after every enabled source
collection succeeds; a failed normal collection returns its existing error
path and does not invoke probes. Keep a direct `availability collect` command
for the recovery systemd service; it must fail closed when context/source
health is invalid.

- [ ] **Step 5: Run focused verification and commit.**

Run: `pytest tests/test_netctl_availability.py tests/test_netctl_cli.py -q -k 'availability or collect_all'`

Expected: PASS, including fixed argv/no shell assertion, 64-worker bound,
deadline handling, no partial offline publication, and no probe-created hosts.

Commit: `git add netctl/availability.py netctl/cli.py tests/test_netctl_availability.py tests/test_netctl_cli.py && git commit -m "feat: collect bounded host availability"`

## Task 4: Project active and passive evidence into one host status

**Files:**

- Modify: `netctl/availability.py`
- Modify: `netctl/store.py:620-718`
- Modify: `netctl/normalizer.py:135-161`
- Test: `tests/test_netctl_availability.py`
- Test: `tests/test_netctl_cli.py`

**Interfaces:**

- Consumes: `network_hosts`, current `availability_results`, availability run
  freshness, current ARP/DHCP/bridge-host records, and authoritative current
  switch FDB records.
- Produces: `project_host_availability(conn, host, *, now) -> dict[str, Any]`,
  `query_hosts(..., status='current') -> list[dict[str, Any]]`, and dashboard
  counts calculated from projection output.

- [ ] **Step 1: Write failing status-precedence tests.**

```python
def test_complete_arp_without_mac_is_not_online_or_seen(conn):
    seed_host(conn, ip="192.0.2.8", mac=None, status="online")
    seed_successful_negative_result(conn, cidr="192.0.2.0/24", ip="192.0.2.8")
    assert project_host_availability(conn, host(conn, "192.0.2.8"), now=NOW)["status"] == "offline"


@pytest.mark.parametrize(("passive_source", "row"), [
    ("mikrotik_arp", valid_arp()), ("mikrotik_dhcp", bound_lease()),
    ("mikrotik_bridge", bridge_host()), ("snmp_fdb", authoritative_fdb()),
])
def test_fresh_valid_mac_passive_evidence_yields_seen_after_negative_probe(conn, passive_source, row):
    ...


def test_missing_or_failed_current_run_is_stale_not_offline(conn):
    ...
```

- [ ] **Step 2: Run the focused tests and confirm RED.**

Run: `pytest tests/test_netctl_availability.py tests/test_netctl_cli.py -q -k 'passive or stale or projection'`

Expected: FAIL because `network_hosts.status` is still returned directly.

- [ ] **Step 3: Stop normalizer from asserting live availability.**

Keep the raw source status for diagnostics, but replace normalizer assignment
of `status="online"` for complete ARP and bound DHCP with source-observation
classification only. Validate `normalize_mac(arp["mac"])` before adding it as
passive evidence. No normalizer path may make a host display `online`; only
the availability projection does so.

- [ ] **Step 4: Implement the projection and default current filter.**

Implement exact precedence:

```python
if host_is_openvpn_connected(host):
    return status("connected", reason="openvpn_management")
if successful_fresh_active_result(host):
    return status("online", method=result.active_method, reason="active_probe")
if failed_or_missing_or_stale_run(host):
    return status("stale", reason=run_reason)
if fresh_valid_passive_evidence(host):
    return status("seen", passive_evidence=evidence)
return status("offline", reason="active_negative_no_passive_evidence")
```

Use a two-interval freshness calculation driven by the collector/availability
interval constants. Return the public `availability` object from the approved
spec. Treat status filter `current` as `online|seen|connected`; it becomes the
default when the caller supplies no status. Preserve an explicit `all` filter
for inventory/history export and explicit `offline`/`stale` filters for
diagnostics.

- [ ] **Step 5: Recalculate dashboard/detail/list consumers and commit.**

Run: `pytest tests/test_netctl_availability.py tests/test_netctl_cli.py -q -k 'projection or dashboard or hosts'`

Expected: PASS; an old empty-MAC ARP record is offline/stale, a current MAC
ARP is seen after a negative active run, and default list counts exclude
offline/stale rows.

Commit: `git add netctl/availability.py netctl/store.py netctl/normalizer.py tests/test_netctl_availability.py tests/test_netctl_cli.py && git commit -m "fix: derive host status from availability evidence"`

## Task 5: Deliver consistent web and API presentation

**Files:**

- Modify: `app/network_observer.py:69-203`
- Modify: `app/api.py:1092-1123`
- Modify: `app/main.py:1574-1625`
- Modify: `app/templates/network_hosts.html`
- Test: `tests/test_web_network_observer.py`

**Interfaces:**

- Consumes: Netctl host rows with `status` and the public `availability`
  object from Task 4.
- Produces: a default `status=current` web/API list, explicit status filters,
  and rendered active check/evidence columns with no raw probe errors.

- [ ] **Step 1: Write failing API/filter/render tests.**

```python
def test_hosts_api_defaults_to_current_availability_rows(client, monkeypatch):
    monkeypatch.setattr(api, "call_netctl", fake_hosts([
        host("192.168.99.2", "offline"), host("192.168.99.44", "online", method="icmp"),
        host("192.168.99.45", "seen", passive=["mikrotik_dhcp"]),
    ]))
    payload = client.get("/api/v1/network/hosts").json()["data"]["hosts"]
    assert [item["ip"] for item in payload] == ["192.168.99.44", "192.168.99.45"]


def test_hosts_page_explicit_stale_filter_shows_sanitized_reason(client):
    response = client.get("/network/hosts?status=stale")
    assert "run failed" in response.text
    assert "socket timeout" not in response.text
```

- [ ] **Step 2: Run focused tests and confirm RED.**

Run: `pytest tests/test_web_network_observer.py -q -k 'availability or current or stale'`

Expected: FAIL because the UI has no `current` default or availability fields.

- [ ] **Step 3: Preserve availability during unified OpenVPN merging.**

Extend `normalize_netctl_host` to copy a mapping-only `availability` object.
When an OpenVPN connection matches an IP, retain that object but set display
status to `connected` and add `availability.reason="openvpn_management"` only
in the response copy. Do not mutate the Netctl row or overwrite its last
active check.

- [ ] **Step 4: Add public filters and table detail.**

Make `status=current` the default in `network_hosts` and `api_network_hosts`.
Allow only `current`, `all`, `online`, `seen`, `offline`, `stale`, and
`connected`; reject any other value with HTTP 422 in the API and an empty
validated choice in the HTML route. Render `Last active check` and `Evidence`
from `availability.active_method`, `checked_at`, `passive_evidence`, and the
sanitized reason. `availability is null` renders `not monitored`, never a
blank online badge.

- [ ] **Step 5: Run web/API suite and commit.**

Run: `pytest tests/test_web_network_observer.py tests/test_netctl_client.py -q`

Expected: PASS; direct API, HTML list, and detail use identical statuses and
exclude raw executor/network error strings.

Commit: `git add app/network_observer.py app/api.py app/main.py app/templates/network_hosts.html tests/test_web_network_observer.py && git commit -m "feat: show current host availability"`

## Task 6: Install recovery scheduling, retention, and rollout controls

**Files:**

- Create: `deploy/netctl-availability.service`
- Create: `deploy/netctl-availability.timer`
- Modify: `deploy/install-openvpn-web.sh`
- Modify: `deploy/verify_netctl_systemd.py`
- Modify: `tests/test_deploy_netctl.py`
- Modify: `tests/test_deploy_netctl_retention.py`
- Create: `docs/runbooks/netctl-host-availability-rollout.md`

**Interfaces:**

- Consumes: CLI `netctl --json availability collect` and the migration from
  Task 2.
- Produces: a verified, hardened recovery service/timer and a no-network-write
  deployment/rollback runbook.

- [ ] **Step 1: Write failing unit-contract and installer tests.**

```python
def test_availability_unit_uses_only_fixed_netctl_argv():
    assert EXPECTED_EXEC_STARTS["netctl-availability.service"] == [
        "/usr/local/sbin/netctl", "--json", "availability", "collect"
    ]


def test_installer_enables_availability_timer_after_systemd_verification(tmp_path):
    result, _bin_dir, calls_path, _environment = _run_installer(tmp_path)
    assert result.returncode == 0
    assert "enable --now netctl-availability.timer" in calls_path.read_text().splitlines()
```

- [ ] **Step 2: Run the focused tests and confirm RED.**

Run: `pytest tests/test_deploy_netctl.py tests/test_deploy_netctl_retention.py -q -k availability`

Expected: FAIL because no availability units, verifier expectations, or installer enablement exist.

- [ ] **Step 3: Add hardened recovery units and installer verification.**

Create a oneshot service with `User=netctl`, `Group=netctl`,
`NoNewPrivileges=true`, `PrivateTmp=true`, `ProtectHome=true`, and exactly:

```ini
ExecStart=/usr/local/sbin/netctl --json availability collect
```

Create its timer with `OnBootSec=3min`, `OnUnitActiveSec=5min`,
`AccuracySec=30s`, `Persistent=true`, and `Unit=netctl-availability.service`.
Install both units, add them to `EXPECTED_EXEC_STARTS`/`EXPECTED_PROPERTIES`,
and enable the timer only after `verify-netctl-systemd` succeeds. Keep the
normal collector's success hook as the primary run path; this timer is a
boot/recovery path and remains read-only.

- [ ] **Step 4: Extend retention and create rollout runbook.**

Add availability tables to existing retention test fixtures and verify the
daily retention service prunes only events/runs older than 30 days while
protecting current results and latest success per CIDR. Write the rollout
runbook with these exact stages: stop collection/availability timers; take and
hash an SQLite backup; deploy application; verify migration ledger through
version 14 and `PRAGMA integrity_check`; validate/import the approved
canonical context; start collection; run one availability cycle; compare
`192.168.99.0/24` current count with a separately authorized active scan;
verify empty-MAC ARP is not online; enable timers. Document rollback by
stopping timers, preserving the failed database for diagnosis, restoring the
verified backup and previous application release, integrity checking, then
starting the prior services. Do not include secrets or private topology data.

- [ ] **Step 5: Run deployment/documentation checks and commit.**

Run: `pytest tests/test_deploy_netctl.py tests/test_deploy_netctl_retention.py tests/test_netctl_retention.py -q && python -m compileall -q netctl app && git diff --check`

Expected: PASS with exact systemd argv/properties, transactional retention
coverage, successful compilation, and no whitespace errors.

Commit: `git add deploy/netctl-availability.service deploy/netctl-availability.timer deploy/install-openvpn-web.sh deploy/verify_netctl_systemd.py tests/test_deploy_netctl.py tests/test_deploy_netctl_retention.py tests/test_netctl_retention.py docs/runbooks/netctl-host-availability-rollout.md && git commit -m "feat: schedule host availability monitoring"`

## Task 7: Full regression and acceptance handoff

**Files:**

- Modify if required by verified outputs only: `docs/verification/network-host-availability-2026-07-29.md`

**Interfaces:**

- Consumes: the completed implementation, deployed active context revision,
  and the runbook from Task 6.
- Produces: a sanitized verification record that proves status semantics and
  contains no credentials, raw command output, or private keys.

- [ ] **Step 1: Run the complete local regression suite.**

Run: `pytest -q`

Expected: PASS. If a pre-existing failure appears, record its test name and
output separately; do not alter unrelated code to make this feature pass.

- [ ] **Step 2: Run static and safety verification.**

Run: `python -m compileall -q app netctl && git diff --check && rg -n -i "(password|secret|token|private key)" docs/runbooks/netctl-host-availability-rollout.md docs/verification/network-host-availability-2026-07-29.md`

Expected: compilation and diff check pass; the credential scan returns no
credential values. Generic words such as `secret` in safety instructions are
permitted only when they do not contain a value.

- [ ] **Step 3: Execute the deployed read-only acceptance sequence.**

Follow the runbook against the deployed copy only after the user authorizes
deployment: inspect source/context health, run one collection plus availability
cycle, obtain status counts for `192.168.99.0/24`, inspect one known live MAC
host and `192.168.99.2`, and compare only aggregate active-scan counts. Do
not change any device configuration.

- [ ] **Step 4: Record sanitized acceptance evidence and commit.**

Record deployed revision, context revision ID, availability run IDs, aggregate
status counts, the empty-MAC status result, source health, and rollback
readiness. Omit usernames, IPs outside approved examples, MAC values, probe
output, secrets, and raw logs.

Run: `git add docs/verification/network-host-availability-2026-07-29.md && git commit -m "docs: verify host availability rollout"`

Expected: the verification record is complete, sanitized, and only created
after the live read-only checks pass.

## Plan Self-Review

- **Spec coverage:** Tasks 1-3 cover canonical CIDR policy, bounded ICMP/TCP
  execution, atomic state, and no arbitrary input. Task 4 implements exact
  status semantics and the empty-MAC correction. Task 5 applies the projection
  uniformly in API/UI. Task 6 covers retention, systemd, deployment, and
  rollback. Task 7 covers full regression and the live acceptance comparison.
- **Consistency:** `SegmentRule.availability_monitoring`,
  `load_active_availability_segments`, `AvailabilityRun`,
  `AvailabilityResult`, `collect_availability`, and
  `project_host_availability` are defined before later tasks consume them.
- **Scope:** The plan contains no RouterOS/SNMP/OpenVPN/firewall writes and
  treats upstream canonical-schema publication as an explicit prerequisite.
