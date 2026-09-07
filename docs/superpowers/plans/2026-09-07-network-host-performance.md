# Network Host Snapshot Implementation Plan

> For agentic workers: use superpowers:executing-plans task by task. Steps use checkbox syntax.

Goal: serve Network Hosts from an atomically published SQLite read model, with bounded projection work, progressive browser updates, and server-side filtering/pagination.

Architecture: netctl.availability gains a pure bulk projection path and netctl.host_snapshot persists its public host rows after collection or reconciliation. CLI/API/UI list reads select the published snapshot only; the page polls metadata and replaces its current filtered page only after a new snapshot is published.

Tech Stack: Python 3, SQLite WAL, FastAPI, Jinja2, Fetch API, pytest.

Spec: docs/superpowers/specs/2026-09-07-network-host-performance-design.md

## Global Constraints

- Preserve all host-status, availability-evidence, active-probe, manual/scheduled, and force-monitor semantics.
- A host-list GET only reads SQLite state and never starts a probe, collector, SNMP/MikroTik call, or reconciliation.
- Use SQLite only; do not add a service or increase the timeout.
- Publish snapshots atomically and retain the prior complete snapshot after a refresh error.
- Keep hosts in public responses, default to page 1 / 100 rows, and cap limit at 250.
- Do not log secrets, credentials, or raw private configuration.

---

### Task 1: Add projection regression tests

Files:
- Modify: tests/test_netctl_availability.py
- Modify: tests/test_netctl_cli.py
- Modify: tests/test_web_network_observer.py

Interfaces:
- Consumes: project_host_availability(conn, host, now), query_hosts(conn, ...).
- Produces: synthetic fixture and SQL-trace assertions consumed by Task 2.

- [ ] Step 1: Write failing legacy-equivalence and SQL-complexity tests.

~~~python
def test_bulk_projection_matches_legacy_for_every_status(conn, seeded_hosts):
    expected = [project_host_availability(conn, host, now=NOW) for host in seeded_hosts]
    assert bulk_project_host_availability(conn, seeded_hosts, now=NOW) == expected

def test_bulk_projection_uses_bounded_sql_for_large_host_list(conn, large_host_fixture):
    statements = []
    conn.set_trace_callback(statements.append)
    bulk_project_host_availability(conn, large_host_fixture, now=NOW)
    assert len(statements) < 80
~~~

The fixture contains 1200 hosts, 2000 FDB entries, 300 bridge entries, ARP/DHCP evidence, manual/scheduled results, failed/stale/missing runs, and force-monitor states.

- [ ] Step 2: Run pytest tests/test_netctl_availability.py -q -k bulk_projection.
Expected: FAIL because bulk_project_host_availability is absent.

- [ ] Step 3: Run pytest tests/test_netctl_availability.py -q -k "unmonitored_host or dashboard_includes_availability".
Expected: PASS.

- [ ] Step 4: Commit the test-only baseline.

~~~bash
git add tests/test_netctl_availability.py tests/test_netctl_cli.py tests/test_web_network_observer.py
git commit -m "test(network): add host projection regressions"
~~~

### Task 2: Implement bounded batch availability projection

Files:
- Modify: netctl/availability.py
- Modify: netctl/store.py
- Modify: netctl/migrations.py
- Modify: tests/test_netctl_availability.py
- Modify: tests/test_netctl_cli.py

Interfaces:
- Consumes: Task 1 fixtures and effective SegmentRule values.
- Produces: bulk_project_host_availability(conn, hosts, *, now) -> list[dict[str, Any]] for Tasks 3 and 4.

- [ ] Step 1: Confirm the Task 1 RED state with pytest tests/test_netctl_availability.py -q -k bulk_projection.

- [ ] Step 2: Add a bulk context and a no-SQL per-host projection.

~~~python
def bulk_project_host_availability(conn, hosts, *, now):
    context = AvailabilityProjectionContext.load(conn, hosts, now=now)
    return [project_host_from_context(host, context, now=context.now) for host in hosts]
~~~

AvailabilityProjectionContext.load reads each evidence table once, or using fixed 400-value chunks, maps normalized IP/MAC data, and loads rules/manual/run/result/force-monitor state. project_host_from_context executes no SQL.

- [ ] Step 3: Route query_hosts, inspect_host, and dashboard_summary through bulk_project_host_availability.

- [ ] Step 4: Add migrations for these query-backed indexes.

~~~sql
CREATE INDEX arp_entries_ip_idx ON arp_entries(ip);
CREATE INDEX dhcp_leases_ip_idx ON dhcp_leases(ip);
CREATE INDEX bridge_hosts_mac_idx ON bridge_hosts(mac);
CREATE INDEX current_switch_fdb_mac_idx ON current_switch_fdb(mac);
CREATE INDEX availability_manual_results_segment_ip_checked_idx
  ON availability_manual_results(segment_id, ip, checked_at DESC, id DESC);
CREATE INDEX availability_results_cidr_ip_run_idx ON availability_results(cidr, ip, run_id);
~~~

- [ ] Step 5: Run pytest tests/test_netctl_availability.py tests/test_netctl_cli.py -q.
Expected: PASS and bounded SQL statements.

- [ ] Step 6: Commit.

~~~bash
git add netctl/availability.py netctl/store.py netctl/migrations.py tests/test_netctl_availability.py tests/test_netctl_cli.py
git commit -m "perf(network): batch host availability projection"
~~~

### Task 3: Build and atomically publish persistent host snapshots

Files:
- Create: netctl/host_snapshot.py
- Modify: netctl/migrations.py
- Modify: netctl/cli.py
- Create: tests/test_netctl_host_snapshot.py
- Modify: tests/test_netctl_cli.py

Interfaces:
- Consumes: Task 2 bulk projection.
- Produces: refresh_host_snapshot(conn, *, now), snapshot_status(conn), and list_host_snapshot(conn, filters, page, limit).

- [ ] Step 1: Write failing publication and failure-preservation tests.

~~~python
def test_refresh_publishes_complete_replacement_snapshot(conn):
    first = refresh_host_snapshot(conn, now=NOW)
    second = refresh_host_snapshot(conn, now=LATER)
    assert second.snapshot_id == first.snapshot_id + 1

def test_failed_snapshot_publication_preserves_previous_rows(conn, monkeypatch):
    previous = refresh_host_snapshot(conn, now=NOW)
    monkeypatch.setattr(host_snapshot, "_insert_snapshot_rows", raise_write_error)
    with pytest.raises(sqlite3.Error):
        refresh_host_snapshot(conn, now=LATER)
    assert snapshot_status(conn).snapshot_id == previous.snapshot_id
~~~

- [ ] Step 2: Run pytest tests/test_netctl_host_snapshot.py -q.
Expected: FAIL because snapshot module/schema do not exist.

- [ ] Step 3: Add one migration with network_host_snapshot_meta, network_host_current_state, and network_host_current_sources. Store snapshot_id, ip, numeric ip_sort, category, status, network, hostname/MAC flags, last_seen_at, public payload JSON, and sources. Add snapshot/filter and snapshot/source indexes.

- [ ] Step 4: Implement build-before-transaction and atomic replacement.

~~~python
snapshot = build_host_snapshot(conn, now=now)
with conn:
    delete_current_snapshot_rows(conn)
    insert_snapshot_rows(conn, snapshot)
    replace_snapshot_metadata(conn, snapshot.metadata)
~~~

Build all payload before replacement. Roll back on an insertion error and log host_snapshot.refresh.start, host_snapshot.refresh.finish, or host_snapshot.refresh.error with id/count/duration only.

- [ ] Step 5: Add hosts snapshot-refresh and hosts snapshot-status CLI subcommands. Refresh after successful collect all --reconcile, standalone reconcile, and complete availability collection. Add a bounded OpenVPN overlay during snapshot construction.

- [ ] Step 6: Run pytest tests/test_netctl_host_snapshot.py tests/test_netctl_cli.py tests/test_deploy_netctl.py -q.
Expected: PASS.

- [ ] Step 7: Commit.

~~~bash
git add netctl/host_snapshot.py netctl/migrations.py netctl/cli.py tests/test_netctl_host_snapshot.py tests/test_netctl_cli.py
git commit -m "feat(network): add persistent host snapshot"
~~~

### Task 4: Serve snapshot pages through CLI, API, and SQLite filters

Files:
- Modify: netctl/cli.py
- Modify: app/api.py
- Modify: app/main.py
- Modify: tests/test_netctl_host_snapshot.py
- Modify: tests/test_api_routes.py
- Modify: tests/test_web_network_observer.py

Interfaces:
- Consumes: Task 3 snapshot APIs.
- Produces: paginated hosts, pagination, and snapshot responses plus lightweight metadata reads.

- [ ] Step 1: Write failing API/CLI contracts.

~~~python
def test_hosts_list_filters_before_payload_deserialization_and_paginates(client):
    data = client.get("/api/v1/network/hosts?status=current&page=2&limit=100").json()["data"]
    assert data["pagination"]["page"] == 2
    assert len(data["hosts"]) == 100

def test_hosts_meta_does_not_call_projection_or_vpn_list(client, monkeypatch):
    monkeypatch.setattr(api, "call_netctl", fail_if_called)
    assert client.get("/api/v1/network/hosts/meta").status_code == 200
~~~

- [ ] Step 2: Run pytest tests/test_api_routes.py tests/test_web_network_observer.py -q -k "hosts_meta or paginat".
Expected: FAIL because snapshot contracts are absent.

- [ ] Step 3: Implement q, category, status, source, network, hostname, MAC, stable ip_sort/ip ordering, and LIMIT/OFFSET inside snapshot SQL before JSON decode. current means online/seen/connected; clamp page >= 1 and limit to 1..250.

- [ ] Step 4: Replace list request paths with snapshot reads and response metadata. Remove full-list vpnctl connected/list merges from list paths; keep single-host detail behavior separately.

- [ ] Step 5: Run pytest tests/test_api_routes.py tests/test_web_network_observer.py -q.
Expected: PASS.

- [ ] Step 6: Commit.

~~~bash
git add netctl/cli.py app/api.py app/main.py tests/test_netctl_host_snapshot.py tests/test_api_routes.py tests/test_web_network_observer.py
git commit -m "feat(network): serve paginated hosts from snapshot"
~~~

### Task 5: Add progressive browser refresh

Files:
- Modify: app/templates/network_hosts.html
- Create: app/static/network-hosts-refresh.js
- Modify: app/main.py
- Modify: tests/test_web_network_observer.py

Interfaces:
- Consumes: Task 4 metadata and paginated list JSON.
- Produces: initial snapshot timestamp/count and a safe 15-second page updater.

- [ ] Step 1: Write a failing browser-contract test.

~~~python
def test_hosts_page_progressively_fetches_only_when_snapshot_changes():
    script = (BASE_DIR / "app/static/network-hosts-refresh.js").read_text()
    assert "AbortController" in script
    assert "/api/v1/network/hosts/meta" in script
    assert "window.location.reload" not in script
~~~

- [ ] Step 2: Run pytest tests/test_web_network_observer.py -q -k progressively_fetches.
Expected: FAIL because the script does not exist.

- [ ] Step 3: Render snapshot metadata and write the poller.

~~~javascript
if (nextMeta.snapshot_id !== currentSnapshotId) {
  controller?.abort();
  controller = new AbortController();
  const response = await fetch(currentListUrl(), {signal: controller.signal, credentials: "same-origin"});
  if (response.ok && requestSequence === sequence) replaceRows(await response.json());
}
~~~

Poll every 15 seconds, preserve query filters/page, retain rendered rows after an error, show a compact warning, and continue the next cycle.

- [ ] Step 4: Run pytest tests/test_web_network_observer.py -q and node --check app/static/network-hosts-refresh.js.
Expected: PASS.

- [ ] Step 5: Commit.

~~~bash
git add app/templates/network_hosts.html app/static/network-hosts-refresh.js app/main.py tests/test_web_network_observer.py
git commit -m "feat(network): refresh host snapshots progressively"
~~~

### Task 6: Verify, document, publish, and deploy safely

Files:
- Modify: README.md
- Create: docs/verification/2026-09-07-network-host-snapshot.md
- Modify: tests/test_netctl_host_snapshot.py

Interfaces:
- Consumes: Tasks 1–5 code and measurements.
- Produces: final verification record and production deployment.

- [ ] Step 1: Write a failing observability test.

~~~python
def test_snapshot_logs_include_non_sensitive_measurements(caplog, conn):
    refresh_host_snapshot(conn, now=NOW)
    assert any("host_snapshot.refresh.finish" in record.message for record in caplog.records)
~~~

- [ ] Step 2: Run pytest tests/test_netctl_host_snapshot.py -q -k logs_include. Add snapshot/list logs with id, counts, page, and duration until it passes.

- [ ] Step 3: Run all verification.

~~~bash
pytest tests/test_netctl_availability.py tests/test_netctl_cli.py tests/test_api_routes.py tests/test_web_network_observer.py tests/test_ui_snapshot_cache.py tests/test_netctl_host_snapshot.py -v
pytest -q
python -m compileall -q app netctl
node --check app/static/network-hosts-refresh.js
git diff --check
~~~

Expected: all commands exit 0.

- [ ] Step 4: Record statement counts before/after, local test results, and non-secret production measurements.

- [ ] Step 5: Review and commit final task files.

~~~bash
git status --short
git diff --check
git add README.md docs/verification/2026-09-07-network-host-snapshot.md tests/test_netctl_host_snapshot.py
git commit -m "test(network): verify host snapshot architecture"
~~~

- [ ] Step 6: Push main, deploy, and smoke test.

~~~bash
git push origin main
ssh ui-vpn-deploy "cd /opt/openvpn-web && sudo /usr/local/sbin/install-openvpn-web"
ssh ui-vpn-deploy "sudo -u netctl /usr/local/sbin/netctl --json hosts snapshot-refresh"
ssh ui-vpn-deploy "sudo -u netctl /usr/local/sbin/netctl --json hosts snapshot-status"
ssh ui-vpn-deploy "curl --noproxy '*' -fsS --max-time 5 http://127.0.0.1:8088/api/v1/network/hosts/meta"
~~~

Expected: non-empty snapshot, active openvpn-web, HTTP success in five seconds, and no new netctl timeout log.
