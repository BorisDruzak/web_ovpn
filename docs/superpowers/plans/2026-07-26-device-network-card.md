# Device Network Card Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use `superpowers:subagent-driven-development` (recommended) or `superpowers:executing-plans` to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Add an accurate, read-only device network card that shows the best known switch/port attachment and keep the underlying collection history bounded to 30 days.

**Architecture:** Reuse Netctl's existing runtime assets, current switch FDB, topology and attachment resolution as the single source for both API and HTML. A complete collection atomically follows with topology and attachment reconciliation under one `CollectLock`; a separate recovery timer runs the same composite reconciliation safely. A daily retention command removes only expired historical rows while protecting current-state references and the newest successful run per source/type.

**Tech Stack:** Python 3.12, FastAPI/Jinja2, SQLite/WAL, systemd, pytest.

## Global Constraints

- This release is strictly read-only for routers, switches, OpenVPN, DNS, DHCP and firewall configuration.
- Preserve the existing attachment states: `confirmed`, `ambiguous`, `uplink_only`, `unresolved`; never select an ambiguous port in the UI.
- The primary reconciliation trigger is only a fully successful `netctl collect all --reconcile`; SNMP `partial` remains an acceptable per-source result, but any failed source makes the aggregate collection fail and skips the primary reconciliation.
- Preserve the recovery `netctl-reconcile.timer`, but execute topology and attachments in one locked command.
- Retain operational history for exactly 30 days; do not remove current state or the most recent successful run required to interpret it.
- Daily cleanup must not run `VACUUM`; reclaiming the existing 3.54 GB database is a separate, operator-approved maintenance procedure.
- New web/API output must not expose credentials, raw SNMP payloads, firewall state, source secret references, or internal SQLite errors.
- Keep all response collections bounded and deterministically ordered.

---

## File Structure

| Path | Responsibility |
|---|---|
| `netctl/context_query.py` | Compose safe, human-readable attachment, port-peer, history and freshness data from current Netctl state. |
| `netctl/cli.py` | Provide atomic collection/reconciliation and retention CLI contracts. |
| `netctl/retention.py` | Compute and apply the FK-safe 30-day cleanup policy. |
| `netctl/topology_reconcile.py`, `netctl/attachment_reconcile.py` | Accept and persist one shared source watermark for a composite reconciliation. |
| `app/main.py` | Resolve a selected runtime asset and render an authenticated HTML asset card. |
| `app/templates/network_asset_detail.html` | Render the device identity, attachment state, port peers, path, freshness and history. |
| `app/templates/network_hosts.html` | Link known asset keys to the asset card while retaining IP/VPN fallback behaviour. |
| `deploy/netctl-*.service`, `deploy/netctl-*.timer` | Run collection+reconciliation and daily retention under systemd. |
| `deploy/install-openvpn-web.sh` | Install and enable the three Netctl timers. |
| `docs/runbooks/netctl-retention-compact.md` | One-time, backup-first database compaction and rollback procedure. |
| `tests/test_netctl_context_query.py`, `tests/test_context_api.py`, `tests/test_web_network_observer.py` | Context payload, authenticated API and HTML behaviour. |
| `tests/test_netctl_cli.py`, `tests/test_netctl_retention.py`, `tests/test_deploy_netctl_retention.py` | CLI ordering/locking, cleanup safety, and systemd/deployment contracts. |

## Task 1: Enrich the read-only asset context

**Files:**

- Modify: `netctl/context_query.py:57-190`
- Modify: `tests/test_netctl_context_query.py`
- Modify: `tests/test_context_api.py`

**Interfaces:**

- Consumes: current `asset_attachment_resolutions`, `network_sources`, `switch_ports`, `current_switch_fdb`, `current_switch_vlan_memberships`, `asset_interfaces`, `current_switch_links`, and `asset_attachment_events`.
- Produces: `inspect_asset_context(conn, asset_key) -> dict[str, Any] | None` whose existing keys remain stable and whose `attachment`, each `interfaces[].attachment`, `topology_path`, and `freshness` are presentation-safe.
- Produces: `_port_peers(conn, asset_id, source_id, port_key, limit=32) -> dict[str, Any]` with `items`, `known_asset_count`, `unknown_mac_count`, and `truncated`.

- [ ] **Step 1: Write failing context-query tests for a confirmed attachment**

  Extend the fixture with one access-switch source, a selected `physical:7`
  port, VLAN membership, the queried asset's FDB row, one FDB row that maps to
  another runtime asset, and one unmapped FDB MAC. Add this expectation:

  ```python
  context = inspect_asset_context(conn, "mac:AA:BB:CC:DD:EE:01")

  assert context["attachment"]["status"] == "confirmed"
  assert context["attachment"]["switch"] == {
      "id": 10, "name": "access-a", "site": "central", "host": "192.0.2.10",
  }
  assert context["attachment"]["port"]["alias"] == "Office 12"
  assert context["attachment"]["port"]["oper_status"] == "up"
  assert context["attachment"]["vlan_membership"] == {
      "vlan_id": 20, "egress": True, "untagged": True, "pvid": True,
  }
  assert context["attachment"]["port_peers"]["known_asset_count"] == 1
  assert context["attachment"]["port_peers"]["unknown_mac_count"] == 1
  assert context["attachment"]["port_peers"]["items"][0]["asset"]["asset_key"] == "mac:AA:BB:CC:DD:EE:02"
  ```

- [ ] **Step 2: Run the focused test to verify it fails**

  Run: `python -m pytest tests/test_netctl_context_query.py -k confirmed_attachment -q`

  Expected: FAIL because the context attachment has no `switch`, `port`,
  `vlan_membership`, or `port_peers` fields.

- [ ] **Step 3: Add safe attachment projection helpers**

  In `netctl/context_query.py`, replace the bare resolution projection with a
  helper that preserves all current `selected_*` fields and adds joined display
  fields. Use `LEFT JOIN` so unavailable switch or port metadata yields empty
  safe values rather than dropping the attachment.

  ```python
  def _attachment(conn: sqlite3.Connection, asset_id: int, asset_interface_id: int | None = None) -> dict[str, Any] | None:
      # Query selected_* exactly as today plus source name/site/host and port metadata.
      # Add switch, port and vlan_membership only when selected_source_id and port_key exist.
      # Call _port_peers only when status == "confirmed".
      ...

  def _port_peers(
      conn: sqlite3.Connection, asset_id: int, source_id: int, port_key: str, limit: int = 32,
  ) -> dict[str, Any]:
      if not 1 <= limit <= 32:
          raise ValueError("port peer limit must be between 1 and 32")
      # Read current FDB only, exclude asset_id and self/mgmt rows, join known MAC interfaces/assets.
      # Return at most limit named items and aggregate any remaining unmapped MACs.
      ...
  ```

  Use `normalize_mac()` for every MAC comparison. Order peers by known-asset
  first, then display name, MAC, VLAN key. Do not return `evidence_json` or
  raw FDB payloads.

- [ ] **Step 4: Add failing tests for uncertainty and bounded peers**

  Add tests that assert:

  ```python
  assert ambiguous["attachment"]["port"] is None
  assert ambiguous["attachment"]["port_peers"] is None
  assert uplink_only["attachment"]["switch"] is None
  assert unresolved["attachment"]["alternatives"] == []
  assert len(confirmed["attachment"]["port_peers"]["items"]) == 32
  assert confirmed["attachment"]["port_peers"]["truncated"] is True
  ```

- [ ] **Step 5: Implement uncertainty-safe output and run the context tests**

  Return `None` for selected switch/port/VLAN/peer fields unless the
  attachment state is `confirmed`. Preserve alternatives for `ambiguous` and
  `uplink_only`, ordered by score exactly as current code does.

  Run: `python -m pytest tests/test_netctl_context_query.py -q`

  Expected: PASS.

- [ ] **Step 6: Add readable path, attachment history and freshness tests**

  Add a topology fixture with two links and events within/outside the 30-day
  cutoff. Assert that the old compatibility `nodes` list remains available and
  new fields are safe and named:

  ```python
  assert context["topology_path"]["nodes"] == [10, 20, 30]
  assert context["topology_path"]["hops"][0]["from"]["name"] == "access-a"
  assert context["topology_path"]["hops"][0]["to"]["name"] == "distribution-a"
  assert len(context["attachment_events"]) == 1
  assert context["freshness"]["attachment_reconciled_at"] == "2026-07-26T10:05:00Z"
  ```

- [ ] **Step 7: Implement edge-aware paths, safe event projection and freshness**

  Change `_topology_path()` to retain each traversed
  `current_switch_links` edge during BFS and return bounded `hops` containing
  source id/name/site and local/remote port key/name, plus state/confidence.
  Add `_attachment_events()` that reads no more than 30 events where
  `observed_at >= utc_now() - timedelta(days=30)`, decodes only `before_json`
  and `after_json` into the public selected source/port/VLAN/confidence fields.
  Add a top-level `freshness` object that reads the latest successful topology
  and attachment run timestamps and their `source_watermark_json`.

- [ ] **Step 8: Verify API compatibility and commit**

  Update the fake Netctl asset response in `tests/test_context_api.py` and
  assert `GET /api/v1/context/assets/{asset_key}` still returns the enriched
  context under `data.context`, with the existing ETag/snapshot envelope.

  Run: `python -m pytest tests/test_netctl_context_query.py tests/test_context_api.py -q`

  Expected: PASS.

  ```bash
  git add netctl/context_query.py tests/test_netctl_context_query.py tests/test_context_api.py
  git commit -m "feat: enrich device network context"
  ```

## Task 2: Add the authenticated asset-card web flow

**Files:**

- Modify: `app/main.py:1519-1570`
- Modify: `app/templates/network_hosts.html`
- Modify: `app/templates/network_host_detail.html`
- Create: `app/templates/network_asset_detail.html`
- Modify: `tests/test_web_network_observer.py`
- Modify: `tests/test_routes_smoke.py`

**Interfaces:**

- Consumes: `context-view search --query <exact-value> --limit 25` and `context-view asset --asset-key <key>` through `net_cli_call`.
- Produces: `GET /network/assets/{asset_key}` requiring the existing session login.
- Produces: an asset-card template consuming `{context, error}` without raw JSON output.

- [ ] **Step 1: Write failing HTML route and link tests**

  Extend the fake Netctl executable in `tests/test_web_network_observer.py` to
  respond to the two context commands. Add tests:

  ```python
  page = client.get("/network/hosts?q=desktop")
  assert 'href="/network/assets/mac:AA:BB:CC:DD:EE:01"' in page.text

  asset_page = client.get("/network/assets/mac:AA:BB:CC:DD:EE:01")
  assert asset_page.status_code == 200
  assert "access-a" in asset_page.text
  assert "Office 12" in asset_page.text
  assert "VLAN 20" in asset_page.text
  assert "Подтверждено" in asset_page.text
  assert "AA:BB:CC:DD:EE:02" in asset_page.text
  ```

- [ ] **Step 2: Run the focused HTML tests to verify failure**

  Run: `python -m pytest tests/test_web_network_observer.py -k "asset or network_hosts" -q`

  Expected: FAIL with a missing asset route and no asset-card link.

- [ ] **Step 3: Implement asset key validation and web route**

  In `app/main.py`, add a narrow validator that accepts only non-empty runtime
  asset keys with a maximum length of 255 and rejects path separators. Add the
  route below; it must call `require_user()` before Netctl.

  ```python
  @app.get("/network/assets/{asset_key}", response_class=HTMLResponse)
  def network_asset_detail(asset_key: str, request: Request, db: Session = Depends(get_db)):
      require_user(request, db)
      valid_asset_key = validate_runtime_asset_key(asset_key)
      data, error = net_cli_call(request, ["context-view", "asset", "--asset-key", valid_asset_key])
      return render(request, "network_asset_detail.html", {
          "asset_key": valid_asset_key,
          "context": data.get("context") or {},
          "error": error,
      }, db)
  ```

  Treat a missing context as an empty-state card with a clear message; do not
  fall back to a different asset.

- [ ] **Step 4: Link known assets without breaking IP/VPN fallback**

  In `network_hosts.html`, link only a valid `host.device_key` beginning with
  `mac:` or `legacy-host:` to `/network/assets/...`. Keep the current
  `/network/hosts/{ip}` link for IP-only and VPN-only rows. Keep the existing
  fuzzy list search unchanged. Do not redirect an IP to an asset based solely
  on an exact context search because one IP can match multiple assets.

- [ ] **Step 5: Build the card template for every attachment state**

  Create `network_asset_detail.html` with distinct panels for identity,
  freshness, confirmed attachment, alternatives, path and 30-day history.
  Render peers with the title `MAC-адреса, выученные на этом порту` and this
  fixed warning:

  ```text
  Несколько MAC на одном порту не доказывают физическое подключение каждого устройства:
  это может быть точка доступа, IP-телефон, downstream-коммутатор или trunk.
  ```

  For `ambiguous`, `uplink_only`, and `unresolved`, render status/reason and
  alternatives only; never render an invented selected port or peer list.
  Remove the raw JSON section from the asset template. Keep the legacy
  IP-detail raw JSON unchanged in `network_host_detail.html` for this release.

- [ ] **Step 6: Add negative and stale-state tests**

  Add assertions for unauthenticated redirect, unknown asset key, ambiguous
  card without port peers, and stale/recovery freshness text. Add the new route
  to `tests/test_routes_smoke.py` if that suite enumerates authenticated pages.

- [ ] **Step 7: Run web and API regression tests and commit**

  Run: `python -m pytest tests/test_web_network_observer.py tests/test_routes_smoke.py tests/test_context_api.py -q`

  Expected: PASS.

  ```bash
  git add app/main.py app/templates/network_hosts.html app/templates/network_asset_detail.html \
      tests/test_web_network_observer.py tests/test_routes_smoke.py
  git commit -m "feat: add device network card"
  ```

## Task 3: Make collection and reconciliation one locked boundary

**Files:**

- Modify: `netctl/cli.py:387-412, 571-640, 1320-1490`
- Modify: `netctl/topology_reconcile.py`
- Modify: `netctl/attachment_reconcile.py`
- Modify: `tests/test_netctl_cli.py`
- Modify: `tests/test_netctl_topology.py`
- Modify: `tests/test_netctl_attachments.py`

**Interfaces:**

- Produces: `netctl --json collect all --reconcile`.
- Produces: `netctl --json reconcile` for recovery/manual reconciliation.
- Produces: `collection_source_watermark(conn) -> dict[str, object]` containing only source id/name, collection status/time, and latest switch-run id.
- Changes: `reconcile_topology(conn, observed_at, source_watermark)` and `reconcile_attachments(conn, observed_at, source_watermark)` persist the supplied watermark in their run records.

- [ ] **Step 1: Write failing collection-order tests**

  In `tests/test_netctl_cli.py`, mock `collect_one`, `reconcile_topology`, and
  `reconcile_attachments`. Add tests with an ordered call list:

  ```python
  rc, payload = dispatch(parser.parse_args(["collect", "all", "--reconcile"]))

  assert rc == 0
  assert calls == ["collect:router", "collect:switch", "topology", "attachments"]
  assert payload["reconciliation"]["attachment_run_id"] == 22
  ```

  Add a failed-source case asserting `rc == 1`, both reconciliation mocks are
  absent, and the result has `reconciliation_skipped == "collection_failed"`.
  Add a `partial` SNMP result case asserting reconciliation still runs.

- [ ] **Step 2: Run collection-order tests to verify failure**

  Run: `python -m pytest tests/test_netctl_cli.py -k "collect.*reconcile or reconciliation" -q`

  Expected: FAIL because `collect` has no `--reconcile` option and no composite command.

- [ ] **Step 3: Refactor collection and composite reconciliation helpers**

  Add helpers that never acquire the same lock twice:

  ```python
  def collect_all_locked(conn: sqlite3.Connection, args: argparse.Namespace) -> tuple[int, list[dict[str, Any]]]:
      ...

  def collection_source_watermark(conn: sqlite3.Connection) -> dict[str, object]:
      # Deterministically ordered, safe source status/time/run identifiers only.
      ...

  def reconcile_current_locked(conn: sqlite3.Connection, observed_at: str) -> dict[str, Any]:
      watermark = collection_source_watermark(conn)
      topology = reconcile_topology(conn, observed_at, watermark)
      attachments = reconcile_attachments(conn, observed_at, watermark)
      return {"topology_run_id": topology["run_id"], "attachment_run_id": attachments["run_id"], "source_watermark": watermark}
  ```

  Make `cmd_collect()` hold one `CollectLock`; when `args.source == "all"`
  and `args.reconcile` is true, call `reconcile_current_locked()` only when all
  enabled sources returned zero. Add `cmd_reconcile()` that obtains one
  `CollectLock` and calls the same helper. Keep `topology reconcile` and
  `attachments reconcile` backward-compatible for diagnostics.

- [ ] **Step 4: Persist one source watermark in both correlation runs**

  Change the two reconciliation function signatures to accept
  `source_watermark: dict[str, object]`. Serialize it with stable JSON when
  creating `network_correlation_runs`; never include source credentials or
  options. Update all direct callers/tests with `{}` when no collection
  boundary exists.

- [ ] **Step 5: Add lock and failure-preservation tests**

  Add a test that a concurrent `cmd_reconcile()` receives the existing
  `collection already running` error while the collection lock is held. Keep
  the existing topology/attachment failure-preservation tests and add:

  ```python
  assert before_links == after_links
  assert before_resolutions == after_resolutions
  assert latest_failed_run["status"] == "failed"
  ```

- [ ] **Step 6: Run the Netctl collection/correlation suite and commit**

  Run: `python -m pytest tests/test_netctl_cli.py tests/test_netctl_topology.py tests/test_netctl_attachments.py tests/test_netctl_context_query.py -q`

  Expected: PASS.

  ```bash
  git add netctl/cli.py netctl/topology_reconcile.py netctl/attachment_reconcile.py \
      tests/test_netctl_cli.py tests/test_netctl_topology.py tests/test_netctl_attachments.py
  git commit -m "feat: reconcile attachments after complete collection"
  ```

## Task 4: Deploy the composite collection and recovery services

**Files:**

- Modify: `deploy/netctl-collect.service`
- Modify: `deploy/netctl-reconcile.service`
- Modify: `deploy/install-openvpn-web.sh:250-265`
- Modify: `tests/test_deploy_netctl.py`
- Modify: `tests/test_netctl_reconcile_units.py`

**Interfaces:**

- `netctl-collect.service` executes `/usr/local/sbin/netctl --json collect all --reconcile`.
- `netctl-reconcile.service` executes exactly `/usr/local/sbin/netctl --json reconcile`.
- The installer installs and enables both `netctl-collect.timer` and `netctl-reconcile.timer` after `daemon-reload`.

- [ ] **Step 1: Write failing unit-file tests**

  Add assertions that prevent returning to two separate reconcile operations:

  ```python
  assert "ExecStart=/usr/local/sbin/netctl --json collect all --reconcile" in collect_service
  assert reconcile_service.count("ExecStart=") == 1
  assert "ExecStart=/usr/local/sbin/netctl --json reconcile" in reconcile_service
  assert "netctl-collect.timer" in installer_enable_commands
  assert "netctl-reconcile.timer" in installer_enable_commands
  ```

- [ ] **Step 2: Run deployment-unit tests to verify failure**

  Run: `python -m pytest tests/test_netctl_reconcile_units.py tests/test_deploy_netctl.py -q`

  Expected: FAIL because collect has no `--reconcile`, reconciliation has two
  `ExecStart` lines, and the installer does not enable collection.

- [ ] **Step 3: Update units and installer**

  Keep all existing service hardening directives (`User`, `Group`,
  `NoNewPrivileges`, `PrivateTmp`, `ProtectHome`). Do not change the recovery
  timer cadence in this release. In the installer, enable both timers only
  after copying units and `systemctl daemon-reload`; the enabled reconciliation
  timer is a recovery backstop, while the collect service is the primary
  trigger.

- [ ] **Step 4: Run unit/deployment tests and commit**

  Run: `python -m pytest tests/test_netctl_reconcile_units.py tests/test_deploy_netctl.py -q`

  Expected: PASS.

  ```bash
  git add deploy/netctl-collect.service deploy/netctl-reconcile.service deploy/install-openvpn-web.sh \
      tests/test_netctl_reconcile_units.py tests/test_deploy_netctl.py
  git commit -m "fix: run netctl reconciliation after collection"
  ```

## Task 5: Implement FK-safe 30-day retention

**Files:**

- Create: `netctl/retention.py`
- Modify: `netctl/cli.py`
- Create: `tests/test_netctl_retention.py`
- Modify: `tests/test_netctl_cli.py`

**Interfaces:**

- Produces: `retention_report(conn, cutoff: str) -> dict[str, int]` with deterministic per-table candidate counts and no writes.
- Produces: `apply_retention(conn, cutoff: str) -> dict[str, int]`, called under `CollectLock` and one `BEGIN IMMEDIATE` transaction.
- Produces: `netctl --json retention cleanup [--days 30] [--apply]` where dry-run is the default and `--days` accepts only 30 for this release.

- [ ] **Step 1: Write a complete retention fixture and dry-run tests**

  In `tests/test_netctl_retention.py`, create current and expired rows for
  every deletion family. Reference an old run from `switch_ports`,
  `current_switch_fdb`, `current_switch_links`, attachment resolution and
  candidates. Include a newer run and a last-successful old run with no
  current reference. Assert dry-run has no side effects:

  ```python
  report = retention_report(conn, "2026-06-26T00:00:00Z")
  assert report["delete"]["host_observations"] == 2
  assert report["keep"]["switch_collection_runs_current_reference"] == 1
  assert report["keep"]["switch_collection_runs_last_success"] == 1
  assert conn.execute("SELECT count(*) FROM host_observations").fetchone()[0] == 2
  ```

- [ ] **Step 2: Run the dry-run test to verify failure**

  Run: `python -m pytest tests/test_netctl_retention.py -k dry_run -q`

  Expected: FAIL because the retention module and command do not exist.

- [ ] **Step 3: Define the retention protection queries**

  In `netctl/retention.py`, make protected run-id sets explicit before any
  deletion:

  ```python
  def protected_switch_run_ids(conn: sqlite3.Connection) -> set[int]:
      # Union collector_run_id from current switch ports/FDB/VLAN/LLDP and
      # latest success/partial run for every source.
      ...

  def protected_correlation_run_ids(conn: sqlite3.Connection) -> set[int]:
      # Union current link/candidate/resolution IDs and latest successful run
      # for topology and attachments.
      ...

  def protected_path_fact_run_ids(conn: sqlite3.Connection) -> set[int]:
      # Union current router fact collector ids and latest successful run/source.
      ...
  ```

  Use parameterized SQL only. Validate UTC timestamps with the existing time
  parser or a strict `datetime.fromisoformat` conversion; reject naive or
  invalid cutoffs.

- [ ] **Step 4: Write failing apply, rollback, and idempotency tests**

  Add tests asserting this deletion order and safety:

  ```python
  result = apply_retention(conn, "2026-06-26T00:00:00Z")
  assert result["deleted"]["switch_fdb_events"] == 1
  assert result["deleted"]["asset_attachment_events"] == 1
  assert current_fdb_run_id in ids(conn, "switch_collection_runs")
  assert current_attachment_run_id in ids(conn, "network_correlation_runs")
  assert apply_retention(conn, "2026-06-26T00:00:00Z")["total_deleted"] == 0
  ```

  Inject an exception after the first deletion statement and assert every
  table equals its pre-call snapshot after rollback.

- [ ] **Step 5: Implement one-transaction deletion in dependency order**

  Delete records older than cutoff in this exact order:

  1. `switch_fdb_events`, `switch_link_events`, `asset_attachment_events`;
  2. `host_observations`, `network_events`;
  3. only non-current `ip_observations` and `hostname_observations`;
  4. old `collection_runs`, retaining the latest successful run for each source;
  5. old unprotected `switch_collection_runs`;
  6. old unprotected `network_correlation_runs`;
  7. old unprotected `router_path_fact_runs`.

  Execute inside `BEGIN IMMEDIATE`; on any exception roll back and return a
  sanitized `retention_failed` error from the CLI. After successful apply,
  run `PRAGMA foreign_key_check` and `PRAGMA integrity_check`; reject the
  transaction if either result is not clean. Return counts and logical page
  metrics, not raw row contents. Do not issue `VACUUM`.

- [ ] **Step 6: Add the CLI contract and tests**

  Add parser contract:

  ```python
  retention = sub.add_parser("retention")
  retention_sub = retention.add_subparsers(dest="retention_command", required=True)
  cleanup = retention_sub.add_parser("cleanup")
  cleanup.add_argument("--days", type=int, default=30, choices=(30,))
  cleanup.add_argument("--apply", action="store_true")
  ```

  `cmd_retention()` acquires `CollectLock`, calculates cutoff from `utc_now()`,
  returns `dry_run: true` without mutation unless `--apply` is present, and
  returns `deleted`/`kept` aggregates after apply. Test invalid values,
  dry-run, apply, and no secret-containing output.

- [ ] **Step 7: Run retention and CLI tests and commit**

  Run: `python -m pytest tests/test_netctl_retention.py tests/test_netctl_cli.py -q`

  Expected: PASS.

  ```bash
  git add netctl/retention.py netctl/cli.py tests/test_netctl_retention.py tests/test_netctl_cli.py
  git commit -m "feat: retain netctl history for 30 days"
  ```

## Task 6: Schedule retention and document database compaction

**Files:**

- Create: `deploy/netctl-retention.service`
- Create: `deploy/netctl-retention.timer`
- Modify: `deploy/install-openvpn-web.sh`
- Create: `docs/runbooks/netctl-retention-compact.md`
- Create: `tests/test_deploy_netctl_retention.py`

**Interfaces:**

- `netctl-retention.service` runs `/usr/local/sbin/netctl --json retention cleanup --days 30 --apply` as `netctl`.
- `netctl-retention.timer` runs once daily at `03:17`, has `Persistent=true`, and is enabled by the installer.
- The runbook performs a manual, backup-first compaction only after normal retention has succeeded.

- [ ] **Step 1: Write failing deployment and documentation tests**

  Add tests that read the unit files and runbook text:

  ```python
  assert "User=netctl" in retention_service
  assert "NoNewPrivileges=true" in retention_service
  assert "retention cleanup --days 30 --apply" in retention_service
  assert "OnCalendar=*-*-* 03:17:00" in retention_timer
  assert "Persistent=true" in retention_timer
  assert "netctl-retention.timer" in installer
  assert "VACUUM" in runbook and "backup" in runbook and "rollback" in runbook
  ```

- [ ] **Step 2: Run deployment tests to verify failure**

  Run: `python -m pytest tests/test_deploy_netctl_retention.py -q`

  Expected: FAIL because no retention units or compaction runbook exist.

- [ ] **Step 3: Add hardened service/timer and installer support**

  Create the service with the same `User=netctl`, `Group=netctl`,
  `NoNewPrivileges=true`, `PrivateTmp=true`, and `ProtectHome=true` controls
  as the existing Netctl services. Create a daily persistent timer and install
  it beside the existing Netctl units. Enable it after daemon reload.

- [ ] **Step 4: Write the manual compaction runbook**

  The runbook must require these concrete stages:

  1. record timer states; disable collection/reconciliation/retention timers;
  2. wait until `CollectLock` is free; create `/var/backups/netctl` SQLite
     `.backup`; record SHA-256 and `PRAGMA integrity_check`;
  3. run `netctl --json retention cleanup --days 30` then the same command
     with `--apply`; verify aggregate counts and integrity;
  4. measure free disk space for a complete SQLite rewrite; run one controlled
     `VACUUM` only while services are stopped;
  5. restart services, run `collect all --reconcile`, verify the card/context,
     then restore prior timer states;
  6. rollback by stopping services, restoring the verified SQLite backup,
     checking integrity, and restoring original timers.

  The runbook must state that the procedure performs no network-device write.

- [ ] **Step 5: Run deployment/documentation tests and commit**

  Run: `python -m pytest tests/test_deploy_netctl_retention.py tests/test_deploy_netctl.py tests/test_netctl_reconcile_units.py -q`

  Expected: PASS.

  ```bash
  git add deploy/netctl-retention.service deploy/netctl-retention.timer deploy/install-openvpn-web.sh \
      docs/runbooks/netctl-retention-compact.md tests/test_deploy_netctl_retention.py
  git commit -m "ops: schedule netctl history retention"
  ```

## Task 7: Integrate, verify, and prepare safe deployment

**Files:**

- Modify: `README.md` only if it documents the Netctl service/timer inventory.
- Modify: `docs/DEPLOYMENT.md` only if it documents Network Observer operational checks.
- Create: `docs/verification/device-network-card-YYYY-MM-DD.md` during the verified deployment.

**Interfaces:**

- Consumes the tested code and systemd artifacts from Tasks 1-6.
- Produces a sanitized verification record containing aggregate statuses and no endpoint MACs, credentials, FDB rows, or raw observations.

- [ ] **Step 1: Run the full relevant test suite**

  Run:

  ```bash
  python -m pytest tests/test_netctl_context_query.py tests/test_context_api.py \
      tests/test_web_network_observer.py tests/test_routes_smoke.py \
      tests/test_netctl_cli.py tests/test_netctl_topology.py tests/test_netctl_attachments.py \
      tests/test_netctl_retention.py tests/test_deploy_netctl.py \
      tests/test_netctl_reconcile_units.py tests/test_deploy_netctl_retention.py -q
  ```

  Expected: PASS.

- [ ] **Step 2: Run static deployment safeguards**

  Run:

  ```bash
  git diff --check
  rg -n "(secret_ref|resolved_secret|password|community)" netctl/context_query.py app/templates/network_asset_detail.html
  ```

  Expected: whitespace check exits 0; the search produces no newly exposed
  sensitive fields in the context or template.

- [ ] **Step 3: Perform production deployment only when explicitly requested**

  Before deployment, use the read-only OpenVPN/Netctl diagnostics first and
  capture source health, timer states, attachment status, database backup
  integrity, and free disk space. Stop at any failed preflight; do not run
  collection, retention, timer enablement, or compaction without explicit
  deployment authorization.

- [ ] **Step 4: Verify the deployed copy after authorized deployment**

  Run the repository runbook steps in this exact operational order:

  ```text
  backup and integrity check → deploy code/units → daemon-reload →
  collect all --reconcile → topology/attachments status → device context/API smoke →
  enable collect/reconcile/retention timers → retention dry-run only
  ```

  Confirm the card identifies a known confirmed attachment, reports one
  unresolved device accurately, and exposes no raw FDB data. Do not run the
  manual `VACUUM` procedure as part of ordinary deployment.

- [ ] **Step 5: Record verification and commit documentation**

  Record only aggregate counts, timestamps, test commands, timer active
  states, backup integrity result, and sanitized card outcomes. Then commit
  only the verification record and any necessary documentation updates:

  ```bash
  git add docs/verification README.md docs/DEPLOYMENT.md
  git commit -m "docs: verify device network card rollout"
  ```

## Plan Self-Review

- **Spec coverage:** Task 1 provides safe attachment/peer/path/freshness data; Task 2 provides the search-to-card UI; Tasks 3-4 ensure post-collection current data and enable recovery; Tasks 5-6 implement exactly 30-day retention plus non-routine compaction; Task 7 supplies verification and rollback-aware deployment sequencing.
- **Completeness check:** every task names exact files, interfaces, concrete tests, commands, and commit boundaries; there are no deferred implementation markers.
- **Consistency check:** the same `confirmed`-only peer rule, `CollectLock` boundary, source watermark, 30-day cutoff and recovery timer behavior are used throughout the plan.

## Execution Handoff

This plan is intended for subagent-driven execution: one fresh implementer per task, followed by an independent test/review gate before starting the next task. Do not deploy to `192.168.100.30` until the user explicitly authorizes deployment after the local implementation and verification are complete.
