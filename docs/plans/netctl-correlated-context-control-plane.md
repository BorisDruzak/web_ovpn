# Netctl Correlated Network Context and Safe Control Plane Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Turn the existing intent, runtime identity, RouterOS and SNMP observations into one evidence-backed asset context API, then add an isolated and auditable control plane whose first bounded operation is asset-level Internet allow/deny.

**Architecture:** Keep `netctl` as the read-only facts, correlation and explanation backend. Materialize switch-to-switch links and endpoint attachments from imported intent, source identity, FDB and optional LLDP, expose one asset-centric query contract, and implement path explanation as a conservative tri-state evaluator. Device writes live in a separate, unprivileged `netopsctld` service behind a Unix socket; the web application can submit only enumerated change plans and cannot send arbitrary RouterOS or shell commands.

**Tech Stack:** Python 3.12, SQLite migrations, existing `netctl` collectors and runtime asset model, FastAPI HTTP API, pytest, systemd socket activation, RouterOS API-SSL and GitHub Actions.

**Mandatory amendment:** [`netctl-correlated-context-control-plane-security-amendment.md`](netctl-correlated-context-control-plane-security-amendment.md) is part of this plan. It defines the required broker trust boundary, stale-precondition checks, tamper-evident audit, API contract and migration rollout gates. Where it is more restrictive, the amendment takes precedence. No PR in this plan may enable a device write without meeting its applicable acceptance criteria.

## Global Constraints

- Start from `web_ovpn/main` commit `bc50c0ce1494ef48282f50a7d0df624235540cb0` or a later fast-forward `main` containing it.
- Netctl migrations `1` through `8` are immutable. New netctl schema starts at migration `9`.
- Preserve the existing separation of imported intent, runtime observations, correlations, findings and desired change state.
- IP addresses remain observations. No new table or API may use an IP address as the stable identity of an asset.
- Different MAC addresses are never merged into one asset automatically. Correlation may propose a candidate merge but cannot execute it.
- Imported `intent_assets` and runtime `assets` remain separate. A matching string ID is not a confirmed binding.
- Raw RouterOS, SNMP, firewall and routing observations are never rewritten by the correlation engine.
- Failed or stale collectors must not erase the last successful current state, topology edge or endpoint attachment.
- Every inferred edge and attachment carries evidence, confidence, first/last-seen time and resolution state.
- The automatic topology uses relational tables and deterministic graph algorithms. Do not introduce a graph database in this phase.
- The unified context and topology contracts are API-first. Do not make web-page redesign a prerequisite for backend acceptance.
- Path evaluation returns only `allowed`, `blocked` or `unknown`. Missing or unsupported evidence must produce `unknown`, never a guessed allow or deny.
- `netctl` performs no device writes. Network changes are handled only by the separate `netopsctld` broker.
- `netopsctld` accepts enumerated structured operations only. It must never accept arbitrary RouterOS paths, commands, shell strings or Python expressions from API callers.
- `netopsctld` runs as a dedicated `netopsctl` system user. It does not run as root and does not receive wildcard sudo.
- Network writes remain disabled until TLS, change-scoped authorization and durable audit logging are verified in production.
- The first write capability is asset-level Internet allow/deny through a dedicated MikroTik address list. Switch-port shutdown, VLAN changes, DHCP writes and DNS writes remain deferred.
- A user-level Internet policy is allowed only when the user has one active, confirmed, non-shared primary asset binding. Otherwise the operation is rejected.
- Every production migration and control-plane rollout requires a SQLite backup, integrity check, pre-check, post-check and rollback evidence.
- Tests use synthetic or sanitized fixtures and never contact live network devices.
- Existing OpenVPN, WireGuard, ViPNet and Network Observer behavior must remain operational throughout the work.

---

## 1. Current context and target acceptance story

### 1.1 Existing foundation

The repository already contains these usable models and observations:

```text
canonical context revisions and one active context head
versioned intent sites, locations, segments, assets, services and links
runtime assets and interfaces
current and historical IP and hostname observations
runtime identity findings
RouterOS interfaces, DHCP, ARP, bridge hosts, neighbors, routes and IPsec views
SNMP switch identity, ports, FDB, FDB events, VLAN membership, STP and optional LLDP
source health and collection-run history
```

The principal missing layer is correlation. The backend can independently know:

```text
runtime interface MAC AA:BB:CC:DD:EE:FF belongs to asset X
switch SNR port ge18 currently learns MAC AA:BB:CC:DD:EE:FF
```

but it does not yet publish the durable conclusion:

```text
asset X -> interface AA:BB:CC:DD:EE:FF -> SNR ge18 -> VLAN 1
```

It also does not yet explain the logical path from that asset to a destination or apply a bounded network policy.

### 1.2 Target operator story

The implementation is complete when this flow is possible through the API:

```text
1. Search by user, asset key, hostname, IP or MAC.
2. Receive exactly one asset or an explicit ambiguous result.
3. Inspect current interfaces, IPs, hostnames, intent identity and owner binding.
4. Inspect the selected switch, port, VLAN, topology path and evidence/confidence.
5. Explain the expected path to a destination IP/protocol/port.
6. See the routing table, selected route, firewall/NAT/IPsec evidence and verdict.
7. Create an Internet deny change plan for an eligible asset.
8. Review generated MikroTik address-list changes and pre-check evidence.
9. Explicitly approve and apply the plan.
10. Verify the post-condition and retain a deterministic rollback action.
```

### 1.3 Expected maturity after each delivery

```text
After PR 4C: complete read-only device card and topology API.
After PR 5C: evidence-backed path explanation.
After PR 6B: safe asset-level Internet allow/deny.
After PR 6C: eligible user-level policy resolution and session-ready model.
```

---

## 2. Fixed architectural decisions

### 2.1 Raw facts, correlations and desired state are different records

```text
raw observations:
  current_switch_fdb, switch_ports, asset_interfaces, ip_observations, routes

correlated conclusions:
  current_switch_links, asset_attachment_resolutions

desired state:
  desired_network_policies in netopsctl.sqlite

executed changes:
  immutable change plans and execution rows in netopsctl.sqlite
```

No correlation table is an input source for a collector. No desired-state record rewrites observation history.

### 2.2 Physical backbone is resolved before endpoint selection

Endpoint resolution depends on knowing which ports are uplinks. Build the switch/router backbone first from:

```text
imported intent links
known runtime and intent identity of each source
management MACs observed through FDB
optional LLDP neighbors
source topology role
```

Only then select the deepest non-uplink FDB candidate for an endpoint MAC.

### 2.3 Relational graph, not a graph database

Use explicit current-state and event tables. Query-time BFS/DFS operates on `current_switch_links`. The expected topology size is small enough for deterministic in-process graph traversal, and SQLite remains adequate.

### 2.4 Evidence and confidence are mandatory

Every current link and attachment stores:

```text
state
confidence 0..100
first_seen_at
last_seen_at
correlation_run_id
evidence_json
```

Confidence never replaces evidence. API consumers receive both.

### 2.5 Ambiguity is a valid result

The correlation engine preserves these states:

```text
confirmed    one sufficiently strong non-uplink candidate
ambiguous    multiple comparable candidates
uplink_only  MAC is visible only through known inter-switch/uplink ports
unresolved   no usable FDB candidate
conflicting  evidence sources disagree about a backbone link
```

It must not select a convenient candidate merely to make the card look complete.

### 2.6 User ownership and active session are different relations

```text
primary_user binding:
  long-lived administrative assignment of an asset

network_session:
  evidence that a user used an asset during a bounded time interval
```

A captive portal, directory login or endpoint agent may create session evidence later. It must not silently overwrite a primary ownership binding.

### 2.7 Path explanation is conservative

Initial path evaluation supports IPv4 and one forward direction through known RouterOS enforcement points. Unsupported matchers, missing tables, stale facts, multiple possible gateways or incomplete reverse-path evidence produce `unknown` with explicit reasons.

### 2.8 Control uses desired policy, not raw IP commands

The API request is:

```json
{
  "subject_type": "asset",
  "subject_key": "mac:AA:BB:CC:DD:EE:FF",
  "policy": "internet_access",
  "desired_state": "deny",
  "reason": "approved support request"
}
```

The broker resolves current IP observations and enforcement points itself. The API caller never supplies the address-list command.

### 2.9 Internet denial does not mean port shutdown

The first policy changes only traffic leaving through the configured WAN boundary. Internal DNS, AD, file shares, Directum, ViPNet and other internal routes are not intentionally blocked.

### 2.10 Failure behavior is fail-safe and explainable

```text
collector failure:
  retain last successful observations

correlation failure:
  retain last successful topology and attachments

control broker unavailable:
  retain current network-device state

identity stale during desired deny:
  retain last managed deny entries and raise policy_stale_identity

post-check failure:
  mark plan failed and expose rollback; do not claim success
```

---

## 3. Pull-request boundaries

### PR 4A — source identity and backbone topology

```text
migration 9 correlation schema
source-to-runtime/intent identity resolver
intent/FDB/LLDP link evidence
current switch/router backbone reconciliation
link events and topology findings
read-only topology CLI
```

### PR 4B — endpoint attachment correlation

```text
MAC-to-FDB candidate extraction
uplink-aware scoring and ambiguity handling
current attachment resolution
attachment events and findings
scheduled reconciliation after collection
```

### PR 4C — unified asset context and topology API

```text
asset-context read model
search by asset key, user-ready key, hostname, IP and MAC
bounded topology export
unified findings aggregation
FastAPI read endpoints
```

### PR 5A — user registry and asset bindings

```text
migration 10 users, identities, asset bindings and network sessions
manual binding commands and API
user-aware context search
no captive portal or directory write-back
```

### PR 5B — RouterOS path facts

```text
migration 11 route metadata from Issue #8
migration 12 routing rules, address lists, filter/NAT/mangle and IPsec observations
bounded read-only RouterOS collection and persistence
```

### PR 5C — path explain engine

```text
pure route/firewall/NAT/IPsec evaluator
allowed/blocked/unknown verdict
CLI and HTTP API
optional retained active-probe evidence
```

### PR 6A — secure control broker

```text
change-scoped API authorization gate
netopsctl database and Unix-socket protocol
dedicated unprivileged netopsctld systemd socket/service
immutable plans, executions and rollback records
MikroTik adapter with enumerated operations only
```

### PR 6B — asset-level Internet policy

```text
desired internet policy model
MikroTik enforcement-point resolution
address-list membership plan/apply/verify/rollback
identity-change reconciler
HTTP plan/apply/rollback endpoints
```

### PR 6C — user policy resolution and session readiness

```text
user-to-primary-asset policy resolution
shared/ambiguous binding rejection
network-session ingestion contract
policy audit through user and asset context
```

Do not combine these deliveries into one pull request.

---

## 4. File map

### New netctl modules

```text
netctl/source_identity.py
netctl/topology_models.py
netctl/topology_evidence.py
netctl/topology_reconcile.py
netctl/attachment_candidates.py
netctl/attachment_reconcile.py
netctl/context_query.py
netctl/findings.py
netctl/user_context.py
netctl/path_models.py
netctl/path_facts.py
netctl/path_engine.py
```

### Existing netctl files modified

```text
netctl/migrations.py
netctl/config.py
netctl/db.py
netctl/cli.py
netctl/store.py
netctl/runtime_assets.py
netctl/switch_queries.py
netctl/drivers/mikrotik_api.py
netctl/drivers/mikrotik_ssh.py
```

### HTTP/API files

```text
app/api.py
app/main.py
app/netctl_client.py
app/models.py
app/auth.py
```

No new Jinja page is required by this plan.

### New netopsctl package and deployment

```text
netopsctl/__init__.py
netopsctl/models.py
netopsctl/migrations.py
netopsctl/store.py
netopsctl/protocol.py
netopsctl/server.py
netopsctl/client.py
netopsctl/policy_resolver.py
netopsctl/reconcile.py
netopsctl/adapters/__init__.py
netopsctl/adapters/mikrotik.py
deploy/netopsctl.service
deploy/netopsctl.socket
deploy/netopsctl-reconcile.service
deploy/netopsctl-reconcile.timer
deploy/netopsctl
```

### Tests

```text
tests/test_netctl_source_identity.py
tests/test_netctl_topology.py
tests/test_netctl_attachments.py
tests/test_netctl_context_query.py
tests/test_netctl_user_context.py
tests/test_netctl_route_metadata.py
tests/test_netctl_path_facts.py
tests/test_netctl_path_engine.py
tests/test_context_api.py
tests/test_network_change_authorization.py
tests/test_netopsctl_store.py
tests/test_netopsctl_protocol.py
tests/test_netopsctl_mikrotik.py
tests/test_netopsctl_internet_policy.py
tests/test_netctl_reconcile_units.py
```

### Runbooks and evidence

```text
docs/runbooks/netctl-correlation-rollout.md
docs/runbooks/netctl-path-facts-rollout.md
docs/runbooks/netopsctl-internet-policy-rollout.md
docs/verification/netctl-correlated-context-readiness.md
docs/verification/netopsctl-internet-policy-readiness.md
```

---

# PR 4A — source identity and backbone topology

## Task 1: Add migration 9 correlation schema

**Files:**
- Modify: `netctl/migrations.py`
- Create: `tests/test_netctl_topology.py`

**Interfaces:**
- Produces migration `9` and the tables used by all PR 4 correlation code.
- Consumes existing `assets`, `asset_interfaces`, `network_sources`, `context_revisions`, `switch_ports` and `current_switch_fdb`.

- [x] **Step 1: Write failing migration tests**

Add a test that opens a database at migration `8`, applies migrations and asserts ledger `1..9`, all tables and constraints.

```python
def test_migration_9_creates_correlation_schema(tmp_path: Path) -> None:
    db_path = tmp_path / "netctl.sqlite"
    conn = create_database_at_migration_8(db_path)
    apply_migrations(conn)

    assert [
        row[0]
        for row in conn.execute(
            "SELECT version FROM schema_migrations ORDER BY version"
        )
    ] == list(range(1, 10))

    tables = {
        row[0]
        for row in conn.execute(
            "SELECT name FROM sqlite_master WHERE type = 'table'"
        )
    }
    assert {
        "network_correlation_runs",
        "current_switch_links",
        "switch_link_events",
        "asset_attachment_resolutions",
        "asset_attachment_candidates",
        "asset_attachment_events",
        "topology_findings",
    } <= tables
```

Add an injected migration failure test and assert that no migration-9 table or ledger row remains.

- [x] **Step 2: Verify RED**

```bash
python -m pytest tests/test_netctl_topology.py::test_migration_9_creates_correlation_schema -q
```

Expected: FAIL because migration 9 is absent.

- [x] **Step 3: Implement migration 9 with individual `conn.execute()` calls**

Do not use `executescript()` and do not call `commit()` inside the migration.

```sql
CREATE TABLE network_correlation_runs (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    run_type TEXT NOT NULL CHECK (run_type IN ('topology','attachments')),
    started_at TEXT NOT NULL,
    finished_at TEXT,
    status TEXT NOT NULL CHECK (status IN ('running','success','partial','failed')),
    context_revision_id INTEGER REFERENCES context_revisions(id) ON DELETE RESTRICT,
    source_watermark_json TEXT NOT NULL DEFAULT '{}',
    counts_json TEXT NOT NULL DEFAULT '{}',
    error_class TEXT NOT NULL DEFAULT '',
    error_message TEXT NOT NULL DEFAULT ''
);

CREATE INDEX network_correlation_runs_type_started_idx
ON network_correlation_runs(run_type, started_at DESC, id DESC);

CREATE TABLE current_switch_links (
    link_key TEXT PRIMARY KEY,
    source_a_id INTEGER NOT NULL REFERENCES network_sources(id) ON DELETE RESTRICT,
    port_a_key TEXT NOT NULL DEFAULT '',
    source_b_id INTEGER NOT NULL REFERENCES network_sources(id) ON DELETE RESTRICT,
    port_b_key TEXT NOT NULL DEFAULT '',
    state TEXT NOT NULL CHECK (state IN ('confirmed','inferred','ambiguous','conflicting')),
    confidence INTEGER NOT NULL CHECK (confidence BETWEEN 0 AND 100),
    intent_link_stable_id TEXT NOT NULL DEFAULT '',
    first_seen_at TEXT NOT NULL,
    last_seen_at TEXT NOT NULL,
    correlation_run_id INTEGER NOT NULL REFERENCES network_correlation_runs(id) ON DELETE RESTRICT,
    evidence_json TEXT NOT NULL DEFAULT '[]',
    CHECK (source_a_id < source_b_id),
    UNIQUE(source_a_id, port_a_key, source_b_id, port_b_key)
);

CREATE INDEX current_switch_links_source_a_idx
ON current_switch_links(source_a_id, port_a_key);
CREATE INDEX current_switch_links_source_b_idx
ON current_switch_links(source_b_id, port_b_key);

CREATE TABLE switch_link_events (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    link_key TEXT NOT NULL,
    event_type TEXT NOT NULL CHECK (event_type IN ('appeared','changed','disappeared')),
    before_json TEXT NOT NULL DEFAULT '{}',
    after_json TEXT NOT NULL DEFAULT '{}',
    observed_at TEXT NOT NULL,
    correlation_run_id INTEGER NOT NULL REFERENCES network_correlation_runs(id) ON DELETE RESTRICT
);

CREATE INDEX switch_link_events_key_time_idx
ON switch_link_events(link_key, observed_at DESC, id DESC);

CREATE UNIQUE INDEX asset_interfaces_id_asset_idx
ON asset_interfaces(id, asset_id);

CREATE TABLE asset_attachment_resolutions (
    asset_interface_id INTEGER PRIMARY KEY,
    asset_id INTEGER NOT NULL,
    status TEXT NOT NULL CHECK (status IN ('confirmed','ambiguous','uplink_only','unresolved')),
    selected_source_id INTEGER REFERENCES network_sources(id) ON DELETE RESTRICT,
    selected_port_key TEXT NOT NULL DEFAULT '',
    selected_vlan_key TEXT NOT NULL DEFAULT '',
    selected_vlan_id INTEGER,
    confidence INTEGER NOT NULL CHECK (confidence BETWEEN 0 AND 100),
    first_seen_at TEXT NOT NULL,
    last_seen_at TEXT NOT NULL,
    correlation_run_id INTEGER NOT NULL REFERENCES network_correlation_runs(id) ON DELETE RESTRICT,
    evidence_json TEXT NOT NULL DEFAULT '[]',
    FOREIGN KEY(asset_interface_id, asset_id)
        REFERENCES asset_interfaces(id, asset_id) ON DELETE RESTRICT
);

CREATE TABLE asset_attachment_candidates (
    asset_interface_id INTEGER NOT NULL,
    asset_id INTEGER NOT NULL,
    switch_source_id INTEGER NOT NULL REFERENCES network_sources(id) ON DELETE RESTRICT,
    port_key TEXT NOT NULL,
    vlan_key TEXT NOT NULL,
    vlan_id INTEGER,
    candidate_class TEXT NOT NULL CHECK (candidate_class IN ('direct','uplink','unknown')),
    topology_depth INTEGER,
    score INTEGER NOT NULL CHECK (score BETWEEN 0 AND 100),
    observed_at TEXT NOT NULL,
    correlation_run_id INTEGER NOT NULL REFERENCES network_correlation_runs(id) ON DELETE RESTRICT,
    evidence_json TEXT NOT NULL DEFAULT '[]',
    PRIMARY KEY(asset_interface_id, switch_source_id, port_key, vlan_key),
    FOREIGN KEY(asset_interface_id, asset_id)
        REFERENCES asset_interfaces(id, asset_id) ON DELETE RESTRICT
);

CREATE INDEX asset_attachment_candidates_switch_port_idx
ON asset_attachment_candidates(switch_source_id, port_key, vlan_key);

CREATE TABLE asset_attachment_events (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    asset_interface_id INTEGER NOT NULL REFERENCES asset_interfaces(id) ON DELETE RESTRICT,
    asset_id INTEGER NOT NULL REFERENCES assets(id) ON DELETE RESTRICT,
    event_type TEXT NOT NULL CHECK (event_type IN (
        'attached','moved','detached','became_ambiguous','resolved_ambiguity'
    )),
    before_json TEXT NOT NULL DEFAULT '{}',
    after_json TEXT NOT NULL DEFAULT '{}',
    observed_at TEXT NOT NULL,
    correlation_run_id INTEGER NOT NULL REFERENCES network_correlation_runs(id) ON DELETE RESTRICT
);

CREATE INDEX asset_attachment_events_asset_time_idx
ON asset_attachment_events(asset_id, observed_at DESC, id DESC);

CREATE TABLE topology_findings (
    finding_key TEXT PRIMARY KEY,
    finding_type TEXT NOT NULL,
    severity TEXT NOT NULL CHECK (severity IN ('info','warning','error','critical')),
    status TEXT NOT NULL CHECK (status IN ('open','acknowledged','resolved')),
    asset_id INTEGER REFERENCES assets(id) ON DELETE RESTRICT,
    source_id INTEGER REFERENCES network_sources(id) ON DELETE RESTRICT,
    first_seen_at TEXT NOT NULL,
    last_seen_at TEXT NOT NULL,
    details_json TEXT NOT NULL DEFAULT '{}'
);

CREATE INDEX topology_findings_status_type_idx
ON topology_findings(status, finding_type, last_seen_at DESC);
```

- [x] **Step 4: Run migration tests**

```bash
python -m pytest tests/test_netctl_topology.py -k migration -q
```

Expected: PASS.

- [x] **Step 5: Commit**

```bash
git add netctl/migrations.py tests/test_netctl_topology.py
git commit -m "feat: add topology correlation schema"
```

## Task 2: Resolve stable identity for network sources

**Files:**
- Create: `netctl/source_identity.py`
- Modify: `netctl/config.py`
- Modify: `netctl/db.py`
- Create: `tests/test_netctl_source_identity.py`

**Interfaces:**
- Produces `SourceIdentity` and `list_source_identities()`.
- Later topology tasks consume management MACs, runtime asset binding, intent binding and topology role.

- [x] **Step 1: Write failing identity tests**

Use this public contract:

```python
@dataclass(frozen=True)
class SourceIdentity:
    source_id: int
    source_name: str
    driver: str
    topology_role: str
    runtime_asset_id: int | None
    runtime_asset_key: str
    intent_context_id: str
    intent_stable_id: str
    management_macs: tuple[str, ...]


def list_source_identities(
    conn: sqlite3.Connection,
) -> tuple[SourceIdentity, ...]: ...
```

Tests prove:

```text
SNMP source binding resolves through switch_devices.runtime_asset_id.
RouterOS source binding resolves configured runtime_asset_key without creating an asset.
Intent binding resolves only an active intent asset in the named active context.
Management MACs come from bound asset_interfaces.
Unknown runtime/intent keys remain unresolved instead of being auto-created.
Allowed topology roles are core, distribution, access, edge and unknown.
Secrets never enter the public identity object.
```

- [x] **Step 2: Verify RED**

```bash
python -m pytest tests/test_netctl_source_identity.py -q
```

Expected: FAIL because `netctl.source_identity` is absent.

- [x] **Step 3: Extend generic source options**

Permit these source YAML scalars for all drivers and store them in `driver_options_json`:

```yaml
runtime_asset_key: mac:D4:01:C3:9C:83:5F
intent_context_id: sosn-admin-network
intent_stable_id: mikrotik-rb3011-sosn
topology_role: core
```

Validation rule:

```python
TOPOLOGY_ROLES = frozenset({"core", "distribution", "access", "edge", "unknown"})
```

Empty identity fields are valid; invalid role or whitespace-only stable identifiers are rejected.

- [x] **Step 4: Implement the resolver**

Resolution order:

```text
1. Read network_sources and decoded driver_options.
2. For snmp_switch, use switch_devices.runtime_asset_id when present.
3. Otherwise resolve runtime_asset_key against assets.asset_key.
4. Resolve intent_stable_id only through the active context head for intent_context_id.
5. Read normalized non-null MACs from asset_interfaces for the resolved runtime asset.
6. Do not insert, update or confirm any binding.
```

- [x] **Step 5: Run tests and regression subset**

```bash
python -m pytest tests/test_netctl_source_identity.py tests/test_netctl_snmp_config.py tests/test_netctl_context_import.py -q
```

Expected: PASS.

- [x] **Step 6: Commit**

```bash
git add netctl/source_identity.py netctl/config.py netctl/db.py tests/test_netctl_source_identity.py
git commit -m "feat: resolve source runtime and intent identity"
```

## Task 3: Produce typed backbone-link evidence

**Files:**
- Create: `netctl/topology_models.py`
- Create: `netctl/topology_evidence.py`
- Modify: `tests/test_netctl_topology.py`

**Interfaces:**
- Consumes `SourceIdentity`, active `intent_links`, `current_switch_fdb`, `current_switch_lldp_neighbors` and `switch_ports`.
- Produces `LinkEvidence` rows without writing the database.

- [x] **Step 1: Define failing evidence tests**

Use these contracts:

```python
@dataclass(frozen=True)
class LinkEndpoint:
    source_id: int
    port_key: str


@dataclass(frozen=True)
class LinkEvidence:
    endpoint_a: LinkEndpoint
    endpoint_b: LinkEndpoint
    evidence_type: str
    confidence: int
    observed_at: str
    intent_link_stable_id: str
    details: dict[str, Any]


def collect_link_evidence(
    conn: sqlite3.Connection,
    identities: tuple[SourceIdentity, ...],
) -> tuple[LinkEvidence, ...]: ...
```

Tests cover:

```text
intent link with exact port-name match returns two known ports and confidence 90;
intent link with one unresolved port remains useful with confidence 65;
FDB management-MAC evidence returns local port and remote source with confidence 70;
LLDP match by chassis MAC returns confidence 90;
LLDP plus matching intent remains separate evidence;
non-unique system names do not resolve an LLDP neighbor;
normal endpoint MACs are not treated as backbone identities;
self-links are rejected.
```

Use synthetic fixtures representing:

```text
central MikroTik <-> SNR ge24
SNR ge21 <-> DGS port52
SNR ge22 <-> CSS326 SRV-1 port24
SNR ge23 <-> TP-Link ITO port47
```

- [x] **Step 2: Verify RED**

```bash
python -m pytest tests/test_netctl_topology.py -k evidence -q
```

Expected: FAIL because evidence modules are absent.

- [x] **Step 3: Implement deterministic endpoint normalization**

Canonicalize a pair so the lower `source_id` is endpoint A. Normalize port matching in this order:

```text
exact port_key
exact case-insensitive switch_ports.name
exact case-insensitive switch_ports.alias only when unique
otherwise empty port_key
```

Never use substring matching for a confirmed port.

- [x] **Step 4: Implement the evidence adapters**

```python
def intent_link_evidence(...): ...
def fdb_management_mac_evidence(...): ...
def lldp_link_evidence(...): ...
```

Each adapter returns evidence rows. It does not merge evidence or write current links.

- [x] **Step 5: Run focused tests**

```bash
python -m pytest tests/test_netctl_topology.py -k evidence -q
```

Expected: PASS.

- [x] **Step 6: Commit**

```bash
git add netctl/topology_models.py netctl/topology_evidence.py tests/test_netctl_topology.py
git commit -m "feat: derive backbone topology evidence"
```

## Task 4: Reconcile current backbone topology atomically

**Files:**
- Create: `netctl/topology_reconcile.py`
- Modify: `netctl/cli.py`
- Modify: `tests/test_netctl_topology.py`
- Modify: `.github/workflows/verify-netctl-runtime.yml`

**Interfaces:**
- Consumes `collect_link_evidence()`.
- Produces `reconcile_topology(conn, observed_at) -> dict[str, Any]` and read-only topology CLI commands.

- [x] **Step 1: Write failing reconciliation tests**

Required behavior:

```text
matching intent + FDB evidence -> confirmed link;
FDB-only management evidence -> inferred link;
two incompatible local ports for the same peer -> conflicting link and open finding;
identical rerun -> no duplicate event;
changed port -> one changed event;
disappeared evidence after a successful complete input -> one disappeared event;
injected transaction error -> previous current links remain unchanged;
no core source -> topology depths are unknown, not fabricated;
cycle in graph -> traversal terminates deterministically.
```

- [x] **Step 2: Verify RED**

```bash
python -m pytest tests/test_netctl_topology.py -k reconcile -q
```

- [x] **Step 3: Implement evidence aggregation**

Aggregation rules:

```text
intent + LLDP/FDB agreement: confirmed, confidence min(100, max evidence + 10)
LLDP only: inferred, confidence 85
FDB management MAC only: inferred, confidence 70
intent only with both ports: inferred, confidence 60
intent only with one port: inferred, confidence 45
incompatible high-confidence evidence: conflicting, confidence 0
```

Persist the complete sorted evidence list in `evidence_json`.

- [x] **Step 4: Implement topology depth**

Build an undirected graph from non-conflicting current links. Start BFS from sources with `topology_role = core`.

```python
def topology_depths(
    links: Sequence[CurrentSwitchLink],
    roots: set[int],
) -> dict[int, int]: ...
```

Unreachable sources have no depth.

- [x] **Step 5: Implement atomic current-state replacement and events**

Create and commit a `network_correlation_runs` row with `run_type = 'topology'` and status `running` before reconciliation. Replace current links, events, findings and final run status in one `BEGIN IMMEDIATE` transaction. On failure, rollback all replacement changes and finalize the durable run as `failed` in a recovery transaction.

- [x] **Step 6: Add CLI**

```bash
netctl --json topology reconcile
netctl --json topology status
netctl --json topology links --state confirmed
netctl --json topology findings --status open
```

All read commands use `connect_read_only()`.

- [ ] **Step 7: Run focused and full tests**

```bash
python -m pytest tests/test_netctl_source_identity.py tests/test_netctl_topology.py tests/test_netctl_switch_store.py -q
python -m pytest -q
```

Expected: PASS.

- [x] **Step 8: Commit**

```bash
git add netctl/topology_reconcile.py netctl/cli.py tests/test_netctl_topology.py .github/workflows/verify-netctl-runtime.yml
git commit -m "feat: reconcile current network backbone"
```

---

# PR 4B — endpoint attachment correlation

## Task 5: Extract FDB candidates for runtime interfaces

**Files:**
- Create: `netctl/attachment_candidates.py`
- Create: `tests/test_netctl_attachments.py`

**Interfaces:**
- Consumes normalized `asset_interfaces.mac`, `current_switch_fdb`, `switch_ports` and current backbone links.
- Produces `AttachmentCandidate` without writing the database.

- [x] **Step 1: Write failing candidate tests**

Use this contract:

```python
@dataclass(frozen=True)
class AttachmentCandidate:
    asset_id: int
    asset_interface_id: int
    switch_source_id: int
    port_key: str
    vlan_key: str
    vlan_id: int | None
    candidate_class: str
    topology_depth: int | None
    score: int
    observed_at: str
    evidence: tuple[dict[str, Any], ...]


def attachment_candidates(
    conn: sqlite3.Connection,
    depths: Mapping[int, int],
) -> tuple[AttachmentCandidate, ...]: ...
```

Tests prove:

```text
MAC matching is case-insensitive after normalization;
known inter-switch link port is candidate_class uplink;
port not participating in a backbone link is candidate_class direct;
missing topology depth remains None;
FDB self/mgmt status for the same switch asset is not treated as an endpoint;
multiple VLAN/FID rows remain distinct candidates;
invalid MAC observations are ignored without changing assets;
failed/old switch run is not interpreted as a new disappearance.
```

- [x] **Step 2: Verify RED**

```bash
python -m pytest tests/test_netctl_attachments.py -k candidates -q
```

- [x] **Step 3: Implement candidate scoring**

Use this deterministic score:

```text
base direct candidate                                      60
base uplink candidate                                      20
base unknown candidate                                     35
known topology depth                                    + min(depth * 5, 20)
known VLAN ID                                                +5
port oper_status == up                                       +5
FDB belongs to selected current collector run                +5
port is a verified backbone port                            -20
```

Clamp the final score to `0..100`.

- [x] **Step 4: Run focused tests**

```bash
python -m pytest tests/test_netctl_attachments.py -k candidates -q
```

Expected: PASS.

- [x] **Step 5: Commit**

```bash
git add netctl/attachment_candidates.py tests/test_netctl_attachments.py
git commit -m "feat: derive endpoint attachment candidates"
```

## Task 6: Resolve and persist endpoint attachments

**Files:**
- Create: `netctl/attachment_reconcile.py`
- Modify: `netctl/cli.py`
- Modify: `tests/test_netctl_attachments.py`

**Interfaces:**
- Consumes `attachment_candidates()` and current topology depths.
- Produces `reconcile_attachments(conn, observed_at) -> dict[str, Any]`.

- [x] **Step 1: Write failing resolution tests**

Resolution contract:

```text
confirmed:
  exactly one highest direct candidate;
  score >= 75;
  score gap to next candidate >= 15.

ambiguous:
  two or more top candidates with gap < 15;
  or multiple direct candidates at the same deepest level.

uplink_only:
  candidates exist but every candidate is uplink.

unresolved:
  no candidates exist for an eligible current interface.
```

An interface is eligible for an operational unresolved finding only when it has a normalized MAC, belongs to a non-retired asset, has a current IP or hostname observation and its site has at least one successfully collected switch source. Other interfaces may have an unresolved status but do not create warning noise.

Tests cover:

```text
C0:9B:F4:61:4B:CD -> TP-Link ITO port48 -> VLAN20 -> confirmed;
endpoint observed on SNR ge23 and TP-Link port48 selects deeper direct port48;
endpoint behind an unmanaged switch produces uplink_only rather than a false direct port;
move between access ports emits one moved event;
ambiguous state emits became_ambiguous and an open finding;
ambiguity resolution emits resolved_ambiguity and resolves the finding;
failed reconciliation transaction preserves prior candidates and resolution;
no candidate does not delete runtime asset or interface;
different MAC interfaces remain different attachment resolutions.
```

- [x] **Step 2: Verify RED**

```bash
python -m pytest tests/test_netctl_attachments.py -k resolution -q
```

- [x] **Step 3: Implement pure resolution**

```python
def resolve_attachment(
    candidates: Sequence[AttachmentCandidate],
) -> AttachmentResolution: ...
```

`AttachmentResolution` contains status, selected candidate, confidence and all alternatives. Confidence is the selected score for confirmed, the highest candidate score capped at 60 for ambiguous/uplink-only, and `0` for unresolved.

- [x] **Step 4: Implement persistence and event comparison**

Create a durable `network_correlation_runs` row with `run_type = 'attachments'`. Candidate replacement, resolution replacement, event insertions, finding reconciliation and run completion occur in one transaction. A collector failure does not invoke attachment reconciliation; a correlation process failure preserves the previous state.

Finding keys:

```text
attachment-ambiguous:<asset_interface_id>
attachment-uplink-only:<asset_interface_id>
attachment-unresolved:<asset_interface_id>
```

- [x] **Step 5: Add CLI**

```bash
netctl --json attachments reconcile
netctl --json attachments status
netctl --json attachments inspect --asset-key mac:C0:9B:F4:61:4B:CD
netctl --json attachments events --asset-key mac:C0:9B:F4:61:4B:CD
```

- [x] **Step 6: Run tests**

```bash
python -m pytest tests/test_netctl_attachments.py tests/test_netctl_topology.py -q
```

Expected: PASS.

- [x] **Step 7: Commit**

```bash
git add netctl/attachment_reconcile.py netctl/cli.py tests/test_netctl_attachments.py
git commit -m "feat: reconcile endpoint network attachments"
```

## Task 7: Schedule correlation without mixing network I/O

**Files:**
- Create: `deploy/netctl-reconcile.service`
- Create: `deploy/netctl-reconcile.timer`
- Modify: `deploy/install-openvpn-web.sh`
- Create: `docs/runbooks/netctl-correlation-rollout.md`
- Modify: `tests/test_installer_security.py`
- Create: `tests/test_netctl_reconcile_units.py`

**Interfaces:**
- Collection remains network I/O.
- Reconciliation is a separate local SQLite operation and acquires the existing `CollectLock`.

- [x] **Step 1: Write failing deployment tests**

Tests assert:

```text
netctl-reconcile.service runs as user netctl;
ExecStart invokes topology reconcile then attachments reconcile;
service performs no sudo and no network-device command;
timer cadence is five minutes and Persistent=true;
installer installs and enables the timer;
OpenVPN and WireGuard units are not restarted by reconciliation deployment.
```

- [x] **Step 2: Verify RED**

```bash
python -m pytest tests/test_netctl_reconcile_units.py tests/test_installer_security.py -q
```

- [x] **Step 3: Add units**

```ini
# deploy/netctl-reconcile.service
[Unit]
Description=Reconcile netctl topology and asset attachments
After=netctl-collect.service

[Service]
Type=oneshot
User=netctl
ExecStart=/usr/local/sbin/netctl --json topology reconcile
ExecStart=/usr/local/sbin/netctl --json attachments reconcile
```

```ini
# deploy/netctl-reconcile.timer
[Unit]
Description=Reconcile netctl context after collection

[Timer]
OnBootSec=4min
OnUnitActiveSec=5min
AccuracySec=30s
Persistent=true
Unit=netctl-reconcile.service

[Install]
WantedBy=timers.target
```

- [x] **Step 4: Write rollout and rollback commands**

The runbook creates a SQLite `.backup`, verifies integrity, applies migration 9 with the timer disabled, runs one manual topology/attachment reconciliation, inspects aggregate counts only, then enables the timer. Rollback restores the database and prior application tree.

- [x] **Step 5: Run tests and commit**

```bash
python -m pytest tests/test_netctl_reconcile_units.py tests/test_installer_security.py -q
git add deploy docs/runbooks/netctl-correlation-rollout.md tests/test_netctl_reconcile_units.py tests/test_installer_security.py
git commit -m "ops: schedule local network correlation"
```

---

# PR 4C — unified asset context and topology API

## Task 8: Build the unified asset context read model

**Files:**
- Create: `netctl/context_query.py`
- Create: `netctl/findings.py`
- Modify: `netctl/runtime_assets.py`
- Create: `tests/test_netctl_context_query.py`

**Interfaces:**
- Consumes runtime asset, intent binding, current observations, attachment, switch, topology, source health and findings.
- Produces `inspect_asset_context()` and `search_context()`.

- [x] **Step 1: Write failing context tests**

Use this contract:

```python
def inspect_asset_context(
    conn: sqlite3.Connection,
    asset_key: str,
) -> dict[str, Any] | None: ...


def search_context(
    conn: sqlite3.Connection,
    query: str,
    limit: int = 25,
) -> list[dict[str, Any]]: ...
```

The asset response contains exactly these top-level keys:

```text
asset
intent
owner
interfaces
attachment
network
topology_path
source_health
findings
evidence
```

Before PR 5A, `owner` is `null`.

Tests cover exact searches by:

```text
asset_key
normalized MAC
IPv4 address
hostname, case-insensitive
intent stable ID
```

An IP or hostname matching multiple assets returns multiple explicit search results; it never selects the newest row silently.

- [x] **Step 2: Verify RED**

```bash
python -m pytest tests/test_netctl_context_query.py -q
```

- [x] **Step 3: Implement bounded composition**

Limits:

```text
interfaces: 32
current IP observations: 64
current hostnames: 64
findings: 100
attachment alternatives: 32
topology path nodes: 32
evidence records per section: 64
```

Do not return secret refs, raw source configuration, raw SNMP values, firewall credentials or database internal error strings.

- [x] **Step 4: Build topology path**

For a confirmed attachment, traverse current non-conflicting links from the selected switch toward the nearest `core` source. Return the shortest deterministic path. If no core is reachable, return the attachment switch alone with `complete: false` and reason `no_core_path`.

- [x] **Step 5: Aggregate findings without rewriting them**

`netctl/findings.py` reads and normalizes:

```text
runtime_identity_findings
topology_findings
switch source/run failures
```

It returns the original finding source and key. It does not copy or change lifecycle state in the source tables.

- [x] **Step 6: Run tests and commit**

```bash
python -m pytest tests/test_netctl_context_query.py tests/test_netctl_attachments.py -q
git add netctl/context_query.py netctl/findings.py netctl/runtime_assets.py tests/test_netctl_context_query.py
git commit -m "feat: compose unified asset network context"
```

## Task 9: Expose read-only context and topology API

**Files:**
- Modify: `netctl/cli.py`
- Modify: `app/api.py`
- Modify: `app/netctl_client.py`
- Create: `tests/test_context_api.py`

**Interfaces:**
- Produces CLI and HTTP read contracts.
- Does not add a new web page.

- [x] **Step 1: Write failing API tests**

Endpoints:

```http
GET /api/v1/context/search?q=192.168.100.75
GET /api/v1/context/assets/mac:AA:BB:CC:DD:EE:FF
GET /api/v1/context/topology?site=central&state=confirmed&depth=4
GET /api/v1/context/findings?status=open
```

Tests assert authentication, pagination bounds, safe keys and no write side effects.

- [x] **Step 2: Add CLI**

```bash
netctl --json context-view search --query 192.168.100.75
netctl --json context-view asset --asset-key mac:AA:BB:CC:DD:EE:FF
netctl --json context-view topology --site central --state confirmed --depth 4
netctl --json context-view findings --status open
```

- [x] **Step 3: Implement HTTP adapters**

HTTP handlers call only the new CLI contracts through `call_netctl()`. They do not read `netctl.sqlite` directly from the web process.

- [x] **Step 4: Run tests and full regression**

```bash
python -m pytest tests/test_context_api.py tests/test_web_network_observer.py -q
python -m pytest -q
```

- [x] **Step 5: Commit**

```bash
git add netctl/cli.py app/api.py app/netctl_client.py tests/test_context_api.py
git commit -m "feat: expose unified network context API"
```

---

# PR 5A — user registry and asset bindings

## Task 10: Add migration 10 user-context schema

**Files:**
- Modify: `netctl/migrations.py`
- Create: `netctl/user_context.py`
- Create: `tests/test_netctl_user_context.py`

**Interfaces:**
- Produces user and binding persistence.
- Does not authenticate users or contact AD/LDAP.

- [x] **Step 1: Write failing migration and model tests**

Migration 10 creates:

```sql
CREATE TABLE users (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    user_key TEXT NOT NULL UNIQUE,
    display_name TEXT NOT NULL,
    status TEXT NOT NULL CHECK (status IN ('active','disabled','retired')),
    department TEXT NOT NULL DEFAULT '',
    source_type TEXT NOT NULL CHECK (source_type IN ('manual','directory','helpdesk')),
    external_id TEXT NOT NULL DEFAULT '',
    created_at TEXT NOT NULL,
    updated_at TEXT NOT NULL,
    evidence_json TEXT NOT NULL DEFAULT '{}'
);

CREATE TABLE user_identities (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    user_id INTEGER NOT NULL REFERENCES users(id) ON DELETE RESTRICT,
    identity_type TEXT NOT NULL CHECK (identity_type IN ('login','email','employee_id','directory_dn')),
    identity_value TEXT NOT NULL,
    source_type TEXT NOT NULL,
    first_seen_at TEXT NOT NULL,
    last_seen_at TEXT NOT NULL,
    UNIQUE(identity_type, identity_value, source_type)
);

CREATE TABLE user_asset_bindings (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    user_id INTEGER NOT NULL REFERENCES users(id) ON DELETE RESTRICT,
    asset_id INTEGER NOT NULL REFERENCES assets(id) ON DELETE RESTRICT,
    relation TEXT NOT NULL CHECK (relation IN ('primary_user','shared_user','temporary_user','owner')),
    status TEXT NOT NULL CHECK (status IN ('candidate','confirmed','rejected','retired')),
    binding_source TEXT NOT NULL CHECK (binding_source IN ('manual','directory','helpdesk','session_inference')),
    confidence INTEGER NOT NULL CHECK (confidence BETWEEN 0 AND 100),
    valid_from TEXT NOT NULL,
    valid_until TEXT,
    created_at TEXT NOT NULL,
    updated_at TEXT NOT NULL,
    evidence_json TEXT NOT NULL DEFAULT '{}',
    UNIQUE(user_id, asset_id, relation, binding_source, valid_from)
);

CREATE TABLE network_sessions (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    user_id INTEGER NOT NULL REFERENCES users(id) ON DELETE RESTRICT,
    asset_id INTEGER REFERENCES assets(id) ON DELETE RESTRICT,
    source_type TEXT NOT NULL CHECK (source_type IN ('captive_portal','radius','directory_agent','manual')),
    session_key TEXT NOT NULL UNIQUE,
    started_at TEXT NOT NULL,
    ended_at TEXT,
    accepted_policy_version TEXT NOT NULL DEFAULT '',
    evidence_json TEXT NOT NULL DEFAULT '{}'
);
```

- [x] **Step 2: Verify RED**

```bash
python -m pytest tests/test_netctl_user_context.py -q
```

- [x] **Step 3: Implement bounded service functions**

```python
def create_user(...): ...
def bind_user_asset(...): ...
def retire_user_asset_binding(...): ...
def inspect_user_context(...): ...
def resolve_policy_asset_for_user(...): ...
```

`resolve_policy_asset_for_user()` succeeds only when exactly one current binding has relation `primary_user`, status `confirmed`, confidence `100`, no active `shared_user` binding exists for the asset, and the binding validity interval includes the current time.

- [x] **Step 4: Run tests and commit**

```bash
python -m pytest tests/test_netctl_user_context.py tests/test_netctl_context_query.py -q
git add netctl/migrations.py netctl/user_context.py tests/test_netctl_user_context.py
git commit -m "feat: add user and asset context bindings"
```

## Task 11: Add manual user-context API and search integration

**Files:**
- Modify: `netctl/cli.py`
- Modify: `netctl/context_query.py`
- Modify: `app/api.py`
- Modify: `app/models.py`
- Modify: `tests/test_context_api.py`
- Modify: `tests/test_netctl_user_context.py`

**Interfaces:**
- Produces manual context-management commands and HTTP endpoints.
- No directory or captive-portal integration is included.

- [x] **Step 1: Write failing tests**

CLI:

```bash
netctl --json users add --user-key employee:ivanov --display-name "Иванов Иван Иванович"
netctl --json users bind-asset --user-key employee:ivanov --asset-key mac:AA:BB:CC:DD:EE:FF --relation primary_user --confidence 100 --reason "approved workstation assignment"
netctl --json users inspect --user-key employee:ivanov
netctl --json users retire-binding --binding-id 42 --reason "workstation reassigned"
```

HTTP:

```http
POST /api/v1/context/users
POST /api/v1/context/users/{user_key}/asset-bindings
DELETE /api/v1/context/user-asset-bindings/{binding_id}
GET /api/v1/context/users/{user_key}
```

Tests assert CSRF/session or bearer authorization, audit records, validation and no device calls.

- [x] **Step 2: Implement and integrate search**

`search_context()` returns user matches alongside asset matches and includes confirmed asset bindings without inventing an active session.

- [x] **Step 3: Run tests and commit**

```bash
python -m pytest tests/test_netctl_user_context.py tests/test_context_api.py -q
git add netctl/cli.py netctl/context_query.py app/api.py app/models.py tests/test_context_api.py tests/test_netctl_user_context.py
git commit -m "feat: manage user asset context through API"
```

---

# PR 5B — RouterOS path facts

## Task 12: Persist routing-table metadata from Issue #8

**Files:**
- Modify: `netctl/migrations.py`
- Modify: `netctl/store.py`
- Modify: `netctl/drivers/mikrotik_api.py`
- Modify: `netctl/drivers/mikrotik_ssh.py`
- Create: `tests/test_netctl_route_metadata.py`

**Interfaces:**
- Produces migration `11` and complete route metadata.
- Preserves existing route query fields.

- [x] **Step 1: Write failing tests**

Migration 11 adds:

```sql
ALTER TABLE network_routes ADD COLUMN routing_table TEXT NOT NULL DEFAULT 'main';
ALTER TABLE network_routes ADD COLUMN scope INTEGER;
ALTER TABLE network_routes ADD COLUMN target_scope INTEGER;
ALTER TABLE network_routes ADD COLUMN immediate_gateway TEXT NOT NULL DEFAULT '';
CREATE INDEX network_routes_source_table_dst_idx
ON network_routes(source_id, routing_table, dst_address, active, distance);
```

Tests prove named tables, scope, target scope and immediate gateway survive driver -> snapshot -> SQLite -> CLI/API.

- [x] **Step 2: Verify RED**

```bash
python -m pytest tests/test_netctl_route_metadata.py -q
```

- [x] **Step 3: Implement migration and storage**

Do not change route identity to IP-only and do not discard legacy rows.

- [x] **Step 4: Run tests and close Issue #8 after merge**

```bash
python -m pytest tests/test_netctl_route_metadata.py tests/test_netctl_cli.py -q
```

- [x] **Step 5: Commit**

```bash
git add netctl/migrations.py netctl/store.py netctl/drivers/mikrotik_api.py netctl/drivers/mikrotik_ssh.py tests/test_netctl_route_metadata.py
git commit -m "feat: persist RouterOS route table metadata"
```

## Task 13: Add migration 12 and read-only path-fact collection

**Files:**
- Modify: `netctl/migrations.py`
- Create: `netctl/path_models.py`
- Create: `netctl/path_facts.py`
- Modify: `netctl/store.py`
- Modify: `netctl/drivers/mikrotik_api.py`
- Modify: `netctl/drivers/mikrotik_ssh.py`
- Create: `tests/test_netctl_path_facts.py`

**Interfaces:**
- Produces normalized current RouterOS path facts.
- Collectors remain read-only.

- [x] **Step 1: Write failing schema and driver tests**

Migration 12 creates current tables:

```text
router_routing_rules
router_address_list_entries
router_filter_rules
router_nat_rules
router_mangle_rules
router_ipsec_policies
router_path_fact_runs
```

Every rule row stores:

```text
source_id
rule_key
chain
position
active/disabled
action
known normalized match fields
comment
observed_at
collector_run_id
unsupported_matchers_json
```

Do not store raw command output, passwords, secrets, IPsec installed-SA keys or arbitrary RouterOS properties.

- [x] **Step 2: Define dataclasses**

```python
@dataclass(frozen=True)
class RouterRule:
    rule_key: str
    family: str
    chain: str
    position: int
    disabled: bool
    action: str
    src_cidr: str
    dst_cidr: str
    protocol: str
    dst_port: str
    in_interface: str
    out_interface: str
    src_address_list: str
    dst_address_list: str
    routing_mark: str
    connection_state: str
    comment: str
    unsupported_matchers: tuple[str, ...]
```

Add equivalent bounded models for routing rules, address-list entries and IPsec policies.

- [x] **Step 3: Implement capability-specific replacement**

Each fact family is replaced only after its own successful collection. A failed firewall query preserves the previous filter/NAT/mangle facts and marks the source path-fact run partial or failed.

- [x] **Step 4: Run tests**

```bash
python -m pytest tests/test_netctl_path_facts.py tests/test_netctl_route_metadata.py -q
```

Expected: PASS.

- [x] **Step 5: Commit**

```bash
git add netctl/migrations.py netctl/path_models.py netctl/path_facts.py netctl/store.py netctl/drivers/mikrotik_api.py netctl/drivers/mikrotik_ssh.py tests/test_netctl_path_facts.py
git commit -m "feat: collect RouterOS path facts"
```

---

# PR 5C — path explain engine

## Task 14: Implement the conservative path evaluator

**Files:**
- Create: `netctl/path_engine.py`
- Create: `tests/test_netctl_path_engine.py`

**Interfaces:**
- Consumes one asset context plus current RouterOS path facts.
- Produces `PathExplanation` without device I/O.

- [x] **Step 1: Write failing evaluator tests**

Use these public models:

```python
class PathVerdict(StrEnum):
    ALLOWED = "allowed"
    BLOCKED = "blocked"
    UNKNOWN = "unknown"


@dataclass(frozen=True)
class PathRequest:
    asset_key: str
    destination_ip: str
    protocol: str
    destination_port: int | None


@dataclass(frozen=True)
class PathExplanation:
    verdict: PathVerdict
    source_asset_key: str
    source_ips: tuple[str, ...]
    enforcement_source: str
    selected_routing_table: str
    selected_route: dict[str, Any] | None
    stages: tuple[dict[str, Any], ...]
    unknown_reasons: tuple[str, ...]
    evidence: tuple[dict[str, Any], ...]
```

Tests cover:

```text
longest-prefix route selection within selected table;
routing-rule priority and lookup table selection;
no matching route -> blocked only when an explicit unreachable/blackhole route exists;
missing route facts -> unknown;
ordered explicit filter drop -> blocked;
ordered explicit filter accept -> allowed when no earlier unsupported matcher can affect the result;
unsupported matcher before decisive rule -> unknown;
WAN-only Internet deny list match -> blocked for WAN destination but not internal segment;
IPsec selector match appears as a tunnel stage;
ambiguous current source IPs across sites -> unknown;
stale path facts -> unknown;
reverse-path analysis absent -> forward-only flag, not a false verified bidirectional result.
```

- [x] **Step 2: Verify RED**

```bash
python -m pytest tests/test_netctl_path_engine.py -q
```

- [x] **Step 3: Implement pure stages**

```python
def select_source_context(...): ...
def select_routing_table(...): ...
def select_route(...): ...
def evaluate_filter(...): ...
def explain_nat(...): ...
def match_ipsec_policy(...): ...
def explain_path(...): ...
```

All functions are deterministic and accept normalized records. No function opens SQLite or contacts a device.

- [x] **Step 4: Run tests and commit**

```bash
python -m pytest tests/test_netctl_path_engine.py -q
git add netctl/path_engine.py tests/test_netctl_path_engine.py
git commit -m "feat: explain network paths conservatively"
```

## Task 15: Add path CLI and API

**Files:**
- Modify: `netctl/cli.py`
- Modify: `app/api.py`
- Modify: `app/models.py`
- Modify: `tests/test_context_api.py`
- Create: `docs/runbooks/netctl-path-facts-rollout.md`

**Interfaces:**
- Produces read-only path explanation.

- [x] **Step 1: Write failing API tests**

```bash
netctl --json path explain \
  --asset-key mac:AA:BB:CC:DD:EE:FF \
  --destination 172.153.159.10 \
  --protocol tcp \
  --port 443
```

```http
GET /api/v1/context/path?asset_key=mac:AA:BB:CC:DD:EE:FF&destination=172.153.159.10&protocol=tcp&port=443
```

- [x] **Step 2: Implement read-only composition**

The CLI loads context and facts from a read-only connection, validates freshness and calls the pure engine.

- [x] **Step 3: Run tests and full regression**

```bash
python -m pytest tests/test_netctl_path_engine.py tests/test_context_api.py -q
python -m pytest -q
```

- [x] **Step 4: Commit**

```bash
git add netctl/cli.py app/api.py app/models.py tests/test_context_api.py docs/runbooks/netctl-path-facts-rollout.md
git commit -m "feat: expose network path explanation"
```

---

# PR 6A — secure control broker

## Task 16: Add network-change authorization scopes

**Files:**
- Modify: `app/models.py`
- Modify: `app/api.py`
- Modify: `app/auth.py`
- Create: `tests/test_network_change_authorization.py`

**Interfaces:**
- Produces API scopes `network:read`, `network:plan`, `network:apply`, `network:rollback`.
- Blocks all control-plane endpoints until HTTPS/trusted proxy and scoped tokens are configured.

- [x] **Step 1: Write failing authorization tests**

Tests assert:

```text
read token cannot create a plan;
plan token cannot apply or rollback;
apply token cannot rollback unless it also has rollback scope;
web session without network admin role cannot create a plan;
all denied attempts are audited;
control endpoints refuse operation when trusted HTTPS mode is false.
```

- [x] **Step 2: Implement the gate**

Do not reuse one unrestricted bearer token for read and change operations.

- [x] **Step 3: Run tests and commit**

```bash
python -m pytest tests/test_network_change_authorization.py -q
git add app/models.py app/api.py app/auth.py tests/test_network_change_authorization.py
git commit -m "security: add network change authorization scopes"
```

## Task 17: Create netopsctl database and immutable change plans

**Files:**
- Create: `netopsctl/__init__.py`
- Create: `netopsctl/models.py`
- Create: `netopsctl/migrations.py`
- Create: `netopsctl/store.py`
- Create: `tests/test_netopsctl_store.py`

**Interfaces:**
- Produces a separate database at `/var/lib/netopsctl/netopsctl.sqlite`.
- Opens `netctl.sqlite` only through `netctl.db.connect_read_only()`.

- [x] **Step 1: Write failing store tests**

Netopsctl migration 1 creates:

```sql
CREATE TABLE change_plans (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    plan_key TEXT NOT NULL UNIQUE,
    actor TEXT NOT NULL,
    reason TEXT NOT NULL,
    subject_type TEXT NOT NULL CHECK (subject_type IN ('asset','user','infrastructure')),
    subject_key TEXT NOT NULL,
    operation_type TEXT NOT NULL CHECK (operation_type IN (
        'internet_access_set','internet_policy_bootstrap'
    )),
    desired_state_json TEXT NOT NULL,
    resolved_targets_json TEXT NOT NULL,
    context_evidence_hash TEXT NOT NULL,
    precheck_json TEXT NOT NULL,
    rollback_json TEXT NOT NULL,
    status TEXT NOT NULL CHECK (status IN (
        'draft','validated','approved','applying','applied','verified',
        'failed','rolling_back','rolled_back','cancelled'
    )),
    created_at TEXT NOT NULL,
    approved_at TEXT,
    applied_at TEXT,
    verified_at TEXT,
    updated_at TEXT NOT NULL
);

CREATE TABLE change_plan_steps (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    change_plan_id INTEGER NOT NULL REFERENCES change_plans(id) ON DELETE RESTRICT,
    step_order INTEGER NOT NULL,
    adapter TEXT NOT NULL,
    operation TEXT NOT NULL,
    target_key TEXT NOT NULL,
    request_json TEXT NOT NULL,
    result_json TEXT NOT NULL DEFAULT '{}',
    status TEXT NOT NULL CHECK (status IN ('pending','applied','verified','failed','rolled_back')),
    UNIQUE(change_plan_id, step_order)
);

CREATE TABLE change_executions (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    change_plan_id INTEGER NOT NULL REFERENCES change_plans(id) ON DELETE RESTRICT,
    execution_type TEXT NOT NULL CHECK (execution_type IN ('apply','verify','rollback','reconcile')),
    started_at TEXT NOT NULL,
    finished_at TEXT,
    status TEXT NOT NULL CHECK (status IN ('running','success','failed')),
    sanitized_result_json TEXT NOT NULL DEFAULT '{}'
);

CREATE TABLE desired_network_policies (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    subject_type TEXT NOT NULL CHECK (subject_type IN ('asset','user')),
    subject_key TEXT NOT NULL,
    policy_type TEXT NOT NULL CHECK (policy_type = 'internet_access'),
    desired_state TEXT NOT NULL CHECK (desired_state IN ('allow','deny')),
    enforcement_scope TEXT NOT NULL DEFAULT 'all-sites',
    reason TEXT NOT NULL,
    valid_from TEXT NOT NULL,
    valid_until TEXT,
    source_plan_id INTEGER NOT NULL REFERENCES change_plans(id) ON DELETE RESTRICT,
    status TEXT NOT NULL CHECK (status IN ('active','expired','retired')),
    updated_at TEXT NOT NULL,
    UNIQUE(subject_type, subject_key, policy_type, enforcement_scope)
);
```

- [x] **Step 2: Verify RED**

```bash
python -m pytest tests/test_netopsctl_store.py -q
```

- [x] **Step 3: Implement immutable plan rules**

After status `approved`, actor, reason, subject, operation, desired state, targets, evidence hash, steps and rollback payload are immutable. Status transitions are validated by one explicit state machine.

- [x] **Step 4: Run tests and commit**

```bash
python -m pytest tests/test_netopsctl_store.py -q
git add netopsctl tests/test_netopsctl_store.py
git commit -m "feat: add immutable network change plans"
```

## Task 18: Add Unix-socket broker and strict protocol

**Files:**
- Create: `netopsctl/protocol.py`
- Create: `netopsctl/server.py`
- Create: `netopsctl/client.py`
- Create: `deploy/netopsctl.service`
- Create: `deploy/netopsctl.socket`
- Create: `deploy/netopsctl`
- Create: `tests/test_netopsctl_protocol.py`

**Interfaces:**
- Web uses the unprivileged client.
- The dedicated `netopsctl` service performs only registered operations.

- [x] **Step 1: Write failing protocol tests**

Request envelope:

```json
{
  "protocol_version": 1,
  "request_id": "7b7f75f7-8467-44b8-9e67-5238a8198010",
  "actor": "api:network-admin",
  "action": "plan.apply",
  "payload": {"plan_key": "plan-20260722-0001"}
}
```

Allowed actions:

```text
plan.create
plan.approve
plan.apply
plan.verify
plan.rollback
policy.reconcile
status
```

Tests reject unknown fields, unknown actions, oversized payloads, newline injection, path traversal and arbitrary command strings.

- [x] **Step 2: Implement system users and read-only netctl access**

Create system user `netopsctl`. Add it to the existing `netctl` group so it can open `/var/lib/netctl/netctl.sqlite` read-only. Set the netctl data directory to `0750 netctl:netctl`, the database/WAL/SHM files to `0640 netctl:netctl`, and keep netopsctl's own database under `0750 netopsctl:netopsctl`. The daemon never writes the netctl database.

- [x] **Step 3: Implement systemd socket activation**

```ini
# deploy/netopsctl.socket
[Socket]
ListenStream=/run/netopsctl/netopsctl.sock
SocketUser=netopsctl
SocketGroup=openvpn-web
SocketMode=0660
RemoveOnStop=true

[Install]
WantedBy=sockets.target
```

```ini
# deploy/netopsctl.service
[Service]
Type=simple
User=netopsctl
Group=netopsctl
SupplementaryGroups=netctl
ExecStart=/opt/openvpn-web/.venv/bin/python -m netopsctl.server
NoNewPrivileges=true
PrivateTmp=true
ProtectSystem=strict
ProtectHome=true
ReadOnlyPaths=/var/lib/netctl
ReadWritePaths=/var/lib/netopsctl /run/netopsctl
```

RouterOS API access requires no Linux root privilege or Linux capabilities.

- [x] **Step 4: Run tests and commit**

```bash
python -m pytest tests/test_netopsctl_protocol.py -q
git add netopsctl deploy/netopsctl.service deploy/netopsctl.socket deploy/netopsctl tests/test_netopsctl_protocol.py
git commit -m "feat: add isolated network control broker"
```

## Task 19: Implement a bounded MikroTik adapter

**Files:**
- Create: `netopsctl/adapters/__init__.py`
- Create: `netopsctl/adapters/mikrotik.py`
- Create: `tests/test_netopsctl_mikrotik.py`

**Interfaces:**
- Produces only address-list and bootstrap-audit operations.
- Consumes enforcement-point configuration from `/etc/netopsctl/netopsctl.env` and protected secret references.

- [x] **Step 1: Write failing adapter tests**

Allowed operations:

```text
inspect_internet_policy_anchor
ensure_address_list_entry
remove_address_list_entry
list_managed_address_list_entries
```

Fixed boundaries:

```text
address list name: WEBOVPN-INTERNET-DENY
managed comment prefix: web_ovpn:
allowed address family: IPv4
allowed target: configured MikroTik enforcement source only
```

Tests assert idempotency, safe redaction, exact-list enforcement and rejection of arbitrary RouterOS menu paths/actions.

- [x] **Step 2: Implement pre-check and post-check**

The adapter verifies that the dedicated firewall anchor exists and matches the approved signature before any membership change:

```text
chain=forward
action=drop
src-address-list=WEBOVPN-INTERNET-DENY
out-interface-list=WAN
disabled=no
```

The adapter does not create or reorder this rule in normal `internet_access_set` plans.

- [x] **Step 3: Run tests and commit**

```bash
python -m pytest tests/test_netopsctl_mikrotik.py -q
git add netopsctl/adapters tests/test_netopsctl_mikrotik.py
git commit -m "feat: add bounded MikroTik policy adapter"
```

---

# PR 6B — asset-level Internet policy

## Task 20: Resolve asset policy targets and generate plans

**Files:**
- Create: `netopsctl/policy_resolver.py`
- Modify: `netopsctl/store.py`
- Create: `tests/test_netopsctl_internet_policy.py`

**Interfaces:**
- Reads netctl context through `connect_read_only()` and the same bounded query functions used by the public context API.
- Produces deterministic `internet_access_set` plans.

- [ ] **Step 1: Write failing resolver tests**

Eligibility rules:

```text
asset exists and is non-provisional;
at least one current IPv4 observation exists;
all selected IPs have a known site and enforcement source;
no current identity collision finding affects the asset;
asset context is fresh enough for the configured source SLA;
address-list anchor pre-check succeeds.
```

Reject:

```text
provisional IP-only asset;
ambiguous asset search;
current IPs across unresolved enforcement points;
stale identity after failed source collection;
asset with no current IP;
unknown desired state.
```

- [ ] **Step 2: Implement target resolution**

A deny plan contains one `ensure_address_list_entry` step per current IPv4 and one rollback `remove_address_list_entry` step. An allow plan contains one remove step per managed entry belonging to the asset.

Managed comment:

```text
web_ovpn:asset=<asset_key>;plan=<plan_key>
```

The angle-bracket tokens above describe serialized fields, not operator-supplied command text. The implementation uses validated values from the immutable plan.

- [ ] **Step 3: Run tests and commit**

```bash
python -m pytest tests/test_netopsctl_internet_policy.py -k plan -q
git add netopsctl/policy_resolver.py netopsctl/store.py tests/test_netopsctl_internet_policy.py
git commit -m "feat: plan asset Internet access policy"
```

## Task 21: Apply, verify, rollback and reconcile desired policy

**Files:**
- Modify: `netopsctl/server.py`
- Create: `netopsctl/reconcile.py`
- Create: `deploy/netopsctl-reconcile.service`
- Create: `deploy/netopsctl-reconcile.timer`
- Modify: `app/api.py`
- Modify: `app/models.py`
- Modify: `tests/test_netopsctl_internet_policy.py`
- Modify: `tests/test_context_api.py`
- Create: `docs/runbooks/netopsctl-internet-policy-rollout.md`

**Interfaces:**
- Produces the first end-to-end network write capability.

- [ ] **Step 1: Write failing lifecycle tests**

Tests cover:

```text
draft -> validated -> approved -> applying -> applied -> verified;
pre-check failure leaves device unchanged and plan failed;
partial step failure records applied steps and exposes deterministic rollback;
verify mismatch marks failed, not verified;
rollback removes only entries managed by the plan/asset;
repeat apply is idempotent;
reconciler updates deny entries when current DHCP IP changes;
failed netctl collection preserves previous managed entries and opens policy_stale_identity;
expired policy is retired and entries are removed only after fresh identity evidence;
web read token cannot plan/apply/rollback.
```

- [ ] **Step 2: Add HTTP endpoints**

```http
POST /api/v1/network-control/plans
POST /api/v1/network-control/plans/{plan_key}/approve
POST /api/v1/network-control/plans/{plan_key}/apply
POST /api/v1/network-control/plans/{plan_key}/verify
POST /api/v1/network-control/plans/{plan_key}/rollback
GET  /api/v1/network-control/plans/{plan_key}
GET  /api/v1/network-control/policies
```

The web app talks only to the Unix-socket client and writes an application audit entry for every request and outcome.

- [ ] **Step 3: Add reconciler timer**

The timer runs every five minutes after netctl correlation. It never creates a new desired policy; it only reconciles active policies against fresh current IP observations.

- [ ] **Step 4: Write production runbook**

The rollout order is:

```text
1. Verify HTTPS/change scopes.
2. Back up netopsctl and netctl databases.
3. Install socket/service with no policies.
4. Verify status and zero allowed arbitrary operations.
5. Manually verify or separately approve the MikroTik anchor rule.
6. Create one test asset deny plan with a short validity window.
7. Review exact target IP and rollback payload.
8. Apply and verify Internet denial while confirming internal resources remain reachable.
9. Roll back and verify Internet restoration.
10. Enable the reconciler timer.
```

- [ ] **Step 5: Run focused and full regression**

```bash
python -m pytest tests/test_netopsctl_store.py tests/test_netopsctl_protocol.py tests/test_netopsctl_mikrotik.py tests/test_netopsctl_internet_policy.py tests/test_network_change_authorization.py tests/test_context_api.py -q
python -m pytest -q
```

- [ ] **Step 6: Commit**

```bash
git add netopsctl deploy app tests docs/runbooks/netopsctl-internet-policy-rollout.md
git commit -m "feat: apply and reconcile asset Internet policy"
```

---

# PR 6C — user policy resolution and session readiness

## Task 22: Resolve eligible user policies through confirmed primary assets

**Files:**
- Modify: `netctl/user_context.py`
- Modify: `netctl/context_query.py`
- Modify: `netopsctl/policy_resolver.py`
- Modify: `tests/test_netctl_user_context.py`
- Modify: `tests/test_netopsctl_internet_policy.py`

**Interfaces:**
- Produces user-level plan resolution without changing the enforcement mechanism.

- [ ] **Step 1: Write failing tests**

Accept only:

```text
one active confirmed primary_user binding;
confidence exactly 100;
asset is not shared;
binding is valid at plan creation and apply time;
asset passes all asset-level eligibility checks.
```

Reject multiple primary assets, shared workstations, candidate bindings, expired bindings and session-only evidence.

- [ ] **Step 2: Implement resolution and audit chain**

The resulting plan retains both:

```text
requested subject: user:<user_key>
resolved enforcement subject: asset:<asset_key>
```

- [ ] **Step 3: Run tests and commit**

```bash
python -m pytest tests/test_netctl_user_context.py tests/test_netopsctl_internet_policy.py -q
git add netctl/user_context.py netctl/context_query.py netopsctl/policy_resolver.py tests/test_netctl_user_context.py tests/test_netopsctl_internet_policy.py
git commit -m "feat: resolve user Internet policy through primary asset"
```

## Task 23: Publish a bounded network-session ingestion contract

**Files:**
- Modify: `netctl/user_context.py`
- Modify: `netctl/cli.py`
- Modify: `app/api.py`
- Modify: `app/models.py`
- Modify: `tests/test_netctl_user_context.py`
- Modify: `tests/test_context_api.py`

**Interfaces:**
- Supports future captive portal, RADIUS and endpoint agents.
- Does not implement those integrations in this PR.

- [ ] **Step 1: Write failing tests**

```http
POST /api/v1/context/network-sessions
POST /api/v1/context/network-sessions/{session_key}/close
GET  /api/v1/context/users/{user_key}/sessions
```

Session evidence may suggest a candidate binding but never confirms or replaces a primary binding automatically.

- [ ] **Step 2: Implement safe ingestion**

Require a stable `session_key`, known user, source type, timestamps and bounded evidence. Asset may be null when only login/IP evidence is available.

- [ ] **Step 3: Run tests and commit**

```bash
python -m pytest tests/test_netctl_user_context.py tests/test_context_api.py -q
git add netctl/user_context.py netctl/cli.py app/api.py app/models.py tests/test_netctl_user_context.py tests/test_context_api.py
git commit -m "feat: add network session context contract"
```

---

## 5. Explicitly deferred work

The following items require separate approved plans after asset-level Internet policy is proven:

```text
switch-port shutdown or enable
access-port VLAN/PVID changes
switch description writes
DHCP reservation changes
Kea deployment
DNS record creation/deletion
automatic firewall-rule reordering
arbitrary RouterOS command execution
full captive portal implementation
802.1X/RADIUS enforcement
automatic asset merge
active endpoint agent deployment
```

---

## 6. Cross-delivery acceptance tests

### Correlated asset card

Given a runtime asset with MAC `C0:9B:F4:61:4B:CD`, the context API returns:

```text
runtime asset and interface
current IP/hostname observations
intent binding when configured
TP-Link ITO as switch
port48 as selected port
VLAN20
backbone path toward the configured core source
confidence and supporting FDB/topology evidence
no invented user owner
```

### Ambiguous attachment

When one MAC is learned on two equal-depth non-uplink ports, the API returns `ambiguous`, both candidates and an open finding. It does not choose one port.

### Collector failure

After a successful topology/attachment run, an SNMP timeout and a failed correlation attempt leave the previous current topology and attachment unchanged.

### Path explanation

A path request identifies the selected routing table/route and returns `unknown` when an unsupported firewall matcher could alter the result.

### Internet deny

For an eligible personal asset:

```text
plan shows exact current IP and enforcement source;
apply adds only WEBOVPN-INTERNET-DENY entries;
Internet path is denied;
internal resources remain reachable;
verify records the observed post-condition;
rollback removes only managed entries and restores Internet;
a later DHCP address change is reconciled without changing the stable policy subject.
```

---

## 7. Verification commands for every PR

```bash
python -m compileall -q netctl app
python -m pytest -q
git diff --check
```

After `netopsctl` is introduced:

```bash
python -m compileall -q netctl netopsctl app
```

For migrations:

```bash
python -m pytest tests/test_netctl_topology.py tests/test_netctl_user_context.py tests/test_netctl_route_metadata.py tests/test_netctl_path_facts.py -q
```

For control-plane work:

```bash
python -m pytest tests/test_network_change_authorization.py tests/test_netopsctl_store.py tests/test_netopsctl_protocol.py tests/test_netopsctl_mikrotik.py tests/test_netopsctl_internet_policy.py -q
```

Expected final result for each PR:

```text
focused suite: pass
full suite: pass
git diff --check: no output
compileall: exit 0
no live device contacted by tests
```

---

## 8. Production evidence and closure

After PR 4C, commit a sanitized record:

```text
docs/verification/netctl-correlated-context-readiness.md
```

It records only:

```text
release SHA
migration ledger
aggregate switch/link/attachment counts
status counts confirmed/ambiguous/uplink_only/unresolved
one sanitized acceptance example by stable test label, not production MAC/IP
service/timer health
SQLite integrity
rollback backup path and checksum
```

After PR 6B, commit:

```text
docs/verification/netopsctl-internet-policy-readiness.md
```

It records only:

```text
release SHA
netopsctl migration ledger
socket/service health
one approved test-plan key
plan/apply/verify/rollback statuses
confirmation that internal reachability remained available
confirmation that Internet access was restored after rollback
no credentials, raw addresses or RouterOS configuration dump
```

The phase is complete only after both evidence documents are merged and temporary worktrees/branches are removed after confirming all commits exist in `origin/main`.
