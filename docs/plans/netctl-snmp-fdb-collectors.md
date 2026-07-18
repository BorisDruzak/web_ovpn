# Netctl Multi-Vendor SNMP/FDB Collector Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Implement read-only, multi-vendor SNMP switch collection with normalized ports, transactional current FDB state, event history, interface counter deltas, optional VLAN/STP facts, and failure isolation across sources.

**Architecture:** Add a dedicated `snmp_switch` driver and switch-specific persistence path without changing the established RouterOS/runtime-identity behavior. Use PySNMP with numeric OIDs and structured varbinds, normalize each vendor through explicit profiles, and replace current FDB state only after a fully successful FDB group. Keep Git intent, runtime assets, switch observations, and operational findings separate.

**Tech Stack:** Python 3.12, SQLite migrations, PySNMP 7.1.27, existing `netctl` driver/CLI framework, pytest, GitHub Actions, systemd deployment runbooks.

## Global Constraints

- Implementation baseline is `web_ovpn/main` commit `67ca3e26e7e755d612505937dcef90409cf73400` or a later fast-forward `main` containing it.
- Existing migrations `1` through `4` are immutable. All switch schema changes use migration `5` or later.
- SNMP is read-only. Do not implement SNMP SET, port shutdown, VLAN changes, description changes, topology writes, or configuration backup through SNMP.
- The initial supported protocol is SNMPv2c because all proven switch profiles use communities. The source schema must reject unsupported versions rather than silently downgrade.
- SNMP credentials remain outside Git in `/etc/netctl/secrets.env` or process environment.
- Community values must never appear in source YAML, database rows, logs, exception text, CLI/API output, raw captures, fixtures, or Git history.
- Numeric OIDs are authoritative. Do not download MIBs at runtime and do not require internet access from the collector host.
- A failed source must not fail unrelated sources.
- A failed FDB group must preserve the previous `current_switch_fdb` state and must not emit `disappeared` events.
- `success_empty` is distinct from timeout, unsupported, authentication/view failure, and parse error. Only a confirmed successful empty FDB may replace current FDB with an empty set.
- Q-BRIDGE is preferred. Legacy dot1d FDB is used only when Q-BRIDGE is explicitly unsupported, not merely when it times out or fails parsing.
- LLDP is optional and must never be required for a successful switch collection.
- Different MAC addresses are never merged automatically into one runtime asset.
- Switch source-to-runtime identity is explicit. A collector may resolve an operator-configured runtime asset key but must not create or confirm an asset-intent binding automatically.
- Raw SNMP capture is disabled by default, diagnostic only, sanitized, outside Git, and retained for at most 24 hours.
- Current FDB is stored as current state. History is stored as appeared/moved/disappeared events, not complete repeated snapshots.
- Counter findings are computed from deltas. Absolute cumulative values alone are not findings.
- Tests must use sanitized fixtures and must not contact live network devices.
- The first production pilot is DGS. Rollout order is DGS, SNR, TP-Link, then CSS326.
- `mikrotik-hex` SSH timeout is unrelated to this collector and must not block SNMP implementation.

---

## 1. Delivery and pull-request boundaries

Implement this plan as three independently reviewable pull requests.

### PR 3A — generic core and DGS vertical slice

```text
migration 5 switch schema
SNMP source configuration and secret resolution
PySNMP transport and outcome classification
system/ifTable/ifXTable/bridge mapping
DGS Q-BRIDGE fixture and profile
transactional FDB current state and events
CLI integration and DGS production pilot
```

PR 3A is complete only when two identical DGS collections produce no duplicate FDB events and a simulated failed collection preserves the prior current FDB.

### PR 3B — SNR, TP-Link and CSS326 profiles

```text
SNR ifIndex/po1 normalization
SNR VLAN/PVID and STP facts
TP-Link physical-port to 49152+ifIndex normalization
CSS326 legacy-FDB fallback
optional LLDP storage when rows exist
all published fixture assertions
```

PR 3B is complete only when every known fixture in Issue #5 and `network_configuration/docs/architecture/snmp-collector-contract.md` normalizes to the expected source, VLAN and port.

### PR 3C — counters, findings, retention and full rollout

```text
counter samples and reset/wrap-safe deltas
switch operational findings
retention pruning
status/inspect CLI
production backup and rollout for all switches
sanitized readiness evidence
```

PR 3C closes Issue #5 after production evidence is committed.

---

## 2. File map

### New SNMP package

```text
netctl/snmp/__init__.py
netctl/snmp/models.py
netctl/snmp/oids.py
netctl/snmp/transport.py
netctl/snmp/outcomes.py
netctl/snmp/system.py
netctl/snmp/interfaces.py
netctl/snmp/fdb.py
netctl/snmp/vlan.py
netctl/snmp/stp.py
netctl/snmp/lldp.py
netctl/snmp/profiles.py
netctl/snmp/collector.py
```

Responsibilities:

- `models.py`: immutable normalized dataclasses and enums.
- `oids.py`: numeric standard OIDs only.
- `transport.py`: PySNMPv2c GET and BULK WALK, typed varbind conversion, timeout/error handling.
- `outcomes.py`: explicit capability outcome classification and secret-safe error text.
- `system.py`: system scalar parsing.
- `interfaces.py`: ifTable/ifXTable, bridge-port mapping and counter extraction.
- `fdb.py`: Q-BRIDGE/legacy parsing and normalized MAC/VLAN rows.
- `vlan.py`: Q-BRIDGE VLAN bitmap and PVID parsing.
- `stp.py`: STP/RSTP root facts.
- `lldp.py`: optional LLDP local/remote parsing.
- `profiles.py`: generic, DGS, SNR, TP-Link and CSS326 port normalization.
- `collector.py`: capability sequence, fallback rules and normalized switch snapshot.

### New driver and persistence files

```text
netctl/drivers/snmp_switch.py
netctl/switch_store.py
netctl/switch_queries.py
```

Responsibilities:

- `snmp_switch.py`: adapt source configuration and secrets to the SNMP collector.
- `switch_store.py`: collection-run lifecycle, transactional current state, events, samples, findings and retention.
- `switch_queries.py`: read-only status, capabilities, ports, FDB, events and findings queries.

### Files modified

```text
requirements.txt
netctl/config.py
netctl/db.py
netctl/migrations.py
netctl/drivers/__init__.py
netctl/cli.py
.github/workflows/verify-netctl-runtime.yml
README.md
```

### Tests and fixtures

```text
tests/test_netctl_snmp_config.py
tests/test_netctl_snmp_transport.py
tests/test_netctl_snmp_parsers.py
tests/test_netctl_snmp_profiles.py
tests/test_netctl_switch_store.py
tests/test_netctl_switch_cli.py
tests/fixtures/snmp/dgs.json
tests/fixtures/snmp/snr.json
tests/fixtures/snmp/tplink.json
tests/fixtures/snmp/css326.json
```

Fixture JSON contains only numeric OIDs, SNMP value type and sanitized value. It contains no community, username, host credential, raw command line or production configuration backup.

---

## 3. Normalized contracts

### 3.1 Outcome values

```python
from enum import StrEnum


class SnmpOutcome(StrEnum):
    SUCCESS_WITH_ROWS = "success_with_rows"
    SUCCESS_EMPTY = "success_empty"
    UNSUPPORTED_NO_SUCH_OBJECT = "unsupported_no_such_object"
    TIMEOUT = "timeout"
    AUTH_OR_VIEW_FAILURE = "auth_or_view_failure"
    PARSE_ERROR = "parse_error"
```

Do not add a generic `unavailable` value.

### 3.2 Varbind and capability result

```python
from dataclasses import dataclass, field
from typing import Any


@dataclass(frozen=True)
class SnmpVarBind:
    oid: tuple[int, ...]
    value_type: str
    value: int | str | bytes


@dataclass(frozen=True)
class CapabilityResult:
    capability: str
    outcome: SnmpOutcome
    rows: tuple[SnmpVarBind, ...] = ()
    error_code: str = ""
    error_message: str = ""
    details: dict[str, Any] = field(default_factory=dict)
```

### 3.3 Normalized switch records

```python
@dataclass(frozen=True)
class SwitchSystem:
    sys_descr: str
    sys_object_id: str
    sys_name: str
    sys_location: str
    sys_uptime_ticks: int | None


@dataclass(frozen=True)
class SwitchPort:
    port_key: str
    if_index: int | None
    bridge_port: int | None
    physical_port: int | None
    name: str
    alias: str
    mac: str | None
    admin_status: str
    oper_status: str
    speed_bps: int | None


@dataclass(frozen=True)
class SwitchFdbEntry:
    vlan_key: str
    vlan_id: int | None
    mac: str
    port_key: str
    bridge_port: int | None
    if_index: int | None
    physical_port: int | None
    port_name: str
    status: str


@dataclass(frozen=True)
class SwitchCounterSample:
    port_key: str
    if_index: int | None
    sys_uptime_ticks: int | None
    in_errors: int | None
    in_discards: int | None
    out_errors: int | None
    out_discards: int | None
    in_octets: int | None
    out_octets: int | None
```

### 3.4 Switch snapshot

```python
@dataclass(frozen=True)
class SwitchSnapshot:
    snapshot_kind: str
    profile_id: str
    profile_fingerprint: str
    system: SwitchSystem
    ports: tuple[SwitchPort, ...]
    fdb: tuple[SwitchFdbEntry, ...]
    vlan_memberships: tuple[dict[str, Any], ...]
    stp: dict[str, Any] | None
    lldp_neighbors: tuple[dict[str, Any], ...]
    counter_samples: tuple[SwitchCounterSample, ...]
    capabilities: tuple[CapabilityResult, ...]
```

`snapshot_kind` is always `"switch"` for this driver.

---

# PR 3A — generic core and DGS vertical slice

## Task 1: Add migration 5 and extensible source options

**Files:**
- Modify: `netctl/migrations.py`
- Modify: `netctl/config.py`
- Modify: `netctl/db.py`
- Create: `tests/test_netctl_snmp_config.py`

**Interfaces:**
- Produces migration version `5` and `network_sources.driver_options_json`.
- Produces normalized source keys under `source["driver_options"]`.
- Keeps source secrets outside `driver_options_json`.

- [ ] **Step 1: Write failing migration and configuration tests**

Tests must assert:

```text
schema_migrations contains [1,2,3,4,5]
network_sources has driver_options_json NOT NULL DEFAULT '{}'
reopening is idempotent
migration-5 failure rolls back schema and ledger
snmp source scalar YAML normalizes into driver_options
public source output contains no community value
unsupported snmp_version is rejected
```

Use this source fixture:

```yaml
name: switch-dgs-server
driver: snmp_switch
host: 192.168.100.16
port: 161
username: ""
secret_ref: switch_dgs_server_snmp
site: main
role: access-switch
enabled: false
snmp_version: 2c
snmp_timeout_seconds: 2
snmp_retries: 1
snmp_max_repetitions: 25
snmp_profile_hint: dgs
snmp_capability_ttl_hours: 168
snmp_raw_capture: false
snmp_raw_retention_hours: 24
snmp_counter_retention_days: 14
snmp_event_retention_days: 180
runtime_asset_key: mac:BC:22:28:0C:EF:E0
intent_context_id: sosn-admin-network
intent_stable_id: dlink-dgs-1210-52-server-switch
```

- [ ] **Step 2: Verify RED**

```bash
python -m pytest tests/test_netctl_snmp_config.py -q
```

Expected: failure because migration 5 and SNMP options do not exist.

- [ ] **Step 3: Add migration 5 using individual `conn.execute()` calls**

Migration 5 creates these tables and the source options column:

```sql
ALTER TABLE network_sources
ADD COLUMN driver_options_json TEXT NOT NULL DEFAULT '{}';

CREATE TABLE switch_devices (
    source_id INTEGER PRIMARY KEY REFERENCES network_sources(id) ON DELETE RESTRICT,
    runtime_asset_id INTEGER REFERENCES assets(id) ON DELETE RESTRICT,
    intent_context_id TEXT NOT NULL DEFAULT '',
    intent_stable_id TEXT NOT NULL DEFAULT '',
    profile_id TEXT NOT NULL DEFAULT 'generic',
    profile_fingerprint TEXT NOT NULL DEFAULT '',
    sys_object_id TEXT NOT NULL DEFAULT '',
    sys_descr TEXT NOT NULL DEFAULT '',
    sys_name TEXT NOT NULL DEFAULT '',
    sys_location TEXT NOT NULL DEFAULT '',
    sys_uptime_ticks INTEGER,
    last_success_at TEXT,
    updated_at TEXT NOT NULL
);

CREATE TABLE switch_collection_runs (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    source_id INTEGER NOT NULL REFERENCES network_sources(id) ON DELETE RESTRICT,
    started_at TEXT NOT NULL,
    finished_at TEXT,
    status TEXT NOT NULL CHECK (status IN ('running','success','partial','failed')),
    profile_id TEXT NOT NULL DEFAULT '',
    sys_uptime_ticks INTEGER,
    error_class TEXT NOT NULL DEFAULT '',
    error_message TEXT NOT NULL DEFAULT '',
    outcomes_json TEXT NOT NULL DEFAULT '{}',
    counts_json TEXT NOT NULL DEFAULT '{}'
);
CREATE INDEX switch_collection_runs_source_started_idx
    ON switch_collection_runs(source_id, started_at DESC, id DESC);

CREATE TABLE switch_capabilities (
    source_id INTEGER NOT NULL REFERENCES network_sources(id) ON DELETE RESTRICT,
    capability TEXT NOT NULL,
    outcome TEXT NOT NULL CHECK (outcome IN (
        'success_with_rows','success_empty','unsupported_no_such_object',
        'timeout','auth_or_view_failure','parse_error'
    )),
    rows_seen INTEGER NOT NULL DEFAULT 0,
    profile_fingerprint TEXT NOT NULL DEFAULT '',
    checked_at TEXT NOT NULL,
    expires_at TEXT NOT NULL,
    details_json TEXT NOT NULL DEFAULT '{}',
    PRIMARY KEY(source_id, capability)
);

CREATE TABLE switch_ports (
    source_id INTEGER NOT NULL REFERENCES network_sources(id) ON DELETE RESTRICT,
    port_key TEXT NOT NULL,
    if_index INTEGER,
    bridge_port INTEGER,
    physical_port INTEGER,
    name TEXT NOT NULL DEFAULT '',
    alias TEXT NOT NULL DEFAULT '',
    mac TEXT,
    admin_status TEXT NOT NULL DEFAULT 'unknown',
    oper_status TEXT NOT NULL DEFAULT 'unknown',
    speed_bps INTEGER,
    last_seen_at TEXT NOT NULL,
    collector_run_id INTEGER NOT NULL REFERENCES switch_collection_runs(id) ON DELETE RESTRICT,
    PRIMARY KEY(source_id, port_key)
);
CREATE INDEX switch_ports_source_ifindex_idx ON switch_ports(source_id, if_index);
CREATE INDEX switch_ports_source_bridge_idx ON switch_ports(source_id, bridge_port);

CREATE TABLE current_switch_fdb (
    source_id INTEGER NOT NULL REFERENCES network_sources(id) ON DELETE RESTRICT,
    vlan_key TEXT NOT NULL,
    vlan_id INTEGER,
    mac TEXT NOT NULL,
    port_key TEXT NOT NULL,
    bridge_port INTEGER,
    if_index INTEGER,
    physical_port INTEGER,
    port_name TEXT NOT NULL DEFAULT '',
    status TEXT NOT NULL DEFAULT 'unknown',
    first_seen_at TEXT NOT NULL,
    last_seen_at TEXT NOT NULL,
    collector_run_id INTEGER NOT NULL REFERENCES switch_collection_runs(id) ON DELETE RESTRICT,
    PRIMARY KEY(source_id, vlan_key, mac)
);
CREATE INDEX current_switch_fdb_source_port_idx
    ON current_switch_fdb(source_id, port_key, vlan_key);
CREATE INDEX current_switch_fdb_mac_idx
    ON current_switch_fdb(mac, source_id);

CREATE TABLE switch_fdb_events (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    source_id INTEGER NOT NULL REFERENCES network_sources(id) ON DELETE RESTRICT,
    vlan_key TEXT NOT NULL,
    vlan_id INTEGER,
    mac TEXT NOT NULL,
    event_type TEXT NOT NULL CHECK (event_type IN ('appeared','moved','disappeared')),
    old_port_key TEXT NOT NULL DEFAULT '',
    new_port_key TEXT NOT NULL DEFAULT '',
    observed_at TEXT NOT NULL,
    collector_run_id INTEGER NOT NULL REFERENCES switch_collection_runs(id) ON DELETE RESTRICT,
    details_json TEXT NOT NULL DEFAULT '{}'
);
CREATE INDEX switch_fdb_events_source_time_idx
    ON switch_fdb_events(source_id, observed_at DESC, id DESC);
CREATE INDEX switch_fdb_events_mac_time_idx
    ON switch_fdb_events(mac, observed_at DESC, id DESC);

CREATE TABLE switch_port_vlans (
    source_id INTEGER NOT NULL REFERENCES network_sources(id) ON DELETE RESTRICT,
    vlan_id INTEGER NOT NULL,
    port_key TEXT NOT NULL,
    egress INTEGER NOT NULL CHECK (egress IN (0,1)),
    untagged INTEGER NOT NULL CHECK (untagged IN (0,1)),
    pvid INTEGER NOT NULL CHECK (pvid IN (0,1)),
    last_seen_at TEXT NOT NULL,
    collector_run_id INTEGER NOT NULL REFERENCES switch_collection_runs(id) ON DELETE RESTRICT,
    PRIMARY KEY(source_id, vlan_id, port_key)
);

CREATE TABLE switch_stp_state (
    source_id INTEGER PRIMARY KEY REFERENCES network_sources(id) ON DELETE RESTRICT,
    protocol TEXT NOT NULL DEFAULT '',
    root_bridge_mac TEXT NOT NULL DEFAULT '',
    root_port_raw INTEGER,
    root_port_key TEXT NOT NULL DEFAULT '',
    root_path_cost INTEGER,
    topology_changes INTEGER,
    last_seen_at TEXT NOT NULL,
    collector_run_id INTEGER NOT NULL REFERENCES switch_collection_runs(id) ON DELETE RESTRICT
);

CREATE TABLE switch_neighbors (
    source_id INTEGER NOT NULL REFERENCES network_sources(id) ON DELETE RESTRICT,
    local_port_key TEXT NOT NULL,
    chassis_id TEXT NOT NULL,
    remote_port_id TEXT NOT NULL,
    system_name TEXT NOT NULL DEFAULT '',
    management_address TEXT NOT NULL DEFAULT '',
    last_seen_at TEXT NOT NULL,
    collector_run_id INTEGER NOT NULL REFERENCES switch_collection_runs(id) ON DELETE RESTRICT,
    PRIMARY KEY(source_id, local_port_key, chassis_id, remote_port_id)
);

CREATE TABLE switch_counter_samples (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    source_id INTEGER NOT NULL REFERENCES network_sources(id) ON DELETE RESTRICT,
    port_key TEXT NOT NULL,
    if_index INTEGER,
    sys_uptime_ticks INTEGER,
    in_errors INTEGER,
    in_discards INTEGER,
    out_errors INTEGER,
    out_discards INTEGER,
    in_octets INTEGER,
    out_octets INTEGER,
    sampled_at TEXT NOT NULL,
    collector_run_id INTEGER NOT NULL REFERENCES switch_collection_runs(id) ON DELETE RESTRICT
);
CREATE INDEX switch_counter_samples_source_port_time_idx
    ON switch_counter_samples(source_id, port_key, sampled_at DESC, id DESC);

CREATE TABLE switch_findings (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    finding_key TEXT NOT NULL UNIQUE,
    source_id INTEGER NOT NULL REFERENCES network_sources(id) ON DELETE RESTRICT,
    port_key TEXT NOT NULL DEFAULT '',
    finding_type TEXT NOT NULL,
    severity TEXT NOT NULL CHECK (severity IN ('info','warning','error','critical')),
    status TEXT NOT NULL CHECK (status IN ('open','acknowledged','resolved')),
    first_seen_at TEXT NOT NULL,
    last_seen_at TEXT NOT NULL,
    details_json TEXT NOT NULL DEFAULT '{}'
);
CREATE INDEX switch_findings_status_type_idx
    ON switch_findings(status, finding_type, last_seen_at DESC);
```

Do not use `executescript()` inside migration 5. Do not call `commit()` from migration 5.

- [ ] **Step 4: Add normalized driver options**

`normalize_source()` must produce:

```python
"driver_options": {
    "snmp_version": "2c",
    "timeout_seconds": 2,
    "retries": 1,
    "max_repetitions": 25,
    "profile_hint": "dgs",
    "capability_ttl_hours": 168,
    "raw_capture": False,
    "raw_retention_hours": 24,
    "counter_retention_days": 14,
    "event_retention_days": 180,
    "runtime_asset_key": "mac:BC:22:28:0C:EF:E0",
    "intent_context_id": "sosn-admin-network",
    "intent_stable_id": "dlink-dgs-1210-52-server-switch",
}
```

Store this dictionary as sorted JSON in `network_sources.driver_options_json`. Decode it in `get_source()` and `list_sources()`. `source_public()` may expose non-secret options but must never expose resolved secret values.

- [ ] **Step 5: Verify GREEN**

```bash
python -m pytest tests/test_netctl_snmp_config.py -q
```

- [ ] **Step 6: Commit**

```bash
git add netctl/migrations.py netctl/config.py netctl/db.py tests/test_netctl_snmp_config.py
git commit -m "feat: add switch collection schema and source options"
```

---

## Task 2: Add PySNMP transport and explicit outcome classification

**Files:**
- Modify: `requirements.txt`
- Create: `netctl/snmp/__init__.py`
- Create: `netctl/snmp/models.py`
- Create: `netctl/snmp/oids.py`
- Create: `netctl/snmp/outcomes.py`
- Create: `netctl/snmp/transport.py`
- Create: `tests/test_netctl_snmp_transport.py`

**Interfaces:**
- Produces `SnmpTransport.get()` and `SnmpTransport.walk()`.
- Produces secret-safe `CapabilityResult` objects.
- Uses numeric OIDs with `lookupMib=False`.

- [ ] **Step 1: Pin the dependency**

Append:

```text
pysnmp==7.1.27
```

- [ ] **Step 2: Define numeric OIDs**

`netctl/snmp/oids.py` must contain at least:

```python
SYS_DESCR = "1.3.6.1.2.1.1.1.0"
SYS_OBJECT_ID = "1.3.6.1.2.1.1.2.0"
SYS_UPTIME = "1.3.6.1.2.1.1.3.0"
SYS_NAME = "1.3.6.1.2.1.1.5.0"
SYS_LOCATION = "1.3.6.1.2.1.1.6.0"

IF_INDEX = "1.3.6.1.2.1.2.2.1.1"
IF_DESCR = "1.3.6.1.2.1.2.2.1.2"
IF_TYPE = "1.3.6.1.2.1.2.2.1.3"
IF_SPEED = "1.3.6.1.2.1.2.2.1.5"
IF_PHYS_ADDRESS = "1.3.6.1.2.1.2.2.1.6"
IF_ADMIN_STATUS = "1.3.6.1.2.1.2.2.1.7"
IF_OPER_STATUS = "1.3.6.1.2.1.2.2.1.8"
IF_IN_DISCARDS = "1.3.6.1.2.1.2.2.1.13"
IF_IN_ERRORS = "1.3.6.1.2.1.2.2.1.14"
IF_OUT_DISCARDS = "1.3.6.1.2.1.2.2.1.19"
IF_OUT_ERRORS = "1.3.6.1.2.1.2.2.1.20"

IF_NAME = "1.3.6.1.2.1.31.1.1.1.1"
IF_HC_IN_OCTETS = "1.3.6.1.2.1.31.1.1.1.6"
IF_HIGH_SPEED = "1.3.6.1.2.1.31.1.1.1.15"
IF_ALIAS = "1.3.6.1.2.1.31.1.1.1.18"
IF_HC_OUT_OCTETS = "1.3.6.1.2.1.31.1.1.1.10"

DOT1D_BASE_PORT_IFINDEX = "1.3.6.1.2.1.17.1.4.1.2"
DOT1D_FDB_ADDRESS = "1.3.6.1.2.1.17.4.3.1.1"
DOT1D_FDB_PORT = "1.3.6.1.2.1.17.4.3.1.2"
DOT1D_FDB_STATUS = "1.3.6.1.2.1.17.4.3.1.3"

DOT1Q_FDB_PORT = "1.3.6.1.2.1.17.7.1.2.2.1.2"
DOT1Q_FDB_STATUS = "1.3.6.1.2.1.17.7.1.2.2.1.3"
DOT1Q_VLAN_CURRENT_EGRESS = "1.3.6.1.2.1.17.7.1.4.2.1.4"
DOT1Q_VLAN_CURRENT_UNTAGGED = "1.3.6.1.2.1.17.7.1.4.2.1.5"
DOT1Q_VLAN_STATIC_NAME = "1.3.6.1.2.1.17.7.1.4.3.1.1"
DOT1Q_VLAN_STATIC_EGRESS = "1.3.6.1.2.1.17.7.1.4.3.1.2"
DOT1Q_VLAN_STATIC_UNTAGGED = "1.3.6.1.2.1.17.7.1.4.3.1.4"
DOT1Q_PVID = "1.3.6.1.2.1.17.7.1.4.5.1.1"

DOT1D_STP_PROTOCOL = "1.3.6.1.2.1.17.2.1.0"
DOT1D_STP_TOPOLOGY_CHANGES = "1.3.6.1.2.1.17.2.4.0"
DOT1D_STP_DESIGNATED_ROOT = "1.3.6.1.2.1.17.2.5.0"
DOT1D_STP_ROOT_COST = "1.3.6.1.2.1.17.2.6.0"
DOT1D_STP_ROOT_PORT = "1.3.6.1.2.1.17.2.7.0"
```

- [ ] **Step 3: Write transport tests**

Test:

```text
integer, octet string, MAC bytes and OID values convert without pretty-print ambiguity
timeout becomes TIMEOUT
authorizationError/noAccess becomes AUTH_OR_VIEW_FAILURE
NoSuchObject/NoSuchInstance becomes UNSUPPORTED_NO_SUCH_OBJECT
end-of-MIB with zero rows becomes SUCCESS_EMPTY
rows become SUCCESS_WITH_ROWS
community is absent from exceptions and repr output
transport works when invoked from a thread that already has an asyncio loop
SnmpEngine dispatcher is closed after success and failure
```

- [ ] **Step 4: Verify RED**

```bash
python -m pytest tests/test_netctl_snmp_transport.py -q
```

- [ ] **Step 5: Implement the transport**

Use `pysnmp.hlapi.v3arch.asyncio` with `CommunityData`, `UdpTransportTarget.create`, `get_cmd` and `bulk_walk_cmd`. The collector entry point is synchronous, therefore run one complete asynchronous source collection inside a dedicated worker thread:

```python
from concurrent.futures import ThreadPoolExecutor
import asyncio
from collections.abc import Awaitable, Callable
from typing import TypeVar

T = TypeVar("T")


def run_async_collection(factory: Callable[[], Awaitable[T]]) -> T:
    with ThreadPoolExecutor(max_workers=1, thread_name_prefix="netctl-snmp") as executor:
        return executor.submit(lambda: asyncio.run(factory())).result()
```

Do not create one thread per OID. Create one worker/event loop per source collection and execute all GET/WALK operations on that loop.

Use:

```python
CommunityData(community, mpModel=1)
await UdpTransportTarget.create(
    (source["host"], int(source["port"])),
    timeout=float(options["timeout_seconds"]),
    retries=int(options["retries"]),
)
```

Set `lookupMib=False` and `lexicographicMode=False`. Close the SNMP dispatcher in `finally`.

Resolve the community only from:

```text
NETCTL_SECRET_<NORMALIZED_SECRET_REF>_COMMUNITY
```

Add:

```python
def snmp_community_env_name(secret_ref: str) -> str:
    token = "".join(ch if ch.isalnum() else "_" for ch in secret_ref.upper())
    return f"NETCTL_SECRET_{token}_COMMUNITY"
```

A missing community raises `ValueError("SNMP community secret is not configured")` without naming or printing the secret value.

- [ ] **Step 6: Verify GREEN and commit**

```bash
python -m pytest tests/test_netctl_snmp_transport.py -q
git add requirements.txt netctl/snmp tests/test_netctl_snmp_transport.py
git commit -m "feat: add structured SNMP transport"
```

---

## Task 3: Parse system, interfaces and bridge mapping

**Files:**
- Create: `netctl/snmp/system.py`
- Create: `netctl/snmp/interfaces.py`
- Create: `netctl/snmp/profiles.py`
- Create: `tests/test_netctl_snmp_parsers.py`
- Create: `tests/test_netctl_snmp_profiles.py`

**Interfaces:**
- Produces `parse_system()`, `parse_interfaces()` and `detect_profile()`.
- Produces normalized `SwitchPort.port_key` values.

- [ ] **Step 1: Write failing parser tests**

Test:

```text
system scalars are required and typed
missing optional sysLocation becomes empty string
ifTable and ifXTable join by ifIndex
ifHighSpeed is used when ifSpeed is saturated or zero
bridge-port mapping joins bridge port to ifIndex
invalid duplicate ifIndex is a parse error
profile_hint overrides auto-detection only when it names a supported profile
SNR is detected by sysObjectID prefix 1.3.6.1.4.1.57206
DGS, TP-Link and CSS326 are detected by sysDescr patterns
unknown devices use generic profile
```

- [ ] **Step 2: Verify RED**

```bash
python -m pytest tests/test_netctl_snmp_parsers.py tests/test_netctl_snmp_profiles.py -q
```

- [ ] **Step 3: Implement profile contracts**

```python
class PortProfile:
    profile_id: str

    def port_key(
        self,
        *,
        raw_fdb_port: int,
        fdb_mode: str,
        bridge_to_ifindex: dict[int, int],
        ports_by_ifindex: dict[int, SwitchPort],
    ) -> str:
        raise NotImplementedError
```

Profiles:

```text
generic: raw bridge port -> dot1dBasePortIfIndex -> ifIndex port
DGS: Q-BRIDGE raw port -> bridge mapping; physical port equals bridge port
SNR: Q-BRIDGE normal values are ifIndex; raw 31071 maps to ifIndex100001/po1
TP-Link: Q-BRIDGE raw value is physical port N; ifIndex is 49152+N
CSS326: legacy raw bridge port -> one-to-one ifIndex/physical port
```

Port keys:

```text
physical ports: physical:<number>
known named LAG: lag:<lowercase name>
generic unresolved ifIndex: ifindex:<number>
```

Do not return a fabricated port when mapping is ambiguous. Raise a parse error so current FDB is preserved.

- [ ] **Step 4: Verify GREEN and commit**

```bash
python -m pytest tests/test_netctl_snmp_parsers.py tests/test_netctl_snmp_profiles.py -q
git add netctl/snmp/system.py netctl/snmp/interfaces.py netctl/snmp/profiles.py tests/test_netctl_snmp_parsers.py tests/test_netctl_snmp_profiles.py
git commit -m "feat: normalize SNMP switch system and ports"
```

---

## Task 4: Implement Q-BRIDGE and legacy FDB parsers

**Files:**
- Create: `netctl/snmp/fdb.py`
- Modify: `tests/test_netctl_snmp_parsers.py`

**Interfaces:**
- Produces `parse_qbridge_fdb()` and `parse_legacy_fdb()`.
- Consumes a `PortProfile`, bridge mapping and normalized ports.

- [ ] **Step 1: Write failing tests**

Q-BRIDGE tests:

```text
OID suffix vlan.mac1.mac2.mac3.mac4.mac5.mac6 is decoded
MAC is uppercase colon notation
VLAN 20 is preserved
status is joined by identical table index
malformed MAC octet rejects the entire FDB group
unknown port mapping rejects the entire FDB group
```

Legacy tests:

```text
address and port tables join by MAC index
vlan_key is 'unknown' and vlan_id is NULL
status joins when available
CSS bridge port resolves one-to-one
```

Fallback tests:

```text
Q-BRIDGE success_with_rows -> use Q-BRIDGE
Q-BRIDGE success_empty -> use confirmed empty Q-BRIDGE
Q-BRIDGE unsupported -> query legacy
Q-BRIDGE timeout/auth/parse -> do not query legacy and preserve current state
both FDB modes unsupported -> source partial/failed without replacement
```

- [ ] **Step 2: Verify RED**

```bash
python -m pytest tests/test_netctl_snmp_parsers.py -k "fdb or qbridge or legacy" -q
```

- [ ] **Step 3: Implement exact current-state keys**

```python
def fdb_key(entry: SwitchFdbEntry) -> tuple[str, str]:
    return entry.vlan_key, entry.mac
```

`vlan_key` is `str(vlan_id)` for Q-BRIDGE and `"unknown"` for legacy. This avoids SQLite NULL uniqueness ambiguity.

- [ ] **Step 4: Verify GREEN and commit**

```bash
python -m pytest tests/test_netctl_snmp_parsers.py -k "fdb or qbridge or legacy" -q
git add netctl/snmp/fdb.py tests/test_netctl_snmp_parsers.py
git commit -m "feat: parse normalized switch FDB tables"
```

---

## Task 5: Build the DGS collector and sanitized fixture

**Files:**
- Create: `netctl/snmp/collector.py`
- Create: `netctl/drivers/snmp_switch.py`
- Modify: `netctl/drivers/__init__.py`
- Create: `tests/fixtures/snmp/dgs.json`
- Create: `tests/test_netctl_snmp_profiles.py`

**Interfaces:**
- `SnmpSwitchDriver.collect()` returns `SwitchSnapshot` as a JSON-compatible dictionary.
- `.test()` performs system identity and reports capability-safe output.

- [ ] **Step 1: Create sanitized DGS fixture data**

Fixture must represent:

```text
sysDescr = WS6-DGS-1210-52/F1 6.20.007
sysName = Server_switch
sysLocation = server-room
52 ports
Q-BRIDGE supported
legacy FDB unsupported
168 normalized FDB entries
F8:F0:82:D6:59:29 -> VLAN1 -> physical:52
```

Generate repetitive synthetic FDB rows in the test helper rather than copying production MAC inventory. Only the published fixture MAC above is retained.

- [ ] **Step 2: Write failing end-to-end driver tests**

Test:

```text
DGS snapshot profile_id is dgs
ports total is 52
FDB mode is qbridge
FDB count is 168
known fixture resolves to physical:52
legacy capability is unsupported
unsupported VLAN/LLDP groups do not fail required collection
no secret appears in snapshot or exception repr
```

- [ ] **Step 3: Implement collection sequence**

Required groups:

```text
system
interfaces
bridge_port_ifindex
qbridge_fdb or supported legacy fallback
```

Optional groups:

```text
vlan_current
vlan_static
pvid
stp
lldp_local
lldp_remote
```

Overall status rules:

```text
success: all required groups succeed and all attempted optional groups succeed/empty/unsupported
partial: required groups succeed, optional group times out/auth-fails/parses-fails
failed: system, interfaces, bridge map or selected FDB path fails
```

- [ ] **Step 4: Register driver**

```python
from .snmp_switch import SnmpSwitchDriver

if driver == "snmp_switch":
    return SnmpSwitchDriver(source, secrets)
```

- [ ] **Step 5: Verify and commit**

```bash
python -m pytest tests/test_netctl_snmp_profiles.py -k dgs -q
git add netctl/snmp/collector.py netctl/drivers/snmp_switch.py netctl/drivers/__init__.py tests/fixtures/snmp/dgs.json tests/test_netctl_snmp_profiles.py
git commit -m "feat: add DGS SNMP switch collector"
```

---

## Task 6: Persist switch runs, ports, FDB and events transactionally

**Files:**
- Create: `netctl/switch_store.py`
- Create: `tests/test_netctl_switch_store.py`

**Interfaces:**

```python
def collect_and_save_switch(
    conn: sqlite3.Connection,
    *,
    source: dict[str, Any],
    driver: NetworkDriver,
    started_at: str,
    force_capability_refresh: bool = False,
    raw_capture: bool = False,
) -> dict[str, Any]: ...
```

- [ ] **Step 1: Write failing persistence tests**

Test:

```text
running run is committed before network collection begins
successful FDB inserts current rows and appeared events
identical second FDB updates last_seen but emits no events
port change emits exactly one moved event
missing old key on confirmed successful snapshot emits disappeared
confirmed success_empty removes current rows and emits disappeared
failed FDB keeps prior current rows and emits no disappeared
optional group failure preserves prior optional state
failed run is persisted after rollback
one failed source does not alter another source
runtime asset key is resolved only when the asset exists
missing configured runtime asset does not create an asset or binding
```

- [ ] **Step 2: Verify RED**

```bash
python -m pytest tests/test_netctl_switch_store.py -q
```

- [ ] **Step 3: Implement run lifecycle**

```text
transaction A:
  insert switch_collection_runs(status='running')
  commit

network phase:
  driver.collect()

transaction B:
  BEGIN IMMEDIATE
  update switch_devices and successful capability rows
  replace/update successful current groups
  diff and write FDB events
  finalize run success/partial
  COMMIT

failure transaction:
  rollback transaction B
  update run failed with sanitized error
  update network_sources last_status/last_error
  commit
```

Do not commit inside FDB diff helpers.

- [ ] **Step 4: Implement FDB diff**

```python
old_by_key = {(row["vlan_key"], row["mac"]): row for row in old_rows}
new_by_key = {(row.vlan_key, row.mac): row for row in snapshot.fdb}

appeared = new_by_key.keys() - old_by_key.keys()
disappeared = old_by_key.keys() - new_by_key.keys()
common = old_by_key.keys() & new_by_key.keys()
moved = {
    key for key in common
    if old_by_key[key]["port_key"] != new_by_key[key].port_key
}
```

Preserve `first_seen_at` for unchanged and moved entries. Set `last_seen_at` to the current run time.

- [ ] **Step 5: Verify GREEN and commit**

```bash
python -m pytest tests/test_netctl_switch_store.py -q
git add netctl/switch_store.py tests/test_netctl_switch_store.py
git commit -m "feat: persist transactional switch FDB state"
```

---

## Task 7: Integrate sources and collection CLI

**Files:**
- Modify: `netctl/cli.py`
- Modify: `netctl/config.py`
- Create: `netctl/switch_queries.py`
- Create: `tests/test_netctl_switch_cli.py`
- Modify: `.github/workflows/verify-netctl-runtime.yml`

**Interfaces:**

```bash
netctl --json sources add-snmp-switch switch-dgs-server \
  --host 192.168.100.16 \
  --secret-ref switch_dgs_server_snmp \
  --site main \
  --role access-switch \
  --profile-hint dgs \
  --runtime-asset-key mac:BC:22:28:0C:EF:E0 \
  --intent-context-id sosn-admin-network \
  --intent-stable-id dlink-dgs-1210-52-server-switch

netctl --json sources test switch-dgs-server
netctl --json collect switch-dgs-server
netctl --json switches status
netctl --json switches capabilities --source switch-dgs-server
netctl --json switches ports --source switch-dgs-server
netctl --json switches fdb --source switch-dgs-server --vlan 1
netctl --json switches events --source switch-dgs-server --event-type moved
netctl --json switches findings --status open
```

- [ ] **Step 1: Write failing CLI tests**

Test:

```text
add-snmp-switch writes YAML without community
sources inspect exposes options but no resolved secret
sources test returns system identity and explicit outcomes
collect all continues after one SNMP source failure
switches queries are read-only
invalid profile/version/retention is rejected with JSON error
FDB output is paginated/limited and never returns raw varbinds
```

- [ ] **Step 2: Add switch dispatch**

In `collect_one()`:

```python
if source["driver"] == "snmp_switch":
    result = collect_and_save_switch(
        conn,
        source=source,
        driver=driver_for(source, load_secrets()),
        started_at=started,
        force_capability_refresh=bool(args.refresh_capabilities),
        raw_capture=bool(args.raw_capture),
    )
    return 0 if result["status"] in {"success", "partial"} else 1, ok(**result)
```

Do not call legacy `save_collection()` for switch snapshots.

- [ ] **Step 3: Extend CI**

Add to the focused job:

```text
tests/test_netctl_snmp_config.py
tests/test_netctl_snmp_transport.py
tests/test_netctl_snmp_parsers.py
tests/test_netctl_snmp_profiles.py
tests/test_netctl_switch_store.py
tests/test_netctl_switch_cli.py
```

- [ ] **Step 4: Verify and commit**

```bash
python -m pytest tests/test_netctl_switch_cli.py tests/test_netctl_switch_store.py -q
python -m pytest -q
git diff --check
git add netctl/cli.py netctl/config.py netctl/switch_queries.py tests/test_netctl_switch_cli.py .github/workflows/verify-netctl-runtime.yml
git commit -m "feat: expose switch collection CLI"
```

---

## Task 8: PR 3A DGS production pilot and evidence

**Files:**
- Create: `docs/runbooks/netctl-snmp-dgs-pilot.md`
- Create after deployment: `docs/verification/netctl-snmp-dgs-pilot.md`
- Modify: `README.md`

- [ ] **Step 1: Write runbook before deployment**

Runbook requirements:

```text
SQLite .backup and integrity_check
application/wrapper backup
record exact main SHA and checksums
install pinned PySNMP in deployed venv
apply migration 5 with sources disabled
verify ledger [1,2,3,4,5]
configure community only in /etc/netctl/secrets.env
sources test DGS
manual collect DGS twice
confirm 168 FDB rows
confirm fixture MAC on physical port52 VLAN1
confirm second identical run emits zero new events
simulate a failed credential in a temporary disabled test source and prove prior DGS state remains
remove temporary source and restore secret file permissions
activate DGS source only after verification
```

Secret file requirement:

```bash
sudo chmod 0640 /etc/netctl/secrets.env
sudo chown root:netctl /etc/netctl/secrets.env
```

The runbook must never print or grep the community value.

- [ ] **Step 2: Execute and record sanitized evidence**

Verification file records only:

```text
release SHA
migration ledger
source name
system identity
capability outcomes
port count
FDB count
known fixture result
second-run event count
failure-preservation result
service/timer status
rollback_required=false
```

- [ ] **Step 3: Commit and complete PR 3A**

```bash
git add docs/runbooks/netctl-snmp-dgs-pilot.md docs/verification/netctl-snmp-dgs-pilot.md README.md
git commit -m "docs: verify DGS SNMP pilot"
python -m pytest -q
git diff --check
```

---

# PR 3B — vendor profiles and optional topology facts

## Task 9: Add SNR profile, VLAN/PVID and STP normalization

**Files:**
- Create: `netctl/snmp/vlan.py`
- Create: `netctl/snmp/stp.py`
- Create: `tests/fixtures/snmp/snr.json`
- Modify: `netctl/snmp/profiles.py`
- Modify: `netctl/snmp/collector.py`
- Modify: `tests/test_netctl_snmp_profiles.py`

- [ ] **Step 1: Write SNR fixture tests**

Required assertions:

```text
sysObjectID 1.3.6.1.4.1.57206.1.1 -> profile snr
bridge ports 1-28 map to ifIndex 5001-5028
bridge port65 maps to ifIndex100001/lag:po1
Q-BRIDGE raw 31071 maps to lag:po1 and ifIndex100001
D4:01:C3:9C:83:5F -> VLAN1 -> physical:24/ge24
BC:22:28:0C:EF:E0 -> VLAN1 -> physical:21/ge21
2C:C8:1B:AB:55:45 -> VLAN1 -> physical:22/ge22
1C:3B:F3:DC:C9:EB -> VLAN1 -> physical:23/ge23
C0:9B:F4:61:4B:CD -> VLAN20 -> physical:23/ge23
FDB count is 180
VLAN20 egress bitmap resolves bridge ports23 and27 -> ge23 and xe3
all bridge ports have PVID1
STP root is 2C:C8:1B:9C:31:EA
STP root port raw927 normalizes to physical:23/ge23
remote LLDP unsupported does not fail collection
```

- [ ] **Step 2: Implement VLAN bitmap normalization**

Q-BRIDGE port list rules:

```text
most-significant bit first inside each octet
bit position 1 maps to bridge port1
bitmap -> bridge ports -> dot1dBasePortIfIndex -> normalized port keys
```

Reject a bitmap if it sets a bridge port absent from the bridge mapping.

- [ ] **Step 3: Implement SNR-specific normalization**

```python
if fdb_mode == "qbridge" and raw_fdb_port == 31071:
    return "lag:po1"
if fdb_mode == "qbridge" and raw_fdb_port in ports_by_ifindex:
    return ports_by_ifindex[raw_fdb_port].port_key
```

Do not interpret ordinary SNR Q-BRIDGE values as bridge-port numbers.

- [ ] **Step 4: Verify and commit**

```bash
python -m pytest tests/test_netctl_snmp_profiles.py -k snr -q
git add netctl/snmp/vlan.py netctl/snmp/stp.py netctl/snmp/profiles.py netctl/snmp/collector.py tests/fixtures/snmp/snr.json tests/test_netctl_snmp_profiles.py
git commit -m "feat: add SNR SNMP VLAN and STP profile"
```

---

## Task 10: Add TP-Link physical-port normalization

**Files:**
- Create: `tests/fixtures/snmp/tplink.json`
- Modify: `netctl/snmp/profiles.py`
- Modify: `tests/test_netctl_snmp_profiles.py`

- [ ] **Step 1: Write fixture tests**

Required assertions:

```text
physical port N resolves to ifIndex 49152+N
C0:9B:F4:61:4B:CD -> VLAN20 -> physical:48 -> ifIndex49200
50:D4:F7:85:B5:5A -> VLAN1 -> physical:31
2C:C8:1B:AB:53:C9 -> VLAN1 -> physical:22
2C:C8:1B:AB:47:23 -> VLAN1 -> physical:18
Q-BRIDGE is preferred when both FDB modes succeed
unsupported standard VLAN/PVID does not clear prior optional state
remote LLDP empty/unsupported does not fail collection
```

- [ ] **Step 2: Implement normalization**

```python
if_index = 49152 + raw_fdb_port
port = ports_by_ifindex.get(if_index)
if port is None:
    raise SnmpParseError(
        f"TP-Link physical port {raw_fdb_port} has no ifIndex {if_index}"
    )
return port.port_key
```

- [ ] **Step 3: Verify and commit**

```bash
python -m pytest tests/test_netctl_snmp_profiles.py -k tplink -q
git add netctl/snmp/profiles.py tests/fixtures/snmp/tplink.json tests/test_netctl_snmp_profiles.py
git commit -m "feat: add TP-Link SNMP port profile"
```

---

## Task 11: Add CSS326 legacy-FDB profile and optional LLDP parser

**Files:**
- Create: `netctl/snmp/lldp.py`
- Create: `tests/fixtures/snmp/css326.json`
- Modify: `netctl/snmp/profiles.py`
- Modify: `netctl/snmp/collector.py`
- Modify: `tests/test_netctl_snmp_profiles.py`

- [ ] **Step 1: Write CSS fixtures**

Required assertions:

```text
Q-BRIDGE unsupported triggers legacy FDB
physical/bridge/ifIndex port range is 1-26
SRV-1 uplink fixture resolves to physical:24
A2 uplink fixture resolves to physical:13
A1 uplink fixture resolves to physical:5
unsupported LLDP and VLAN groups do not fail source
legacy FDB vlan_key is unknown
```

- [ ] **Step 2: Add optional LLDP behavior**

```text
success_with_rows -> transactionally replace switch_neighbors for the source
success_empty -> replace with empty neighbors
unsupported/timeout/auth/parse -> preserve prior neighbors
```

- [ ] **Step 3: Verify all vendor fixtures and commit**

```bash
python -m pytest tests/test_netctl_snmp_profiles.py -q
python -m pytest tests/test_netctl_snmp_parsers.py -q
git add netctl/snmp/lldp.py netctl/snmp/profiles.py netctl/snmp/collector.py tests/fixtures/snmp/css326.json tests/test_netctl_snmp_profiles.py
git commit -m "feat: add CSS326 legacy FDB profile"
```

---

# PR 3C — counters, findings, retention and rollout

## Task 12: Store counter samples and compute reset-safe deltas

**Files:**
- Create: `netctl/snmp/counters.py`
- Modify: `netctl/switch_store.py`
- Create: `tests/test_netctl_switch_counters.py`

**Interfaces:**

```python
def counter_delta(
    previous: int | None,
    current: int | None,
    *,
    bits: int,
    previous_uptime: int | None,
    current_uptime: int | None,
) -> int | None: ...
```

- [ ] **Step 1: Write failing tests**

Test:

```text
normal increase returns current-previous
missing value returns NULL delta
sysUpTime decrease marks reboot/reset and returns NULL
32-bit wrap is handled when uptime increased
ifIndex change with same port_key uses port_key history
failed collection stores no counter sample
absolute historical counters alone create no finding
```

- [ ] **Step 2: Implement counter policy**

Defaults:

```text
error delta threshold: 1
discard delta threshold: 100
counter sample retention: 14 days
```

Findings:

```text
interface_errors_increasing
interface_discards_increasing
counter_reset_or_reboot (info event, not an error finding)
```

Resolve an error/discard finding after one successful sample below threshold. Never resolve on failed or missing collection.

- [ ] **Step 3: Verify and commit**

```bash
python -m pytest tests/test_netctl_switch_counters.py -q
git add netctl/snmp/counters.py netctl/switch_store.py tests/test_netctl_switch_counters.py
git commit -m "feat: add switch counter delta findings"
```

---

## Task 13: Add capability cache, capability-change events and retention

**Files:**
- Modify: `netctl/snmp/collector.py`
- Modify: `netctl/switch_store.py`
- Modify: `tests/test_netctl_switch_store.py`

- [ ] **Step 1: Write failing tests**

Test:

```text
capabilities are reused before expires_at
--refresh-capabilities bypasses cache
profile fingerprint change invalidates capability cache
capability outcome change creates capability_changed finding/event
known unsupported optional group is skipped until expiry
required FDB groups are still validated according to fallback rules
old events are removed after event_retention_days
old counter samples are removed after counter_retention_days
raw diagnostic files older than raw_retention_hours are removed
current state and open findings are never removed by retention
```

- [ ] **Step 2: Implement profile fingerprint**

```python
fingerprint_input = {
    "sys_object_id": system.sys_object_id,
    "sys_descr": system.sys_descr,
    "profile_id": profile.profile_id,
}
profile_fingerprint = sha256(
    json.dumps(fingerprint_input, sort_keys=True, separators=(",", ":")).encode()
).hexdigest()
```

- [ ] **Step 3: Implement retention**

Run pruning after successful source persistence. Use indexed timestamp predicates and report deleted counts in collection summary.

Raw capture path:

```text
/var/lib/netctl/raw/snmp/<source-name>/<run-id>.jsonl.gz
```

Create files mode `0640`, directory mode `0750`, owner `netctl:netctl`. Raw capture rows contain OID/type/value only. They never contain source secrets.

- [ ] **Step 4: Verify and commit**

```bash
python -m pytest tests/test_netctl_switch_store.py -k "capability or retention or raw" -q
git add netctl/snmp/collector.py netctl/switch_store.py tests/test_netctl_switch_store.py
git commit -m "feat: cache switch capabilities and prune history"
```

---

## Task 14: Add switch operational findings and read-only status

**Files:**
- Modify: `netctl/switch_store.py`
- Modify: `netctl/switch_queries.py`
- Modify: `netctl/cli.py`
- Modify: `tests/test_netctl_switch_cli.py`

- [ ] **Step 1: Write failing finding tests**

Findings included in this phase:

```text
mac_moved_to_port
access_port_many_macs
undocumented_aggregation_candidate
link_speed_below_100m
interface_errors_increasing
interface_discards_increasing
stp_root_changed
capability_changed
```

Rules:

```text
mac_moved_to_port: emitted from moved FDB event; provenance remains historical
access_port_many_macs: port has >=10 current FDB MACs and is not explicitly role uplink/downlink
undocumented_aggregation_candidate: port has >=10 MACs and no known intent link on that port
link_speed_below_100m: oper up and reported speed <100,000,000 bps
stp_root_changed: prior nonblank root differs from new root
```

Do not automatically modify intent or port role.

- [ ] **Step 2: Add pagination and aggregate status**

`switches status` returns:

```text
sources total/success/partial/failed
current ports/FDB/VLAN/neighbor counts
open findings by type/severity
last successful run per source
capability expiry state
history retention settings
raw capture enabled sources
```

All list commands accept `--limit` with maximum `5000` and default `500`.

- [ ] **Step 3: Verify and commit**

```bash
python -m pytest tests/test_netctl_switch_cli.py tests/test_netctl_switch_counters.py -q
git add netctl/switch_store.py netctl/switch_queries.py netctl/cli.py tests/test_netctl_switch_cli.py
git commit -m "feat: expose switch operational findings"
```

---

## Task 15: Production rollout for SNR, TP-Link and CSS326

**Files:**
- Create: `docs/runbooks/netctl-snmp-multivendor-rollout.md`
- Create after deployment: `docs/verification/netctl-snmp-multivendor-readiness.md`
- Modify: `README.md`

- [ ] **Step 1: Define source files without secrets**

Required production sources:

```text
switch-dgs-server       192.168.100.16  profile dgs
switch-snr-core         192.168.100.254 profile snr
switch-tplink-ito       192.168.100.15  profile tplink
switch-tplink-asmr      192.168.100.14  profile tplink
switch-css326-srv1      192.168.100.23  profile css326
switch-css326-a2        192.168.100.24  profile css326
switch-css326-a1        192.168.100.25  profile css326
```

Each source gets a distinct `secret_ref`. Community values stay only in the protected secret file.

- [ ] **Step 2: Write staged rollout runbook**

For each device, execute:

```text
source disabled
sources test
manual collect with capability refresh
inspect capabilities/ports/FDB
second identical collect
verify event idempotence
review findings
source enable
wait one timer cycle
verify status
```

Exact acceptance values:

```text
DGS: 52 ports; Q-BRIDGE; 168 FDB; SNR CPU MAC VLAN1 physical:52
SNR: 30 interfaces; 180 FDB; po1 normalization; VLAN20 ge23+xe3; expected STP root facts
TP-Link ITO: Q-BRIDGE; endpoint VLAN20 physical:48/ifIndex49200
TP-Link ASMR: Q-BRIDGE preferred; expected uplink direction physical:47
CSS326: legacy FDB; SRV1 physical:24; A2 physical:13; A1 physical:5
```

Any count difference must be explained as live network churn, while fixture mapping must remain exact.

- [ ] **Step 3: Failure tests in production**

Use only a temporary disabled source with a nonexistent secret reference. Confirm:

```text
run status failed
error contains no secret
real source current FDB count unchanged
no disappeared events emitted
other sources still collect
```

Remove the temporary source after verification.

- [ ] **Step 4: Disk and retention checks**

```text
/var/lib/netctl free space >20 GiB
raw capture disabled for scheduled sources
no raw files older than 24 hours
counter samples older than 14 days pruned
events older than 180 days pruned
local rollback backups retained according to current operator policy
```

- [ ] **Step 5: Commit readiness evidence**

The verification document contains aggregate counts, capabilities, known fixture outcomes, failure preservation, tests and service states. It does not contain communities, raw FDB inventory or raw SNMP captures.

```bash
git add docs/runbooks/netctl-snmp-multivendor-rollout.md docs/verification/netctl-snmp-multivendor-readiness.md README.md
git commit -m "docs: verify multi-vendor SNMP collectors"
```

---

## Task 16: Final regression, Issue #5 closure and roadmap synchronization

**Files:**
- Modify: `docs/verification/netctl-snmp-multivendor-readiness.md`
- Modify in `network_configuration`: `docs/status/web-ovpn-current-phase.md`
- Modify in `network_configuration`: `docs/web-ovpn-backlog.md`

- [ ] **Step 1: Run focused tests**

```bash
python -m pytest -q \
  tests/test_netctl_snmp_config.py \
  tests/test_netctl_snmp_transport.py \
  tests/test_netctl_snmp_parsers.py \
  tests/test_netctl_snmp_profiles.py \
  tests/test_netctl_switch_store.py \
  tests/test_netctl_switch_counters.py \
  tests/test_netctl_switch_cli.py
```

Expected: exit `0`.

- [ ] **Step 2: Run full regression and static repository checks**

```bash
python -m pytest -q
git diff --check
git grep -nE '(community|NETCTL_SECRET_.*_COMMUNITY)=' -- ':!docs/plans/netctl-snmp-fdb-collectors.md' || true
```

The grep must not reveal an assigned credential value. References to environment variable names in documentation/tests are allowed only without a real value.

- [ ] **Step 3: Verify CI on the exact merge commit**

Required jobs:

```text
focused-runtime-identity
full-regression
```

Retain the full pytest artifact.

- [ ] **Step 4: Close Issue #5**

Closure comment references:

```text
implementation merge commits for PR 3A/3B/3C
full regression result
production readiness document
DGS/SNR/TP-Link/CSS326 aggregate outcomes
failed-source state-preservation proof
secret scan result
service/timer status
```

- [ ] **Step 5: Synchronize `network_configuration`**

Mark multi-vendor SNMP/FDB collection complete and set the next phase explicitly. Do not authorize switch writes.

---

## 4. Acceptance matrix

| Requirement | Required evidence |
|---|---|
| Generic SNMPv2c source | source config/secret tests and DGS pilot |
| Secrets outside Git | source-public tests, secret scan, protected secret file |
| Explicit outcome classes | transport and capability tests |
| DGS Q-BRIDGE-only profile | 168-entry fixture and port52 mapping |
| SNR SNMP-first profile | 180 entries, po1, VLAN20 and STP fixtures |
| TP-Link physical/ifIndex mapping | port48 to ifIndex49200 fixture |
| CSS326 legacy fallback | Q-BRIDGE unsupported and legacy fixtures |
| Failed source isolation | collect-all and production disabled-source test |
| Failed FDB preserves current | persistence test and production proof |
| Successful empty clears current | success-empty event test |
| Identical run emits no events | DGS second-run proof |
| Move emits one event | switch-store test |
| Counter findings use deltas | reset/wrap tests |
| LLDP optional | unsupported/empty vendor tests |
| Retention protects disk | pruning tests and production disk check |
| No network writes | source code review and read-only runbooks |

---

## 5. Explicitly deferred

```text
SNMPv1
SNMPv3 USM credentials
switch configuration backup through SNMP
SNMP SET operations
automatic port shutdown
automatic VLAN or PVID changes
automatic port description changes
automatic topology-intent writes
automatic asset merge from FDB evidence
full visual topology editor
long-term raw SNMP archive
PostgreSQL migration
parallel source collection
```

SNMPv3 may be added later through the existing transport abstraction without changing normalized tables.

---

## 6. Implementation start point

Start PR 3A from current `main` and complete Task 1 before adding transport code. Do not create production source files or install a community until migration tests, transport secret tests, parser fixtures and transactional FDB tests are green.
