# Netctl Multi-Vendor SNMP/FDB Collector Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Build a read-only multi-vendor switch collector that normalizes ports and FDB data, preserves current state across failures, records FDB events and counter deltas, and supports DGS, SNR, TP-Link T1600G and MikroTik CSS326.

**Architecture:** Add a dedicated `snmp_switch` driver and switch-specific persistence path alongside the existing RouterOS and runtime-identity paths. Use PySNMP with numeric OIDs and structured values, normalize vendor differences through explicit profiles, and publish current FDB only after the selected FDB path has completed successfully. Git intent, runtime assets, switch observations and operational findings remain separate.

**Tech Stack:** Python 3.12, SQLite migrations, `pysnmp==7.1.27`, the existing `netctl` driver/CLI framework, pytest, GitHub Actions and systemd deployment runbooks.

## Global Constraints

- Start from `web_ovpn/main` commit `67ca3e26e7e755d612505937dcef90409cf73400` or a later fast-forward `main` containing it.
- Migrations `1` through `4` are immutable. All switch schema work starts at migration `5`.
- SNMP is read-only. Do not implement SNMP SET, port shutdown, VLAN/PVID changes, description changes, topology writes or switch configuration changes.
- PR 3 initially supports SNMPv2c only. Reject unsupported versions explicitly; never silently downgrade.
- Communities exist only in `/etc/netctl/secrets.env` or the process environment.
- Community values must never appear in source YAML, database rows, logs, exceptions, CLI/API output, test fixtures, diagnostic captures or Git history.
- Numeric OIDs are authoritative. Do not require internet access or runtime MIB downloads.
- A failed source must not fail unrelated sources.
- A failed FDB collection must preserve the previous `current_switch_fdb` state and must not emit false `disappeared` events.
- `success_empty` is different from timeout, unsupported, authentication/view failure and parse error. Only confirmed `success_empty` may replace current FDB with an empty set.
- Prefer Q-BRIDGE. Use legacy dot1d FDB only when Q-BRIDGE is explicitly unsupported, not when Q-BRIDGE times out or fails parsing.
- Q-BRIDGE FDB indexes contain an FDB ID/FID, not universally a VLAN ID/VID. Generic code must never assume `FID == VID`.
- DGS, TP-Link and SNR may use a profile-level, fixture-proven `FID == VID` rule when no VID-to-FID mapping is available. Unknown devices may not.
- LLDP is optional and never blocks a successful required collection.
- Different MAC addresses are never merged automatically into one runtime asset.
- Switch-to-runtime identity is explicit. The collector may resolve a configured `runtime_asset_key`; it must not create or confirm an asset-intent binding automatically.
- Current FDB is stored as current state. History is stored as `appeared`, `moved` and `disappeared` events rather than complete repeated snapshots.
- Counter findings use deltas/rates. Absolute cumulative values alone are not findings.
- Raw SNMP capture is disabled by default, diagnostic only, sanitized, outside Git and retained for no more than 24 hours.
- Tests use sanitized fixtures and never contact live devices.
- Production rollout order is DGS, SNR, TP-Link and then CSS326.
- The `mikrotik-hex` SSH timeout is outside this work and does not block SNMP collection.
- Local rollback backups remain on the current `/var/lib/netctl` disk under the operator's accepted temporary policy; free-space and retention checks are mandatory.

---

## 1. Pull-request boundaries

### PR 3A — generic core and DGS vertical slice

```text
migration 5 switch schema
extensible source options and secret resolution
PySNMP transport and explicit outcome classes
system/ifTable/ifXTable/bridge mapping
Q-BRIDGE FID handling
DGS profile and sanitized fixture
transactional current FDB and FDB events
switch CLI
DGS production pilot
```

PR 3A is accepted when:

```text
two identical DGS collections emit no duplicate events;
a moved fixture MAC emits exactly one move event;
a failed FDB collection preserves prior current FDB;
a failed source does not prevent another source from completing.
```

### PR 3B — SNR, TP-Link and CSS326

```text
SNR ifIndex and po1 normalization
SNR VLAN/PVID/STP collection
TP-Link physical-port to ifIndex normalization
CSS326 legacy-FDB fallback
optional LLDP storage
all published vendor fixtures
```

### PR 3C — counters, findings, retention and full rollout

```text
counter samples and reset/wrap-safe deltas
operational findings
capability cache and change detection
history/raw retention
multi-vendor production rollout
sanitized readiness evidence
Issue #5 closure
```

Do not merge all work into one large pull request.

---

## 2. File map

### New package

```text
netctl/snmp/__init__.py
netctl/snmp/models.py
netctl/snmp/oids.py
netctl/snmp/outcomes.py
netctl/snmp/transport.py
netctl/snmp/system.py
netctl/snmp/interfaces.py
netctl/snmp/fdb.py
netctl/snmp/vlan.py
netctl/snmp/stp.py
netctl/snmp/lldp.py
netctl/snmp/profiles.py
netctl/snmp/collector.py
```

### Driver, persistence and reads

```text
netctl/drivers/snmp_switch.py
netctl/switch_store.py
netctl/switch_queries.py
```

### Modified files

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
tests/test_netctl_switch_counters.py
tests/test_netctl_switch_cli.py
tests/fixtures/snmp/dgs.json
tests/fixtures/snmp/snr.json
tests/fixtures/snmp/tplink.json
tests/fixtures/snmp/css326.json
```

Fixture files contain only numeric OIDs, value types and sanitized values. They contain no community, credential, raw command line, full production FDB or device configuration backup.

---

## 3. Shared normalized contracts

### 3.1 Outcome classes

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

SNMPv2c wrong-community behavior often appears as no response and therefore `timeout`. Classify `auth_or_view_failure` only when the agent returns an explicit protocol error such as `authorizationError` or `noAccess`. Do not guess authentication failure from a timeout.

### 3.2 Structured SNMP values

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

### 3.3 Normalized records

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
class PortResolution:
    port_key: str
    if_index: int | None
    bridge_port: int | None
    physical_port: int | None
    port_name: str


@dataclass(frozen=True)
class SwitchFdbEntry:
    fdb_id: int | None
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

### 3.4 Snapshot

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

`NetworkDriver.collect()` remains JSON-compatible. `SnmpSwitchDriver.collect()` serializes the dataclasses through explicit `to_dict()` helpers; it does not expose raw PySNMP objects.

---

# PR 3A — generic core and DGS pilot

## Task 1: Add migration 5 and extensible source options

**Files:**
- Modify: `netctl/migrations.py`
- Modify: `netctl/config.py`
- Modify: `netctl/db.py`
- Create: `tests/test_netctl_snmp_config.py`

**Interfaces:**
- Produces schema migration `5`.
- Produces `network_sources.driver_options_json` and decoded `source["driver_options"]`.
- Does not store resolved secret material.

- [ ] **Step 1: Write failing tests**

Tests assert:

```text
schema ledger becomes [1,2,3,4,5]
migration 5 applies exactly once
migration 5 rollback leaves no partial table or ledger row
network_sources.driver_options_json defaults to '{}'
SNMP source scalar YAML normalizes to driver_options
source_public contains no community or resolved secret
unsupported snmp_version/profile/retention is rejected
existing MikroTik source normalization is unchanged
```

Use this disabled fixture:

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
snmp_access_port_mac_threshold: 10
snmp_low_speed_threshold_bps: 100000000
runtime_asset_key: mac:BC:22:28:0C:EF:E0
intent_context_id: sosn-admin-network
intent_stable_id: dlink-dgs-1210-52-server-switch
```

- [ ] **Step 2: Verify RED**

```bash
python -m pytest tests/test_netctl_snmp_config.py -q
```

- [ ] **Step 3: Implement migration 5 with individual `conn.execute()` calls**

Do not use `executescript()` and do not call `commit()` from migration 5.

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
    fdb_id INTEGER,
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
    fdb_id INTEGER,
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

- [ ] **Step 4: Normalize and persist driver options**

`normalize_source()` produces:

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
    "access_port_mac_threshold": 10,
    "low_speed_threshold_bps": 100000000,
    "runtime_asset_key": "mac:BC:22:28:0C:EF:E0",
    "intent_context_id": "sosn-admin-network",
    "intent_stable_id": "dlink-dgs-1210-52-server-switch",
}
```

Store sorted JSON in `network_sources.driver_options_json`. Decode it in source query helpers. `source_public()` exposes non-secret options but never resolved secret values.

- [ ] **Step 5: Verify and commit**

```bash
python -m pytest tests/test_netctl_snmp_config.py -q
git add netctl/migrations.py netctl/config.py netctl/db.py tests/test_netctl_snmp_config.py
git commit -m "feat: add switch collection schema and source options"
```

---

## Task 2: Add PySNMP transport and explicit outcomes

**Files:**
- Modify: `requirements.txt`
- Create: `netctl/snmp/__init__.py`
- Create: `netctl/snmp/models.py`
- Create: `netctl/snmp/oids.py`
- Create: `netctl/snmp/outcomes.py`
- Create: `netctl/snmp/transport.py`
- Create: `tests/test_netctl_snmp_transport.py`

**Interfaces:**
- Produces synchronous `collect_on_worker_loop()`.
- Produces asynchronous `SnmpTransport.get()` and `SnmpTransport.walk()` used on one event loop per source.
- Returns structured `CapabilityResult`; no pretty-printed varbind parsing.

- [ ] **Step 1: Pin dependency**

```text
pysnmp==7.1.27
```

- [ ] **Step 2: Add numeric OIDs**

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
IF_HC_OUT_OCTETS = "1.3.6.1.2.1.31.1.1.1.10"
IF_HIGH_SPEED = "1.3.6.1.2.1.31.1.1.1.15"
IF_ALIAS = "1.3.6.1.2.1.31.1.1.1.18"

DOT1D_BASE_PORT_IFINDEX = "1.3.6.1.2.1.17.1.4.1.2"
DOT1D_FDB_ADDRESS = "1.3.6.1.2.1.17.4.3.1.1"
DOT1D_FDB_PORT = "1.3.6.1.2.1.17.4.3.1.2"
DOT1D_FDB_STATUS = "1.3.6.1.2.1.17.4.3.1.3"

DOT1Q_FDB_PORT = "1.3.6.1.2.1.17.7.1.2.2.1.2"
DOT1Q_FDB_STATUS = "1.3.6.1.2.1.17.7.1.2.2.1.3"
DOT1Q_VLAN_FDB_ID = "1.3.6.1.2.1.17.7.1.4.2.1.3"
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

- [ ] **Step 3: Write failing transport tests**

Test:

```text
integer/octet string/MAC bytes/OID values convert without pretty-print ambiguity
timeout -> TIMEOUT
explicit authorizationError/noAccess -> AUTH_OR_VIEW_FAILURE
NoSuchObject/NoSuchInstance -> UNSUPPORTED_NO_SUCH_OBJECT
end-of-MIB with zero rows -> SUCCESS_EMPTY
rows -> SUCCESS_WITH_ROWS
community absent from repr, exceptions and result dictionaries
one source collection works when caller thread already owns an asyncio loop
SnmpEngine dispatcher closes after success and failure
```

- [ ] **Step 4: Implement one worker loop per source**

Use `pysnmp.hlapi.v3arch.asyncio`, `CommunityData`, `UdpTransportTarget.create`, `get_cmd` and `bulk_walk_cmd`, with `lookupMib=False` and `lexicographicMode=False`.

```python
from concurrent.futures import ThreadPoolExecutor
import asyncio
from collections.abc import Awaitable, Callable
from typing import TypeVar

T = TypeVar("T")


def collect_on_worker_loop(factory: Callable[[], Awaitable[T]]) -> T:
    with ThreadPoolExecutor(max_workers=1, thread_name_prefix="netctl-snmp") as executor:
        return executor.submit(lambda: asyncio.run(factory())).result()
```

Create one `SnmpEngine` and one event loop per source collection, not per OID. Close the transport dispatcher in `finally`.

Resolve community from:

```text
NETCTL_SECRET_<NORMALIZED_SECRET_REF>_COMMUNITY
```

```python
def snmp_community_env_name(secret_ref: str) -> str:
    token = "".join(ch if ch.isalnum() else "_" for ch in secret_ref.upper())
    return f"NETCTL_SECRET_{token}_COMMUNITY"
```

A missing value raises exactly:

```text
SNMP community secret is not configured
```

- [ ] **Step 5: Verify and commit**

```bash
python -m pytest tests/test_netctl_snmp_transport.py -q
git add requirements.txt netctl/snmp tests/test_netctl_snmp_transport.py
git commit -m "feat: add structured SNMP transport"
```

---

## Task 3: Parse system, interfaces and port mappings

**Files:**
- Create: `netctl/snmp/system.py`
- Create: `netctl/snmp/interfaces.py`
- Create: `netctl/snmp/profiles.py`
- Create: `tests/test_netctl_snmp_parsers.py`
- Create: `tests/test_netctl_snmp_profiles.py`

**Interfaces:**
- Produces `parse_system()`, `parse_interfaces()` and `detect_profile()`.
- Produces explicit `PortResolution` values.

- [ ] **Step 1: Write failing tests**

```text
system scalars are typed
missing optional sysLocation becomes empty string
ifTable and ifXTable join by ifIndex
ifHighSpeed is used when ifSpeed is zero/saturated
bridge-port mapping joins bridge port to ifIndex
duplicate conflicting ifIndex is a parse error
profile_hint may select only a supported profile
SNR detected by sysObjectID 1.3.6.1.4.1.57206 prefix
DGS/TP-Link/CSS326 detected from sysDescr patterns
unknown device selects generic profile
ambiguous port mapping is a parse error
```

- [ ] **Step 2: Implement profile interface**

```python
class PortProfile:
    profile_id: str
    qbridge_fid_mode: str  # mapped_only | proven_equals_vid

    def resolve_fdb_port(
        self,
        *,
        raw_fdb_port: int,
        fdb_mode: str,
        bridge_to_ifindex: dict[int, int],
        ports_by_ifindex: dict[int, SwitchPort],
    ) -> PortResolution:
        raise NotImplementedError

    def resolve_fdb_vlan(
        self,
        *,
        fdb_id: int,
        vids_by_fid: dict[int, set[int]],
    ) -> tuple[str, int | None]:
        vids = vids_by_fid.get(fdb_id, set())
        if len(vids) == 1:
            vid = next(iter(vids))
            return f"vid:{vid}", vid
        if not vids and self.qbridge_fid_mode == "proven_equals_vid":
            return f"vid:{fdb_id}", fdb_id
        return f"fid:{fdb_id}", None
```

Never duplicate one FDB entry into several VLANs when multiple VIDs share one FID.

Profiles:

```text
generic: bridge port -> dot1dBasePortIfIndex; mapped_only FID policy
DGS: bridge/physical one-to-one; proven_equals_vid
SNR: Q-BRIDGE normal value is ifIndex, 31071 -> po1; proven_equals_vid
TP-Link: Q-BRIDGE raw value is physical port, ifIndex=49152+N; proven_equals_vid
CSS326: legacy bridge/ifIndex/physical one-to-one; no Q-BRIDGE VLAN
```

Port keys:

```text
physical:<number>
lag:<lowercase-name>
ifindex:<number> only when no physical identity exists
```

- [ ] **Step 3: Verify and commit**

```bash
python -m pytest tests/test_netctl_snmp_parsers.py tests/test_netctl_snmp_profiles.py -q
git add netctl/snmp/system.py netctl/snmp/interfaces.py netctl/snmp/profiles.py tests/test_netctl_snmp_parsers.py tests/test_netctl_snmp_profiles.py
git commit -m "feat: normalize SNMP switch system and ports"
```

---

## Task 4: Parse Q-BRIDGE and legacy FDB

**Files:**
- Create: `netctl/snmp/fdb.py`
- Modify: `tests/test_netctl_snmp_parsers.py`

**Interfaces:**
- Produces `parse_qbridge_fdb()` and `parse_legacy_fdb()`.
- Consumes `PortProfile`, normalized ports, bridge mapping and VID-to-FID mapping.

- [ ] **Step 1: Write failing tests**

Q-BRIDGE tests:

```text
OID suffix is decoded as FID + six MAC octets, not VLAN + MAC
DOT1Q_VLAN_FDB_ID maps VID to FID when available
one VID per FID returns vid:<VID>
multiple VIDs per FID returns fid:<FID> and vlan_id NULL
DGS/TP-Link/SNR proven profile may use FID as VID only when mapping is absent
unknown profile never assumes FID equals VID
MAC is normalized uppercase colon notation
status joins by the same FID+MAC index
malformed MAC octet rejects the FDB group
ambiguous/unknown port mapping rejects the FDB group
```

Legacy tests:

```text
address/port/status tables join by MAC index
fdb_id and vlan_id are NULL
vlan_key is legacy:unknown
CSS326 bridge port resolves one-to-one
```

Fallback tests:

```text
Q-BRIDGE success_with_rows -> use Q-BRIDGE
Q-BRIDGE success_empty -> confirmed empty, do not fall back
Q-BRIDGE unsupported -> query legacy
Q-BRIDGE timeout/auth/parse -> do not query legacy and preserve current
both paths unsupported -> no current replacement
```

- [ ] **Step 2: Implement keys**

```python
def fdb_key(entry: SwitchFdbEntry) -> tuple[str, str]:
    return entry.vlan_key, entry.mac
```

Use:

```text
vid:<number>      unambiguous VLAN
fid:<number>      filtering database not safely mapped to one VLAN
legacy:unknown    dot1d FDB without VLAN context
```

- [ ] **Step 3: Verify and commit**

```bash
python -m pytest tests/test_netctl_snmp_parsers.py -k "fdb or qbridge or legacy" -q
git add netctl/snmp/fdb.py tests/test_netctl_snmp_parsers.py
git commit -m "feat: parse normalized switch FDB tables"
```

---

## Task 5: Build the DGS driver vertical slice

**Files:**
- Create: `netctl/snmp/collector.py`
- Create: `netctl/drivers/snmp_switch.py`
- Modify: `netctl/drivers/__init__.py`
- Create: `tests/fixtures/snmp/dgs.json`
- Modify: `tests/test_netctl_snmp_profiles.py`

**Interfaces:**
- `SnmpSwitchDriver.collect()` returns a JSON-compatible serialized `SwitchSnapshot`.
- `SnmpSwitchDriver.test()` returns system identity and secret-safe capability outcomes.

- [ ] **Step 1: Create sanitized DGS fixture**

The fixture proves:

```text
sysDescr WS6-DGS-1210-52/F1 6.20.007
sysName Server_switch
sysLocation server-room
52 ports
Q-BRIDGE supported
legacy FDB unsupported
168 synthetic normalized FDB entries
F8:F0:82:D6:59:29 -> vid:1 -> physical:52
```

Generate repetitive synthetic MAC rows in test code. Keep only the published management-MAC fixture.

- [ ] **Step 2: Write end-to-end driver tests**

```text
profile_id=dgs
52 normalized ports
168 fixture FDB entries
fixture MAC resolves to physical:52 and vid:1
legacy capability is unsupported
unsupported VLAN/LLDP optional groups do not fail required collection
no secret appears in result or exception representation
```

- [ ] **Step 3: Implement collection sequence**

Required groups:

```text
system
interfaces
bridge_port_ifindex
selected FDB path
```

Optional groups:

```text
VID-to-FID map
VLAN current/static/PVID
STP
LLDP local/remote
```

Overall status:

```text
success: required groups succeed; optional groups succeed/empty/unsupported
partial: required groups succeed; optional group timeout/auth/parse failure
failed: system, interfaces, bridge mapping or selected FDB path fails
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

## Task 6: Persist collection runs, ports, FDB and events

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

- [ ] **Step 1: Write failing tests**

```text
running run is committed before network I/O
successful first FDB creates current rows and appeared events
identical second FDB changes last_seen only and emits zero events
one port change emits exactly one moved event
confirmed missing key emits disappeared
confirmed success_empty clears current and emits disappeared
failed FDB retains current and emits no disappeared
optional group failure retains prior optional state
failed run persists sanitized error after rollback
one failed source does not alter another source
configured runtime asset resolves only when it exists
missing configured runtime asset creates no asset and no binding
```

- [ ] **Step 2: Implement lifecycle**

```text
transaction A:
  insert switch_collection_runs(status=running)
  commit

network phase:
  driver.collect()

transaction B:
  BEGIN IMMEDIATE
  update switch_devices and successful capability rows
  replace/update only successful observation groups
  diff and write FDB events
  finalize success/partial run
  update network_sources status
  COMMIT

failure transaction:
  rollback transaction B
  finalize failed run with sanitized error
  update network_sources error state
  commit
```

Do not call `netctl.db.insert_event()` from transaction B because that existing helper commits internally. Do not call any helper that commits from inside transaction B.

- [ ] **Step 3: Implement FDB diff**

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

Preserve `first_seen_at` for common keys. Set `last_seen_at` to run time.

- [ ] **Step 4: Verify and commit**

```bash
python -m pytest tests/test_netctl_switch_store.py -q
git add netctl/switch_store.py tests/test_netctl_switch_store.py
git commit -m "feat: persist transactional switch FDB state"
```

---

## Task 7: Add switch CLI and CI coverage

**Files:**
- Modify: `netctl/cli.py`
- Modify: `netctl/config.py`
- Create: `netctl/switch_queries.py`
- Create: `tests/test_netctl_switch_cli.py`
- Modify: `.github/workflows/verify-netctl-runtime.yml`

**CLI contract:**

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

```text
add-snmp-switch writes YAML without a community
source inspect exposes non-secret options only
source test returns system identity and outcomes
collect all continues after one SNMP source fails
switch queries are read-only
invalid version/profile/retention returns JSON error
FDB output is limited/paginated and contains no raw varbinds
```

- [ ] **Step 2: Dispatch switch collections**

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
    rc = 0 if result["status"] in {"success", "partial"} else 1
    return rc, ok(**result)
```

Do not call legacy `save_collection()` for switch snapshots.

- [ ] **Step 3: Extend focused CI**

Add:

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

## Task 8: DGS production pilot

**Files:**
- Create before deployment: `docs/runbooks/netctl-snmp-dgs-pilot.md`
- Create after deployment: `docs/verification/netctl-snmp-dgs-pilot.md`
- Modify: `README.md`

- [ ] **Step 1: Write the runbook**

Required sequence:

```text
SQLite .backup and integrity_check
application/wrapper backup
record exact main SHA and checksums
install pinned PySNMP in deployed venv
apply migration 5 with SNMP sources disabled
verify ledger [1,2,3,4,5]
configure community only in /etc/netctl/secrets.env
source test DGS
manual DGS collection twice
record live FDB count without requiring it to remain 168
verify known SNR CPU MAC is on vid:1 physical:52 when currently present
verify second unchanged run emits zero duplicate events
use a temporary disabled source with missing secret to prove failure preservation
remove temporary source
activate only DGS
wait one timer cycle and verify services
```

The synthetic fixture remains exactly 168 entries. The production FDB count is expected to change with live network churn and must be recorded, not hard-coded as a deployment pass condition.

Secret permissions:

```bash
sudo chown root:netctl /etc/netctl/secrets.env
sudo chmod 0640 /etc/netctl/secrets.env
```

The runbook must never print, grep or echo the community.

- [ ] **Step 2: Commit sanitized evidence**

Record only:

```text
release SHA
migration ledger
system identity
capability outcomes
port count
observed live FDB count
known fixture result or documented absence at collection time
second-run event count
failure-preservation result
service/timer state
rollback_required=false
```

- [ ] **Step 3: Finish PR 3A**

```bash
python -m pytest -q
git diff --check
git add docs/runbooks/netctl-snmp-dgs-pilot.md docs/verification/netctl-snmp-dgs-pilot.md README.md
git commit -m "docs: verify DGS SNMP pilot"
```

---

# PR 3B — SNR, TP-Link and CSS326

## Task 9: Add SNR VLAN/PVID/STP profile

**Files:**
- Create: `netctl/snmp/vlan.py`
- Create: `netctl/snmp/stp.py`
- Create: `tests/fixtures/snmp/snr.json`
- Modify: `netctl/snmp/profiles.py`
- Modify: `netctl/snmp/collector.py`
- Modify: `tests/test_netctl_snmp_profiles.py`

- [ ] **Step 1: Write SNR fixture tests**

```text
sysObjectID 1.3.6.1.4.1.57206.1.1 -> snr
bridge ports1-28 -> ifIndex5001-5028
bridge port65 -> ifIndex100001 -> lag:po1
Q-BRIDGE raw31071 -> lag:po1/ifIndex100001
D4:01:C3:9C:83:5F -> vid:1 -> physical:24/ge24
BC:22:28:0C:EF:E0 -> vid:1 -> physical:21/ge21
2C:C8:1B:AB:55:45 -> vid:1 -> physical:22/ge22
1C:3B:F3:DC:C9:EB -> vid:1 -> physical:23/ge23
C0:9B:F4:61:4B:CD -> vid:20 -> physical:23/ge23
fixture FDB count 180
VLAN20 egress bitmap -> ge23 and xe3
PVID1 on all bridge ports
STP root 2C:C8:1B:9C:31:EA
STP root raw927 -> physical:23/ge23
remote LLDP unsupported does not fail collection
```

- [ ] **Step 2: Parse VLAN bitmaps**

```text
most-significant bit first per octet
bit position1 -> bridge port1
bitmap -> bridge ports -> ifIndex -> normalized port keys
```

Reject a bitmap that references a bridge port missing from the bridge map.

- [ ] **Step 3: Implement SNR port rule**

```python
if fdb_mode == "qbridge" and raw_fdb_port == 31071:
    return resolution_for_ifindex(100001)
if fdb_mode == "qbridge":
    return resolution_for_ifindex(raw_fdb_port)
```

Ordinary SNR Q-BRIDGE values are ifIndex values, not bridge-port values.

- [ ] **Step 4: Verify and commit**

```bash
python -m pytest tests/test_netctl_snmp_profiles.py -k snr -q
git add netctl/snmp/vlan.py netctl/snmp/stp.py netctl/snmp/profiles.py netctl/snmp/collector.py tests/fixtures/snmp/snr.json tests/test_netctl_snmp_profiles.py
git commit -m "feat: add SNR SNMP VLAN and STP profile"
```

---

## Task 10: Add TP-Link normalization

**Files:**
- Create: `tests/fixtures/snmp/tplink.json`
- Modify: `netctl/snmp/profiles.py`
- Modify: `tests/test_netctl_snmp_profiles.py`

- [ ] **Step 1: Write fixture tests**

```text
physical port N -> ifIndex49152+N
C0:9B:F4:61:4B:CD -> vid:20 -> physical:48 -> ifIndex49200
50:D4:F7:85:B5:5A -> vid:1 -> physical:31
2C:C8:1B:AB:53:C9 -> vid:1 -> physical:22
2C:C8:1B:AB:47:23 -> vid:1 -> physical:18
Q-BRIDGE preferred when both modes work
unsupported VLAN/PVID does not clear prior optional state
remote LLDP empty/unsupported does not fail collection
```

- [ ] **Step 2: Implement rule**

```python
if_index = 49152 + raw_fdb_port
port = ports_by_ifindex.get(if_index)
if port is None:
    raise SnmpParseError(
        f"TP-Link physical port {raw_fdb_port} has no ifIndex {if_index}"
    )
return resolution_from_port(port, physical_port=raw_fdb_port)
```

- [ ] **Step 3: Verify and commit**

```bash
python -m pytest tests/test_netctl_snmp_profiles.py -k tplink -q
git add netctl/snmp/profiles.py tests/fixtures/snmp/tplink.json tests/test_netctl_snmp_profiles.py
git commit -m "feat: add TP-Link SNMP port profile"
```

---

## Task 11: Add CSS326 legacy FDB and optional LLDP

**Files:**
- Create: `netctl/snmp/lldp.py`
- Create: `tests/fixtures/snmp/css326.json`
- Modify: `netctl/snmp/profiles.py`
- Modify: `netctl/snmp/collector.py`
- Modify: `tests/test_netctl_snmp_profiles.py`

- [ ] **Step 1: Write CSS fixtures**

```text
Q-BRIDGE unsupported -> legacy FDB
port range1-26 is bridge/ifIndex/physical one-to-one
SRV-1 upstream evidence -> physical:24
A2 upstream evidence -> physical:13
A1 upstream evidence -> physical:5
legacy entries use legacy:unknown
unsupported LLDP/VLAN groups do not fail source
```

- [ ] **Step 2: Implement optional neighbor state**

```text
success_with_rows -> replace neighbors
success_empty -> replace with empty neighbors
unsupported/timeout/auth/parse -> preserve prior neighbors
```

- [ ] **Step 3: Verify and commit**

```bash
python -m pytest tests/test_netctl_snmp_profiles.py tests/test_netctl_snmp_parsers.py -q
git add netctl/snmp/lldp.py netctl/snmp/profiles.py netctl/snmp/collector.py tests/fixtures/snmp/css326.json tests/test_netctl_snmp_profiles.py
git commit -m "feat: add CSS326 legacy FDB profile"
```

---

# PR 3C — counters, findings, retention and rollout

## Task 12: Add counter samples and reset-safe deltas

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

```text
normal increase returns current-previous
missing value returns NULL
sysUpTime decrease returns NULL and records reboot/reset
32-bit wrap works only when uptime increased
same port_key survives ifIndex change
failed collection stores no sample
absolute counter values alone create no finding
```

- [ ] **Step 2: Implement default thresholds**

```text
error delta threshold: 1
discard delta threshold: 100
sample retention: 14 days
```

Findings:

```text
interface_errors_increasing
interface_discards_increasing
```

Resolve after one successful below-threshold sample. Do not resolve on failed/missing collection.

- [ ] **Step 3: Verify and commit**

```bash
python -m pytest tests/test_netctl_switch_counters.py -q
git add netctl/snmp/counters.py netctl/switch_store.py tests/test_netctl_switch_counters.py
git commit -m "feat: add switch counter delta findings"
```

---

## Task 13: Add capability cache and retention

**Files:**
- Modify: `netctl/snmp/collector.py`
- Modify: `netctl/switch_store.py`
- Modify: `tests/test_netctl_switch_store.py`

- [ ] **Step 1: Write failing tests**

```text
optional capability reused before expiry
refresh flag bypasses cache
profile fingerprint change invalidates cache
capability outcome change creates a finding
known unsupported optional group skipped until expiry
system/interfaces/bridge/FDB data still collected every run
old events pruned after configured days
old counter samples pruned after configured days
raw files pruned after configured hours
current state/open findings never pruned
```

- [ ] **Step 2: Implement profile fingerprint**

```python
payload = {
    "sys_object_id": system.sys_object_id,
    "sys_descr": system.sys_descr,
    "profile_id": profile.profile_id,
}
fingerprint = sha256(
    json.dumps(payload, sort_keys=True, separators=(",", ":")).encode()
).hexdigest()
```

Cache only capability support decisions. Never cache current FDB rows or interface state.

- [ ] **Step 3: Implement raw capture and pruning**

```text
/var/lib/netctl/raw/snmp/<source-name>/<run-id>.jsonl.gz
```

Directory mode `0750`, file mode `0640`, owner `netctl:netctl`. Store OID/type/value only, never community or secret references.

- [ ] **Step 4: Verify and commit**

```bash
python -m pytest tests/test_netctl_switch_store.py -k "capability or retention or raw" -q
git add netctl/snmp/collector.py netctl/switch_store.py tests/test_netctl_switch_store.py
git commit -m "feat: cache switch capabilities and prune history"
```

---

## Task 14: Add operational findings and status

**Files:**
- Modify: `netctl/switch_store.py`
- Modify: `netctl/switch_queries.py`
- Modify: `netctl/cli.py`
- Modify: `tests/test_netctl_switch_cli.py`

- [ ] **Step 1: Write finding tests**

Implement only:

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
access_port_many_macs: current MAC count >= configured threshold and no explicit uplink/downlink intent
undocumented_aggregation_candidate: threshold reached and no known intent link for port
link_speed_below_100m: oper up and speed below configured threshold
stp_root_changed: previous and new nonblank roots differ
```

These are observations/findings only. Do not edit Git intent or device configuration.

- [ ] **Step 2: Add pagination and status**

All list commands use `--limit`, default `500`, maximum `5000`.

`switches status` returns:

```text
source success/partial/failed counts
current port/FDB/VLAN/neighbor counts
open findings by type/severity
last successful run per source
capability expiry state
retention settings
raw capture enabled sources
free space under /var/lib/netctl
```

- [ ] **Step 3: Verify and commit**

```bash
python -m pytest tests/test_netctl_switch_cli.py tests/test_netctl_switch_counters.py -q
git add netctl/switch_store.py netctl/switch_queries.py netctl/cli.py tests/test_netctl_switch_cli.py
git commit -m "feat: expose switch operational findings"
```

---

## Task 15: Multi-vendor production rollout

**Files:**
- Create before deployment: `docs/runbooks/netctl-snmp-multivendor-rollout.md`
- Create after deployment: `docs/verification/netctl-snmp-multivendor-readiness.md`
- Modify: `README.md`

- [ ] **Step 1: Define secret-free sources**

```text
switch-dgs-server   192.168.100.16  dgs
switch-snr-core     192.168.100.254 snr
switch-tplink-ito   192.168.100.15  tplink
switch-tplink-asmr  192.168.100.14  tplink
switch-css326-srv1  192.168.100.23  css326
switch-css326-a2    192.168.100.24  css326
switch-css326-a1    192.168.100.25  css326
```

Each source has a distinct `secret_ref`. Community values stay only in the protected secret file.

- [ ] **Step 2: Roll out one source at a time**

```text
source disabled
source test
manual collection with capability refresh
inspect capabilities/ports/FDB
second collection
verify event idempotence
review findings
enable source
wait one timer cycle
verify status
```

Fixture mappings must remain exact. Live row counts are recorded and may differ because of network churn.

Expected mapping checks:

```text
DGS: Q-BRIDGE; SNR CPU MAC vid:1 physical:52
SNR: po1 raw31071; VLAN20 ge23+xe3; published STP root facts
TP-Link ITO: VLAN20 endpoint physical:48/ifIndex49200
TP-Link ASMR: upstream direction physical:47
CSS326: legacy; SRV1 physical:24; A2 physical:13; A1 physical:5
```

- [ ] **Step 3: Prove failure preservation**

Use a temporary disabled source with a nonexistent secret reference. Confirm:

```text
run failed
error contains no secret
real source current FDB unchanged
no disappeared event emitted
other sources still complete
```

Delete the temporary source after verification.

- [ ] **Step 4: Verify disk/retention**

```text
/var/lib/netctl free space >20 GiB
raw scheduled capture disabled
no raw file older than 24 hours
counter samples older than 14 days pruned
events older than 180 days pruned
rollback backup integrity ok
```

- [ ] **Step 5: Commit sanitized evidence**

Evidence contains aggregate counts, capabilities, fixture outcomes, failure-preservation result, regression result and service states. It contains no community, raw FDB inventory or raw capture.

```bash
git add docs/runbooks/netctl-snmp-multivendor-rollout.md docs/verification/netctl-snmp-multivendor-readiness.md README.md
git commit -m "docs: verify multi-vendor SNMP collectors"
```

---

## Task 16: Final verification and Issue #5 closure

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

- [ ] **Step 2: Run full checks**

```bash
python -m pytest -q
git diff --check
git grep -nE '(community|NETCTL_SECRET_.*_COMMUNITY)=' -- ':!docs/plans/netctl-snmp-fdb-collectors.md' || true
```

The grep may show variable names or examples without assigned real values. It must not expose credential material.

- [ ] **Step 3: Verify CI on exact merge commits**

Required jobs:

```text
focused-runtime-identity
full-regression
```

Because branch protection is not currently available through the connector, record successful checks manually before each merge and retain the full pytest artifact.

- [ ] **Step 4: Close Issue #5**

The closure comment references:

```text
PR 3A/3B/3C merge commits
focused and full regression
production readiness document
aggregate DGS/SNR/TP-Link/CSS326 outcomes
failed-source preservation proof
secret scan
service/timer status
```

- [ ] **Step 5: Synchronize `network_configuration`**

Mark multi-vendor read-only SNMP/FDB collection complete and select the next phase explicitly. Do not authorize switch writes.

---

## Acceptance Matrix

| Requirement | Evidence |
|---|---|
| Read-only SNMPv2c source | config tests and DGS pilot |
| Secrets outside Git | secret-safe tests and protected env file |
| Explicit outcomes | transport tests |
| Correct FID/VID handling | RFC-based parser tests and profile fixtures |
| DGS Q-BRIDGE profile | synthetic 168-entry fixture and port52 mapping |
| SNR profile | 180-entry fixture, po1, VLAN20 and STP |
| TP-Link normalization | physical48 to ifIndex49200 |
| CSS326 fallback | Q-BRIDGE unsupported, legacy FDB |
| Failed source isolation | collect-all and production failure test |
| Failed FDB preserves current | store test and production proof |
| Successful empty clears current | success-empty test |
| Identical run emits no events | DGS second-run proof |
| Move emits one event | FDB diff test |
| Counter findings use deltas | reset/wrap tests |
| LLDP optional | unsupported/empty tests |
| Retention controls disk | pruning tests and disk check |
| No network writes | code review and read-only runbooks |

---

## Explicitly Deferred

```text
SNMPv1
SNMPv3 USM
SNMP SET
switch configuration backup through SNMP
automatic port shutdown
automatic VLAN/PVID changes
automatic description changes
automatic topology-intent writes
automatic asset merge from FDB
visual topology editor
long-term raw SNMP archive
PostgreSQL migration
parallel source collection
```

The transport abstraction must permit later SNMPv3 support without changing normalized switch tables.

---

## Implementation Start Point

Start PR 3A with Task 1. Do not install production communities or enable SNMP sources until migration tests, secret-safe transport tests, parser fixtures and transactional FDB tests pass.
