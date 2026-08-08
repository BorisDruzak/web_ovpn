# Network Observer Enrichment V2 — Implementation Plan

> **For Codex / agentic workers:** use `superpowers:subagent-driven-development` where practical, or `superpowers:executing-plans`. Work task-by-task with tests and review gates.
> Before implementation, save this plan as:
> `docs/superpowers/plans/2026-08-09-network-observer-enrichment-v2.md`

## Goal

Extend the existing Network Observer without replacing its current runtime-asset/topology architecture.

Implement:

1. SNMP Telemetry Completion.
2. LLDP enrichment while preserving all currently working LLDP behavior.
3. MAC-density / Port Role inference.
4. FDB subtree correlation for switches without reliable LLDP, especially MikroTik CSS.
5. Device Fingerprinting V2 with explainable evidence/confidence.
6. Nmap Fingerprint **only for a specific already-known asset when its device card is opened**.

Do **not** implement OPNsense integration in this phase.

---

# Global constraints

## Repository/workflow

Read `AGENTS.md` first.

Local code:

`C:\Users\admin-2\Documents\ui_vpn`

Deploy host:

`openvpm@192.168.100.30`

Preferred SSH:

`ssh ui-vpn-deploy`

Important:

* inspect the local working tree before changing anything;
* do not reset the local tree to remote `main`;
* preserve any uncommitted/unpushed web-performance changes;
* make changes locally first;
* run targeted and full tests locally;
* deploy only verified changes;
* publish verified final work to `main`.

Do not duplicate network topology, CIDRs or credentials from `BorisDruzak/network_configuration`.

Network collection remains read-only. Do not modify configuration on MikroTik, SNR, TP-Link, CSS, D-Link or other production equipment.

---

# Explicit non-goals

Do NOT implement:

* OPNsense integration;
* Nmap subnet/network discovery;
* scheduled Nmap scans;
* Nmap from `netctl collect all`;
* Nmap from `/network/hosts`;
* arbitrary user-supplied Nmap arguments;
* NSE vulnerability scripts;
* `--script vuln`;
* security-baseline scans;
* UDP scans;
* brute force;
* exploit checks;
* automatic CVE scanning;
* automatic configuration changes on network equipment.

Nmap in this phase has exactly one role:

> enrich an already-existing runtime asset when its device card is opened.

---

# Architectural target

```text
MikroTik ARP/DHCP
        +
Switch SNMP/FDB
        +
LLDP
        +
Endpoint Agent evidence
        |
        v
   Runtime Asset
        |
        +---------------------+
        |                     |
        v                     v
Topology/Attachment      Device card opened
        |                     |
MAC density                   |
FDB correlation               v
        |              Nmap Fingerprint
        |              one asset / one IP
        |                     |
        +----------+----------+
                   |
                   v
          Fingerprinting V2
                   |
          type + confidence
          explainable evidence
```

A device-card GET must remain fast.

**Nmap must never block HTML rendering.**

Correct flow:

```text
GET /network/assets/{asset_key}
        |
        +--> render current DB state immediately
        |
        v
browser JS
        |
POST fingerprint/ensure
        |
        +--> fresh result? return cached
        +--> scan running? do nothing
        +--> stale/missing? start one background fingerprint
        |
GET fingerprint/status
        |
        v
update fingerprint panel
```

---

# Phase 0 — Preserve local work and capture production baseline

## Step 0.1 — Inspect local Git state

From PowerShell:

```powershell
cd C:\Users\admin-2\Documents\ui_vpn

git status --short
git branch --show-current
git rev-parse HEAD
git log -5 --oneline
git diff --stat
git diff
git fetch origin
git log --left-right --oneline origin/main...HEAD
```

Record:

* current local commit;
* branch;
* uncommitted files;
* commits ahead of remote;
* whether the earlier web-performance work is local only.

Do not reset, checkout or overwrite those changes.

## Step 0.2 — Run current tests before modification

At minimum:

```powershell
pytest tests/test_netctl_snmp_parsers.py -q
pytest tests/test_netctl_switch_store.py -q
pytest tests/test_netctl_topology.py -q
pytest tests/test_netctl_attachments.py -q
pytest tests/test_netctl_context_query.py -q
pytest tests/test_web_network_observer.py -q
```

Existing failures must be recorded separately from new failures.

## Step 0.3 — Capture live LLDP baseline before code deployment

Using the deployed instance:

```powershell
ssh ui-vpn-deploy "sudo -u netctl /usr/local/sbin/netctl --json sources list"
ssh ui-vpn-deploy "sudo -u netctl /usr/local/sbin/netctl --json switches status"
ssh ui-vpn-deploy "sudo -u netctl /usr/local/sbin/netctl --json switches capabilities --limit 500"
ssh ui-vpn-deploy "sudo -u netctl /usr/local/sbin/netctl --json switches lldp --limit 5000"
```

Save sanitized outputs outside Git.

For every SNMP source currently returning LLDP information, record:

* source;
* LLDP neighbor count;
* `local_port_key`;
* `chassis_id`;
* `port_id`;
* `system_name`;
* current LLDP capability outcome.

This is the mandatory regression baseline.

A switch which currently has no LLDP rows must **not** automatically be classified as broken.

---

# Task 1 — SNMP Telemetry Completion

The current model already contains `SwitchCounterSample`, and OIDs for errors/discards/high-capacity octets already exist. Complete this path end-to-end.

## Files

Modify:

* `netctl/snmp/oids.py`
* `netctl/snmp/models.py` if counter metadata needs extension
* `netctl/snmp/collector.py`
* `netctl/switch_store.py`
* `netctl/switch_queries.py`
* `netctl/cli.py`
* `netctl/migrations.py`
* `netctl/retention.py`
* `netctl/context_query.py`
* `app/templates/network_asset_detail.html`

Create:

* `netctl/snmp/counters.py`
* `netctl/switch_telemetry.py`

Tests:

* `tests/test_netctl_snmp_parsers.py`
* `tests/test_netctl_switch_store.py`
* `tests/test_netctl_switch_cli.py`
* `tests/test_netctl_retention.py`
* `tests/test_netctl_context_query.py`
* `tests/test_web_network_observer.py`

## Required SNMP data

Collect per interface:

```text
ifHCInOctets
ifHCOutOctets

ifInErrors
ifOutErrors

ifInDiscards
ifOutDiscards
```

Prefer 64-bit HC octet counters.

Also add fallback OIDs if HC counters are unsupported:

```text
ifInOctets  = 1.3.6.1.2.1.2.2.1.10
ifOutOctets = 1.3.6.1.2.1.2.2.1.16
```

The normalized sample must retain enough information to know whether octet counters are 64-bit or 32-bit.

Example extension:

```python
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
    octet_counter_bits: int | None
```

## Persistence

Add a migration using the **next migration number present in the actual local tree**, not a hardcoded number from remote GitHub.

Create historical raw samples:

```text
switch_port_counter_samples
```

Fields at minimum:

```text
id
source_id
collector_run_id
port_key
if_index
observed_at
sys_uptime_ticks
octet_counter_bits
in_octets
out_octets
in_errors
out_errors
in_discards
out_discards
```

Create current derived state:

```text
current_switch_port_telemetry
```

Fields:

```text
source_id
port_key
collector_run_id
observed_at
sample_interval_seconds

rx_bps
tx_bps

rx_utilization_pct
tx_utilization_pct

in_errors_delta
out_errors_delta
in_discards_delta
out_discards_delta

telemetry_state
```

Allowed state examples:

```text
ok
insufficient_history
counter_reset
unsupported
invalid_sample
```

## Delta rules

First sample:

```text
insufficient_history
```

Normal case:

```text
delta = current_counter - previous_counter
rate = delta * 8 / elapsed_seconds
```

Utilization:

```text
rate / port_speed_bps * 100
```

only when port speed is known and valid.

If `sysUpTime` decreases:

```text
counter_reset
```

Do not calculate negative or enormous rates after a device reboot.

For 64-bit counters decreasing unexpectedly:

* treat as reset/invalid;
* do not assume 64-bit wrap.

For 32-bit fallback:

* one modulo `2^32` wrap may be considered;
* accept it only if the resulting bit rate is physically plausible for the known port speed and sample interval;
* otherwise treat it as reset/invalid.

Never clamp an impossible 500% utilization to 100%. Mark the sample invalid instead.

## Collection failure semantics

Telemetry is optional enrichment.

A failed counter capability must:

* not clear a valid FDB;
* not destroy topology;
* not turn an otherwise valid switch snapshot into empty data;
* produce partial/unsupported telemetry state.

Preserve current FDB safety semantics.

## Query

Add:

```text
netctl --json switches telemetry
netctl --json switches telemetry --source <source>
```

Support existing pagination conventions.

## Asset card

For a confirmed attachment, expose port telemetry in:

```text
context.attachment.port.telemetry
```

Show:

```text
Port speed
RX
TX
RX utilization
TX utilization
Errors Δ
Discards Δ
Telemetry state
Last sample
```

Do not create charts in this phase.

## Retention

Use the already existing:

```text
counter_retention_days
```

SNMP source option.

Historical counter samples must respect that setting.

Current derived telemetry must remain available regardless of history cleanup.

## Tests

Cover:

1. first sample;
2. normal 64-bit delta;
3. errors/discards delta;
4. switch reboot;
5. invalid decreasing 64-bit counter;
6. 32-bit fallback;
7. valid 32-bit wrap;
8. physically impossible wrap;
9. unknown port speed;
10. telemetry failure does not destroy FDB;
11. retention;
12. CLI serialization;
13. asset-card context.

Commit independently after all telemetry tests pass.

---

# Task 2 — LLDP Enrichment + mandatory LLDP regression protection

Do not rewrite the existing LLDP implementation.

Preserve the existing identity tuple:

```text
local_port_key
chassis_id
port_id
system_name
```

All existing callers and tests depending on these fields must continue working.

## Files

Modify:

* `netctl/snmp/oids.py`
* `netctl/snmp/lldp.py`
* `netctl/snmp/collector.py`
* `netctl/snmp/models.py` if required
* `netctl/switch_store.py`
* `netctl/switch_queries.py`
* `netctl/migrations.py`
* `netctl/topology_evidence.py`

Tests:

* `tests/test_netctl_snmp_parsers.py`
* `tests/test_netctl_switch_store.py`
* `tests/test_netctl_switch_cli.py`
* `tests/test_netctl_topology.py`

## Add LLDP fields

Collect at minimum:

```text
lldpRemChassisIdSubtype
lldpRemChassisId
lldpRemPortIdSubtype
lldpRemPortId
lldpRemPortDesc
lldpRemSysName
lldpRemSysDesc
lldpRemSysCapSupported
lldpRemSysCapEnabled
```

Use numeric OIDs only.

Extend normalized neighbor to:

```python
{
    "local_port_key": "...",

    "chassis_id": "...",
    "chassis_id_subtype": "...",

    "port_id": "...",
    "port_id_subtype": "...",
    "port_description": "...",

    "system_name": "...",
    "system_description": "...",

    "system_capabilities": [...],
    "enabled_capabilities": [...],

    "management_addresses": [...]
}
```

## Optional-field rule

This is critical.

Currently working LLDP must **not stop working because one enrichment OID is unsupported**.

Core neighbor identity requires only what is necessary to safely join the existing LLDP record.

Optional fields such as:

```text
system description
port description
capabilities
management address
```

must be independently optional.

Do not require all optional OID index sets to be identical before accepting the core neighbor.

## Capabilities

Normalize LLDP capability bits into explicit names, for example:

```text
bridge
router
telephone
wlan_access_point
station_only
repeater
```

Implement according to the LLDP-MIB bit definition and back it with fixtures/tests.

Do not guess bit positions.

## Management address

Implement IPv4 management-address parsing first.

IPv6 may be included only if it can be added cleanly without weakening validation.

Malformed management address data must not destroy an otherwise valid LLDP neighbor.

## Topology

Existing chassis-MAC topology evidence remains stronger than textual names.

Additional LLDP data may enrich evidence:

```text
management_address
system_description
capabilities
```

but must not create false links solely because two devices have similar `sysName`.

## Fingerprinting provider

Expose LLDP evidence for Fingerprinting V2:

```text
bridge            -> network
router            -> network
telephone         -> phone
wlan_access_point -> network
```

Do not create a new AP UI device type in this phase.

## Regression tests

Existing tests must remain.

Add explicit regression fixture:

```text
old LLDP payload:
chassis_id + port_id + system_name only
```

Expected:

* neighbor still parses;
* existing output fields unchanged;
* enrichment fields empty rather than failure.

Add enriched fixture with all new fields.

## Mandatory production verification

Before deployment we already captured LLDP baseline.

After deployment:

1. pick **one currently working LLDP-enabled switch**;
2. manually trigger read-only collection for only that source;
3. run:

```text
netctl --json switches capabilities --source <source>
netctl --json switches lldp --source <source> --limit 5000
```

Compare the core tuples:

```text
source
local_port_key
chassis_id
port_id
system_name
```

They must remain present unless the physical network actually changed.

Only after this passes, collect remaining enabled SNMP switches.

Final implementation report must contain:

```text
LLDP before:
sources with rows
neighbor count per source

LLDP after:
sources with rows
neighbor count per source

core rows lost unexpectedly: 0
```

---

# Task 3 — Port Role / MAC-density Engine

Implement deterministic port-role inference.

This does not depend on OPNsense.

## Files

Create:

* `netctl/port_roles.py`
* `netctl/fdb_correlation.py`

Modify:

* `netctl/migrations.py`
* `netctl/cli.py`
* `netctl/switch_queries.py`
* `netctl/attachment_candidates.py`
* `netctl/attachment_reconcile.py`
* `netctl/topology_reconcile.py`
* `netctl/context_query.py`
* `app/templates/network_asset_detail.html`

Tests:

* `tests/test_netctl_attachments.py`
* `tests/test_netctl_topology.py`
* new `tests/test_netctl_port_roles.py`
* `tests/test_netctl_context_query.py`
* `tests/test_web_network_observer.py`

## Persistence

Create:

```text
current_switch_port_roles
```

At minimum:

```text
source_id
port_key

role
confidence

mac_count
known_asset_count
unique_vendor_count

child_source_id
evidence_json

observed_at
correlation_run_id
```

Allowed roles:

```text
endpoint
backbone
downstream_bridge
shared_edge
unknown
```

## Existing configuration

Reuse:

```text
snmp_access_port_mac_threshold
```

Default currently configured as 10.

Do not create a second competing threshold option.

## Evidence rules

### Confirmed topology

If the port participates in an existing confirmed/non-conflicting switch link:

```text
role = backbone
confidence ~= 100
```

### LLDP child switch

If LLDP confidently identifies another known switch:

```text
role = backbone/downstream_bridge
confidence >= 95
```

depending on topology direction.

### Single endpoint

If:

```text
learned endpoint MAC count = 1
no switch management MAC
not backbone
no conflicting topology
```

then:

```text
role = endpoint
confidence ~= 80
```

### 2–3 MAC

Do not immediately call it an uplink.

Possible causes:

* IP phone + PC passthrough;
* hypervisor;
* small bridge;
* AP;
* downstream switch.

Use:

```text
shared_edge or unknown
```

with moderate confidence.

### High density

If:

```text
MAC count >= access_port_mac_threshold
```

but no child switch has been identified:

```text
role = shared_edge
```

not `downstream_bridge`.

Reason:

high MAC density alone does not distinguish:

```text
switch
Wi-Fi AP
bridge
virtualization host
```

---

# Task 4 — FDB Subtree Correlation

This specifically targets CSS and other downstream switches where LLDP may be missing or weak.

## Core concept

For each possible child switch:

```text
child_leaf_mac_set
```

consists of current child FDB MACs, excluding:

* child's own management/self MACs;
* MACs learned on known backbone ports;
* invalid/self entries.

For every candidate parent port:

```text
parent_port_mac_set
```

Calculate:

```text
intersection = child_leaf_mac_set ∩ parent_port_mac_set

coverage =
    len(intersection)
    /
    len(child_leaf_mac_set)
```

## Strong inference

A downstream-switch candidate becomes strong when, for example:

```text
child leaf MAC count >= 4
coverage >= 0.80
```

and preferably:

```text
child management MAC also appears on the parent port
```

Store evidence similar to:

```json
{
  "type": "fdb_subtree",
  "child_source": "css326-floor2",
  "child_leaf_mac_count": 16,
  "matched_mac_count": 15,
  "coverage": 0.9375,
  "child_management_mac_seen": true
}
```

## Reverse-port resolution

Attempt to find the parent's management MAC in the child's FDB.

If exactly one child port contains it:

```text
parent port known
child uplink port known
```

A complete inferred topology link may be produced.

If remote child port cannot be proven:

**do not invent it.**

Keep:

```text
parent port -> suspected child switch
```

in port-role evidence.

Do not manufacture:

```text
CSS ether1
CSS port24
```

without evidence.

## Conflict hierarchy

Stronger evidence wins:

```text
declared intent
>
LLDP exact link
>
bidirectional management-MAC/FDB evidence
>
FDB subtree correlation
>
MAC density alone
```

Never allow FDB correlation to silently replace contradictory stronger LLDP/intent evidence.

## Attachment scoring

Use port-role data when resolving endpoints.

A port marked:

```text
backbone
downstream_bridge
```

must receive a strong penalty as a direct endpoint attachment.

`shared_edge` should reduce confidence but not eliminate the candidate.

## CLI

Add:

```text
netctl --json switches port-roles
netctl --json switches port-roles --source <source>
```

## Asset card

In the connection section display, when relevant:

```text
Роль порта: downstream bridge
Уверенность: 94%
MAC на порту: 17
Предполагаемый дочерний коммутатор: CSS326-02
```

Show a concise evidence reason.

---

# Task 5 — Nmap Fingerprint Core

Nmap is not a discovery source.

It operates only on a runtime asset already in the database.

## Files

Create package:

```text
netctl/nmap/
    __init__.py
    models.py
    policy.py
    runner.py
    parser.py
    store.py
```

Modify:

* `netctl/migrations.py`
* `netctl/cli.py`
* `netctl/context_query.py`
* `netctl/retention.py` if history retention is added
* `deploy/install-openvpn-web.sh`
* deployment sudoers/helper files

Create:

```text
deploy/netctl-nmap-fingerprint
deploy/sudoers-netctl-nmap
```

Tests:

```text
tests/test_netctl_nmap_policy.py
tests/test_netctl_nmap_parser.py
tests/test_netctl_nmap_runner.py
tests/test_netctl_nmap_store.py
tests/test_netctl_nmap_cli.py
```

Do not add a Python Nmap wrapper dependency.

Use:

```python
subprocess.run(...)
xml.etree.ElementTree
```

## Input contract

The public/CLI entrypoint accepts only:

```text
asset_key
```

It does NOT accept:

```text
IP supplied by web client
ports
Nmap arguments
scripts
scan profile arguments
CIDR
hostname
```

Netctl resolves the newest/current IPv4 observation from the runtime asset.

Version 1 supports only one canonical IPv4 address.

Reject:

```text
CIDR
hostname
0.0.0.0
loopback
multicast
broadcast-like invalid input
```

## Nmap fixed profile

Define one immutable profile:

```text
asset-fingerprint-v1
```

It should perform bounded:

```text
TCP port fingerprinting
service/version detection
OS fingerprinting
```

No NSE scripts.

Use a fixed command built in code/helper, roughly:

```text
nmap
-n
-Pn
-sS
-O
--osscan-limit
-sV
--version-light
--top-ports 100
--max-retries 1
--host-timeout 20s
-T3
-oX -
<one validated IPv4>
```

The exact bounded port profile may be adjusted after one live test if required for useful results, but it must remain hardcoded/config-defined — never browser supplied.

Use:

```python
shell=False
```

No shell interpolation.

## Privilege isolation

Do not run the web service as root.

OS detection/SYN scanning needs raw-packet privileges.

Use a small root-owned helper:

```text
/usr/local/libexec/netctl-nmap-fingerprint
```

The helper:

* accepts exactly one argument;
* validates it as canonical IPv4;
* rejects additional arguments;
* constructs the complete Nmap command itself;
* outputs XML;
* has a hard timeout;
* never evaluates shell text.

`netctl` may sudo only this helper.

Do not give `openvpn-web` permission to call arbitrary Nmap as root.

Current chain should remain:

```text
openvpn-web
    |
sudo -u netctl
    |
netctl fingerprint ...
    |
sudo restricted-helper <validated-ip>
    |
nmap
```

Validate sudoers with:

```text
visudo -cf
```

## Deployment dependency

Add an explicit Nmap dependency check.

Do not silently continue when `/usr/bin/nmap` is absent.

Installation may either:

* install the distro package consistently with project deployment conventions; or
* fail preflight with an explicit actionable dependency error.

Do not introduce a Python Nmap package.

## XML parser

Parse only normalized fields.

### Port

```text
protocol
port
state

service_name
product
version
extra_info
tunnel
method
confidence
CPE[]
```

### OS

Parse:

```text
osmatch.name
osmatch.accuracy

osclass.type
osclass.vendor
osclass.osfamily
osclass.osgen
osclass.accuracy
CPE[]
```

### Run

Record Nmap version.

Ignore `<script>` nodes.

The command must never generate NSE output in this phase.

Do not persist raw XML long-term.

## Persistence

Create:

```text
nmap_fingerprint_runs
nmap_fingerprint_ports
nmap_fingerprint_os_matches
```

`nmap_fingerprint_runs`:

```text
id
asset_id
target_ip
profile
status
started_at
finished_at
nmap_version
error_class
error_message
```

Statuses:

```text
running
success
failed
```

Ports reference a run.

OS matches reference a run.

Keep error messages sanitized. Do not expose raw stderr to web users.

## TTL

Default:

```text
3600 seconds
```

Make it configurable.

Opening the same card repeatedly must not repeatedly scan the host.

## Single-flight

Implement atomically.

`ensure(asset)`:

```text
latest successful result fresh
    -> return fresh

running scan exists and is not stale
    -> return running

running scan is stale
    -> mark failed/reclaim

no fresh/running scan
    -> create one running run
    -> execute exactly one fingerprint
```

Concurrent ensures for the same asset must result in one Nmap process.

A web-process crash must not permanently lock the asset in `running`.

Define a short stale-running timeout greater than the Nmap hard timeout.

## CLI

Add:

```text
netctl --json fingerprint status --asset-key <asset_key>

netctl --json fingerprint ensure --asset-key <asset_key>
```

Do not add network-wide commands.

Do not add:

```text
fingerprint all
fingerprint subnet
```

in this phase.

---

# Task 6 — Device Fingerprinting V2

Implement deterministic, explainable classification.

Nmap is one evidence provider, not the authority.

## Files

Create:

```text
netctl/fingerprint/
    __init__.py
    models.py
    engine.py
    providers.py
    oui.py
```

Modify:

* `netctl/migrations.py`
* `netctl/context_query.py`
* reconciliation flow as described below

Tests:

```text
tests/test_netctl_fingerprint_engine.py
tests/test_netctl_fingerprint_providers.py
tests/test_netctl_context_query.py
```

## Supported output types

Keep current public types:

```text
pc
phone
server
network
camera
printer
noise
unknown
```

Do not proliferate new types yet.

## Evidence model

Use a typed structure equivalent to:

```python
@dataclass(frozen=True)
class FingerprintEvidence:
    provider: str
    signal: str
    candidate_type: str
    weight: int
    summary: str
```

Output:

```python
@dataclass(frozen=True)
class AssetFingerprint:
    device_type: str
    confidence: int
    evidence: tuple[FingerprintEvidence, ...]
    alternatives: tuple[dict[str, object], ...]
    version: str
```

Version:

```text
fingerprint-v2
```

## Deterministic precedence

Strong evidence:

```text
existing authoritative endpoint-agent OS/device evidence
known SNMP switch identity
LLDP bridge/router/telephone capabilities
```

Medium evidence:

```text
Nmap OS class
Nmap device class
Nmap service product/version/CPE
OUI vendor
```

Weak evidence:

```text
DHCP hostname
DNS PTR
display name
legacy textual hints
port role
```

A weak hostname hint must never overpower strong contradictory evidence.

## Example scoring direction

Examples, not independent classification shortcuts:

```text
known SNMP switch                  network +100
LLDP bridge/router                 network +90
LLDP telephone                     phone +90

Nmap device type network device    network +70
Nmap OS general purpose Windows    pc/server candidates +40

Hikvision/Dahua/HiWatch OUI        camera +50
Grandstream/Yealink OUI            phone +50
Kyocera/Brother/Xerox              printer +50

RTSP/Hikvision Nmap product        camera +60
JetDirect/IPP printer product      printer +60
RouterOS/MikroTik service          network +60
```

Final selection:

```text
top score >= 60
AND
top score - second score >= 15
```

Otherwise:

```text
device_type = unknown
```

and expose alternatives.

Cap final confidence at 100.

## OUI

Use the local Nmap MAC prefix database when installed:

```text
/usr/share/nmap/nmap-mac-prefixes
```

Requirements:

* read-only;
* cached in memory;
* missing file degrades gracefully;
* no internet lookup;
* no OUI download when opening a card;
* unit tests use a fixture file.

Vendor alone must not always force a type.

Example:

```text
MikroTik OUI + known switch/network evidence
    -> strong network

generic HP OUI alone
    -> insufficient to decide PC vs printer
```

## Port role as evidence

Port role describes attachment topology, not device identity.

Therefore:

```text
endpoint port
```

may modestly strengthen endpoint-like classifications.

But:

```text
downstream_bridge
```

does not automatically turn the attached asset into a switch unless switch identity evidence also exists.

## Persistence

Create:

```text
asset_fingerprint_current
```

At minimum:

```text
asset_id PRIMARY KEY
device_type
confidence
evidence_json
alternatives_json
fingerprint_version
computed_at
```

Do not destructively overwrite raw runtime identity.

`assets.kind` remains existing/raw state.

Expose derived V2 fingerprint separately.

## Recompute

Recompute Fingerprinting V2:

1. after topology/attachment/port-role reconciliation using DB-only evidence;
2. after a successful Nmap fingerprint for that asset.

Do **not** launch Nmap from reconciliation.

---

# Task 7 — Card-triggered Nmap integration

This is the only automatic Nmap trigger in this phase.

## Existing route

Keep:

```text
GET /network/assets/{asset_key}
```

fast and DB-only.

The GET route must not directly execute Nmap.

## Web endpoints

Add authenticated endpoint:

```text
POST /network/assets/{asset_key}/fingerprint/ensure
```

Requirements:

* authenticated session;
* CSRF verification;
* validate runtime asset key;
* no target IP from browser;
* immediately return status/202;
* schedule bounded background `netctl fingerprint ensure`.

Add:

```text
GET /network/assets/{asset_key}/fingerprint/status
```

Requirements:

* authenticated;
* read only;
* return cached normalized result.

## Background behavior

Use the existing FastAPI background-task mechanism or an equally bounded existing project pattern.

The HTTP response must not wait for Nmap.

The single-flight protection lives inside the netctl/database layer, not only in the browser.

## JavaScript

When `network_asset_detail.html` loads:

```text
1. render cached state
2. POST fingerprint/ensure once
3. check fingerprint/status
4. if running -> poll every ~2 seconds
5. stop after success/failure
6. stop polling when page becomes hidden
7. never have overlapping polling requests
8. impose a total UI polling deadline around 30 seconds
```

Refreshing the card inside TTL must produce:

```text
Nmap processes started: 0
```

## Card panel

Add:

### Device fingerprint

```text
Тип
Уверенность
OUI/vendor
OS
Nmap accuracy
Last fingerprint time
```

### Network services

Compact table:

```text
Port | Protocol | Service | Product | Version
```

Only show normalized open-port results.

### Evidence

Show concise explainable evidence:

```text
LLDP: bridge
OUI: MikroTik
Nmap: RouterOS
FDB: direct attachment
```

Do not display:

* raw Nmap XML;
* command line;
* raw stderr;
* vulnerability language;
* CVE claims.

## Nmap state

Show:

```text
Нет данных
Обновление...
Актуально
Ошибка fingerprint
```

A failed Nmap scan must not make the device card itself fail.

---

# Task 8 — Integrate enriched data into asset context

Extend:

```text
netctl context-view asset --asset-key ...
```

with bounded sections:

```json
{
  "fingerprint": {
    "device_type": "camera",
    "confidence": 96,
    "evidence": [],
    "alternatives": [],
    "computed_at": "...",
    "version": "fingerprint-v2"
  },
  "nmap_fingerprint": {
    "status": "success",
    "target_ip": "...",
    "started_at": "...",
    "finished_at": "...",
    "ports": [],
    "os_matches": []
  }
}
```

Also expose:

```text
attachment.port.telemetry
attachment.port.role
```

Keep the response bounded.

Do not expose internal secrets, SNMP communities, sudo information or raw collector payloads.

Use the existing empty `evidence` concept only if it remains semantically clean; otherwise add the explicit top-level `fingerprint` section rather than stuffing unrelated structures into a generic dictionary.

---

# Task 9 — Test matrix

Run targeted tests after each subsystem.

## SNMP

```powershell
pytest tests/test_netctl_snmp_parsers.py -q
pytest tests/test_netctl_switch_store.py -q
pytest tests/test_netctl_switch_cli.py -q
pytest tests/test_netctl_retention.py -q
```

Must cover:

* counters;
* fallback;
* reboot/reset;
* LLDP legacy payload;
* LLDP enriched payload;
* unsupported optional LLDP OIDs.

## Port roles/topology

```powershell
pytest tests/test_netctl_port_roles.py -q
pytest tests/test_netctl_topology.py -q
pytest tests/test_netctl_attachments.py -q
```

Required scenarios:

### Single endpoint

```text
1 learned MAC
=> endpoint
```

### Phone/pass-through style

```text
2 MAC
=> not automatically uplink
```

### Dense unknown port

```text
>= threshold
no child identified
=> shared_edge
```

### CSS downstream

```text
parent port sees child mgmt MAC
child leaf FDB coverage >= 80%
=> downstream_bridge
```

### Missing remote child port

```text
child inferred
remote uplink unknown
=> do not invent remote port
```

### LLDP conflict

```text
LLDP says child A
FDB correlation suggests child B
=> preserve stronger LLDP
=> expose conflict/evidence
```

## Fingerprinting

```powershell
pytest tests/test_netctl_fingerprint_engine.py -q
pytest tests/test_netctl_fingerprint_providers.py -q
```

Required examples:

```text
Hikvision OUI + RTSP/Hikvision service
=> camera high confidence

Grandstream OUI + LLDP telephone
=> phone high confidence

known SNMP switch + Nmap network device
=> network high confidence

HP OUI alone
=> do not force printer

Windows Nmap OS + PC hostname
=> pc

two competing strong types
=> unknown/ambiguous
```

## Nmap

```powershell
pytest tests/test_netctl_nmap_policy.py -q
pytest tests/test_netctl_nmap_parser.py -q
pytest tests/test_netctl_nmap_runner.py -q
pytest tests/test_netctl_nmap_store.py -q
pytest tests/test_netctl_nmap_cli.py -q
```

Required:

* only one IPv4;
* CIDR rejected;
* hostname rejected;
* extra arguments impossible;
* `shell=False`;
* fixed profile;
* XML parser Windows fixture;
* Linux fixture;
* network-device fixture;
* service-only fixture;
* malformed XML;
* timeout;
* fresh TTL;
* stale TTL;
* stale-running recovery;
* concurrent `ensure` creates only one Nmap invocation.

## Web

```powershell
pytest tests/test_web_network_observer.py -q
```

Explicit tests:

```text
GET asset card does NOT call Nmap
POST ensure requires auth
POST ensure requires CSRF
POST ensure does not block on scan
status returns cached result
Nmap failure does not fail asset card
```

## Full suite

Finally:

```powershell
pytest -q
```

Do not deploy with unexplained failures.

---

# Task 10 — Deployment and production verification

## Step 10.1 — Review local diff

```powershell
git status --short
git diff --stat
git diff
```

Check especially:

* no credentials;
* no topology hardcoding;
* no arbitrary shell execution;
* no Nmap arguments sourced from request;
* no broad sudo permission.

## Step 10.2 — Deploy using project workflow

Deploy to:

```text
192.168.100.30
```

Do not restart unrelated infrastructure.

Verify:

```text
nmap binary
root-owned helper
sudoers
netctl migrations
web service
```

Run:

```text
visudo -cf /etc/sudoers.d/<new-file>
```

## Step 10.3 — LLDP canary

Before collecting every switch, select one switch that had working LLDP in the baseline.

Run one source collection.

Then:

```text
netctl --json switches capabilities --source <source>
netctl --json switches lldp --source <source> --limit 5000
```

Verify:

```text
core LLDP neighbors preserved
new fields present where supported
unsupported fields do not break core neighbors
```

Only then continue.

## Step 10.4 — Full SNMP verification

Run:

```text
netctl --json switches status
netctl --json switches capabilities --limit 500
netctl --json switches ports --limit 5000
netctl --json switches fdb --limit 5000
netctl --json switches lldp --limit 5000
netctl --json switches telemetry --limit 5000
netctl --json switches port-roles --limit 5000
```

Verify:

* counters populate where supported;
* unsupported switches remain usable;
* CSS FDB remains usable;
* no FDB unexpectedly vanished;
* port roles are plausible.

## Step 10.5 — Verify CSS correlation

Pick at least one known CSS downstream path.

Compare:

```text
parent switch FDB
CSS FDB
port role
child-source inference
```

Check that:

* dense parent port is detected;
* child can be inferred when evidence is sufficient;
* remote CSS port is not fabricated when unknown.

## Step 10.6 — Nmap canary

Pick one known normal asset.

Open:

```text
/network/assets/<asset>
```

Verify:

1. HTML renders without waiting for Nmap.
2. One background fingerprint starts.
3. Process targets exactly one IP.
4. No CIDR/range arguments.
5. No NSE scripts.
6. Result reaches status endpoint.
7. Device card updates.
8. Fingerprinting V2 recomputes.
9. Refresh card inside TTL.
10. No second Nmap process starts.

Then test a second asset.

It may start its own fingerprint.

## Step 10.7 — Negative Nmap verification

Verify that Nmap does **not** run when:

```text
opening /network/hosts
running netctl collect all
running netctl reconcile
systemd network collection timer runs
opening dashboard
```

## Step 10.8 — Resource check

Check:

```text
CPU
load average
memory
netctl logs
web logs
collection duration
```

The new SNMP counters must not cause unacceptable collection-duration growth.

---

# Acceptance criteria

Implementation is complete only when all of the following are true.

## SNMP telemetry

* Real counter samples are collected.
* RX/TX rates are derived safely.
* Errors/discards deltas work.
* Reboots/counter resets never produce giant false rates.
* Current FDB behavior is preserved.
* Telemetry is visible for the attached port in device card.

## LLDP

* Existing LLDP parser behavior remains valid.
* Existing LLDP production neighbors remain visible.
* `chassis_id`, `port_id`, `system_name` remain backward compatible.
* New LLDP fields appear where supported.
* Unsupported enrichment OIDs do not destroy a valid neighbor.
* Before/after LLDP verification report shows no unexplained lost core neighbors.

## MAC density / CSS

* Port-role inference exists.
* 1-MAC endpoint is distinguishable from dense shared ports.
* High MAC count alone does not automatically mean switch.
* FDB subtree correlation can identify probable downstream CSS.
* Strong LLDP/intent wins over weaker inference.
* Unknown CSS remote uplink ports are never fabricated.

## Fingerprinting V2

* Classification is deterministic.
* Classification is evidence-driven.
* Confidence is explainable.
* Ambiguous results remain ambiguous.
* Nmap is only one provider.
* Strong SNMP/LLDP/agent evidence has precedence over weak text/OUI evidence.

## Nmap

* Only already-known runtime assets can be fingerprinted.
* Browser cannot supply IP/ports/Nmap arguments.
* Exactly one IPv4 target per run.
* No subnet scanning exists.
* No scheduled Nmap scanning exists.
* No NSE scripts exist in this phase.
* Device-card GET does not block on Nmap.
* Opening a stale/unscanned asset card triggers one bounded fingerprint.
* Reopening inside TTL produces zero new scans.
* Concurrent opens produce one scan through single-flight.
* Raw XML is not stored.
* Web never receives raw stderr.

## Quality

* targeted tests pass;
* full `pytest -q` passes;
* deployment smoke passes;
* LLDP regression verification passes;
* no secrets committed;
* verified work published to `main`.

---

# Required final Codex report

Return a concise implementation report containing:

```text
1. Local starting Git state
2. Files changed
3. Migrations added
4. SNMP telemetry implemented
5. LLDP fields added
6. LLDP before/after live verification
7. Port-role/MAC-density algorithm implemented
8. CSS/FDB subtree test result
9. Fingerprinting V2 evidence providers
10. Exact fixed Nmap profile
11. Nmap privilege isolation
12. Nmap TTL/single-flight behavior
13. Unit/integration/full test results
14. Production canary results
15. Any unsupported SNMP/LLDP capabilities found on real equipment
16. Final commit SHA on main
```

If a real device behaves differently from fixtures, preserve its sanitized SNMP/Nmap characteristics in a test fixture before adding a vendor-specific workaround.

Do not solve vendor-specific behavior by weakening global validation.
