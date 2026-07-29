# Network Host Availability Design

**Date:** 2026-07-29

## Goal

Make the `online` value on the Network Observer device page mean that the
address responded to a completed, recent active availability probe.  The
feature must remove the current false-positive behaviour where a historical
MikroTik ARP row without a MAC address can remain `online` indefinitely.

The design combines bounded active ICMP/TCP probing with the existing
read-only ARP, DHCP, MikroTik bridge-host and SNMP FDB evidence.  It changes
only Netctl data, the read-only web/API presentation, and its timers.  It
must not configure routers, switches, DHCP, DNS, OpenVPN, or firewalls.

## Problem Statement

On 2026-07-29 the deployed observer returned 250 records for
`192.168.99.1` through `192.168.99.250`, all marked `online`.  Only 26 had a
MAC address.  Of the 250, 221 had last been observed on 2026-07-10; their raw
ARP evidence declared `complete=true` while the MAC was empty.  For example,
`192.168.99.2` had no MAC and a last observation from 2026-07-10.

The current normalizer maps any complete ARP entry to `online`, and host
storage retains its status until that IP is later upserted.  Absence cleanup
only demotes selected noise categories.  Consequently, neither a missing MAC
nor old `last_seen_at` protects the user from a false current-status claim.

## Scope

### Included

- A read-only active probe of every address in each explicitly allowed CIDR.
- ICMP and configured TCP evidence with bounded execution time and
  concurrency.
- A single, documented meaning for `online`, `seen`, `offline`, and `stale`.
- Current probe evidence and bounded probe history in Netctl storage.
- Recalculation of existing host presentation after the first completed
  availability cycle.
- API, web-table, host-detail, dashboard, log, timer, deployment, rollback,
  and test changes required for the new semantics.

### Excluded

- Router, switch, DHCP, DNS, firewall, OpenVPN, or endpoint configuration
  writes.
- Arbitrary user-selected networks, ports, commands, credentials, or probe
  options in the web UI or API.
- Port scanning, service discovery, Nmap installation, OS fingerprinting, or
  exposing raw network packet data.
- A guarantee that an endpoint blocking both ICMP and all allowed TCP ports
  is powered off; it is reported as `offline` from the observer's viewpoint.

## Authoritative Configuration and Safety Boundary

The active revision of the canonical network context remains the sole source
of monitored CIDRs.  Netctl derives the availability target set from active
context segments whose `availability_monitoring` flag is enabled.  A segment
without that flag is never probed.  This repository does not duplicate CIDRs
or topology in a second hand-maintained list.

The context contract adds these optional, validated fields to an eligible
segment:

```yaml
availability_monitoring: true
availability_tcp_ports: [22, 80, 443]
```

`availability_tcp_ports` is a deduplicated list of integers in `1..65535`.
An omitted list means ICMP only.  The context importer rejects a monitoring
flag on a non-IPv4 segment in this release and rejects any other probe
configuration field.  Endpoint- or device-specific exceptions are explicitly
out of scope for release one; this keeps the active surface auditable.

The availability job accepts no request parameters and no operator input.  It
uses fixed executable arguments, never a shell, and contacts only target IPs
expanded from the validated active context.  TCP probes use `connect()` only;
they send no application payload and do not authenticate.  ICMP uses the
platform's fixed ping command with a numeric address and fixed timeout.

## Availability Semantics

Availability is the presentation status computed from the latest completed
availability run for the host's eligible CIDR.  The outcome never reuses a
historic `network_hosts.status` value.

| Status | Definition | Required evidence |
| --- | --- | --- |
| `online` | The host answered a probe in the latest successful CIDR run. | ICMP reply or successful TCP connection to an allowed port. |
| `seen` | The latest successful run did not confirm the address, but passive evidence is fresh. | Valid MAC plus current ARP, bound/online DHCP, bridge-host, or authoritative SNMP FDB evidence. |
| `offline` | The latest successful run completed for the address and did not produce active or fresh passive evidence. | Completed negative probe outcome; no fresh qualifying passive evidence. |
| `stale` | The observer cannot make a current availability assertion. | The relevant CIDR run failed, was incomplete, is older than its freshness budget, or no successful CIDR run exists. |
| `connected` | Existing OpenVPN session state. | Unchanged; it takes precedence for a matching tunnel IP. |

`online` is intentionally not inferred from DHCP lease state, an ARP entry,
an FDB entry, or a bridge-host entry.  These inputs can explain `seen` but
cannot upgrade it.  An ARP entry with a null, blank, or malformed MAC is never
qualifying passive evidence and is retained only as diagnostic history.

For an active result, ICMP success wins immediately.  If ICMP does not
succeed, Netctl tries the segment's allowed TCP ports in ascending order and
records the first successful `tcp:<port>` method.  A timeout, refused TCP
connection, unreachable error, or missing ICMP binary is not a successful
probe.  A TCP refusal is useful diagnostic detail but is not evidence of
reachability for this feature.

Fresh passive evidence means a valid-MAC observation from a collection that
finished no more than two collection intervals ago.  For the deployed
five-minute collector this is ten minutes.  The value is derived from the
collector interval, not hard-coded at each call site.  Availability runs are
fresh for two availability intervals; with the release-one interval of five
minutes, a successful result becomes `stale` after ten minutes.

## Active Probe Design

The `netctl availability collect` command runs every five minutes after the
normal collection cycle.  It expands every enabled monitored CIDR, excluding
network and broadcast addresses for IPv4.  Overlapping segment targets are
deduplicated by IP; the most-specific segment supplies its TCP port policy.

The default resource limits are:

- maximum 64 concurrent address workers;
- ICMP timeout of one second;
- TCP connect timeout of one second per allowed port;
- maximum three TCP ports per segment;
- one attempt per method per run; no retries;
- an overall run deadline of 90 seconds per `/24` equivalent.

The runner persists an incomplete run as `failed` with a sanitized reason.
It must never publish partial negative outcomes as `offline`: all addresses
belonging to that CIDR are `stale` until a complete successful run replaces
the result.  Positive observations gathered before a run failure remain in
history but do not make the failed run current.

Probe execution begins only after `netctl collect all` completes successfully.
The availability timer remains a recovery mechanism: it may run independently
after boot, but it first verifies that the active context is valid and that
the relevant collector sources are healthy.  A collector or context failure
produces `stale`, not a fresh scan based on unknown topology.

## Passive Evidence Design

Existing data sources are retained with narrower meaning:

- MikroTik ARP: valid IP-to-MAC mapping can support `seen`; empty or invalid
  MAC cannot.
- DHCP: a `bound` or `online` lease with a valid MAC can support `seen`.
- MikroTik bridge-host: a valid MAC observed on a current bridge port can
  support `seen` and provides a port hint.
- authoritative SNMP FDB: a valid MAC from a successful current collector
  run can support `seen` and provides switch, port, and VLAN context.

Passive records must be joined by normalized MAC where applicable.  They must
not manufacture an IP from an FDB-only MAC.  A host with only FDB evidence
therefore remains a device/attachment observation until an IP association is
also known.

## Data Model

Add three Netctl tables through a new forward-only SQLite migration:

1. `availability_runs`: one row per CIDR execution with `id`, context revision
   id, CIDR, started/finished timestamps, `status` (`success` or `failed`),
   target count, completed target count, and sanitized error reason.
2. `availability_results`: current result per `(cidr, ip)`, with the run id,
   `active_state` (`reachable`, `unreachable`, `not_run`), successful method,
   last checked timestamp, and a normalized failure class.  Only a successful
   run replaces current results for its CIDR.
3. `availability_result_events`: append-only, compact history of result
   changes and run outcomes.  Retention is 30 days, using the existing Netctl
   retention flow.

`network_hosts` remains the source of identity, category, site, passive
timestamps, and historical observation data.  Its stored `status` column is
no longer the authoritative display value for monitored CIDRs.  A dedicated
`availability_for_host()` projection joins `network_hosts`, current results,
source health, and valid passive evidence, then returns the computed status
and evidence summary.  The dashboard, CLI, API, and web routes all use this
same projection.  Probe targets alone do not create `network_hosts` rows: a
new host is materialized only after active success or qualifying passive
evidence.  This prevents a `/24` scan from turning 254 addresses into 254
displayed devices.

The public host object gains these stable fields:

```json
{
  "status": "online",
  "availability": {
    "state": "online",
    "active_method": "icmp",
    "checked_at": "2026-07-29T07:10:43Z",
    "run_status": "success",
    "cidr": "192.168.99.0/24",
    "passive_evidence": ["mikrotik_arp", "snmp_fdb"],
    "reason": "active_icmp_reply"
  }
}
```

For non-monitored addresses `availability` is `null`; their existing
presentation is unchanged.  The API never returns command output, TCP error
text, credentials, raw SNMP records, or probe timing details.

## UI and API Behaviour

`GET /api/v1/network/hosts` and `/network/hosts` use the computed status.
The default view is **Current devices** and includes only `online`, `seen`,
and `connected`; this is the count compared with an active scan.  `offline`
and `stale` history is available only through explicit status filters and is
clearly labelled as historical/not currently confirmed.  The existing status
filter gains `stale`; `online`, `seen`, `offline`, and `connected` retain
their names but receive the semantics above.  The network filter offers only
active monitored CIDRs plus existing filters.

The table shows `Last active check` and a compact `Evidence` column.  Examples:

- `online · ICMP · 12:10`;
- `online · TCP 443 · 12:10`;
- `seen · DHCP, FDB · passive evidence 12:08`;
- `offline · active probe 12:10`;
- `stale · run failed at 12:10`.

The detail page shows the same status plus its CIDR, probe method, most recent
check, passive evidence, and a non-sensitive reason.  The dashboard publishes
separate counts for `online`, `seen`, `offline`, and `stale`, the last
successful availability run for each monitored CIDR, and failed/incomplete
run counts.  It must not combine `seen` or `stale` into `online`.

## Historical Recalculation and Rollout

Deployment starts with a SQLite backup and migration verification.  No host
rows are deleted.  Until the first successful availability run, every host in
a monitored CIDR displays `stale`; historical `network_hosts.status=online`
does not leak through.

After the first successful full run, every existing host in the CIDR is
recalculated from that run and fresh passive evidence.  The default current
view for `192.168.99.0/24` then changes from 250 historical `online` rows to
only currently confirmed `online`/`seen` devices, while old ARP/DHCP/bridge
history remains available through an explicit historical-status filter.  An
interrupted first run leaves the CIDR `stale`, never partially `offline`.

Rollback disables the availability timer and reverts the application release;
the migration is additive and retained.  The old UI must not be restored
against a database schema it cannot read.  A forward-compatible application
release continues to ignore availability tables when monitoring is disabled.

## Error Handling and Observability

- Invalid or unavailable active context: do not probe; mark its prior targets
  `stale` with `context_unavailable`.
- Collector unhealthy or stale: do not treat passive data as fresh; mark
  affected targets `stale` if no current successful active run exists.
- Missing ping executable, socket resource exhaustion, or run deadline:
  fail the CIDR run atomically and log only the error class.
- Individual ICMP/TCP negative results within a fully completed run are normal
  results, not job errors.
- Configuration validation rejects overly broad CIDRs, duplicates after
  normalization, more than three TCP ports, and monitoring not backed by the
  active canonical context.
- Logs contain run id, CIDR, aggregate counts, duration, and error class; they
  never enumerate every failed IP at info level.

## Verification and Acceptance Criteria

Automated tests must prove:

- complete ARP with a missing MAC cannot yield `online` or qualifying passive
  evidence;
- ICMP success yields `online` and records `icmp`;
- ICMP failure followed by allowed TCP success yields `online` and
  `tcp:<port>`;
- ICMP/TCP failure with fresh valid-MAC ARP, DHCP, bridge, or authoritative
  FDB yields `seen`;
- a fully completed negative run with no fresh passive evidence yields
  `offline`;
- no completed run, stale run, failed run, or partial run yields `stale`, not
  `offline`;
- an OpenVPN-connected tunnel IP remains `connected`;
- target expansion includes every usable IPv4 address in the enabled CIDR,
  excludes network/broadcast, deduplicates overlap, and never uses UI/API
  input;
- a probe result alone does not create a host row; the default list contains
  only current `online`/`seen`/`connected` devices and an explicit historical
  filter is required to display `offline` or `stale` rows;
- run replacement is atomic: failed runs cannot overwrite current successful
  results;
- API, page filters, dashboard counts, and host detail use the same projected
  status and redact sensitive details;
- the first successful rollout run recalculates historical false `online`
  records while retaining raw observations;
- timer/service contracts enforce fixed intervals, resource limits, and
  read-only network operation.

Deployment acceptance for `192.168.99.0/24` requires a before/after export of
the host count by availability status, manual comparison against a separately
run active scan, verification that an empty-MAC ARP record is not `online`,
and confirmation that no RouterOS/SNMP/OpenVPN configuration changed.
