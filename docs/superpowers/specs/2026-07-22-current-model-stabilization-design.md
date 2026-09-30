# Current Model Stabilization Design

**Date:** 2026-07-22  
**Status:** approved design, pending implementation plan  
**Repository:** `BorisDruzak/web_ovpn`

## 1. Purpose

Stabilize the already implemented correlated-context and network-control model before adding any new policy type or infrastructure feature.

This phase corrects the consistency, correlation, audit, credential-delivery, and API-contract defects found after the first production deployment. It does not add DNS filtering, domain policies, route collection, path-engine features, service-access policies, VLAN changes, switch writes, or a web redesign.

The approved implementation shape is three independently reviewable deliveries:

```text
S1 — consistency and control-plane security
S2 — correlation quality and complete asset context
S3 — versioned API and operational contract
```

## 2. Current state

The repository already contains:

```text
canonical context revisions and imported intent
runtime assets, interfaces, IP and hostname observations
multi-vendor SNMP switch collection
current FDB, ports, VLAN, STP, LLDP and events
source identity and topology reconciliation
endpoint attachment candidates and resolutions
user registry, bindings and network sessions
RouterOS path facts and conservative path explanation
netopsctld with signed authorization envelopes
asset/user Internet allow/deny plans
signed append-only audit and external checkpoints
```

The production deployment has proven the migrations and services, but the current model still has these defects:

1. `netopsctl.policy_resolver` opens the live WAL-backed `netctl.sqlite` with `immutable=1`, which is invalid for a database that collectors continue to modify.
2. Attachment eligibility accepts only switch runs with `status='success'`; an authoritative FDB from a `partial` run may be ignored even when only an optional capability failed.
3. Production source identity is incomplete, so the topology engine conservatively produces no backbone links and most endpoint attachments remain ambiguous or unresolved.
4. Asset context returns one best attachment for the whole asset instead of one resolution per interface.
5. Asset context keeps `owner=null` despite implemented user-to-asset bindings.
6. The broker authenticates the Unix peer with `SO_PEERCRED`, but signed audit payloads do not retain the actual UID, GID, and PID of the accepted connection.
7. Private signing material is loaded from paths named in an environment file instead of systemd credentials.
8. New context endpoints use `/api/v1`, but their response, snapshot, pagination, bounds, and caching contracts are incomplete.
9. Operational documentation still describes several completed stages as pending.

## 3. Fixed scope

### 3.1 In scope

```text
WAL-safe read-only snapshots for plan creation and apply-time revalidation
fail-closed behavior when context cannot be read consistently
actual Unix peer UID/GID/PID in signed audit evidence
systemd credential delivery for private signing material
partial-run FDB eligibility based on mandatory capability success
source-identity readiness diagnostics
backbone evidence diagnostics
per-interface endpoint attachments
real owner/user-binding context
preservation of ambiguity and last successful state
versioned context API envelopes
snapshot metadata
signed cursor pagination
ETag/If-None-Match
bounded topology responses
deployment, backup, rollback, verification, and roadmap synchronization
```

### 3.2 Explicitly out of scope

```text
DNS filtering or domain blocking
new DNS collectors or adapters
new route collection or path-engine behavior
service-access policy
new firewall policy types
new firewall anchors
VLAN migrations or VLAN writes
switch-port shutdown or enable
switch configuration writes
DHCP or DNS writes
captive portal or RADIUS integration
new directory/helpdesk adapters
web-page redesign
asset auto-merge
changing the operator-selected production-writes flag
```

## 4. Production-write decision

Production writes may remain enabled throughout this stabilization phase.

The implementation must not set either of these values automatically:

```text
NETOPSCTL_PRODUCTION_WRITES_ENABLED
NETOPSCTL_AUDIT_CHECKPOINT_HEALTHY
```

The release preserves the operator-configured values. If production writes are enabled before a deployment, they remain enabled after the deployment. During the short atomic update window, the broker socket and service are stopped so that no new operation can start against mixed application versions. Existing MikroTik address-list state remains active while the broker is unavailable.

Enabled writes do not weaken failure behavior. Every request remains fail-closed. No RouterOS mutation may occur when any of these conditions is true:

```text
live context snapshot cannot be opened
snapshot transaction cannot be established
plan basis changed
plan expired
IP observation is stale
IP is currently bound to another asset
asset is provisional or retired
identity collision is open
attachment is ambiguous, uplink-only, unresolved, or conflicting
source collection is stale or failed
firewall anchor is absent, duplicated, or changed
audit checkpoint cannot be delivered
device operation lock is held
```

The phase adds no new write operation. Only the existing Internet policy lifecycle remains available.

## 5. Selected architecture

### 5.1 Rejected alternatives

#### One hotfix PR

Rejected because it would remove `immutable=1` but leave correlation quality, asset context, and API compatibility unresolved.

#### Full rewrite

Rejected because the existing intent, identity, SNMP, topology, user, path, authorization, audit, and policy foundations are usable. The defects are bounded and can be corrected incrementally.

### 5.2 Selected approach

Three deliveries with separate acceptance and rollback boundaries:

```text
S1 fixes context consistency and broker evidence.
S2 fixes what the model concludes from existing observations.
S3 fixes how that model is exposed and operated.
```

No delivery depends on a web redesign.

---

# S1 — Consistency and Control-Plane Security

## 6. WAL-safe context snapshots

### 6.1 Single read-only connection contract

Remove the private `_open_context_immutable()` implementation from `netopsctl.policy_resolver`.

All live reads of `netctl.sqlite` must use the existing `netctl.db.connect_read_only()` behavior:

```text
SQLite URI mode=ro
PRAGMA query_only=ON
PRAGMA busy_timeout=5000
no schema creation
no migration application
no journal-mode mutation
no immutable=1
```

Add a reusable snapshot context manager, for example:

```python
with read_context_snapshot(db_url) as conn:
    ...
```

Its contract is:

```text
open one read-only connection
execute BEGIN
read the complete basis through that connection
COMMIT on success
ROLLBACK on failure
close the connection
```

Plan creation and apply-time revalidation each use one independent read transaction. A plan may be created from snapshot A; apply must open a new snapshot B immediately before device writes and compare the complete basis.

### 6.2 Snapshot failure semantics

Any SQLite operational error, busy timeout, missing WAL visibility, malformed basis, or inconsistent read produces a bounded precondition failure. It never falls back to cached plan targets and never performs a RouterOS write.

The broker returns a stable error classification such as:

```json
{
  "status": "stale_precondition",
  "replan_required": true,
  "changed_preconditions": ["context_snapshot_unavailable"]
}
```

Internal database paths and exception text are not exposed to API callers.

### 6.3 Concurrency tests

Tests must prove:

```text
a committed WAL update is visible to a new read snapshot
one snapshot never mixes rows from before and after a writer commit
apply-time revalidation detects IP/context/attachment changes
failed read transaction causes zero adapter calls
read-only connection creates no schema or data changes
immutable=1 is absent from production code
```

## 7. Unix peer evidence in the audit chain

`SO_PEERCRED` remains the first trust check. The accepted connection identity must be passed through the broker as an immutable structure:

```text
uid
gid
pid
service_principal
```

`ControlService.dispatch()` and `_audit()` must receive both:

```text
authenticated_peer
  uid, gid, pid, service_principal

authorized_subject
  principal_type, principal_id, principal_name,
  session_id, authorization_id
```

The audit payload must never reconstruct UID/GID/PID from configuration. It records the credentials returned by the accepted socket connection.

Tests must reject:

```text
unknown UID before JSON parsing
configured UID with wrong GID
forged JSON actor
valid envelope from the wrong local principal
reconciler principal invoking plan approval or apply
```

Tests must verify that successful and failed signed audit events contain the real peer UID/GID/PID and the separately authorized human/API subject.

## 8. Systemd credential delivery

Private keys must no longer be selected by arbitrary paths from `EnvironmentFile`.

Use systemd credentials for at least:

```text
web-to-broker Ed25519 signing key
netopsctl audit signing key
reconciler signing key, when the reconciler is enabled
```

Units declare explicit credentials and production code reads them from:

```text
${CREDENTIALS_DIRECTORY}/<credential-name>
```

The environment file may retain non-secret settings:

```text
key IDs
source mappings
plan TTL
freshness thresholds
audit sink host and instance ID
feature gates
```

Public verification keys may remain ordinary root-owned configuration files because they are not secret, but their ownership and mode remain validated at startup.

Startup fails closed when a required credential is missing, empty, oversized, symlinked, or has invalid key length. Error output identifies only the credential role, not its contents or absolute secret path.

## 9. S1 deployment behavior

The deployment procedure is:

```text
1. Create online SQLite backups of netctl.sqlite and netopsctl.sqlite.
2. Verify both backups with PRAGMA integrity_check and SHA-256.
3. Record the deployed application commit and current write-gate values.
4. Stop netopsctl-reconcile.timer if active.
5. Stop netopsctl.socket and netopsctl.service.
6. Deploy the new application and unit files atomically.
7. Install systemd credentials without changing the write-gate values.
8. Apply additive migrations only if the reviewed implementation requires them.
9. Verify migration ledgers and database integrity.
10. Start netopsctl.socket and netopsctl.service.
11. Run a signed status request.
12. Create a dry-run plan and prove a stale-precondition rejection.
13. Verify existing desired policies and managed address-list entries are unchanged.
14. Run one approved test-asset plan/apply/verify/rollback lifecycle.
15. Re-enable the reconciler timer only if it was enabled before the update and its credential is valid.
```

Rollback restores both the previous application tree and the matching SQLite backups. It does not change the production-write flag.

### S1 acceptance

```text
live WAL reads use a normal read-only transaction
apply-time basis is re-read immediately before writes
zero writes occur on snapshot failure
actual peer UID/GID/PID is signed into audit events
private signing keys arrive through systemd credentials
existing Internet-policy operations still pass controlled apply/verify/rollback
full regression passes
```

---

# S2 — Correlation Quality and Complete Asset Context

## 10. Authoritative switch-run eligibility

Attachment eligibility must not depend only on `switch_collection_runs.status='success'`.

A site has authoritative FDB evidence when the latest relevant switch run satisfies all of these conditions:

```text
run status is success or partial
the selected FDB capability is qbridge_fdb or legacy_fdb
the selected FDB outcome is success_with_rows or success_empty
the current FDB transaction for that run committed successfully
```

A `partial` run is eligible only when the failure is confined to optional capabilities such as VLAN, STP, or LLDP. Timeout, authentication failure, or parse failure of the selected FDB capability is not authoritative and must preserve the previous current attachment state.

Implement one shared helper for this decision. Do not duplicate status parsing in SQL fragments.

Tests must cover:

```text
success + FDB rows is eligible
success + authoritative empty FDB is eligible
partial + FDB success + optional VLAN failure is eligible
partial + FDB timeout is ineligible
failed run is ineligible
older success does not override a newer authoritative success/partial run
failed latest run preserves the last successful current model
```

## 11. Source-identity readiness

Add a read-only readiness model for every RouterOS and SNMP source.

The response includes only sanitized metadata:

```text
source name and driver
site
topology role
runtime asset binding and status
intent context/stable-ID binding and status
management MAC count
latest identity/FDB/LLDP collection state
latest authoritative FDB run ID and age
known switch-port count
eligible for topology: yes/no
blocking reason codes
```

Stable reason codes include:

```text
missing_topology_role
missing_runtime_asset_binding
missing_intent_binding
missing_management_mac
no_authoritative_fdb
stale_authoritative_fdb
no_port_inventory
ambiguous_management_mac
ready
```

The readiness command/API must explain why the current production graph contains no backbone link. It must not mutate source configuration or auto-confirm a binding.

## 12. Backbone evidence diagnostics

For every attempted source pair, expose bounded evidence diagnostics:

```text
intent link matched or unmatched
management MAC visible or not visible
LLDP matched or unmatched
local port resolved or unresolved
remote port resolved or unresolved
confidence contribution
conflict reason
```

No raw FDB dump is returned through this diagnostic.

The correlation engine continues to preserve these states:

```text
confirmed
inferred
ambiguous
conflicting
```

If reconciliation fails before a complete candidate graph is produced, current links and link events remain unchanged. A failed run records bounded failure evidence only.

## 13. Per-interface attachment model

An asset may have several active interfaces. Context output must represent every interface independently.

Target structure:

```json
{
  "interfaces": [
    {
      "interface_key": "mac:AA:BB:CC:DD:EE:FF",
      "mac": "AA:BB:CC:DD:EE:FF",
      "interface_type": "ethernet",
      "lifecycle": "active",
      "attachment": {
        "status": "confirmed",
        "switch_source": "tplink-ito",
        "port_key": "48",
        "vlan_key": "vid:20",
        "vlan_id": 20,
        "confidence": 95,
        "last_seen_at": "...",
        "alternatives": []
      }
    }
  ]
}
```

Rules:

```text
one interface never borrows another interface's attachment
ambiguous alternatives stay attached to the correct interface
inactive interfaces remain visible but are not policy-eligible
an asset-level summary may be retained temporarily for compatibility
new control logic uses per-interface data only
```

## 14. Owner and user-binding context

Replace the hard-coded `owner=null` with an explicit owner-resolution object.

Target states:

```text
none
confirmed
ambiguous
shared
```

Resolution rules:

```text
one active confirmed owner or primary_user binding -> confirmed
multiple active confirmed owner/primary_user bindings -> ambiguous
active confirmed shared_user binding -> shared
no active confirmed binding -> none
candidate, rejected, retired, or expired bindings do not become owner
session evidence never becomes owner automatically
```

The context includes bounded binding evidence:

```text
user key
display name
relation
status
confidence
validity interval
binding source
```

No personal data beyond fields already stored in the user registry is added.

## 15. S2 preservation semantics

```text
failed topology reconciliation preserves current_switch_links
failed attachment reconciliation preserves confirmed current resolutions
ineligible latest switch run does not emit false detached/disappeared events
new ambiguity replaces a confirmed resolution only after a complete successful run
all events reference the correlation run that produced them
findings are bounded and deduplicated
```

### S2 production acceptance

The acceptance target is correctness and explainability, not a hard-coded number of confirmed devices.

Production verification must show:

```text
a readiness result for every configured switch/router source
an explicit reason for every source not used in the backbone
at least one known expected link represented as confirmed/inferred or an exact blocking reason
per-interface attachment output for a known multi-interface fixture
owner state derived from real bindings
partial authoritative FDB accepted in a controlled fixture
failed reconciliation preserves the previous current state
```

---

# S3 — Versioned API and Operational Contract

## 16. Compatibility strategy

Do not rewrite every existing `/api/v1` response at once.

Apply the new envelope first to the correlated-context endpoints:

```text
/api/v1/context/search
/api/v1/context/assets/{asset_key}
/api/v1/context/topology
/api/v1/context/findings
/api/v1/context/source-readiness
```

The response retains the existing `status` and `data` fields during the compatibility window and adds the versioned contract:

```json
{
  "status": "ok",
  "api_version": "1.0",
  "request_id": "...",
  "generated_at": "...",
  "snapshot": {
    "context_revision_id": 1,
    "correlation_run_id": 4,
    "observation_cutoff": "..."
  },
  "data": {},
  "pagination": null,
  "errors": []
}
```

Existing clients that read `data` continue to work. New clients must use `api_version` and `snapshot`.

Breaking field removal, enum changes, or semantic changes require `/api/v2`. The v1 compatibility window is at least 90 days or two production release cycles, whichever is longer.

## 17. Snapshot contract

Each context response pins the state used to answer the request:

```text
active context revision
latest successful topology correlation run
latest successful attachment correlation run
observation cutoff timestamp
```

A response must not combine rows from multiple correlation runs without declaring the relevant run IDs.

## 18. Cursor pagination

Use opaque signed cursors for:

```text
context search
findings
attachment events
link events
source-readiness history, if exposed
```

Cursor contents bind:

```text
API version
snapshot/run IDs
sort timestamp
stable numeric ID
normalized filters
limit
expiry
```

Clients never receive raw cursor fields. The cursor is authenticated with a dedicated signing credential. Tampering, expiry, or filter mismatch returns a stable 400/409 error without exposing signature details.

Limits:

```text
default collection limit: 100
maximum collection limit: 500
search default: 25
search maximum: 50
```

Offset pagination is not added to the new contract.

## 19. Topology bounds

Topology is bounded rather than paginated.

```text
default depth: 3
maximum depth: 8
default max_nodes: 250
maximum max_nodes: 1000
```

The response includes:

```json
{
  "truncated": true,
  "truncation_reason": "max_nodes"
}
```

The existing normal UI depth remains within the new limits.

## 20. ETag and cache consistency

Asset context and topology responses include an ETag derived from:

```text
API version
context revision
correlation run IDs
asset update marker
binding update marker
attachment update marker
finding update marker
normalized request filters
```

`If-None-Match` returns `304` only when the same logical snapshot is still current.

## 21. API error contract

Errors use stable codes and sanitized details:

```json
{
  "status": "error",
  "api_version": "1.0",
  "request_id": "...",
  "generated_at": "...",
  "snapshot": null,
  "data": null,
  "pagination": null,
  "errors": [
    {
      "code": "cursor_expired",
      "message": "The cursor is no longer valid for this snapshot"
    }
  ]
}
```

No database path, SQL statement, credential path, RouterOS response, or Python exception is returned.

## 22. Documentation and issue synchronization

After S3 verification:

```text
mark the correlated-context implementation as completed
record S1/S2/S3 deployment evidence
close or update issues whose implementation already exists
record remaining production topology blockers separately
retain the no-DNS/no-new-routes scope of this stabilization phase
```

Documentation must distinguish:

```text
implemented code
deployed capability
production data quality
production writes enabled/disabled state
```

---

# 23. Testing strategy

## 23.1 Focused suites

```text
S1:
  policy resolver snapshots
  broker peer security
  authorization
  audit
  systemd credential deployment
  Internet policy lifecycle

S2:
  source identity
  topology evidence
  topology reconciliation
  attachment eligibility
  attachment reconciliation
  context query
  user bindings

S3:
  context API
  cursor signing
  cursor tamper/expiry
  ETag
  topology bounds
  compatibility responses
```

## 23.2 Full verification

Every delivery requires:

```text
focused pytest suite
full pytest regression
Python compilation
git diff --check
secret-pattern scan
migration test from the current production schema when applicable
backup restore rehearsal when schema or credential layout changes
```

Tests use synthetic or sanitized fixtures and never contact live devices.

# 24. Rollout sequence

```text
1. Implement and deploy S1.
2. Run controlled plan/apply/verify/rollback with production writes still operator-enabled.
3. Implement and deploy S2.
4. Populate or correct source metadata through the existing approved configuration workflow.
5. Re-run topology and attachment reconciliation.
6. Implement and deploy S3.
7. Verify compatibility with the current web client and API token clients.
8. Synchronize network_configuration roadmap and GitHub issues.
```

# 25. Completion criteria

The stabilization phase is complete when all of the following are true:

```text
no production code opens live netctl.sqlite with immutable=1
plan creation and apply revalidation use separate WAL-aware read transactions
snapshot failure produces zero RouterOS mutations
signed audit events contain actual peer UID/GID/PID
private signing material is delivered through systemd credentials
production-write configuration is preserved, not toggled by deployment
partial runs with authoritative FDB can participate in attachment correlation
source readiness explains every missing backbone source/link
failed reconciliation preserves the previous current graph and attachments
asset context returns owner state and attachment per interface
context APIs expose version, request ID, snapshot, pagination, and errors
cursor tampering and expiry are rejected
asset/topology ETags work
production verification includes backup, integrity, pre-check, post-check, and rollback evidence
no DNS, route, service-access, VLAN, or new network-write feature is introduced
```

# 26. Architectural decisions retained

```text
IP is an observation, never stable asset identity.
Different MACs are never merged automatically.
Imported intent, raw observations, correlations, desired policy, and executed changes remain separate.
Ambiguity is a valid result and is never guessed away.
Failed collection or reconciliation preserves the last successful current state.
netctl remains read-only toward devices.
netopsctld accepts only enumerated operations.
Existing Internet policy writes remain fail-closed and evidence-backed.
Production writes may remain enabled; this phase does not toggle the gate.
```