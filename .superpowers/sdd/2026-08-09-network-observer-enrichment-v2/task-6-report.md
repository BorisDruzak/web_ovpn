# Task 6 — Device Fingerprinting V2 — implementation report

## Status

Implemented and verified locally in the isolated worktree
`C:\Users\admin-2\Documents\ui_vpn\.worktrees\network-observer-enrichment-v2`.

Starting Git state:

```text
branch: codex/network-observer-enrichment-v2
HEAD: 6b658cb31d34406e2be7cf31c8697bdaa5beb64a
worktree: clean
```

No deployment, SSH, live Nmap scan, package installation, server change,
network lookup, OUI download, or production-network/device write was
performed.

## Implementation

### Typed deterministic engine

- Added frozen, slotted `FingerprintEvidence` and `AssetFingerprint` models.
- Kept the public output set fixed to `pc`, `phone`, `server`, `network`,
  `camera`, `printer`, `noise`, and `unknown`.
- Fixed the version to `fingerprint-v2` and validated all evidence candidates
  and weights at construction time.
- Added deterministic evidence de-duplication and ordering. Repeated versions
  of the same provider/signal/candidate cannot inflate a score.
- Strong, medium, and weak evidence tiers are explicit. Strong evidence ranks
  ahead of contradictory weak hints rather than being defeated by accumulated
  display-name/hostname noise.
- A decision is returned only when the winning score is at least 60 and its
  same-authority lead is at least 15. Otherwise the type is `unknown` and the
  deterministic ranked alternatives are exposed. Confidence is capped at 100.

### Evidence providers

- Strong evidence:
  - confirmed endpoint-agent device type or bounded OS family;
  - known SNMP switch identity;
  - MAC-matched LLDP bridge/router/telephone/access-point capabilities.
- Medium evidence:
  - successful, current-target Nmap OS/device classes with accuracy gating;
  - Nmap service/product/version/CPE with confidence and method weighting;
  - selected product-specific OUI vendors.
- Weak evidence:
  - current DHCP hostname and DNS PTR text;
  - display/manual names and legacy comment/raw kind hints;
  - endpoint switch-port role at only +10.
- Cisco IOS, IOS XE, and NX-OS are explicitly network operating systems;
  Apple iOS/iPadOS remain phone evidence.
- Nmap `probed` service evidence can receive the example +60 weight, while a
  `table` service-name hint is limited to +40. Low-confidence service results
  and low-accuracy OS matches are ignored.
- A downstream-bridge port role never creates switch identity evidence.

### Local OUI behavior

- Added a read-only in-memory-cached parser for
  `/usr/share/nmap/nmap-mac-prefixes`.
- Lookup uses the longest available normalized prefix.
- A missing/unreadable local file returns no evidence without error.
- No network client, download, or browser/card-time external lookup exists.
- Unit tests use the local `tests/fixtures/nmap-mac-prefixes` fixture.

### Persistence and ingestion

- The previously current local migration was 23. Task 6 adds migration 24.
- Added `asset_fingerprint_current` with the required typed result,
  explanation JSON, alternatives JSON, fixed version, and computation time.
- Added a narrow `asset_endpoint_agent_evidence_current` table containing only
  confirmed bounded `device_type`, `os_family`, and observation time.
- The existing endpoint refresh now carries those two safe fields only after
  a unique exact-MAC correlation. It invokes a bounded internal netctl CLI
  ingestion command that atomically replaces the snapshot and recomputes V2.
- The ingestion accepts at most 1000 records and a 256 KiB JSON argument,
  resolves only existing exact asset keys, sanitizes fields, and never invokes
  Nmap. A failed sync leaves the previous web cache intact.
- Derived results never update `assets.kind`; raw runtime identity remains
  unchanged.

### Context and recomputation

- Existing `context["fingerprint"]` remains the backward-compatible normalized
  Nmap projection.
- V2 is exposed additively as `context["device_fingerprint"]`, with a stable
  unknown/default projection when it has not yet been computed.
- Successful topology and attachment reconciliation recompute all asset
  fingerprints inside their existing database transactions using database
  state and the local OUI file only.
- Successful Nmap finalization recomputes only that run's asset in the same
  transaction as the normalized child rows. Failed/reused Nmap runs do not.
- Reconciliation contains no Nmap runner/store invocation and cannot launch a
  scan.

## Files

Created:

- `netctl/fingerprint/__init__.py`
- `netctl/fingerprint/models.py`
- `netctl/fingerprint/engine.py`
- `netctl/fingerprint/providers.py`
- `netctl/fingerprint/oui.py`
- `tests/fixtures/nmap-mac-prefixes`
- `tests/test_netctl_fingerprint_engine.py`
- `tests/test_netctl_fingerprint_providers.py`
- `.superpowers/sdd/2026-08-09-network-observer-enrichment-v2/task-6-report.md`

Modified:

- `netctl/migrations.py`
- `netctl/context_query.py`
- `netctl/topology_reconcile.py`
- `netctl/attachment_reconcile.py`
- `netctl/nmap/store.py`
- `netctl/cli.py`
- `app/endpoint_context_adapter.py`
- `app/endpoint_agent_network.py`
- adjacent migration, context, reconciliation, Nmap, CLI, and endpoint tests

## TDD evidence

The pre-change adjacent baseline passed 48 tests.

Initial RED phases:

- engine/model tests: 7 failures because `netctl.fingerprint` did not exist;
- provider/OUI tests: 8 failures because providers did not exist;
- persistence/context tests: 4 failures before migration 24 and V2 projection;
- Nmap method-quality test: expected table weight 40, received 60;
- final review-boundary group: 7 failures for Cisco IOS mapping, missing
  atomic replacement/CLI ingestion, and missing endpoint refresh caller.

Initial and review-fix GREEN phases:

- engine: 7 passed;
- providers: 8 passed;
- first expanded implementation suite: 169 passed, 1 skipped;
- first review fix suite: 173 passed, 1 skipped;
- final boundary group: 10 passed;
- final expanded Task 6/adjacent suite: 189 passed, 1 skipped.

Mutation checks were also used for required orchestration behavior:

- removing topology and attachment recomputation produced the two expected
  failures, then passed after restoration;
- removing successful-Nmap recomputation produced the expected failure, then
  passed after restoration;
- removing endpoint-refresh ingestion produced the expected failure, then
  passed after restoration.

## Independent review

The first review found no Critical issues, three Important issues, and one
Minor issue: endpoint-agent data lacked a database path, the new context key
had replaced the existing Nmap contract, Nmap confidence was ignored, and the
modest endpoint-port role omitted `server`. These were fixed with bounded
storage, an additive context key, quality-gated Nmap evidence, and the complete
endpoint-like candidate set.

The second review found no Critical issues and two Important issues: Cisco IOS
could be mistaken for Apple iOS, and the endpoint-agent store still had no
production ingestion caller. Both were reproduced and fixed with token-aware
OS handling and the bounded endpoint-refresh-to-netctl sync path.

Final independent re-review ran 102 focused tests and `git diff --check`.
Verdict: `Ready`; no remaining Critical or Important findings.

## Verification

Fresh expanded suite:

```text
pytest -q tests/test_netctl_fingerprint_engine.py \
  tests/test_netctl_fingerprint_providers.py tests/test_netctl_nmap_cli.py \
  tests/test_netctl_nmap_store.py tests/test_endpoint_agent_network.py \
  tests/test_netctl_context_query.py tests/test_netctl_context_migrations.py \
  tests/test_netctl_attachments.py tests/test_netctl_topology.py \
  tests/test_netctl_cli.py
```

Result: 189 passed, 1 skipped, 0 failed in 9.84 seconds.

Fresh full suite:

```text
pytest -q
```

Result: 1561 passed, 11 skipped, 0 failed in 269.07 seconds. Existing
FastAPI/Starlette/pytest-asyncio deprecation warnings remain.

Static verification:

```text
python -m compileall -q netctl/fingerprint netctl/cli.py \
  app/endpoint_agent_network.py app/endpoint_context_adapter.py
git diff --check
```

Both returned exit 0 before the report was written and are repeated in the
final pre-commit verification.

## Scope boundary

This change implements only Task 6. It does not add a browser-triggered flow,
start Nmap from a GET/card view or reconciliation, scan a subnet or asset
collection, download OUI data, overwrite `assets.kind`, deploy code, install
packages, contact the deployment host, or modify network/device configuration.
