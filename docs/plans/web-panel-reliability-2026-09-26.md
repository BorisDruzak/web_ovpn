# Web panel reliability implementation plan

**Goal:** Implement T01–T13 from [SPEC](../specs/web_ovpn_codex_spec_2026-09-26.md).
**Execution:** Native, task by task, with regression tests before fixes.
**Architecture:** Retain FastAPI/Jinja, SQLAlchemy and SQLite, CLI boundaries and saved Netctl snapshots. Inventory owns physical facts; network and Endpoint observations remain separate.
**Baseline:** clean `main`, `fab1cac1db0bc95e5536ff73c5d8fb103c90b358`; GitNexus indexed the same commit. No deployment or production actions are authorized. Existing docs/plans is used.

## Traceability and readiness

| Requirement | Stage | Components | Dependencies | Tests / readiness |
|---|---|---|---|---|
| T01 | M2 | main.py, api.py, CLI clients, durable operations | T02 | CLI barrier, deduplication, restart/unknown result, partial success |
| T02 | M1 | auth.py, models.py, config.py, browser/API gates | none | capability matrix, CSRF, ownership, bootstrap/cookie configuration |
| T03 | M1 | audit.py, inventory web/api/service, db.py | none | fresh-session rollback, late failure, one commit, legacy audit callers |
| T04 | M2 | network_hosts.html, snapshot page backend | snapshot contract | 230 rows, URL state, clamping, no snapshot vs empty filter |
| T05 | M2 | inventory.js, inventory_asset_form.html | form contract | real clicks, IP/MAC, zero/select normalization, undo and dirty state |
| T06 | M4 | endpoint_agent_network.py, network web/API/JS | T13 | shared SSR/refresh projection, unchanged snapshot, no live read/N+1 |
| T07 | M3 | inventory forms, server draft model/service | T02,T09 | independent tabs, owner/expiry, reload/errors, bounded cookie |
| T08 | M2 | network-hosts-refresh.js | T04,T06,T13 | deferred responses/timers, cancellation, hidden tab, timeout/recovery |
| T09 | M1 | asset model, migration, web/API/service | T03 | atomic revision compare/write, children, telemetry separation, edit/delete/link races |
| T10 | M6 | existing templates/CSS/navigation | other stages | accessible controls, desktop/mobile flows, complete browser scenario |
| T11 | M3 | asset lifecycle, all readers/workers/photos | T02,T03,T09 | historical deletion/restore, peripheral retention, no resurrection/external deletion |
| T12 | M5 | export service/routes/templates | T02,T11,T13 | parser, all pages, safe text/types, coherent snapshot, bounded resources, synthetic workbook |
| T13 | M4 | source-specific bindings/indexes, Netctl identity, projections/UI | T02,T03,T09,T11 | IP change/reuse, multiple interfaces, collisions/concurrency, both directions |

## Implementation sequence

- [x] M0: Read affected paths and relevant tests; run baseline, record environment/failures.
- [ ] M1a/T03: Reproduce PC + peripherals + invalid identifier using a fresh DB session. Make audit commit optional while preserving legacy default; operation owns commit and rollback. Verify SQLite savepoint behavior and API workplace path. Validate detail parsing errors before writes. Run inventory/audit regressions.
- [ ] M1b/T02: Enumerate browser/service capability gates and establish explicit inventory/VPN/network/export rights without granting legacy bearer blanket administration. Test every mutation and protected download.
- [ ] M1c/T09: Add non-destructive manual revision migration; implement atomic compare-and-write shared by HTML/API and relevant relationship actions, with conflict input retention.
- [ ] M2a/T05: Add explicit source-to-form map, visible normalization failures, reversible replacement. Exercise actual controls in isolated browser.
- [ ] M2b/T04,T08: Add server pagination controls and URL state; replace interval polling with completion scheduling, timeout and generation cancellation. Prove races with controlled timers.
- [ ] M2c/T01: Map complete blocking paths; offload bounded synchronous work; add small durable executor for long mutations with owned sessions, scoped idempotency and restart reconciliation. No blind retry of unknown external effects.
- [ ] M3/T07,T11: Server-owned independent draft lifecycle and historical soft deletion across readers, workers, API and files. Upgrade synthetic old schema twice; verify preserved IDs/history and no automatic relationship restoration.
- [ ] M4/T13,T06: Verify runtime device_key semantics and source-specific cardinality. Add explicit confirmed/rejected/history bindings and shared batched read projection with enrichment revision. Keep Endpoint constraints intact.
- [ ] M5/T12: Select declared XLSX library after documentation check. Implement bounded authorized inventory and single-version network export; attach synthetic file and parser results.
- [ ] M6/T10: Complete UI states, run end-to-end with Endpoint absent/network unavailable, full applicable regressions and application smoke. Inspect complete diff, diff --check, GitNexus impact; publish verified atomic changes to main. Never deploy.

## Review focus

SQLite SAVEPOINT release outside an actual outer BEGIN; late validation after an audit write; multiple same-location tabs; stale response following filter navigation; reused IP and repeated MAC. Each belongs to its stage tests above.

## Discovery evidence / verification log

- `python -m pytest -q tests/test_inventory_web.py tests/test_inventory_service.py tests/test_inventory_endpoint_models.py tests/test_network_host_snapshot.py`: NOT RUN (incorrect final test filename; collection reported no tests). Correct Netctl filename: tests/test_netctl_host_snapshot.py.
- Targeted baseline running: `python -m pytest -q tests/test_inventory_web.py tests/test_inventory_service.py tests/test_inventory_endpoint_models.py`.
- Environment: Windows/PowerShell, Python 3.14, Node.js available. Dependencies pinned in requirements.txt; installed runtime versions must be recorded separately.
- T03: write_audit commits every call; HTML workplace creation writes relation success before details/identifiers validation. API workplace creates a released nested savepoint before later validations. These are hypotheses pending regression evidence.
- T05: source ip/mac differs from input ip_address/mac_address; insertion handler silently returns on missing control/empty value. Pending browser reproduction.
- T08: interval polling overlaps metadata; metadata-only success clears warning. Pending controlled behavioral tests.

## Checkpoint 2026-09-26

Overall goal remains ACTIVE. T03, T04 and T05 have local regression/browser evidence; T08 core polling is verified, with composed enrichment freshness pending T06/T13. T01,T02,T06,T07,T09,T10,T11,T12,T13 remain OPEN.

- Baseline inventory command above: 57 PASS.
- T03: regression before fix: 5 FAIL, 1 PASS (persisted PC/peripherals, released SQLite savepoint, three commits); after fix: 9 PASS. Fresh DB sessions check no cards/relations/success audit remain after validation, late detail/audit failures, or rollback. Success commits once; legacy audit default and optional rollback tested.
- Ruling: explicitly BEGIN only the SQLite workplace write transaction before its savepoint. A trial global non-legacy BEGIN added reader locks and broke Endpoint lease/failure workflows; it was removed. Endpoint sync regressions pass with the targeted implementation. No schema/config changes in T03.
- T05: Playwright MCP reproduced missing IP insertion before fix. `tests/browser/inventory_endpoint_insert.js` passed on loopback synthetic fixture: IP/MAC save/reload, undo, zero, unsupported OS preservation, dirty-state action lock. Browser console: zero errors. Cache version endpoint-5; script now loads on every asset form.
- T04: `tests/browser/network_hosts_pagination.js` passed: 230 unique rows via UI in 3 pages, Back/Forward, page jump, size 25, empty filter. Server regression first failed on page=999; after fix clamps within one saved SQL snapshot. Existing out-of-range tests updated to the required clamping behavior.
- T08: old interval overlaps metadata (RED: 2 requests vs 1). `node tests/network_hosts_refresh.test.js` PASS: pending request serialization, hidden/visible/context cancellation, late response discard, timeout/session recovery, failed-row retry despite unchanged metadata, malformed row preservation, freshness transitions. Projection version consumer prepared; provider belongs to M4.
- `python -m pytest -q tests/test_inventory_atomicity.py tests/test_inventory_api.py tests/test_inventory_web.py tests/test_inventory_service.py tests/test_inventory_endpoint_web.py tests/test_inventory_endpoint_sync.py --disable-warnings --tb=short`: 109 PASS.
- `python -m pytest -q tests/test_netctl_host_snapshot.py tests/test_inventory_netctl_sync.py tests/test_web_network_observer.py --disable-warnings --tb=short`: 131 PASS.
- Environment actual: Python 3.14.3, FastAPI 0.115.6, installed SQLAlchemy 2.0.51 (deployment pin 2.0.36), Node 24.15.0. SQLite transaction approach verified against SQLAlchemy 2.0 docs via Context7. Exact pinned runtime verification remains OPEN.
- A full suite overlapped implementation edits and is diagnostic only: 2278 PASS, 7 FAIL, 11 SKIP. Three failures were the removed global-BEGIN trial; one caught polling during RED. The remaining three are baseline failures, independently reproduced on an untouched `git archive HEAD` extract in C:/Temp/web-ovpn-spec-baseline: test_api_routes.py::test_hosts_list_paginates_snapshot_without_live_commands; ::test_hosts_api_accepts_dash_prefixed_query_with_real_snapshot; test_netctl_cli.py::test_runtime_assets_status_reports_identity_operational_summary. Two use September 7 records with default 24h filtering on September 26; third expects migrations through 26 although baseline includes 27. Keep as separate backlog; no production defect inferred.
- GitNexus `write_audit` upstream impact: 97 direct callers, 55 processes, CRITICAL indexed blast radius. Preserve default commit semantics for all untouched callers; only explicit multi-write operations opt out. API/web shapes retained.
- `git diff --check` and Node syntax checks passed at checkpoint. Full stable release regression, rights, migration, XLSX and complete end-to-end remain OPEN. Production: NOT RUN, not authorized.

## Permission checkpoint

- T02 core: explicit browser/service capability checks before CLI/domain/file work; observers read, inventory editors/VPN operators have separate writes/downloads, delete/export not granted to legacy bearer. Existing network-control scopes/HTTPS gates are retained. Newly added delete/export endpoints must still be tested when implemented in T11/T12.
- Repeatable permissions migration preserves old hashes/roles; bootstrap is create-only; new accounts default to non-admin. Production rejects the development secret/short keys and always sets Secure/HttpOnly/SameSite=Lax cookies. Administrator-only `/admin/users` assigns known capabilities with CSRF and atomic success audit. Configuration guidance: docs/runbooks/panel-permissions.md; no production configuration changed.
- Download consumption checks ownership and uses conditional UPDATE; two simultaneous consumers yield exactly one success. Denied capability/foreign owner cannot consume the token.
- RED administration test: 404 before the UI existed; GREEN latest command: `python -m pytest -q tests/test_panel_permissions.py tests/test_download_tokens.py tests/test_inventory_api.py tests/test_inventory_endpoint_api.py tests/test_network_change_authorization.py tests/test_network_control_api.py tests/test_routes_smoke.py --disable-warnings --tb=short`: 70 PASS (48.34s).
- Stable archived commit 37e109e full suite: 2286 PASS, 3 baseline FAIL, 11 SKIP (442.51s). The same three baseline failures identified above; no mixed-edit verification claim.

## Revision foundation checkpoint

- T09 foundation: SQLite additive manual_revision + fact/relation triggers (not observations or telemetry timestamps), atomic conditional UPDATE; missing revision 428 and stale revision 409. Full-card HTML/API and attach/detach of existing workplace cards are guarded. HTML retains the original revision and compares values. Existing writers must pass revisions; docs/runbooks/inventory-revisions.md records the explicit compatibility change.
- RED: unguarded PATCH returned 200, missing column/input; relation POST without revisions returned 201. GREEN: five behavior tests cover repeated stale PATCH, changed child facts, observation independence, simultaneous independent DB sessions (one saved/one conflict), stale relation detach rollback. Synthetic old-schema upgrade twice: 1 PASS, same ID/facts/revision retained.
- Latest regression: `python -m pytest -q tests/test_inventory_revision.py tests/test_inventory_atomicity.py tests/test_inventory_api.py tests/test_inventory_web.py tests/test_inventory_service.py tests/test_inventory_endpoint_regression.py tests/test_inventory_endpoint_sync.py tests/test_inventory_endpoint_models.py tests/test_panel_permissions.py --disable-warnings --tb=short`: 123 PASS (79.62s).
- Playwright MCP `tests/browser/inventory_revision_conflict.js`: two actual tabs, first saved, second retained its input/base revision/current-value comparison and repeated stale submission rejected; zero console errors. Administrator permissions page rendered with Russian labels.
- T09 remains PARTIAL: new peripheral attached to an existing parent, external binding actions, delete/restore and independent server draft lifecycle are integrated in M3/M4. SQLite-only triggers; other database engines remain unverified.
- T05 follow-up found by actual browser control: invalid numeric Endpoint value becomes empty and optional validity accepts it. RED reproduced; fix and verification remain next work.
- GitNexus InventoryAsset impact: MEDIUM, 9 direct dependents, lower-bound due to dynamic/interface relationships. Source and inventory/Endpoint regressions above verify the actual Python consumers; no absence-of-dependency claim. Latest revision + migration command: 6 PASS after adding the database default for fresh schemas.
- T05 numeric follow-up GREEN: rejects non-finite numeric input before assignment and rejects number/date values sanitized to empty, restoring the prior value. Browser script now verifies invalid numeric input retains 8 with explanation, then zero insertion, undo, IP/MAC save/reload and dirty lock; zero errors/warnings. `python -m pytest -q tests/test_inventory_endpoint_web.py --disable-warnings --tb=short`: 17 PASS. Node syntax and diff --check PASS. Script cache version bumped to endpoint-6.
