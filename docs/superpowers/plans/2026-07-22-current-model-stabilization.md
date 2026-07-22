# Current Model Stabilization Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use `superpowers:executing-plans` to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Stabilize the deployed correlated-context and existing Internet-policy control plane across S1, S2, and S3 without adding a new device-write operation or changing operator-selected write gates.

**Architecture:** Keep `netctl` the read-only context authority and `netopsctl` the only Internet-policy broker. S1 replaces immutable SQLite reads with a single WAL-aware snapshot and carries actual Unix peer credentials into signed audit events and systemd credentials. S2 improves correlation conclusions without inventing data. S3 wraps the existing context endpoints in a backward-compatible v1 contract with immutable snapshot metadata, signed cursors, ETags, and bounded topology.

**Tech Stack:** Python 3.14, SQLite WAL, FastAPI, systemd socket activation and credentials, Ed25519, pytest.

## Global Constraints

- Do not add DNS/domain filtering, route collection, path-engine behavior, service-access policy, new firewall anchors/policy types, VLAN/switch/DHCP/DNS writes, directory adapters, auto-merge, or web redesign.
- Preserve `NETOPSCTL_PRODUCTION_WRITES_ENABLED` and `NETOPSCTL_AUDIT_CHECKPOINT_HEALTHY`; deployment must record and restore their current values, never set them.
- Every context failure is fail-closed: no cached policy targets and no RouterOS call after snapshot/precondition failure.
- Use additive SQLite migrations only; never delete migration ledger rows.
- Use sanitized fixtures only. Tests must not contact production devices.
- Preserve last successful topology and attachment rows when reconciliation cannot complete.

---

## File map

- `netctl/db.py` — normal read-only SQLite connection and the new read transaction context manager.
- `netopsctl/policy_resolver.py` and `netopsctl/reconcile.py` — all plan/reconcile context reads, basis construction, and preflight errors.
- `netopsctl/server.py`, `netopsctl/service.py`, `netopsctl/audit.py` — accepted socket peer evidence and signed audit events.
- `deploy/netopsctl*.service`, `deploy/openvpn-web.service`, `deploy/netopsctl` — systemd credentials and gate-preserving deployment.
- `netctl/switch_store.py`, `netctl/attachment_candidates.py`, `netctl/attachment_reconcile.py` — authoritative FDB eligibility and preservation behavior.
- `netctl/source_identity.py`, `netctl/topology_evidence.py`, `netctl/topology_reconcile.py` — source readiness and bounded backbone evidence.
- `netctl/context_query.py`, `netctl/cli.py`, `app/api.py` — per-interface/owner context and v1 compatibility envelope.
- `app/context_contract.py` (new) — snapshot IDs, cursor signing, ETag calculation, validation, and response shaping.
- `tests/test_netopsctl_*.py`, `tests/test_netctl_*.py`, `tests/test_context_api.py`, `tests/test_deploy_netopsctl.py` (new) — regression and deployment contracts.
- `docs/runbooks/current-model-stabilization-rollout.md` (new) and `docs/verification/current-model-stabilization.md` (new) — operator rollout, rollback, evidence, and remaining data-quality blockers.

---

## S1 — Consistency and control-plane security

### Task 1: WAL-safe read transaction primitive

**Files:**
- Modify: `netctl/db.py`
- Modify: `netopsctl/policy_resolver.py`
- Modify: `netopsctl/reconcile.py`
- Test: `tests/test_netopsctl_internet_policy.py`

**Interfaces:**
- Produce `read_context_snapshot(db_url: str) -> Iterator[sqlite3.Connection]`.
- The yielded connection is opened with `connect_read_only`, has `BEGIN` executed before reads, commits on normal exit, rolls back on failure, and always closes.

- [ ] **Step 1: Write failing snapshot tests.** Add tests that create a WAL database, commit an update between two snapshots, and assert the second snapshot sees it; assert rows read inside one snapshot do not mix pre/post writer values; monkeypatch `sqlite3.Connection.execute` so `BEGIN` fails and assert `create_asset_internet_access_plan` raises `ValueError("context snapshot is unavailable")` before the adapter callback is evaluated.
- [ ] **Step 2: Run RED.** Run `pytest tests/test_netopsctl_internet_policy.py -k 'snapshot or immutable' -q`; expected failure is missing `read_context_snapshot` and the old immutable URI behavior.
- [ ] **Step 3: Implement the primitive.** In `netctl/db.py`, implement `@contextmanager read_context_snapshot`; call `connect_read_only`, execute `BEGIN`, yield, `COMMIT`, and on `sqlite3.Error` execute `ROLLBACK` when in a transaction, then re-raise. Replace `_open_context_immutable` in all resolver/reconcile paths with this context manager and translate SQLite failures at the public plan/preflight boundary into only `context snapshot is unavailable`.
- [ ] **Step 4: Run GREEN.** Run `pytest tests/test_netopsctl_internet_policy.py -k 'snapshot or immutable' -q` and `rg -n 'immutable=1|_open_context_immutable' netopsctl`; expected: tests pass and ripgrep has no production-code match.
- [ ] **Step 5: Commit.** `git add netctl/db.py netopsctl/policy_resolver.py netopsctl/reconcile.py tests/test_netopsctl_internet_policy.py && git commit -m "fix: use WAL-safe context snapshots"`.

### Task 2: Apply-time snapshot basis and fail-closed classification

**Files:**
- Modify: `netopsctl/policy_resolver.py`
- Modify: `netopsctl/service.py`
- Modify: `netopsctl/protocol.py`
- Test: `tests/test_netopsctl_internet_policy.py`
- Test: `tests/test_network_control_api.py`

**Interfaces:**
- Produce `ContextSnapshotUnavailable(ValueError)` and `changed_plan_preconditions(...) -> list[str]` that returns `context_snapshot_unavailable` instead of stale cached targets.
- Produce broker/API response data with `status="stale_precondition"`, `replan_required=true`, and `changed_preconditions` for preflight rejection.

- [ ] **Step 1: Write failing tests.** Make a validated plan, make the plan’s IP/attachment/context basis change in a new transaction, and assert apply reports `changed_preconditions` without adapter calls. Add a test where snapshot opening raises `sqlite3.OperationalError`; assert the HTTP caller receives a sanitized stale-precondition payload containing only `context_snapshot_unavailable`.
- [ ] **Step 2: Run RED.** Run `pytest tests/test_netopsctl_internet_policy.py tests/test_network_control_api.py -k 'precondition or snapshot' -q`; expected failure is the current generic error/exception path.
- [ ] **Step 3: Implement classification.** Define the exception and a single serializer in `netopsctl/service.py`; catch only snapshot errors in creation/apply preflight, return the stable data shape, and leave all other errors audited and fail-closed. Do not expose a DB URL, database path, SQLite message, or cached target.
- [ ] **Step 4: Run GREEN.** Run the focused command and `pytest tests/test_netopsctl_internet_policy.py -q`; expected: all green and adapter call counters remain zero in failure tests.
- [ ] **Step 5: Commit.** `git add netopsctl/policy_resolver.py netopsctl/service.py netopsctl/protocol.py tests/test_netopsctl_internet_policy.py tests/test_network_control_api.py && git commit -m "fix: classify context snapshot preconditions"`.

### Task 3: Preserve actual Unix peer credentials in the audit chain

**Files:**
- Modify: `netopsctl/server.py`
- Modify: `netopsctl/service.py`
- Test: `tests/test_netopsctl_server.py` (new)
- Test: `tests/test_netopsctl_audit.py`

**Interfaces:**
- `AuthenticatedPeer` remains immutable and is passed unchanged from `serve` through `handle` to `ControlService.dispatch`.
- `_audit(..., peer: AuthenticatedPeer, subject: dict[str, str], ...)` serializes `authenticated_peer={uid,gid,pid,service_principal}` separately from `authorized_subject`.

- [ ] **Step 1: Write failing peer tests.** Use a fake accepted socket returning `(pid=4321, uid=1001, gid=1002)`, a signed valid request, and inspect `audit_events.payload_json`. Assert UID/GID/PID equal socket values, not configured defaults; assert unknown UID and matching UID/wrong GID fail before `decode_request`; assert forged JSON actor cannot replace `authorized_subject`; assert reconcile peer cannot approve/apply.
- [ ] **Step 2: Run RED.** Run `pytest tests/test_netopsctl_server.py tests/test_netopsctl_audit.py -q`; expected failure is string-only `authenticated_peer` or missing test module.
- [ ] **Step 3: Implement evidence propagation.** Change `handle` to pass `AuthenticatedPeer`; update `dispatch` and `_audit` signatures; construct the four-field peer map only from the object accepted after `SO_PEERCRED`. Keep authorization subject fields unchanged and do not read PID/UID/GID from environment/configuration.
- [ ] **Step 4: Run GREEN.** Run the focused tests plus `pytest tests/test_network_change_authorization.py -q`; expected: successful and failed events validate with the real peer map.
- [ ] **Step 5: Commit.** `git add netopsctl/server.py netopsctl/service.py tests/test_netopsctl_server.py tests/test_netopsctl_audit.py && git commit -m "fix: sign actual broker peer credentials"`.

### Task 4: Deliver private keys through systemd credentials

**Files:**
- Modify: `netopsctl/server.py`
- Modify: `app/config.py`
- Modify: `app/netopsctl_client.py`
- Modify: `netopsctl/reconcile_runner.py`
- Modify: `deploy/netopsctl.service`
- Modify: `deploy/openvpn-web.service`
- Modify: `deploy/netopsctl-reconcile.service`
- Modify: `deploy/netopsctl`
- Test: `tests/test_deploy_netopsctl.py` (new)
- Test: `tests/test_netopsctl_server.py`

**Interfaces:**
- Produce `credential_path(role: str, *, credentials_directory: str | None = None) -> Path` that accepts only a regular, non-symlink 32-byte Ed25519 key.
- Units use `LoadCredential=` for `netopsctl-audit-signing-key`, `web-netopsctl-signing-key`, and `netopsctl-reconcile-signing-key`.

- [ ] **Step 1: Write failing credential tests.** Test a missing, empty, oversized, symlinked, and 31-byte credential and assert startup raises a role-only message such as `invalid audit signing credential`, with no file path. Assert unit text contains the three explicit `LoadCredential` declarations and no private key variable in `EnvironmentFile` parsing.
- [ ] **Step 2: Run RED.** Run `pytest tests/test_deploy_netopsctl.py tests/test_netopsctl_server.py -k credential -q`; expected failure is absent helper/unit directives.
- [ ] **Step 3: Implement credential loader and units.** Add loader in `netopsctl/runtime.py` or a focused new `netopsctl/credentials.py`; use `${CREDENTIALS_DIRECTORY}` only, validate with `lstat`, ownership/mode suitable for systemd delivery, and exact key length. Update web client, broker, and reconciler to request named credentials. Update installer to install root-owned source files and use `LoadCredential=` without changing either gate variable.
- [ ] **Step 4: Run GREEN.** Run focused tests, `pytest tests/test_network_control_api.py -q`, and `systemd-analyze verify deploy/netopsctl.service deploy/openvpn-web.service deploy/netopsctl-reconcile.service` when available; expected success or documented unavailable command only.
- [ ] **Step 5: Commit.** `git add netopsctl app deploy tests/test_deploy_netopsctl.py tests/test_netopsctl_server.py && git commit -m "fix: load control-plane keys as systemd credentials"`.

### Task 5: S1 rollout and rollback contract

**Files:**
- Create: `docs/runbooks/current-model-stabilization-rollout.md`
- Modify: `deploy/netopsctl`
- Test: `tests/test_deploy_netopsctl.py`

- [ ] **Step 1: Write failing deployment-order tests.** Assert the deploy script captures both existing gate lines before stopping services, stops reconcile timer/socket/service, backs up and validates both databases, installs credentials, applies migrations, runs a signed status and stale-precondition smoke test, and restores the captured gate lines without assigning a literal true/false value.
- [ ] **Step 2: Run RED.** Run `pytest tests/test_deploy_netopsctl.py -q`; expected failure is missing order assertions/script behavior.
- [ ] **Step 3: Implement the runbook/script changes.** Add idempotent shell helpers that reject missing gate lines, preserve their exact values, and verify policy/address-list state read-only. Document atomic update, one controlled apply/verify/rollback only with operator approval, and rollback to the matching backups/application tree.
- [ ] **Step 4: Run GREEN.** Run deployment tests and `bash -n deploy/netopsctl`; expected: PASS.
- [ ] **Step 5: Commit.** `git add deploy/netopsctl docs/runbooks/current-model-stabilization-rollout.md tests/test_deploy_netopsctl.py && git commit -m "docs: define stabilization S1 rollout"`.

## S2 — Correlation quality and complete asset context

### Task 6: Shared authoritative FDB eligibility

**Files:**
- Create: `netctl/switch_eligibility.py`
- Modify: `netctl/attachment_candidates.py`
- Modify: `netctl/attachment_reconcile.py`
- Modify: `netctl/findings.py`
- Test: `tests/test_netctl_attachments.py`
- Test: `tests/test_netctl_switch_store.py`

**Interfaces:**
- Produce `authoritative_fdb_run(conn, source_id) -> dict[str, Any] | None`.
- Eligible only if latest relevant run is `success`/`partial`, FDB capability is `qbridge_fdb`/`legacy_fdb`, FDB outcome is `success_with_rows`/`success_empty`, and current FDB transaction committed.

- [ ] **Step 1: Write failing eligibility matrix tests.** Cover success with rows, success authoritative empty, partial with successful FDB plus optional VLAN failure, partial with FDB timeout, failed latest run, and newer authoritative partial beating older success.
- [ ] **Step 2: Run RED.** Run `pytest tests/test_netctl_attachments.py tests/test_netctl_switch_store.py -k 'authoritative or partial' -q`; expected failure is status-only filtering.
- [ ] **Step 3: Implement one helper.** Parse `outcomes_json` once in `switch_eligibility.py`; return reason codes, never raw parser messages. Make candidate selection, reconciliation, and findings call that helper rather than independently filtering `switch_collection_runs.status`.
- [ ] **Step 4: Run GREEN.** Run focused tests and `pytest tests/test_netctl_attachments.py -q`; expected PASS.
- [ ] **Step 5: Commit.** `git add netctl/switch_eligibility.py netctl/attachment_candidates.py netctl/attachment_reconcile.py netctl/findings.py tests/test_netctl_attachments.py tests/test_netctl_switch_store.py && git commit -m "fix: accept authoritative partial FDB runs"`.

### Task 7: Preserve current graph and attachment state on failed/ineligible reconciliation

**Files:**
- Modify: `netctl/attachment_reconcile.py`
- Modify: `netctl/topology_reconcile.py`
- Test: `tests/test_netctl_attachments.py`
- Test: `tests/test_netctl_topology.py`

- [ ] **Step 1: Write failing preservation tests.** Seed confirmed current links/resolutions, force candidate/evidence collection to fail and then force latest FDB to be ineligible. Assert current tables and their previous `correlation_run_id` values stay byte-equivalent; assert only failed-run bounded metadata is recorded and no detached/disappeared event is emitted.
- [ ] **Step 2: Run RED.** Run `pytest tests/test_netctl_attachments.py tests/test_netctl_topology.py -k 'preserve or failed' -q`; expected failure is destructive replace/delete behavior.
- [ ] **Step 3: Implement transaction boundary.** Build complete candidates/evidence before `BEGIN IMMEDIATE`; only replace current tables after all validation succeeds. In the exception path, record class/reason code on the run in a separate transaction and preserve old current rows/findings/events.
- [ ] **Step 4: Run GREEN.** Run focused tests plus `pytest tests/test_netctl_reconcile_units.py -q`; expected PASS.
- [ ] **Step 5: Commit.** `git add netctl/attachment_reconcile.py netctl/topology_reconcile.py tests/test_netctl_attachments.py tests/test_netctl_topology.py && git commit -m "fix: preserve correlation state on failed runs"`.

### Task 8: Source readiness and backbone evidence diagnostics

**Files:**
- Modify: `netctl/source_identity.py`
- Modify: `netctl/topology_evidence.py`
- Modify: `netctl/context_query.py`
- Modify: `netctl/cli.py`
- Test: `tests/test_netctl_source_identity.py`
- Test: `tests/test_netctl_topology.py`

**Interfaces:**
- Produce `source_readiness(conn) -> list[dict[str, Any]]` with the fixed reason-code vocabulary.
- Produce `backbone_evidence(conn, *, site: str, limit: int) -> list[dict[str, Any]]` containing only bounded decision metadata.

- [ ] **Step 1: Write failing readiness/evidence tests.** Create one fixture for every reason code (`missing_topology_role`, `missing_runtime_asset_binding`, `missing_intent_binding`, `missing_management_mac`, `no_authoritative_fdb`, `stale_authoritative_fdb`, `no_port_inventory`, `ambiguous_management_mac`, `ready`) and assert no host/IP/MAC dump appears. Assert an attempted source pair returns intent/management-MAC/LLDP/port/conflict fields.
- [ ] **Step 2: Run RED.** Run `pytest tests/test_netctl_source_identity.py tests/test_netctl_topology.py -k 'readiness or backbone' -q`; expected failure is missing command/model.
- [ ] **Step 3: Implement diagnostics.** Derive readiness from existing source identity, source collection, eligibility, port inventory, and evidence rows; add `context-view source-readiness` and `context-view backbone-evidence` parser commands. Cap evidence to 100 pairs and redact raw FDB rows.
- [ ] **Step 4: Run GREEN.** Run focused tests and `python -m netctl.cli --help`; expected PASS and new subcommands listed.
- [ ] **Step 5: Commit.** `git add netctl/source_identity.py netctl/topology_evidence.py netctl/context_query.py netctl/cli.py tests/test_netctl_source_identity.py tests/test_netctl_topology.py && git commit -m "feat: expose correlation readiness diagnostics"`.

### Task 9: Per-interface attachments and resolved owner context

**Files:**
- Modify: `netctl/context_query.py`
- Modify: `netctl/user_context.py`
- Test: `tests/test_netctl_context_query.py` (new)
- Test: `tests/test_netctl_user_context.py`

**Interfaces:**
- Asset output contains `interfaces: list[dict[str, Any]]`; each has independent attachment and lifecycle.
- Asset output contains `owner={status, bindings}` where status is `none`, `confirmed`, `ambiguous`, or `shared`.

- [ ] **Step 1: Write failing context tests.** Create an asset with two interfaces and one confirmed/one ambiguous attachment; assert no borrowing and inactive interface remains visible but is policy-ineligible. Cover exactly one active confirmed primary/owner binding, multiple confirmed owner bindings, shared binding, and candidate/retired/expired bindings.
- [ ] **Step 2: Run RED.** Run `pytest tests/test_netctl_context_query.py tests/test_netctl_user_context.py -q`; expected failure is `owner=None` and a single asset-level attachment.
- [ ] **Step 3: Implement query helpers.** Replace `_attachment(asset_id)` with `_interfaces(asset_id)` keyed by `asset_interface_id`; add `resolve_owner_context` that filters active confirmed bindings and returns bounded registry fields. Retain the existing asset-level `attachment` as a compatibility summary but make policy resolver use per-interface rows.
- [ ] **Step 4: Run GREEN.** Run focused tests and `pytest tests/test_netopsctl_internet_policy.py -q`; expected: owner/context additions do not weaken policy eligibility.
- [ ] **Step 5: Commit.** `git add netctl/context_query.py netctl/user_context.py tests/test_netctl_context_query.py tests/test_netctl_user_context.py && git commit -m "feat: expose interface and owner context"`.

## S3 — Versioned API and operational contract

### Task 10: Stable v1 envelope and context snapshot metadata

**Files:**
- Create: `app/context_contract.py`
- Modify: `app/api.py`
- Modify: `netctl/context_query.py`
- Test: `tests/test_context_api.py`

**Interfaces:**
- `context_response(request, data, snapshot, *, pagination=None, errors=None) -> JSONResponse` emits `status`, `api_version="1.0"`, `request_id`, `generated_at`, `snapshot`, `data`, `pagination`, and `errors`.
- `context_snapshot(conn) -> dict[str, Any]` contains context revision ID, successful topology/attachment run IDs, and observation cutoff.

- [ ] **Step 1: Write failing compatibility tests.** For search, asset, topology, findings, and source readiness, assert legacy `status`/`data` remain, the new fixed fields exist, and snapshot run IDs are consistent. Assert failures use the same envelope with `data=null`, `snapshot=null`, and stable codes.
- [ ] **Step 2: Run RED.** Run `pytest tests/test_context_api.py -q`; expected failure is the existing generic `api_response` shape.
- [ ] **Step 3: Implement contract module.** Keep generic API responses untouched; route only `/api/v1/context/search`, `/assets/{asset_key}`, `/topology`, `/findings`, and `/source-readiness` through `context_response`. Obtain one netctl snapshot per command response and sanitize errors at the boundary.
- [ ] **Step 4: Run GREEN.** Run `pytest tests/test_context_api.py -q`; expected PASS with legacy callers still reading `data`.
- [ ] **Step 5: Commit.** `git add app/context_contract.py app/api.py netctl/context_query.py tests/test_context_api.py && git commit -m "feat: version correlated context API responses"`.

### Task 11: Signed cursor pagination

**Files:**
- Modify: `app/context_contract.py`
- Modify: `app/api.py`
- Modify: `netctl/cli.py`
- Modify: `netctl/context_query.py`
- Modify: `app/config.py`
- Test: `tests/test_context_api.py`

**Interfaces:**
- `encode_cursor(payload, signer) -> str` and `decode_cursor(cursor, signer, *, filters, now) -> CursorState` bind version, snapshot/run IDs, timestamp, numeric ID, normalized filters, limit, and expiry.
- Supported cursor routes: search, findings, attachment events, link events, and source-readiness history when exposed.

- [ ] **Step 1: Write failing cursor tests.** Assert default/max limits are search 25/50 and collections 100/500; assert the second page is stable; assert tampered cursor, expired cursor, changed filters, and changed limit return only `cursor_invalid`, `cursor_expired`, or `cursor_filter_mismatch`.
- [ ] **Step 2: Run RED.** Run `pytest tests/test_context_api.py -k cursor -q`; expected failure is no `cursor` argument/pagination payload.
- [ ] **Step 3: Implement opaque cursor flow.** Use a dedicated systemd credential named `context-api-cursor-signing-key`; normalize filters before signing; forward cursor boundary values to netctl query functions; return only opaque token, `has_more`, and limit in pagination.
- [ ] **Step 4: Run GREEN.** Run cursor tests and `pytest tests/test_context_api.py -q`; expected PASS with no cursor internals in output.
- [ ] **Step 5: Commit.** `git add app/context_contract.py app/api.py app/config.py netctl/cli.py netctl/context_query.py tests/test_context_api.py deploy/openvpn-web.service deploy/netopsctl && git commit -m "feat: paginate context with signed cursors"`.

### Task 12: Topology bounds and ETags

**Files:**
- Modify: `app/context_contract.py`
- Modify: `app/api.py`
- Modify: `netctl/context_query.py`
- Test: `tests/test_context_api.py`
- Test: `tests/test_netctl_topology.py`

- [ ] **Step 1: Write failing bound/cache tests.** Assert topology defaults to depth 3/max_nodes 250 and rejects values above 8/1000; create a graph beyond the node bound and assert `truncated=true`, `truncation_reason="max_nodes"`. Assert matching `If-None-Match` returns 304 and a changed context revision/run/attachment/binding changes the ETag.
- [ ] **Step 2: Run RED.** Run `pytest tests/test_context_api.py tests/test_netctl_topology.py -k 'etag or truncat or max_nodes' -q`; expected failure is absent fields/current permissive depth 32.
- [ ] **Step 3: Implement bounded query and ETag.** Add `max_nodes` to topology CLI/query, breadth-first stop at the bound, and return a declared truncation object. Hash API version, normalized filters, context revision, run IDs, and asset/binding/attachment markers with canonical JSON; evaluate `If-None-Match` only after the current snapshot is calculated.
- [ ] **Step 4: Run GREEN.** Run focused tests then `pytest tests/test_context_api.py -q`; expected PASS.
- [ ] **Step 5: Commit.** `git add app/context_contract.py app/api.py netctl/context_query.py tests/test_context_api.py tests/test_netctl_topology.py && git commit -m "feat: bound topology and add context ETags"`.

### Task 13: Documentation, migration rehearsal, and release evidence

**Files:**
- Modify: `docs/plans/netctl-correlated-context-control-plane.md`
- Modify: `docs/runbooks/current-model-stabilization-rollout.md`
- Create: `docs/verification/current-model-stabilization.md`
- Modify: `deploy/netopsctl`
- Test: `tests/test_deploy_netopsctl.py`

- [ ] **Step 1: Write failing evidence/secret-scan tests.** Assert deployment documentation distinguishes implemented code, deployed capability, production data quality, and write-gate state; assert the script performs backup SHA/integrity/migration ledger/status/stale-precondition/address-list checks; add a test that documentation contains no IP, password, private-key, or raw FDB fixture literal.
- [ ] **Step 2: Run RED.** Run `pytest tests/test_deploy_netopsctl.py -q`; expected failure is absent S1/S2/S3 evidence document.
- [ ] **Step 3: Implement evidence and rollout.** Add exact backup/restore and verification commands, explicitly state no write gate is changed, list source readiness blockers separately, and cross-link the completed earlier plan without claiming production topology completeness from code alone.
- [ ] **Step 4: Run GREEN.** Run deployment tests, `git diff --check`, `rg -n '(password|PRIVATE KEY|BEGIN OPENSSH)' docs/verification/current-model-stabilization.md`, and the focused S1/S2/S3 suites; expected: tests pass and secret scan has no match.
- [ ] **Step 5: Commit.** `git add docs deploy/netopsctl tests/test_deploy_netopsctl.py && git commit -m "docs: record stabilization rollout evidence"`.

### Task 14: Full regression and controlled deployment

**Files:**
- Verify: all modified files
- Verify: `docs/verification/current-model-stabilization.md`

- [ ] **Step 1: Run local verification.** Run `pytest -q`, `python -m compileall -q app netctl netopsctl`, `git diff --check`, and `rg -n 'immutable=1' netctl netopsctl app`; expected: full suite passes, compilation succeeds, diff is clean, and immutable query has no production match.
- [ ] **Step 2: Create deployment backups.** On `ui-vpn-deploy`, run the runbook’s online SQLite backup commands, SHA-256, and `PRAGMA integrity_check` as each database owner; record only hashes and statuses.
- [ ] **Step 3: Deploy atomically.** Capture the two gate lines, stop only broker socket/service and reconcile timer during update, install application/credentials/migrations, restore the exact gate lines, and start services. Do not enable a disabled timer and do not change either gate.
- [ ] **Step 4: Run production-safe verification.** Verify ledgers, database integrity, signed status, stale-precondition dry-run, desired policy/address-list equality, source readiness, bounded context API, cursor/ETag smoke tests, and audit-chain verification. Run an apply/verify/rollback lifecycle only after explicit operator approval for the selected test asset.
- [ ] **Step 5: Commit and publish.** `git add -A && git commit -m "feat: stabilize current context model" && git push origin codex/current-model-stabilization`; open a draft PR, review all checks, then merge to `main` only after successful verification.

## Coverage review

- S1 requirements map to Tasks 1–5: WAL snapshots, preflight failure, actual peer evidence, systemd credentials, and gate-preserving rollout.
- S2 requirements map to Tasks 6–9: partial FDB eligibility, state preservation, readiness/evidence, per-interface attachment, and owner state.
- S3 requirements map to Tasks 10–12: compatibility envelopes, snapshot metadata, signed pagination, bounded topology, ETags, and sanitized errors.
- Task 13 records roadmap/operational evidence; Task 14 enforces full regression and safe deployment.
- The plan deliberately excludes every feature listed out of scope in the approved design.
