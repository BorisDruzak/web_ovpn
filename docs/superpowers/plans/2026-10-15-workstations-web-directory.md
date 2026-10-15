# Workstations Web, Directory and MCP Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:executing-plans to implement this plan task-by-task in this chat. Steps use checkbox (`- [ ]`) syntax for tracking. The user has selected execution in this chat; do not create another user-owned task.

**Goal:** Deliver the existing panel's Workstations section with protected ALT setup, AD employee selection, automatic AD/DNS/network/inventory reconciliation, progress/error history and existing-plugin MCP access.

**Architecture:** The panel calls an allowlisted JSON gateway over restricted SSH; the gateway reuses canonical controller services and durable jobs. A separate read-only observer collects complete directory/DNS snapshots, and the panel reconciles them with Netctl API snapshots and existing inventory relationships. The browser and existing MCP share one authenticated API.

**Tech Stack:** Python, FastAPI 0.115.6, SQLAlchemy 2.0.36, Jinja2 3.1.5, existing OpenLDAP CLI/Kerberos transport, dnspython 2.8.0, OpenSSH and systemd. No new application framework or LDAP dependency.

**Spec:** [Approved design](../specs/2026-10-15-workstations-web-directory-design.md), approved by the user on 2026-10-15. Implementation plan approved by the user in this chat; inline execution is in progress.

## Global Constraints

- Keep its FastAPI/Jinja2 design, authentication, CSRF protection, audit and inventory relations.
- Do not add router, DHCP, DNS-record or employee-account writes.
- Mutating Setup jobs keep the existing global serialization and show their queue position/blocker.
- A DNS name or IP address does not prove physical-device identity or ownership.
- Automatic reconciliation updates observations and findings, not manually entered inventory ownership, confirmed bindings, AD objects or DNS records.
- There is no employee-creation API, hidden enabled form or MCP tool.
- Require at least two characters for a name query; cap input at 160 characters, return at most 50 rows, and explicitly report truncation.
- Use explicit paging with complete result validation, a 10,000-object/16-MiB source budget, and a two-minute total deadline.
- Run collection/reconciliation every five minutes with a singleton worker lock and no overlapping runs.
- Initial source-specific freshness limit is fifteen minutes.
- Bound routine run/log retention to thirty days without deleting Setup history or relationship audit.
- Never automatically retry an apply after a timeout; query its receipt/job first and show an uncertain outcome if it cannot be proven.
- Protected controller domain assignments remain controller-owned and take precedence over incompatible portal link requests.
- Keep admission hashes, actual identities, topology, credentials and private evidence out of tracked artifacts and general logs.
- Use isolated implementation staging; publish verified work to main by default and clean up only this feature's branch/worktree.

## Review Focus

- A shared PC's previously assigned employee must not be silently replaced by a new directory match; Task 6 tests conflict/history.
- A multi-interface device must not become two physical inventory cards; Task 5 tests two MAC relations to one card.
- A connection drop after a successful apply must resolve to the original job, never another join; Task 3 injects lost response.
- A paged LDAP/DNS read that fails at its last page must not delete absent devices or mark the snapshot complete; Tasks 1 and 5 test publication.
- An observer with generic read access must not obtain employee data through journal export, alternate API paths or MCP; Tasks 7 and 9 test all entry points.

## File structure and ownership

Controller code goes in `deploy/alt-linux/control/alt_deploy/`:
`directory_observer.py` owns paged read-only AD projections;
`directory_dns.py` owns directory DNS record decoding;
`workstations_gateway.py` owns request validation/dispatch;
`workstations_receipts.py` owns immutable request identity/outcome recovery;
`workstations_projection.py` owns safe native-service projections.
Root-owned launch/provisioning artifacts go in `deploy/alt-linux/` and its
`systemd/` directory, integrated with the existing control-plane installer.

Panel code goes in new `app/workstations/` modules: `models.py`, `schema.py`,
`client.py`, `reconcile.py`, `links.py`, `service.py`, `api.py`, `web.py`, and
`journal.py`. `schema.py` owns targeted additive schema readiness/migration;
`service.py` owns panel operations/receipts and composes the other modules.
Use focused modules rather than expanding `app/main.py` with feature logic.
UI assets are `app/templates/workstations*.html` and `app/static/workstations.js`
and `.css`. Tests mirror these boundaries. Existing inventory and Netctl domains
retain their ownership; no direct Netctl database access.

Existing local plugin files are `scripts/openvpn_mcp_server.py` and
`skills/openvpn-control/SKILL.md` under the discovered canonical plugin root.
The plugin root and credential paths are local deployment inputs, not repository
configuration. Repository source remains `mcp/openvpn_mcp_server.py`.

## Task 1: Paged read-only directory observer and employee search

**Files:** Create controller `directory_observer.py`; modify `ad_transport.py` only to share bounded transport primitives without changing existing defaults; create `tests/alt_linux/test_directory_observer.py` and safe synthetic LDIF fixtures.

**Interfaces:** `DirectoryObserverConfig.load(path: Path) -> DirectoryObserverConfig` requires `readonly-vault`; `DirectoryObserver.search_users(query: str, *, limit: int = 50) -> dict`; `DirectoryObserver.collect(*, deadline: float) -> dict` returns schema version, complete flag, source generation/time and normalized users/computers. Use GUID/SID as stable keys; collection includes only necessary employee fields.

- [x] Write tests `test_name_search_escapes_filter_and_disambiguates_homonyms`, `test_readonly_observer_rejects_join_vault`, `test_search_rejects_over_160_chars`, `test_search_reports_51st_result_as_truncated`, `test_last_page_failure_never_returns_complete`, `test_collection_enforces_10000_objects_16mib_and_120_seconds`. Assert no raw credentials/diagnostics in failures.
- [x] Run `python -m pytest tests/alt_linux/test_directory_observer.py -q` on Linux; confirm the new interfaces fail before implementation.
- [x] Implement the interfaces with fixed bases/attribute allowlists, private Kerberos caches and explicit paged-result validation. Keep existing exact `ADDirectory.user()` and Setup's usability checks unchanged. Preserve per-process request deadlines across pages and discard partial generations.
- [x] Run new tests plus `python -m pytest tests/alt_linux/test_ad_directory.py -q`; inspect exact results.
- [x] Review full diff, `git diff --check`, stage only these files and commit `feat(workstations): add restricted paged directory observer`.

## Task 2: AD-integrated DNS collection and decoding

**Files:** Create controller `directory_dns.py`, `tests/alt_linux/test_directory_dns.py` and synthetic binary/LDIF fixtures; extend Task 1 observer collection with configured DNS partitions/zones.

**Interfaces:** `decode_dns_record(value: bytes, *, owner: str, zone: str) -> dict | None`; `DirectoryDNS.collect(*, deadline: float) -> dict`. Output distinguishes A/AAAA/CNAME/PTR, tombstones, unsupported record counts, complete generation and source error. No record-write API.

- [x] Write tests `test_decode_a_aaaa_cname_ptr`, `test_reject_short_length_or_wrong_version`, `test_tombstone_is_not_live_dns`, `test_alias_loop_is_a_finding`, `test_partition_failure_preserves_previous_complete_snapshot`. Assert directory-record header endian/length rules against Microsoft's format.
- [x] Run `python -m pytest tests/alt_linux/test_directory_dns.py -q`; confirm failure before code.
- [x] Implement bounded parsing and fixed-zone enumeration; use the existing dnspython version for optional bounded resolution verification, with explicit NXDOMAIN/timeout/no-answer classifications. Share the observer's total collection deadline/budget instead of multiplying it per zone.
- [x] Run both observer/DNS suites and `python -m pytest tests/test_netctl_cli.py -q` for existing resolver/CLI behavior.
- [x] Inspect/stage the exact diff and commit `feat(workstations): collect read-only directory DNS evidence`.

## Task 3: Fixed-operation controller gateway and durable receipts

**Files:** Create controller `workstations_gateway.py`, `workstations_receipts.py`, `workstations_projection.py`, `tests/alt_linux/test_workstations_gateway.py`, `tests/alt_linux/test_workstations_receipts.py`, and executable `deploy/alt-linux/control/alt-workstations-gateway`.

**Interfaces:** `Gateway.dispatch(envelope: dict, *, scope: str) -> dict`; envelope `{schema_version: 1, request_id: UUID, operation: str, parameters: dict}`. Response `{schema_version: 1, request_id, status, data, error_code}`. `GatewayReceiptStore.execute(request_id: str, intent: dict, operation: Callable) -> dict`; `GatewayReceiptStore.status(request_id: str) -> dict`.

Allowed operations: `status`, `machines.list`, `machines.show`, `catalog.list`, `directory.search`, `directory.snapshot`, `assignments.show`, `plans.create`, `component_plans.create`, `plans.apply`, `jobs.list`, `jobs.status`, `jobs.events`, `jobs.verify`, `jobs.cancel`, `receipts.status`. Read scope cannot call planning/execution/verification/cancel. Directory snapshot is a bounded read-only collection operation; persisted receipts describe its outcome without authorizing target mutation.

- [x] Write tests for exact operation/schema allowlists, typed IDs, size/deadline limits, wrong scope, private-field redaction, same request/different intent rejection, lost apply response and no replay after an interrupted receipt. Assert two repeated matching submissions return one native job ID.
- [x] Run `python -m pytest tests/alt_linux/test_workstations_gateway.py tests/alt_linux/test_workstations_receipts.py -q`; observe failing imports/assertions.
- [x] Delegate planning to `SetupService.plan(identifier, login, ou, software, remote)` and `ComponentSetupService.plan(identifier, component_id)`. Load exact confirmed plans through native stores. Submit full plans with `SetupService.apply(plan_id, confirmed_sha, detach=True)` and components with the existing nonblocking `ComponentSetupService.apply(plan_id, sha256)`. Both return native durable job IDs; do not duplicate their admission logic.
- [x] Use `SetupJobsService.list/status/events_for/verify_continuation/cancel` for job operations. Include per-job admission sequence/queue blocker in a bounded safe projection without changing worker policy. Receipt recovery reads the existing plan claim/job; it cannot revive a consumed claim. If a pre-admission outcome cannot be proved, retain uncertainty and require a fresh explicit request.
- [x] Run the new tests and `python -m pytest tests/alt_linux/test_setup_jobs.py tests/alt_linux/test_setup_jobs_cli.py -q`. Commit `feat(workstations): expose guarded controller gateway` after full diff/check.

## Task 4: Restricted SSH provisioning and panel transport

**Files:** Create `app/workstations/__init__.py`, `client.py`; modify `app/config.py`; create `deploy/alt-linux/install-workstations-gateway.sh`, root-managed per-key forced-command enrollment, `tests/test_workstations_client.py`, `tests/alt_linux/test_workstations_gateway_install.py`; integrate artifacts in `install-control-plane-lib.sh` and installer source validation.

**Interfaces:** `WorkstationsClient.call(operation: str, parameters: dict, *, request_id: str, scope: str = 'read') -> dict`. `WorkstationsTransportError` carries an allowlisted code, request ID and uncertain-outcome boolean, never stderr. Fixed admin-configured host/user/key/known-hosts paths cannot be overridden in HTTP parameters.

- [x] Test strict host-key checking, no shell command interpolation, scope-specific credentials, output/input bounds, timeout and malformed JSON. Installer tests assert root-owned forced commands, key-only source-bound gateway credentials, disabled forwarding/TTY/user RC and exact service-user forced commands; no unrestricted controller SSH key is copied.
- [x] Run `python -m pytest tests/test_workstations_client.py tests/alt_linux/test_workstations_gateway_install.py -q`; prove failures.
- [x] Implement `subprocess` argv plus JSON stdin, finite connect/operation deadlines and credential-file ownership/mode validation. Add optional disabled-by-default settings so an unconfigured feature renders a clear unavailable state without breaking existing startup.
- [x] Run transport/install tests plus existing controller installer tests selected from actual touched-file coverage. Commit `feat(workstations): add restricted controller transport`.

## Task 5: Additive schema and coherent reconciliation worker

**Files:** Create panel `models.py`, `schema.py`, `reconcile.py`; modify `app/db.py` only for explicit schema integration; create `deploy/workstations-reconcile.service` and `.timer`, `tests/test_workstations_schema.py`, `tests/test_workstations_reconcile.py`.

**Interfaces:** `ensure_schema(engine) -> None` and `check_schema(engine) -> None`; `reconcile_once(*, client: WorkstationsClient, netctl_call: Callable, session_factory: Callable, clock: Callable) -> dict`. CLI entry `python -m app.workstations.reconcile` returns a safe run summary and nonzero on incomplete run.

Tables: `workstation_source_runs` (attempt/success/complete/generation/time/error/counts), `workstation_source_snapshots` (last complete bounded normalized source payload), `workstation_directory_links` (stable employee/computer/device references, revision, actor/reason/history), `workstation_findings` (typed evidence/revision/state), `workstation_requests` (actor/action/intent digest/request ID/receipt/outcome). Add database uniqueness for active per-device employee binding and request identity; keep schema transactions targeted.

- [x] Test idempotent migration, exact schema readiness, no unrelated repair, five-minute singleton behavior, fifteen-minute freshness, partial source failure, last-page truncation, duplicate MACs, future/naive timestamps, inventory revision changed mid-run, two interfaces mapped to one card and no automatic ownership mutation.
- [x] Run `python -m pytest tests/test_workstations_schema.py tests/test_workstations_reconcile.py -q`; confirm RED.
- [x] Build sources through Task 4 and existing `inventory.netctl_sync.read_current_snapshot`, inventory bindings and projection revision. Read Endpoint facts only from the existing local inventory projection. Publish only coherent complete generations; independently retain source failures/last success. Prune routine runs older than thirty days without removing binding audit or Setup jobs.
- [x] Run new suites and `python -m pytest tests/test_inventory_netctl_sync.py tests/test_inventory_network_projection.py tests/test_inventory_netctl_bindings.py -q`; commit `feat(workstations): reconcile directory DNS and inventory evidence`.

## Task 6: Explicit employee/device links and conflict history

**Files:** Create panel `links.py`; extend `tests/test_workstations_links.py`.

**Interfaces:** `preview_link(db: Session, *, device_key: str, user_guid: str, computer_guid: str | None, source_revision: str) -> dict`; `confirm_link(db, *, preview_id: str, expected_revision: int, actor: str, reason: str) -> dict`; `end_link(db, *, link_id: str, expected_revision: int, actor: str, reason: str) -> dict`.

- [x] Write tests for homonymous employees, changed GUID/SID, one employee/several PCs, existing different protected assignment, existing employee replacement, disabled/deleted user, stale source preview, duplicated network identity, deleted card and optimistic revision races. Assert automatic refresh leaves the previous employee intact and records a discrepancy.
- [x] Run `python -m pytest tests/test_workstations_links.py -q`; observe failures.
- [x] Implement short-lived server-owned previews bound to all source and relationship revisions, explicit confirmation/reason and ended history. Use existing inventory confirmation service when a relation needs confirmation; require its expected manual revision. Portal links cannot manufacture a controller domain assignment or bypass native reconfiguration gates.
- [x] Re-run link and inventory revision/link suites; commit `feat(workstations): confirm employee device links with evidence`.

## Task 7: Permission-scoped API, async operations and safe journal

**Files:** Create panel `service.py`, `api.py`, `journal.py`; modify `app/auth.py`, `permissions.py`, `config.py`, `main.py`; create `tests/test_workstations_api.py`, `test_workstations_permissions.py`, `test_workstations_journal.py`.

**Interfaces:** `WorkstationsService.start(action: str, parameters: dict, *, actor: str, request_id: str) -> dict` returns an existing panel operation ID or native job projection; `WorkstationsService.operation(operation_id: str, *, actor: str) -> dict` recovers safe results from durable workstation requests. `JournalService.list(db, *, filters: dict, cursor: str | None, limit: int) -> dict`; `export` streams the same authorized fields. API paths exactly follow design section 8, mounted under `/api/v1/workstations`.

Scoped credential configuration is `WORKSTATIONS_API_CREDENTIALS_FILE`, a protected JSON list of token hashes, actors and explicit workstation permission grants, validated fail-closed. Existing legacy authentication remains available only for its explicitly configured grants. Never put plaintext tokens in this file or expand legacy permission defaults. Operation polling is `GET /api/v1/workstations/operations/{id}` and checks the original owner plus the original action's current permission.

- [x] Test observer read-summary access versus directory denial, exact plan/apply/link/diagnose grants, legacy token default exclusion, dedicated scoped credentials, CSRF for session mutations/search, no-store directory responses, extra fields rejected, worker-owned DB sessions and uncertain remote outcomes. Test private-data denial through every journal/export/API path and tokens with only summary permission.
- [x] Run `python -m pytest tests/test_workstations_api.py tests/test_workstations_permissions.py tests/test_workstations_journal.py -q`; confirm RED.
- [x] Add workstation grants without extending generic `permission.endswith(':read')` to personal-data surfaces. Reuse existing session/token hashing/auth checks and panel operation registration. Keep durable safe response receipts in feature storage because existing process-local operation futures do not survive restart. Audit actor/action/IDs/code; never query bodies, raw LDAP, private plan payloads or stdout/stderr.
- [x] Implement event cursor pagination, redacted error classifications and bounded journal export. State explicitly when evidence is missing/UNKNOWN; do not turn transport failure into native execution failure or success. Test operation/result ownership across sessions and service tokens.
- [x] Run new tests plus `python -m pytest tests/test_panel_permissions.py tests/test_panel_operations.py tests/test_api_routes.py tests/test_mcp_server.py -q`; commit `feat(workstations): add authorized operations and audit API`.

## Task 8: Navigation, wizard, reconciliation and live progress UI

**Files:** Create panel `web.py`, `app/templates/workstations.html`, `workstations_device.html`, `workstations_plan.html`, `workstations_job.html`, `workstations_reconcile.html`, `workstations_sources.html`, `app/static/workstations.js` and `.css`; modify `base.html`, `app/main.py` and existing PC/network detail templates for stable links; create `tests/test_workstations_web.py`, `tests/workstations.test.js`, and isolated browser fixture/journey under `tests/browser/`.

**Interfaces:** Web routes `/workstations`, `/workstations/devices/{id}`, `/workstations/plans/{id}`, `/workstations/jobs/{id}`, `/workstations/reconcile`, `/workstations/sources`. Browser uses the authenticated Task 7 API and CSRF, never controller SSH. JS consumes canonical status/events with monotonic sequence cursors and typed error envelopes.

- [x] Test separate navigation item, all six wizard stages, homonym selection, approved OU/profile choices, exact-plan confirmation/expiry, inactive `Создать пользователя` with exact explanatory copy, read-only observer rendering and no request from disabled creation controls.
- [x] Test queue blocker/position, running stage, first-login/reboot human action, failure/UNKNOWN, technical versus functional verification, pagination beyond one event page, reconnect deduplication, missing evidence and backoff. Use fake timers for two-second visible polling and hidden-tab pause; GET polling must not invoke verification.
- [x] Run `python -m pytest tests/test_workstations_web.py -q` and `node --test tests/workstations.test.js`; verify failing assertions before implementation.
- [x] Implement existing visual patterns, accessible stage list and error panel, coherent-source comparison and links to existing inventory relation confirmation. Escape directory/log fields in HTML/DOM; no raw `innerHTML` for external values. Preserve in-progress selection through recoverable failures.
- [x] Run suites and isolated browser journey at desktop/mobile widths, capture screenshots and console/network errors. Commit `feat(workstations): add setup and reconciliation web interface`.

## Task 9: Existing MCP tools and OpenVPN Control skill

**Files:** Modify repository `mcp/openvpn_mcp_server.py`, `tests/test_mcp_server.py`; add `docs/runbooks/workstations-mcp.md`; update canonical local plugin script and `skills/openvpn-control/SKILL.md` plus relevant existing plugin metadata. Do not edit memory files or create a second MCP integration.

**Interfaces:** Add `openvpn_workstations_status`, `openvpn_workstations_devices`, `openvpn_workstations_catalog`, `openvpn_workstations_search_users`, `openvpn_workstations_link_preview`, `openvpn_workstations_link_confirm`, `openvpn_workstations_link_end`, `openvpn_workstations_plan`, `openvpn_workstations_component_plan`, `openvpn_workstations_apply`, `openvpn_workstations_operation`, `openvpn_workstations_jobs`, `openvpn_workstations_job_status`, `openvpn_workstations_job_events`, `openvpn_workstations_verify`, `openvpn_workstations_cancel`, `openvpn_workstations_reconcile`, `openvpn_workstations_reconcile_status`, `openvpn_workstations_findings`, `openvpn_workstations_sources`, `openvpn_workstations_journal`. Parameter schemas match Task 7 routes and reject extra fields.

- [x] Add MCP schema/API mapping tests, exact-confirmation/revision requirements, forbidden employee creation/arbitrary command absence, readonly credential denial and safe errors on every new tool. Assert all old tools still map unchanged.
- [x] Run `python -m pytest tests/test_mcp_server.py -q`; confirm new assertions fail.
- [x] Extend API dispatch using the existing HTTP client, with bounded pagination and the same operation/job receipts. Read `skill-creator` and `writing-skills` instructions before the actual skill edit; document search/select/preview/confirm/watch, source freshness, identity ambiguity and UNKNOWN stop conditions without adding new approval flows.
- [x] Run all MCP tests and an isolated stdio initialize/tools-list/tools-call session against the test API. Compare repository/plugin script hashes, update plugin through its supported source/install workflow and check actual new server tool discovery separately from tools already loaded in this chat. Commit repository files as `feat(mcp): expose workstation setup and directory reconciliation`. Canonical plugin source is updated; cached-skill/current-chat refresh remains a Task 12 installed acceptance gate.

## Task 10: Restricted AD account and deployment packaging

**Files:** Create `deploy/alt-linux/provision-directory-observer.ps1`, observer config sample, `deploy/workstations.env.sample`, `tests/alt_linux/test_directory_observer_provisioning.py`, `tests/test_workstations_deploy.py`; modify existing controller installer manifests/validation, `deploy/install-openvpn-web.sh` and service credential declarations only where required; add `docs/runbooks/workstations.md`.

**Interfaces:** Bootstrap script takes configuration/credential input through protected files or a secure administrator session; it creates one integration identity, records its stable SID, and applies only account-specific scoped grants/restrictions. It never accepts employee bulk creation or writes DNS records. Its check mode emits only safe membership/ACL/readiness booleans and counts.

- [x] Test dedicated readonly source, absence of administrative/DNS management membership, inherited write-right detection, protected secret handoff, no raw secret/password argv/logging, exact scoped ACL change, idempotent recheck of the same SID, collision refusal and no unrelated ACL/policy edits. Account creation/ACL bootstrap is a deployment operation, not an HTTP/MCP tool.
- [x] Run provisioning/deployment tests and validate shell/PowerShell syntax on their actual platforms; do not claim static string checks prove effective AD rights.
- [x] Implement source validation and native guarded-install coverage for every new controller executable/config; require a verified rollback backup and a fresh native maintenance review where historical UNKNOWN requires it. Gate reconciliation timer activation on schema/gateway/readonly credential readiness. Existing unconfigured installs remain usable.
- [x] Implement scoped API credential provisioning for new MCP capabilities without silently adding permissions to old token defaults. Register explicit owned keys/paths in the protected deployment receipt, not tracked config. Document backup/rollback and evidence commands without production addresses.
- [x] Re-run packaging and relevant installer/service tests; commit `feat(workstations): package restricted integration deployment`.

## Task 11: Integration verification, review and publication

**Files:** Add `docs/verification/WORKSTATIONS_WEB_DIRECTORY_2026-10-15.md`; update `README.md` and canonical ALT/operator guides where entry points change. Keep environment evidence private.

- [x] Read both approved documents and execute all new boundary suites plus full Linux CI: `python -m pytest tests -q`. Run `node --test tests/workstations.test.js`, JS syntax checks and actual browser journey. Record exact commands/results rather than reusing historical counts.
- [x] Refresh GitNexus status/context/impact for touched web/controller/MCP boundaries. Confirm no new Endpoint provider/consumer contract was introduced; verify dynamic gateway/service paths directly in source/tests. Do not trigger manual central synchronization.
- [x] Obtain independent whole-change review using the applicable review skill, resolve actionable findings with fresh targeted verification, inspect full diff and run `git diff --check`. Scan staged/tracked new files for credentials, private identifiers and environment evidence.
- [x] Safely integrate the feature branch into fresh main, run exact-source CI, and publish main according to repository rules. Record full commit SHAs, messages, included files and actual checks for each logical commit. Do not publish known failing/incomplete behavior as finished.

## Task 12: Guarded rollout and live acceptance

**Files:** Populate the verification report with safe installed evidence; preserve private deployment receipts separately.

- [x] Read-only preflight both deployment hosts: source revision, service state, controller active/admission state, capacity, protected bootstrap availability, schema and transport reachability. Reuse existing protected access; do not request passwords in chat or infer administrative AD rights from successful LDAP reads.
- [x] Create/verify/rehearse a fresh controller backup using native `alt-deploy-backup` commands. Generate/confirm any required fresh scoped maintenance review with existing services; preserve UNKNOWN and leases. Pass resulting backup ID/review through protected files/argv without printing them in general reports.
- [x] Run `install-control-plane.sh --rollback-backup-id ...` with its required fresh maintenance argument when applicable, from the exact published source. Verify installed hashes, guard/readiness, service ownership and forced-command restrictions before giving the panel gateway credentials.
- [x] Provision the AD integration identity through the protected administrator bootstrap; inspect effective memberships/ACLs including inherited DNS child creation/machine join rights, verify required paged reads and safe write-right checks. If the administrator bootstrap is unavailable, continue independent code/web work but leave directory deployment explicitly pending.
- [x] Deploy panel through `deploy/install-openvpn-web.sh` using its established source path and protected environment; apply targeted schema changes and start the five-minute reconciliation timer only after readiness checks. Verify real complete generations, inventory relations, conflict examples and safe failure indication.
- [x] In a separate browser tab, authenticate with an existing authorized operator session. Verify employee search/selection, a read-only real plan preview, existing retained job stages/errors, inventory/network navigation and disabled employee creation. Do not join/reboot a real PC for a UI demonstration.
- [x] Run newly installed MCP tools for status, employee search, device reconciliation and retained job events with appropriately scoped protected credentials. Prove write denial with a read credential without attempting a target mutation.
- [x] Verify web/controller installed hashes and active services, inspect bounded journals for new failures, verify VPN/network regression read-only through existing MCP. Document source publication, installed acceptance and any unfulfilled real-target gate distinctly.
- [x] Remove only this feature's staging branch/worktree after preserving private evidence. Leave unrelated worktrees and user browser state intact. Report actual outcome and any remaining external prerequisite without calling a partial rollout complete.

## Self-review coverage

Spec sections 1-3 map to Tasks 3/4/7/8; section 4 to Tasks 1/2/10;
section 5 to Tasks 5/6; sections 6-7 to Tasks 7/8; section 8 to Task 7;
section 9 to Task 9; sections 10-11 to Tasks 10-12. All five Review Focus
conditions have named owning test steps. Newly proposed signatures are defined
before consumers; native method signatures above were checked against source.
Read-only search/collection and mutating execution remain separate scopes.
