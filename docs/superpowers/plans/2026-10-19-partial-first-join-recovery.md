# Partial First-Join Recovery Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Complete the authorized workstation configuration through safe diagnostics, one verified local-authentication recovery and a new confirmed Setup job while preserving UNKNOWN history.

**Architecture:** Retain the protected Setup pipeline and existing GUID recovery. Add a read-only closed-failure/partial-state contract shared with the native maintenance validator, then a separate one-shot local recovery and its additive Setup continuation. Maintenance coverage remains controller-only; no recovery writer is exposed through web/MCP.

**Tech Stack:** Python 3.12 standard library, existing Ansible Core 2.18.6, ALT p11 native system-auth/Samba/SSSD tools, existing pytest and FastAPI/Jinja2 workstation UI. No new runtime dependency or service.

**Spec:** [Approved design](../specs/2026-10-19-partial-first-join-recovery-design.md).

**Execution method:** Native execution in this chat, preserving the operator's standing choice. One independent whole-branch review before publication. This plan is proposed for review; its checkboxes are not execution evidence.

## Global Constraints

- Retain every original UNKNOWN job, event, assignment revision, consumed plan and reservation.
- Recovery itself must not join a domain, create/delete/reset/move an AD object, change DNS, install packages, reboot, log in as an employee or run an old job.
- A subsequent Setup requires a separate fresh plan, its exact confirmation, and a new job.
- Plans expire after 30 minutes; maintenance confirmation grants a six-hour nonrenewing maintenance window.
- Execute only the hash-bound packaged `system-auth write local`, without --gpo.
- No computer GUID is fabricated or replaced by a sentinel.
- A timeout, disconnect, missing result, unexpected write or failed postcondition leaves the new recovery attempt UNKNOWN and blocks continuation.
- Do not delete Samba/SSSD configuration, clear credential databases, modify local accounts or replace the packaged tool.
- Keep schema-1 joined snapshots and QueueAdmissionReview behavior unchanged.
- Keep secrets in protected runtime storage; use synthetic identities in tracked tests and documentation.
- Preserve the three existing untracked workstation PNGs. Publish completed verified code to main through ordinary Git integration; do not rewrite pushed history.

## Review Focus

1. A wrapper succeeds at an AD write but loses its final reply: diagnosis must retain uncertainty and must never authorize another join (Task 1).
2. A different AD object owns the requested DNS hostname or short/FQDN host SPN: account-name absence alone must not admit recovery (Task 2).
3. Another closed failure or legacy reservation appears after maintenance confirmation: coverage must expire by evidence drift, with no implicit exclusion (Task 3).
4. A recovery claim exists but execution/result publication was interrupted: another plan, ordinary worker, legacy writer and maintenance must not bypass it (Tasks 4–5).
5. The mutable current assignment advances after a successful successor: archival predecessor validation must retain the original sealed bytes without requiring the old assignment to remain current (Task 5).

## Preparation and file boundaries

Use the existing `codex/partial-first-join-recovery` staging branch. At implementation time use the native managed-worktree tool with this exact branch as its ref, after checking attached worktrees. Do not restore an unrelated archived checkout. Keep the original checkout's PNGs untouched.

Linux commands below run in an isolated checkout and venv with repository requirements plus `ansible-core==2.18.6`; they must never run against the live controller state root. Record the exact checkout SHA and test output. The current GitNexus tool inventory is empty; retry discovery before implementation and use repository `web_ovpn` query/context if it becomes available. Otherwise record that limitation and verify the named dynamic consumers against source/tests. Use Context7 before introducing any new library-dependent behavior.

Before changing product code, run the existing focused baseline: `python -m pytest -q tests/test_alt_first_join_compat.py tests/alt_linux/test_setup_events.py tests/alt_linux/test_setup_maintenance_review.py tests/alt_linux/test_setup_queue_review.py tests/alt_linux/test_setup_detach.py`. Resolve or account for pre-existing failures before attributing failures to this change. Do not install dependencies globally on the production controller.

New control modules have separate responsibilities: `setup_partial_local_state.py` validates protected state; `setup_partial_local.py` coordinates plan/apply/status; `setup_partial_local_runtime.py` executes the fixed target protocol; `partial_local_target.py` owns target snapshot/write/verification; `setup_partial_local_continuation.py` offers a normal Setup plan. Read-only closure and observation modules live with the canonical backup validator so its supported installer can publish them before the controller update. No staged controller mutation code is imported to bypass that installation order.

### Task 1: Preserve safe first-join diagnostics and test the native interface

**Files:**
- Modify: `deploy/alt-linux/ansible/roles/domain_join/files/first_join.py`.
- Create: `deploy/alt-linux/ansible/roles/domain_join/files/first_join_diagnostics.py`.
- Modify: `deploy/alt-linux/ansible/roles/domain_join/tasks/main.yml`, `deploy/alt-linux/control/alt_deploy/configure.py`, `deploy/alt-linux/control/alt_deploy/setup_events.py`, `deploy/alt-linux/ansible/callback_plugins/alt_setup_events.py`.
- Test: `tests/test_alt_first_join_compat.py`, new `tests/test_alt_first_join_diagnostics.py`, `tests/alt_linux/test_setup_events.py`, `tests/test_workstations_journal.py`.

**Interfaces:**
- `first_join_diagnostics.Diagnostics(binding: dict, *, root: Path)` exposes `intent(phase: str)`, `result(phase: str, *, code: str, returncode: int | None)` and `publish() -> dict`. Module-level `read_public(binding: dict, *, root: Path) -> dict` validates a retained receipt.
- Binding fields: `schema_version=1`, `configuration_run_id` (32 lowercase hex), `invocation_id` (32 lowercase hex), `identity_sha256` (64 lowercase hex). Fixed evidence root: `/var/lib/alt-deploy-first-join`; callers cannot supply a target path in production.
- Receipt fields: binding plus `phase`, `code`, `directory_effect` (`not_dispatched`, `dispatch_entered`, `returned_success`, `returned_failure`, `uncertain`) and `returncode`. A returned failure is not proof of no AD effect. Public reader returns only binding and allowlisted phase/code/effect, never raw output.
- Phase IDs: `request`, `native_interface`, `preconditions`, `directory_observation`, `native_arguments`, `native_execution`, `offline_keytab`, `keytab_bind`, `trust_verify`, `machine_as`. Codes use the `first_join_` prefix with exactly `request_invalid`, `native_interface_invalid`, `local_state_conflict`, `directory_unavailable`, `native_arguments_invalid`, `native_failed`, `native_access_denied`, `native_kerberos_failed`, `native_name_collision`, `native_cache_unavailable`, `keytab_create_failed`, `keytab_bind_failed`, `trust_failed`, `machine_as_failed`, `timeout`, `output_limit`, `internal_error`, `ok`. Specific native classes require recognized bounded native status markers; unmatched text yields `native_failed` and is never printed or treated as no-write evidence.

- [x] **Step 1: Add RED cases** named `test_wrapper_reply_loss_retains_uncertain_effect`, `test_receipt_survives_private_wrapper_cleanup`, `test_foreign_binding_and_no_log_never_export`, and `test_native_contract_probe_has_no_directory_writer`. Assert that no error text, synthetic secret or command argument reaches a receipt/event; missing/oversized/unsafe receipts fail closed. Exercise request, native-interface, argument, native-command, offline-keytab, bind, trust and machine-AS failure phases. Preserve all existing compatibility tests.
- [x] **Step 2: Run** `python -m pytest -q tests/test_alt_first_join_compat.py tests/test_alt_first_join_diagnostics.py tests/alt_linux/test_setup_events.py tests/test_workstations_journal.py`. Confirm new tests fail for the missing diagnostic contract, not imports or platform dependencies.
- [x] **Step 3: Implement** root-private bounded receipts (maximum 4096 encoded bytes), no-follow ownership checks, atomic create-only publication and fixed phase/code validation. Parent and private wrapper share one operation binding; retain intent before invoking a writer and publish the final safe receipt before temporary-directory cleanup. Preserve the fatal compatibility marker and existing join authorization inputs.
- [x] **Step 4: Integrate** the controller-generated run/invocation binding into fixed Ansible variables. Install the diagnostic helper with the fixed first-join assets; retain isolated Python execution by loading its exact trusted installed file rather than widening sys.path. Put receipt reading in the domain role's `always` section outside `no_log`, with `no_log: false` only for its bounded public result. Missing receipts must not mask the original failure. Extend native event codes only for the tagged reader task with matching binding; never parse arbitrary task stderr. Existing code/event schemas remain readable. Journal and MCP expose the same paginated events.
- [x] **Step 5: Run GREEN** with the Step 2 command and `python -m pytest -q tests/test_alt_domain_resilience_assets.py tests/test_alt_manual_configure_request.py`. Reproduce native command/cache construction in an isolated fixture with all writer calls intercepted. Change join behavior only if this proves a concrete defect; otherwise document that the historical exception is unrecoverable and retain join behavior.
- [x] **Step 6: Inspect full diff, run** `git diff --check`, stage only these task files and commit `fix(workstations): retain safe first-join diagnostics`.

### Task 2: Define read-only closed-failure and partial-local evidence

**Files:**
- Create: `deploy/alt-linux/backup/alt_deploy_backup/setup_closed_failure.py`, `deploy/alt-linux/backup/alt_deploy_backup/setup_partial_observation.py`, `deploy/alt-linux/backup/alt_deploy_backup/partial_local_probe.py`.
- Modify: `deploy/alt-linux/control/alt_deploy/setup_maintenance_review_bridge.py`.
- Test: new `tests/alt_linux/test_setup_closed_failure.py`, `tests/alt_linux/test_setup_partial_observation.py`, `tests/alt_linux/test_partial_local_probe.py`.

**Interfaces:**
- `ClosedFailureEvidence(settings).load(job_id: str) -> dict`: returns `job_id`, `failed_run_id`, `configuration_run_id`, `machine`, `binding`, `lease_ids`, `history_sha256`, and `files` (exact protected bytes with their SHA-256). This is internal archival evidence, not execution permission. Coverage/Setup plans contain references and manifests, not duplicated raw history.
- `PartialLocalObserver(settings).observe(closed: dict, *, mode: str) -> dict`: `mode` is exactly `partial_ad` or `local`; returns fresh original identities, SSH binding, complete collision evidence, native-tool/side-effect manifest, boot/clock/package/process facts, local-administrator access and expected target snapshot metadata.
- `partial_local_probe.collect(request: dict, *, root: Path, owner: int) -> dict`: fixed read-only target collector. Production root is `/`; alternate roots are test-only, never accepted from the CLI.
- Trusted bridge functions `closed_failure_service(settings)` and `partial_observer_service(settings)` resolve only the named root-owned canonical backup modules.

- [x] **Step 1: Add RED cases** `test_original_closed_join_is_sealed_without_guid`, `test_dns_or_spn_collision_denies_absence`, `test_missing_result_or_event_gap_denies_history`, `test_unexpected_tdb_key_denies_partial_state`, and `test_probe_never_writes_authentication_files`. Assert original bytes are unchanged; a false/empty result caused by failed or incomplete LDAP is rejected. Test both `host/short` and `host/fqdn` SPNs, account-name and DNS-hostname matches, duplicate objects and paged/budget failures.
- [x] **Step 2: Run** `python -m pytest -q tests/alt_linux/test_setup_closed_failure.py tests/alt_linux/test_setup_partial_observation.py tests/alt_linux/test_partial_local_probe.py`; verify RED from absent interfaces.
- [x] **Step 3: Implement** history validation using existing job/event/ConfigureRequest/result validators and exact two same-machine UNKNOWN legacy reservations. Seal old assignment bytes before a successor can advance the current assignment. Require initial local/no-object/no-trust observations and domain-join events. Do not modify the timeout or existing GUID recovery validators.
- [x] **Step 4: Implement** complete bounded collision queries through the existing approved LDAP transport, immutable employee/OU/profile identity checks, strict SSH and existing `SetupRuntime.probe_prejoin`/component package-health collectors. The additional fixed probe reads native hashes, PAM/NSS links and templates, authentication-file metadata, local admin/sudo policy, services and synchronized clock. Require safe link targets, regular root-owned native tools, no credentials and no incompatible process. Distinguish expected unresolved employee NSS in partial mode from broken local admin access. Record exact supported GOA/control/service effects; unsupported implementations deny admission.
- [x] **Step 5: Run GREEN** with Step 2 plus `python -m pytest -q tests/alt_linux/test_setup_prejoin_tdb.py tests/alt_linux/test_setup_recovery_history.py tests/alt_linux/test_setup_recovery_facts.py`. Verify unsafe ancestry, symlinks, file replacement during read, other-domain state, changed boot and ambiguous identities all deny.
- [x] **Step 6: Inspect diff/check, stage named files and commit** `feat(workstations): validate partial first-join evidence`.

### Task 3: Cover multiple closed failures for controller maintenance

**Files:**
- Create: `deploy/alt-linux/backup/alt_deploy_backup/setup_maintenance_coverage.py`.
- Modify: `deploy/alt-linux/backup/alt_deploy_backup/setup_maintenance_review.py`, `deploy/alt-linux/backup/alt_deploy_backup/setup_compat.py`, `deploy/alt-linux/install-backup-tool-lib.sh`, `deploy/alt-linux/control/alt_deploy/setup_cli.py`.
- Test: new `tests/alt_linux/test_setup_maintenance_coverage.py`; existing `test_setup_maintenance_review.py`, `test_setup_maintenance_review_retry.py`, `test_setup_queue_review.py`, `test_setup_backup_compatibility.py`, `test_or3p3_backup_installer.py` in `tests/alt_linux/`.

**Interfaces:**
- `MaintenanceCoverage(settings, *, observer=None, clock=None).plan() -> dict`, `.confirm(plan_id: str, sha: str) -> dict`, `.exclusions(sha: str) -> dict`.
- Schema 2 uses existing `setup-maintenance-<sha>` prefix, `setup_maintenance_plan` operation and `controller_maintenance_only` purpose. Payload contains sorted covered jobs, exact sorted lease IDs, sealed history, each observation mode, fresh evidence and hashes of all validator dependencies. Confirmation receipt keeps the existing fields with `schema_version=2`.
- `MaintenanceReview.plan_all_closed()` delegates to coverage. Its `confirm`/`exclusions` dispatch schema 2 only for the maintenance purpose; QueueAdmissionReview and schema-1 snapshots retain their existing paths.

- [x] **Step 1: Add RED cases** `test_joined_and_partial_failures_have_exact_maintenance_coverage`, `test_late_closed_failure_invalidates_coverage`, `test_foreign_or_running_lease_is_not_covered`, and `test_partial_maintenance_receipt_cannot_admit_queue`. Add schema-1 archival compatibility, root validation and duplicate confirmation without deadline extension.
- [x] **Step 2: Run** `python -m pytest -q tests/alt_linux/test_setup_maintenance_coverage.py tests/alt_linux/test_setup_maintenance_review.py tests/alt_linux/test_setup_maintenance_review_retry.py tests/alt_linux/test_setup_queue_review.py`; confirm new cases RED.
- [x] **Step 3: Implement** complete-set discovery under the native lifecycle lock, excluding only validated reviewed predecessors. Seal complete history apart from maintenance plans/receipts, require exactly paired closed leases per covered job, and recheck the set after observations. Reuse strict joined observations; use Task 2 for partial mode. Plan TTL is 30 minutes; a confirmed receipt lasts exactly 21600 seconds and cannot be renewed by duplicate confirmation.
- [x] **Step 4: Integrate** mutually exclusive `maintenance-plan JOB_ID` / `maintenance-plan --all-closed` CLI handling. Extend the trusted backup installer and its native-observer dependency whitelist with the new read-only modules. Bootstrap must work with the prior installed controller and no partial-recovery artifacts. Validate all new-version records in backup/restore and keep default backup blocked without explicit coverage. No partial maintenance receipt is a target-execution token.
- [x] **Step 5: Run GREEN** with Step 2 and `python -m pytest -q tests/alt_linux/test_setup_backup_compatibility.py tests/alt_linux/test_or3p3_backup_installer.py tests/alt_linux/test_or3p3_backup_rehearsal.py tests/alt_linux/test_setup_jobs_cli.py`. Include native root sandbox create/verify/rehearse and exact-history restore refusal. Confirm source-versus-installed validator mismatch denies.
- [x] **Step 6: Inspect diff/check and commit** `feat(workstations): cover closed failures in maintenance review`.

### Task 4: Implement one-shot local-authentication recovery

**Files:**
- Create in `deploy/alt-linux/control/alt_deploy/`: `setup_partial_local_state.py`, `setup_partial_local_runtime.py`, `partial_local_target.py`, `setup_partial_local.py`.
- Modify: `deploy/alt-linux/control/alt_deploy/setup_cli.py`.
- Test: new `tests/alt_linux/test_setup_partial_local_state.py`, `test_setup_partial_local_runtime.py`, `test_partial_local_target.py`, `test_setup_partial_local.py`, `test_setup_partial_local_cli.py`.

**Interfaces:**
- `PartialLocalStore(settings, *, clock=None)`: `retain_closed(closed: dict) -> dict`, `create(payload: dict) -> dict`, `load(plan_id: str, sha: str, *, archival=False) -> dict`, `claim_once(plan: dict) -> dict`, `publish_result(claim: dict, result: dict) -> dict`, `validate_artifacts() -> None`, `pending_attempts() -> list[dict]`.
- Fixed directories under state root: `setup-partial-local-evidence`, `setup-partial-local-plans`, `setup-partial-local-claims`, `setup-partial-local-results`. Evidence is a content-addressed manifest with separately retained protected original files; do not pack all event bytes into one bounded plan JSON. Preserve existing state-file size limits and event limits. Plan prefix `partial-local-`, schema 1, operation `partial_local_recovery`, TTL 30 minutes. Claim key is the digest of original job/failed-run identity, not plan ID: changing plans cannot permit a second dispatch.
- `PartialLocalRuntime(settings).snapshot(closed: dict, *, mode: str) -> dict` uses Task 2; `.apply(plan: dict, claim: dict) -> dict` dispatches the fixed target helper once and returns verified backup/result evidence; `.verify(plan: dict, result: dict) -> dict` is read-only.
- `partial_local_target.execute(request: dict, *, root: Path, owner: int) -> dict` creates the exact private backup, validates all preconditions and executes only the fixed native local transition. Production accepts no alternate root or arbitrary command.
- `PartialLocalService(settings, *, observer=None, runtime=None, clock=None)`: `plan(job_id: str) -> dict`, `apply(plan_id: str, sha: str) -> dict`, `status(plan_id: str) -> dict`. CLI: `setup recovery partial-local plan JOB_ID`, `apply PLAN_ID --confirm-sha256 SHA`, `status PLAN_ID`.

- [x] **Step 1: Add RED cases** `test_one_claim_per_original_failure_across_plans`, `test_disconnect_after_dispatch_stays_unknown`, `test_missing_or_tampered_backup_denies_write`, `test_native_hash_or_boot_drift_denies_before_claim`, `test_local_transition_preserves_accounts_and_credentials_absence`, and CLI tests for exact SHA, expiry and command rejection. Assert plan/status call no target writer; preconditions fail before claim; a consumed claim is never dispatched twice.
- [x] **Step 2: Run** `python -m pytest -q tests/alt_linux/test_setup_partial_local_state.py tests/alt_linux/test_setup_partial_local_runtime.py tests/alt_linux/test_partial_local_target.py tests/alt_linux/test_setup_partial_local.py tests/alt_linux/test_setup_partial_local_cli.py`; verify RED.
- [x] **Step 3: Implement** protected bounded create-only plans/claims/results, archival validation independent of current TTL and live validation enforcing TTL/source/identity. Follow lifecycle then admission-lock ordering, recheck the exact closed target, reject unrelated executing/queued work, and consume the original-failure claim only after all preflight/backup prerequisites. Do not call ordinary legacy execution admission with a fabricated completed predecessor.
- [x] **Step 4: Implement** expected snapshot manifest from fresh read-only bytes, private root-owned forensic backup with safe symlink metadata/absence markers, fsync and exact verification. Bind native tool/control/PAM template hashes, relevant service state and the supported GOA behavior. Backup failure dispatches no auth writer. Execute `system-auth write local` once without --gpo, then verify unchanged machine/boot/accounts, local PAM/NSS, fresh pinned SSH/sudo, absent machine credentials/directory collisions, expected services and quiet healthy packages. Unexpected effects or uncertain completion publish no successful receipt. Status reads never resume the attempt.
- [x] **Step 5: Run GREEN** with Step 2 and `python -m pytest -q tests/alt_linux/test_setup_recovery_operator.py tests/alt_linux/test_setup_recovery_attempt_context.py`. Exercise concurrent apply in separate processes and controller termination after claim, target dispatch and result publication. Every incomplete boundary must retain one claim and block continuation.
- [x] **Step 6: Inspect diff/check and commit** `feat(workstations): add one-shot partial-local recovery`.

### Task 5: Admit one fresh successor and protect all execution boundaries

**Files:**
- Create: `deploy/alt-linux/control/alt_deploy/setup_partial_local_continuation.py`.
- Modify in `deploy/alt-linux/control/alt_deploy/`: `setup.py`, `setup_retry.py`, `setup_jobs.py`, `setup_worker.py`, `setup_cli.py`, `controller_readiness.py`, `configure.py`, `setup_recovery_history.py`, `setup_recovery_resolution.py`.
- Modify: `deploy/alt-linux/backup/alt_deploy_backup/setup_compat.py`.
- Test: new `tests/alt_linux/test_setup_partial_local_continuation.py`, `test_setup_partial_local_admission.py`; existing `test_setup_detach.py`, `test_setup_automatic_admission.py`, `test_setup_backup_compatibility.py`, `test_setup_recovery_continuation.py`, `test_setup_recovery_prejoin_history.py` in `tests/alt_linux/`.

**Interfaces:**
- `PartialLocalContinuation(settings, *, setup=None, runtime=None, clock=None).plan(recovery_plan_id: str) -> dict` returns an ordinary full-Setup plan and performs no join.
- `load_resolution(settings, reference: dict, *, archival: bool) -> dict` and `validate_resolution(settings, reference: dict, binding: dict, *, live: dict | None) -> dict` live in the new continuation module. Proof key is `partial_local_resolution`; reference fields are original `job_id`, `failed_run_id`, `configuration_run_id`, `recovery_plan_id`, `recovery_sha256`, `result_sha256`, `history_sha256`.
- Add `partial_local_resolution=None` to `SetupService._snapshot`. Full-plan validation allows at most one of `prejoin_retry`, `recovery_resolution`, `partial_local_resolution`; a predecessor continuation requires exactly one. Ordinary initial plans retain no continuation proof. Normal plan/apply continues through the existing service, engine and worker.
- Native backup validation uses `PartialLocalStore.validate_artifacts()` and seals every new directory. If absent, prior-controller bootstrap remains supported; if present, a compatible controller validator is mandatory.

- [ ] **Step 1: Add RED cases** `test_successful_local_recovery_offers_new_plan_without_join`, `test_only_one_successor_consumes_partial_resolution`, `test_archival_resolution_survives_assignment_revision`, `test_unknown_partial_attempt_blocks_worker_legacy_and_backup`, `test_maintenance_coverage_does_not_authorize_recovery`, and `test_guid_recovery_can_read_partial_successor_failure`. Assert old job/request/status/events/leases and sealed old assignment remain byte-identical. Assert a fresh native assignment revision advances only during the new Setup execution. A later independently failed new join with an actual AD object must remain inspectable by the existing GUID-based history contract.
- [ ] **Step 2: Run** `python -m pytest -q tests/alt_linux/test_setup_partial_local_continuation.py tests/alt_linux/test_setup_partial_local_admission.py tests/alt_linux/test_setup_recovery_continuation.py tests/alt_linux/test_setup_recovery_prejoin_history.py`; confirm RED.
- [ ] **Step 3: Implement** fresh successful-result/source/absence/health verification under lifecycle lock, then call the ordinary Setup snapshot/planner with the new proof. Preserve original employee/OU/profile and archive exact predecessor evidence. Extend detached-apply and worker revalidation, predecessor review, reviewed legacy-run calculation and existing native supersession of only the matching old run IDs. Add a dedicated partial-local predecessor-revision validator in RecoveryHistoryStore and use it in both history and resolution archival loads; preserve the original timeout branch and GUID identity/terminal checks. Add `partial-local continue-plan PLAN_ID` to CLI.
- [ ] **Step 4: Protect** job admission, worker dispatch, legacy configure/Setup, controller readiness and backup against any entered partial-local claim without a valid successful terminal receipt. Centralize this check in the store; do not mark old jobs completed or release their claims. Successful recovery alone grants no legacy or Setup exception. Use the existing immutable old-job review publication to atomically bind one successor and reject a second consumer, including concurrent submissions.
- [ ] **Step 5: Run GREEN** with Step 2 and `python -m pytest -q tests/alt_linux/test_setup_service.py tests/alt_linux/test_setup_detach.py tests/alt_linux/test_setup_automatic_admission.py tests/alt_linux/test_setup_jobs.py tests/alt_linux/test_setup_backup_compatibility.py`. Include an ordinary successful new job, component-plan refusal before protected Setup completes, stale evidence/source denial, and read-only status after controller restart. Re-read all dynamic proof consumers listed in Files; an empty graph result is insufficient.
- [ ] **Step 6: Inspect diff/check and commit** `feat(workstations): admit verified partial-local successors`.

### Task 6: Rehearse on isolated ALT and finish operator documentation

**Files:**
- Create: `tests/alt_linux/support/partial_local_sandbox.py`, `tests/alt_linux/test_partial_local_rehearsal.py`, `docs/runbooks/alt-partial-local-recovery.md`.
- Modify: `docs/ALT_OPERATOR_SETUP_CLI.md`, `docs/ALT_SETUP_ENGINE_V2.md`, `docs/WORKSTATIONS_WEB_GUIDE.md`, `docs/runbooks/workstations.md`.

**Interfaces:**
- `partial_local_sandbox.rehearse(snapshot: dict, native_tools: dict) -> dict` returns safe assertions and hashes for the isolated filesystem test; it grants no production execution permission.
- The live rehearsal record binds tested source, actual ALT native hashes and fixture outcome. This is distinct from synthetic pytest evidence and from real-workstation acceptance.

- [ ] **Step 1: Add RED** `test_rehearsal_refuses_unexpected_native_side_effect` and `test_rehearsal_preserves_local_authentication_and_snapshot`. Assert exact expected PAM/NSS changes, unchanged local account bytes, supported service effects and immutable forensic backup. Run `python -m pytest -q tests/alt_linux/test_partial_local_rehearsal.py` and confirm RED.
- [ ] **Step 2: Implement and run GREEN** the isolated native-file rehearsal and backup verification. Reject unsupported native effects; do not derive an allowlist by accepting arbitrary observed changes.
- [ ] **Step 3: Prepare real ALT rehearsal** using a new disposable clone of the existing reference VM, without changing or resetting that reference VM. First inspect hypervisor capacity and allocate an unused VM ID. Before its first boot, remove/disconnect all NICs, confirm fresh clone MAC/SMBIOS identity and no production network path. Use the working QEMU guest agent for control. Prepare a synthetic partial-local fixture only inside the disconnected clone; retained AD credentials must not be used or exported. Compare native executable/template hashes with the authorized target and refuse a mismatched rehearsal.
- [ ] **Step 4: Rehearse** the exact local transition in the disconnected clone. Use fresh SSH connections over guest loopback through guest-agent commands with explicitly pinned local host keys and throwaway fixture credentials. Verify PAM/local administrator authentication and sudo, normal ansible access, services, file effects and recovery uncertainty injection. Keep fixture-only account/credential preparation separate from the target helper, which must never modify accounts. Stop and retain evidence if the clone cannot be safely isolated or a native invariant fails; do not touch the reference VM. Clean up only the verified newly created disposable clone after evidence is retained privately.
- [ ] **Step 5: Write the runbook** with exact CLI, old-job preservation, failure meanings, expired-plan handling, original-receipt lookup, maintenance schema-2 rollout order, and separate recovery/Setup/reboot/login confirmations. Update web guidance only for the supported operator handoff and improved safe diagnostic codes; do not add a web recovery button. Keep live identities and secrets outside tracked examples.
- [ ] **Step 6: Inspect diff/check and commit** `docs(workstations): document partial-local recovery operations`; keep test code with its own meaningful test commit if independently reviewable.

### Task 7: Review, publish, deploy and complete the authorized workstation

**Files:**
- Create: `docs/verification/ALT_PARTIAL_LOCAL_RECOVERY_ACCEPTANCE_2026-10-19.md` with source/deployment hashes, safe counts and distinctions between synthetic tests, isolated rehearsal and actual acceptance. Actual target IDs and detailed receipts stay in protected runtime evidence.

**Interfaces:** Existing native `alt-deploy-backup`, guarded `install-control-plane.sh`, `workstationctl`, workstation MCP and web job/event views. No new release or remote execution mechanism.

- [ ] **Step 1: Run** `python -m pytest -q` once on the final candidate Linux checkout with Python 3.12, repository requirements and Ansible Core 2.18.6. Require exit 0 and retain actual counts/logs; do not reuse old results. Run native installer/sandbox checks appropriate to changed backup and controller files. Run `git diff --check`.
- [ ] **Step 2: Obtain independent whole-branch review** following requesting-code-review, with the approved spec, plan and complete diff. Resolve findings and rerun affected checks. Recheck GitNexus availability/status if available; report the limitation if unavailable and summarize source-verified dynamic proof/queue/backup consumers. No unrelated repository contract is introduced.
- [ ] **Step 3: Publish verified work to main** with ordinary non-force integration, preserving untracked user files and pushed history. Record all full commit SHAs, messages, included files and actual verification. Require hosted full-regression success bound to the published candidate; repository workflow `verify-netctl-runtime.yml` supplies the existing exact-source full suite. Do not label a cancelled or infrastructure-failed check passed.
- [ ] **Step 4: Stage the exact published source** below a root-managed controller release directory and normalize only that new stage's ownership/modes. Recheck real queue/execution is empty, controller capacity and immutable history. Install the compatible native backup tool first. Use the trusted staged `alt_deploy.cli` with its control PYTHONPATH and the normal service identity to generate `--json setup jobs maintenance-plan --all-closed`; the still-old installed workstationctl cannot parse the new option. The source bridge must resolve the same validated canonical backup revision. Present exact SHA/TTL and scope for confirmation, then confirm that exact fresh plan through the same native source CLI. Existing broad recovery authorization does not invent a current native SHA.
- [ ] **Step 5: Create, verify and rehearse a fresh matching controller backup** using that maintenance scope; pass its real backup ID and review SHA to the guarded installer. Keep its full checks enabled. Verify installed module/asset hashes against published source, unchanged old-history hashes, preserved SSH access and native readiness. No installed-file patches, stale receipt reuse or backup excluding UNKNOWN are permitted.
- [ ] **Step 6: Prepare the authorized target's partial-local plan** and present exact machine/scope, backup manifest, effects, SHA and TTL. Apply only after exact confirmation, once. Inspect the original attempt status after any lost reply. Require fresh successful local-access and no-object/no-credential verification. Keep the old UNKNOWN unchanged. If the new attempt is uncertain, stop target writes and report its original IDs.
- [ ] **Step 7: Prepare and confirm the separate new Setup plan** through `partial-local continue-plan`. Use the ordinary apply receipt and new job ID, watch every event page without gaps, and explicitly verify final components. Confirm that no old job or join was replayed. Use the existing web view and MCP to inspect the actual new job and safe diagnostics. Preserve the approved office profile and employee identity.
- [ ] **Step 8: Report actual acceptance** with technical state, new job outcome, old UNKNOWN preservation, remaining reboot/real employee login and functional checks. Perform reboot or employee login only within their separately authorized scope. Never create a fake home or call an incomplete installation successful. Commit the sanitized acceptance report after reviewing its full diff; publish it normally and remove the completed staging branch after successful main integration.

## Self-review and handoff

Spec coverage maps to Tasks 1 (diagnostics), 2 (absence/history/native facts), 3 (maintenance), 4 (backup/one-shot target action), 5 (successor/global guards), 6 (rehearsal/runbooks) and 7 (release/live acceptance). Review Focus cases are assigned above. The source currently contains no partial-local implementation; this plan does not imply that it exists or passed tests.

Before implementation, the operator reviews this written plan. Native execution in the current chat is already selected; do not ask to choose an execution method again. Apply the existing scope authorization throughout, requesting only the concrete exact-SHA confirmations required by the native protected plans and separately scoped reboot/login actions.
