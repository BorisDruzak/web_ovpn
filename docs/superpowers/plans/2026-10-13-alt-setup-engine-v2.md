# ALT Setup Engine V2 Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:executing-plans
> for inline execution, or superpowers:subagent-driven-development if the user
> selects delegation. Steps use checkbox syntax for tracking.

**Goal:** Give workstationctl a versioned approved component catalog, immutable
plans, durable execution jobs and independent actual-state verification while
preserving existing Setup/domain/recovery safeguards.

**Architecture:** Extend the current controller service and JobRepository with
typed Setup records and one shared execution entry point. A published YAML catalog
drives Python, Ansible selection and verification recipes. A systemd worker owns
the deterministic queue; CLI processes submit work or wait for the same engine.

**Tech Stack:** Existing Python controller, PyYAML 6.0.2, Ansible, systemd,
strict SSH, private atomic JSON state and pytest on Linux. No new database/broker.

**Spec:** `docs/superpowers/specs/2026-10-13-alt-setup-engine-v2-design.md`
**Baseline:** `3935bad3ab728c886f8f7dca2f93e5baa3ed16f9`
**Execution:** User approved this plan and inline execution in this chat on 2026-10-13.

## Global constraints

- Preserve `setup plan/apply/status/verify`, `base`, `core-apps`, historical records,
  30-minute plan TTL, SHA-256 confirmation, employee/computer GUID/SID and OU checks.
- Domain join/GPO is a protected full-Setup adapter; component apply cannot select
  domain-join, AD-account, recovery or legacy provision roles directly.
- Registration and existing domain assignment are mandatory for component mutation.
- No AD user creation, ISO/PXE, web pages, infrastructure change or fleet rollout.
- Only published Git/deployment assets define components. No runtime YAML upload,
  arbitrary playbook/path/role/shell/Ansible-expression CLI overrides.
- Independent probes are read-only. Unknown evidence cannot produce success.
- No automatic reboot, artificial domain home creation or replay of a claimed step.
- Publication to `main` is authorized; active deployment and mutating live
  acceptance require the separate operator approvals specified in the task.
- Focused RED -> GREEN per task and applicable regression per milestone; one full
  regression before publication. No heavy CI repetition without a new reason.
- Work on staging branch `codex/alt-setup-engine-v2`; no unrelated edits.

## Review focus

These conditions have dedicated tests in the owning tasks below:

1. Own queued reservation changes registration's active-job projection: admission
   must recognize its own reservation without accepting an unrelated active job.
2. Legacy worker runs Ansible outside lifecycle lock: V2 and legacy admission must
   not overlap mutation even when the lock is available.
3. Crash between reservation and job publication: consumed plan/identity claims
   must survive and block replay, including missing/corrupt linked records.
4. User home or SSH identity changes between plan and apply: fail before mutation;
   package presence cannot substitute for the selected employee identity.
5. Office profile without CryptoPro: desktop shortcuts must not require cptools;
   healthy software must not be copied/reinstalled just to produce a new result.

## File responsibilities and interfaces

All controller module paths below are under
`deploy/alt-linux/control/alt_deploy/`; all new tests are under `tests/alt_linux/`.
These prefixes are part of the exact file paths, not alternate locations.

| File | Responsibility |
| --- | --- |
| `component_catalog.py` | Strict complete published catalog, profile expansion and approved role mapping |
| `component_probe.py` | Fixed bounded actual-state probes over existing strict SSH transport |
| `component_verification.py` | Evidence validation, desired-state comparison and public verification |
| `component_setup.py` | Existing-assignment identity admission and immutable component plans |
| `setup_jobs.py` | Schema-2 Setup job adapter on JobRepository, claims, reservations, transitions |
| `setup_execution.py` | Shared locked full/component execution, safe results and continuation verification |
| `setup_worker.py` | Persistent FIFO worker, process identity and conservative restart reconciliation |
| `setup_events.py` | Versioned allowlisted events, safe error envelopes and bounded event reads |
| Existing `setup.py`, `setup_cli.py`, `configure.py` | Compatible full Setup adapters and CLI dispatch |
| Existing `jobs.py`, `job_reconcile.py`, `job_retention.py`, `provision.py` | Explicit v1/v2 compatibility at current consumer boundaries |
| Existing `setup_runtime.py`, `setup_plans.py`, `config.py` | Source/SSH binding, durable I/O reuse, worker settings |
| Published `software_catalog.yml` | One registry, profiles, approved role mapping and existing artifact metadata |
| `ansible/callback_plugins/alt_setup_events.py` | Safe structured execution events, no arbitrary result serialization |
| `ansible/playbooks/04-setup-component.yml` | Fixed component-only application without domain join |
| `systemd/alt-setup-worker.service` and `control/alt-setup-worker` | Detached service packaging |

Controller state remains file-based. A Setup job uses the existing `job-*` ID and
JobRecord wrapper with `status.schema_version=2`, `status.kind='setup'`. Legacy
records without this discriminator retain v1 validation. New Setup plans use
`setup-component-<64 hex>` under `setup-component-plans`, via SetupPlanStore subclass.
No v2 job is passed to provision result validation or recovery execution.

## Milestone 1 — Component Catalog

### Task 1: Strict catalog and immutable profiles

**Files:** Create `component_catalog.py`, `test_component_catalog.py`;
extend `deploy/alt-linux/ansible/group_vars/software_catalog.yml`;
create `docs/ALT_COMPONENT_CATALOG.md`.

**Interfaces:** `ComponentCatalog.load(project: Path) -> ComponentCatalog`;
`component(component_id: str) -> dict`; `profile(profile_id: str) -> dict`;
`ordered(component_ids: list[str], *, os_id: str) -> list[dict]`;
`fingerprint: str`. Accessors return defensive copies.
Published `setup_catalog` declares `schema_version`, `version`, `components` and
`profiles`; components/profiles are lists with unique IDs. A profile declares
`id`, `version`, `name`, ordered required `components`, `optional_components` and
`confirmation_policy='sha256'`. Initial supported OS ID is `alt-kworkstation-11`.

- [ ] Add `test_catalog_initial_profiles` asserting 13 initial IDs, `base` has no
  software, `core-apps` has exactly the existing seven applications in existing
  order, `office-standard-v1` excludes the signature suite, and KRFB is opt-in.
  Pin the profile assertions to these exact values:

  ```python
  assert catalog.profile('core-apps')['version'] == 1
  assert [c for c in catalog.profile('core-apps')['components'] if c.startswith('software.')] == [
      'software.browser', 'software.onlyoffice', 'software.nextcloud',
      'software.directum', 'software.cryptopro', 'software.cades', 'software.gosplugin']
  assert 'remote.krfb' not in catalog.profile('core-apps')['components']
  ```
- [ ] Add table-driven `test_catalog_rejects_entire_invalid_document`: duplicate
  YAML key/ID, bool-as-version, unknown key/role/artifact/dependency, cyclic graph,
  unsafe or symlinked role path, unsupported OS/order, missing preflight/verification,
  arbitrary command/expressions and direct protected-role selection all reject
  with `component_catalog_invalid` and expose no executable partial selection.
- [ ] Add `test_add_published_component_without_orchestrator_change`: copy the
  project to a temporary fixture, add approved role/metadata using an existing
  recipe, assert it is visible and ordered after its dependencies. Assert changing
  component/profile version changes catalog SHA and preserves an older snapshot.
- [ ] Run `python -m pytest -q tests/alt_linux/test_component_catalog.py`; expect
  RED for the missing catalog API, then implement strict bounded SafeLoader
  duplicate-key handling and whole-document validation; consult Context7 for
  PyYAML 6.0.2 before changing YAML-dependent behavior.
- [ ] Declare the 13 IDs from the spec, exact protected-domain adapter, artifact
  references and version-1 profiles in the existing YAML. Preserve all package
  checksums/identities and certificate source manifests. Document addition/versioning.
- [ ] Run the same command; expect all tests PASS. Inspect full diff and
  `git diff --check`; commit only these task files as
  `feat(alt-setup): add versioned component catalog`.

### Task 2: Independent detector and verification recipes

**Files:** Create `component_probe.py`, `component_verification.py`,
`test_component_probe.py`, `test_component_verification.py`; extend
`setup_runtime.py` only for source fingerprint and reusable SSH binding.

**Interfaces:** `ComponentProbe(settings, *, runner=None)`;
`observe(machine, user: dict, components: list[dict]) -> dict`;
`VerificationEngine(catalog)`;
`evaluate(evidence: dict, selected: list[str]) -> dict`;
`source_fingerprint(project, control) -> str` remains the existing API.
Observation envelope version 1 includes `observed_at`, actual OS/boot/UUID/hostname,
domain/user identity, package-process state and per-component facts. Public
verification version 2 contains `machine_uuid`, `overall_status`, `components`,
`reboot_required`, `operator_action_required`; never arbitrary probe stdout.

- [ ] Add `test_real_package_identity_drives_status` using a synthetic local
  command runner: exact EVR/epoch/arch/executable -> compliant; absent -> missing;
  wrong version/config -> drifted; unreadable/malformed/timed-out probe -> unknown.
  Assert prior successful run does not change any result.
- [ ] Add `test_probe_only_uses_fixed_read_commands`: no install, join, user-add,
  reboot, shell evaluation or untrusted argument fragment; strict SSH host checking
  and bounded output/timeouts remain enforced. Unknown OS/UUID mismatch blocks.
- [ ] Add `test_home_ownership_and_identity_are_required`: altered NSS user,
  symlink/out-of-home path, local shadow account or wrong ownership blocks; missing
  home is deferred and never created. Functional Directum/signature acceptance
  remains required even when technical packages are verified.
- [ ] Add `test_source_binding_includes_callback_plugins`: changing callback Python
  code changes source SHA; private Vault is excluded. Changing selected host/public
  key invalidates SSH binding without publishing private-key contents or hashes.
- [ ] Run `python -m pytest -q tests/alt_linux/test_component_probe.py tests/alt_linux/test_component_verification.py`;
  expect RED, implement generic package and all initial fixed baseline/domain/
  certificate/user recipes, then repeat; expect PASS. Unknown means unavailable
  actual evidence, not an unimplemented initial recipe. Task 9 deepens negative
  and integrated verification coverage rather than finishing a partial detector.
- [ ] Inspect diff/check and commit `feat(alt-setup): detect component state independently`.

### Task 3: Read-only component plans and catalog CLI

**Files:** Create `component_setup.py`, `test_component_setup.py`,
`test_component_cli.py`; extend `setup_cli.py`; update catalog documentation.

**Interfaces:** `ComponentSetupService(settings, *, setup=None, catalog=None,
probe=None, clock=None)`; `plan(identifier: str, component_id: str) -> dict`;
`verify(identifier: str, component_id: str) -> dict`;
`validate(plan_id: str, sha256: str, *, own_job_id: str | None=None) -> dict`;
`ComponentPlanStore(SetupPlanStore)` with prefix/directory defined above.
Plan payload freezes identities, catalog/component/profile versions, source/SSH
binding, dependency evidence, `action=noop|install|repair|blocked`, budget and
canonical observation projection. Snapshot timestamps are excluded from drift
comparison, but preserved alongside evidence.

- [ ] Add `test_component_plan_noop_missing_drift_unknown`: compliant -> noop,
  missing -> install, drifted -> repair, blocked/unknown dependencies -> blocked;
  assert no Ansible mutation, assignment, lock or job reservation during planning.
  Assert `plan['payload']['action'] == 'noop'` for an exact compliant ONLYOFFICE
  fixture and `plan['payload']['action'] == 'blocked'` for unknown `domain.ready`.
- [ ] Add `test_component_plan_preserves_ad_and_registration_safeguards`: require
  ready registration and existing successful/degraded assignment; selected user
  GUID/SID, computer GUID/SID/OU, trust/SSSD must match fresh observations. Reject
  unjoined/failed/recovery-unresolved machines and direct domain component apply.
- [ ] Add `test_component_plan_drift_sha_ttl`: altered SSH/AD/registration/source/
  catalog/evidence rejects; wrong SHA and expired 30-minute plan reject. Observation
  time alone is not drift. Own reservation is allowed only by matching job/plan.
- [ ] Add parser/dispatch/JSON tests for `setup components list/show`,
  `setup profiles list/show`, `setup component plan/verify`; reject arbitrary
  paths/roles/expressions and abbreviated flags. Inspection needs no AD connection.
- [ ] Run `python -m pytest -q tests/alt_linux/test_component_setup.py tests/alt_linux/test_component_cli.py`;
  expect RED, implement interfaces/CLI, rerun -> PASS. Add version-2 public envelope
  without altering old setup/recovery CLI output.
- [ ] Milestone gate: run `python -m pytest -q tests/alt_linux/test_component_catalog.py tests/alt_linux/test_component_probe.py tests/alt_linux/test_component_verification.py tests/alt_linux/test_component_setup.py tests/alt_linux/test_component_cli.py tests/alt_linux/test_setup_service.py tests/alt_linux/test_setup_plans.py tests/alt_linux/test_setup_runtime.py tests/alt_linux/test_setup_cli.py`;
  require PASS on Linux. No live machine.
- [ ] Inspect diff/check; commit `feat(alt-setup): expose guarded component planning`.

## Milestone 2 — Durable Execution Jobs

### Task 4: Typed durable job records and reservation transactions

**Files:** Create `setup_jobs.py`, `test_setup_jobs.py`; extend `jobs.py`,
`setup_plans.py`, `job_reconcile.py`, `job_retention.py`; extend existing job tests
for mixed v1/v2 history.

**Interfaces:** `SetupJobRepository(settings, *, clock=None)` wraps JobRepository;
`submit(plan: dict, *, operation: str) -> JobRecord`;
`transition(job_id: str, state: str, *, stage: dict | None=None) -> JobRecord`;
`claim(job_id: str, process_identity: dict) -> JobRecord`;
`list(machine_uuid: str | None=None) -> list[JobRecord]`;
`get(job_id: str) -> JobRecord`. `JobRepository.list/get/active_for_machine`
continue to return JobRecord and dispatch validation by schema/kind.

- [ ] Add `test_job_claim_consumes_plan_once`: duplicate submission returns
  existing reservation or rejects before dispatch; completed/failed/unknown plans
  never execute twice. Immutable identity/request/catalog snapshot survives reads.
- [ ] Add `test_reservation_crash_boundaries`: inject termination after each
  durable write (plan claim, identity reservation, request/status publication),
  reconstruct repositories, assert no replay and unresolved partial admission is
  visible. Require atomic publication and parent-directory fsync; fail on symlinks,
  unsafe ancestors, malformed schema and oversized state.
- [ ] Add `test_mixed_history_preserves_v1_reconcile_retention`: old fixtures read
  unchanged, v2 never enters provision result validator; queued/running/waiting/
  review-required claims block incompatible admission and are not garbage-collected.
  Reservation removal cannot erase an original unknown/consumed-plan record.
- [ ] Run `python -m pytest -q tests/alt_linux/test_setup_jobs.py`; expect RED,
  implement adapter and compatible consumer dispatch, rerun -> PASS. Avoid adding
  Setup states to v1 stage validators without discriminating the record first.
- [ ] Run `python -m pytest -q tests/alt_linux/test_jobs.py tests/alt_linux/test_job_reconcile.py tests/alt_linux/test_job_retention.py tests/alt_linux/test_job_stages.py`;
  require PASS; inspect diff/check; commit
  `feat(alt-setup): persist typed setup jobs and claims`.

### Task 5: Safe structured Ansible events and component execution

**Files:** Create `setup_events.py`, `setup_execution.py`, `test_setup_events.py`,
`test_component_execution.py`, callback `deploy/alt-linux/ansible/callback_plugins/alt_setup_events.py`,
playbook `deploy/alt-linux/ansible/playbooks/04-setup-component.yml` and task fragment
`playbooks/tasks/setup_component_execution.yml`; extend `configure.py`, existing
component preflight/critical-phase fragments and `standard_software/tasks/main.yml`.

**Interfaces:** `SetupEventStore(settings)`;
`append(job_id: str, event: dict) -> dict`;
`read(job_id: str, *, after: int=0, limit: int=100) -> dict`;
`ComponentExecutor(settings, catalog)` in `setup_execution.py`;
`run(plan: dict, job: JobRecord) -> dict`. Events declare version 1, sequence,
job/component/version, stage/task identifier, timestamp, type, changed and safe code.
Result declares selected identity/version, component outcome and changed/reboot
evidence; controller independently verifies it in Task 7.

- [ ] Add `test_events_never_serialize_secret_results`: inject sentinel password,
  ticket, private key, no_log output and arbitrary stderr; none appears in events
  or public errors. Invalid sequence/schema/size fails closed; missing last event
  does not imply successful completion.
- [ ] Add `test_component_playbook_executes_only_selected_approved_role`: ONLYOFFICE
  selection cannot invoke domain join or unrelated software. Artifact/license
  preflight precedes any mutation and uses the same catalog-derived selection.
- [ ] Add `test_catalog_drives_legacy_profile_mapping`: legacy seven-component
  order/result remains unchanged; remove duplicate selection/role lists from
  Ansible. Extend existing role-contract tests to assert equivalent semantics,
  rather than retaining obsolete literal list assertions.
- [ ] Run `python -m pytest -q tests/alt_linux/test_setup_events.py tests/alt_linux/test_component_execution.py`;
  expect RED; consult version-matched Context7 for Ansible include_role/callback
  APIs, implement fixed playbook, allowlisted callback/events and structured failure
  reading. Use safe component/stage codes; keep protected logs out of public JSON.
- [ ] Repeat tests -> PASS; run Ansible syntax checks for stage-03 and stage-04 and
  isolated local non-mutating selected/base/core preflight. Assert `changed=0` and
  missing-artifact/blank-license rejection before install. No workstation inventory.
- [ ] Inspect diff/check; commit `feat(alt-setup): execute approved roles with safe events`.

### Task 6: Worker queue and legacy lock compatibility

**Files:** Create `setup_worker.py`, `test_setup_worker.py`,
`test_setup_lock_compatibility.py`, `deploy/alt-linux/control/alt-setup-worker`,
`deploy/alt-linux/systemd/alt-setup-worker.service`; extend `config.py`, `provision.py`,
existing `configure.py` and legacy Setup admission; update `install-control-plane.sh`,
`install-control-plane-lib.sh`, and `controller_readiness.py` for new published files.

**Interfaces:** `SetupWorker(settings, *, engine=None, process_probe=None)`;
`run_once() -> dict`; `reconcile() -> dict`; `main(argv=None) -> int`;
process identity includes controller boot ID, PID/start time and owning service.
`SetupJobRepository` from Task 4 provides FIFO admission sequence and persisted claim.
One mutating controller job runs at a time; never bypass existing lifecycle lock.
Queue admission uses the separate short `state_root/setup-queue.lock` and never
waits on the long execution lifecycle lock. Dispatch acquires lifecycle then queue
lock for the final claim; legacy admission uses that same order when inspecting
V2 reservations. Release queue lock before Ansible. This permits rapid submission
for another machine while execution is active without allowing concurrent mutation.

- [ ] Add `test_worker_fifo_and_same_machine_conflict` and
  `test_different_machine_readonly_is_not_blocked`: duplicate UUID/hostname/AD GUID
  cannot mutate; queue order is deterministic; read-only status/verify works while
  the execution lock is held.
- [ ] Add `test_legacy_worker_outside_lock_blocks_v2`: live legacy provision
  reservation/process prevents V2 dispatch even when lifecycle lock is free;
  concurrent legacy admission sees v2 reservation. Test both admission race orders
  using separate Linux processes, not only sequential mocks.
- [ ] Add `test_worker_restart_never_replays_claim`: queued/unclaimed may run;
  claimed/live stays running; claimed/dead/malformed result ->
  unknown_requires_review. PID reuse, controller reboot and transient systemctl
  observation error never revive a claim. No automatically repeated Ansible/AD call.
  Pin restart assertions to:

  ```python
  assert jobs.get(job_id).state == 'unknown_requires_review'
  assert dispatched_commands == original_dispatched_commands
  assert jobs.get(job_id).request['plan_id'] == original_plan_id
  ```
- [ ] Run `python -m pytest -q tests/alt_linux/test_setup_worker.py tests/alt_linux/test_setup_lock_compatibility.py`;
  expect RED; implement persistent service and conservative reconcile, rerun -> PASS.
  Before dispatch revalidate source/TTL/identity under the retained lifecycle lock.
  Detect unrelated legacy jobs explicitly; avoid nested stage-manager flock calls.
- [ ] Validate packaging with `bash -n` for changed installer scripts and
  `systemd-analyze verify` on the service in an isolated Linux environment. Installation
  assets are prepared only; do not install/start the service on the active controller.
- [ ] Inspect diff/check; commit `feat(alt-setup): add durable serialized setup worker`.

### Task 7: One execution path and compatible full Setup

**Files:** Complete `setup_execution.py`, extend `setup.py`, `setup_cli.py`, `configure.py`,
`component_setup.py`; create `test_setup_execution.py`, `test_setup_detach.py` and
extend existing `test_setup_service.py` and `test_setup_cli.py`.

**Interfaces:** `SetupExecutionEngine(settings, *, setup=None, components=None,
jobs=None, events=None)`; `execute(job_id: str) -> dict`;
`verify_continuation(job_id: str) -> dict` (read-only);
`SetupService.apply(plan_id, confirmed_sha, *, detach=False)`;
`ComponentSetupService.apply(plan_id: str, sha256: str) -> dict` returns v2 job_id.
Factor existing locked Setup body into `SetupService._execute_locked(plan_id, sha)`
without changing protected domain/recovery/assignment behavior. Worker already owns
the lock when calling it; synchronous callers submit/wait on this same path.
Extend `ConfigureRequest.from_mapping(payload, *, expected_uuid=None, catalog=None)`
to validate new profiles against the published catalog supplied by the service;
old base/core requests keep the existing call signature and semantics. Full-Setup
plans freeze catalog/profile versions for new requests. CLI accepts only catalog
profile IDs, including `office-standard-v1` and `office-signature-v1`.

- [ ] Add `test_full_setup_sync_and_detach_share_engine`: old sync result and exit
  contract remain; detach returns queued job_id before Ansible finishes; CLI loss
  does not kill worker. Historical successful-plan reads do not execute again.
  Add `test_full_setup_versioned_profiles`: office-standard installs only its
  declared software, signature selects the signature suite, changed published
  profile invalidates an older plan, and old core/base request history still reads.
- [ ] Add `test_noop_never_invokes_ansible`: fresh healthy component completes via
  verification with changed=false; missing/drifted invokes approved role once;
  fresh dependency/identity drift fails before dispatch; own reservation is accepted
  only when plan/job/machine match.
  Assert `job.state == 'successful'`, the component stage `changed is False` and
  `ansible_calls == []`; never infer noop from the absence of a failure.
- [ ] Add `test_partial_application_retains_safe_stage`: rc=0 with invalid result,
  timeout, SSH loss or worker termination cannot mean success. Known no-change
  preflight failure is failed; ambiguous effects are unknown_requires_review and
  retain component/stage/operator action. Keep legacy error/result shape on sync CLI.
- [ ] Add `test_waiting_reboot_and_first_login`: reboot requirement stores original
  boot; continuation rejects same boot, accepts fresh verified boot. Missing home
  waits; wrong ownership/user never passes; no reboot/home creation/role replay.
  Remaining corrective work requires a newly confirmed plan.
- [ ] Run `python -m pytest -q tests/alt_linux/test_setup_execution.py tests/alt_linux/test_setup_detach.py`;
  expect RED, implement shared dispatch/post-probes/state projection, rerun -> PASS.
- [ ] Milestone gate: run `python -m pytest -q tests/alt_linux/test_setup_jobs.py tests/alt_linux/test_setup_events.py tests/alt_linux/test_component_execution.py tests/alt_linux/test_setup_worker.py tests/alt_linux/test_setup_lock_compatibility.py tests/alt_linux/test_setup_execution.py tests/alt_linux/test_setup_detach.py tests/alt_linux/test_setup_service.py tests/alt_linux/test_jobs.py tests/alt_linux/test_job_reconcile.py tests/alt_linux/test_job_stages.py tests/alt_linux/test_provision_start.py tests/alt_linux/test_provision_preview.py tests/alt_linux/test_machine_lifecycle.py tests/alt_linux/test_setup_recovery_continuation.py`;
  require PASS.
  Inspect diff/check; commit `feat(alt-setup): unify full and component job execution`.

## Milestone 3 — Verification and Acceptance

### Task 8: Package interruption and explicit retries

**Files:** Extend `component_probe.py`, `component_setup.py`, `setup_execution.py`,
`setup_events.py`, package-role task metadata and prejoin stage metadata;
create `test_setup_package_interruption.py`.

**Interfaces:** Task 2 observation adds `package_manager` facts with
`processes_absent`, lock/health status and bounded source/simulation summary.
Task 5 stages include download/transaction/verification and time budget; existing
fresh full-Setup budget remains 21600 seconds, joined-machine budget 5400 seconds.

- [ ] Add `test_package_transaction_interruption_requires_fresh_plan`: running or
  unknown apt/rpm/remote processes block mutation; a dead controller cannot prove
  remote transaction stopped. Fresh package-health observation is mandatory before
  guarded/idempotent retry; original failed/unknown job and plan remain immutable.
- [ ] Add `test_package_source_simulation_and_budget`: approved source and actual
  package identities are recorded; supported native simulation reports planned
  installation/removal; unavailable simulation is explicit unknown, not invented.
  Domain/recovery operations stay non-replayable; timeout identifies exact stage.
- [ ] Run `python -m pytest -q tests/alt_linux/test_setup_package_interruption.py`;
  expect RED, implement fixed read-only process/manager probes and stage metadata,
  rerun -> PASS. No automatic transaction restart or dist-upgrade retry.
- [ ] Inspect diff/check; commit `fix(alt-setup): guard retries after package interruption`.

### Task 9: Complete baseline, certificates and user verification

**Files:** Complete `component_probe.py`, `component_verification.py`,
`component_catalog.py`; extend desktop-shortcut published defaults/tasks for
catalog-selected entries; create `test_setup_initial_components.py`.

**Interfaces:** Task 2 VerificationEngine remains the public entry point. Recipes
derive desired state from existing source templates/defaults/certificate manifests;
no second component or artifact list. `overall_status` is successful only when all
selected technical checks pass and no pending reboot/home/unknown is hidden;
functional acceptance is a separate per-component field.

- [ ] Add parametrized `test_every_initial_component_detects_drift` for all 13 IDs:
  exact compliant facts, missing data, incorrect version/config and malformed facts.
  Assert every initial recipe is implemented, not a permanent unknown placeholder.
- [ ] Add `test_system_domain_gpo_and_certificates_use_current_evidence`: OS/session,
  trust/SSSD/GPO and selected-user GUID/SID are freshly verified; government root
  fingerprints/expiry/store contents and required user imports are checked.
- [ ] Add `test_office_standard_shortcuts_do_not_require_cryptopro`: base/core
  shortcut semantics remain; standard office omits cptools and verifies selected
  launchers/Nextcloud autostart/ownership. Plasma defaults and existing profile
  values are compared without executing apply helpers during verification.
- [ ] Add `test_krfb_optin_home_and_network_checks`: not_selected by default; selected
  path requires restricted TCP-access confirmation, secret availability and verified
  domain home; never expose secret value or infer functional acceptance.
- [ ] Run `python -m pytest -q tests/alt_linux/test_setup_initial_components.py`;
  expect RED, complete recipes and profile-sensitive shortcuts, rerun -> PASS.
  Ansible syntax/preflight checks for changed roles must also PASS.
- [ ] Inspect diff/check; commit `feat(alt-setup): verify baseline and user components`.

### Task 10: Operator CLI, backend schemas and documentation

**Files:** Complete `setup_cli.py`, `test_component_cli.py`; create
`test_setup_jobs_cli.py`, `test_setup_v2_contracts.py`,
`docs/ALT_SETUP_ENGINE_V2.md`, `docs/ALT_SETUP_OPERATOR_GUIDE.md`, and
`docs/verification/ALT_SETUP_ENGINE_V2_ACCEPTANCE_2026-10-13.md`;
update `docs/ALT_COMPONENT_CATALOG.md` and `deploy/alt-linux/README.md`.

**Interfaces:** `setup component apply PLAN_ID --confirm-sha256 SHA`,
`setup jobs list --machine UUID`, `status JOB_ID`, `events JOB_ID`,
`verify-continuation JOB_ID`, existing full `setup apply --detach`, plus Task 3
inspection/plan/verify commands. Keep global `--json`, bounded safe envelopes and
stable v2 schema discriminator. Backend service signatures are Tasks 1-7 APIs.

- [ ] Add `test_operator_flow_only_uses_workstationctl`: catalog -> component plan
  -> SHA-confirmed submission -> status/events -> independent verify -> noop plan;
  waiting/review/error states produce actionable text and safe structured JSON.
- [ ] Add `test_cli_no_arbitrary_execution_inputs_and_legacy_compatibility`: every
  new command rejects unknown/abbreviated overrides; old setup/configure/recovery
  syntax, outputs and exit codes remain verified. Jobs reads do not contact AD/SSH.
- [ ] Add `test_v2_public_contract_has_no_secret_or_unbounded_fields`: fixed envelope
  and component/job/event schemas; source results/logs cannot leak via CLI errors.
- [ ] Run `python -m pytest -q tests/alt_linux/test_component_cli.py tests/alt_linux/test_setup_jobs_cli.py tests/alt_linux/test_setup_v2_contracts.py tests/alt_linux/test_setup_cli.py`;
  expect RED for missing commands, implement CLI/contract projections, rerun -> PASS.
- [ ] Document adding roles/components, immutable profile versions, noop/drift,
  job errors, retry policies, restart/reboot/login procedure and future API reuse.
  Acceptance document separates synthetic/Linux/controller/live evidence and leaves
  deployment/live requirements pending until Task 12 proves them.
- [ ] Inspect diff/check; commit `docs(alt-setup): document operator and backend contracts`.

### Task 11: Review, complete regression and main publication

**Files:** Add `test_setup_v2_end_to_end.py` under `tests/alt_linux`; update
acceptance document with real results and ledger of design rulings.

- [ ] Test integrated controller flow on an isolated Linux environment using
  synthetic AD and subprocess workers: full Setup, replanning, independent component,
  noop, interruption/restart, reboot and first-login states. Assert no live AD calls.
  This is integration evidence, explicitly not live ALT VM acceptance.
- [ ] Run applicable ALT regression and Ansible syntax/preflight. Before code
  verification establish an available isolated Linux runner; Windows skips cannot
  replace these runs. If no runner is available, report that gate without deploying.
- [ ] Perform one independent whole-change review using the approved execution
  method; fix material findings with focused RED -> GREEN. Use GitNexus impact/context
  for final Setup/JobRepository/consumer boundaries and verify dynamic links in source.
- [ ] Fetch `origin/main`, inspect complete diff and `git diff --check`; safely merge
  upstream if needed without rewriting published history. Run one full
  `python -m pytest -q` Linux regression after final changes; require success and
  record skips/warnings accurately. Any repeated full run needs an actual changed
  dependency, failure or unresolved concern.
- [ ] Confirm task-only files, no credentials/runtime state/debug/build artifacts;
  clean tree and exact-SHA CI. Publish verified changes to `main` according to repo
  policy, then remove the staging branch locally/remotely after successful integration.
  Report full SHAs, Conventional Commit messages, included files and exact checks.
  If a PR is used it is draft by default and must be attached to this chat.

### Task 12: Separately authorized deployment and live acceptance

**Files:** Finalize `docs/verification/ALT_SETUP_ENGINE_V2_ACCEPTANCE_2026-10-13.md`.

- [ ] Prepare a concrete guarded deployment manifest/commands, exact published SHA,
  backup/rollback plan and readiness checks. Obtain the task-required separate
  operator deployment authorization before applying to the active controller.
- [ ] Obtain an explicitly selected/authorized ALT target. Run only authorized
  read-only catalog/detect/plan/history/verify first; prove there is no domain join,
  unnecessary installation or assignment/recovery rewrite.
- [ ] Present the exact component plan/SHA and required target change for separate
  operator confirmation. Only after confirmation apply that plan through CLI,
  inspect structured events/job, independently verify and replan -> noop.
- [ ] On an authorized disposable ALT VM complete full Setup, interruption/status
  recovery, permitted reboot and actual domain first login. Use only dedicated or
  synthetic AD error objects; no production conflicts, OS reinstall or AD account
  reset to demonstrate the engine. Preserve actual signing/document-opening status.
- [ ] Record source/deployed SHA, authorized target, exact actual commands/results
  and residual limitations. Commit/publish sanitized acceptance documentation after
  verifying it. No failed/missing live gate may be relabeled as complete.

## Plan self-review and execution handoff

Spec coverage maps to Tasks 1-3 (catalog/profiles/detect/plans), 4-7 (durable
execution/locks/events/compatibility), 8-10 (errors/retry/verification/operator
contracts), 11 (review/regression/publication), and 12 (guarded deployment/live
acceptance). All five Review Focus conditions have explicit owning tests.
Task 12 approvals cannot be inferred from design or plan approval.

After plan approval, execute task-by-task and retain concise test/ruling evidence.
Recommended method is inline because these tasks share identity/plan/job interfaces;
one independent review before publication checks the complete integration.
