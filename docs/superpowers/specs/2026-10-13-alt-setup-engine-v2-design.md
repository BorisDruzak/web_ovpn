# ALT Setup Engine V2 — approved design

Date: 2026-10-13. Status: user-approved design; implementation and acceptance pending.
Repository baseline: `3935bad3ab728c886f8f7dca2f93e5baa3ed16f9` on `main`.

## Purpose and boundaries

Implement the operator-managed lifecycle requested in ALT Setup Engine V2:
`CLI -> Setup Service -> Plan -> Job Engine -> Component Catalog -> Ansible -> Verification`.
An administrator must be able to inspect, plan, apply and independently verify
an approved component without invoking Ansible directly or depending on Codex.

Preserve existing `setup plan/apply/status/verify`, `base`, `core-apps`, selected
existing AD users, approved OUs, SHA-256 confirmation, 30-minute plan TTL,
GUID/SID checks, assignments and immutable recovery evidence. No AD user creation,
ISO/PXE work, web pages, infrastructure changes or fleet rollout. Keep working
domain join, SSSD, Kerberos and first-join compatibility logic intact.

Git publication to `main` is authorized by the task. Active-controller deployment
requires separate operator authorization and the guarded deployment procedure.
Live acceptance requires an explicitly selected and authorized ALT target;
installation/correction additionally requires separate operator confirmation.

## Verified baseline and consequences

Local HEAD, fetched `origin/main` and the GitNexus `web_ovpn` index all match the
baseline. The initial working tree is clean. GitNexus context and upstream impact
were checked for `SetupService` and `JobRepository`; source inspection verifies
dynamic relationships in addition to the graph.

* `SetupService._snapshot` already validates registration, AD employee, OU,
  trust/computer identity, prerequisites and the existing assignment. `apply`
  holds the lifecycle lock across ConfigurePlanner execution and post-verification.
* `SetupPlanStore` already provides immutable SHA-addressed plans, TTL and private
  JSON I/O. New component plans reuse that format through a distinct prefix and
  directory; existing plans and results remain readable.
* `JobRepository` is consumed by provision, registration, machine lifecycle,
  readiness, retention and reconcile. Its current active states and stage validator
  assume legacy provision records; adding Setup states blindly would break them.
* Legacy provision admits jobs under the lifecycle lock and runs a detached worker.
  Setup, ConfigurePlanner, reconcile and numerous recovery operations also use that
  lock. Per-machine locks alone cannot prove safe controller-wide parallel writes.
  In particular, `worker.run_job` releases the lock between stage updates and runs
  Ansible outside it. A Setup execution lock must be combined with explicit checks
  of admitted legacy jobs; the lock by itself does not exclude a legacy process.
* Software selection is repeated in component preflight and `standard_software`.
  `software_catalog.yml` already holds approved package sources and identities.
* Software roles verify pinned payloads and installed packages. They are reusable,
  but invoking them again can copy artifacts and run apt even on a healthy machine.
  A fresh detector must decide `noop` before execution.
* The existing read-only Setup SSH probe proves domain identity and home presence,
  but does not independently verify installed software or current GPO state.
* ConfigurePlanner currently uses log labels for some timeout phases and generic
  errors for nonzero exits. V2 needs safe structured events rather than parsing
  arbitrary output as its primary evidence.
* The ALT pytest directory requires POSIX and is skipped on Windows. Verification
  must use an isolated Linux runner; a Windows skip is not a passing ALT regression.
  Local WSL is unavailable. The existing GitHub Actions Linux workflow is available;
  [baseline run `38439218745`](https://github.com/BorisDruzak/web_ovpn/actions/runs/38439218745)
  completed successfully for the exact baseline SHA: focused tests `555 passed`;
  full `python -m pytest -q` regression `5346 passed, 89 skipped, 3315 warnings`.
  That run is baseline evidence only and contains no V2 implementation or acceptance.

## Approach selection

Recommended: incrementally extend the current service and file-based job machinery.
Use one published catalog and one execution entry point, with adapters for legacy
full Setup and component-only operations. Reuse strict SSH, Vault, AD and recovery
boundaries. Version Setup records explicitly and leave provision v1 data intact.

An independent second Setup pipeline would reduce initial coupling but duplicate
identity checks, execution and recovery semantics; it is rejected. Replacing the
controller with a database/broker would introduce migration and operating costs
without an established need; it is also rejected.

## Catalog V1

Extend the published `ansible/group_vars/software_catalog.yml` with a versioned
`setup_catalog` section containing components and profiles. Preserve the existing
artifact entries as package metadata, referenced by component `artifact_key`.
Python and Ansible consume the same declarations; remove duplicate software
profile lists and role maps when integrating the catalog. Verification recipes
reference existing certificate manifests, role defaults and templates rather
than copying their desired contents into another independent registry.

Each component declares exactly these fields: `id`, positive integer `version`,
`name`, `category`, `supported_os`, `dependencies`, `execution`, `preflight` and
`verification`. Execution declares an approved role (or protected critical-stage
adapter), operation type, system/user scope, domain/home requirements, reboot
requirement and `read_only|idempotent|guarded|non_replayable` retry policy.
Verification declares a supported recipe and functional-acceptance requirement.
No scripts, CLI-provided role names, arbitrary paths or Ansible expressions.

Validate the entire published document before exposing any executable selection:
strict keys/types, duplicate YAML keys and component IDs, role existence and safe
paths, artifact references, dependencies, cycles, profile order, OS compatibility,
mandatory preflight/verification and execution parameter allowlists. Unknown
recipes fail closed. Role membership comes from the published Git package, never
from runtime YAML upload. A new approved role and its declarative recipes are a
normal Git/deployment change; adding a component does not change the orchestrator.
Reject a component that directly maps to domain-join, AD-account, recovery or
legacy provisioning roles even if those roles exist in the published bundle.
Their only valid catalog representation is the protected critical-stage adapter.

Initial IDs and existing integrations:

| ID | Published integration | Execution boundary |
| --- | --- | --- |
| `system.base` | `workstation_base` | Guarded system baseline |
| `domain.ready` | Existing domain/GPO critical stage | Protected full-Setup adapter; component apply forbidden |
| `desktop.plasma` | `plasma_baseline` | System defaults and deferred existing-home work |
| `certificates.government` | `government_ca` | System roots plus user-store verification |
| `desktop.shortcuts` | `desktop_shortcuts` | Selected applications and user autostart |
| `software.browser` | `software_browser` | Approved software |
| `software.onlyoffice` | `software_onlyoffice` | Approved software |
| `software.nextcloud` | `software_nextcloud_desktop` | Approved software |
| `software.directum` | `software_directum` | Technical install plus functional acceptance |
| `software.cryptopro` | `software_cryptopro` | License/payload prerequisites; signing acceptance separate |
| `software.cades` | `software_cryptopro_cades` | Depends on CryptoPro |
| `software.gosplugin` | `software_gosuslugi_plugin` | Approved payload; signing acceptance separate |
| `remote.krfb` | `remote_access_krfb` | Explicit opt-in, restricted-access confirmation, existing home |

`base` keeps the current system/domain baseline. `core-apps` keeps browser,
ONLYOFFICE, Nextcloud, Directum, CryptoPro, CAdES and ГосПлагин plus the current
system/desktop/certificate behavior. `office-standard-v1` omits the signature
suite; `office-signature-v1` includes it. KRFB is never implicitly selected.
Profiles declare version, ordered required/optional components and confirmation
policy. A semantic profile change requires a new version; historical records
retain the complete selected profile and catalog snapshot.

## Detect, planning and independent verification

Implement fixed read-only probes selected by validated verification recipes.
Probe real OS, registered UUID/hostname, boot ID, AD/trust/SSSD/GPO, selected
employee identity, package EVR/architecture/epoch, required executable/service,
managed configuration, certificate stores, home ownership, shortcuts and autostart.
Never evaluate catalog strings as shell or Python code. Restrict user-home reads
to the verified SSSD identity and safe paths. Return bounded structured evidence;
missing tools or malformed evidence produce `unknown`, not compliance.

Per-component observed states: `compliant|missing|drifted|blocked|unknown`;
unselected components are `not_selected`. Compare exact package identities when
pinned; repository packages report actual versions and their declared supported
constraints. A complete healthy component plans `noop`; missing/drifted components
plan only their approved installation/repair. Unsatisfied dependencies block
individual-component mutation rather than silently invoking domain join.

Component-only plans derive user/OU from an existing verified Setup assignment.
They retain machine registration, live AD GUID/SID and trust identity, strict SSH
binding, catalog/profile versions, published-source fingerprint, dependencies,
target evidence and execution budget. A new machine still uses full Setup first.
All required dependencies must be freshly compliant before component application.
Changed identity, catalog, source, SSH binding or relevant observed state requires
a fresh plan and SHA confirmation. Preserve the 30-minute TTL and single-use plan
reservation; completed plans cannot execute again.
Include published event callback/plugin code in the source fingerprint explicitly:
the current fingerprint does not include Python callback files outside roles.
Bind SSH to the selected target's known-host/public-key identity without exposing
private-key bytes or their hashes in public plans or evidence.

Do not include observation timestamps in drift equality. Report timestamps beside
the canonical observation projection. Mutable job/process state is validated as an
admission condition, not mistakenly compared to its own queued reservation.

Verify after each application through a fresh read-only probe independently of
Ansible's return code. Report `installed_verified`,
`functional_verification_required` and `accepted` distinctly. Acceptance requires
separate functional evidence; package presence never proves Directum document
opening or token signing. Independent verify never runs an installation role.

## Durable jobs and locking

Add schema-discriminated Setup job records to the existing file-repository model,
with a typed Setup adapter and explicit legacy provision compatibility. Reuse
private atomic state I/O; store immutable request/plan, job state, per-component
stages, safe events and protected logs. Do not rewrite provision history or its
stage vocabulary. Teach active-job queries and lifecycle admission about Setup
reservations without interpreting them as provision requests.
Make durable publication crash-consistent: fsync file content, atomically publish
the record and fsync its parent directory. Interrupted multi-record admission
must remain detectable and block execution until reconciled, without losing or
reviving a consumed plan. Existing retention must not delete Setup records in
waiting or review-required states, or their reservation/evidence links.

States: `queued`, `preflight`, `running`, `waiting_reboot`, `waiting_first_login`,
`verifying`, `successful`, `degraded`, `failed`, `unknown_requires_review`.
Stages retain job/plan/machine/component/version, start/end, changed evidence,
verification, safe error and operator action. `changed` remains unknown when
effects cannot be established; never invent a false unchanged result.

Use a persistent systemd-managed Setup worker with a deterministic queue ordered
by admitted sequence. Both component apply and full `setup apply --detach` submit
to it. Synchronous full `setup apply` uses the same execution function and waits
for the result, retaining legacy output and exit behavior. Preserve recovery
continuation validation and never let generic submission execute recovery plans.

At admission use short controller-state critical sections and durable reservations
for UUID, hostname and AD computer GUID. At execution retain the existing lifecycle
lock and a per-machine lock. Initially allow one controller mutation at a time,
including compatibility with admitted legacy provision jobs. Holding the legacy
execution lock remains necessary until all consumers permit a narrower contract.
Under that lock, the V2 worker must refuse dispatch while any conflicting legacy
job is queued/running or has ambiguous live-process evidence. Legacy provision
admission must check V2 reservations under the same lock. Preserve its existing
stage-update lock contract to avoid nested flock deadlocks; do not wrap its whole
worker in the lock while stage updates reacquire it.
New read-only list/status/detect/verify operations avoid that execution lock.
Document any remaining legacy read path that still takes the lock.

Before dispatch, persist a non-replayable claim and exact process/unit identity.
On restart inspect unit/PID/start-time identity and protected event/result files.
Never replay a claimed step. A live process remains running; proven pre-dispatch
work can remain queued; missing, contradictory or ambiguous execution evidence
becomes `unknown_requires_review`. Worker loss cannot automatically authorize a
package transaction, domain join or recovery. New retry requires fresh evidence,
a new immutable plan and operator confirmation appropriate to its retry policy.

For `waiting_reboot`, store pre-change boot identity and verify a changed boot on
explicit operator continuation; never reboot automatically. For
`waiting_first_login`, verify selected user/home/ownership without creating a
home. Read-only continuation verification records readiness; any remaining
mutation requires a newly confirmed component plan.

## Structured execution and errors

A fixed component playbook invokes only catalog-approved roles. It reuses existing
artifact/license preflight and initializes the role-compatible result structure.
Its validated request contains no executable operator input. Protected domain
critical execution remains the existing playbook and first-join adapter.

Add an Ansible event adapter with an allowlisted envelope: sequence, job/stage,
component/version, safe task identifier, event type, changed, safe code and time.
Never serialize arbitrary result dictionaries, command arguments, stdout/stderr,
Vault contents, tickets or credentials. Secret tasks yield safe identifiers only.
Events identify the component/stage even if Ansible or SSH stops before final
result publication. Protected logs remain separate from public CLI JSON.

Package evidence records approved source, read-only native simulation where
supported, download/transaction boundaries, timeout and post-error state. A large
prejoin dist-upgrade retains the current fresh-install budget. After interruption,
probe package-manager/process state before a new plan can permit a transaction.
No result/invalid result/timeout/transport loss is conservatively unknown whenever
effects are ambiguous. Known preflight rejection can be failed with no mutation.

## CLI and backend contracts

Add `setup components list/show`, `setup profiles list/show`,
`setup component plan/apply/verify`, `setup jobs list/status/events`,
`setup jobs verify-continuation`, and `setup apply --detach`.
Reuse existing global `--json` conventions. V2 responses declare
`schema_version: 2` and operation discriminator; legacy commands preserve their
existing envelope. Components/profiles/events and public verification use
bounded, secret-free projections. No FastAPI routes or web UI are added.

Service interfaces separate catalog inspection, component planning,
SHA-confirmed submission, job reads and independent verification. Future HTTP
handlers can call these interfaces without owning a worker or running Ansible.

## Milestones and verification

1. **Catalog:** strict validator, immutable profiles, independent detect/verify,
   read-only component planning and inspection CLI. Gate: real evidence controls
   planning; legacy full Setup behavior is unchanged. Tests cover all invalid
   catalog/dependency/OS cases, noop/drift/unknown and identity/SHA/TTL drift.
2. **Jobs:** typed file records, durable worker, shared execution entry point,
   component-only application, reservations/locks, structured safe events and
   precise failures. Gate: duplicates, conflicting identities, sequential queue,
   worker restart, SSH interruption, timeout, partial effects, invalid results,
   missing artifacts/secrets and consumed-plan replay are tested.
3. **Verification and acceptance:** remaining system/user recipes, continuation
   checks, legacy CLI regression, operator guide, future backend contracts and
   live acceptance on the separately authorized target. Gate: an operator can
   apply and verify the selected component through workstationctl alone.

Use focused RED -> GREEN and applicable Linux regressions per milestone; run one
full regression before publication. Run Ansible syntax and isolated non-mutating
preflight checks with the actual supported Ansible version. Consult Context7 for
version-matched external APIs before their implementation; PyYAML is pinned at
`6.0.2`. Tests must not create artificial production AD conflicts or contact a
workstation implicitly. Isolated runner code transfer is not active deployment.

Produce `docs/ALT_SETUP_ENGINE_V2.md`, `docs/ALT_COMPONENT_CATALOG.md`,
`docs/ALT_SETUP_OPERATOR_GUIDE.md` and
`docs/verification/ALT_SETUP_ENGINE_V2_ACCEPTANCE_2026-10-13.md`.
Record exact source/deployed SHAs, commands/results and scope for live acceptance.
Read-only and mutating acceptance are separate approvals and separate evidence.
Leave deployment/live criteria explicitly pending until actually demonstrated.

## Review decision

The user approved this written design on 2026-10-13. Suggested
execution method: inline in this chat, with milestone test gates and one independent
review before publication. Catalog and execution share identity/plan interfaces,
so per-task delegation would repeatedly reload the same coupled safeguards.
No product code, installation or live operation is authorized by this document
itself; the original task and subsequent operator approvals govern those actions.
