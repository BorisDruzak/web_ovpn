# ALT Setup Engine V2

The controller follows `CLI -> SetupService -> immutable plan -> file-backed job
-> systemd worker -> approved Ansible roles -> independent verification`.
See [catalog maintenance](ALT_COMPONENT_CATALOG.md) and the
[operator guide](ALT_SETUP_OPERATOR_GUIDE.md).

## Catalog and plans

The single published declaration is
`deploy/alt-linux/ansible/group_vars/software_catalog.yml`. It defines thirteen
components, approved artifacts, dependency ordering and role mappings. `base`
and `core-apps` retain their legacy meanings; `office-standard-v1` and
`office-signature-v1` add versioned office selections. Invalid catalog items
reject the entire selection. Runtime uploads, arbitrary roles/playbooks, shell
commands and Ansible expressions are not operator inputs.

`ComponentSetupService` reuses machine registration, existing Setup assignments,
AD Directory, approved OU policy, verified computer/domain identity and SSH
bindings. The fixed collector independently reads RPM EVR/epoch/architecture,
executables/services, baseline configuration, trust stores and user files.
Detect/plan/verify execute no apply roles and create no user home.

Plans freeze selected versions/profile, catalog SHA, actual published source
fingerprint, registration, employee GUID/SID, computer identity, SSH public keys
and observed facts. Exact SHA confirmation and a 30-minute TTL remain mandatory.
Admission and worker preflight revalidate these facts. Drift requires a new plan.
Compliant components produce `noop`: no Ansible, installation or Vault access.
The source fingerprint is distinct from the Git commit SHA recorded at deployment.
Historical frozen profiles are parsed as retained evidence, not a current role map.

## Durable jobs and locking

`SetupJobRepository` shares the original JobRepository filesystem. Provision V1
records retain their schema. Typed Setup records use schema 2, `kind: setup`,
operation `component` or `full_setup`, and a monotonic FIFO admission sequence.
Single-use claims, identity reservations, immutable requests and atomic status
files use private permissions and fsync. Partial admission blocks review; it
never revives a plan.

`alt-setup-worker.service` executes as the controller service account. Component
submission and full `setup apply --detach` return durable job IDs. Closing CLI,
SSH or web processes does not stop execution. The compatible synchronous full
apply waits for that same job and returns its legacy run envelope. Old unversioned
plans preserve their original protected path.

States: `queued`, `preflight`, `running`, `waiting_reboot`, `waiting_first_login`,
`verifying`, `successful`, `degraded`, `failed`, `unknown_requires_review`. Claims
record PID, process start ticks and boot ID. A missing/ambiguous process becomes
UNKNOWN after restart; the worker never replays it. Ansible result, completion
journal and independent verification must agree; return code zero is insufficient.

Mutation is serialized until every legacy lifecycle consumer supports safe
parallelism. UUID, hostname and AD computer GUID reservations also protect
waiting/review states. Read-only operations avoid the long lifecycle lock.
Lock order is lifecycle then short queue lock; submission takes only queue.
Legacy Setup/Configure leases retain unresolved execution evidence and participate
in the same admission. Safe events expose component/version, stage, opaque task
ID, timestamp, changed flag and allowlisted code. Raw task names, arguments,
stdout/stderr, LDAP DNs and result objects are excluded from public events.

## Verification and retries

Fresh facts are compared with published desired state. Checks include exact
packages and executable/service state, system/session/Plasma baseline, domain/GPO,
government certificate fingerprints/expiry/stores/import helpers, and selected
shortcut/autostart bytes and ownership. KRFB is opt-in and requires an existing
safe home, secret readiness and explicit restricted-network assertion. The
assertion does not change firewall rules.

Read-only package checks inspect processes, existing locks, RPM database and APT
dependencies/simulation. ALT APT simulations run unprivileged to avoid cache
writes. Unavailable simulation stays explicit. A controller timeout does not
prove remote APT/RPM or Ansible stopped. Interrupted jobs preserve the originating
stage and actual post-error package facts, including after rescue tasks.

`--after-job` creates a new confirmed plan for the same idempotent component after
fresh identity and package/remote-process health checks. A selected idempotent
component may also review an UNKNOWN full job with intact completed protected
Setup evidence. Immutable links name the successor; old claims/plans/jobs stay
unchanged. Domain/recovery cannot use this component path. Original prejoin and
terminal recovery gates remain mandatory for a full successor.

Continuation only re-observes. Reboot clears through an actual changed boot ID;
first login needs the selected employee's real safe home. Continuation never
reboots, creates homes, applies roles or performs domain join. Missing user work
after login needs a new permitted component plan.

`installed_verified` means technical installation. User workflows retain
`functional_verification_required`. Explicit `setup component accept` records
operator attestation against a fresh compliant plan. Fresh component verify
returns `accepted` only while its identity/source/component facts match the
receipt. Job results retain the state observed at completion; later attestation
does not rewrite them.

## Backup / restore

OR-3P3 captures the new worker helper/unit, stops the worker for maintenance and
resumes its recorded state. The worker requires the existing backup guard. V1
four-unit manifests remain readable; pre-V2 restore removes the newer helper/unit
rather than leaving a daemon attached to older runtime code.

A root-protected stable admission flock beside controller state is outside
restored generations. Backup/restore holds it exclusively; queue callers fail
promptly with `setup_controller_maintenance`, even while holding lifecycle. No
waiting admission retains the old generation's lock inode. Read-only archive
inspection does not acquire this maintenance gate.

Rehearsal validates mixed V1/V2 records, safe events, claims/reservations and review
links using trusted installed validators, never restored code. Unresolved jobs
and partial admissions block maintenance. Restore rejects a generation whose
retained execution ledger or functional receipts differ from current history,
before production paths move. Use a current matching backup: old restore must
not erase consumed claims or revive operations. This is an intentional limit.

Scoped maintenance revalidates native component-predecessor review links just as
ordinary backup admission does. Reviewed historical UNKNOWN does not become an
extra maintenance blocker after its successor finishes. Active successors and
unreviewed UNKNOWN remain blockers, and the explicit closed-full maintenance
receipt is still required. Neither path rewrites a predecessor or authorizes
workstation replay.

Idle lifecycle-lock polling leaves an already-private state directory and lock
file unchanged; redundant chmod calls must not create false backup inventory
drift before the waiter owns the lock. Missing paths and incorrect modes still
receive the existing `0700`/`0600` permissions. Backup source comparison remains
strict for actual data or metadata changes.

Protected maintenance/queue review waits up to five monotonic seconds for a brief
lifecycle holder inside the same request. After acquisition it revalidates the
named inode, owner, mode and directory ancestry before observing any evidence.
History, active work, identity, health and SHA/TTL are then checked fresh under
that lock. A persistent holder or replaced/unsafe lock denies; this handoff does
not rerun a backup, deployment, job or workstation operation.

The existing protected recovery flow has one narrow snapshot exception:
`create-recovery` accepts only private SHA-keyed admission for an exact reserved
attempt, fresh sealed credential/intent, unexpired recovery plan, original closed
full job and its exact correlated legacy reservations. Other unresolved work
stays blocked. The snapshot neither resolves UNKNOWN nor authorizes a target/AD
writer; original recovery approval and terminal gates still apply.

## Future backend contract

No HTTP route or UI is added. A future authenticated/authorized API can reuse:

| Service | Operations |
| --- | --- |
| `ComponentCatalog` | load, component/profile lookup, ordered selection |
| `ComponentSetupService` | plan, apply, verify, explicit functional accept |
| `SetupService` | protected full plan/apply and current deep verification |
| `SetupJobsService` | paged list, status, safe events, read-only continuation |
| `SetupJobsService.cancel` | SHA-confirmed cancellation of an unclaimed queued job |
| `QueueAdmissionReview` | one different queued candidate after fresh closed-UNKNOWN proof |

Job and component V2 envelopes use integer `schema_version: 2` and a fixed
`operation`. Protected maintenance/queue review envelopes use `schema_version: 1`.
Job pages contain at most 100 jobs, event pages at most 1000 events. Job reads
use bounded projections and construct no AD/SSH service. Protected requests,
raw results and logs are not public response fields. Only explicit workstation
verification/continuation contacts targets. Transport authentication and operator
authorization remain responsibilities of the future API.

Main publication, controller deployment and live acceptance are separate gates.
See the [acceptance ledger](verification/ALT_SETUP_ENGINE_V2_ACCEPTANCE_2026-10-13.md).

## One-job queue review after a closed UNKNOWN

Ordinary dispatch still blocks unresolved legacy execution or UNKNOWN. A separate
`queued_other_machine_only` review can exclude one closed full UNKNOWN and exactly
its two correlated failed legacy reservations for one different queued candidate.
It preserves their records and never permits recovery or join replay on the old
machine. UUID, hostname and an existing AD computer GUID cannot collide.

The review binds candidate request/initial queued status/plan/source hashes and
fresh native closure, package/process and AD/SSH identity evidence. Worker checks
it under the existing lifecycle lock before the single-use claim, retains FIFO,
and executes through the normal full preflight and engine. Other active work or
unexplained leases remain blocked. Parallel target mutation is not enabled.

Private queue plans, reviews and candidate admissions are included in retained
backup history. Expired or consumed evidence remains valid history but gives no
execution permission. Maintenance and queue review purposes are separate.

Queued cancellation consumes the existing single-use worker claim, records zero
target changes and transitions preflight to failed with
`operator_cancelled_before_execution`. Interrupted cancellation remains ambiguous
and cannot be replayed. Cancellation never applies to an executing or UNKNOWN job.
