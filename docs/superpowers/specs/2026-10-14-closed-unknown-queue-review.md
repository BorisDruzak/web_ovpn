# One-job queue admission after a closed UNKNOWN

The current serialized worker blocks every queued machine while an unreviewed
UNKNOWN or unresolved legacy reservation remains. A stopped full Setup with
intact failed protected results can therefore prevent acceptance on a different
disposable machine even after the controller source has been repaired.

The operator approved the bounded scope in the local queue-unblock proposal:
permit one different machine after fresh positive closure checks, preserve the
original UNKNOWN and reservations, and retain sequential execution. This design
implements that scope using the existing protected review and queue mechanisms.

## Admission contract

Introduce a separate `queued_other_machine_only` review purpose. It authorizes
one specific already-admitted, unclaimed queued job, identified by its job ID,
request hash, queued status hash, plan SHA and complete machine identities.
It does not authorize the original machine, recover its Setup, or release its
identity reservations. A `controller_maintenance_only` receipt never satisfies
this contract, and a queue receipt never satisfies maintenance admission.

The original blocker must be one closed UNKNOWN full job with the intact failed
full/configure results and exactly its two unresolved nested legacy reservations.
Reuse the native maintenance validator's positive read-only identity, AD,
trust, SSSD, package-manager, remote-process and safe user-runtime checks.
Missing, unknown, changed or unsafe evidence denies admission. Other unresolved
jobs, executing provision jobs or unexplained reservations cannot be excluded.

The candidate must differ from the original in UUID and hostname, and cannot
share an existing AD computer GUID. Bind the candidate's current published source
fingerprint and protected job records. The existing execution engine still runs
its full source/SSH/AD GUID/SID/registration/SHA/TTL preflight before target writes.

Review plans have the existing 30-minute protected-plan TTL. Confirmation binds
an immutable receipt valid for at most six hours, matching the existing review
window. Dispatch additionally requires the candidate Setup plan to be unexpired.
There is no TTL extension, old-plan replay, force flag or implicit confirmation.

## Worker and locking

Select the oldest queued job using existing FIFO ordering. Retain the global
lifecycle lock, existing queue lock ordering and one serialized worker. When
ordinary admission is blocked, read only the receipt for that exact candidate.
Revalidate the original closed history and fresh evidence under the lifecycle
lock immediately before claim; exclude only the proven original job and its two
leases from the global blocker check. Claim and execute through the existing
engine. Do not skip an unapproved earlier queued job to execute a later one.

A receipt refers to the candidate's queued status, so it cannot be used again
after claim, cancellation, restart reconciliation or a terminal outcome. No
worker restart resumes a consumed operation. The original UNKNOWN, claims,
assignments and reservation bytes remain unchanged throughout admission.

## CLI and persistence

Add these operator commands without changing existing commands:

```text
workstationctl setup jobs queue-review-plan UNKNOWN_JOB --candidate QUEUED_JOB
workstationctl setup jobs queue-review-confirm PLAN_ID --confirm-sha256 SHA
workstationctl setup jobs cancel QUEUED_JOB --confirm-plan-sha256 SHA
```

Queue plans use prefix `setup-queue-review-`, operation
`queued_other_machine_review_plan`, private service-owned 0700 directories and
0600 content-addressed files. A private candidate-keyed receipt points to its
confirmed review SHA. CLI JSON returns only safe identifiers, purpose and dates;
private user/OU/identity snapshots remain protected.

Retained queue plans and receipts are structurally validated and included in
backup history comparison even after expiration or candidate completion. Do not
import restored runtime code. Share only trusted public validator modules using
the existing installer/bridge; preserve private backup/Vault/key permissions.

Cancellation is limited to an exact unclaimed queued job. Under the lifecycle
lock, check admission integrity and confirmed plan SHA, acquire the existing
single-use claim, persist a zero-target-change cancellation result, and use the
existing preflight-to-failed transition with stage
`operator_cancelled_before_execution`. Never cancel an executing/waiting/UNKNOWN
job through this command. Keep its plan claim and complete history. A repeated
request must return the identical cancellation result without another claim.

## Verification and live acceptance

Test no-review and wrong-purpose denial; candidate identity collisions; exact
request/status/source/history binding; TTL; unsafe files; fresh process/package
uncertainty; unexplained reservations; FIFO and serialization; immutable original
records; single-use dispatch; cancellation guards and interruption evidence;
CLI routing; public-module installation; backup/restore history preservation.

Run targeted RED/GREEN tests, applicable ALT regressions and one full regression
before publication. Obtain a whole-branch review. Publish completed verified code
to main, then use the native guarded deployment with a fresh verified/rehearsed
backup and applicable operator confirmation.

The earlier unstarted queued attempt was cancelled through existing typed APIs;
it is not live Setup acceptance. After deployment, create a fresh plan and job
for the approved disposable target, confirm the exact queue review, and perform
full Setup plus component/verify/noop/interruption/reboot/real-login acceptance.
Never reset the old computer account, fabricate a user home or change network
infrastructure to obtain passing evidence.
