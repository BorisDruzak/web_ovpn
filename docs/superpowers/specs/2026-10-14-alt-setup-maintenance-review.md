# Explicit maintenance review of a stopped Setup UNKNOWN

The operator approved the written local maintenance-review proposal on
2026-10-14 and delegated implementation in this chat. This follows the existing
ALT Setup V2 task and preserves its target-mutation and history constraints.

## Outcome and boundary

A stopped, partially applied full Setup can block backup and controller updates
through its immutable UNKNOWN job and nested legacy reservations. Provide an
explicit reviewed exception for controller maintenance. Keep ordinary job
admission, worker replay, first join/recovery, assignments and target acceptance
unchanged. This review performs no target writes and never converts UNKNOWN to
success or deletes/rewrites claims, results, events or reservations.

## Existing primitives and canonical implementation

Reuse protected SHA-addressed 30-minute plans, service-owned 0700/0600 stores,
native job/event/reservation validators, lifecycle locking, registered machine
and selected AD identity checks, strict SSH and the read-only component collector.
The canonical review validator lives in the backup package, whose installer is
already the deployment prerequisite. The controller CLI imports that same
implementation from a trusted root-owned installed or published sibling backup
directory; do not maintain two independent receipt validators.

The worker PID identifies the durable daemon and can remain alive after the
failed run. Require a validated finished execution record and prove execution
quiescence through the existing lifecycle flock. The checker may reuse a lock
already held by its own native maintenance process; detect that fact through
the actual Linux lock record, not an operator-supplied bypass flag. Otherwise
take a nonblocking lock and fail safely if busy. Never chmod or edit history
during validation. Native backup still stops services and takes its normal locks.

## Protected envelope and receipt

Commands: `setup jobs maintenance-plan JOB_ID` and
`setup jobs maintenance-confirm PLAN_ID --confirm-sha256 SHA`.

The plan binds one claimed full-Setup UNKNOWN, its exact original plan and
request/status/execution/event bytes, the exact failed legacy run/configure
result, and only the two corresponding unresolved nested legacy reservations.
Reject any unrelated active/unresolved job or reservation. Validate complete
native schemas and cross-references; missing/partial evidence blocks review.

Fresh read-only evidence must prove:

- registered UUID/hostname/address and strict SSH identity;
- original selected enabled AD user GUID/SID and approved OU identity;
- current computer GUID/SID/OU matching Samba trust on the same machine;
- current boot identity and safe user identity;
- no package or remote execution, clear locks, readable database and healthy
  dependencies.

Admission and confirmation recheck the complete immutable snapshot and fresh
identity/health evidence under the lifecycle lock. Relevant drift invalidates
the plan. Store detailed identity/hashes privately; public CLI responses contain
only safe IDs, SHA/expiry, scope and counts. No credentials are exported.

Confirmation within the 30-minute plan TTL creates one additive immutable
service-owned receipt. Reconfirmation cannot extend its deadline. Its explicitly
planned maintenance execution budget is 21600 seconds, matching existing full
Setup's six-hour budget; validity is checked at every maintenance admission.
This separates plan confirmation TTL from execution duration. The receipt binds
the validator code digest and original evidence, and cannot authorize a different
job, source interpretation or purpose.

## Native consumers

Add optional `--maintenance-review SHA` to the native backup CLI and guarded
installer. Propagate it through BackupSettings, repository/quiescence and
readiness without changing default behavior. Reject malformed or conflicting
review/recovery scopes. Exclude only the exact checked job/reservation IDs for
backup and guarded controller deployment; other jobs, registrations, transient
processes and existing secret/capacity/rollback guards still block.

An explicit maintenance readiness response identifies its maintenance-only
scope. Ordinary readiness, mutation admission and worker behavior retain their
unresolved-UNKNOWN checks. Bootstrap from published source is supported through
the existing source CLI/native backup installation workflow, with trusted code
ownership and source checks; never patch installed files directly.

Backup captures the complete UNKNOWN and review/plan evidence. Extend history
fingerprinting and ledger validation for the new directories. A restore must
retain exact history, including review receipts. Any scoped rollback admission
still uses native matching-history, source, identity, service and capacity gates;
it does not resume target execution. Default backup/restore calls remain blocked
without a valid explicit maintenance scope.

## Verification and operator gates

Use synthetic records and real native backup/restore sandbox checks for positive
admission, lock/process/identity/package drift, altered or malformed history,
expiry, duplicate confirmation, foreign leases, concurrent work and history
preservation. Include real root validation and CLI/installer argument checks.
Run focused RED/GREEN, one full exact-SHA regression and independent review.

After publication, creating a live review plan is read-only. Applying its exact
SHA is a separate operator-confirmed metadata action. Native controller
deployment remains separately authorized under original section 14. No reboot,
first employee login, component mutation, join replay or full live acceptance is
included in this implementation authorization.
