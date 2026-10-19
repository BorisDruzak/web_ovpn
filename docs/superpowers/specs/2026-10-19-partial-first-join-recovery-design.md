# Partial first-join diagnostics and local-authentication recovery

Status: written specification approved by the operator in the current chat on
2026-10-19. Implementation and live recovery have not started. The next artifact
is the implementation plan for review, using native execution in this chat.

## Outcome and boundaries

Finish the authorized workstation configuration after a closed first-join
failure left local AD configuration, but no currently observable AD computer
object or machine credentials. Retain every original UNKNOWN job, event,
assignment revision, consumed plan and reservation. A successful recovery means
only that the machine safely returned to local authentication; it does not mean
that Setup or domain membership succeeded.

Use the existing protected CLI, lifecycle lock, plan SHA/TTL, strict SSH,
directory identity checks, native backup and guarded deployment. Recovery itself
must not join a domain, create/delete/reset/move an AD object, change DNS, install
packages, reboot, log in as an employee or run an old job. A subsequent Setup
requires a separate fresh plan, its exact confirmation, and a new job.

## Evidence and remaining uncertainty

The closed attempt completed the system upgrade and entered domain join. Its
first-join adapter returned the compatibility-failure marker. All 192 retained
task events were read without gaps. Fresh independent observations found:

- local authentication scheme reports the requested AD domain;
- Samba trust fails, the system keytab is absent and the directory computer
  lookup returns no object;
- the existing read-only prejoin collector reports machine credentials absent
  and execution processes absent; package-health checks pass;
- the packaged system-auth bytes, Samba version and approved directory endpoint
  match the previously configured reference machine;
- the join account is enabled and its observed machine-account usage does not
  exhaust the domain quota. Explicit delegated OU creation rights remain
  unproven.

These observations describe current state. They do not prove that an AD write
never happened, or identify the historical exception. The adapter collapses
exceptions to one marker; the managed callback retained only generic task codes.
Do not invent a historical cause or replay a join to recover lost output.

Operational correction during acceptance: a later direct directory query found
the join account's quota fully used and no effective OU computer-create
delegation. The earlier statement that usage did not exhaust quota was not
established by that complete creator-SID count. Operator-authorized delegation
is a separate directory action; it does not prove the lost historical native
exception or permit replay. A distinct failed successor with intact original
recovery proof must retain its own current reservation pair while validating
the exact ancestor set; the one-claim-per-job/run and one-successor-per-receipt
contracts remain unchanged.

The original GUID-based recovery requires an existing computer object. The
prejoin-timeout continuation requires that domain join was never entered.
Neither contract admits this case. Current maintenance review also requires
healthy domain membership and only one unreviewed pair of legacy reservations;
multiple closed failures now need explicit coverage.

## Selected approach

Add a narrow partial-local recovery alongside the existing GUID-based recovery.
First improve safe diagnostics and validate the native argument/cache contract
without a directory write. Then restore local authentication with one fixed
native operation and prove the postconditions before offering a new Setup plan.

Using the GUID-based path would require inventing or provisioning an object;
reinstalling the OS would discard local state and exceed this recovery scope.
Neither is selected. Existing trust/keytab recovery and timeout retry retain
their current admission rules.

## Safe first-join diagnostics

Keep the current compatibility failure marker and fatal guard. Introduce fixed,
allowlisted phases and codes for request validation, native interface, existing
trust/local scheme/credentials, directory observation, native argument
validation, native execution, offline keytab generation/binding, trust checking
and machine AS exchange. Distinguish rejected input, subprocess failure,
timeout, oversized output and unexpected internal exception without printing
exception text, command arguments or raw stdout/stderr.

The private native-wrapper directory carries a bounded structured diagnostic
receipt across the wrapper and parent process. Missing or malformed wrapper
evidence stays uncertain. Record an intent before calling the directory writer
and its returned result afterwards; a missing result cannot become proof of
no write. Diagnostics do not authorize recovery or retry.

Before removing the temporary wrapper directory, the parent persists the
validated receipt in a fixed root-private first-join evidence directory. Bind
it to the trusted configuration-run ID, one invocation ID and requested-machine
identity digest. Accept no arbitrary path argument and never overwrite another
invocation. The separate reader must match that binding and enforce schema,
ownership, no-symlink and size limits; absent durable evidence remains unknown.

Read the structured receipt in a separate fixed task outside the credential
block. The role/callback propagates only its recognized diagnostic codes into
the native event stream, including when the original command task uses
failed_when:false. Existing events remain valid and byte-identical. The web
journal and MCP retain sequence and pagination semantics and display these
codes without exposing raw results. Respect no_log; arbitrary output and a
receipt with a wrong operation binding cannot become public diagnostic data.

Before changing join behavior, reproduce a specific defect through an isolated
native-interface/argument/cache probe or independently retained server evidence.
Tests must demonstrate that the probe never calls a directory writer. If the
original cause cannot be reconstructed, report that limit explicitly; a new
production join is not a diagnostic probe. Do not claim an unproven join fix.

## Maintenance coverage for closed failures

Preserve existing schema-1 maintenance plans and receipts. Add a versioned
maintenance-only envelope covering the exact complete set of unreviewed closed
full-Setup UNKNOWN jobs and their corresponding nested legacy reservations.
Filter only already validated predecessor reviews through the existing native
validator. Reject running, unclaimed, incomplete, foreign or uncovered work.

Add `setup jobs maintenance-plan --all-closed`, mutually exclusive with the
existing single JOB_ID argument. Exact `maintenance-confirm` remains the
confirmation command. Use a distinct coverage snapshot and versioned payload;
keep schema-1 joined snapshots and QueueAdmissionReview behavior unchanged.
Partial-local evidence never authorizes an unrelated machine's queue admission.

For every covered job, validate original request/status/execution/events, failed
Setup/configuration results and assignment binding. Fresh evidence must prove
UUID, registration, hostname, pinned SSH identity, selected enabled AD employee,
approved OU, boot identity, stopped remote execution and package health. Two
explicit observation modes are admitted: the existing healthy joined state, or
the partial-local state defined below. Absence of domain-user NSS resolution is
expected only in the partial-local mode and never weakens joined-mode checks.

Bind complete immutable history, all covered identities, observation modes and
validator bytes to the plan. Keep the 30-minute confirmation TTL, six-hour
nonrenewing maintenance window and fresh checks at every admission. Exclusions
contain only exact covered job/reservation IDs and authorize controller backup
and guarded deployment only. They grant no worker, queue, recovery or target
mutation permission. An added job or relevant drift invalidates coverage.

Install the compatible native backup validator first with an empty real queue,
using the existing published-source installer. Prepare and confirm a fresh
coverage plan, create/verify/rehearse its matching controller backup, then run
guarded controller deployment. Source and installed validator digests must agree.
Preserve all review versions in ledger validation, backup and restore checks.

## Admission for partial-local recovery

Add `workstationctl setup recovery partial-local` with `plan JOB_ID`,
`apply PLAN_ID --confirm-sha256 SHA`, `status PLAN_ID`, and
`continue-plan PLAN_ID`. These commands are operator-only; no new web or MCP
recovery writer is added. Plan and status never execute a target change.

Bind the original claimed full-Setup UNKNOWN, original failed Setup and configure
runs, configuration result, complete event history, exact two corresponding
legacy reservations and unchanged failed assignment. The original plan must
show local authentication, no trust and no computer object. The failure must
have entered initial domain join and completed execution. Ambiguous or missing
history fails closed; a timeout-before-join or existing-object recovery uses its
own unchanged route.

Fresh controller and target evidence under the lifecycle lock must prove:

- identical registered UUID, hostname, address and strict SSH binding;
- original enabled employee GUID/SID, approved OU and requested profiles;
- no computer collision in complete bounded directory searches for the requested
  account name, DNS hostname and host SPNs on the approved directory endpoint;
- local AD scheme names exactly the originally requested domain, trust fails,
  keytab/alternative credentials are absent, and the existing read-only TDB
  collector admits only noncredential SID entries;
- no incompatible controller/target processes or package locks, healthy package
  database/dependencies, synchronized clock and unchanged boot identity;
- a working local administrative account, retained pinned ansible SSH access,
  safe PAM/NSS files and supported native authentication tools.

No computer GUID is fabricated or replaced by a sentinel. The new proof type
uses machine UUID plus original job/run identity, with an explicit absent-object
observation. A found object, credential, changed identity, uncertain LDAP result,
unsafe path, busy process or unsupported native implementation blocks the plan.

## Target operation, backup and uncertainty

The plan lists the exact native tool hashes, supported side effects, affected
authentication files/symlinks, service state changes, snapshot manifest, source
digest, boot identity, preconditions and expiry. It is immutable and expires
after 30 minutes. Application takes the existing lifecycle/admission locks,
rechecks evidence and atomically consumes one execution claim before dispatch.

Create a private root-owned forensic backup of the exact PAM/NSS control links
and referenced templates, authentication configurations, machine-credential
absence evidence and affected service states. Include metadata and absence
markers; read symlinks only according to a fixed safe link policy. No secrets
leave protected storage. Verify its contents and rehearse the supported local
transition and retained administrator access in an isolated ALT fixture before
permitting the real target operation.

Execute only the hash-bound packaged `system-auth write local`, without --gpo.
Supported effects are switching the native PAM/control links and NSS sources to
local, stopping/disabling the previous SSSD/winbind authentication services, and
the packaged local-mode behavior for GOA. The fixed validator must enumerate
those effects for the pinned native version before execution; unsupported GOA,
control facilities, service hooks or additional side effects block admission.
Do not delete Samba/SSSD configuration, clear credential databases, modify local
accounts or replace the packaged tool. Retain the partial configuration backup.

Afterwards prove local scheme, safe local PAM/NSS, unchanged UUID/hostname/boot,
working fresh pinned SSH with sudo, absent domain credentials, failed trust,
no directory collision and healthy quiet package/execution state. Persist a new
immutable successful-local-recovery receipt only when all checks pass. A timeout,
disconnect, missing result, unexpected write or failed postcondition leaves the
new recovery attempt UNKNOWN and blocks continuation. Never redispatch it or
perform an automatic rollback; retain the backup and report missing evidence.

## Fresh Setup continuation and immutable predecessor

`continue-plan` accepts only the exact successful local-recovery receipt and
fresh matching identity/absence/health observations. It produces an ordinary
new full-Setup plan, retaining the original employee/OU/profile choices, with a
distinct partial-local proof and source-bound diagnostics. It performs no join.
Existing prejoin-timeout and GUID terminal-resolution proof schemas are unchanged.

Integrate the new proof in assignment/history validators and predecessor
admission. Creating the successor publishes only an additive old-job to new-job
review, using the existing native review model. No old job, consumed claim,
assignment revision, legacy reservation or result is edited to admit it. Fresh
execution gets its own reservations. A lost reply is resolved by its retained
request/claim; no second dispatch is allowed. One partial-local receipt can
authorize only one successor, under atomic claim checks.

A new join remains subject to the normal existing-account conflict guard,
source/TTL checks, exact confirmation and one-PC execution lock. A changed
employee, OU, hostname or machine requires a different explicit workflow.
Reboot and real employee login remain separate visible operator actions.

If the historical exception is unrecoverable, the operator may still review a
new configuration plan after verified local recovery and successful isolated
native-contract checks. State that the old cause remains unknown. Its purpose
is completing configuration under current verified preconditions; it is not
permission to retry joins until a diagnostic appears or to claim a proven fix.

## Verification and acceptance

Use focused RED/GREEN tests for safe diagnostic propagation, every wrapper
failure boundary, secret/nonallowlisted output suppression, old-event
compatibility, complete paging and uncertainty after a missing child result.

Test maintenance coverage for multiple closed failures, mixed joined/partial
states, uncovered/foreign reservations, source drift, locks, expiry and immutable
history. Include native root/sandbox backup verification and restore rehearsal.

Test recovery refusal for existing AD objects/aliases/SPNs, credentials, another
domain, identity/user/OU changes, unsafe links/files, unknown native hashes,
active processes, stale boot/evidence, repeated/concurrent apply, incomplete
backup and failed administrator-access rehearsal. Inject dispatch loss and
postcondition failures: no automatic retry or successor may result. Verify the
new successor once and refusal of a second consumer. Preserve old proof fixtures.

Run relevant Linux regression checks, independent review and exact-source CI
before publication to main. Guarded deployment requires the fresh matching
controller backup and exact current maintenance confirmation. Verify installed
source hashes and old-history hashes afterwards. Record actual private live
IDs separately from tracked documentation; do not commit credentials or topology.

On the authorized workstation, prepare the concrete new recovery plan for exact
confirmation, execute it once, verify fresh local access, then prepare and confirm
the new Setup plan. Follow the new job through every event page and independent
verification. Report technical Setup, reboot/first-login requirements and user
acceptance separately. Keep the original UNKNOWN visible throughout.
