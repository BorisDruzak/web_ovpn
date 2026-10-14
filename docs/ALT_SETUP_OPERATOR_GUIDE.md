# ALT Setup operator guide

Use installed `workstationctl` through the existing controller sudo policy.
Examples use `sudo -u altserver`. Replace uppercase placeholders with returned
IDs. Global `--json` precedes `setup`. Direct Ansible commands are unnecessary.

## Inspect, plan and submit

```bash
sudo -u altserver workstationctl --json setup components list
sudo -u altserver workstationctl --json setup components show software.onlyoffice
sudo -u altserver workstationctl --json setup profiles list
sudo -u altserver workstationctl --json setup profiles show office-standard-v1
sudo -u altserver workstationctl --json setup component verify --machine UUID --component software.onlyoffice
sudo -u altserver workstationctl --json setup component plan --machine UUID --component software.onlyoffice
```

The machine must be registered and bound to the selected existing AD employee.
Machine/AD/OU/SSH identity, supported OS and dependencies must verify. Planning
is read-only on the target. Inspect action, selected versions/profile and all
prerequisites. `noop` means compliant; `blocked`/`unknown` require investigation.
Plans expire after 30 minutes. Confirm only the exact returned SHA.

```bash
sudo -u altserver workstationctl --json setup component apply PLAN_ID --confirm-sha256 SHA256
sudo -u altserver workstationctl --json setup jobs status JOB_ID
sudo -u altserver workstationctl --json setup jobs events JOB_ID --after 0 --limit 100
sudo -u altserver workstationctl --json setup jobs list --machine UUID --offset 0 --limit 100
```

Submission returns quickly; CLI/SSH disconnection leaves the systemd worker
running. Save job/plan IDs and SHA. Safe events identify stage/component/errors;
sensitive logs remain in protected controller stores. Never edit or delete
claims, reservations, status or review links to get past a gate.

APT probes require root-owned cache metadata without group/other write access.
An unsafe cache leaves package health unknown; arrange approved maintenance
before making a fresh plan. Probes never change cache permissions or contents.
Approved p11 sources support `classic`, and x86_64 also supports the standard
`classic gostcrypto` form. Other source components remain unapproved.

## Full Setup

```bash
sudo -u altserver workstationctl --json setup plan --machine UUID --user EXISTING_LOGIN --computer-ou APPROVED_OU --software-profile core-apps
sudo -u altserver workstationctl --json setup apply PLAN_ID --confirm-sha256 SHA256 --detach
```

`--detach` provides asynchronous full Setup. Without it, compatible full apply
waits for the durable worker and returns the legacy run result. `setup status
RUN_ID` reads original evidence. Full Setup/recovery retains protected domain,
Vault and OU gates. KRFB still needs the existing explicit restricted-access
confirmation; profile selection does not authorize network configuration changes.

## Outcomes and continuation

| State | Action |
| --- | --- |
| queued/preflight/running/verifying | Read events and let the worker finish. |
| waiting_reboot | Arrange an authorized actual reboot, then verify continuation. |
| waiting_first_login | Selected employee performs a real domain login, then verify continuation. |
| successful | Technical checks pass; inspect per-component functional acceptance. |
| degraded | Inspect missing/drifted/blocked components and make the needed component plan. |
| failed | Correct the named preflight problem, then make a fresh plan. |
| unknown_requires_review | Establish actual target/process/package state; never replay the old plan. |

```bash
sudo -u altserver workstationctl --json setup jobs verify-continuation JOB_ID
sudo -u altserver workstationctl --json setup verify --machine UUID
sudo -u altserver workstationctl --json setup component verify --machine UUID --component software.onlyoffice
```

Continuation only observes facts. A changed actual boot ID proves reboot;
first-login checks require the real selected-user home. It never reboots, logs
in, creates a home or applies roles. Missing user-file work after login needs
a new idempotent component plan.

## Interruption and retry

A plan cannot execute twice. Worker restart reconciles process identity without
rerunning Ansible. Controller timeout does not prove remote package transactions
stopped. Inspect stage, installed package facts and fresh package/remote-process
health. Do not delete package locks or reset AD accounts.

For a permitted idempotent component, after resolving actual health:

```bash
sudo -u altserver workstationctl --json setup component plan --machine UUID --component software.onlyoffice --after-job UNKNOWN_JOB_ID
sudo -u altserver workstationctl --json setup component apply NEW_PLAN_ID --confirm-sha256 NEW_SHA256
```

This handles the same interrupted component, or a selected component of an
UNKNOWN full job with intact completed protected Setup. Domain join, guarded
KRFB and unresolved protected Setup cannot use ordinary component retry. Full
prejoin/recovery successors require original reviewed gates. The old UNKNOWN
remains immutable and the new job records its review relationship.

`setup_controller_maintenance` means backup/restore blocks admission; retry after
maintenance. Invalid/partial admission evidence requires review, not claim
deletion. Restore rejects older archives with differing retained execution
history; use a current matching backup.

## Controller maintenance after a closed UNKNOWN

A stopped full Setup can require a source correction while its UNKNOWN and two
nested legacy reservations block normal maintenance. Limited maintenance review
permits backup/guarded controller deployment only. It does not authorize target
execution, join, recovery, reboot or login. Ordinary readiness stays blocked.

```bash
sudo -u altserver workstationctl --json setup jobs maintenance-plan JOB_ID
# Inspect the protected plan and separately approve its exact SHA.
sudo -u altserver workstationctl --json setup jobs maintenance-confirm PLAN_ID --confirm-sha256 SHA256
```

Plans expire after 30 minutes; confirmation creates an immutable six-hour
maintenance receipt. Duplicate confirmation cannot extend it. Each explicit
admission freshly checks registered machine, AD employee/OU/computer, strict SSH,
boot identity, positive SSS UID/GID, safe user home path, five package-health
predicates and original history under the lifecycle lock. A home may be absent
before first login. The finished job's idle worker daemon may remain alive.
Unrelated work, unsafe state, drift, busy execution or expiry denies admission.

The published native backup tool must contain the validator before scoped
backup. Install it through its normal procedure within separately approved
controller deployment preparation. Source CLI uses the trusted sibling backup
package. Installed CLI uses `/opt/alt-deploy-maintenance`: root-owned readable
validator code and its schema/import dependencies only. Backup executables,
bundles, private data and keys retain restricted modes. Root checks shared and
private validator code equality before running the read-only observer as the
service user. Restored code is never a receipt validator.

```bash
sudo alt-deploy-backup create --maintenance-review SHA256
sudo alt-deploy-backup verify BACKUP_ID --maintenance-review SHA256
sudo alt-deploy-backup rehearse BACKUP_ID --maintenance-review SHA256
# After separate approval of exact source and matching rollback backup:
sudo ./deploy/alt-linux/install-control-plane.sh --rollback-backup-id BACKUP_ID --maintenance-review SHA256
sudo -u altserver workstationctl --json controller readiness --maintenance-review SHA256
```

Scoped readiness is labelled `controller_maintenance_only`; all other guards
remain mandatory. Restore/recover also require this explicit scope and exact
retained history. Older archives cannot erase UNKNOWN, claims, reservations or
maintenance metadata. Ordinary target admission never consumes this exception.
A failed protected Setup still needs its existing separately authorized
continuation/recovery contract.

## A different queued machine after a closed UNKNOWN

If normal dispatch is blocked by a closed failed full Setup on another machine,
read its protected status and the candidate's status first. The candidate must be
unclaimed `queued`, have an unexpired source-bound Setup plan, and differ in UUID,
hostname and existing AD computer GUID. Other active or unexplained work must be
resolved through its own existing contract; the review cannot exclude it.
Historical component UNKNOWNs already linked through a valid native idempotent
review are recognized as reviewed; unreviewed UNKNOWNs remain blockers.

```bash
sudo -u altserver workstationctl --json setup jobs queue-review-plan UNKNOWN_JOB --candidate QUEUED_JOB
sudo -u altserver workstationctl --json setup jobs queue-review-confirm REVIEW_PLAN --confirm-sha256 REVIEW_SHA
sudo -u altserver workstationctl --json setup jobs status QUEUED_JOB
```

Review the exact plan before confirmation. Planning and confirming do not install
roles; confirmation allows the persistent worker to claim that exact candidate
after another fresh closure check. The worker retains its lifecycle lock and FIFO
ordering. Its ordinary source/SSH/AD/registration/SHA/TTL preflight still runs.

The review plan expires in 30 minutes; the confirmed receipt lasts at most six
hours and never extends the candidate Setup plan's own 30-minute TTL. A changed,
expired, already claimed or cancelled candidate cannot consume it. The original
UNKNOWN, claims, reservations and assignment remain unchanged. Maintenance-only
review cannot authorize this execution, and queue review cannot authorize backup
or deployment. A real domain login is still required for user-home components.

Cancel an unstarted queued job, including an expired plan, using its admitted SHA:

```bash
sudo -u altserver workstationctl --json setup jobs cancel QUEUED_JOB --confirm-plan-sha256 ADMITTED_PLAN_SHA
```

The result is `failed`, stage/error `operator_cancelled_before_execution`, with
`target_changes_started: false`. Repeating that exact cancellation returns the
same receipt. Running, waiting and UNKNOWN jobs are rejected. The used plan claim
and history remain; create a fresh plan for a later attempt. If cancellation was
interrupted after claim, inspect the retained ambiguous evidence instead of retrying.

## Functional acceptance

Perform the real document/token/signature or desktop workflow first. Installation
alone leaves `functional_verification_required`. Create a fresh compliant noop
plan and explicitly attest the completed workflow:

```bash
sudo -u altserver workstationctl --json setup component plan --machine UUID --component software.directum
sudo -u altserver workstationctl --json setup component accept PLAN_ID --confirm-sha256 SHA256 --confirm-functional
sudo -u altserver workstationctl --json setup component verify --machine UUID --component software.directum
```

Only explicit attestation produces `accepted`. Changed identity/source/component
facts invalidate its relevance. The receipt neither installs software nor rewrites
job history. Without a real user check, retain functional acceptance pending.
