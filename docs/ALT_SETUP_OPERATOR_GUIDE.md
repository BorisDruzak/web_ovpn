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
