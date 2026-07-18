# ALT workstation provisioning — structured job stages design

Date: 2026-07-18

Status: approved for implementation planning

Repository: `BorisDruzak/web_ovpn`

Branch: `feat/alt-workstation-provisioning-mvp`

## 1. Context

The current provisioning worker changes a job directly from `stage=created` to
`stage=ansible`, then to `stage=complete`. This is sufficient for execution but
not for operator diagnostics, recovery or the future web UI. The control plane
already has natural execution boundaries in the planner, worker and Ansible
roles, so Phase 2.3 introduces authoritative structured stages without parsing
human Ansible output.

This design applies to new jobs only. Existing test jobs will be removed during
a separate, explicitly approved runtime rollout. There is no automatic or
synthetic migration of old job records.

## 2. Goals

- expose the last authoritative provisioning stage through `jobs status`;
- retain an ordered timestamped history of all entered stages;
- preserve the last reached stage when a job fails;
- make stage transitions strict, atomic, idempotent and fail-closed;
- provide explicit stage markers around existing Ansible role boundaries;
- keep one transition implementation shared by planner, worker, reconciliation
  and the Ansible helper;
- reject damaged job state instead of silently ignoring it;
- avoid secrets, arbitrary paths, arbitrary Ansible arguments and log parsing.

## 3. Non-goals

- no progress percentage;
- no parsing of task names or Ansible stdout;
- no automatic recovery or retry based only on a stage;
- no public `workstationctl jobs stage` command;
- no migration of pre-Phase-2.3 jobs;
- no database or separate event store;
- no changes to workstation assignment semantics;
- no automatic deletion of existing runtime jobs by the installer.

## 4. Canonical stage model

The complete ordered stage sequence is:

```text
created
launching
validating
connecting
identity
employee
login_screen
verifying
recording
complete
```

`state` and `stage` remain separate concepts:

- `state` describes lifecycle outcome: `queued`, `running`, `successful`,
  `failed`;
- `stage` describes the last authoritative work boundary reached;
- failure is a state and is never appended as a stage;
- a failed job keeps the last reached stage;
- a successful job must end at `stage=complete`.

Every new job contains a non-empty `stage_history`:

```json
{
  "state": "running",
  "stage": "employee",
  "stage_history": [
    {
      "stage": "created",
      "entered_at": "2026-07-18T12:00:00+00:00"
    },
    {
      "stage": "launching",
      "entered_at": "2026-07-18T12:00:01+00:00"
    },
    {
      "stage": "validating",
      "entered_at": "2026-07-18T12:00:03+00:00"
    },
    {
      "stage": "connecting",
      "entered_at": "2026-07-18T12:00:04+00:00"
    },
    {
      "stage": "identity",
      "entered_at": "2026-07-18T12:00:08+00:00"
    },
    {
      "stage": "employee",
      "entered_at": "2026-07-18T12:00:11+00:00"
    }
  ]
}
```

Each history item contains exactly `stage` and `entered_at`.

## 5. Transition rules

A transition is valid only when all of the following hold:

1. the job record and its history pass strict validation;
2. the job is not terminal;
3. the requested stage is in the canonical allowlist;
4. the requested stage is either the current stage or the immediately next
   stage;
5. timestamps are timezone-aware UTC values and do not move backwards.

Behaviour:

- requesting the current stage is an idempotent no-op;
- requesting the immediately next stage appends one history item and changes
  `stage` in the same atomic `status.json` write;
- skipping a stage fails with `invalid_job_stage_transition`;
- moving backwards fails with `invalid_job_stage_transition`;
- changing a terminal job fails with `job_stage_terminal`;
- invalid history fails with `job_stage_history_invalid`.

The transition API may atomically update additional non-stage status fields.
Examples:

```text
created -> launching
+ systemd_unit

launching -> validating
+ state=running
+ started_at

recording -> complete
+ state=successful
+ finished_at
+ result_file
```

Ordinary `JobRepository.update()` must reject direct updates to `stage` and
`stage_history`. All stage changes go through the domain stage manager.

## 6. Components

### 6.1 `job_stages.py`

New module:

```text
deploy/alt-linux/control/alt_deploy/job_stages.py
```

Responsibilities:

- define the canonical stage sequence and index;
- build the initial `created` history entry;
- validate `stage`, `stage_history` and timestamp ordering;
- advance one stage atomically;
- support idempotent current-stage calls;
- accept a narrow set of additional status fields for the same atomic write;
- use the shared `workstationctl.lock` when called from an unlocked context;
- expose an unlocked internal path for callers already holding that lock.

The module does not execute Ansible, inspect logs or contact workstations.

### 6.2 `JobRepository`

`JobRepository.create()` initializes:

```json
{
  "state": "queued",
  "stage": "created",
  "stage_history": [
    {
      "stage": "created",
      "entered_at": "<timezone-aware UTC timestamp>"
    }
  ]
}
```

All real job records are strictly validated during load. A real `job-*`
directory with an invalid history is not silently skipped. Symlinks and objects
that are not real job directories remain ignored as unsafe entries.

`JobRepository.list()`, `active_for_machine()`, machine listing,
reconciliation and cleanup therefore fail closed when a real job record is
damaged. This prevents a malformed active job from disappearing and allowing a
parallel provision request.

### 6.3 Planner

`ProvisionPlanner.start()` performs `created -> launching` before invoking the
systemd launcher. The same transition atomically records the exact expected
systemd unit.

If the unit launch fails, the job becomes `state=failed` but remains
`stage=launching`.

### 6.4 Worker

The worker performs:

```text
launching -> validating -> connecting
```

`launching -> validating` atomically sets `state=running` and `started_at`.

`validating` covers loading and validating controller-side job and machine
state. `connecting` is entered immediately before Ansible execution.

After Ansible returns a valid result, the worker performs:

```text
verifying -> recording -> complete
```

`recording` is entered before writing `result.json` and controller assignment.
`complete` is entered only after both writes succeed and atomically sets
`state=successful`, `finished_at` and `result_file`.

Any exception sets `state=failed`, `finished_at` and bounded `error` without
changing the current stage.

## 7. Ansible stage markers

The playbook uses explicit marker tasks rather than Ansible log parsing or a
callback plugin.

Canonical placement:

```text
marker identity
role workstation_identity

marker employee
role local_employee

marker login_screen
role lightdm_accounts

marker verifying
role provision_verify
```

Markers execute on the controller with:

```yaml
delegate_to: localhost
become: false
```

A marker invokes the internal helper:

```text
/usr/local/libexec/alt-job-stage
```

Command contract:

```bash
alt-job-stage --job-id <job_id> --stage <allowed_stage>
```

The helper:

- runs as `altserver`;
- accepts only a validated job ID and an allowlisted stage;
- accepts no filesystem paths, JSON payloads, shell commands or arbitrary
  Ansible arguments;
- imports the shared domain stage manager;
- writes under the common lock;
- returns short JSON without secret values;
- exits non-zero on any invalid or unsafe transition.

A marker failure stops the playbook before the next role begins. This is a
fail-closed contract: workstation mutation does not continue when authoritative
controller stage state cannot be recorded.

The helper is internal and is not exposed as a public `workstationctl`
subcommand or future browser API.

## 8. Strict history validation

A valid history must satisfy all of the following:

- it exists and is a non-empty list;
- its first item is `created`;
- each item is an object containing exactly `stage` and `entered_at`;
- all stages are known;
- stages form a contiguous prefix of the canonical sequence;
- no stage is repeated;
- every timestamp is valid ISO-8601 with timezone information;
- normalized UTC timestamps are non-decreasing;
- current `stage` equals the final history item;
- `state=successful` requires `stage=complete`;
- `state=queued` is permitted only at `created` or `launching`;
- `state=running` is permitted from `validating` through `recording`;
- `state=failed` may retain any reached stage except `complete`.

A missing or invalid history is `job_stage_history_invalid`.

## 9. Reconciliation contract

Reconciliation no longer writes `stage=reconcile`.

- queued job without a worker keeps `stage=launching` and becomes failed with
  `worker_not_started`;
- a lost running worker becomes failed and keeps its last actual stage;
- a rejected result keeps its last actual stage;
- result recovery is accepted only from `state=running, stage=recording`;
- after idempotent assignment recording, recovery advances
  `recording -> complete` and sets `state=successful`;
- an active worker remains unchanged;
- malformed histories stop reconciliation explicitly.

This preserves the location of the real failure instead of replacing it with a
reconciliation pseudo-stage.

## 10. Retention and public CLI

`jobs status` returns `stage_history` automatically as part of the public job
status object.

Retention rules remain unchanged:

- `queued` and `running` jobs are never archived or deleted;
- failed jobs may have any valid last reached stage;
- successful jobs must be `complete`;
- a damaged history stops cleanup fail-closed;
- cleanup does not delete or repair malformed records.

No new public stage mutation command is added.

## 11. Failure semantics

Expected final stages for representative failures:

| Failure point | Final stage |
| --- | --- |
| systemd unit launch | `launching` |
| worker/job/machine validation | `validating` |
| SSH or Ansible connection/start | `connecting` |
| hostname role | `identity` |
| employee role | `employee` |
| LightDM or AccountsService role | `login_screen` |
| final workstation verification or result validation | `verifying` |
| `result.json` or assignment write | `recording` |

Every failed job receives:

```text
state=failed
stage=<last reached stage>
finished_at=<timezone-aware UTC timestamp>
error=<bounded public diagnostic>
```

No failure history entry is created.

## 12. Security properties

- stage values are a fixed allowlist;
- the helper does not accept arbitrary paths or commands;
- job ID validation uses the existing strict job ID format;
- marker tasks run locally and do not send controller paths or helper access to
  the workstation;
- `stage_history` contains only stage names and timestamps;
- no Vault value, password hash, private-key path or employee secret is stored;
- all status writes remain atomic private files;
- symlink protections and common locking remain mandatory.

## 13. Test strategy

Implementation proceeds through small red-green TDD slices.

### 13.1 Creation and validation

- new jobs start with `created` and one UTC history entry;
- missing, empty or malformed history is rejected;
- incorrect order, duplicate stages and skipped stages are rejected;
- timezone-free or decreasing timestamps are rejected;
- current stage/history mismatch is rejected;
- invalid state/stage combinations are rejected;
- a damaged real job is not hidden by list operations.

### 13.2 Domain transitions

- the next stage advances atomically;
- the current stage is an idempotent no-op;
- backwards and skipped transitions fail;
- terminal jobs reject markers;
- atomic additional status fields are recorded;
- ordinary repository updates cannot mutate stages.

### 13.3 Planner and worker

- planner records `launching` and the exact systemd unit;
- launch failure remains at `launching`;
- worker records `validating` and `connecting`;
- successful flow records `recording` and `complete`;
- generic failure preserves the reached stage;
- result validation failure remains at `verifying`;
- assignment write failure remains at `recording`.

### 13.4 Helper and Ansible

- helper validates arguments and stage allowlist;
- unknown jobs and invalid transitions fail;
- output is bounded JSON without secret-like keys;
- helper uses the common lock;
- playbook markers appear immediately before their roles;
- markers use localhost and `become: false`;
- missing helper is detected before the first workstation-mutating role;
- both playbooks pass syntax checks.

### 13.5 Reconciliation and retention

- reconciliation never creates `stage=reconcile`;
- worker loss and result rejection preserve the actual stage;
- result recovery is allowed only from `recording`;
- successful recovery appends `complete` exactly once;
- active jobs remain byte-identical;
- retention fails closed on a malformed history.

### 13.6 Full verification

After the final Phase 2.3 slice:

```text
all tests in tests/alt_linux
Python compilation of controller modules
Bash syntax of install-control-plane.sh
Bash syntax of bootstrap.sh
Ansible syntax of 01-preflight.yml
Ansible syntax of 02-provision-account.yml
git diff --check
clean worktree
```

## 14. Runtime rollout

The installer must not delete or migrate runtime jobs automatically.

A separate approved rollout procedure will:

1. verify no job is `queued` or `running`;
2. list the exact existing test job IDs;
3. back up `/var/lib/alt-deploy/jobs`;
4. remove only the explicitly reviewed test job directories;
5. leave assignments untouched;
6. back up the installed runtime;
7. install the new package and `/usr/local/libexec/alt-job-stage`;
8. verify CLI, helper, Vault, permissions and systemd units;
9. run a read-only cleanup check;
10. avoid any provisioning of the assigned reference UUID.

The complete live stage history must then be tested on a new clean VM or
physical workstation. The previously assigned reference machine must not be
provisioned again.

## 15. Acceptance criteria

Phase 2.3 is accepted when:

- every new job has a valid `stage_history` beginning at `created`;
- all stage transitions follow the canonical sequence;
- repeat markers are safe no-ops;
- invalid transitions and damaged histories fail closed;
- planner, worker, Ansible and reconciliation use one shared stage domain;
- failures preserve the last reached stage;
- successful jobs end with `complete` and a complete history;
- public job status exposes the history without secrets;
- retention and reconciliation remain safe;
- installer deploys and verifies the internal helper;
- the complete repository verification passes;
- a new clean workstation demonstrates the full live sequence.
