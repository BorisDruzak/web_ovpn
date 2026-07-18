# ALT Workstation Provisioning — next steps and acceptance checklist

Status: continuation roadmap after the first verified end-to-end physical-machine
provisioning run on 2026-07-17. Phases 0, 1, 2.1, 2.2 and 2.3 are implemented
in branch `feat/alt-workstation-provisioning-mvp`.

Phase 2.3 runtime rollout remains a separate explicitly approved operation
because the strict schema does not migrate old job directories automatically.

Read first:

```text
docs/ALT_WORKSTATION_PROVISIONING_CONTEXT.md
```

Repository branch:

```text
feat/alt-workstation-provisioning-mvp
```

The current MVP is operational. Do not redesign or replace the verified CLI,
job, assignment, Vault, structured-stage or Ansible boundaries without a
specific failing requirement and regression coverage.

## Working rules for the next session

1. Work only from the feature branch or an isolated worktree created from it.
2. Use test-driven development for every behavior change: failing test, minimal implementation, full verification.
3. Run only the ALT suite by default:

   ```bash
   .venv/bin/python -m pytest -q tests/alt_linux
   ```

   The unrelated OpenVPN tests depend on `/etc/openvpn/vpnctl.env` and are outside this workstream.
4. Run both Ansible syntax checks after any playbook or role change.
5. Run `git diff --check` before every commit.
6. Never add the active `vault.yml`, `.ansible-vault-pass`, private keys, runtime jobs, assignments or registration state to Git.
7. Never repeat `provision start` for an assigned machine. Add an explicit release workflow first.
8. Keep the future UI on `192.168.100.30` separated from SSH keys and Vault on `192.168.100.17`.
9. Preserve direct-IP SSH options including `StrictHostKeyChecking=yes`, isolated known-hosts and `ProxyCommand=none`.
10. Preserve the current LightDM and AccountsService implementation. Do not reintroduce SDDM assumptions.
11. Do not install Phase 2.3 into the controller runtime or delete old job state without separate approval.
12. Do not synthesize `stage_history` for pre-Phase-2.3 jobs.

## Phase 0 — repository and documentation hygiene

Status: implemented.

### 0.1 Verify branch contents and commit history

Checks:

```bash
git status --short
git log --oneline --decorate -15
git branch -vv
git diff origin/main...HEAD --stat
```

Acceptance:

- worktree is clean;
- branch tracks `origin/feat/alt-workstation-provisioning-mvp`;
- all controller, Ansible, installer and ALT test files are present;
- active secrets and runtime state are absent.

### 0.2 Keep historical documents explicitly historical

Historical design files may still mention SDDM, dotted logins or coarse
`stage=ansible`. Current behavior is defined by:

```text
docs/ALT_WORKSTATION_PROVISIONING_CONTEXT.md
deploy/alt-linux/README.md
```

Any remaining obsolete assumption must be labelled historical rather than
presented as runtime behavior.

### 0.3 Maintain the deploy README

The deploy README must continue to include:

- architecture and security boundaries;
- controller prerequisites and installation;
- Vault preparation and validation without exposing secrets;
- CLI examples and request schema;
- job stages, reconciliation and retention;
- state, log and recovery paths;
- full verification commands;
- links to this roadmap and the context document.

## Phase 1 — installer and controller hardening

Status: implemented.

### 1.1 Dependency preflight

The installer validates required commands before runtime mutation:

```text
python3
ansible-playbook
ansible-vault
systemd-run
install
cp
ssh
ssh-keyscan
mkpasswd
```

A missing dependency fails early without partially replacing runtime files.

### 1.2 Preserve runtime secrets during reinstall

Verified boundary:

- active encrypted `group_vars/vault.yml` is not copied from the repository;
- `.ansible-vault-pass` is never copied;
- example Vault data cannot overwrite runtime Vault data;
- runtime secret values are not printed by installer verification.

### 1.3 Vault health command

Implemented command:

```text
workstationctl --json vault check
```

It validates existence, ownership, mode, Vault header, decryption, required
variable and yescrypt format without returning the hash.

### 1.4 Controller state permissions

Implemented commands:

```text
workstationctl --json controller permissions
workstationctl --json controller permissions repair
```

Repair is root-only and narrowly scoped to known paths and owner/group/mode.

## Phase 2 — reliability and recovery

Priority: complete the final repository gate and then perform a controlled
runtime rollout before operating at scale.

### 2.1 Recover stale jobs after controller reboot

Status: implemented.

Implemented command:

```text
workstationctl --json jobs reconcile
```

Current behavior:

- genuinely running unit -> report `still_running` without mutation;
- queued job without unit -> retryable failure preserving `created`;
- queued job with a missing recorded unit -> retryable failure preserving `launching`;
- running job without unit and result -> `worker_lost` while preserving its real stage;
- valid result recovery -> only from `running/recording`;
- malformed or invalid result -> retryable failure preserving `recording`;
- result before `recording` -> fail closed with `job_reconcile_invalid_stage`.

No automatic boot service invokes reconciliation yet.

### 2.2 Job and log retention

Status: implemented.

Retention root:

```text
/var/lib/alt-deploy/jobs/<job_id>/
```

Implemented contract:

- successful and failed jobs are retained for 90 days;
- assignment records are retained independently;
- `ansible.log` is archived after 14 days as `ansible.log.gz` mode `0600`;
- active `queued` and `running` jobs are protected;
- cleanup never follows symlinks outside the state root;
- dry-run is the default;
- mutating cleanup requires root;
- malformed stage history fails closed and is not classified or removed.

Commands:

```text
workstationctl --json jobs cleanup
workstationctl --json jobs cleanup --apply
```

No automatic cleanup service is installed.

### 2.3 More precise job stages

Status: implemented.

Canonical sequence:

```text
created -> launching -> validating -> connecting
-> identity -> employee -> login_screen
-> verifying -> recording -> complete
```

Implemented contract:

- every new job starts at `created` with a non-empty `stage_history`;
- each history entry contains only `stage` and timezone-aware `entered_at`;
- `state` remains separate from `stage`;
- failure preserves the last reached stage;
- successful jobs finish at `complete`;
- direct stage writes through `JobRepository.update()` are forbidden;
- transitions are atomic one-step operations through `JobStageManager`;
- unknown, skipped, backward and terminal transitions fail closed;
- repeated current-stage markers are byte-identical no-ops;
- planner records `launching` and the transient systemd unit;
- worker records `validating`, `connecting`, `recording` and `complete`;
- Ansible records `identity`, `employee`, `login_screen` and `verifying`;
- Ansible markers run on the controller only and do not parse task output;
- `/usr/local/libexec/alt-job-stage` is internal and not a public operator command;
- reconciliation never creates a synthetic `reconcile` stage;
- retention and machine reads fail closed on malformed real job history.

No automatic migration exists. Before runtime rollout, old job directories must
be backed up and explicitly removed after review. The assigned reference UUID
must not be provisioned again.

Phase 2.3 acceptance gate:

```bash
.venv/bin/python -m pytest -q tests/alt_linux

python3 -m py_compile \
  deploy/alt-linux/control/alt_deploy/*.py \
  deploy/alt-linux/api/process_pending.py \
  deploy/alt-linux/control/alt-job-stage

bash -n deploy/alt-linux/install-control-plane.sh
bash -n deploy/alt-linux/bootstrap/bootstrap.sh

ANSIBLE_CONFIG="$PWD/deploy/alt-linux/ansible/ansible.cfg" \
  ansible-playbook --syntax-check \
  deploy/alt-linux/ansible/playbooks/01-preflight.yml

ANSIBLE_CONFIG="$PWD/deploy/alt-linux/ansible/ansible.cfg" \
  ansible-playbook --syntax-check \
  deploy/alt-linux/ansible/playbooks/02-provision-account.yml

git diff --check
test -z "$(git status --short)"
```

### 2.3.1 Controlled runtime rollout

Status: not started; requires explicit approval.

Required sequence:

1. finish the clean repository gate;
2. stop creating new jobs;
3. inspect active jobs through `workstationctl`;
4. back up `/var/lib/alt-deploy/jobs/` without printing private content;
5. reconcile or resolve active legacy jobs before schema replacement;
6. explicitly remove obsolete test job directories after approval;
7. install with `install-control-plane.sh`;
8. verify helper installation and executable mode;
9. create a new job only for a disposable, non-assigned machine;
10. verify full `stage_history` and recovery behavior.

Rollback must restore the controller package and job-store backup together.
Never try to downgrade while keeping newly structured jobs under an old runtime.

### 2.4 Failure injection tests

Status: next behavior phase.

Add automated or controlled tests for:

- SSH unavailable;
- host-key mismatch;
- SSSD proxy accidentally inherited;
- Vault missing;
- Vault decryption failure;
- invalid yescrypt hash;
- employee login conflict;
- primary group conflict;
- insufficient disk space;
- AccountsService inactive;
- LightDM inactive;
- controller reboot during a stage;
- target reboot during a stage;
- assignment write failure after target verification;
- stage helper missing or non-executable;
- stage marker rejection before a role;
- malformed `stage_history` in each job reader.

Every failure must preserve secrets, return a specific error code and retain the
last reached stage. A machine remains retryable unless assignment completed.

## Phase 3 — second-machine acceptance and idempotency

Priority: before broad rollout.

### 3.1 Provision a second clean physical or VM target

Do not reuse the existing assigned reference machine.

Acceptance sequence:

1. clean ALT Workstation K 11.2 autoinstall;
2. automatic registration;
3. automatic SSH readiness;
4. preflight success;
5. preview success;
6. root-only provision start;
7. complete structured stage history;
8. job success;
9. reboot;
10. LightDM account visibility check;
11. graphical employee login;
12. assignment and repeat-provision protection.

### 3.2 Idempotency on a compatible partial state

Create controlled partial states and rerun provisioning:

- hostname already correct;
- primary group already exists;
- compatible employee already exists;
- AccountsService records already correct;
- LightDM drop-in already correct.

Expected result: no destructive changes, final verification succeeds, stages
remain monotonic, and unnecessary tasks report `ok` rather than `changed`.

### 3.3 Conflict safety

Verify provisioning refuses to overwrite:

- an existing account with UID below 1000;
- a login with a different home path;
- protected technical accounts;
- a conflicting group identity;
- an already assigned machine;
- a hostname assigned to another machine.

## Phase 4 — explicit release and reassignment

Priority: required before real employee turnover or workstation reassignment.

Do not implement reassignment by deleting assignment JSON manually.

Design commands such as:

```text
workstationctl --json release preview <uuid> --vars-file <file>
workstationctl --json release start <uuid> --vars-file <file>
```

Decisions must be explicit:

- whether the previous local account is disabled, retained or archived;
- whether the home directory is retained, renamed, backed up or removed;
- whether Nextcloud, browser and application data are retained;
- whether the shared employee password is reapplied;
- whether the hostname changes;
- who approves release;
- audit fields and reason codes;
- rollback behavior.

Acceptance:

- preview is non-mutating;
- release requires a constrained privileged action;
- data is never deleted by default;
- previous and new assignments remain auditable;
- failed release cannot open unsafe parallel provisioning.

## Phase 5 — constrained deployment API on 192.168.100.17

Priority: prerequisite for the web UI.

The API wraps the existing domain layer. It must not accept arbitrary shell
commands, playbook paths, inventory text or Ansible extra vars.

Suggested endpoints:

```text
GET  /api/v1/workstations
GET  /api/v1/workstations/{uuid}
POST /api/v1/workstations/{uuid}/preflight
POST /api/v1/workstations/{uuid}/provision/preview
POST /api/v1/workstations/{uuid}/provision
GET  /api/v1/provision-jobs/{job_id}
GET  /api/v1/provision-jobs/{job_id}/log
```

Security requirements:

- authenticated and encrypted traffic between `.30` and `.17`;
- network allowlist for the UI host;
- strict request schemas;
- no Vault values or private-key access;
- audit operator, action, machine UUID, request summary and result;
- rate limits and duplicate-request protection;
- root transition through a narrowly scoped helper, systemd/polkit action or
  exact sudo rule;
- preview remains unprivileged and start remains explicitly privileged.

Do not run the whole API as root. Write the threat model first.

## Phase 6 — web operator UI on 192.168.100.30

Priority: after API security and live tests.

Use the existing `web_ovpn` authentication/session layer.

Minimum UI:

- workstation table with search and filters;
- ready, preflight-failed, awaiting-assignment, provisioning and assigned states;
- current stage plus full `stage_history` timeline;
- machine details and latest preflight checks;
- provision form and preview confirmation;
- explicit privileged confirmation;
- live or polled job status;
- bounded log viewer;
- assignment details;
- clear error codes and remediation hints.

The browser must never receive SSH private keys, Vault material, employee hashes,
arbitrary filesystem paths or arbitrary Ansible arguments.

## Phase 7 — additional workstation roles

Priority: add one independent role at a time after API and operational stability.

Candidate order:

1. organization local CA certificate installation;
2. managed Plasma profile and desktop defaults;
3. browser installation and managed policies;
4. Nextcloud client installation and autostart;
5. ONLYOFFICE Desktop Editors;
6. network shares and `scan` share integration;
7. desktop and menu shortcuts;
8. standard printers;
9. endpoint monitoring agent;
10. approved security software;
11. CryptoPro and certificate workflows after licensing and secret-handling design.

For Plasma, capture configuration from a clean reference account, separate
portable settings from monitor/cache/session state, and deploy the profile
before first graphical login. Do not copy an entire home `.config`, `.cache` or
`.local/share` tree.

Each role must have:

- its own defaults and variables;
- preflight requirements;
- idempotency tests;
- verification tasks;
- no dependency on UI state;
- explicit rollback or disable strategy;
- structured result fields without secrets.

Do not turn `02-provision-account.yml` into one monolithic office-setup
playbook. Add profile composition and versioning first.

## Phase 8 — profile and configuration model

Current profile is fixed to `standard`.

Before adding multiple profiles, define a versioned server-side contract:

```yaml
profile: standard
profile_version: 1
roles:
  - local_account
  - plasma_profile
  - organization_ca
  - browser
  - nextcloud
```

Requirements:

- profiles are server-defined, not arbitrary client-provided role lists;
- assignment records store profile and version;
- preview returns exact planned roles and versions;
- job result records verification per role;
- changing a profile definition does not rewrite historical assignments;
- update/reconcile workflow is separate from first provisioning.

## Phase 9 — machine inventory and lifecycle improvements

Consider adding:

- last registration time;
- last successful SSH check;
- last preflight time;
- OS version and hardware summary;
- current assigned employee and assignment history;
- last provision/update job;
- stale/offline indication;
- manual notes and location/department metadata.

Keep DMI UUID as durable identity. Treat IP as current operational data and MAC
as secondary identity.

Do not move from JSON state to PostgreSQL merely for convenience. Introduce a
database when concurrent API operations, querying, history or transactional
requirements justify it. Preserve import/export and recovery tooling.

## Phase 10 — security hardening

### Target SSH account

Review agent forwarding, port forwarding, X11 forwarding, PTY allocation,
controller source restrictions, key rotation and host-key replacement. Avoid
restrictions that break required Ansible module execution.

### Audit trail

Record operator identity, machine UUID, action, non-secret request fields,
preview, approval, job ID, completion/failure and release history.

### Secret rotation

Document Vault password rotation, `vault.yml` rekeying, employee hash rotation,
existing-account update policy and backup/log sanitation.

## Phase 11 — observability and operations

Add monitoring for:

- registration API and static HTTP units;
- pending processor path/service;
- failed preflights and jobs;
- stale queued/running jobs and their current stages;
- disk use under `/var/lib/alt-deploy`;
- Vault health without contents;
- last successful registration;
- SSH host-key mismatches.

Possible outputs include structured journal fields, Prometheus textfile metrics,
Zabbix items/triggers and a daily operational summary.

## Phase 12 — CI and review gate

Add CI that runs without runtime secrets:

```bash
python -m pytest -q tests/alt_linux
python -m py_compile deploy/alt-linux/control/alt_deploy/*.py
ansible-playbook --syntax-check deploy/alt-linux/ansible/playbooks/01-preflight.yml
ansible-playbook --syntax-check deploy/alt-linux/ansible/playbooks/02-provision-account.yml
git diff --check
```

Recommended merge gate:

- ALT tests pass;
- controller Python compiles;
- installer and bootstrap Bash syntax pass;
- both playbooks pass syntax check;
- no forbidden secret paths in the diff;
- documentation is updated for contract changes;
- security-boundary changes receive review;
- SSH, accounts, LightDM, Vault and assignment changes receive live acceptance.

## Immediate next implementation slice

Continue in this order:

1. run the full clean Phase 2.3 repository gate;
2. review the complete diff and commit history;
3. obtain explicit approval for runtime rollout;
4. back up and retire incompatible legacy test jobs;
5. install and smoke-test Phase 2.3 on a disposable non-assigned machine;
6. implement Phase 2.4 failure-injection coverage;
7. provision a second clean disposable machine for Phase 3.1 acceptance;
8. verify partial-state idempotency and conflict safety;
9. design release/reassignment before employee turnover;
10. design the constrained API privilege boundary before the web UI.

Do not begin the web UI before the constrained API and privilege-boundary design
are documented and tested.

## Definition of ready for broad workstation rollout

The system is ready for a controlled multi-machine rollout only when:

- the Phase 2.3 runtime rollout is complete and observed on a disposable target;
- a second clean machine passes the complete E2E flow;
- partial-state retry and conflict tests pass;
- installer dependency and Vault-preservation tests pass;
- stale job recovery and retention are operationally verified;
- release/reassignment design is approved or reassignment is explicitly forbidden;
- controller state and secret permissions are audited;
- operational alerts exist for failed jobs and controller services;
- documentation does not present SDDM, dotted logins or coarse stages as current;
- rollback and recovery procedures are repeatable and documented.
