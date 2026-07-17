# ALT Workstation Provisioning — next steps and acceptance checklist

Status: continuation roadmap after the first verified end-to-end physical-machine provisioning run on 2026-07-17.

Read first:

```text
docs/ALT_WORKSTATION_PROVISIONING_CONTEXT.md
```

Repository branch:

```text
feat/alt-workstation-provisioning-mvp
```

The current MVP is operational. Do not redesign or replace the verified CLI, job, assignment, Vault or Ansible boundaries without a specific failing requirement and regression coverage.

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

## Phase 0 — repository and documentation hygiene

Priority: immediate.

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

### 0.2 Update stale design and plan references

Files:

```text
docs/superpowers/specs/2026-07-16-alt-workstation-provisioning-mvp-design.md
docs/superpowers/plans/2026-07-16-alt-workstation-provisioning-mvp.md
```

Required corrections:

- SDDM -> LightDM plus AccountsService;
- `sddm_accounts` -> `lightdm_accounts`;
- dotted logins such as `i.ivanov` -> `i-ivanov` or `i_ivanov`;
- allowed login characters exclude `.`;
- automatic SSH uses `ProxyCommand=none`;
- provision playbook explicitly loads Vault through `vars_files`;
- final displayed machine state is `assigned`;
- sudo denial verification uses `LC_ALL=C` and the actual denial text;
- first successful physical-machine acceptance run is recorded.

Acceptance:

```bash
grep -RIn -E 'sddm|SDDM|i\.ivanov' \
  docs/superpowers/specs/2026-07-16-alt-workstation-provisioning-mvp-design.md \
  docs/superpowers/plans/2026-07-16-alt-workstation-provisioning-mvp.md
```

Any remaining matches must be explicitly labelled historical rather than current behavior.

### 0.3 Add a concise deploy README

Create or repair:

```text
deploy/alt-linux/README.md
```

It should include:

- architecture summary;
- controller prerequisites;
- installation command;
- Vault creation and validation without exposing the secret;
- CLI examples;
- request JSON example using a non-dotted login;
- state and log paths;
- recovery and diagnostic commands;
- link to the context and this roadmap.

Acceptance:

- no secret values;
- commands match the installed implementation;
- README installation procedure works on a clean controller snapshot.

## Phase 1 — installer and controller hardening

Priority: before deploying additional production workstations.

### 1.1 Dependency preflight in the installer

Audit and explicitly validate required controller commands and packages, including at least:

```text
python3
ansible-playbook
ansible-vault
systemd-run
install
rsync or the actual copy mechanism
ssh
ssh-keyscan
mkpasswd for initial Vault preparation
```

The installer must fail early with a clear package/command diagnostic rather than partially installing.

Tests:

- missing dependency returns a nonzero exit;
- error identifies the missing command;
- no runtime files are partially replaced before dependency checks pass.

### 1.2 Preserve runtime secrets during reinstall

The installer currently succeeded while preserving the active Vault. Add explicit regression coverage for:

- existing encrypted `group_vars/vault.yml` remains byte-identical;
- mode remains `0600`;
- owner remains `altserver`;
- `.ansible-vault-pass` is never copied from the repository;
- example Vault does not overwrite the active Vault.

### 1.3 Add a Vault health command

Preferred CLI addition:

```text
workstationctl --json vault check
```

It should verify without exposing values:

- Vault file exists;
- Vault password file exists;
- ownership and mode are acceptable;
- file begins with an Ansible Vault header;
- decryption succeeds;
- `vault_employee_password_hash` exists;
- hash format is yescrypt (`$y$`).

Do not return the hash.

### 1.4 Validate controller state permissions

Add tests and an operational audit for:

```text
/var/lib/alt-deploy
/var/lib/alt-deploy/jobs
/var/lib/alt-deploy/assignments
/srv/alt-deploy/registration
/home/altserver/.ssh
/home/altserver/ansible/group_vars/vault.yml
/home/altserver/.ansible-vault-pass
```

Document expected owner/group/mode and repair only known-safe deviations.

## Phase 2 — reliability and recovery

Priority: before operating at scale.

### 2.1 Recover stale jobs after controller reboot

Define behavior for jobs left in `queued` or `running` when the controller restarts or a transient unit disappears.

Required states:

- genuinely running unit -> report running;
- queued job without unit -> relaunch or mark recoverable according to an explicit policy;
- running job without unit and without result -> mark failed with `worker_lost`;
- result exists but status update was interrupted -> reconcile to successful only after result validation.

Add a reconciliation command or service, for example:

```text
workstationctl --json jobs reconcile
```

### 2.2 Job and log retention

Define retention for:

```text
/var/lib/alt-deploy/jobs/<job_id>/
```

Requirements:

- successful and failed jobs retained for an explicit period;
- assignment records retained independently;
- logs rotated or archived safely;
- cleanup never removes an active job;
- cleanup never follows symlinks outside the state root;
- dry-run mode available.

### 2.3 More precise job stages

Current jobs largely report `stage=ansible`. Add structured stages useful to the UI and troubleshooting, such as:

```text
validating
launching
connecting
identity
employee
login_screen
verifying
recording
complete
```

Do not parse human Ansible output to derive authoritative state. Prefer callbacks or explicit stage records.

### 2.4 Failure injection tests

Add automated or controlled live tests for:

- SSH unavailable;
- host key mismatch;
- SSSD proxy accidentally inherited;
- Vault missing;
- Vault decryption failure;
- invalid yescrypt hash;
- employee login conflict;
- primary group conflict;
- insufficient disk space;
- AccountsService inactive;
- LightDM inactive;
- controller reboot during job;
- target reboot during job;
- assignment write failure after target verification.

Every failure must preserve secrets, produce a specific error code and leave the machine safely retryable unless an assignment was completed.

## Phase 3 — second-machine acceptance and idempotency

Priority: before broad rollout.

### 3.1 Provision a second clean physical or VM target

Do not reuse only the existing assigned reference machine.

Acceptance sequence:

1. clean ALT Workstation K 11.2 autoinstall;
2. automatic registration;
3. automatic SSH readiness;
4. preflight success;
5. preview success;
6. root-only provision start;
7. job success;
8. reboot;
9. LightDM account visibility check;
10. graphical employee login;
11. assignment and repeat-provision protection.

### 3.2 Idempotency on a compatible partial state

Create controlled partial states and rerun provisioning:

- hostname already correct;
- primary group already exists;
- compatible employee already exists;
- AccountsService records already correct;
- LightDM drop-in already correct.

Expected result: no destructive changes, final verification succeeds, and unnecessary tasks report `ok` rather than `changed`.

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

Decisions that must be explicit:

- whether the previous local employee account is disabled, retained or archived;
- whether the home directory is retained, renamed, backed up or removed;
- whether Nextcloud/browser/application data is retained;
- whether the shared employee password is reapplied;
- whether the workstation hostname changes;
- who can approve release;
- audit fields and reason codes;
- rollback behavior.

Acceptance:

- preview is non-mutating;
- release requires root or a constrained privileged API action;
- data is never deleted by default;
- previous and new assignments remain auditable;
- a failed release does not leave the machine open for unsafe parallel provisioning.

## Phase 5 — constrained deployment API on 192.168.100.17

Priority: prerequisite for the web UI.

The API must wrap the existing domain layer and CLI behavior. It must not accept arbitrary shell commands, playbook paths, inventory text or Ansible extra vars.

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

- authentication between `192.168.100.30` and `192.168.100.17`;
- TLS, preferably organization CA or mutual TLS;
- network allowlist for the UI host;
- strict request schemas;
- no Vault values in API responses;
- no private key access by the API caller;
- audit operator identity, action, machine UUID, request summary and result;
- rate limits and duplicate-request protection;
- root transition only through a narrowly scoped helper, systemd/polkit action or sudo rule;
- provision preview remains unprivileged and provision start remains explicitly privileged.

### Privileged boundary design

Do not run the whole API as root.

Evaluate one constrained approach:

1. root-owned helper that accepts only an existing validated job ID;
2. systemd service template activated through a restricted D-Bus/polkit rule;
3. sudoers rule permitting exactly `workstationctl provision start` with validated file ownership and path constraints.

Write the threat model before implementation.

## Phase 6 — web operator UI on 192.168.100.30

Priority: after API security and live tests.

Use the existing `web_ovpn` authentication/session layer.

Minimum UI:

- workstation table with search and filters;
- states: ready, preflight failed, awaiting assignment, provisioning, assigned;
- machine details and latest preflight checks;
- provision form;
- preview confirmation screen;
- explicit destructive/privileged confirmation;
- live or polled job status;
- bounded job log viewer;
- assignment details;
- clear error codes and remediation hints.

The browser must never receive:

- SSH private keys;
- Vault ciphertext or password;
- employee password hash;
- arbitrary filesystem paths that enable traversal;
- arbitrary Ansible arguments.

## Phase 7 — additional workstation roles

Priority: add one independent role at a time after API/operational stability.

Candidate order:

1. organization local CA certificate installation;
2. browser installation and managed policies;
3. Nextcloud client installation and autostart;
4. ONLYOFFICE Desktop Editors;
5. network shares and `scan` share integration;
6. desktop/menu shortcuts;
7. standard printers;
8. endpoint monitoring agent;
9. approved security software;
10. CryptoPro and certificate workflows, only after licensing and secret-handling design.

Each role must have:

- its own defaults and variables;
- preflight requirements;
- idempotency tests;
- verification tasks;
- no dependency on UI state;
- explicit rollback or disable strategy;
- structured result fields without secrets.

Do not turn `02-provision-account.yml` into one large monolithic office-setup playbook. Add profile composition and versioning first.

## Phase 8 — profile and configuration model

Current profile is fixed to `standard`.

Before adding multiple profiles, define a versioned contract, for example:

```yaml
profile: standard
profile_version: 1
roles:
  - local_account
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
- OS version;
- hardware summary;
- current assigned employee;
- assignment history;
- last provision/update job;
- stale/offline indication;
- manual notes and location/department metadata.

Keep DMI UUID as durable identity. Treat IP as current operational data and MAC as secondary identity.

Do not move from JSON state to PostgreSQL merely for convenience. Introduce a database when concurrent API operations, querying, history or transactional requirements justify it. If migrating, preserve import/export and recovery tooling.

## Phase 10 — security hardening

### Target SSH account

Audit and consider restricting the `ansible` authorized key with options appropriate to Ansible operation. Evaluate carefully because overly restrictive `command=` rules can break modules.

At minimum review:

- agent forwarding;
- port forwarding;
- X11 forwarding;
- PTY allocation;
- SSH source-address restriction to the controller;
- `AllowUsers ansible` or equivalent interaction with local admin access;
- key rotation workflow;
- host-key replacement workflow after reinstall.

### Audit trail

Record:

- operator identity;
- machine UUID;
- action and request fields excluding secrets;
- preview result;
- approval/start time;
- job ID;
- completion or failure;
- release/reassignment history.

### Secret rotation

Add a documented process to:

- rotate `.ansible-vault-pass`;
- rekey `vault.yml`;
- rotate the shared employee password hash;
- decide whether existing employee accounts are updated immediately or through an explicit credential-rotation job;
- verify no old hashes remain in backups or logs.

## Phase 11 — observability and operations

Add controller monitoring for:

- registration API and static HTTP units;
- pending processor path/service;
- failed preflights;
- failed provision jobs;
- stale queued/running jobs;
- disk use under `/var/lib/alt-deploy`;
- Vault health without exposing contents;
- last successful machine registration;
- SSH host-key mismatches.

Possible outputs:

- structured journal fields;
- Prometheus textfile metrics;
- Zabbix items/triggers;
- daily operational summary.

## Phase 12 — CI and review gate

Add a GitHub Actions workflow or equivalent CI job that runs without real runtime secrets:

```bash
python -m pytest -q tests/alt_linux
ansible-playbook --syntax-check deploy/alt-linux/ansible/playbooks/01-preflight.yml
ansible-playbook --syntax-check deploy/alt-linux/ansible/playbooks/02-provision-account.yml
git diff --check
```

Use fixture Vault data only where tests require it. Never add the runtime Vault or password file to CI secrets unless a later integration test has an approved threat model.

Recommended merge gate:

- ALT tests pass;
- both playbooks pass syntax check;
- no forbidden secret paths in the diff;
- documentation updated for contract changes;
- at least one reviewer checks security-boundary changes;
- live acceptance required for changes to SSH, accounts, LightDM, Vault or assignment semantics.

## Immediate next implementation slice

Start with Phase 0 and Phase 1, in this order:

1. verify the feature branch and clean worktree;
2. update stale design/plan references from SDDM to LightDM and remove dotted-login examples;
3. create or repair `deploy/alt-linux/README.md`;
4. add installer dependency validation through a failing test;
5. add explicit regression coverage that reinstall preserves active Vault bytes, ownership and mode;
6. add `workstationctl --json vault check` through TDD;
7. rerun the 80-test baseline and both playbook syntax checks;
8. install on the controller and confirm the already assigned machine remains `assigned` without rerunning provisioning;
9. commit and push a small reviewed change set.

Do not begin the web UI before the constrained API and privilege-boundary design are documented and tested.

## Definition of ready for broad workstation rollout

The system is ready for a controlled multi-machine rollout only when all of the following are true:

- second clean machine passes the complete E2E flow;
- partial-state retry and conflict tests pass;
- installer dependency and Vault-preservation tests pass;
- stale job recovery policy is implemented;
- job/log retention is implemented;
- release/reassignment design is approved or rollout policy explicitly forbids reassignment;
- controller state and secret permissions are audited;
- operational alerts exist for failed jobs and controller services;
- old documentation no longer presents SDDM or dotted logins as current behavior;
- a repeatable rollback/recovery procedure is documented.
