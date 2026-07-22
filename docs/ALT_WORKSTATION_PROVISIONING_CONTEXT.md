# ALT Workstation Provisioning — verified implementation context

Status: verified end to end on 2026-07-17 and subsequently hardened through
Phase 1 controller work, Phase 2.1 job reconciliation, Phase 2.2 job and log
retention, and Phase 2.3 structured job stages.

Phase 2.3 is implemented and tested in branch
`feat/alt-workstation-provisioning-mvp`. Runtime rollout of the strict schema is
not implicit and requires separate approval.

Repository: `BorisDruzak/web_ovpn`

Implementation branch: `feat/alt-workstation-provisioning-mvp`

This document is the operational source of truth for the ALT Workstation
provisioning control plane. Historical design and implementation-plan documents
remain useful for intent, but this file takes precedence when they differ.

## OR-3P1 pilot readiness — repository state

OR-3P1 is implemented in PR #21 but has not been applied to the live controller.
It adds `jobs active`, the local read-only `controller readiness` gate, complete
installation of both API programs and all systemd units, pre-mutation active-job
and pending-registration blocks, and synthetic installer preservation tests.

The readiness gate uses only controller-local filesystem, systemd, loopback HTTP,
Vault/permission sources of truth and installed Ansible syntax checks. It never
contacts a workstation. A failure is `controller_not_ready` with exit code `11`.

OR-3P3 backup/restore is mandatory before live rollout. OR-3P2 machine archive and
re-registration remains a separate workflow. See
`docs/ALT_OR3P1_PILOT_ROLLOUT.md`.

## OR-3P3 coordinated backup/restore — repository and operational state

OR-3P3 provides an independent root-only backup utility, six-component atomic
bundle publication, byte-bound verification and isolated rehearsal evidence,
durable restore journals, same-filesystem staging, automatic rollback proof,
manual-recovery fail-closed handling and an `alt-deploy-guard.service` boot
boundary.

Repository implementation is complete only after PR #24 final verification and
merge. Repository completion does not mean the live gate is complete. On
controller `192.168.100.17`, operators must install the dedicated backup tool and
successfully run `create`, `verify` and `rehearse` for one exact backup ID.

OR-3P4 is blocked until that ID is supplied explicitly:

```bash
sudo bash deploy/alt-linux/install-control-plane.sh \
  --rollback-backup-id <backup-id>
```

The installer never selects the newest bundle. It uses a read-only
`rehearse-status` check before mutation and preserves all backup-tool paths.
Operational details are authoritative in
`docs/ALT_OR3P3_COORDINATED_BACKUP_RESTORE.md`.

## 1. Purpose and verified result

The control plane takes an ALT Workstation K 11.2 computer through:

```text
ALT autoinstall
  -> first-boot bootstrap
  -> ansible service account
  -> registration on 192.168.100.17
  -> isolated SSH known_hosts refresh
  -> automatic SSH/Ansible readiness
  -> workstationctl preflight
  -> awaiting_assignment
  -> provision preview
  -> root-approved asynchronous provision job
  -> structured stage progression
  -> final verification
  -> assignment records
  -> assigned
```

The first complete physical-machine run succeeded, survived reboot and was
verified through an actual graphical login to Plasma.

## 2. Deployment architecture

### Controller

Host: `192.168.100.17`

Service account and group: `altserver:altserver`

Responsibilities:

- machine registration processing;
- SSH known-host handling;
- `workstationctl` CLI;
- Ansible playbooks and roles;
- Ansible Vault and non-secret Vault health checks;
- controller permission audit and narrowly scoped repair;
- provision jobs, structured stages, logs, results and assignments;
- reconciliation and retention;
- constrained API in a future stage.

Important runtime paths:

```text
/usr/local/sbin/workstationctl
/usr/local/libexec/alt-provision-worker
/usr/local/libexec/alt-job-stage
/opt/alt-deploy-control/alt_deploy/
/opt/alt-deploy-api/register_api.py
/opt/alt-deploy-api/process_pending.py
/home/altserver/ansible/
/home/altserver/ansible/group_vars/vault.yml
/home/altserver/.ansible-vault-pass
/home/altserver/.ssh/known_hosts_autoinstall
/var/lib/alt-deploy/
/var/lib/alt-deploy/jobs/
/var/lib/alt-deploy/assignments/
/srv/alt-deploy/registration/
```

Allowlisted unprivileged deployment HTTP service: port `8087`; only `/bootstrap/*`, `/metadata/*` and `/health` are served.

Registration API: port `8088`.

Systemd units:

```text
alt-deploy-http.service
alt-deploy-register.service
alt-deploy-process.path
alt-deploy-process.service
```

Transient provisioning units use:

```text
alt-provision-<job_id>.service
```

### Future web interface

Planned host: `192.168.100.30`.

The web application remains a thin operator UI. SSH private keys, Vault
material, direct Ansible execution and direct workstation SSH access remain on
`192.168.100.17`.

The UI must call a constrained API on the controller and must not invoke
`ansible-playbook` directly.

## 3. Repository implementation

Main implementation root:

```text
deploy/alt-linux/
```

Key controller components:

```text
deploy/alt-linux/install-control-plane.sh
deploy/alt-linux/api/process_pending.py
deploy/alt-linux/control/workstationctl
deploy/alt-linux/control/alt-provision-worker
deploy/alt-linux/control/alt-job-stage
deploy/alt-linux/control/alt_deploy/controller_permissions.py
deploy/alt-linux/control/alt_deploy/job_reconcile.py
deploy/alt-linux/control/alt_deploy/job_retention.py
deploy/alt-linux/control/alt_deploy/job_stage_helper.py
deploy/alt-linux/control/alt_deploy/job_stages.py
deploy/alt-linux/control/alt_deploy/vault.py
deploy/alt-linux/ansible/playbooks/01-preflight.yml
deploy/alt-linux/ansible/playbooks/02-provision-account.yml
deploy/alt-linux/ansible/roles/preflight/
deploy/alt-linux/ansible/roles/workstation_identity/
deploy/alt-linux/ansible/roles/local_employee/
deploy/alt-linux/ansible/roles/lightdm_accounts/
deploy/alt-linux/ansible/roles/provision_verify/
tests/alt_linux/
```

The installer:

1. validates required commands before runtime mutation;
2. requires root and the `altserver` service account;
3. installs the controller package, CLI, worker and internal stage helper;
4. copies playbooks and roles without overwriting unrelated Ansible files;
5. does not copy or mutate the active Vault or Vault password file;
6. prepares private controller job and assignment directories;
7. runs the ALT-specific test suite;
8. syntax-checks both playbooks;
9. restarts the pending-registration path unit only after verification succeeds.

Required command preflight covers:

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

## 4. Authoritative CLI contract

Machine-readable commands return one JSON object:

```text
workstationctl --json machines list
workstationctl --json machines show <uuid>
workstationctl --json preflight <uuid>
workstationctl --json vault check
workstationctl --json controller permissions
workstationctl --json controller permissions repair
workstationctl --json provision preview <uuid> --vars-file <file>
workstationctl --json provision start <uuid> --vars-file <file>
workstationctl --json jobs status <job_id>
workstationctl --json jobs log <job_id>
workstationctl --json jobs reconcile
workstationctl --json jobs cleanup
workstationctl --json jobs cleanup --apply
```

Execution boundary:

- machine reads, preflight, Vault check, permission audit, preview, job reads and
  retention dry-run run as `altserver`;
- `jobs reconcile` runs as `altserver` and may update only controller job and
  assignment state;
- `jobs cleanup --apply` requires root and mutates only the private job store;
- controller permission repair requires root;
- `provision start` requires root because it creates the transient systemd job;
- the transient worker runs as `altserver` and writes private job state;
- no command returns Vault values, password hashes or private-key contents.

Provision request fields:

```json
{
  "machine_uuid": "<DMI UUID>",
  "employee_login": "i-ivanov",
  "employee_full_name": "Иванов Иван Иванович",
  "final_hostname": "buh-023",
  "profile": "standard"
}
```

The request never contains a password or password hash.

The stage helper `/usr/local/libexec/alt-job-stage` is intentionally not a
public `workstationctl` command. It is an internal localhost-only integration
boundary used by the provision playbook.

## 5. Validation rules

### Employee login

Allowed:

- lowercase ASCII letters;
- digits;
- `_` and `-`;
- maximum length enforced by the implementation;
- starts and ends with a letter or digit.

Not allowed:

- dots;
- `@`;
- uppercase protected-name variants;
- reserved accounts `root`, `ansible`, `osn-admin`.

The dot is intentionally forbidden because ALT `groupadd` rejects a matching
primary group such as `test.user`.

### Hostname

Allowed characters are lowercase ASCII letters, digits and `-`. The hostname
starts and ends with a letter or digit.

### Profile

Only `standard` is currently supported.

## 6. Preflight and SSH contract

The verified preflight checks:

- ALT Workstation K 11.x release;
- DMI UUID correspondence;
- static hostname availability;
- SSH and Python through the `ansible` account;
- passwordless sudo for `ansible`;
- required `ansible` and `osn-admin` accounts;
- available employee login;
- sufficient filesystem space;
- LightDM package and active service;
- AccountsService package and active `accounts-daemon`.

Successful preflight produces `awaiting_assignment`. Failed preflight persists
structured diagnostics and produces `preflight_failed`.

All automated direct-IP SSH paths retain:

```text
StrictHostKeyChecking=yes
UserKnownHostsFile=/home/altserver/.ssh/known_hosts_autoinstall
ProxyCommand=none
```

`ProxyCommand=none` bypasses the system-wide `sss_ssh_knownhostsproxy`
configuration without weakening strict host-key checking.

## 7. Provisioning behavior

The provision job:

1. validates the request, machine, preflight, Vault and uniqueness constraints;
2. enters `launching` after the transient unit is accepted;
3. validates worker input and enters `validating`;
4. enters `connecting` before Ansible establishes target access;
5. sets and verifies the final hostname in stage `identity`;
6. creates or reconciles the local employee in stage `employee`;
7. applies AccountsService and LightDM state in stage `login_screen`;
8. verifies hostname, account, sudo and display-manager state in `verifying`;
9. validates and records the public result in `recording`;
10. writes target and controller assignment records only after verification;
11. enters `complete` only with `state=successful`.

The sudo denial check uses `LC_ALL=C` and accepts the actual ALT text
`User <login> is not allowed to run sudo ...`. A zero return code from
`sudo -l -U` means the listing operation succeeded; it does not grant sudo.

## 8. Phase 2.3 structured job stages

Canonical sequence:

```text
created -> launching -> validating -> connecting
-> identity -> employee -> login_screen
-> verifying -> recording -> complete
```

The canonical stage names are exactly:

```text
created launching validating connecting identity employee login_screen verifying recording complete
```

Stage and state are independent:

- `state` is `queued`, `running`, `successful` or `failed`;
- `stage` identifies the last entered provisioning step;
- failure preserves the last reached stage;
- failure is not a stage;
- a successful job must end at `complete`;
- backward, skipped and unknown transitions fail closed;
- repeating the current stage on a non-terminal job is a byte-identical no-op.

Every new job begins with:

```text
state=queued
stage=created
```

and a non-empty `stage_history`. Each history entry has exactly `stage` and a
timezone-aware `entered_at` timestamp normalized to UTC. `jobs status` exposes
both the current stage and `stage_history`.

`JobRepository.update()` rejects direct writes to `stage` and `stage_history`.
All transitions go through `JobStageManager` under the common controller lock.

Ansible markers execute only on the controller with:

```text
delegate_to: localhost
become: false
run_once: true
changed_when: false
```

The helper delegates to the same stage manager. Human Ansible output and task
names are never parsed as authoritative stage state. If a marker fails, the
next role is not started.

No automatic migration exists. Pre-Phase-2.3 job directories do not receive a
synthetic history and malformed real jobs fail closed with
`job_stage_history_invalid`. Before runtime installation, back up and explicitly
remove old test job directories. Runtime installation and job cleanup require
separate approval.

## 9. LightDM and AccountsService state

Managed files on the workstation:

```text
/var/lib/AccountsService/users/ansible
/var/lib/AccountsService/users/<employee_login>
/etc/lightdm/lightdm.conf.d/90-alt-workstation.conf
/var/lib/alt-workstation/assignment.json
```

Expected AccountsService state:

```ini
# ansible
[User]
SystemAccount=true

# employee
[User]
SystemAccount=false
```

Expected LightDM drop-in:

```ini
[Seat:*]
autologin-user=
autologin-user-timeout=0
```

The role does not restart LightDM during provisioning. AccountsService is
restarted only when managed visibility files change.

## 10. Vault and secrets

Runtime Vault:

```text
/home/altserver/ansible/group_vars/vault.yml
```

Vault password file:

```text
/home/altserver/.ansible-vault-pass
```

Required encrypted variable:

```yaml
vault_employee_password_hash: "$y$..."
```

Rules:

- never commit the active `vault.yml`;
- never commit `.ansible-vault-pass`;
- never print or log the password or hash;
- keep both files mode `0600`;
- keep a protected controller-side backup outside Git.

Vault health command:

```bash
sudo -u altserver workstationctl --json vault check
```

## 11. Controller permission contract

Expected owner, group, mode and object type:

| Path | Owner | Group | Mode | Type |
| --- | --- | --- | --- | --- |
| `/var/lib/alt-deploy` | `altserver` | `altserver` | `0700` | directory |
| `/var/lib/alt-deploy/jobs` | `altserver` | `altserver` | `0700` | directory |
| `/var/lib/alt-deploy/assignments` | `altserver` | `altserver` | `0700` | directory |
| `/srv/alt-deploy/registration` | `altserver` | `altserver` | `0700` | directory |
| `/home/altserver/.ssh` | `altserver` | `altserver` | `0700` | directory |
| `/home/altserver/ansible/group_vars/vault.yml` | `altserver` | `altserver` | `0600` | regular file |
| `/home/altserver/.ansible-vault-pass` | `altserver` | `altserver` | `0600` | regular file |

Read-only audit:

```bash
sudo -u altserver workstationctl --json controller permissions
```

Root-only repair:

```bash
sudo workstationctl --json controller permissions repair
```

Repair validates all paths before mutation, blocks on missing paths, symbolic
links or unexpected types, uses no-follow file descriptors, changes only
owner/group/mode and never creates missing Vault files.

## 12. Job reconciliation after controller restart

Manual command:

```bash
sudo -u altserver workstationctl --json jobs reconcile
```

Reconciliation:

- holds the common `workstationctl.lock`;
- considers only jobs in `queued` or `running`;
- verifies the exact unit `alt-provision-<job_id>.service`;
- queries `LoadState`, `ActiveState` and `SubState`;
- never follows arbitrary unit names from job state;
- does not contact or mutate the workstation directly.

Verified outcomes:

### `still_running`

An active unit is reported in `unchanged`. The job record remains byte-for-byte
unchanged.

### `queued_recoverable`

A queued job without a unit keeps `stage=created`. A queued job whose recorded
unit is missing keeps `stage=launching` and the recorded unit. Both become:

```text
state=failed
error_code=worker_not_started
retryable=true
action=queued_recoverable
```

### `worker_lost`

A running job whose unit disappeared before producing `result.json` becomes
`failed` with `error_code=worker_lost`. Its real stage, such as `employee`, is
preserved in both `stage` and `stage_history`.

### `result_recovered`

Recovery is accepted only from:

```text
state=running
stage=recording
```

The result is validated with the worker contract, assignment is written
idempotently, and `JobStageManager.advance_unlocked()` records
`recording -> complete` with `state=successful`.

A result found at any other stage produces `job_reconcile_invalid_stage` before
reading the result or writing an assignment.

### `result_rejected`

Malformed JSON or a result that fails verification produces:

```text
state=failed
stage=recording
error_code=invalid_provision_result
retryable=true
action=result_rejected
```

The original result is retained and no assignment is written.

Reconciliation is explicit. No automatic boot service invokes it yet.

## 13. Phase 2.2 job and log retention

Implementation: `deploy/alt-linux/control/alt_deploy/job_retention.py`.

The verified policy is:

- successful and failed jobs are retained for 90 days;
- logs are archived after 14 days from terminal completion;
- the archive is `ansible.log.gz` mode `0600`;
- active `queued` and `running` jobs are never archived or deleted;
- assignment records are retained independently;
- job-directory and log access use no-follow checks;
- malformed stage history fails closed and is never omitted or deleted.

Dry-run:

```bash
sudo -u altserver workstationctl --json jobs cleanup
```

Apply:

```bash
sudo workstationctl --json jobs cleanup --apply
```

No automatic cleanup service is installed.

## 14. Verified reference run

Reference target:

```text
UUID: 53b03180-5d78-11f0-bd95-f027db877a00
IP at validation time: 192.168.101.56
MAC: c0:9b:f4:62:54:e5
Hostname: alt-auto-test
Employee: test-user
Profile: standard
Successful job: job-20260717T112903Z-71b5afe0
```

Verified result:

- job state `successful` and stage `complete`;
- all 38 Ansible tasks completed, `failed=0`;
- controller and target assignment records exist;
- machine derived status is `assigned`;
- repeated preview is blocked with `machine_already_assigned`;
- employee has its own group and home mode `0700`;
- employee is not in `wheel` and has no sudo permission;
- `ansible` remains usable with passwordless sudo;
- `ansible` has `SystemAccount=true`;
- employee has `SystemAccount=false`;
- LightDM autologin is disabled;
- all state survived reboot;
- graphical LightDM login successfully opened Plasma.

The assigned reference UUID must not be provisioned again. Release and
reassignment require a dedicated workflow.

## 15. Machine state model

Displayed machine state is derived from registration, latest preflight, active
job and assignment.

Relevant states:

```text
ready
preflight_failed
awaiting_assignment
assigned
```

A successful assignment produces `assigned` without rewriting the original
registration record. Repeated preview returns `machine_already_assigned`.

Machine list/show fail closed when a real job has malformed stage history; the
job is not silently omitted from derived state.

## 16. Verification baseline

Use the latest successful full command output as the exact test-count baseline;
do not rely on an old hard-coded count in documentation.

Required verification after a behavior phase:

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

The full repository suite contains unrelated OpenVPN tests that require
`/etc/openvpn/vpnctl.env`. For this workstream use `tests/alt_linux` unless that
environment is intentionally prepared.

## 17. Safe operational commands

```bash
cd /home/altserver/web_ovpn-src/.worktrees/alt-workstation-mvp
.venv/bin/python -m pytest -q tests/alt_linux

sudo -u altserver workstationctl --json machines list
sudo -u altserver workstationctl --json machines show <uuid>
sudo -u altserver workstationctl --json vault check
sudo -u altserver workstationctl --json controller permissions
sudo -u altserver workstationctl --json jobs reconcile
sudo -u altserver workstationctl --json jobs cleanup
```

Install or update controller runtime only with explicit approval:

```bash
sudo bash deploy/alt-linux/install-control-plane.sh \
  --rollback-backup-id <backup-id>
```

Do not rerun `provision start` for the assigned reference machine.

## 18. Runtime rollout boundary for Phase 2.3

The repository implementation is complete, but existing runtime jobs are not
compatible with the strict non-empty history requirement.

Before rollout:

1. verify the complete ALT suite and syntax gates;
2. stop creating new provision jobs;
3. back up `/var/lib/alt-deploy/jobs/` without printing private content;
4. review active jobs and reconcile them under the old runtime if required;
5. explicitly remove old test job directories only after approval;
6. install the controller through `install-control-plane.sh`;
7. create a new disposable test job on a non-assigned machine;
8. verify `stage_history`, markers, failure preservation and reconciliation.

No automatic migration exists and rollout must not synthesize history for old
jobs. The assigned UUID `53b03180-5d78-11f0-bd95-f027db877a00` remains excluded
from any new provisioning test.

## 19. Historical differences

Do not copy obsolete assumptions into new code:

- SDDM: verified implementation uses LightDM and AccountsService;
- dotted employee logins are rejected;
- examples use `i-ivanov` or `i_ivanov`;
- final displayed success state is `assigned`;
- Vault loading remains explicit through `vars_files`;
- automated SSH retains `ProxyCommand=none`;
- `provision start` remains root-only;
- sudo denial verification uses `LC_ALL=C` and actual ALT denial text;
- `stage=ansible` and `stage=reconcile` are historical and not valid Phase 2.3
  stages.

## 20. Continuation document

Remaining work and acceptance checks are maintained in:

```text
docs/ALT_WORKSTATION_PROVISIONING_NEXT_STEPS.md
```

## OR-3P2 verified repository state

OR-3P2 machine registry lifecycle is implemented and verified in PR #22.
It adds read-only removal preview, root-only audited archive apply,
generation-aware re-registration, shared API lifecycle admission,
pending-processor race protection and the register-only workstation helper.

The implementation has not been installed on controller `192.168.100.17`.
OR-3P3 is the mandatory next operational stage: repository completion requires
PR #24 verification and merge, while the live gate additionally requires the
dedicated installer plus successful create/verify/rehearse for one exact backup
ID. OR-3P4 remains blocked until that ID is passed to the guarded control-plane
installer. Reference workstation `192.168.101.111` remains immutable.

Operational details: `docs/ALT_OR3P2_MACHINE_REGISTRY_LIFECYCLE.md`.
