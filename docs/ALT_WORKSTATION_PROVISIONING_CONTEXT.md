# ALT Workstation Provisioning — verified implementation context

Status: verified end to end on 2026-07-17 and subsequently hardened through
Phase 1 controller work and Phase 2.1 job reconciliation.

Repository: `BorisDruzak/web_ovpn`

Implementation branch: `feat/alt-workstation-provisioning-mvp`

This document is the operational source of truth for the ALT Workstation
provisioning control plane. Historical design and implementation-plan documents
remain useful for intent, but this file takes precedence when they differ.

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
- provision jobs, logs, results, assignments and recovery;
- constrained API in a future stage.

Important runtime paths:

```text
/usr/local/sbin/workstationctl
/usr/local/libexec/alt-provision-worker
/opt/alt-deploy-control/alt_deploy/
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

Static deployment HTTP service: port `8087`.

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

Key components:

```text
deploy/alt-linux/install-control-plane.sh
deploy/alt-linux/api/process_pending.py
deploy/alt-linux/control/workstationctl
deploy/alt-linux/control/alt-provision-worker
deploy/alt-linux/control/alt_deploy/controller_permissions.py
deploy/alt-linux/control/alt_deploy/job_reconcile.py
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
3. installs the controller package, CLI and worker;
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
```

Execution boundary:

- machine reads, preflight, Vault check, permission audit, preview and job reads
  run as `altserver`;
- `jobs reconcile` runs as `altserver` and may update only controller job and
  assignment state;
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
2. sets and verifies the final hostname;
3. creates or reconciles the local primary group;
4. creates or reconciles the employee account;
5. applies the Vault-provided yescrypt password hash;
6. verifies the employee is not in `wheel`;
7. verifies sudo policy denies the employee;
8. hides only `ansible` through AccountsService;
9. keeps the employee visible through AccountsService;
10. disables LightDM autologin through a managed drop-in;
11. verifies LightDM, AccountsService, account and sudo state;
12. writes target and controller assignment records only after verification;
13. validates the structured public result before accepting success.

The sudo denial check uses `LC_ALL=C` and accepts the actual ALT text
`User <login> is not allowed to run sudo ...`. A zero return code from
`sudo -l -U` means the listing operation succeeded; it does not grant sudo.

## 8. LightDM and AccountsService state

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

## 9. Vault and secrets

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

`02-provision-account.yml` explicitly loads `../group_vars/vault.yml` through
`vars_files`. An inline host inventory does not load this file automatically.

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

It verifies file presence, owner, mode, Vault header, decryption, required
variable and yescrypt prefix `$y$`. An unhealthy response uses
`error.code=vault_unhealthy`; no secret value is returned.

## 10. Controller permission contract

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

Repair validates all seven paths before mutation, blocks on missing paths,
symbolic links or unexpected types, uses no-follow file descriptors, changes
only owner/group/mode and never creates missing Vault files.

## 11. Job reconciliation after controller restart

Manual command:

```bash
sudo -u altserver workstationctl --json jobs reconcile
```

Reconciliation:

- holds the common `workstationctl.lock` used by provision preview/start;
- considers only jobs in `queued` or `running`;
- verifies the exact recorded unit name `alt-provision-<job_id>.service`;
- queries `LoadState`, `ActiveState` and `SubState` through `systemctl show`;
- never follows arbitrary unit names from job state;
- does not contact or mutate the workstation directly.

Verified outcomes:

### `still_running`

A unit in `active`, `activating` or `reloading` is reported in `unchanged` with
its systemd states. The job record remains byte-for-byte unchanged.

### `queued_recoverable`

A queued job with no recorded unit, or a recorded unit with
`LoadState=not-found`, becomes:

```text
state=failed
stage=reconcile
error_code=worker_not_started
retryable=true
action=queued_recoverable
```

A queued job without a recorded unit does not invoke `systemctl`.

### `worker_lost`

A running job whose unit disappeared before producing `result.json` becomes:

```text
state=failed
stage=reconcile
error_code=worker_lost
action=worker_lost
```

It no longer blocks a new preview through `active_for_machine`.

### `result_recovered`

When the worker is inactive and a `result.json` exists:

1. JSON is read as an object;
2. the same `_validate_result` contract used by the worker is applied;
3. assignment is written through the idempotent `AssignmentRepository`;
4. the job becomes `successful / complete`;
5. `finished_at` is taken from the validated `completed_at` field.

No result is recovered while its worker remains active.

### `result_rejected`

Malformed JSON or a result that fails verification produces:

```text
state=failed
stage=reconcile
error_code=invalid_provision_result
retryable=true
action=result_rejected
```

The original `result.json` is retained for diagnostics and no assignment is
written. Assignment conflicts, invalid systemd unit records and systemd query
failures remain explicit errors rather than being hidden as result rejection.

Reconciliation is currently an explicit operator command. No automatic boot
service invokes it yet.

## 12. Verified reference run

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

## 13. Machine state model

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

## 14. Verification baseline

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

## 15. Safe operational commands

```bash
cd /home/altserver/web_ovpn-src/.worktrees/alt-workstation-mvp
.venv/bin/python -m pytest -q tests/alt_linux

sudo -u altserver workstationctl --json machines list
sudo -u altserver workstationctl --json machines show <uuid>
sudo -u altserver workstationctl --json vault check
sudo -u altserver workstationctl --json controller permissions
sudo -u altserver workstationctl --json jobs reconcile
```

Install or update controller runtime only with explicit approval:

```bash
sudo bash deploy/alt-linux/install-control-plane.sh
```

Repair known permission deviations only after reviewing the audit:

```bash
sudo workstationctl --json controller permissions repair
```

Do not rerun `provision start` for the assigned reference machine.

## 16. Historical differences

Do not copy obsolete assumptions into new code:

- SDDM: verified implementation uses LightDM and AccountsService;
- dotted employee logins are rejected;
- examples use `i-ivanov` or `i_ivanov`;
- final displayed success state is `assigned`;
- Vault loading remains explicit through `vars_files`;
- automated SSH retains `ProxyCommand=none`;
- `provision start` remains root-only;
- sudo denial verification uses `LC_ALL=C` and actual ALT denial text.

## 17. Continuation document

Remaining work and acceptance checks are maintained in:

```text
docs/ALT_WORKSTATION_PROVISIONING_NEXT_STEPS.md
```
