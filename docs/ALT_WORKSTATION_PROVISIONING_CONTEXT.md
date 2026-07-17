# ALT Workstation Provisioning — verified implementation context

Status: verified end to end on 2026-07-17.

Repository: `BorisDruzak/web_ovpn`

Implementation branch: `feat/alt-workstation-provisioning-mvp`

This document is the current operational source of truth for the ALT Workstation provisioning control plane. The earlier design and implementation-plan documents remain useful for intent and history, but some details in them are obsolete. In particular, the real target uses LightDM with AccountsService rather than SDDM, and local employee logins must not contain a dot.

## 1. Purpose and current result

The implemented MVP takes an ALT Workstation K 11.2 computer from successful registration through non-mutating preflight and operator-approved local account provisioning.

Verified flow:

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
  -> asynchronous provision job
  -> final verification
  -> assignment records
  -> assigned
```

The first complete physical-machine run succeeded, survived reboot, and was verified through an actual graphical login to Plasma.

## 2. Deployment architecture

### Controller

Host: `192.168.100.17`

Service account: `altserver`

Responsibilities:

- machine registration processing;
- SSH known-host handling;
- `workstationctl` CLI;
- Ansible playbooks and roles;
- Ansible Vault;
- provision jobs, logs, results and assignments;
- constrained API in a future stage.

Important runtime paths:

```text
/usr/local/sbin/workstationctl
/usr/local/libexec/alt-provision-worker
/opt/alt-deploy-control/alt_deploy/
/opt/alt-deploy-api/process_pending.py
/home/altserver/ansible/
/home/altserver/.ansible-vault-pass
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

### Future web interface

Planned host: `192.168.100.30`.

The web application must be a thin operator UI. SSH private keys, Vault material, direct Ansible execution and direct workstation SSH access must remain on `192.168.100.17`.

The UI must call a constrained API on the controller. It must not invoke `ansible-playbook` directly.

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
deploy/alt-linux/control/alt_deploy/
deploy/alt-linux/ansible/playbooks/01-preflight.yml
deploy/alt-linux/ansible/playbooks/02-provision-account.yml
deploy/alt-linux/ansible/roles/preflight/
deploy/alt-linux/ansible/roles/workstation_identity/
deploy/alt-linux/ansible/roles/local_employee/
deploy/alt-linux/ansible/roles/lightdm_accounts/
deploy/alt-linux/ansible/roles/provision_verify/
tests/alt_linux/
```

The installer copies the controller package and Ansible project into their runtime locations, runs the ALT-specific test suite, performs syntax checks for both playbooks and restarts the pending-registration path unit.

## 4. Authoritative CLI contract

Machine-readable commands return one JSON object:

```text
workstationctl --json machines list
workstationctl --json machines show <uuid>
workstationctl --json preflight <uuid>
workstationctl --json provision preview <uuid> --vars-file <file>
workstationctl --json provision start <uuid> --vars-file <file>
workstationctl --json jobs status <job_id>
workstationctl --json jobs log <job_id>
```

Execution boundary:

- list, show, preflight, preview and job reads run as `altserver`;
- `provision start` requires root because it creates and launches the transient systemd job;
- the transient worker runs with the constrained controller runtime and writes private job state.

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

The request must never contain a password or password hash.

## 5. Current validation rules

### Employee login

Allowed:

- lowercase ASCII letters;
- digits;
- `_` and `-`;
- maximum length enforced by the implementation;
- must start and end with a letter or digit.

Not allowed:

- dots;
- `@`;
- uppercase protected-name variants;
- reserved accounts `root`, `ansible`, `osn-admin`.

The dot is intentionally forbidden because ALT `groupadd` rejects a primary group such as `test.user`. The role creates a matching primary group for the employee.

### Hostname

Allowed characters are lowercase ASCII letters, digits and `-`. It must start and end with a letter or digit.

### Profile

Only `standard` is currently supported.

## 6. Preflight contract

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

Successful preflight produces `awaiting_assignment`. Failed preflight persists structured diagnostics and produces `preflight_failed`.

All automated SSH paths explicitly pass `ProxyCommand=none`. This prevents the system-wide `sss_ssh_knownhostsproxy` configuration from intermittently causing SSH banner-exchange timeouts when connecting directly by registered IP. Strict host-key checking and the isolated autoinstall known-hosts file remain enabled.

## 7. Provisioning behavior

The provision job:

1. validates the request, machine, preflight, Vault and uniqueness constraints;
2. sets and verifies the final hostname;
3. creates or reconciles the matching local primary group;
4. creates or reconciles the local employee account;
5. applies the Vault-provided yescrypt password hash;
6. verifies the employee is not in `wheel`;
7. verifies sudo policy denies the employee;
8. hides only `ansible` through AccountsService;
9. keeps the employee visible through AccountsService;
10. disables LightDM autologin through a managed drop-in;
11. verifies LightDM, AccountsService, account and sudo state;
12. writes target and controller assignment records only after verification;
13. validates the structured public result before accepting the job as successful.

The sudo denial check uses `LC_ALL=C` and accepts the actual ALT sudo output `User <login> is not allowed to run sudo ...`. `sudo -l -U` returning code zero means the listing operation itself succeeded and does not imply that the user has sudo authorization.

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

The role does not restart LightDM during provisioning. AccountsService is restarted only when managed account visibility files change.

## 9. Vault and secrets

Runtime Vault:

```text
/home/altserver/ansible/group_vars/vault.yml
```

Vault password file:

```text
/home/altserver/.ansible-vault-pass
```

Required variable:

```yaml
vault_employee_password_hash: "$y$..."
```

`02-provision-account.yml` explicitly loads `../group_vars/vault.yml` through `vars_files`. A file named `group_vars/vault.yml` is not automatically loaded for an inline host inventory unless it is referenced explicitly or associated with a matching group.

Rules:

- never commit the active `vault.yml`;
- never commit `.ansible-vault-pass`;
- never print or log the password or hash;
- keep both files mode `0600`;
- use a rotated production password if a previous value appeared in chat or logs;
- keep a protected controller-side Vault backup outside Git.

The repository contains only `vault.yml.example`.

## 10. Verified reference run

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
- controller assignment exists;
- target assignment exists;
- machine derived status is `assigned`;
- repeated preview is blocked with `machine_already_assigned`;
- employee exists with its own group and home mode `0700`;
- employee is not in `wheel` and has no sudo permission;
- `ansible` remains usable with passwordless sudo;
- `ansible` has `SystemAccount=true`;
- employee has `SystemAccount=false`;
- LightDM autologin is disabled;
- all state survived reboot;
- graphical LightDM login as the employee successfully opened Plasma;
- `ansible` was hidden and normal accounts remained available.

## 11. Current test and verification baseline

At the completed implementation point:

```text
.venv/bin/python -m pytest -q tests/alt_linux
80 passed
```

Both playbooks pass syntax checking:

```text
ansible-playbook --syntax-check deploy/alt-linux/ansible/playbooks/01-preflight.yml
ansible-playbook --syntax-check deploy/alt-linux/ansible/playbooks/02-provision-account.yml
```

The full repository test suite still has unrelated OpenVPN tests that require access to `/etc/openvpn/vpnctl.env`. For ALT provisioning work, use `tests/alt_linux` unless the OpenVPN environment is intentionally prepared.

## 12. Machine state model

The displayed machine status is derived from registration data, latest preflight, active job and assignment.

Relevant states currently observed:

```text
ready
preflight_failed
awaiting_assignment
assigned
```

When a successful assignment exists, `MachineRepository` derives `status=assigned` without rewriting the original registration record. A repeated preview checks assignment existence before readiness and returns `machine_already_assigned`.

## 13. Known documentation differences

The following details in the original approved design are stale and must not be copied into new code:

- SDDM references: the verified implementation uses LightDM and AccountsService;
- dotted employee logins: dots are now rejected;
- examples such as `i.ivanov` should become `i-ivanov` or `i_ivanov`;
- the final successful displayed state is currently `assigned`;
- Vault loading must remain explicit in the provision playbook;
- automated SSH must continue to disable the inherited SSSD ProxyCommand.

Future documentation cleanup should update the old design and plan while preserving their historical role.

## 14. Safe verification commands

Controller tests:

```bash
cd /home/altserver/web_ovpn-src/.worktrees/alt-workstation-mvp
.venv/bin/python -m pytest -q tests/alt_linux

git diff --check

ANSIBLE_CONFIG="$PWD/deploy/alt-linux/ansible/ansible.cfg" \
  ansible-playbook --syntax-check \
  deploy/alt-linux/ansible/playbooks/01-preflight.yml

ANSIBLE_CONFIG="$PWD/deploy/alt-linux/ansible/ansible.cfg" \
  ansible-playbook --syntax-check \
  deploy/alt-linux/ansible/playbooks/02-provision-account.yml
```

Install/update controller runtime:

```bash
sudo bash deploy/alt-linux/install-control-plane.sh
```

Read machine state without changing it:

```bash
sudo -u altserver workstationctl --json machines list
sudo -u altserver workstationctl --json machines show <uuid>
```

Do not rerun `provision start` for a machine that is already assigned. Implement and use an explicit release/reassignment workflow in a later stage.

## 15. Continuation document

The ordered remaining work, acceptance checks, hardening tasks and future roles are maintained in:

```text
docs/ALT_WORKSTATION_PROVISIONING_NEXT_STEPS.md
```
