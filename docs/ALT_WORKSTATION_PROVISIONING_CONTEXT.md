# ALT Workstation Provisioning — verified implementation context

Status: verified end to end on 2026-07-17 and subsequently hardened through
Phase 1 installer and Vault-health work.

Repository: `BorisDruzak/web_ovpn`

Implementation branch: `feat/alt-workstation-provisioning-mvp`

This document is the operational source of truth for the ALT Workstation
provisioning control plane. Historical design and implementation-plan documents
remain useful for intent, but this file takes precedence when they differ.

## 1. Purpose and current result

The implemented MVP takes an ALT Workstation K 11.2 computer from successful
registration through non-mutating preflight and operator-approved local account
provisioning.

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

The first complete physical-machine run succeeded, survived reboot and was
verified through an actual graphical login to Plasma.

## 2. Deployment architecture

### Controller

Host: `192.168.100.17`

Service account: `altserver`

Responsibilities:

- machine registration processing;
- SSH known-host handling;
- `workstationctl` CLI;
- Ansible playbooks and roles;
- Ansible Vault and non-secret Vault health checks;
- provision jobs, logs, results and assignments;
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

The web application must remain a thin operator UI. SSH private keys, Vault
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
deploy/alt-linux/control/alt_deploy/
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

1. validates all required controller commands before any runtime mutation;
2. requires root and the `altserver` service account;
3. installs the controller package, CLI and worker;
4. copies playbooks and roles without overwriting unrelated Ansible files;
5. does not copy or mutate the active Vault or Vault password file;
6. runs the ALT-specific test suite;
7. syntax-checks both playbooks;
8. restarts the pending-registration path unit only after verification succeeds.

Required command preflight currently covers:

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
workstationctl --json provision preview <uuid> --vars-file <file>
workstationctl --json provision start <uuid> --vars-file <file>
workstationctl --json jobs status <job_id>
workstationctl --json jobs log <job_id>
```

Execution boundary:

- list, show, preflight, Vault check, preview and job reads run as `altserver`;
- `provision start` requires root because it creates and launches the transient
  systemd job;
- the transient worker runs with the constrained controller runtime and writes
  private job state.

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

The dot is intentionally forbidden because ALT `groupadd` rejects a matching
primary group such as `test.user`.

### Hostname

Allowed characters are lowercase ASCII letters, digits and `-`. The hostname
must start and end with a letter or digit.

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

Successful preflight produces `awaiting_assignment`. Failed preflight persists
structured diagnostics and produces `preflight_failed`.

All automated SSH paths explicitly pass `ProxyCommand=none`. This bypasses the
system-wide `sss_ssh_knownhostsproxy` configuration without weakening strict
host-key checking or the isolated autoinstall known-hosts file.

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
13. validates the structured public result before accepting the job as
    successful.

The sudo denial check uses `LC_ALL=C` and accepts the actual ALT sudo text
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
- use a rotated production password if a previous value appeared in chat or
  logs;
- keep a protected controller-side Vault backup outside Git.

The repository contains only `vault.yml.example`.

### Vault health command

Run as `altserver`:

```bash
sudo -u altserver workstationctl --json vault check
```

The command checks:

- Vault file existence;
- Vault password file existence;
- ownership by the executing service account;
- mode `0600` for both files;
- the Ansible Vault header;
- successful `ansible-vault view` decryption;
- presence of `vault_employee_password_hash`;
- yescrypt prefix `$y$`.

A healthy response contains only boolean checks. An unhealthy response uses
`error.code=vault_unhealthy` with boolean diagnostics and exit code `7`.
Neither response contains decrypted YAML, the hash or the Vault password.

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

The ALT-specific suite has been expanded beyond the original `80 passed`
baseline with documentation, installer dependency, Vault-preservation and Vault
health regression coverage.

The latest compact controller verification after the Phase 1.3 implementation
reported:

```text
vault check tests               PASS
all ALT tests                   PASS
Python compile                  PASS
installer syntax                PASS
preflight playbook              PASS
provision playbook              PASS
git diff check                  PASS
clean worktree                  PASS
```

Use the next local run to record the exact updated pytest count after the latest
negative Vault regression and documentation synchronization.

The full repository suite contains unrelated OpenVPN tests that require
`/etc/openvpn/vpnctl.env`. For ALT provisioning work, use `tests/alt_linux`
unless that environment is intentionally prepared.

## 12. Machine state model

The displayed machine status is derived from registration data, latest
preflight, active job and assignment.

Relevant states:

```text
ready
preflight_failed
awaiting_assignment
assigned
```

When a successful assignment exists, `MachineRepository` derives
`status=assigned` without rewriting the original registration record. Repeated
preview checks assignment existence before readiness and returns
`machine_already_assigned`.

## 13. Historical documentation differences

Do not copy these obsolete historical assumptions into new code:

- SDDM: the verified implementation uses LightDM and AccountsService;
- dotted employee logins: dots are rejected;
- examples such as `i.ivanov` must use `i-ivanov` or `i_ivanov`;
- the final displayed success state is `assigned`;
- Vault loading remains explicit in the provision playbook;
- automated SSH continues to set `ProxyCommand=none`;
- `provision start` remains root-only;
- sudo denial verification uses `LC_ALL=C` and the real ALT denial text.

## 14. Safe verification commands

Controller checks:

```bash
cd /home/altserver/web_ovpn-src/.worktrees/alt-workstation-mvp
.venv/bin/python -m pytest -q tests/alt_linux

python3 -m py_compile \
  deploy/alt-linux/control/alt_deploy/*.py \
  deploy/alt-linux/api/process_pending.py

bash -n deploy/alt-linux/install-control-plane.sh

git diff --check

ANSIBLE_CONFIG="$PWD/deploy/alt-linux/ansible/ansible.cfg" \
  ansible-playbook --syntax-check \
  deploy/alt-linux/ansible/playbooks/01-preflight.yml

ANSIBLE_CONFIG="$PWD/deploy/alt-linux/ansible/ansible.cfg" \
  ansible-playbook --syntax-check \
  deploy/alt-linux/ansible/playbooks/02-provision-account.yml
```

Install or update controller runtime:

```bash
sudo bash deploy/alt-linux/install-control-plane.sh
```

Read controller state without changing a workstation:

```bash
sudo -u altserver workstationctl --json machines list
sudo -u altserver workstationctl --json machines show <uuid>
sudo -u altserver workstationctl --json vault check
```

Do not rerun `provision start` for an already assigned machine. Implement and
use an explicit release/reassignment workflow in a later stage.

## 15. Continuation document

The ordered remaining work, acceptance checks, hardening tasks and future roles
are maintained in:

```text
docs/ALT_WORKSTATION_PROVISIONING_NEXT_STEPS.md
```
