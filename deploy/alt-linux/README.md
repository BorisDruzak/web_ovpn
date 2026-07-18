# ALT Workstation Provisioning

This directory contains the verified ALT Workstation K 11.2 autoinstall,
bootstrap, registration, preflight and local-account provisioning control
plane.

Authoritative documentation:

- [Verified implementation context](../../docs/ALT_WORKSTATION_PROVISIONING_CONTEXT.md)
- [Remaining work and acceptance roadmap](../../docs/ALT_WORKSTATION_PROVISIONING_NEXT_STEPS.md)
- [Autoinstall and bootstrap background](../../docs/ALT_LINUX_AUTOINSTALL.md)

## Architecture

The controller runs on `192.168.100.17` under the `altserver` service account.
It owns `workstationctl`, Ansible, SSH host-key handling, Vault, provision jobs,
logs, assignments and job reconciliation.

The future operator web interface runs on `192.168.100.30`. It must use a
constrained API on the controller and must not receive SSH private keys, Vault
material, direct Ansible execution or direct workstation SSH access.

Provisioned workstations use LightDM with AccountsService. The verified
implementation does not use SDDM.

## Controller prerequisites

Required controller facilities:

- root access through `sudo` for installation and provision start;
- local service account `altserver`;
- Python 3;
- `ansible-playbook` and `ansible-vault`;
- systemd and OpenSSH client tools;
- `mkpasswd` for initial password-hash preparation.

Before changing runtime files, the installer verifies `python3`,
`ansible-playbook`, `ansible-vault`, `systemd-run`, `install`, `cp`, `ssh`,
`ssh-keyscan` and `mkpasswd`. It then requires root and the `altserver` service
account.

## Install or update the controller

```bash
sudo bash deploy/alt-linux/install-control-plane.sh
```

The installer:

- installs `workstationctl` and the asynchronous provision worker;
- installs the Ansible project without copying an active Vault;
- prepares private job and assignment directories;
- installs the pending-registration processor;
- runs `tests/alt_linux`;
- syntax-checks `01-preflight.yml` and `02-provision-account.yml`;
- restarts `alt-deploy-process.path` only after verification succeeds.

It does not copy `.ansible-vault-pass` or create an active `vault.yml`.

## Vault setup and validation

The repository contains only:

```text
deploy/alt-linux/ansible/group_vars/vault.yml.example
```

The active encrypted files exist only on the controller:

```text
/home/altserver/ansible/group_vars/vault.yml
/home/altserver/.ansible-vault-pass
```

The provision playbook explicitly loads `../group_vars/vault.yml` through
`vars_files` and expects `vault_employee_password_hash`.

Never print the Vault password, decrypted Vault content, employee password or
employee password hash. Never commit either active secret file.

Create the private Vault password file interactively:

```bash
sudo install -o altserver -g altserver -m 0600 /dev/null \
  /home/altserver/.ansible-vault-pass

sudo -u altserver sh -c '
  read -r -s -p "Vault password: " p
  printf "\n" >&2
  printf "%s\n" "$p" > /home/altserver/.ansible-vault-pass
  unset p
'
```

Generate the yescrypt value interactively and encrypt it without displaying it:

```bash
sudo -u altserver bash -lc '
set -Eeuo pipefail
umask 077
plain=/tmp/alt-workstation-vault.yml
trap "rm -f ${plain}" EXIT
HASH=$(mkpasswd --method=yescrypt)
printf "vault_employee_password_hash: %s\n" "${HASH}" > "${plain}"
unset HASH
ANSIBLE_VAULT_PASSWORD_FILE=/home/altserver/.ansible-vault-pass \
  ansible-vault encrypt \
  "${plain}" \
  --output /home/altserver/ansible/group_vars/vault.yml
'

sudo chmod 0600 \
  /home/altserver/.ansible-vault-pass \
  /home/altserver/ansible/group_vars/vault.yml
```

Validate the complete Vault contract without displaying any secret:

```bash
sudo -u altserver workstationctl --json vault check
```

The command checks file presence, ownership, mode `0600`, the Ansible Vault
header, successful decryption, the required variable and yescrypt format. A
healthy Vault returns only boolean checks. An unhealthy Vault returns
`error.code=vault_unhealthy` and boolean diagnostics; neither response contains
the hash, decrypted YAML or Vault password.

## Controller state permissions

Expected controller permission contract:

| Path | Owner | Group | Mode | Type |
| --- | --- | --- | --- | --- |
| `/var/lib/alt-deploy` | `altserver` | `altserver` | `0700` | directory |
| `/var/lib/alt-deploy/jobs` | `altserver` | `altserver` | `0700` | directory |
| `/var/lib/alt-deploy/assignments` | `altserver` | `altserver` | `0700` | directory |
| `/srv/alt-deploy/registration` | `altserver` | `altserver` | `0700` | directory |
| `/home/altserver/.ssh` | `altserver` | `altserver` | `0700` | directory |
| `/home/altserver/ansible/group_vars/vault.yml` | `altserver` | `altserver` | `0600` | regular file |
| `/home/altserver/.ansible-vault-pass` | `altserver` | `altserver` | `0600` | regular file |

Run the read-only audit as the service account:

```bash
sudo -u altserver workstationctl --json controller permissions
```

A healthy audit returns boolean checks for existence, owner, group, mode and
object type. An unhealthy audit returns
`error.code=controller_permissions_unhealthy`. It never reads or returns file
contents.

Repair only these known paths as root:

```bash
sudo workstationctl --json controller permissions repair
```

The repair command:

- requires root;
- validates every expected path before changing any path;
- refuses missing paths, symbolic links and unexpected object types;
- does not create a missing Vault file or password file;
- opens objects with no-follow semantics and changes only owner, group and mode;
- returns the symbolic path keys that were changed, not secret contents.

A blocked repair returns
`error.code=controller_permissions_repair_blocked`. A system error during
sequential `fchown` or `fchmod` returns
`error.code=controller_permissions_repair_failed`; run the read-only audit again
to see the resulting state before retrying.

## CLI and provision request

Service-account operations:

```bash
sudo -u altserver workstationctl --json machines list
sudo -u altserver workstationctl --json machines show <uuid>
sudo -u altserver workstationctl --json preflight <uuid>
sudo -u altserver workstationctl --json vault check
sudo -u altserver workstationctl --json controller permissions
sudo -u altserver workstationctl --json provision preview <uuid> \
  --vars-file /path/to/request.json
sudo -u altserver workstationctl --json jobs status <job_id>
sudo -u altserver workstationctl --json jobs log <job_id>
sudo -u altserver workstationctl --json jobs reconcile
sudo -u altserver workstationctl --json jobs cleanup
```

`jobs reconcile` is not read-only. It may update controller-side `status.json`
and assignment records, but it does not provision or reconnect to a workstation
and does not require root.

The provision request contains no password or password hash:

```json
{
  "machine_uuid": "<uuid>",
  "employee_login": "i-ivanov",
  "employee_full_name": "Иванов Иван Иванович",
  "final_hostname": "buh-023",
  "profile": "standard"
}
```

Employee logins may contain lowercase ASCII letters, digits, `_` and `-`.
A dot is not allowed.

`provision start` requires root because it creates the transient systemd job:

```bash
sudo workstationctl --json provision start <uuid> \
  --vars-file /path/to/request.json
```

Permission repair also requires root:

```bash
sudo workstationctl --json controller permissions repair
```

Do not run `provision start` for a machine whose derived state is `assigned`.
A repeat request is rejected with `machine_already_assigned`. An explicit
release or reassignment workflow must be implemented first.

## Job reconciliation after controller restart

Run reconciliation after a controller reboot, after an unexpected transient
worker disappearance, or before creating a new job when an old job remains
`queued` or `running`:

```bash
sudo -u altserver workstationctl --json jobs reconcile
```

The command holds the common `workstationctl.lock`, checks only active jobs and
uses the exact recorded unit name `alt-provision-<job_id>.service`.

Possible actions:

- `still_running`: the unit is `active`, `activating` or `reloading`; the job
  record remains unchanged and the systemd states are returned in `unchanged`;
- `queued_recoverable`: a queued job has no recorded unit, or its recorded unit
  has `LoadState=not-found`; the job becomes `failed`, receives
  `error_code=worker_not_started` and `retryable=true`;
- `worker_lost`: a running job has no unit and no result; the job becomes
  `failed` with `stage=reconcile` and `error_code=worker_lost`;
- `result_recovered`: an inactive worker left a valid `result.json`; the result
  is validated with the same contract as the worker, the assignment is written
  idempotently, and the job becomes `successful / complete`;
- `result_rejected`: an inactive worker left malformed JSON or a result that
  fails result verification; no assignment is written, the original result file
  is retained, and the job becomes retryable failure with
  `error_code=invalid_provision_result`.

A result is never recovered while the worker is still active. Assignment-store,
systemd and invalid-unit errors are not hidden as result-validation failures.

Reconciliation is currently an explicit operator command. No automatic boot
service invokes it yet.

## Job and log retention

Retention applies only to:

```text
/var/lib/alt-deploy/jobs/<job_id>/
```

The current policy is:

- successful and failed jobs are retained for 90 days;
- their `ansible.log` files are archived after 14 days as `ansible.log.gz`;
- `queued` and `running` jobs are never archived or deleted by cleanup;
- assignment records under `/var/lib/alt-deploy/assignments/` are retained
  independently;
- cleanup does not follow symbolic links outside the jobs directory.

Review the planned actions without changing state:

```bash
sudo -u altserver workstationctl --json jobs cleanup
```

Apply the reported archive and deletion actions explicitly as root:

```bash
sudo workstationctl --json jobs cleanup --apply
```

`jobs log` transparently reads both `ansible.log` and `ansible.log.gz` and
returns `archived=true` for a gzip-backed log. No automatic cleanup service is
installed; both dry-run and apply are explicit operator commands.

## State, diagnostics, and recovery

Controller state:

```text
/srv/alt-deploy/registration/
/var/lib/alt-deploy/jobs/<job_id>/
/var/lib/alt-deploy/assignments/<uuid>.json
/home/altserver/.ssh/known_hosts_autoinstall
```

Each job directory may contain `request.json`, `status.json`, `result.json`,
`ansible.log`, `ansible.log.gz` and `provision-result.json`.

Target assignment state:

```text
/var/lib/alt-workstation/assignment.json
```

Use the CLI before reading private files directly:

```bash
sudo -u altserver workstationctl --json machines show <uuid>
sudo -u altserver workstationctl --json vault check
sudo -u altserver workstationctl --json controller permissions
sudo -u altserver workstationctl --json jobs status <job_id>
sudo -u altserver workstationctl --json jobs log <job_id>
sudo -u altserver workstationctl --json jobs reconcile
sudo -u altserver workstationctl --json jobs cleanup
```

Controller service diagnostics:

```bash
systemctl status alt-deploy-process.path --no-pager
systemctl status alt-deploy-process.service --no-pager
journalctl -u alt-deploy-process.service --no-pager -n 200
```

Automated direct-IP SSH must retain:

```text
StrictHostKeyChecking=yes
UserKnownHostsFile=/home/altserver/.ssh/known_hosts_autoinstall
ProxyCommand=none
```

`ProxyCommand=none` bypasses inherited SSSD SSH proxy configuration without
weakening strict host-key checking.

For a failed, unassigned machine, inspect the structured error and bounded job
log, correct the cause, rerun preview, and start a new job only after preview
succeeds.

Do not delete assignment JSON manually. Do not rerun provisioning for an
assigned machine. Release and reassignment require a dedicated audited
workflow.

## Repository layout

```text
deploy/alt-linux/
├── ansible/
│   ├── playbooks/
│   │   ├── 01-preflight.yml
│   │   └── 02-provision-account.yml
│   └── roles/
│       ├── preflight/
│       ├── workstation_identity/
│       ├── local_employee/
│       ├── lightdm_accounts/
│       └── provision_verify/
├── api/process_pending.py
├── control/
│   ├── alt_deploy/
│   │   ├── controller_permissions.py
│   │   ├── job_reconcile.py
│   │   ├── job_retention.py
│   │   └── vault.py
│   ├── workstationctl
│   └── alt-provision-worker
├── install-control-plane.sh
├── autoinstall/
├── bootstrap/
├── ssh/
└── systemd/
```

## Verification

Run only the ALT provisioning suite by default. The unrelated OpenVPN tests
require `/etc/openvpn/vpnctl.env`.

```bash
.venv/bin/python -m pytest -q tests/alt_linux

ANSIBLE_CONFIG="$PWD/deploy/alt-linux/ansible/ansible.cfg" \
  ansible-playbook --syntax-check \
  deploy/alt-linux/ansible/playbooks/01-preflight.yml

ANSIBLE_CONFIG="$PWD/deploy/alt-linux/ansible/ansible.cfg" \
  ansible-playbook --syntax-check \
  deploy/alt-linux/ansible/playbooks/02-provision-account.yml

git diff --check
```

## Autoinstall boot parameter

Append to the stock ALT installer kernel command line:

```text
ai curl=http://192.168.100.17:8087/metadata/
```

The current profile clears the first detected disk. Use a disposable target
with one disk until disk-selection hardening is complete.
