# ALT Workstation Provisioning

This directory contains the verified ALT Workstation K 11.2 autoinstall,
bootstrap, registration, preflight and local-account provisioning control
plane.

Authoritative documentation:

- [Verified implementation context](../../docs/ALT_WORKSTATION_PROVISIONING_CONTEXT.md)
- [Remaining work and acceptance roadmap](../../docs/ALT_WORKSTATION_PROVISIONING_NEXT_STEPS.md)
- [Autoinstall and bootstrap background](../../docs/ALT_LINUX_AUTOINSTALL.md)
- [OR-3P1 pilot rollout](../../docs/ALT_OR3P1_PILOT_ROLLOUT.md)
- [OR-3P3 coordinated backup and restore](../../docs/ALT_OR3P3_COORDINATED_BACKUP_RESTORE.md)

## Architecture

The controller runs on `192.168.100.17` under the `altserver` service account.
It owns `workstationctl`, Ansible, SSH host-key handling, Vault, provision jobs,
structured stage history, logs, assignments, retention and reconciliation.

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

The public installer requires root before loading deployment logic. Before the
first runtime mutation, the installer validates all required commands, including
`systemd-run` and `ssh-keyscan`, every source asset, the `altserver` account,
Python and shell syntax, `tests/alt_linux`, active jobs, Vault, controller
permissions, SSH identity, static autoinstall assets, the pending registration
queue and processor inactivity.

## Install or update the controller

Install the independent OR-3P3 utility first:

```bash
sudo bash deploy/alt-linux/install-backup-tool.sh
```

Create, verify and rehearse one exact rollback bundle as described in the
[OR-3P3 runbook](../../docs/ALT_OR3P3_COORDINATED_BACKUP_RESTORE.md). Then pass
that exact ID to the control-plane installer:

```bash
sudo bash deploy/alt-linux/install-control-plane.sh \
  --rollback-backup-id backup-YYYYMMDDTHHMMSSZ-xxxxxxxx
```

The installer:

- makes exactly one read-only `rehearse-status` call before repository tests or
  runtime mutation;
- blocks before mutation when the bundle/evidence is stale, a provision job is
  active, a real job is malformed, the pending registration queue is non-empty,
  Vault or permissions are unhealthy, SSH/static prerequisites are unsafe, or
  the processor is active;
- creates a durable rollout marker and uses an ephemeral guard permit for service
  activation;
- installs `workstationctl`, the provision worker, the stage helper, the
  allowlisted static server, both API programs, all four systemd units, the
  served bootstrap scripts and the Ansible project;
- preserves active Vault files, SSH identity, the active authorized key, ISO
  metadata archives, jobs, assignments, registrations and every backup-tool
  path;
- stops only the path watcher, registration API and allowlisted static service
  during the maintenance window;
- performs `daemon-reload`, enables the three long-lived units and removes the
  rollout marker only after `controller readiness` passes.

A failed rollout revokes activation, leaves the durable marker and keeps the
maintenance services stopped for emergency full restore.

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
header, successful decryption, the required variable and yescrypt format. An
unhealthy Vault returns `error.code=vault_unhealthy` and boolean diagnostics;
neither response contains the hash, decrypted YAML or Vault password.

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

Read-only audit:

```bash
sudo -u altserver workstationctl --json controller permissions
sudo -u altserver workstationctl --json jobs active
sudo -u altserver workstationctl --json controller readiness
```

An unhealthy audit returns `error.code=controller_permissions_unhealthy` with
boolean diagnostics and never returns file contents.

Repair only these known paths as root:

```bash
sudo workstationctl --json controller permissions repair
```

Repair requires root, refuses missing paths, symbolic links and unexpected
object types, and returns `controller_permissions_repair_blocked` when the
pre-mutation safety check fails. It uses no-follow file descriptors, changes
only owner, group and mode, and does not create a missing Vault file or password
file. A system error during a permitted repair returns
`controller_permissions_repair_failed`; run the read-only audit again before
retrying.

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

Employee logins may contain lowercase ASCII letters, digits, `_` and `-`. A dot
is not allowed.

`provision start` requires root because it creates the transient systemd job:

```bash
sudo workstationctl --json provision start <uuid> \
  --vars-file /path/to/request.json
```

Do not run `provision start` for a machine whose derived state is `assigned`.
A repeat request is rejected with `machine_already_assigned`. An explicit
release or reassignment workflow must be implemented first.

## Structured provision job stages

Phase 2.3 uses one strict, timestamped sequence:

```text
created launching validating connecting identity employee login_screen verifying recording complete
```

The state and stage have different meanings:

- `state` is one of `queued`, `running`, `successful` or `failed`;
- `stage` is the last successfully entered provisioning step;
- failure preserves the last reached stage rather than creating a failure
  stage;
- successful jobs must end at `stage=complete`;
- skipped, backward and unknown transitions fail closed.

Every new job has a non-empty `stage_history`. Each history entry contains only:

```json
{
  "stage": "employee",
  "entered_at": "2026-07-18T12:00:00+00:00"
}
```

`jobs status` returns the current stage and the complete `stage_history`.
Repeating the current stage on a non-terminal job is a byte-for-byte no-op.
Direct `stage` or `stage_history` updates through `JobRepository.update()` are
forbidden.

Ansible role markers call the internal controller helper:

```text
/usr/local/libexec/alt-job-stage
```

This helper is not a public operator or API command. Marker tasks use
`delegate_to: localhost`, `become: false`, `run_once: true` and
`changed_when: false`. A failed marker stops the next role; authoritative stage
state is never derived by parsing human Ansible output or task names.

No automatic migration exists. Existing pre-Phase-2.3 job directories are not
repaired or synthesized. Before runtime rollout, back up and explicitly remove
old test jobs under `/var/lib/alt-deploy/jobs/`, then install the strict schema
only after separate approval. The assigned reference UUID must not be
provisioned again.

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

- `still_running`: an active unit is reported without changing the job;
- `queued_recoverable`: the job becomes `failed` while preserving `created` or
  `launching`, with `error_code=worker_not_started` and `retryable=true`;
- `worker_lost`: the running job becomes `failed` while preserving its current
  real stage, with `error_code=worker_lost`;
- `result_recovered`: only `state=running, stage=recording` may recover a valid
  inactive-worker result; recovery records `recording -> complete`, writes the
  assignment and makes the job successful;
- `result_rejected`: malformed or invalid results make the job a retryable
  failure while preserving `recording`, with
  `error_code=invalid_provision_result`; no assignment is written.

A result is never recovered while the worker is active. Recovery from any stage
other than `recording` fails with `job_reconcile_invalid_stage`. Assignment,
systemd and invalid-unit errors are not hidden as result-validation failures.

Reconciliation remains an explicit operator command. No automatic boot service
invokes it yet.

## Job and log retention

Retention applies only to:

```text
/var/lib/alt-deploy/jobs/<job_id>/
```

The current policy is:

- successful and failed jobs are retained for 90 days;
- their `ansible.log` files are archived after 14 days as `ansible.log.gz`;
- `queued` and `running` jobs are never archived or deleted by cleanup;
- assignment records are retained independently;
- cleanup does not follow symbolic links outside the jobs directory;
- malformed real stage history fails closed with
  `job_stage_history_invalid`; it is not skipped, repaired or deleted.

Dry-run:

```bash
sudo -u altserver workstationctl --json jobs cleanup
```

Apply explicitly as root:

```bash
sudo workstationctl --json jobs cleanup --apply
```

`jobs log` transparently reads both `ansible.log` and `ansible.log.gz`. No
automatic cleanup service is installed.

## Legacy stale registration recovery

For the narrowly defined legacy conflict where an assigned test machine has a
regular record in `registration/failed/` with JSON status
`awaiting_assignment`, use the audited recovery workflow:

```bash
sudo -u altserver workstationctl --json machines \
  recover-stale-registration preview <uuid>
sudo workstationctl --json machines recover-stale-registration apply <uuid> \
  --reason "Clear approved legacy failed registration"
```

Apply is root-only, preserves the original record bytes and a SHA-256 manifest
under `machine-archives/`, and leaves assignments and jobs unchanged. It is not
a release or reassignment operation. Do not edit registration JSON directly.

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

For a failed, unassigned machine, inspect the structured error and bounded job
log, correct the cause, rerun preview, and start a new job only after preview
succeeds.

Do not delete assignment JSON manually. Release and reassignment require a
dedicated audited workflow.

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
├── api/
│   ├── register_api.py
│   └── process_pending.py
├── control/
│   ├── alt-job-stage
│   ├── alt-provision-worker
│   ├── workstationctl
│   └── alt_deploy/
│       ├── controller_permissions.py
│       ├── controller_readiness.py
│       ├── job_reconcile.py
│       ├── job_retention.py
│       ├── job_stage_helper.py
│       ├── job_stages.py
│       └── vault.py
├── install-control-plane.sh
├── install-control-plane-lib.sh
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

python3 -m py_compile \
  deploy/alt-linux/control/alt_deploy/*.py \
  deploy/alt-linux/api/static_server.py \
  deploy/alt-linux/api/register_api.py \
  deploy/alt-linux/api/process_pending.py \
  deploy/alt-linux/backup/alt_deploy_backup/*.py \
  deploy/alt-linux/backup/alt-deploy-backup \
  deploy/alt-linux/control/alt-job-stage

bash -n deploy/alt-linux/install-backup-tool.sh
bash -n deploy/alt-linux/install-backup-tool-lib.sh
bash -n deploy/alt-linux/install-control-plane.sh
bash -n deploy/alt-linux/install-control-plane-args.sh
bash -n deploy/alt-linux/install-control-plane-lib.sh
bash -n deploy/alt-linux/bootstrap/bootstrap.sh

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

## OR-3P2 machine registry lifecycle

OR-3P2 adds audited registration archival, exact registration generations,
lifecycle admission checks, stale pending-result suppression and the local
`alt-bootstrap-register` command. See
[the OR-3P2 operator runbook](../../docs/ALT_OR3P2_MACHINE_REGISTRY_LIFECYCLE.md).

OR-3P2 is repository-verified but not installed on `192.168.100.17`.
OR-3P3 repository implementation is complete only after PR #24 final verification
and merge. The live operational gate still requires installing the backup tool
and successfully running `create`, `verify` and `rehearse` on the controller.
OR-3P4 remains blocked until the exact successful backup ID is supplied to
`install-control-plane.sh`. Do not use reference workstation
`192.168.101.111` for acceptance.
