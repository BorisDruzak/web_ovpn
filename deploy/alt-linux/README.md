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
logs and assignments.

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

The current installer validates root, `altserver` and `ansible-playbook`.
Phase 1 will make dependency validation exhaustive before replacing runtime
files.

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

Validate decryption and the required variable without displaying its value:

```bash
sudo -u altserver env \
  ANSIBLE_VAULT_PASSWORD_FILE=/home/altserver/.ansible-vault-pass \
  ansible-vault view \
  /home/altserver/ansible/group_vars/vault.yml \
  >/dev/null

sudo -u altserver env \
  ANSIBLE_VAULT_PASSWORD_FILE=/home/altserver/.ansible-vault-pass \
  ansible-vault view \
  /home/altserver/ansible/group_vars/vault.yml \
  | grep -q '^vault_employee_password_hash:[[:space:]]\+'
```

## CLI and provision request

Read and non-mutating operations run as `altserver`:

```bash
sudo -u altserver workstationctl --json machines list
sudo -u altserver workstationctl --json machines show <uuid>
sudo -u altserver workstationctl --json preflight <uuid>
sudo -u altserver workstationctl --json provision preview <uuid> \
  --vars-file /path/to/request.json
sudo -u altserver workstationctl --json jobs status <job_id>
sudo -u altserver workstationctl --json jobs log <job_id>
```

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

Do not run `provision start` for a machine whose derived state is `assigned`.
A repeat request is rejected with `machine_already_assigned`. An explicit
release or reassignment workflow must be implemented first.

## State, diagnostics, and recovery

Controller state:

```text
/srv/alt-deploy/registration/
/var/lib/alt-deploy/jobs/<job_id>/
/var/lib/alt-deploy/assignments/<uuid>.json
/home/altserver/.ssh/known_hosts_autoinstall
```

Each job directory may contain `request.json`, `status.json`, `result.json`,
`ansible.log` and `provision-result.json`.

Target assignment state:

```text
/var/lib/alt-workstation/assignment.json
```

Use the CLI before reading private files directly:

```bash
sudo -u altserver workstationctl --json machines show <uuid>
sudo -u altserver workstationctl --json jobs status <job_id>
sudo -u altserver workstationctl --json jobs log <job_id>
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
