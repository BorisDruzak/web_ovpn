# ALT Workstation Provisioning MVP Design

Status: approved in design discussion on 2026-07-16.

## 1. Purpose

Define the first implementation stage after the verified ALT Linux autoinstall and bootstrap chain. The result must let an operator assign a newly installed ALT Workstation K 11.2 computer to a local employee account through a stable CLI. A web interface will be added later as a thin client over the same control plane.

The already verified installation chain is:

```text
USB installer
  -> ALT autoinstall over HTTP
  -> first-boot bootstrap
  -> create ansible service account
  -> register machine on 192.168.100.17
  -> refresh isolated SSH known_hosts
  -> automatic ansible.builtin.ping
  -> machine status READY
```

This design begins at `READY`.

## 2. Deployment architecture

```text
192.168.100.30
web_ovpn / FastAPI / operator UI
        |
        | future authenticated HTTP API
        v
192.168.100.17
ALT Deployment API
workstationctl
Ansible playbooks and roles
Ansible Vault
SSH private keys
job state and logs
        |
        | SSH through the ansible service account
        v
ALT Workstation K 11.2 computers
```

Ansible remains on `192.168.100.17`. The web application on `192.168.100.30` must never receive Ansible private keys, Vault material, or direct SSH access to workstations.

The initial implementation is CLI-first. The future web interface will call a constrained API on `192.168.100.17`; that API will invoke `workstationctl`, not `ansible-playbook` directly.

## 3. MVP scope

The first provision operation performs only these actions:

1. Validate that the machine is registered and reachable.
2. Run a non-mutating preflight check.
3. Set the operator-supplied final hostname.
4. Create one local employee account.
5. Apply the shared employee password from Ansible Vault.
6. Ensure the employee is not a member of `wheel` and has no sudo rights.
7. Hide only the technical `ansible` account from SDDM.
8. Keep `osn-admin` visible for emergency local access.
9. Keep automatic login disabled.
10. Record the successful assignment locally and on the deployment server.
11. Run a final verification and save complete job logs.

The initial implementation deliberately excludes browsers, CryptoPro, ONLYOFFICE, Nextcloud, organization certificates, the `scan` share, desktop shortcuts, and other GUI settings. Those become independent roles after this control plane is stable.

## 4. Confirmed operator decisions

### Employee account

- The employee uses a local account, not a domain account.
- The operator enters the login manually.
- The operator enters the employee full name manually.
- The login is normalized to lowercase.
- Allowed login characters are ASCII lowercase letters, digits, `.`, `_`, and `-`.
- The employee is a normal user without `sudo`.
- The employee password is a shared value stored only in Ansible Vault.
- The employee is not forced to change the password at first login.
- The password value must not be stored in Git, API request JSON, job metadata, or logs.
- Because the previously discussed value appeared in chat, production deployment should use a rotated value in Vault.

### Hostname

- The operator enters the final hostname manually.
- It is normalized to lowercase.
- Allowed characters are ASCII lowercase letters, digits, and `-`.
- It must start and end with a letter or digit.
- Maximum length is 63 characters.
- Uniqueness is checked against known assignments before a job starts.

### Login screen

- `ansible` is hidden from SDDM.
- `osn-admin` remains visible.
- The employee account remains visible.
- Automatic login is disabled.

### Provision profile

The MVP exposes one fixed profile:

```yaml
profile: standard
```

The field is retained in request and assignment records so additional profiles can be introduced later without changing the contract.

### Reassignment

A computer with a successful assignment cannot be provisioned for another employee through the normal `provision start` command.

A future explicit `workstationctl release` workflow will handle reassignment. The MVP must not delete, disable, or overwrite an existing employee account automatically.

## 5. Machine lifecycle

```text
registered
  -> ready
  -> preflight_running
  -> awaiting_assignment
  -> provisioning
  -> provisioned

Failure states:
registered/ready/preflight_running/provisioning
  -> failed
```

Existing registration records under `/srv/alt-deploy/registration/ready` remain the source for newly available machines.

A successful assignment creates a server-side record:

```text
/var/lib/alt-deploy/assignments/<machine_uuid>.json
```

The target computer receives:

```text
/var/lib/alt-workstation/assignment.json
```

The target assignment file contains no password or Vault data. It records at least machine UUID, final hostname, employee login, employee full name, profile, job ID, and completion timestamp.

The assignment record is written only after final verification succeeds. A failed partial run may therefore be retried safely.

## 6. `workstationctl` CLI contract

`workstationctl` is the authoritative control interface on `192.168.100.17`. All machine-readable commands support `--json` and return a JSON object on stdout. Human diagnostics go to stderr.

Initial commands:

```text
workstationctl --json machines list
workstationctl --json machines show <uuid>
workstationctl --json preflight <uuid>
workstationctl --json provision preview <uuid> --vars-file <file>
workstationctl --json provision start <uuid> --vars-file <file>
workstationctl --json jobs status <job_id>
workstationctl --json jobs log <job_id>
```

### `machines list`

Returns registered machines from `pending`, `ready`, and `failed`, plus assignment and active-job state when present.

### `machines show`

Returns one normalized machine object identified by DMI UUID. MAC is retained as a secondary identifier. IP is operational data, not machine identity.

### `preflight`

Runs the non-mutating Ansible preflight playbook synchronously and returns a structured result. It does not create a job directory for the first implementation unless detailed diagnostics need preservation.

### `provision preview`

Validates all requested values and returns the planned actions without changing the machine. Preview checks:

- machine exists and is `ready`;
- no successful assignment exists;
- no other active provision job exists for the UUID;
- hostname and login formats are valid;
- final hostname is not already assigned;
- requested employee login does not conflict with a known successful assignment;
- profile is exactly `standard`;
- Vault configuration is available without revealing any secret.

### `provision start`

Repeats preview validation, creates a job, and launches it through a transient systemd unit. It returns the job ID immediately.

### `jobs status` and `jobs log`

Expose stored job state and log output. Log reads may support an optional tail limit later, but the MVP can return the complete bounded log.

## 7. Provision request format

The CLI accepts an operator-created JSON file:

```json
{
  "machine_uuid": "53b03180-5d78-11f0-bd95-f027db877a00",
  "employee_login": "i.ivanov",
  "employee_full_name": "Иванов Иван Иванович",
  "final_hostname": "buh-023",
  "profile": "standard"
}
```

The request never includes the employee password.

Validation rules are applied before writing a job or invoking Ansible. Unknown fields are rejected to avoid silently accepting misspellings or unsupported behaviour.

## 8. Job execution and logging

Every asynchronous provision run has a unique job ID, for example:

```text
job-20260716T121530Z-a1b2c3d4
```

Job directory:

```text
/var/lib/alt-deploy/jobs/<job_id>/
├── request.json
├── status.json
├── result.json
└── ansible.log
```

Job states:

```text
queued -> running -> successful
                 -> failed
```

`status.json` is updated atomically and includes timestamps, machine UUID, current stage, and process outcome. `result.json` contains the final structured verification result. `ansible.log` contains stdout and stderr from the playbook but no Vault values.

The CLI launches a transient systemd service such as:

```text
alt-provision-<job_id>.service
```

The API process must not own the lifetime of Ansible. A restart of the API or future web service must not terminate an active job.

Only one active provision job is allowed per machine UUID.

## 9. Ansible structure

Initial project layout:

```text
/home/altserver/ansible/
├── inventories/
│   └── autoinstall/
├── playbooks/
│   ├── 01-preflight.yml
│   └── 02-provision-account.yml
├── roles/
│   ├── preflight/
│   ├── workstation_identity/
│   ├── local_employee/
│   ├── sddm_accounts/
│   └── provision_verify/
├── group_vars/
│   ├── all.yml
│   └── vault.yml
└── ansible.cfg
```

The existing registration data can be converted to an inline inventory for each run; the MVP does not require a permanent inventory entry for every newly installed machine.

### `preflight` role

Checks without changing the target:

- SSH and Python work;
- passwordless sudo through the `ansible` account works;
- target is ALT Workstation K 11.x;
- target UUID matches the requested machine record;
- target has a usable hostname service;
- SDDM configuration location can be determined;
- `osn-admin` and `ansible` exist;
- employee login does not conflict with an incompatible local account;
- sufficient filesystem space exists for account creation and later roles.

### `workstation_identity` role

- sets the final hostname idempotently;
- preserves Ansible connectivity by using the registered IP during the job;
- verifies the resulting static hostname.

### `local_employee` role

- creates or reconciles the requested local account;
- sets full name and home directory;
- sets the password from an encrypted Vault variable;
- does not expire the password for the MVP;
- explicitly removes the account from `wheel` if present;
- verifies that `sudo -n` fails for the employee.

### `sddm_accounts` role

- hides only the `ansible` account;
- leaves `osn-admin` and the employee visible;
- keeps automatic login disabled;
- uses managed configuration files rather than editing generated files in place.

### `provision_verify` role

Verifies:

- final hostname matches the request;
- employee exists with the expected UID-class local account and home directory;
- employee is not in `wheel`;
- no sudoers rule grants the employee administrative access;
- `ansible` remains usable over SSH with passwordless sudo;
- SDDM hides `ansible` and has autologin disabled;
- target assignment file can be written.

## 10. Idempotency and retries

The playbooks must be safe to rerun after partial failure.

- If the hostname was already changed, the role reports no change and continues.
- If the employee account exists with compatible attributes, it is reconciled.
- If the employee account exists but represents a conflicting account, the job fails before destructive changes.
- SDDM configuration is managed declaratively.
- The assignment marker is written only after verification.
- A machine with no successful assignment may be retried after a failed job.
- A machine with a successful assignment is blocked from normal reprovisioning.

The MVP does not implement automatic rollback of hostname or user creation after failure. Instead, it relies on idempotent retry and complete logs. Destructive rollback would risk deleting legitimate local data.

## 11. Security boundaries

- Ansible private keys and Vault files remain only on `192.168.100.17`.
- The web server on `192.168.100.30` will receive only a constrained API token in a later phase.
- `workstationctl` invokes subprocesses with an argument list and `shell=False`.
- Operator values are validated before they become CLI or Ansible arguments.
- Passwords and licenses are never accepted from the provision request.
- Vault secrets use `no_log: true` in relevant Ansible tasks.
- Job metadata and logs are root/`altserver` controlled and are not publicly served by the static HTTP server.
- Existing isolated SSH host-key management through `known_hosts_autoinstall` remains in use.
- Global `StrictHostKeyChecking=no` is prohibited.

## 12. Future web integration

After the CLI and Ansible implementation pass acceptance tests, the deployment API on `192.168.100.17` will expose constrained endpoints:

```text
GET  /api/workstations
GET  /api/workstations/{uuid}
POST /api/workstations/{uuid}/provision
GET  /api/jobs/{job_id}
GET  /api/jobs/{job_id}/log
```

`web_ovpn` on `192.168.100.30` will poll job state approximately every two seconds. No WebSocket is required for the first web version.

The web form will ask only for:

- employee login;
- employee full name;
- final hostname.

The profile is submitted as `standard`. Passwords are not displayed or submitted.

## 13. Deferred software roles

After the MVP is stable, implement independent roles in this order:

1. Organization root certificate and HTTPS verification.
2. ONLYOFFICE Desktop Editors.
3. Nextcloud Client installation and employee autostart; the employee signs in manually.
4. Yandex Browser and managed extensions.
5. CryptoPro CSP, IFC and browser plugins; personal certificates remain a manual import.
6. Read-only `scan` CIFS share using a dedicated service account stored in Vault, systemd automount, and a `~/Scan` link.
7. Monitoring and helpdesk agents.
8. User-facing KDE conveniences that do not alter security boundaries.

## 14. Acceptance criteria

The MVP is accepted when all of the following work on the verified ALT test machine:

1. `workstationctl --json machines list` returns the registered machine.
2. `workstationctl --json machines show <uuid>` returns its UUID, MAC, IP, registration state, and assignment state.
3. `workstationctl --json preflight <uuid>` succeeds without changing the target.
4. Invalid login, hostname, profile, missing UUID, duplicate assignment, and concurrent-job requests are rejected before Ansible starts.
5. `provision preview` returns a deterministic action plan and no secret values.
6. `provision start` immediately returns a job ID and starts a transient systemd service.
7. `jobs status` transitions from `queued` or `running` to `successful` or `failed`.
8. `jobs log` exposes useful Ansible progress and errors without the shared password.
9. A successful job sets the final hostname and creates the employee account.
10. The employee is not in `wheel` and cannot use passwordless sudo.
11. `ansible` remains reachable and retains passwordless sudo.
12. SDDM hides `ansible`, shows `osn-admin` and the employee, and does not autologin.
13. Server-side and target assignment records are created only after successful verification.
14. A second normal provision request for the assigned UUID is rejected.
15. Re-running after a failed partial attempt reconciles existing changes instead of corrupting the machine.

## 15. Explicit non-goals for this stage

- Building or modifying the web UI on `192.168.100.30`.
- Domain enrollment.
- Multiple workstation profiles.
- Automatic password rotation or first-login password change.
- Reassignment, release, archival, or deletion of previous employee data.
- Application installation.
- Personal certificate import.
- Full rollback of partial provisioning.
- Replacing the current autoinstall and bootstrap chain.
