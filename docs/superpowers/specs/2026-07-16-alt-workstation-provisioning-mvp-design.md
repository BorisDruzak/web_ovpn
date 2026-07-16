# ALT Workstation Provisioning MVP Design

Status: approved in design discussion on 2026-07-16.

## 1. Purpose

Define the first implementation stage after the verified ALT Linux autoinstall and bootstrap chain. The result must automatically validate a newly registered ALT Workstation K 11.2 computer, then let an operator assign it to a local employee account through a stable CLI. A web interface will be added later as a thin client over the same control plane.

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

This design begins at `READY` and adds automatic preflight plus operator-triggered provisioning.

## 2. Deployment architecture

```text
192.168.100.30
web_ovpn / FastAPI / operator UI
        |
        | future constrained HTTP API
        v
192.168.100.17
ALT Deployment API
/usr/local/sbin/workstationctl
Ansible playbooks and roles
Ansible Vault
SSH private keys
preflight results, assignments, jobs and logs
        |
        | SSH through the ansible service account
        v
ALT Workstation K 11.2 computers
```

Ansible remains on `192.168.100.17`. The web application on `192.168.100.30` must never receive Ansible private keys, Vault material, or direct SSH access to workstations.

The initial implementation is CLI-first. The future web interface will use the existing `web_ovpn` login/session and call a constrained API on `192.168.100.17`. That API will invoke `workstationctl`, not `ansible-playbook` directly.

## 3. MVP scope

### 3.1 Automatic action after registration

Immediately after the registration processor obtains a successful Ansible ping, it invokes a non-mutating preflight through `workstationctl`.

Preflight checks the operating system, machine identity, Ansible privilege path, required local technical accounts, SDDM availability, and account-creation prerequisites. Its result and log are persisted.

A successful preflight produces the derived machine status `awaiting_assignment`. A failed preflight produces `failed` with diagnostics. The operator can rerun preflight manually.

### 3.2 Operator-triggered provision

The first provision operation performs only these actions:

1. Revalidate the machine, request, and latest preflight result.
2. Set the operator-supplied final hostname.
3. Create one local employee account.
4. Apply the shared employee password from Ansible Vault.
5. Ensure the employee is not a member of `wheel` and has no sudo rights.
6. Hide only the technical `ansible` account from SDDM.
7. Keep `osn-admin` visible for emergency local access.
8. Keep automatic login disabled.
9. Record the successful assignment locally and on the deployment server.
10. Run a final verification and save complete job logs.

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
- The same employee login may exist on more than one workstation; uniqueness is enforced only against incompatible accounts on the target machine.

### Hostname

- The operator enters the final hostname manually.
- It is normalized to lowercase.
- Allowed characters are ASCII lowercase letters, digits, and `-`.
- It must start and end with a letter or digit.
- Maximum length is 63 characters.
- Uniqueness is checked against successful machine assignments before a job starts.

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

## 5. Machine lifecycle and derived state

```text
registered
  -> ready
  -> preflight_running
  -> awaiting_assignment
  -> provisioning
  -> provisioned

Failure paths:
preflight_running -> failed
provisioning      -> failed
```

Existing registration records under `/srv/alt-deploy/registration` remain the source of machine identity and current network information.

`workstationctl machines list/show` derives the displayed state by combining:

- registration record;
- latest preflight result;
- active provision job, if any;
- successful assignment record, if any.

The registration JSON is not used as the only lifecycle database and does not need to be rewritten for every stage.

Automatic and manual preflight results are stored under:

```text
/var/lib/alt-deploy/preflight/<machine_uuid>/
├── status.json
├── result.json
└── ansible.log
```

A successful assignment creates a server-side record:

```text
/var/lib/alt-deploy/assignments/<machine_uuid>.json
```

The target computer receives:

```text
/var/lib/alt-workstation/assignment.json
```

The target assignment file contains no password or Vault data. It records machine UUID, final hostname, employee login, employee full name, profile, job ID, and completion timestamp.

Assignment records are written only after final verification succeeds. A failed partial run may therefore be retried safely.

## 6. `workstationctl` CLI contract

`/usr/local/sbin/workstationctl` is the authoritative control interface on `192.168.100.17`. All machine-readable commands support `--json` and return one JSON object on stdout. Human diagnostics go to stderr.

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

Returns normalized machines from registration `pending`, `ready`, and `failed` directories, enriched with latest preflight, active-job, and assignment state.

### `machines show`

Returns one normalized machine object identified by DMI UUID. MAC is retained as a secondary identifier. IP is operational data, not durable identity.

### `preflight`

Runs the non-mutating Ansible preflight synchronously, persists its status, structured result, and log, then returns the structured result. The registration processor calls the same command automatically after a successful Ansible ping. A later manual invocation replaces the machine's latest preflight result atomically.

### `provision preview`

Validates all requested values and returns the planned actions without changing the machine. Preview checks:

- machine exists and registration is usable;
- latest preflight succeeded;
- no successful assignment exists;
- no other active provision job exists for the UUID;
- hostname and login formats are valid;
- final hostname is not already assigned;
- requested login does not conflict with an incompatible local account on the target;
- profile is exactly `standard`;
- Vault configuration is available without revealing any secret.

### `provision start`

Repeats preview validation, creates a job, and launches it through a transient systemd unit. It returns the job ID immediately.

### `jobs status` and `jobs log`

Expose stored job state and log output. The MVP returns a bounded complete log; a tail/stream option may be added later without changing stored job data.

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

Validation occurs before writing a job or invoking Ansible. Unknown fields are rejected to avoid silently accepting misspellings or unsupported behaviour.

## 8. Provision job execution and logging

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

Job and preflight directories are writable only by the deployment service account and administrators. They are outside `/srv/alt-deploy`, so the static HTTP service on port 8087 cannot publish them accidentally.

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

The existing registration data is converted to an inline inventory for each run. The MVP does not require a permanent inventory entry for every newly installed machine.

### `preflight` role

Checks without changing the target:

- SSH and Python work;
- passwordless sudo through the `ansible` account works;
- target is ALT Workstation K 11.x;
- target UUID matches the requested registration record;
- target has a usable hostname service;
- SDDM configuration location can be determined;
- `osn-admin` and `ansible` exist;
- a requested employee login, when supplied during preview/start, does not conflict with an incompatible local account;
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
- verifies that no sudoers policy grants the employee administrative commands.

### `sddm_accounts` role

- hides only the `ansible` account;
- leaves `osn-admin` and the employee visible;
- keeps automatic login disabled;
- uses managed configuration files rather than editing generated files in place.

### `provision_verify` role

Verifies:

- final hostname matches the request;
- employee exists with the expected local-account attributes and home directory;
- employee is not in `wheel`;
- no sudoers rule grants the employee administrative access;
- `ansible` remains usable over SSH with passwordless sudo;
- SDDM hides `ansible` and has autologin disabled;
- target assignment file is written only after all preceding checks pass.

## 10. Idempotency and retries

The playbooks must be safe to rerun after partial failure.

- If the hostname was already changed, the role reports no change and continues.
- If the employee account exists with compatible attributes, it is reconciled.
- If the employee account exists but represents a conflicting account, the job fails without deleting or replacing it.
- SDDM configuration is managed declaratively.
- Assignment markers are written only after verification.
- A machine with no successful assignment may be retried after a failed job.
- A machine with a successful assignment is blocked from normal reprovisioning.

The MVP does not implement automatic rollback of hostname or user creation after failure. Instead, it relies on idempotent retry and complete logs. Destructive rollback would risk deleting legitimate local data.

## 11. Security boundaries

- Ansible private keys and Vault files remain only on `192.168.100.17`.
- The web server on `192.168.100.30` will receive only a constrained server-to-server API token in a later phase.
- `workstationctl` invokes subprocesses with an argument list and `shell=False`.
- Operator values are validated before they become CLI or Ansible arguments.
- Passwords and licenses are never accepted from the provision request.
- Vault secrets use `no_log: true` in relevant Ansible tasks.
- The Vault password source is root/service-account readable and is never passed as a literal command-line value.
- Job metadata and logs are root/deployment-account controlled and are not publicly served by the static HTTP server.
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

`web_ovpn` on `192.168.100.30` will use its existing operator login and poll job state approximately every two seconds. No WebSocket is required for the first web version.

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

1. A successful registration automatically invokes preflight and produces `awaiting_assignment`.
2. A failed automatic preflight produces a persisted error and useful log.
3. `workstationctl --json machines list` returns the registered machine and derived state.
4. `workstationctl --json machines show <uuid>` returns its UUID, MAC, IP, registration, preflight, active-job, and assignment state.
5. `workstationctl --json preflight <uuid>` reruns the non-mutating check and persists its result.
6. Invalid login, hostname, profile, missing UUID, duplicate assignment, and concurrent-job requests are rejected before Ansible provision starts.
7. `provision preview` returns a deterministic action plan and no secret values.
8. `provision start` immediately returns a job ID and starts a transient systemd service.
9. `jobs status` transitions from `queued` or `running` to `successful` or `failed`.
10. `jobs log` exposes useful Ansible progress and errors without the shared password.
11. A successful job sets the final hostname and creates the employee account.
12. The employee is not in `wheel` and has no sudo authorization.
13. `ansible` remains reachable and retains passwordless sudo.
14. SDDM hides `ansible`, shows `osn-admin` and the employee, and does not autologin.
15. Server-side and target assignment records are created only after successful verification.
16. A second normal provision request for the assigned UUID is rejected.
17. Re-running after a failed partial attempt reconciles existing changes instead of corrupting the machine.

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
