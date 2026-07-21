# ALT OR-3P1 Pilot Installer Readiness Design

**Status:** approved for planning  
**Date:** 2026-07-21  
**Base:** `main` at `500bca8fe0e309078930bc49c8fbd4ed0f2f6827`

## Goal

Make the already verified ALT Workstation K 11.2 provisioning chain usable in a controlled pilot as soon as possible. OR-3P1 completes the current control-plane installer and adds a reusable local readiness gate. It does not build the deferred transactional release manager.

Approved order:

```text
OR-3P1 installer completeness and readiness
OR-3P2 machine removal/archive and re-registration
OR-3P3 backup/restore runbook
OR-3P4 controlled rollout on 192.168.100.17
OR-3P5 second disposable VM acceptance
OR-3P6 limited pilot
OR-3A transactional installer and rollback
OR-3B full reliability matrix
```

OR-3P1 and OR-3P2 remain separate PRs.

## Scope

OR-3P1 must:

- install both API programs: `register_api.py` and `process_pending.py`;
- install all four existing systemd units;
- create `pending`, `ready`, and `failed` registration directories explicitly;
- preserve active Vault files, SSH identity, jobs, assignments, registration records, metadata archives, and the active Ansible public key;
- block before mutation when any provision job is `queued` or `running`;
- update the served bootstrap script without replacing environment-specific assets;
- reload systemd, enable/start the expected pilot services, and run a local acceptance command;
- contact no workstation during installer verification;
- return only safe structured diagnostics.

Non-goals:

- versioned releases or a `current` symlink;
- automatic or transaction-ID rollback;
- secret generation;
- automatic job reconciliation or forced worker termination;
- machine removal/re-registration;
- release/reassignment;
- application roles, API/UI integration, or reference-VM testing.

OR-3P3 backup/restore is mandatory before applying OR-3P1 to the live controller. OR-3P1 does not claim rollback.

## Current gaps

The installer currently installs the controller package, three entrypoints, the Ansible project, and only `process_pending.py`. It does not install `register_api.py`, the systemd units, or a complete service health gate.

The active static server also depends on runtime assets under `/srv/alt-deploy`:

```text
metadata/autoinstall.scm
metadata/vm-profile.scm
metadata/pkg-groups.tar
metadata/install-scripts.tar
bootstrap/bootstrap.sh
bootstrap/ansible_authorized_keys
```

The ISO-specific archives and active public key are not generated or overwritten by OR-3P1; readiness only validates them.

## New CLI contracts

### `jobs active`

```bash
sudo -u altserver workstationctl --json jobs active
```

Use `JobRepository.list()` and its canonical active states. Output only:

```json
{
  "status": "ok",
  "active_jobs": [
    {
      "job_id": "job-...",
      "machine_uuid": "...",
      "state": "running",
      "stage": "employee",
      "created_at": "..."
    }
  ],
  "count": 1
}
```

Do not expose request data, employee names, logs, results, or Ansible output. A malformed real job remains fail-closed and must not be treated as an empty list.

### `controller readiness`

```bash
sudo -u altserver workstationctl --json controller readiness
```

This command is read-only and local. It returns `ready=true` only when all checks pass. Failure contract:

```text
error.code = controller_not_ready
exit code = 11
```

Safe checks:

```text
active_jobs_empty
controller_permissions
vault
runtime_entrypoints
api_files
static_assets
systemd_units_loaded
systemd_units_enabled
systemd_units_active
registration_api_health
static_http_health
ansible_preflight_syntax
ansible_provision_syntax
```

Reuse `ControllerPermissionAuditor` and `VaultHealthChecker`; do not duplicate their policy. Output booleans and safe path/unit names only. Never return file contents, HTTP bodies, decrypted values, hashes, keys, or subprocess output.

## Readiness details

Required executable entrypoints:

```text
/usr/local/sbin/workstationctl
/usr/local/libexec/alt-provision-worker
/usr/local/libexec/alt-job-stage
```

Required API files:

```text
/opt/alt-deploy-api/register_api.py
/opt/alt-deploy-api/process_pending.py
```

Static prerequisites must be non-symlink regular files and non-empty; the active bootstrap script must pass `bash -n`.

Expected unit state:

```text
alt-deploy-http.service       enabled + active
alt-deploy-register.service   enabled + active
alt-deploy-process.path       enabled + active
alt-deploy-process.service    static oneshot, inactive while idle
```

Local endpoint checks:

```text
GET 127.0.0.1:8088/health -> 200, JSON status=ok
GET 127.0.0.1:8087/bootstrap/bootstrap.sh -> 200
GET 127.0.0.1:8087/bootstrap/ansible_authorized_keys -> 200
GET 127.0.0.1:8087/metadata/autoinstall.scm -> 200
```

Run installed Ansible syntax checks as `altserver` for `01-preflight.yml` and `02-provision-account.yml`. Keep only success/failure and return code.

## Installer flow

`deploy/alt-linux/install-control-plane.sh` remains the public installer and stays Bash in OR-3P1.

### Pre-mutation

Before replacing runtime files:

1. require root and the `altserver` account;
2. validate required commands and every source file;
3. run shell syntax and Python compilation checks;
4. run `tests/alt_linux`;
5. query active jobs through the source-tree CLI;
6. fail with no mutation if active jobs exist or a real job is invalid;
7. fail if `alt-deploy-process.service` is active;
8. verify the current pilot controller has safely typed Vault, SSH identity, and external static prerequisites.

Do not reconcile jobs or stop transient provision units.

### Maintenance and install

After prechecks:

1. stop the path watcher;
2. stop registration API;
3. stop static HTTP while updating the served bootstrap script;
4. re-check the processor is inactive;
5. install files and ensure directories;
6. run `systemctl daemon-reload`;
7. enable/start HTTP, registration API, and path watcher;
8. run `controller readiness`;
9. print success only after readiness passes.

Install/update:

```text
/opt/alt-deploy-control/alt_deploy/
/usr/local/sbin/workstationctl
/usr/local/libexec/alt-provision-worker
/usr/local/libexec/alt-job-stage
/opt/alt-deploy-api/register_api.py
/opt/alt-deploy-api/process_pending.py
/srv/alt-deploy/bootstrap/bootstrap.sh
/etc/systemd/system/alt-deploy-*.service
/etc/systemd/system/alt-deploy-process.path
/home/altserver/ansible configuration, playbooks, roles
```

Never replace:

```text
active vault.yml or vault password
SSH private/public identity
known_hosts_autoinstall contents
bootstrap/ansible_authorized_keys
ISO-specific metadata archives
jobs, assignments, or registration records
```

Required private directories use `altserver:altserver` and mode `0700`:

```text
/var/lib/alt-deploy
/var/lib/alt-deploy/jobs
/var/lib/alt-deploy/assignments
/srv/alt-deploy/registration
/srv/alt-deploy/registration/pending
/srv/alt-deploy/registration/ready
/srv/alt-deploy/registration/failed
/home/altserver/.ssh
```

Do not recursively rewrite existing state files merely to ensure a parent directory.

## Failure behavior

Before maintenance, any error leaves services and runtime files unchanged.

After maintenance begins, OR-3P1 exits non-zero on failure, reports the safe phase and remediation command, and never claims readiness. It does not automatically roll back. It must not delete the previous package tree, state, or secrets as cleanup. Live rollout remains blocked until OR-3P3.

`controller readiness` performs no repair. Existing Vault and permission commands remain the remediation interfaces.

## Tests

Use TDD.

CLI tests must prove:

- exact `jobs active` summaries;
- terminal jobs are excluded;
- malformed jobs fail closed;
- no PII/log/result leakage;
- readiness success/failure and exit `11`;
- reuse of Vault and permission sources of truth;
- no raw subprocess/HTTP body leakage;
- no workstation connection attempt.

Installer tests run against a temporary filesystem and fake command PATH. Prove:

- dependencies, source gaps, active jobs, or active processor fail before mutation;
- both API files and all units are installed;
- directory modes/owners follow the contract;
- bootstrap changes while active public key is byte-identical;
- Vault, SSH identity, jobs, assignments, and registrations remain byte-identical;
- systemd operations occur in approved order;
- readiness is the final acceptance command;
- readiness failure suppresses the success message.

Final verification:

```bash
python -m pytest -q tests/alt_linux
python3 -m py_compile deploy/alt-linux/control/alt_deploy/*.py \
  deploy/alt-linux/api/register_api.py \
  deploy/alt-linux/api/process_pending.py \
  deploy/alt-linux/control/alt-job-stage
bash -n deploy/alt-linux/install-control-plane.sh
bash -n deploy/alt-linux/bootstrap/bootstrap.sh
# syntax-check both playbooks with a CI-safe Vault fixture
git diff --check
```

## Documentation

Update the deploy README, verified context, and next-steps roadmap with the complete installed file set, new commands, active-job prohibition, local readiness checks, external prerequisites, lack of rollback, OR-3P3 gate, and revised pilot order.

## OR-3P2 handoff

The next separate design/PR adds:

```text
machines remove preview <uuid>
machines remove <uuid>
register-only target command
```

Approved boundary:

- archive registration records instead of irreversible deletion;
- retain jobs/logs;
- reject assigned machines and machines with active jobs;
- re-registration must not reinstall packages, recreate `ansible`, rewrite sudoers, or remove SSH identity;
- release/reassignment remains separate.

## Acceptance

OR-3P1 is complete when the installer deploys the full existing runtime, active jobs block pre-mutation, protected state is unchanged in tests, local readiness proves all controller boundaries without contacting a target, the ALT suite passes, documentation requires OR-3P3 before live rollout, and the reference VM and real secrets remain untouched during development.