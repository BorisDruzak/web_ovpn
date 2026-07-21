# ALT OR-3P1 Pilot Controller Rollout

Status: repository implementation complete; live rollout is blocked until the
separate OR-3P3 backup/restore procedure is approved and executed.

This runbook covers only the current pilot layout on controller
`192.168.100.17`. It does not provide transactional releases or automatic
rollback.

## Safety boundaries

- Do not use the accepted reference workstation `192.168.101.111`.
- Do not start installation while a provision job is `queued` or `running`.
- Do not start installation while `registration/pending` contains a JSON record.
- Do not delete jobs, assignments, registrations, Vault files, or SSH identity.
- Do not treat removal of an assignment JSON as release or reassignment.
- Keep OR-3P2 machine archive/re-registration and OR-3P3 backup/restore as
  separate workflows.

## Pre-rollout checks

Run as the `altserver` service account:

```bash
sudo -u altserver workstationctl --json jobs active
sudo -u altserver workstationctl --json vault check
sudo -u altserver workstationctl --json controller permissions
```

Required results:

```text
jobs active: count=0
vault check: status=ok
controller permissions: status=ok
```

Confirm the pending queue is empty without reading record contents:

```bash
sudo find /srv/alt-deploy/registration/pending \
  -maxdepth 1 -type f -name '*.json' -print
```

Expected: no output.

Confirm the pending processor is not running:

```bash
systemctl is-active alt-deploy-process.service
```

Expected: `inactive`.

External pilot assets must already exist and remain non-empty:

```text
/home/altserver/.ssh/id_ed25519
/srv/alt-deploy/bootstrap/ansible_authorized_keys
/srv/alt-deploy/metadata/autoinstall.scm
/srv/alt-deploy/metadata/vm-profile.scm
/srv/alt-deploy/metadata/pkg-groups.tar
/srv/alt-deploy/metadata/install-scripts.tar
```

The SSH private key must remain `altserver:altserver` mode `0600`.

## Mandatory backup gate

Do not run the installer on the live controller until OR-3P3 has created and
verified a coordinated backup of:

```text
/opt/alt-deploy-control
/opt/alt-deploy-api
/usr/local/sbin/workstationctl
/usr/local/libexec/alt-provision-worker
/usr/local/libexec/alt-job-stage
/etc/systemd/system/alt-deploy-*
/home/altserver/ansible excluding group_vars/vault.yml
/var/lib/alt-deploy/jobs
/var/lib/alt-deploy/assignments
/srv/alt-deploy/registration
```

Vault, its password file and SSH private identity remain in place and are not
duplicated by the OR-3P1 installer. The OR-3P3 procedure must define their
verification and the coordinated restore of package files and job state.

## Installation

From the reviewed repository checkout:

```bash
sudo bash deploy/alt-linux/install-control-plane.sh
```

Before the first runtime mutation the installer:

1. validates dependencies and every source asset;
2. compiles Python and syntax-checks shell files;
3. runs `tests/alt_linux`;
4. validates active jobs, Vault, controller permissions, SSH identity, static
   assets, pending registrations, and processor inactivity.

It then stops only:

```text
alt-deploy-process.path
alt-deploy-register.service
alt-deploy-http.service
```

It never stops a transient provision unit and never reconciles a job.

The installer deploys:

```text
/opt/alt-deploy-control/alt_deploy
/opt/alt-deploy-api/register_api.py
/opt/alt-deploy-api/process_pending.py
/usr/local/sbin/workstationctl
/usr/local/libexec/alt-provision-worker
/usr/local/libexec/alt-job-stage
/etc/systemd/system/alt-deploy-http.service
/etc/systemd/system/alt-deploy-register.service
/etc/systemd/system/alt-deploy-process.path
/etc/systemd/system/alt-deploy-process.service
/srv/alt-deploy/bootstrap/bootstrap.sh
/home/altserver/ansible configuration, playbooks, and roles
```

It preserves active Vault files, SSH identity, the active authorized key,
ISO-specific metadata archives, jobs, assignments, and registration records.

After `daemon-reload`, the installer enables and starts HTTP, registration API,
and the path watcher. Success is printed only after the installed command below
returns exit code `0`:

```bash
sudo -u altserver workstationctl --json controller readiness
```

## Local readiness contract

`controller readiness` is read-only and contacts no workstation. It validates:

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

A failure returns:

```text
error.code=controller_not_ready
exit code=11
```

Only boolean diagnostics and failed check names are returned.

Expected unit states:

```text
alt-deploy-http.service       loaded active enabled
alt-deploy-register.service   loaded active enabled
alt-deploy-process.path       loaded active enabled
alt-deploy-process.service    loaded inactive static
```

## Post-install verification

```bash
sudo -u altserver workstationctl --json jobs active
sudo -u altserver workstationctl --json controller readiness
systemctl status alt-deploy-http.service --no-pager
systemctl status alt-deploy-register.service --no-pager
systemctl status alt-deploy-process.path --no-pager
```

Do not create a new job until all checks are healthy.

## Second disposable workstation

After controller rollout, use a new unassigned physical machine or VM:

1. ALT Workstation K 11.2 autoinstall;
2. first-boot bootstrap;
3. automatic registration and SSH readiness;
4. automatic preflight to `awaiting_assignment`;
5. operator `provision preview`;
6. root-only `provision start`;
7. complete monotonic `stage_history`;
8. successful assignment;
9. reboot;
10. LightDM visibility and graphical employee login;
11. repeat-provision rejection.

Operate one pilot machine at a time. Do not proceed to broad rollout until the
second-machine acceptance result and OR-3P2/OR-3P3 controls are complete.
