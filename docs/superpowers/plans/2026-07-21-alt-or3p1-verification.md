# ALT OR-3P1 Pilot Installer Readiness Verification

Verification date: 2026-07-21.

## Status

```text
PASS
```

OR-3P1 was verified in GitHub Actions on the pull-request merge reference:

```text
pull request: #21
branch: feat/alt-or3p1-pilot-installer-readiness-20260721
branch source SHA: be72e97ad64754e3b87e70f68b3bf1cd2ba103fe
verified merge ref: 143c6fb95cf5c12a8cad4165cf6c39fc59b5f07e
base main: 500bca8fe0e309078930bc49c8fbd4ed0f2f6827
OR-3P1 verification run: 29822687374
```

The verified merge ref contains the complete OR-3P1 production, test and
operator-documentation tree together with the current `main` base.

## Test results

### Focused OR-3P1 suite

```bash
python -m pytest -q \
  tests/alt_linux/test_or3p1_cli_readiness.py \
  tests/alt_linux/test_or3p1_controller_readiness.py \
  tests/alt_linux/test_or3p1_controller_readiness_failures.py \
  tests/alt_linux/test_or3p1_installer.py \
  tests/alt_linux/test_or3p1_installer_failure_phase.py
```

```text
33 passed in 5.86s
```

### Complete ALT Linux suite

```bash
python -m pytest -q tests/alt_linux
```

```text
289 passed in 7.77s
```

### Complete repository suite

```bash
python -m pytest -q
```

```text
832 passed, 102 warnings in 45.98s
```

The warnings are existing deprecation warnings in unrelated web application
code. OR-3P1 introduced no new warning class.

## Static verification

The same run passed:

```text
Python compilation:
  deploy/alt-linux/control/alt_deploy/*.py
  deploy/alt-linux/api/register_api.py
  deploy/alt-linux/api/process_pending.py
  deploy/alt-linux/control/alt-job-stage

Shell syntax:
  deploy/alt-linux/install-control-plane.sh
  deploy/alt-linux/install-control-plane-lib.sh
  deploy/alt-linux/bootstrap/bootstrap.sh

Ansible syntax:
  deploy/alt-linux/ansible/playbooks/01-preflight.yml
  deploy/alt-linux/ansible/playbooks/02-provision-account.yml

Repository integrity:
  git diff --check origin/main...HEAD
  clean git status after temporary Vault fixture removal
```

## Standard repository workflows

On the same branch source SHA:

```text
Verify netctl context stage
  run 29822687387: success

Verify netctl runtime identity
  run 29822687373: success
```

Their focused and full-regression jobs completed successfully.

## Verified behavior

### Active job gate

`workstationctl --json jobs active`:

- returns only job ID, machine UUID, state, stage and creation timestamp;
- includes only `queued` and `running` jobs;
- excludes terminal jobs;
- exposes no request, employee, log, Ansible or result data;
- fails closed for malformed real job records.

### Local readiness gate

`workstationctl --json controller readiness` verifies:

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

The command uses fixed controller-local paths, systemd queries, loopback HTTP
endpoints and installed Ansible syntax checks. It invokes no target SSH,
`systemd-run`, provision worker or inventory command. Failure returns
`controller_not_ready` with exit code `11` and safe boolean diagnostics only.

### Installer pre-mutation boundary

Before the first runtime mutation the installer proves:

- required command and source-file availability;
- Python and shell syntax;
- complete ALT test suite success;
- no active or malformed provision job;
- healthy Vault and controller permissions;
- safe SSH private-key metadata;
- required external autoinstall/bootstrap assets;
- empty pending registration queue;
- inactive pending-registration processor.

Every tested pre-mutation failure preserved synthetic Vault, SSH identity, jobs,
assignments, registrations and static assets byte-for-byte and invoked no
maintenance or mutation command.

### Complete installed runtime

The installer now deploys:

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
/home/altserver/ansible configuration, playbooks and roles
```

It creates private state directories individually and does not recursively
rewrite protected controller state. The active Vault, Vault password, SSH
identity, authorized key, ISO metadata, jobs, assignments and registration
records remain preserved.

The maintenance order is:

```text
prechecks
stop path watcher
stop registration API
stop static HTTP
re-check processor inactivity
install runtime
systemctl daemon-reload
enable/start HTTP
 enable/start registration API
 enable/start path watcher
installed controller readiness
success message
```

A post-maintenance failure reports its phase, exits non-zero, suppresses the
success message and directs the operator to restore the OR-3P3 backup. OR-3P1
does not claim automatic rollback.

## Safety and operational boundary

Development and verification used only synthetic filesystem state and fake
system commands. They did not access or modify:

- controller `192.168.100.17`;
- accepted reference workstation `192.168.101.111`;
- any real workstation or SSH target;
- production Vault or password material;
- production SSH private keys;
- production jobs, assignments or registrations.

Live rollout remains blocked until the separate OR-3P3 coordinated
backup/restore procedure is approved and executed. OR-3P2 machine
archive/re-registration remains a separate implementation phase.

The existing root-run Python static HTTP service remains a known hardening item:
before expanding beyond the controlled pilot, restrict its access to public
bootstrap/metadata content so registration state cannot be served.

## Cleanup requirement

The temporary `.github/workflows/or3p1-verification.yml` workflow is used only
to capture this evidence and must be removed before the pull request is marked
Ready for review. The final clean head must then pass the standard repository
workflows again.
