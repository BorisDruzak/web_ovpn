# ALT OR-3P1 Pilot Installer Readiness Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Complete the existing ALT control-plane installer and add a local readiness gate so a controlled pilot can begin without the deferred transactional release manager.

**Architecture:** Keep the existing runtime paths and stable entrypoints. Add read-only `jobs active` and `controller readiness` commands, extract testable Bash installation functions into a sourced library, and keep the public installer as the root-only entrypoint. All validations run before maintenance; the installer installs the complete runtime and prints success only after the installed readiness command passes.

**Tech Stack:** Python 3.11, argparse, pathlib, subprocess, urllib, Bash, systemd, Ansible, pytest, synthetic filesystem and fake-PATH tests.

## Global Constraints

- Base commit: `500bca8fe0e309078930bc49c8fbd4ed0f2f6827`.
- OR-3P1 and OR-3P2 are separate PRs; no machine removal, archive, or re-registration here.
- No versioned releases, `current` symlink, transaction manifest, or automatic rollback.
- OR-3P3 backup/restore is mandatory before applying OR-3P1 to `192.168.100.17`.
- Block before mutation for active or malformed jobs, unhealthy Vault/permissions, unsafe SSH/static prerequisites, or active `alt-deploy-process.service`.
- Do not reconcile jobs, stop transient provision units, or contact a workstation.
- Preserve Vault, Vault password, SSH identity, `known_hosts_autoinstall`, jobs, assignments, registrations, ISO archives, and `bootstrap/ansible_authorized_keys` byte-for-byte.
- Install both API programs, all four systemd units, and the repository bootstrap script.
- Readiness failure: `controller_not_ready`, exit `11`, safe diagnostics only.
- Tests use synthetic state only; no production secrets, controller mutation, or reference VM.
- Remove temporary CI workflows/helpers before Ready for review.

## File Map

**Create production:**
- `deploy/alt-linux/control/alt_deploy/controller_readiness.py`
- `deploy/alt-linux/install-control-plane-lib.sh`

**Modify production:**
- `deploy/alt-linux/control/alt_deploy/cli.py`
- `deploy/alt-linux/install-control-plane.sh`

**Create tests/support:**
- `tests/alt_linux/support/installer_sandbox.py`
- `tests/alt_linux/test_or3p1_cli_readiness.py`
- `tests/alt_linux/test_or3p1_installer.py`

**Modify docs:**
- `deploy/alt-linux/README.md`
- `docs/ALT_WORKSTATION_PROVISIONING_CONTEXT.md`
- `docs/ALT_WORKSTATION_PROVISIONING_NEXT_STEPS.md`

---

### Task 1: Add `jobs active`

**Files:**
- Modify: `deploy/alt-linux/control/alt_deploy/cli.py`
- Create: `tests/alt_linux/test_or3p1_cli_readiness.py`

**Interfaces:**
- Consumes: `JobRepository.list() -> list[JobRecord]`.
- Produces: `workstationctl --json jobs active` with `status`, `active_jobs`, `count` only.

- [ ] **Step 1: Write failing empty-list test**

```python
def test_jobs_active_returns_empty_safe_summary(settings) -> None:
    rc, payload = run_cli(["--json", "jobs", "active"], settings)
    assert rc == 0
    assert payload == {"status": "ok", "active_jobs": [], "count": 0}
```

Run:

```bash
python -m pytest -q tests/alt_linux/test_or3p1_cli_readiness.py::test_jobs_active_returns_empty_safe_summary
```

Expected: FAIL because `active` is unknown.

- [ ] **Step 2: Add parser and dispatch**

```python
job_commands.add_parser("active")
```

```python
elif parsed.command == "jobs" and parsed.job_command == "active":
    active_jobs = [
        job for job in JobRepository(active_settings).list()
        if job.state in {"queued", "running"}
    ]
    payload = {
        "status": "ok",
        "active_jobs": [
            {
                "job_id": job.job_id,
                "machine_uuid": job.machine_uuid,
                "state": job.state,
                "stage": job.stage,
                "created_at": job.created_at,
            }
            for job in active_jobs
        ],
        "count": len(active_jobs),
    }
```

Do not use `to_public_dict()`.

- [ ] **Step 3: Add filtering/redaction tests**

Create queued, running, successful, and failed jobs. Assert two active results in repository order and exact key sets. Assert serialized output excludes `employee_full_name`, logs, results, and Ansible output.

- [ ] **Step 4: Add malformed-job fail-closed test**

Create a real `job-*` directory with malformed `status.json`. Assert the existing `job_invalid` or `job_stage_history_invalid` error propagates; never return `count=0`.

- [ ] **Step 5: Run and commit**

```bash
python -m pytest -q tests/alt_linux/test_or3p1_cli_readiness.py -k jobs_active
git add deploy/alt-linux/control/alt_deploy/cli.py \
  tests/alt_linux/test_or3p1_cli_readiness.py
git commit -m "feat: expose active ALT provision jobs"
```

Expected: PASS.

---

### Task 2: Add `controller readiness`

**Files:**
- Create: `deploy/alt-linux/control/alt_deploy/controller_readiness.py`
- Modify: `deploy/alt-linux/control/alt_deploy/cli.py`
- Modify: `tests/alt_linux/test_or3p1_cli_readiness.py`

**Interfaces:**
- Consumes: `Settings`, `JobRepository`, `ControllerPermissionAuditor`, `VaultHealthChecker`.
- Produces: `ControllerReadinessChecker.check() -> dict[str, object]` and CLI command.

- [ ] **Step 1: Write failing healthy-contract test**

```python
EXPECTED_CHECKS = {
    "active_jobs_empty", "controller_permissions", "vault",
    "runtime_entrypoints", "api_files", "static_assets",
    "systemd_units_loaded", "systemd_units_enabled",
    "systemd_units_active", "registration_api_health",
    "static_http_health", "ansible_preflight_syntax",
    "ansible_provision_syntax",
}
rc, payload = run_cli(["--json", "controller", "readiness"], settings)
assert rc == 0
result = payload["controller_readiness"]
assert result["ready"] is True
assert set(result["checks"]) == EXPECTED_CHECKS
assert all(result["checks"].values())
assert result["failed_checks"] == []
```

Expected: FAIL because the command/module is absent.

- [ ] **Step 2: Add fixed boundaries**

Define module constants:

```python
RUNTIME_ENTRYPOINTS = {
    "workstationctl": Path("/usr/local/sbin/workstationctl"),
    "provision_worker": Path("/usr/local/libexec/alt-provision-worker"),
    "job_stage_helper": Path("/usr/local/libexec/alt-job-stage"),
}
API_FILES = {
    "register_api": Path("/opt/alt-deploy-api/register_api.py"),
    "process_pending": Path("/opt/alt-deploy-api/process_pending.py"),
}
STATIC_FILES = {
    "autoinstall": Path("/srv/alt-deploy/metadata/autoinstall.scm"),
    "vm_profile": Path("/srv/alt-deploy/metadata/vm-profile.scm"),
    "pkg_groups": Path("/srv/alt-deploy/metadata/pkg-groups.tar"),
    "install_scripts": Path("/srv/alt-deploy/metadata/install-scripts.tar"),
    "bootstrap": Path("/srv/alt-deploy/bootstrap/bootstrap.sh"),
    "authorized_keys": Path("/srv/alt-deploy/bootstrap/ansible_authorized_keys"),
}
EXPECTED_UNIT_STATE = {
    "alt-deploy-http.service": ("loaded", "active", "enabled"),
    "alt-deploy-register.service": ("loaded", "active", "enabled"),
    "alt-deploy-process.path": ("loaded", "active", "enabled"),
    "alt-deploy-process.service": ("loaded", "inactive", "static"),
}
```

Add monkeypatchable module functions:

```python
def run_command(command: list[str], *, timeout: int = 30, env=None):
    return subprocess.run(
        command, text=True, capture_output=True, check=False,
        timeout=timeout, env=env,
    )


def regular_nonempty(path: Path, *, executable: bool = False) -> bool:
    try:
        metadata = path.lstat()
    except OSError:
        return False
    if not stat.S_ISREG(metadata.st_mode) or metadata.st_size < 1:
        return False
    return not executable or os.access(path, os.X_OK)
```

Tests monkeypatch constants, `run_command`, and imported `urlopen`; callers cannot supply paths/commands/URLs.

- [ ] **Step 3: Implement local sources of truth**

```python
class ControllerReadinessChecker:
    def __init__(self, settings: Settings):
        self.settings = settings

    def active_jobs_empty(self) -> bool:
        try:
            jobs = JobRepository(self.settings).list()
        except ControlError:
            return False
        return not any(job.state in {"queued", "running"} for job in jobs)

    def permissions_ok(self) -> bool:
        try:
            ControllerPermissionAuditor(self.settings).check()
        except ControlError:
            return False
        return True

    def vault_ok(self) -> bool:
        try:
            VaultHealthChecker(self.settings).check()
        except ControlError:
            return False
        return True
```

Do not duplicate Vault/permission policy.

- [ ] **Step 4: Implement fixed systemd/HTTP/Ansible helpers**

For each unit run exactly:

```text
systemctl show <unit> --property=LoadState --property=ActiveState --property=UnitFileState
```

Parse `key=value`; non-zero, timeout, malformed output, or mismatch sets the corresponding aggregate boolean false. Never return stdout/stderr.

Use only these five-second URLs:

```text
http://127.0.0.1:8088/health
http://127.0.0.1:8087/bootstrap/bootstrap.sh
http://127.0.0.1:8087/bootstrap/ansible_authorized_keys
http://127.0.0.1:8087/metadata/autoinstall.scm
```

Registration health requires HTTP 200 and JSON `status=ok`; static files require HTTP 200 and one readable byte. Never return bodies.

Run with `ANSIBLE_CONFIG=/home/altserver/ansible/ansible.cfg`:

```text
ansible-playbook --syntax-check /home/altserver/ansible/playbooks/01-preflight.yml
ansible-playbook --syntax-check /home/altserver/ansible/playbooks/02-provision-account.yml
```

Also run `bash -n /srv/alt-deploy/bootstrap/bootstrap.sh`. Store booleans only.

- [ ] **Step 5: Aggregate and raise exact error**

```python
def check(self) -> dict[str, object]:
    checks = {
        "active_jobs_empty": self.active_jobs_empty(),
        "controller_permissions": self.permissions_ok(),
        "vault": self.vault_ok(),
        "runtime_entrypoints": all(
            regular_nonempty(path, executable=True)
            for path in RUNTIME_ENTRYPOINTS.values()
        ),
        "api_files": all(regular_nonempty(path) for path in API_FILES.values()),
        "static_assets": self.static_assets_ok(),
        **self.systemd_checks(),
        "registration_api_health": self.registration_health_ok(),
        "static_http_health": self.static_http_ok(),
        "ansible_preflight_syntax": self.ansible_syntax_ok(
            "/home/altserver/ansible/playbooks/01-preflight.yml"
        ),
        "ansible_provision_syntax": self.ansible_syntax_ok(
            "/home/altserver/ansible/playbooks/02-provision-account.yml"
        ),
    }
    result = {
        "ready": all(checks.values()),
        "checks": checks,
        "failed_checks": [name for name, ok in checks.items() if not ok],
    }
    if not result["ready"]:
        raise ControlError(
            code="controller_not_ready",
            message="ALT deployment controller is not ready",
            exit_code=11,
            details=result,
        )
    return result
```

Implement `static_assets_ok`, `systemd_checks`, `registration_health_ok`, `static_http_ok`, and `ansible_syntax_ok` using only Step 4 boundaries.

Add parser and dispatch:

```python
controller_commands.add_parser("readiness")
```

```python
elif parsed.command == "controller" and parsed.controller_command == "readiness":
    payload = {
        "status": "ok",
        "controller_readiness": ControllerReadinessChecker(
            active_settings
        ).check(),
    }
```

- [ ] **Step 6: Add failure/redaction/no-target tests**

Parameterize each failed check. Assert `controller_not_ready/11`, exact `failed_checks`, and absence of command output, HTTP body, Vault/key fixture, and employee data. Fail the test if a command includes `ssh`, workstation IP, inventory arguments, `alt-provision-worker`, or `systemd-run`.

- [ ] **Step 7: Run and commit**

```bash
python -m pytest -q tests/alt_linux/test_or3p1_cli_readiness.py
git add deploy/alt-linux/control/alt_deploy/controller_readiness.py \
  deploy/alt-linux/control/alt_deploy/cli.py \
  tests/alt_linux/test_or3p1_cli_readiness.py
git commit -m "feat: add ALT controller readiness gate"
```

Expected: PASS.

---

### Task 3: Extract Testable Installer Functions and Enforce Prechecks

**Files:**
- Create: `deploy/alt-linux/install-control-plane-lib.sh`
- Modify: `deploy/alt-linux/install-control-plane.sh`
- Create: `tests/alt_linux/support/installer_sandbox.py`
- Create: `tests/alt_linux/test_or3p1_installer.py`

**Interfaces:**
- Public installer remains root-only and calls `install_control_plane_main ""`.
- Tests source the library directly and call `install_control_plane_main "$tmp_root"` with fake PATH; no root/EUID override exists.
- `InstallerSandbox.run(...) -> CompletedProcess[str]` exposes protected snapshots and ordered command log.

- [ ] **Step 1: Write public root-boundary and active-job tests**

On a non-root test runner, execute the public script and assert it exits before sourcing/mutation. Separately source the library in a Bash subprocess, seed protected state, return one running job from fake `sudo`, and assert non-zero, byte-identical state, and no maintenance/mutation commands.

- [ ] **Step 2: Make public script a strict root wrapper**

```bash
#!/bin/bash
set -Eeuo pipefail

if [[ ${EUID} -ne 0 ]]; then
    echo "Run as root" >&2
    exit 1
fi

REPO_ROOT=$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)
ALT_ROOT="${REPO_ROOT}/deploy/alt-linux"
source "${ALT_ROOT}/install-control-plane-lib.sh"
install_control_plane_main ""
```

No environment variable may bypass root or redirect production destinations.

- [ ] **Step 3: Create library path and command primitives**

```bash
install_destination() {
    local root=$1
    local absolute=$2
    printf '%s%s' "${root}" "${absolute}"
}

require_command() {
    command -v "$1" >/dev/null 2>&1 || {
        echo "Missing required command: $1" >&2
        return 1
    }
}

require_regular_nonempty() {
    local path=$1
    [[ -f "${path}" && ! -L "${path}" && -s "${path}" ]] || {
        echo "Unsafe or missing required runtime file: ${path}" >&2
        return 1
    }
}
```

`install_control_plane_main(root_prefix)` uses the prefix only for destination paths; source and live CLI/systemd checks remain unprefixed in production. The test sandbox replaces those commands through fake PATH.

- [ ] **Step 4: Implement InstallerSandbox**

Create fake `id`, `sudo`, `systemctl`, `install`, `cp`, `rm`, `chown`, `chmod`, and `find`. Log each invocation as one JSON line. File fakes copy/create/chmod beneath the supplied root prefix and ignore ownership. Fake `sudo` returns configured JSON for `jobs active`, `vault check`, `controller permissions`, and final `controller readiness`.

Seed/snapshot:

```text
vault.yml, .ansible-vault-pass
id_ed25519, id_ed25519.pub, known_hosts_autoinstall
bootstrap/ansible_authorized_keys
metadata/pkg-groups.tar, metadata/install-scripts.tar
a job request/status/log, one assignment
pending/ready/failed registration records
```

- [ ] **Step 5: Put every repository check before mutation**

Require commands:

```text
python3 ansible-playbook ansible-vault systemd-run systemctl sudo
install cp ssh ssh-keyscan mkpasswd stat
```

Validate source controller package, three entrypoints, both API programs, four units, Ansible config/group vars/playbooks/roles, and bootstrap script.

Run before service stop/destination write:

```bash
python3 -m py_compile \
  "${ALT_ROOT}/control/alt_deploy"/*.py \
  "${ALT_ROOT}/api/register_api.py" \
  "${ALT_ROOT}/api/process_pending.py" \
  "${ALT_ROOT}/control/alt-job-stage"
bash -n "${ALT_ROOT}/install-control-plane.sh"
bash -n "${ALT_ROOT}/install-control-plane-lib.sh"
bash -n "${ALT_ROOT}/bootstrap/bootstrap.sh"
cd "${REPO_ROOT}"
"${PYTHON_BIN}" -m pytest -q tests/alt_linux
```

- [ ] **Step 6: Add exact live-state prechecks**

Run source-tree CLI as `altserver` for `jobs active`, `vault check`, and `controller permissions`. Parse active count with Python JSON parsing; command failure, invalid JSON/type, or nonzero count blocks installation.

Apply `require_regular_nonempty` to current SSH private key, active authorized key, autoinstall profile, VM profile, and both ISO archives. Require SSH key mode `600` and `altserver:altserver` using `stat`.

Finally:

```bash
if systemctl is-active --quiet alt-deploy-process.service; then
    echo "Pending-registration processor is active" >&2
    return 1
fi
```

Do not stop/reconcile it.

- [ ] **Step 7: Add pre-mutation failure matrix**

Cover dependency/source/compile/test failure, invalid/malformed/active jobs, unhealthy Vault/permissions, unsafe key/static file, and active processor. All must preserve bytes and avoid maintenance/mutation commands.

- [ ] **Step 8: Run and commit**

```bash
python -m pytest -q tests/alt_linux/test_or3p1_installer.py -k pre_mutation
git add deploy/alt-linux/install-control-plane.sh \
  deploy/alt-linux/install-control-plane-lib.sh \
  tests/alt_linux/support/installer_sandbox.py \
  tests/alt_linux/test_or3p1_installer.py
git commit -m "test: enforce ALT installer pre-mutation gates"
```

Expected: PASS.

---

### Task 4: Complete Runtime Installation and Acceptance

**Files:**
- Modify: `deploy/alt-linux/install-control-plane-lib.sh`
- Modify: `tests/alt_linux/test_or3p1_installer.py`

**Interfaces:**
- Consumes: Task 3 prechecks and installed Task 2 readiness command.
- Produces: complete current-layout installation and final readiness acceptance.

- [ ] **Step 1: Write failing complete-file-set test**

Assert installation creates both API files, all four `/etc/systemd/system/alt-deploy-*` units, `/srv/alt-deploy/bootstrap/bootstrap.sh`, and registration `pending/ready/failed` directories.

- [ ] **Step 2: Add fixed maintenance window**

```bash
stop_if_loaded() {
    local unit=$1
    local load_state
    load_state=$(systemctl show "${unit}" --property=LoadState --value)
    if [[ "${load_state}" != "not-found" ]]; then
        systemctl stop "${unit}"
    fi
}

stop_if_loaded alt-deploy-process.path
stop_if_loaded alt-deploy-register.service
stop_if_loaded alt-deploy-http.service

if systemctl is-active --quiet alt-deploy-process.service; then
    echo "Processor became active during maintenance entry" >&2
    return 1
fi
```

Never stop processor/transient provision units.

- [ ] **Step 3: Install complete file set**

Install both API files `root:root 0755`, all units `root:root 0644`, and served bootstrap `root:root 0644`. Create state/jobs/assignments/registration root/subdirs and `.ssh` individually as `altserver:altserver 0700`. Never recursively chown/chmod existing state.

Example:

```bash
install -o root -g root -m 0755 \
  "${ALT_ROOT}/api/register_api.py" \
  "$(install_destination "${root_prefix}" /opt/alt-deploy-api/register_api.py)"
```

- [ ] **Step 4: Prove protected-state preservation**

Assert all seeded files remain byte-identical; only served `bootstrap/bootstrap.sh` may change. Keep the existing active Vault exclusion.

- [ ] **Step 5: Reload, start, and accept**

```bash
systemctl daemon-reload
systemctl enable --now alt-deploy-http.service
systemctl enable --now alt-deploy-register.service
systemctl enable --now alt-deploy-process.path
sudo -u altserver workstationctl --json controller readiness
echo "ALT deployment control plane installed successfully"
```

Success line is emitted only after readiness exit `0`.

- [ ] **Step 6: Add exact-order/readiness-failure tests**

Assert: all prechecks → stop path/register/http → second processor check → mutations → daemon-reload → enable/start three units → readiness → success. Readiness exit `11` means nonzero installer exit and no success line. Diagnostics may name the phase and OR-3P3/manual recovery, but not captured stderr/body.

- [ ] **Step 7: Run and commit**

```bash
python -m pytest -q tests/alt_linux/test_or3p1_installer.py
git add deploy/alt-linux/install-control-plane-lib.sh \
  tests/alt_linux/test_or3p1_installer.py
git commit -m "feat: complete ALT pilot control-plane install"
```

Expected: PASS.

---

### Task 5: Documentation, Verification, and PR

**Files:**
- Modify: `deploy/alt-linux/README.md`
- Modify: `docs/ALT_WORKSTATION_PROVISIONING_CONTEXT.md`
- Modify: `docs/ALT_WORKSTATION_PROVISIONING_NEXT_STEPS.md`
- Create: `docs/superpowers/plans/2026-07-21-alt-or3p1-verification.md`

- [ ] **Step 1: Update operator docs**

Document new commands, complete file set, pre-mutation blocks, external prerequisites, maintenance order, no target contact, no automatic rollback, mandatory OR-3P3, and separate OR-3P2. Remove stale installer descriptions.

- [ ] **Step 2: Run focused, ALT, and repository suites**

```bash
python -m pytest -q \
  tests/alt_linux/test_or3p1_cli_readiness.py \
  tests/alt_linux/test_or3p1_installer.py
python -m pytest -q tests/alt_linux
python -m pytest -q
```

Expected: zero failures; record counts/skips/warnings exactly.

- [ ] **Step 3: Run compile/syntax gates**

```bash
python3 -m py_compile \
  deploy/alt-linux/control/alt_deploy/*.py \
  deploy/alt-linux/api/register_api.py \
  deploy/alt-linux/api/process_pending.py \
  deploy/alt-linux/control/alt-job-stage
bash -n deploy/alt-linux/install-control-plane.sh
bash -n deploy/alt-linux/install-control-plane-lib.sh
bash -n deploy/alt-linux/bootstrap/bootstrap.sh
ANSIBLE_CONFIG="$PWD/deploy/alt-linux/ansible/ansible.cfg" \
  ansible-playbook --syntax-check \
  deploy/alt-linux/ansible/playbooks/01-preflight.yml
ANSIBLE_CONFIG="$PWD/deploy/alt-linux/ansible/ansible.cfg" \
  ansible-playbook --syntax-check \
  deploy/alt-linux/ansible/playbooks/02-provision-account.yml
```

Use a CI-safe synthetic Vault fixture if necessary; never alter production configuration.

- [ ] **Step 4: Check scope/integrity**

```bash
git diff --check origin/main...HEAD
git status --short
git diff --name-only origin/main...HEAD
```

Confirm no secret/runtime state, ISO archive, temporary workflow, or patch helper is present.

- [ ] **Step 5: Write evidence and commit docs**

Record exact branch/merge-ref SHA, fresh results, changed production files, and safety statement: synthetic filesystem only; no live controller/target/reference VM access.

```bash
git add deploy/alt-linux/README.md \
  docs/ALT_WORKSTATION_PROVISIONING_CONTEXT.md \
  docs/ALT_WORKSTATION_PROVISIONING_NEXT_STEPS.md \
  docs/superpowers/plans/2026-07-21-alt-or3p1-verification.md
git commit -m "docs: verify OR-3P1 pilot installer readiness"
```

- [ ] **Step 6: Review and open draft PR**

Request code review, open draft PR against `main`, and mark Ready only after current merge-ref checks pass and temporary infrastructure is absent. Never merge without explicit user confirmation.
