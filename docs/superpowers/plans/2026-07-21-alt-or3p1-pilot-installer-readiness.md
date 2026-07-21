# ALT OR-3P1 Pilot Installer Readiness Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Complete the existing ALT control-plane installer and add a local readiness gate so a controlled pilot can begin without building the deferred transactional release manager.

**Architecture:** Preserve the current `/opt/alt-deploy-control`, `/opt/alt-deploy-api`, `/home/altserver/ansible`, `/srv/alt-deploy`, and stable entrypoint layout. Add two read-only CLI surfaces (`jobs active`, `controller readiness`), then make the Bash installer perform every validation before mutation, install the missing API/unit/bootstrap assets, enter a short maintenance window, and accept the installation only after the installed readiness command passes.

**Tech Stack:** Python 3.11, argparse, pathlib, subprocess, urllib, Bash, systemd, Ansible, pytest, temporary filesystem/fake-PATH installer tests.

## Global Constraints

- Base commit is `500bca8fe0e309078930bc49c8fbd4ed0f2f6827`.
- OR-3P1 and OR-3P2 remain separate PRs; do not implement machine removal, archive, or re-registration here.
- Do not introduce versioned releases, a `current` symlink, transaction manifests, or automatic rollback.
- OR-3P3 backup/restore remains mandatory before applying OR-3P1 to `192.168.100.17`.
- Block before mutation when any job is `queued` or `running`, when a real job is malformed, or when `alt-deploy-process.service` is active.
- Do not reconcile jobs, stop transient provision units, or contact any workstation.
- Preserve active Vault files, Vault password, SSH identity, `known_hosts_autoinstall`, jobs, assignments, registrations, ISO-specific metadata archives, and `bootstrap/ansible_authorized_keys` byte-for-byte.
- Install `register_api.py`, `process_pending.py`, all four existing systemd units, and the repository bootstrap script.
- Readiness failure uses `controller_not_ready` with exit code `11` and safe diagnostics only.
- Runtime development/tests use only synthetic state and fake system commands; do not access the reference VM or production secrets.
- Temporary CI workflows and test patch helpers must be absent from the final PR.

---

## File Map

**Create production:**

- `deploy/alt-linux/control/alt_deploy/controller_readiness.py` — local, read-only readiness aggregation.

**Modify production:**

- `deploy/alt-linux/control/alt_deploy/cli.py` — add `jobs active` and `controller readiness`.
- `deploy/alt-linux/install-control-plane.sh` — complete prechecks, installation, maintenance order, and final readiness gate.

**Create test support:**

- `tests/alt_linux/support/installer_sandbox.py` — synthetic destination tree, sentinel state, fake command PATH, and command log.

**Create tests:**

- `tests/alt_linux/test_or3p1_cli_readiness.py` — CLI and readiness contracts.
- `tests/alt_linux/test_or3p1_installer.py` — pre-mutation, preservation, file-set, systemd-order, and final-gate tests.

**Modify documentation:**

- `deploy/alt-linux/README.md`
- `docs/ALT_WORKSTATION_PROVISIONING_CONTEXT.md`
- `docs/ALT_WORKSTATION_PROVISIONING_NEXT_STEPS.md`

---

### Task 1: Add the Safe Active-Job Query

**Files:**
- Modify: `deploy/alt-linux/control/alt_deploy/cli.py`
- Create: `tests/alt_linux/test_or3p1_cli_readiness.py`

**Interfaces:**
- Consumes: `JobRepository.list() -> list[JobRecord]` and `ACTIVE_STATES = {"queued", "running"}`.
- Produces: `workstationctl --json jobs active` with keys `status`, `active_jobs`, and `count`.

- [ ] **Step 1: Write the failing parser and empty-list test**

```python
def test_jobs_active_returns_empty_safe_summary(settings) -> None:
    rc, payload = run_cli(["--json", "jobs", "active"], settings)
    assert rc == 0
    assert payload == {
        "status": "ok",
        "active_jobs": [],
        "count": 0,
    }
```

Run:

```bash
python -m pytest -q tests/alt_linux/test_or3p1_cli_readiness.py::test_jobs_active_returns_empty_safe_summary
```

Expected: FAIL because `active` is not a jobs subcommand.

- [ ] **Step 2: Add the parser and dispatch branch**

In `build_parser()`:

```python
job_commands.add_parser("active")
```

In `main()` before `jobs status`/`jobs log` handling:

```python
elif parsed.command == "jobs" and parsed.job_command == "active":
    active_jobs = [
        job
        for job in JobRepository(active_settings).list()
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

Do not call `job.to_public_dict()` because it exposes fields outside the approved summary.

- [ ] **Step 3: Add active/terminal filtering and redaction tests**

Create one queued, one running, one successful, and one failed synthetic job. Assert exact ordering inherited from `JobRepository.list()` and exact key set:

```python
assert payload["count"] == 2
assert [item["state"] for item in payload["active_jobs"]] == [
    "running",
    "queued",
]
assert all(
    set(item) == {
        "job_id",
        "machine_uuid",
        "state",
        "stage",
        "created_at",
    }
    for item in payload["active_jobs"]
)
serialized = json.dumps(payload, ensure_ascii=False)
assert "employee_full_name" not in serialized
assert "ansible_output" not in serialized
assert "result" not in serialized
```

- [ ] **Step 4: Add malformed-real-job fail-closed test**

Write a real `job-*` directory with malformed `status.json`; invoke `jobs active` and assert the existing `job_invalid` or `job_stage_history_invalid` error propagates. It must not return `count=0`.

- [ ] **Step 5: Run focused tests**

```bash
python -m pytest -q tests/alt_linux/test_or3p1_cli_readiness.py -k jobs_active
```

Expected: PASS.

- [ ] **Step 6: Commit**

```bash
git add deploy/alt-linux/control/alt_deploy/cli.py \
  tests/alt_linux/test_or3p1_cli_readiness.py
git commit -m "feat: expose active ALT provision jobs"
```

---

### Task 2: Add the Local Controller Readiness Gate

**Files:**
- Create: `deploy/alt-linux/control/alt_deploy/controller_readiness.py`
- Modify: `deploy/alt-linux/control/alt_deploy/cli.py`
- Modify: `tests/alt_linux/test_or3p1_cli_readiness.py`

**Interfaces:**
- Consumes: `Settings`, `JobRepository.list()`, `ControllerPermissionAuditor.check()`, and `VaultHealthChecker.check()`.
- Produces: `ControllerReadinessChecker(settings).check() -> dict[str, object]` and CLI `controller readiness`.

- [ ] **Step 1: Write the failing healthy-contract test**

Monkeypatch readiness system boundaries and assert:

```python
rc, payload = run_cli(["--json", "controller", "readiness"], settings)
assert rc == 0
assert payload["status"] == "ok"
assert payload["controller_readiness"]["ready"] is True
assert payload["controller_readiness"]["checks"] == {
    "active_jobs_empty": True,
    "controller_permissions": True,
    "vault": True,
    "runtime_entrypoints": True,
    "api_files": True,
    "static_assets": True,
    "systemd_units_loaded": True,
    "systemd_units_enabled": True,
    "systemd_units_active": True,
    "registration_api_health": True,
    "static_http_health": True,
    "ansible_preflight_syntax": True,
    "ansible_provision_syntax": True,
}
```

Expected: FAIL because the command/module does not exist.

- [ ] **Step 2: Create the checker skeleton and stable command seam**

Create module constants and injectable module-level helpers:

```python
READINESS_CHECK_NAMES = (
    "active_jobs_empty",
    "controller_permissions",
    "vault",
    "runtime_entrypoints",
    "api_files",
    "static_assets",
    "systemd_units_loaded",
    "systemd_units_enabled",
    "systemd_units_active",
    "registration_api_health",
    "static_http_health",
    "ansible_preflight_syntax",
    "ansible_provision_syntax",
)


def run_command(command: list[str], *, timeout: int = 30):
    return subprocess.run(
        command,
        text=True,
        capture_output=True,
        check=False,
        timeout=timeout,
    )


class ControllerReadinessChecker:
    def __init__(self, settings: Settings):
        self.settings = settings

    def check(self) -> dict[str, object]:
        ...
```

Tests monkeypatch `controller_readiness.run_command` and `controller_readiness.urlopen`; production code does not accept arbitrary commands or URLs from callers.

- [ ] **Step 3: Implement safe filesystem checks**

Use `lstat()` and require regular, non-symlink, non-empty files. Runtime entrypoints additionally require `os.access(path, os.X_OK)`.

Required runtime paths:

```python
(
    Path("/usr/local/sbin/workstationctl"),
    self.settings.provision_worker_path,
    self.settings.job_stage_helper_path,
)
```

Required API paths:

```python
(
    Path("/opt/alt-deploy-api/register_api.py"),
    Path("/opt/alt-deploy-api/process_pending.py"),
)
```

Required static paths:

```python
(
    Path("/srv/alt-deploy/metadata/autoinstall.scm"),
    Path("/srv/alt-deploy/metadata/vm-profile.scm"),
    Path("/srv/alt-deploy/metadata/pkg-groups.tar"),
    Path("/srv/alt-deploy/metadata/install-scripts.tar"),
    Path("/srv/alt-deploy/bootstrap/bootstrap.sh"),
    Path("/srv/alt-deploy/bootstrap/ansible_authorized_keys"),
)
```

Add a `bash -n /srv/alt-deploy/bootstrap/bootstrap.sh` subprocess check. Diagnostics may include only logical names and paths, not contents.

- [ ] **Step 4: Implement source-of-truth and active-job checks**

```python
checks["active_jobs_empty"] = not any(
    job.state in {"queued", "running"}
    for job in JobRepository(self.settings).list()
)
```

Call permission and Vault sources of truth and convert their safe success/failure into booleans:

```python
try:
    ControllerPermissionAuditor(self.settings).check()
except ControlError:
    checks["controller_permissions"] = False
else:
    checks["controller_permissions"] = True
```

Repeat for `VaultHealthChecker`. Do not copy their path or secret validation rules.

- [ ] **Step 5: Implement systemd and endpoint checks**

Query only the fixed unit allowlist:

```python
MANAGED_UNITS = (
    "alt-deploy-http.service",
    "alt-deploy-register.service",
    "alt-deploy-process.path",
    "alt-deploy-process.service",
)
```

Use `systemctl show <unit> --property=LoadState --property=ActiveState --property=UnitFileState --value` or an equivalent fixed command. Expected:

```text
http/register/path: loaded, enabled, active
process.service: loaded, static, inactive while idle
```

Use fixed local URLs with a five-second timeout:

```text
http://127.0.0.1:8088/health
http://127.0.0.1:8087/bootstrap/bootstrap.sh
http://127.0.0.1:8087/bootstrap/ansible_authorized_keys
http://127.0.0.1:8087/metadata/autoinstall.scm
```

For registration health, parse JSON and require `status == "ok"`. For static files, require HTTP 200 and read at most one byte; never return body content.

- [ ] **Step 6: Implement installed Ansible syntax checks**

Run as the current `altserver` caller with fixed paths and environment:

```python
[
    "ansible-playbook",
    "--syntax-check",
    "/home/altserver/ansible/playbooks/01-preflight.yml",
]
```

and the corresponding provision playbook. Set `ANSIBLE_CONFIG=/home/altserver/ansible/ansible.cfg`. Store only the boolean return-code result.

- [ ] **Step 7: Raise the exact readiness error**

After all checks:

```python
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

Add parser `controller readiness` and CLI payload:

```python
payload = {
    "status": "ok",
    "controller_readiness": ControllerReadinessChecker(
        active_settings
    ).check(),
}
```

- [ ] **Step 8: Add failure, redaction, and no-target tests**

Parameterize each check to fail. Assert exit `11`, exact failed check, and no raw subprocess output, HTTP body, Vault fixture, private-key fixture, or employee data in JSON. Install a subprocess spy that rejects commands containing `ssh`, workstation IPs, inventory strings, or provision worker execution.

- [ ] **Step 9: Run focused tests and commit**

```bash
python -m pytest -q tests/alt_linux/test_or3p1_cli_readiness.py
```

Expected: PASS.

```bash
git add deploy/alt-linux/control/alt_deploy/controller_readiness.py \
  deploy/alt-linux/control/alt_deploy/cli.py \
  tests/alt_linux/test_or3p1_cli_readiness.py
git commit -m "feat: add ALT controller readiness gate"
```

---

### Task 3: Build the Installer Sandbox and Prove Pre-Mutation Failures

**Files:**
- Create: `tests/alt_linux/support/installer_sandbox.py`
- Create: `tests/alt_linux/test_or3p1_installer.py`
- Modify: `deploy/alt-linux/install-control-plane.sh`

**Interfaces:**
- Produces: `InstallerSandbox.run(*args, active_jobs=None, processor_active=False, readiness_ok=True) -> CompletedProcess[str]`, `command_log`, and destination-root helpers.
- Installer consumes test-only `ALT_DEPLOY_INSTALL_TESTING=1`, `ALT_DEPLOY_INSTALL_ROOT`, and `ALT_DEPLOY_TEST_EUID`; non-test execution rejects a non-empty root override.

- [ ] **Step 1: Create a failing no-mutation active-job test**

Seed destination sentinels and invoke the installer with a canned `jobs active` response containing one running job. Assert non-zero exit, unchanged sentinel bytes, and an empty mutation/systemd command log.

- [ ] **Step 2: Add narrowly gated installer test seams**

At the top of the installer:

```bash
INSTALL_TESTING=${ALT_DEPLOY_INSTALL_TESTING:-0}
DEST_ROOT=${ALT_DEPLOY_INSTALL_ROOT:-}
EFFECTIVE_EUID=${ALT_DEPLOY_TEST_EUID:-${EUID}}

if [[ -n "${DEST_ROOT}" && "${INSTALL_TESTING}" != 1 ]]; then
    echo "ALT_DEPLOY_INSTALL_ROOT is test-only" >&2
    exit 2
fi

root_path() {
    printf '%s%s' "${DEST_ROOT}" "$1"
}
```

Use `root_path` for every destination, never for repository source paths. Production behavior with an empty prefix remains unchanged.

- [ ] **Step 3: Implement the fake-PATH sandbox**

The sandbox creates executable fakes for `id`, `sudo`, `systemctl`, `install`, `cp`, `rm`, `chown`, `chmod`, and `find`. Each fake appends one JSON line to `command_log`. File fakes must perform the requested copy/mkdir/chmod inside `DEST_ROOT` while ignoring owner changes; `sudo` returns configured JSON for `jobs active` and `controller readiness`.

Seed byte sentinels for:

```text
vault.yml
.ansible-vault-pass
id_ed25519
id_ed25519.pub
known_hosts_autoinstall
bootstrap/ansible_authorized_keys
metadata/pkg-groups.tar
metadata/install-scripts.tar
one job request/status/log
one assignment
pending/ready/failed registration records
```

- [ ] **Step 4: Move all source validation before mutation**

Add a fixed required-source list covering both API files, all four unit files, three entrypoints, Ansible config/group vars/playbooks/roles, and bootstrap script. Before any destination mutation run:

```bash
python3 -m py_compile \
  "${ALT_ROOT}/control/alt_deploy"/*.py \
  "${ALT_ROOT}/api/register_api.py" \
  "${ALT_ROOT}/api/process_pending.py" \
  "${ALT_ROOT}/control/alt-job-stage"
bash -n "${ALT_ROOT}/install-control-plane.sh"
bash -n "${ALT_ROOT}/bootstrap/bootstrap.sh"
cd "${REPO_ROOT}"
"${PYTHON_BIN}" -m pytest -q tests/alt_linux
```

Then invoke the source-tree CLI as `altserver`:

```bash
PYTHONPATH="${ALT_ROOT}/control" \
sudo -u altserver env \
  PYTHONPATH="${ALT_ROOT}/control" \
  "${PYTHON_BIN}" -m alt_deploy.cli --json jobs active
```

Parse `count` with Python, not `grep`; fail if the command fails, JSON is invalid, or `count != 0`.

- [ ] **Step 5: Add processor-active precheck**

Before mutation require:

```bash
if systemctl is-active --quiet alt-deploy-process.service; then
    echo "Pending-registration processor is active" >&2
    exit 1
fi
```

Do not stop it automatically.

- [ ] **Step 6: Add pre-mutation test matrix**

Cover missing dependency, missing source, compilation failure, ALT test failure, invalid active-job JSON, malformed real job, active job, and active processor. For every case assert the original runtime/state sentinels and unit state are unchanged.

- [ ] **Step 7: Run tests and commit**

```bash
python -m pytest -q tests/alt_linux/test_or3p1_installer.py -k pre_mutation
```

Expected: PASS.

```bash
git add deploy/alt-linux/install-control-plane.sh \
  tests/alt_linux/support/installer_sandbox.py \
  tests/alt_linux/test_or3p1_installer.py
git commit -m "test: enforce ALT installer pre-mutation gates"
```

---

### Task 4: Complete Runtime Installation and Final Acceptance Order

**Files:**
- Modify: `deploy/alt-linux/install-control-plane.sh`
- Modify: `tests/alt_linux/test_or3p1_installer.py`

**Interfaces:**
- Consumes: successful Task 3 prechecks and `controller readiness` from Task 2.
- Produces: complete current-layout installation and success only after readiness.

- [ ] **Step 1: Write the failing complete-file-set test**

Run the sandbox successfully and assert exact destinations exist:

```text
/opt/alt-deploy-api/register_api.py
/opt/alt-deploy-api/process_pending.py
/etc/systemd/system/alt-deploy-http.service
/etc/systemd/system/alt-deploy-register.service
/etc/systemd/system/alt-deploy-process.path
/etc/systemd/system/alt-deploy-process.service
/srv/alt-deploy/bootstrap/bootstrap.sh
```

Also assert `pending`, `ready`, and `failed` directories exist.

- [ ] **Step 2: Add the maintenance window in fixed order**

After every precheck succeeds:

```bash
systemctl stop alt-deploy-process.path
systemctl stop alt-deploy-register.service
systemctl stop alt-deploy-http.service

if systemctl is-active --quiet alt-deploy-process.service; then
    echo "Processor became active during maintenance entry" >&2
    exit 1
fi
```

Do not stop `alt-deploy-process.service` or transient provision units.

- [ ] **Step 3: Install the missing runtime assets**

Use exact ownership/modes:

```bash
install -o root -g root -m 0755 \
  "${ALT_ROOT}/api/register_api.py" \
  "$(root_path /opt/alt-deploy-api/register_api.py)"
install -o root -g root -m 0755 \
  "${ALT_ROOT}/api/process_pending.py" \
  "$(root_path /opt/alt-deploy-api/process_pending.py)"
install -o root -g root -m 0644 \
  "${ALT_ROOT}/systemd/alt-deploy-http.service" \
  "$(root_path /etc/systemd/system/alt-deploy-http.service)"
```

Repeat for the remaining units. Install the repository bootstrap as root-owned mode `0644` to `/srv/alt-deploy/bootstrap/bootstrap.sh`; readiness validates `bash -n`, and HTTP serves it read-only.

Create registration subdirectories individually as `altserver:altserver 0700`. Do not recursively chown or chmod existing files.

- [ ] **Step 4: Preserve external and private state exactly**

Replace recursive state operations with parent-only `install -d`. Keep the existing Vault exclusion. Tests compare all seeded sentinel bytes before/after and prove only `bootstrap/bootstrap.sh` changes while `bootstrap/ansible_authorized_keys` and metadata archives remain identical.

- [ ] **Step 5: Add systemd reload/start and final readiness call**

```bash
systemctl daemon-reload
systemctl enable --now alt-deploy-http.service
systemctl enable --now alt-deploy-register.service
systemctl enable --now alt-deploy-process.path

sudo -u altserver workstationctl --json controller readiness

echo "ALT deployment control plane installed successfully"
```

The success message must be the final output after readiness returns zero.

- [ ] **Step 6: Add exact order and failure tests**

Assert command-log ordering:

```text
all prechecks
stop path
stop register
stop http
second processor check
all file mutations
daemon-reload
enable/start http
enable/start register
enable/start path
controller readiness
success output
```

When readiness returns exit `11`, assert installer exit is non-zero and success text is absent. Confirm the installer reports that OR-3P1 has no automatic rollback and points to OR-3P3/manual recovery documentation without exposing command stderr bodies.

- [ ] **Step 7: Run installer and preservation tests**

```bash
python -m pytest -q tests/alt_linux/test_or3p1_installer.py
```

Expected: PASS.

- [ ] **Step 8: Commit**

```bash
git add deploy/alt-linux/install-control-plane.sh \
  tests/alt_linux/test_or3p1_installer.py
git commit -m "feat: complete ALT pilot control-plane install"
```

---

### Task 5: Documentation, Full Verification, and PR Preparation

**Files:**
- Modify: `deploy/alt-linux/README.md`
- Modify: `docs/ALT_WORKSTATION_PROVISIONING_CONTEXT.md`
- Modify: `docs/ALT_WORKSTATION_PROVISIONING_NEXT_STEPS.md`
- Create: `docs/superpowers/plans/2026-07-21-alt-or3p1-verification.md`

**Interfaces:**
- Consumes: final OR-3P1 branch.
- Produces: operator-visible contracts, exact fresh verification evidence, and a reviewable draft PR.

- [ ] **Step 1: Update operator documentation**

Document:

```text
jobs active
controller readiness
complete installed API/unit/bootstrap file set
active-job and active-processor pre-mutation block
external static prerequisites
maintenance stop/start order
no workstation contact during readiness
no automatic rollback
OR-3P3 required before live controller rollout
OR-3P2 machine lifecycle remains next and separate
```

Remove stale statements that the installer copies only `process_pending.py` or merely restarts the path unit.

- [ ] **Step 2: Run focused tests**

```bash
python -m pytest -q \
  tests/alt_linux/test_or3p1_cli_readiness.py \
  tests/alt_linux/test_or3p1_installer.py
```

Expected: PASS.

- [ ] **Step 3: Run the complete ALT suite**

```bash
python -m pytest -q tests/alt_linux
```

Expected: PASS with zero failures.

- [ ] **Step 4: Run the complete repository suite**

```bash
python -m pytest -q
```

Expected: PASS with zero failures; record unrelated environment-dependent skips/warnings precisely.

- [ ] **Step 5: Run compile and syntax gates**

```bash
python3 -m py_compile \
  deploy/alt-linux/control/alt_deploy/*.py \
  deploy/alt-linux/api/register_api.py \
  deploy/alt-linux/api/process_pending.py \
  deploy/alt-linux/control/alt-job-stage
bash -n deploy/alt-linux/install-control-plane.sh
bash -n deploy/alt-linux/bootstrap/bootstrap.sh
ANSIBLE_CONFIG="$PWD/deploy/alt-linux/ansible/ansible.cfg" \
  ansible-playbook --syntax-check \
  deploy/alt-linux/ansible/playbooks/01-preflight.yml
ANSIBLE_CONFIG="$PWD/deploy/alt-linux/ansible/ansible.cfg" \
  ansible-playbook --syntax-check \
  deploy/alt-linux/ansible/playbooks/02-provision-account.yml
```

Use a CI-safe synthetic Vault password fixture where required; never weaken production configuration.

- [ ] **Step 6: Check diff integrity and scope**

```bash
git diff --check origin/main...HEAD
git status --short
git diff --name-only origin/main...HEAD
```

Confirm no active Vault, password file, SSH identity, registration data, jobs, assignments, ISO archives, temporary workflow, or test patch helper is present.

- [ ] **Step 7: Write fresh verification evidence**

Record exact branch SHA, merge-ref SHA, focused/ALT/full test counts, compile/syntax results, changed production files, and explicit safety statement: synthetic filesystem only, no real controller mutation, no target access, and no reference VM access.

- [ ] **Step 8: Commit documentation/evidence**

```bash
git add deploy/alt-linux/README.md \
  docs/ALT_WORKSTATION_PROVISIONING_CONTEXT.md \
  docs/ALT_WORKSTATION_PROVISIONING_NEXT_STEPS.md \
  docs/superpowers/plans/2026-07-21-alt-or3p1-verification.md
git commit -m "docs: verify OR-3P1 pilot installer readiness"
```

- [ ] **Step 9: Review and open a draft PR**

Review every changed file, request code review, and open a draft PR against `main`. Mark Ready only after current merge-ref checks pass and temporary verification infrastructure is absent. Do not merge without explicit user confirmation.
