# ALT Job Retention and Cleanup Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Add a safe, explicit retention workflow for ALT provision jobs and logs without deleting assignments or active work.

**Architecture:** A focused `JobRetentionManager` scans only direct children of `Settings.jobs_dir`, classifies terminal jobs by `finished_at`, and returns a structured cleanup report. Dry-run is the default. Apply mode archives old terminal logs atomically and removes expired terminal job directories without following symbolic links; all work runs under the existing controller lock.

**Tech Stack:** Python 3.12 standard library, argparse, gzip, pathlib/os/shutil, pytest.

## Global Constraints

- Work only on `feat/alt-workstation-provisioning-mvp`.
- Run only `tests/alt_linux` by default.
- Default terminal-job retention is 90 days.
- Default terminal-log archive threshold is 14 days.
- `queued` and `running` jobs are never archived or deleted.
- Assignment records under `/var/lib/alt-deploy/assignments` are never changed by cleanup.
- Cleanup must not follow a symbolic link outside `Settings.jobs_dir`.
- Dry-run is the default; mutation requires explicit `--apply`.
- Cleanup uses `workstationctl.lock`.
- Do not run cleanup against real controller state until read-only output is reviewed.

---

### Task 1: Dry-run retention classification

**Files:**
- Create: `deploy/alt-linux/control/alt_deploy/job_retention.py`
- Create: `tests/alt_linux/test_job_retention.py`

**Interfaces:**
- Produces: `DEFAULT_RETENTION_DAYS = 90`
- Produces: `DEFAULT_ARCHIVE_AFTER_DAYS = 14`
- Produces: `JobRetentionManager(settings).cleanup(*, apply: bool, now: datetime, retention_days: int, archive_after_days: int) -> dict[str, object]`

- [ ] **Step 1: Write a failing dry-run test**

Create terminal jobs older than 90 and 14 days, a recent terminal job, and an old active job. Assert dry-run reports `delete_job` and `archive_log` actions but changes no file or assignment.

- [ ] **Step 2: Verify RED**

Run:

```bash
.venv/bin/python -m pytest -q \
  tests/alt_linux/test_job_retention.py::test_cleanup_dry_run_classifies_jobs_without_mutation
```

Expected: FAIL because `alt_deploy.job_retention` does not exist.

- [ ] **Step 3: Implement minimal classification**

Scan only direct, non-symlink directories matching the job ID pattern. Load `request.json` and `status.json` through `JobRepository`. For terminal jobs, parse `finished_at`; report:

```text
age >= retention_days                 -> delete_job
archive_after_days <= age < retention -> archive_log when ansible.log exists
otherwise                             -> retained
queued/running                        -> active_job
```

Do not mutate in Task 1.

- [ ] **Step 4: Verify GREEN**

Run the focused test and `tests/alt_linux/test_jobs.py`.

- [ ] **Step 5: Commit**

```bash
git add deploy/alt-linux/control/alt_deploy/job_retention.py \
  tests/alt_linux/test_job_retention.py
git commit -m "feat: plan ALT job retention cleanup"
```

---

### Task 2: Safe log archive apply mode

**Files:**
- Modify: `deploy/alt-linux/control/alt_deploy/job_retention.py`
- Modify: `tests/alt_linux/test_job_retention.py`

**Interfaces:**
- Produces atomic `ansible.log.gz` mode `0600`.

- [ ] **Step 1: Write failing archive tests**

Assert apply mode creates valid gzip content, removes the original `ansible.log`, leaves `request.json`, `status.json`, `result.json`, and assignment unchanged, and is idempotent on a second run.

- [ ] **Step 2: Verify RED**

Run focused archive tests. Expected: action is reported but files remain unchanged.

- [ ] **Step 3: Implement atomic archive**

Open `ansible.log` with no-follow semantics, write a private temporary gzip file in the same job directory, flush and fsync it, replace `ansible.log.gz`, then unlink the original. Reject a symlink source log.

- [ ] **Step 4: Verify GREEN**

Run all retention and job tests.

- [ ] **Step 5: Commit**

```bash
git commit -am "feat: archive retained provision logs safely"
```

---

### Task 3: Safe expired-job deletion and CLI

**Files:**
- Modify: `deploy/alt-linux/control/alt_deploy/job_retention.py`
- Modify: `deploy/alt-linux/control/alt_deploy/cli.py`
- Modify: `tests/alt_linux/test_job_retention.py`
- Create: `tests/alt_linux/test_job_cleanup_cli.py`

**Interfaces:**
- Adds: `workstationctl --json jobs cleanup`
- Adds: `--apply`, `--retention-days`, `--archive-after-days`

- [ ] **Step 1: Write failing deletion and CLI tests**

Assert default CLI is dry-run, apply removes only expired terminal job directories, active jobs survive, assignments survive, a symlink job directory is skipped, and an external symlink target inside a deleted job remains untouched.

- [ ] **Step 2: Verify RED**

Run focused tests. Expected: unsupported `cleanup` command or no deletion.

- [ ] **Step 3: Implement safe apply mode**

Validate thresholds as positive integers with `archive_after_days < retention_days`. Run under `exclusive_lock(settings.lock_file)`. Use a validated direct child path and symlink-safe recursive removal. Return structured `actions`, `skipped`, policy, and `dry_run` fields.

- [ ] **Step 4: Verify GREEN**

Run cleanup, reconciliation, job, CLI, and all ALT tests.

- [ ] **Step 5: Commit**

```bash
git add deploy/alt-linux/control/alt_deploy tests/alt_linux
git commit -m "feat: add safe provision job cleanup CLI"
```

---

### Task 4: Documentation and controller verification

**Files:**
- Modify: `deploy/alt-linux/README.md`
- Modify: `docs/ALT_WORKSTATION_PROVISIONING_CONTEXT.md`
- Modify: `docs/ALT_WORKSTATION_PROVISIONING_NEXT_STEPS.md`
- Modify: `tests/alt_linux/test_provisioning_docs.py`

- [ ] **Step 1: Write failing documentation test**

Require the CLI command, 90/14-day policy, dry-run default, `--apply`, assignment independence, active-job protection, common lock, and symlink boundary.

- [ ] **Step 2: Verify RED**

Run the documentation test. Expected: missing retention contract.

- [ ] **Step 3: Update operating documentation**

Document read-only review before apply and state that no automatic timer is installed yet.

- [ ] **Step 4: Run full verification**

```bash
.venv/bin/python -m pytest -q tests/alt_linux
python3 -m py_compile deploy/alt-linux/control/alt_deploy/*.py \
  deploy/alt-linux/api/process_pending.py
bash -n deploy/alt-linux/install-control-plane.sh
bash -n deploy/alt-linux/bootstrap/bootstrap.sh
ANSIBLE_CONFIG="$PWD/deploy/alt-linux/ansible/ansible.cfg" \
  ansible-playbook --syntax-check \
  deploy/alt-linux/ansible/playbooks/01-preflight.yml
ANSIBLE_CONFIG="$PWD/deploy/alt-linux/ansible/ansible.cfg" \
  ansible-playbook --syntax-check \
  deploy/alt-linux/ansible/playbooks/02-provision-account.yml
git diff --check
git status --short
```

- [ ] **Step 5: Deploy only after review**

Install the updated runtime, run `jobs cleanup` without `--apply`, review its report, and do not apply deletion until explicitly approved.
