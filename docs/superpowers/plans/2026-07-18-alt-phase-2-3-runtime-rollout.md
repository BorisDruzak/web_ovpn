# ALT Phase 2.3 Controlled Runtime Rollout Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:executing-plans to execute this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Install the verified Phase 2.3 structured job-stage implementation on the ALT deployment controller without losing assignments, secrets, registrations, or rollback capability, then validate the complete stage history on one new disposable workstation.

**Architecture:** The rollout is split into two separately approved changes. Phase A freezes controller mutations, inventories and backs up all affected runtime paths, removes only explicitly reviewed pre-Phase-2.3 terminal jobs, installs the exact verified commit, and performs read-only smoke checks. Phase B is a later live acceptance on a new clean VM or physical workstation; it must never use the already assigned reference UUID.

**Tech Stack:** Bash, Python 3.12 standard library, systemd, Ansible Core, atomic JSON job state, SHA-256 evidence, GNU tar, ALT Linux controller runtime.

## Global Constraints

- Execute only from `/home/altserver/web_ovpn-src/.worktrees/alt-workstation-mvp`.
- The approved repository commit is exactly `51b8e7dd3bba3b3c2e52cce3906fdd021acf3587`.
- `HEAD` and `origin/feat/alt-workstation-provisioning-mvp` must both equal the approved commit immediately before rollout.
- The clean-worktree final gate must still pass: 165 ALT tests, Python compile, two Bash syntax checks, two Ansible syntax checks, `git diff --check`, and clean status.
- Do not run any rollout mutation until the operator explicitly approves Phase A.
- Do not delete any job until its exact manifest has been displayed and explicitly approved.
- Do not hard-code an expected old-job count. The read-only audit is the source of truth.
- Refuse rollout if any old job is `queued` or `running`, any job already contains `stage_history`, any job entry is unsafe, or any status changes after approval.
- Do not read, print, archive, copy, checksum, or expose `/home/altserver/.ansible-vault-pass`, decrypted Vault content, password hashes, or private SSH keys.
- Do not include `/home/altserver/ansible/group_vars/vault.yml`, `/home/altserver/.ansible-vault-pass`, `/home/altserver/.ssh/id_ed25519`, or `/var/lib/alt-deploy/assignments` in runtime backup archives.
- Assignment files are never deleted or restored by this rollout. Their path list and SHA-256 values are compared before and after.
- Do not run `jobs cleanup --apply` during rollout.
- Do not run `provision start` during Phase A.
- Never provision assigned reference UUID `53b03180-5d78-11f0-bd95-f027db877a00` again.
- Phase B must use a new clean disposable VM or physical workstation with a different UUID.
- Do not mix OpenVPN, netctl, Network Observer, web UI, Plasma profile work, release/reassignment, or unrelated Ansible roles into this rollout.
- Every command output must be stored in a root-only evidence directory.
- Any failed install, installed-file mismatch, assignment checksum change, unhealthy Vault/permissions result, nonzero cleanup/reconciliation count, or failed required service check triggers rollback. Do not retry the installer over an uncertain partial state.

---

## Runtime Change Map

The installer changes these paths:

```text
/opt/alt-deploy-control/alt_deploy/
/usr/local/sbin/workstationctl
/usr/local/libexec/alt-provision-worker
/usr/local/libexec/alt-job-stage
/opt/alt-deploy-api/process_pending.py
/home/altserver/ansible/ansible.cfg
/home/altserver/ansible/group_vars/all.yml
/home/altserver/ansible/playbooks/
/home/altserver/ansible/roles/
```

The rollout intentionally changes this state path before installation:

```text
/var/lib/alt-deploy/jobs/
```

The rollout must leave these paths byte-identical:

```text
/var/lib/alt-deploy/assignments/
/home/altserver/ansible/group_vars/vault.yml
/home/altserver/.ansible-vault-pass
/home/altserver/.ssh/id_ed25519
```

Systemd services used by the maintenance window:

```text
alt-deploy-register.service
alt-deploy-process.path
alt-deploy-process.service
alt-provision-<job_id>.service
```

---

### Task 1: Pin the Verified Source and Create the Evidence Directory

**Files:**
- Read: repository worktree at `/home/altserver/web_ovpn-src/.worktrees/alt-workstation-mvp`
- Create at runtime: `/root/alt-phase-2-3-rollout.env`
- Create at runtime: `/root/alt-phase-2-3-rollout-<timestamp>/`

**Interfaces:**
- Produces: `ROLLOUT_DIR`, `APPROVED_SHA`, `WORKTREE`, and source metadata used by every later task.
- Does not mutate controller runtime.

- [ ] **Step 1: Verify exact commit and clean worktree**

```bash
cd /home/altserver/web_ovpn-src/.worktrees/alt-workstation-mvp || exit 1

git fetch origin feat/alt-workstation-provisioning-mvp || exit 1

APPROVED_SHA=51b8e7dd3bba3b3c2e52cce3906fdd021acf3587
HEAD_SHA="$(git rev-parse HEAD)"
REMOTE_SHA="$(git rev-parse origin/feat/alt-workstation-provisioning-mvp)"

printf 'APPROVED_SHA=%s\nHEAD_SHA=%s\nREMOTE_SHA=%s\n' \
  "$APPROVED_SHA" "$HEAD_SHA" "$REMOTE_SHA"

test "$HEAD_SHA" = "$APPROVED_SHA"
test "$REMOTE_SHA" = "$APPROVED_SHA"
test -z "$(git status --short)"
```

Expected: all three SHA values are identical and the final two `test` commands exit `0`.

- [ ] **Step 2: Create a root-only evidence directory**

```bash
STAMP="$(date +%Y%m%d-%H%M%S)"
ROLLOUT_DIR="/root/alt-phase-2-3-rollout-${STAMP}"

sudo install -d -o root -g root -m 0700 "$ROLLOUT_DIR"

printf '%s\n' \
  "ROLLOUT_DIR=${ROLLOUT_DIR}" \
  "APPROVED_SHA=51b8e7dd3bba3b3c2e52cce3906fdd021acf3587" \
  "WORKTREE=/home/altserver/web_ovpn-src/.worktrees/alt-workstation-mvp" \
  | sudo tee /root/alt-phase-2-3-rollout.env >/dev/null

sudo chmod 0600 /root/alt-phase-2-3-rollout.env
sudo cat /root/alt-phase-2-3-rollout.env
```

Expected: the file contains only the evidence directory, approved SHA, and worktree path.

- [ ] **Step 3: Save repository metadata**

```bash
source <(sudo cat /root/alt-phase-2-3-rollout.env)
cd "$WORKTREE" || exit 1

{
  git status --short
  git log -1 --format='commit=%H%nsubject=%s%nauthor=%an <%ae>%ndate=%aI'
  git branch -vv
} | sudo tee "$ROLLOUT_DIR/repository.txt" >/dev/null

sudo chmod 0600 "$ROLLOUT_DIR/repository.txt"
sudo cat "$ROLLOUT_DIR/repository.txt"
```

Expected: the status section is empty and `commit=` equals `APPROVED_SHA`.

---

### Task 2: Re-run the Complete Pre-Rollout Gate

**Files:**
- Read: all repository ALT provisioning files
- Create at runtime: `$ROLLOUT_DIR/pre-rollout-gate/`

**Interfaces:**
- Produces fresh proof that the exact source being installed still passes the complete gate.
- Does not mutate controller runtime.

- [ ] **Step 1: Run the complete gate**

```bash
source <(sudo cat /root/alt-phase-2-3-rollout.env)
cd "$WORKTREE" || exit 1

LOG_DIR="$ROLLOUT_DIR/pre-rollout-gate"
sudo install -d -o root -g root -m 0700 "$LOG_DIR"
TMP_LOG_DIR="/tmp/alt-phase-2-3-pre-rollout-$$"
install -d -m 0700 "$TMP_LOG_DIR"
trap 'rm -rf "$TMP_LOG_DIR"' EXIT

FAIL=0

run_check() {
  NAME="$1"
  shift
  "$@" >"$TMP_LOG_DIR/${NAME}.log" 2>&1
  RC=$?
  printf '%s_RC=%s\n' "$NAME" "$RC"
  if [ "$RC" -ne 0 ]; then
    FAIL=1
    tail -n 160 "$TMP_LOG_DIR/${NAME}.log"
  fi
}

run_check tests \
  .venv/bin/python -m pytest -q tests/alt_linux

run_check compile \
  python3 -m py_compile \
    deploy/alt-linux/control/alt_deploy/*.py \
    deploy/alt-linux/api/process_pending.py \
    deploy/alt-linux/control/alt-job-stage

run_check install_bash \
  bash -n deploy/alt-linux/install-control-plane.sh

run_check bootstrap_bash \
  bash -n deploy/alt-linux/bootstrap/bootstrap.sh

run_check preflight_syntax \
  env ANSIBLE_CONFIG="$PWD/deploy/alt-linux/ansible/ansible.cfg" \
  ansible-playbook --syntax-check \
    deploy/alt-linux/ansible/playbooks/01-preflight.yml

run_check provision_syntax \
  env ANSIBLE_CONFIG="$PWD/deploy/alt-linux/ansible/ansible.cfg" \
  ansible-playbook --syntax-check \
    deploy/alt-linux/ansible/playbooks/02-provision-account.yml

run_check diff_check git diff --check

if [ -n "$(git status --short)" ]; then
  STATUS_RC=1
  FAIL=1
  git status --short >"$TMP_LOG_DIR/status.log"
else
  STATUS_RC=0
  : >"$TMP_LOG_DIR/status.log"
fi

printf 'status_RC=%s\nFINAL_GATE_RC=%s\n' "$STATUS_RC" "$FAIL"

sudo cp -a "$TMP_LOG_DIR/." "$LOG_DIR/"
sudo chmod -R go-rwx "$LOG_DIR"

if [ "$FAIL" -ne 0 ]; then
  echo 'PRE_ROLLOUT_GATE=FAIL'
  exit 1
fi

echo 'PRE_ROLLOUT_GATE=PASS'
tail -n 12 "$TMP_LOG_DIR/tests.log"
```

Expected:

```text
tests_RC=0
compile_RC=0
install_bash_RC=0
bootstrap_bash_RC=0
preflight_syntax_RC=0
provision_syntax_RC=0
diff_check_RC=0
status_RC=0
FINAL_GATE_RC=0
PRE_ROLLOUT_GATE=PASS
165 passed
```

- [ ] **Step 2: Stop if the gate is not completely green**

Do not continue to Task 3 if any command returned nonzero or the worktree is not clean.

---

### Task 3: Perform a Read-Only Controller Audit and Build the Preview Manifest

**Files:**
- Read: `/var/lib/alt-deploy/jobs/`
- Read: `/var/lib/alt-deploy/assignments/`
- Read: `/srv/alt-deploy/registration/`
- Create at runtime: `$ROLLOUT_DIR/old-jobs-preview.json`
- Create at runtime: `$ROLLOUT_DIR/assignment-sha256-before.txt`

**Interfaces:**
- Produces a non-mutating list of every pre-Phase-2.3 terminal job and its status checksum.
- Refuses active jobs, new-schema jobs, unsafe entries, unexpected states, or malformed status files.
- Produces the assignment checksum baseline.

- [ ] **Step 1: Record service and registration state**

```bash
source <(sudo cat /root/alt-phase-2-3-rollout.env)

sudo systemctl is-active alt-deploy-register.service \
  | sudo tee "$ROLLOUT_DIR/register-active-before.txt"
sudo systemctl is-active alt-deploy-process.path \
  | sudo tee "$ROLLOUT_DIR/process-path-active-before.txt"
sudo systemctl is-active alt-deploy-process.service \
  | sudo tee "$ROLLOUT_DIR/process-service-active-before.txt"

sudo find /srv/alt-deploy/registration/pending \
  -maxdepth 1 -type f -printf '%f\n' \
  | sort \
  | sudo tee "$ROLLOUT_DIR/pending-before.txt" >/dev/null

sudo systemctl list-units \
  --type=service \
  --state=active,activating,reloading \
  --no-legend \
  'alt-provision-*.service' \
  | sudo tee "$ROLLOUT_DIR/active-provision-units.txt" >/dev/null

printf 'PENDING_COUNT=%s\nACTIVE_PROVISION_UNIT_COUNT=%s\n' \
  "$(sudo wc -l <"$ROLLOUT_DIR/pending-before.txt")" \
  "$(sudo wc -l <"$ROLLOUT_DIR/active-provision-units.txt")"
```

Expected before continuing:

```text
PENDING_COUNT=0
ACTIVE_PROVISION_UNIT_COUNT=0
```

If either count is nonzero, stop. Do not interrupt a registration or provisioning job.

- [ ] **Step 2: Run current read-only health commands**

```bash
source <(sudo cat /root/alt-phase-2-3-rollout.env)

sudo -u altserver workstationctl --json vault check \
  | sudo tee "$ROLLOUT_DIR/vault-before.json" >/dev/null

sudo -u altserver workstationctl --json controller permissions \
  | sudo tee "$ROLLOUT_DIR/permissions-before.json" >/dev/null

sudo python3 - "$ROLLOUT_DIR" <<'PY'
from __future__ import annotations

import json
import sys
from pathlib import Path

root = Path(sys.argv[1])
for name in ("vault-before.json", "permissions-before.json"):
    payload = json.loads((root / name).read_text(encoding="utf-8"))
    if payload.get("status") != "ok":
        raise SystemExit(f"{name} did not return status=ok")
print("READ_ONLY_HEALTH=PASS")
PY
```

Expected: `READ_ONLY_HEALTH=PASS`.

- [ ] **Step 3: Generate the old-job preview manifest without mutation**

```bash
source <(sudo cat /root/alt-phase-2-3-rollout.env)

sudo env ROLLOUT_DIR="$ROLLOUT_DIR" python3 - <<'PY'
from __future__ import annotations

import hashlib
import json
import os
import re
import stat
from pathlib import Path

rollout = Path(os.environ["ROLLOUT_DIR"])
root = Path("/var/lib/alt-deploy/jobs")
manifest_path = rollout / "old-jobs-preview.json"
summary_path = rollout / "old-jobs-preview.txt"
job_id_re = re.compile(r"^job-\d{8}T\d{6}Z-[0-9a-f]{8}$")
terminal_states = {"successful", "failed"}
active_states = {"queued", "running"}
records: list[dict[str, str]] = []

root_stat = root.lstat()
if not stat.S_ISDIR(root_stat.st_mode):
    raise SystemExit(f"jobs root is unsafe: {root}")

with os.scandir(root) as entries:
    for entry in sorted(entries, key=lambda item: item.name):
        if not job_id_re.fullmatch(entry.name):
            raise SystemExit(f"unexpected jobs entry: {entry.name}")
        if not entry.is_dir(follow_symlinks=False):
            raise SystemExit(f"unsafe job entry: {entry.name}")

        job_dir = Path(entry.path)
        status_path = job_dir / "status.json"
        status_stat = status_path.lstat()
        if not stat.S_ISREG(status_stat.st_mode):
            raise SystemExit(f"unsafe status file: {status_path}")

        raw = status_path.read_bytes()
        try:
            payload = json.loads(raw)
        except json.JSONDecodeError as exc:
            raise SystemExit(f"invalid status JSON: {status_path}: {exc}") from exc
        if not isinstance(payload, dict):
            raise SystemExit(f"status is not an object: {status_path}")

        state = str(payload.get("state") or "")
        stage = str(payload.get("stage") or "")
        job_id = str(payload.get("job_id") or "")

        if job_id != entry.name:
            raise SystemExit(
                f"job ID mismatch: directory={entry.name} payload={job_id}"
            )
        if state in active_states:
            raise SystemExit(f"active job blocks rollout: {job_id} state={state}")
        if state not in terminal_states:
            raise SystemExit(f"unexpected job state: {job_id} state={state}")
        if "stage_history" in payload:
            raise SystemExit(f"new-schema job blocks rollout review: {job_id}")

        records.append(
            {
                "job_id": job_id,
                "state": state,
                "stage": stage,
                "status_sha256": hashlib.sha256(raw).hexdigest(),
            }
        )

manifest_path.write_text(
    json.dumps(records, ensure_ascii=False, indent=2) + "\n",
    encoding="utf-8",
)
os.chmod(manifest_path, 0o600)

summary_lines = [
    f"OLD_JOB_COUNT={len(records)}",
    *(
        "REVIEW "
        f"{item['job_id']} state={item['state']} stage={item['stage']} "
        f"status_sha256={item['status_sha256']}"
        for item in records
    ),
]
summary_path.write_text("\n".join(summary_lines) + "\n", encoding="utf-8")
os.chmod(summary_path, 0o600)
print("\n".join(summary_lines))
print(f"MANIFEST={manifest_path}")
PY
```

Expected: one `OLD_JOB_COUNT=<observed count>` line, one `REVIEW` line per terminal old-schema job, and no exception. Zero old jobs is valid. The count is not assumed in advance.

- [ ] **Step 4: Record assignment checksums without reading them into logs**

```bash
source <(sudo cat /root/alt-phase-2-3-rollout.env)

sudo find /var/lib/alt-deploy/assignments \
  -maxdepth 1 -type f -name '*.json' -print0 \
  | sudo sort -z \
  | sudo xargs -0 -r sha256sum \
  | sudo tee "$ROLLOUT_DIR/assignment-sha256-before.txt" >/dev/null

sudo chmod 0600 "$ROLLOUT_DIR/assignment-sha256-before.txt"
printf 'ASSIGNMENT_COUNT=%s\n' \
  "$(sudo wc -l <"$ROLLOUT_DIR/assignment-sha256-before.txt")"
```

Expected: only the count is printed. Do not print assignment file contents.

---

### Task 4: Explicitly Review and Approve the Exact Old-Job Manifest

**Files:**
- Read: `$ROLLOUT_DIR/old-jobs-preview.txt`
- Read: `$ROLLOUT_DIR/old-jobs-preview.json`
- Create after approval: `$ROLLOUT_DIR/old-jobs-approved.json`
- Create after approval: `$ROLLOUT_DIR/old-jobs-approved.sha256`

**Interfaces:**
- Produces the immutable manifest used by deletion.
- This task is a hard stop; Task 5 must not begin automatically.

- [ ] **Step 1: Display the exact reviewed entries**

```bash
source <(sudo cat /root/alt-phase-2-3-rollout.env)
sudo cat "$ROLLOUT_DIR/old-jobs-preview.txt"
sudo cat "$ROLLOUT_DIR/old-jobs-preview.json"
```

- [ ] **Step 2: Obtain explicit approval for the exact manifest**

The operator must confirm the observed count and every exact `job_id`. Do not accept a generic approval such as “delete old jobs” without displaying the current manifest in the same review sequence.

- [ ] **Step 3: Freeze the approved manifest only after approval**

```bash
source <(sudo cat /root/alt-phase-2-3-rollout.env)

sudo install -o root -g root -m 0600 \
  "$ROLLOUT_DIR/old-jobs-preview.json" \
  "$ROLLOUT_DIR/old-jobs-approved.json"

sudo sha256sum "$ROLLOUT_DIR/old-jobs-approved.json" \
  | sudo tee "$ROLLOUT_DIR/old-jobs-approved.sha256" >/dev/null

sudo cat "$ROLLOUT_DIR/old-jobs-approved.sha256"
```

Expected: one SHA-256 line for the approved manifest.

---

### Task 5: Enter the Maintenance Freeze and Create Complete Backups

**Files:**
- Create: `$ROLLOUT_DIR/jobs-before.tar.gz`
- Create: `$ROLLOUT_DIR/runtime-before.tar.gz`
- Create: `$ROLLOUT_DIR/runtime-paths.txt`
- Create: `$ROLLOUT_DIR/backup-sha256.txt`

**Interfaces:**
- Stops new registration processing during the critical section.
- Verifies no pending registration, active provision unit, or changed approved job.
- Produces complete rollback archives without secrets or assignments.

- [ ] **Step 1: Stop new registration intake and processing**

```bash
source <(sudo cat /root/alt-phase-2-3-rollout.env)

sudo systemctl stop alt-deploy-register.service
sudo systemctl stop alt-deploy-process.path

for _ in $(seq 1 60); do
  if ! sudo systemctl is-active --quiet alt-deploy-process.service; then
    break
  fi
  sleep 1
done

if sudo systemctl is-active --quiet alt-deploy-process.service; then
  echo 'PROCESS_SERVICE_STILL_ACTIVE'
  exit 1
fi

sudo find /srv/alt-deploy/registration/pending \
  -maxdepth 1 -type f -printf '%f\n' \
  | sort \
  | sudo tee "$ROLLOUT_DIR/pending-after-freeze.txt" >/dev/null

test ! -s "$ROLLOUT_DIR/pending-after-freeze.txt"

sudo systemctl list-units \
  --type=service \
  --state=active,activating,reloading \
  --no-legend \
  'alt-provision-*.service' \
  | sudo tee "$ROLLOUT_DIR/active-provision-units-after-freeze.txt" >/dev/null

test ! -s "$ROLLOUT_DIR/active-provision-units-after-freeze.txt"

echo 'MAINTENANCE_FREEZE=PASS'
```

Expected: `MAINTENANCE_FREEZE=PASS`.

- [ ] **Step 2: Revalidate every approved job against its status checksum**

```bash
source <(sudo cat /root/alt-phase-2-3-rollout.env)

sudo env ROLLOUT_DIR="$ROLLOUT_DIR" python3 - <<'PY'
from __future__ import annotations

import hashlib
import json
import os
import re
import stat
from pathlib import Path

rollout = Path(os.environ["ROLLOUT_DIR"])
root = Path("/var/lib/alt-deploy/jobs")
manifest_path = rollout / "old-jobs-approved.json"
job_id_re = re.compile(r"^job-\d{8}T\d{6}Z-[0-9a-f]{8}$")
terminal_states = {"successful", "failed"}
records = json.loads(manifest_path.read_text(encoding="utf-8"))
if not isinstance(records, list):
    raise SystemExit("approved manifest is not a list")

approved_ids: set[str] = set()
for item in records:
    if not isinstance(item, dict):
        raise SystemExit("approved manifest item is not an object")
    if set(item) != {"job_id", "state", "stage", "status_sha256"}:
        raise SystemExit("approved manifest item has unexpected fields")
    job_id = str(item["job_id"])
    if not job_id_re.fullmatch(job_id) or job_id in approved_ids:
        raise SystemExit(f"invalid or duplicate approved job ID: {job_id}")
    approved_ids.add(job_id)

    job_dir = root / job_id
    job_stat = job_dir.lstat()
    if not stat.S_ISDIR(job_stat.st_mode):
        raise SystemExit(f"approved job is not a real directory: {job_id}")

    status_path = job_dir / "status.json"
    status_stat = status_path.lstat()
    if not stat.S_ISREG(status_stat.st_mode):
        raise SystemExit(f"approved status is unsafe: {status_path}")
    raw = status_path.read_bytes()
    current_hash = hashlib.sha256(raw).hexdigest()
    if current_hash != item["status_sha256"]:
        raise SystemExit(f"approved status changed after review: {job_id}")

    payload = json.loads(raw)
    if payload.get("state") not in terminal_states:
        raise SystemExit(f"approved job is no longer terminal: {job_id}")
    if "stage_history" in payload:
        raise SystemExit(f"approved job now uses new schema: {job_id}")

current_ids: set[str] = set()
with os.scandir(root) as entries:
    for entry in entries:
        if not job_id_re.fullmatch(entry.name):
            raise SystemExit(f"unexpected jobs entry after approval: {entry.name}")
        current_ids.add(entry.name)

if current_ids != approved_ids:
    raise SystemExit(
        "jobs set changed after approval: "
        f"approved={sorted(approved_ids)} current={sorted(current_ids)}"
    )

print(f"APPROVED_JOB_REVALIDATION=PASS count={len(records)}")
PY
```

Expected: `APPROVED_JOB_REVALIDATION=PASS count=<approved count>`.

- [ ] **Step 3: Back up the complete jobs directory**

```bash
source <(sudo cat /root/alt-phase-2-3-rollout.env)

sudo tar -C / -czpf "$ROLLOUT_DIR/jobs-before.tar.gz" \
  var/lib/alt-deploy/jobs

sudo chmod 0600 "$ROLLOUT_DIR/jobs-before.tar.gz"
sudo tar -tzf "$ROLLOUT_DIR/jobs-before.tar.gz" \
  | sudo tee "$ROLLOUT_DIR/jobs-backup-contents.txt" >/dev/null
```

Expected: archive creation and listing both exit `0`.

- [ ] **Step 4: Build the exact runtime backup path list**

```bash
source <(sudo cat /root/alt-phase-2-3-rollout.env)

cat <<'EOF' | sudo tee "$ROLLOUT_DIR/runtime-paths.txt" >/dev/null
opt/alt-deploy-control
usr/local/sbin/workstationctl
usr/local/libexec/alt-provision-worker
opt/alt-deploy-api/process_pending.py
home/altserver/ansible/ansible.cfg
home/altserver/ansible/group_vars/all.yml
home/altserver/ansible/playbooks
home/altserver/ansible/roles
EOF

if sudo test -e /usr/local/libexec/alt-job-stage; then
  echo 'usr/local/libexec/alt-job-stage' \
    | sudo tee -a "$ROLLOUT_DIR/runtime-paths.txt" >/dev/null
  echo 'HELPER_PREEXISTED=yes' \
    | sudo tee "$ROLLOUT_DIR/helper-preexisting.txt" >/dev/null
else
  echo 'HELPER_PREEXISTED=no' \
    | sudo tee "$ROLLOUT_DIR/helper-preexisting.txt" >/dev/null
fi

while IFS= read -r relative_path; do
  sudo test -e "/${relative_path}" || {
    echo "MISSING_RUNTIME_PATH=/${relative_path}"
    exit 1
  }
done < <(sudo cat "$ROLLOUT_DIR/runtime-paths.txt")

sudo chmod 0600 \
  "$ROLLOUT_DIR/runtime-paths.txt" \
  "$ROLLOUT_DIR/helper-preexisting.txt"

sudo cat "$ROLLOUT_DIR/runtime-paths.txt"
sudo cat "$ROLLOUT_DIR/helper-preexisting.txt"
```

Expected: every listed path exists; only `alt-job-stage` is optional before Phase 2.3.

- [ ] **Step 5: Back up all installer-mutated runtime paths**

```bash
source <(sudo cat /root/alt-phase-2-3-rollout.env)

sudo tar -C / -czpf "$ROLLOUT_DIR/runtime-before.tar.gz" \
  -T "$ROLLOUT_DIR/runtime-paths.txt"

sudo chmod 0600 "$ROLLOUT_DIR/runtime-before.tar.gz"
sudo tar -tzf "$ROLLOUT_DIR/runtime-before.tar.gz" \
  | sudo tee "$ROLLOUT_DIR/runtime-backup-contents.txt" >/dev/null

if sudo grep -E \
  '(^|/)(vault\.yml|\.ansible-vault-pass|id_ed25519)$|^var/lib/alt-deploy/assignments/' \
  "$ROLLOUT_DIR/runtime-backup-contents.txt"; then
  echo 'FORBIDDEN_PATH_IN_RUNTIME_BACKUP'
  exit 1
fi

sudo sha256sum \
  "$ROLLOUT_DIR/jobs-before.tar.gz" \
  "$ROLLOUT_DIR/runtime-before.tar.gz" \
  | sudo tee "$ROLLOUT_DIR/backup-sha256.txt" >/dev/null

sudo cat "$ROLLOUT_DIR/backup-sha256.txt"
```

Expected: both archives have SHA-256 entries and the forbidden-path check returns no matches.

---

### Task 6: Remove Only the Approved Pre-Phase-2.3 Jobs

**Files:**
- Read: `$ROLLOUT_DIR/old-jobs-approved.json`
- Delete: only matching directories under `/var/lib/alt-deploy/jobs/`

**Interfaces:**
- Revalidates every approved status checksum immediately before deletion.
- Does not follow symbolic links.
- Leaves assignments untouched.

- [ ] **Step 1: Delete approved jobs with no-follow traversal**

```bash
source <(sudo cat /root/alt-phase-2-3-rollout.env)

sudo env ROLLOUT_DIR="$ROLLOUT_DIR" python3 - <<'PY'
from __future__ import annotations

import hashlib
import json
import os
import re
import stat
from pathlib import Path

rollout = Path(os.environ["ROLLOUT_DIR"])
root = Path("/var/lib/alt-deploy/jobs")
manifest = rollout / "old-jobs-approved.json"
job_id_re = re.compile(r"^job-\d{8}T\d{6}Z-[0-9a-f]{8}$")
terminal_states = {"successful", "failed"}


def remove_no_follow(path: Path) -> None:
    entry_stat = path.lstat()
    if stat.S_ISDIR(entry_stat.st_mode):
        with os.scandir(path) as entries:
            for entry in entries:
                child = path / entry.name
                if entry.is_dir(follow_symlinks=False):
                    remove_no_follow(child)
                else:
                    child.unlink()
        path.rmdir()
        return
    path.unlink()

records = json.loads(manifest.read_text(encoding="utf-8"))
if not isinstance(records, list):
    raise SystemExit("approved manifest is not a list")

for item in records:
    job_id = str(item["job_id"])
    if not job_id_re.fullmatch(job_id):
        raise SystemExit(f"invalid approved job ID: {job_id}")
    job_dir = root / job_id
    if job_dir.parent != root:
        raise SystemExit(f"job path escaped root: {job_dir}")
    job_stat = job_dir.lstat()
    if not stat.S_ISDIR(job_stat.st_mode):
        raise SystemExit(f"job path is not a real directory: {job_dir}")

    status_path = job_dir / "status.json"
    status_stat = status_path.lstat()
    if not stat.S_ISREG(status_stat.st_mode):
        raise SystemExit(f"status path is unsafe: {status_path}")
    raw = status_path.read_bytes()
    if hashlib.sha256(raw).hexdigest() != item["status_sha256"]:
        raise SystemExit(f"status changed before deletion: {job_id}")
    payload = json.loads(raw)
    if payload.get("state") not in terminal_states:
        raise SystemExit(f"refusing non-terminal job: {job_id}")
    if "stage_history" in payload:
        raise SystemExit(f"refusing new-schema job: {job_id}")

for item in records:
    job_id = str(item["job_id"])
    remove_no_follow(root / job_id)
    print(f"REMOVED={job_id}")

remaining = list(root.iterdir())
if remaining:
    raise SystemExit(
        "unexpected jobs remain after approved removal: "
        + ", ".join(sorted(path.name for path in remaining))
    )
print(f"OLD_JOB_REMOVAL=PASS count={len(records)}")
PY
```

Expected: one `REMOVED=` line per approved job and `OLD_JOB_REMOVAL=PASS`.

- [ ] **Step 2: Verify assignments remain byte-identical**

```bash
source <(sudo cat /root/alt-phase-2-3-rollout.env)

sudo find /var/lib/alt-deploy/assignments \
  -maxdepth 1 -type f -name '*.json' -print0 \
  | sudo sort -z \
  | sudo xargs -0 -r sha256sum \
  | sudo tee "$ROLLOUT_DIR/assignment-sha256-after-job-removal.txt" >/dev/null

sudo diff -u \
  "$ROLLOUT_DIR/assignment-sha256-before.txt" \
  "$ROLLOUT_DIR/assignment-sha256-after-job-removal.txt"

echo 'ASSIGNMENTS_AFTER_JOB_REMOVAL=UNCHANGED'
```

Expected: empty diff and `ASSIGNMENTS_AFTER_JOB_REMOVAL=UNCHANGED`.

---

### Task 7: Install the Exact Verified Runtime

**Files:**
- Execute: `deploy/alt-linux/install-control-plane.sh`
- Modify: only the runtime paths listed in the Runtime Change Map

**Interfaces:**
- Installs the strict schema, internal stage helper, worker, CLI, API processor, and Ansible project.
- The installer itself runs compile, ALT tests, and both playbook syntax checks before reporting success.

- [ ] **Step 1: Recheck source SHA immediately before install**

```bash
source <(sudo cat /root/alt-phase-2-3-rollout.env)
cd "$WORKTREE" || exit 1

test "$(git rev-parse HEAD)" = "$APPROVED_SHA"
test "$(git rev-parse origin/feat/alt-workstation-provisioning-mvp)" = "$APPROVED_SHA"
test -z "$(git status --short)"
```

Expected: all commands exit `0`.

- [ ] **Step 2: Run the installer once and capture its exact exit code**

```bash
source <(sudo cat /root/alt-phase-2-3-rollout.env)
cd "$WORKTREE" || exit 1

set -o pipefail
sudo bash deploy/alt-linux/install-control-plane.sh \
  2>&1 \
  | sudo tee "$ROLLOUT_DIR/install.log"
INSTALL_RC=${PIPESTATUS[0]}

echo "INSTALL_RC=${INSTALL_RC}" \
  | sudo tee "$ROLLOUT_DIR/install-result.txt"

if [ "$INSTALL_RC" -ne 0 ]; then
  echo 'INSTALL=FAIL; EXECUTE TASK 10 ROLLBACK'
  exit 1
fi

echo 'INSTALL=PASS'
```

Expected: `INSTALL_RC=0`, all embedded tests/syntax checks pass, and the installer reports successful completion.

Do not rerun the installer if it fails. Execute Task 10 rollback first.

---

### Task 8: Verify Installed Files and Run Read-Only Controller Smoke Checks

**Files:**
- Read: installed runtime paths
- Create: `$ROLLOUT_DIR/post-install-*.json`
- Does not create a provisioning job.

**Interfaces:**
- Proves installed content matches the approved source.
- Proves the strict repository can read an empty job store.
- Proves Vault, permissions, assignment files, registration state, and required services remain healthy.

- [ ] **Step 1: Verify installed content matches the repository**

```bash
source <(sudo cat /root/alt-phase-2-3-rollout.env)
cd "$WORKTREE" || exit 1

sudo test -x /usr/local/sbin/workstationctl
sudo test -x /usr/local/libexec/alt-provision-worker
sudo test -x /usr/local/libexec/alt-job-stage

sudo cmp -s \
  deploy/alt-linux/control/workstationctl \
  /usr/local/sbin/workstationctl

sudo cmp -s \
  deploy/alt-linux/control/alt-provision-worker \
  /usr/local/libexec/alt-provision-worker

sudo cmp -s \
  deploy/alt-linux/control/alt-job-stage \
  /usr/local/libexec/alt-job-stage

sudo cmp -s \
  deploy/alt-linux/api/process_pending.py \
  /opt/alt-deploy-api/process_pending.py

sudo diff -qr \
  --exclude='__pycache__' \
  --exclude='*.pyc' \
  deploy/alt-linux/control/alt_deploy \
  /opt/alt-deploy-control/alt_deploy

sudo diff -qr \
  deploy/alt-linux/ansible/playbooks \
  /home/altserver/ansible/playbooks

sudo diff -qr \
  deploy/alt-linux/ansible/roles \
  /home/altserver/ansible/roles

sudo cmp -s \
  deploy/alt-linux/ansible/ansible.cfg \
  /home/altserver/ansible/ansible.cfg

sudo cmp -s \
  deploy/alt-linux/ansible/group_vars/all.yml \
  /home/altserver/ansible/group_vars/all.yml

echo 'INSTALLED_CONTENT=PASS'
```

Expected: no diff output and `INSTALLED_CONTENT=PASS`.

- [ ] **Step 2: Run strict-schema read-only commands**

```bash
source <(sudo cat /root/alt-phase-2-3-rollout.env)

sudo -u altserver workstationctl --json vault check \
  | sudo tee "$ROLLOUT_DIR/post-install-vault.json" >/dev/null

sudo -u altserver workstationctl --json controller permissions \
  | sudo tee "$ROLLOUT_DIR/post-install-permissions.json" >/dev/null

sudo -u altserver workstationctl --json jobs cleanup \
  | sudo tee "$ROLLOUT_DIR/post-install-cleanup.json" >/dev/null

sudo -u altserver workstationctl --json jobs reconcile \
  | sudo tee "$ROLLOUT_DIR/post-install-reconcile.json" >/dev/null

sudo -u altserver workstationctl --json machines list \
  | sudo tee "$ROLLOUT_DIR/post-install-machines.json" >/dev/null

sudo python3 - "$ROLLOUT_DIR" <<'PY'
from __future__ import annotations

import json
import sys
from pathlib import Path

root = Path(sys.argv[1])

vault = json.loads((root / "post-install-vault.json").read_text(encoding="utf-8"))
permissions = json.loads(
    (root / "post-install-permissions.json").read_text(encoding="utf-8")
)
cleanup = json.loads(
    (root / "post-install-cleanup.json").read_text(encoding="utf-8")
)
reconcile = json.loads(
    (root / "post-install-reconcile.json").read_text(encoding="utf-8")
)
machines = json.loads(
    (root / "post-install-machines.json").read_text(encoding="utf-8")
)

for name, payload in (
    ("vault", vault),
    ("permissions", permissions),
    ("cleanup", cleanup),
    ("reconcile", reconcile),
    ("machines", machines),
):
    if payload.get("status") != "ok":
        raise SystemExit(f"{name} did not return status=ok")

cleanup_report = cleanup.get("cleanup") or cleanup.get("retention")
if not isinstance(cleanup_report, dict):
    raise SystemExit("cleanup report is missing")
if cleanup_report.get("checked") != 0:
    raise SystemExit(f"cleanup checked is not zero: {cleanup_report}")

reconciliation = reconcile.get("reconciliation")
if not isinstance(reconciliation, dict):
    raise SystemExit("reconciliation report is missing")
if reconciliation.get("checked") != 0:
    raise SystemExit(f"reconciliation checked is not zero: {reconciliation}")

print("POST_INSTALL_JSON_SMOKE=PASS")
PY
```

Expected: `POST_INSTALL_JSON_SMOKE=PASS`, cleanup `checked=0`, and reconciliation `checked=0`.

- [ ] **Step 3: Verify assignments are still byte-identical**

```bash
source <(sudo cat /root/alt-phase-2-3-rollout.env)

sudo find /var/lib/alt-deploy/assignments \
  -maxdepth 1 -type f -name '*.json' -print0 \
  | sudo sort -z \
  | sudo xargs -0 -r sha256sum \
  | sudo tee "$ROLLOUT_DIR/assignment-sha256-after-install.txt" >/dev/null

sudo diff -u \
  "$ROLLOUT_DIR/assignment-sha256-before.txt" \
  "$ROLLOUT_DIR/assignment-sha256-after-install.txt"

echo 'ASSIGNMENTS_AFTER_INSTALL=UNCHANGED'
```

Expected: empty diff and `ASSIGNMENTS_AFTER_INSTALL=UNCHANGED`.

- [ ] **Step 4: Restore service states and verify them**

```bash
source <(sudo cat /root/alt-phase-2-3-rollout.env)

REGISTER_BEFORE="$(sudo cat "$ROLLOUT_DIR/register-active-before.txt")"
PATH_BEFORE="$(sudo cat "$ROLLOUT_DIR/process-path-active-before.txt")"

if [ "$REGISTER_BEFORE" = 'active' ]; then
  sudo systemctl start alt-deploy-register.service
else
  sudo systemctl stop alt-deploy-register.service
fi

if [ "$PATH_BEFORE" = 'active' ]; then
  sudo systemctl start alt-deploy-process.path
else
  sudo systemctl stop alt-deploy-process.path
fi

sudo systemctl is-active alt-deploy-register.service \
  | sudo tee "$ROLLOUT_DIR/register-active-after.txt"
sudo systemctl is-active alt-deploy-process.path \
  | sudo tee "$ROLLOUT_DIR/process-path-active-after.txt"

sudo journalctl \
  -u alt-deploy-process.path \
  -u alt-deploy-process.service \
  --since '-10 minutes' \
  --no-pager \
  | sudo tee "$ROLLOUT_DIR/process-journal-after.txt" >/dev/null

sudo systemctl --failed --no-legend \
  | sudo tee "$ROLLOUT_DIR/failed-units-after.txt" >/dev/null

echo 'SERVICE_STATE_RESTORED'
```

Expected: register and process-path states equal their recorded pre-rollout states. Review `failed-units-after.txt`; any newly failed ALT deployment unit blocks acceptance.

- [ ] **Step 5: Mark Phase A controller rollout evidence complete**

```bash
source <(sudo cat /root/alt-phase-2-3-rollout.env)

sudo sha256sum "$ROLLOUT_DIR"/*.json "$ROLLOUT_DIR"/*.txt \
  | sudo tee "$ROLLOUT_DIR/evidence-sha256.txt" >/dev/null

sudo chmod -R go-rwx "$ROLLOUT_DIR"
echo "PHASE_A_EVIDENCE=$ROLLOUT_DIR"
echo 'PHASE_A_CONTROLLER_ROLLOUT=READY_FOR_REVIEW'
```

Stop here. Do not start Phase B automatically.

---

### Task 9: Explicit Phase A Acceptance Gate

**Files:**
- Review: all evidence under `$ROLLOUT_DIR`

**Interfaces:**
- Separates controller installation from live provisioning.
- Produces an explicit operator decision: accept controller rollout, or execute rollback.

- [ ] **Step 1: Review the required evidence**

Review at minimum:

```text
repository.txt
pre-rollout-gate/tests.log
old-jobs-approved.json
backup-sha256.txt
install-result.txt
install.log
post-install-vault.json
post-install-permissions.json
post-install-cleanup.json
post-install-reconcile.json
assignment-sha256-before.txt
assignment-sha256-after-install.txt
failed-units-after.txt
```

- [ ] **Step 2: Accept or reject Phase A**

Accept only if all of the following are true:

```text
approved source SHA installed
complete pre-rollout gate passed
only approved old jobs removed
runtime and jobs backups exist and have checksums
installer exited 0
installed files match repository source
Vault health status=ok
controller permissions status=ok
cleanup checked=0
reconciliation checked=0
assignments byte-identical
required service states restored
no new failed ALT deployment unit
```

If any condition is false, execute Task 10 rollback. If all conditions are true, retain both backup archives until Phase B live acceptance is completed and reviewed.

---

### Task 10: Roll Back the Controller Runtime on Any Phase A Failure

**Files:**
- Restore: `$ROLLOUT_DIR/runtime-before.tar.gz`
- Restore: `$ROLLOUT_DIR/jobs-before.tar.gz`
- Do not restore or alter assignments, Vault, Vault password, or private keys.

**Interfaces:**
- Returns installer-mutated runtime paths and old jobs to their pre-rollout state.
- Removes files introduced only by Phase 2.3 before extracting the backup.

- [ ] **Step 1: Stop registration intake and processing**

```bash
source <(sudo cat /root/alt-phase-2-3-rollout.env)

sudo systemctl stop alt-deploy-register.service
sudo systemctl stop alt-deploy-process.path
sudo systemctl stop alt-deploy-process.service || true
```

- [ ] **Step 2: Verify backup checksums before restore**

```bash
source <(sudo cat /root/alt-phase-2-3-rollout.env)
sudo sha256sum -c "$ROLLOUT_DIR/backup-sha256.txt"
```

Expected: both archives report `OK`.

- [ ] **Step 3: Remove only installer-managed runtime paths**

```bash
sudo rm -rf \
  /opt/alt-deploy-control \
  /home/altserver/ansible/playbooks \
  /home/altserver/ansible/roles

sudo rm -f \
  /usr/local/sbin/workstationctl \
  /usr/local/libexec/alt-provision-worker \
  /usr/local/libexec/alt-job-stage \
  /opt/alt-deploy-api/process_pending.py \
  /home/altserver/ansible/ansible.cfg \
  /home/altserver/ansible/group_vars/all.yml
```

Do not remove `/home/altserver/ansible/group_vars/vault.yml`.

- [ ] **Step 4: Restore the previous runtime and jobs exactly**

```bash
source <(sudo cat /root/alt-phase-2-3-rollout.env)

sudo tar -C / -xzpf "$ROLLOUT_DIR/runtime-before.tar.gz"

sudo rm -rf /var/lib/alt-deploy/jobs
sudo tar -C / -xzpf "$ROLLOUT_DIR/jobs-before.tar.gz"
```

- [ ] **Step 5: Verify assignments remain unchanged during rollback**

```bash
source <(sudo cat /root/alt-phase-2-3-rollout.env)

sudo find /var/lib/alt-deploy/assignments \
  -maxdepth 1 -type f -name '*.json' -print0 \
  | sudo sort -z \
  | sudo xargs -0 -r sha256sum \
  | sudo tee "$ROLLOUT_DIR/assignment-sha256-after-rollback.txt" >/dev/null

sudo diff -u \
  "$ROLLOUT_DIR/assignment-sha256-before.txt" \
  "$ROLLOUT_DIR/assignment-sha256-after-rollback.txt"
```

Expected: empty diff.

- [ ] **Step 6: Restore pre-rollout service states**

```bash
source <(sudo cat /root/alt-phase-2-3-rollout.env)

REGISTER_BEFORE="$(sudo cat "$ROLLOUT_DIR/register-active-before.txt")"
PATH_BEFORE="$(sudo cat "$ROLLOUT_DIR/process-path-active-before.txt")"

if [ "$REGISTER_BEFORE" = 'active' ]; then
  sudo systemctl start alt-deploy-register.service
else
  sudo systemctl stop alt-deploy-register.service
fi

if [ "$PATH_BEFORE" = 'active' ]; then
  sudo systemctl start alt-deploy-process.path
else
  sudo systemctl stop alt-deploy-process.path
fi

sudo systemctl is-active alt-deploy-register.service
sudo systemctl is-active alt-deploy-process.path
```

- [ ] **Step 7: Run old-runtime read-only smoke checks**

```bash
sudo -u altserver workstationctl --json vault check
sudo -u altserver workstationctl --json controller permissions
sudo -u altserver workstationctl --json machines list

echo 'PHASE_A_ROLLBACK=COMPLETE'
```

Do not rerun Phase A until the failure cause is understood and a new explicit approval is given.

---

### Task 11: Prepare a Separate New-Machine Live Acceptance

**Files:**
- Create at runtime: `$ROLLOUT_DIR/new-machine-request.json`
- Create at runtime: `$ROLLOUT_DIR/new-machine-*.json`
- Modify only a new disposable workstation.

**Interfaces:**
- Consumes an accepted Phase A controller rollout.
- Produces a real successful history containing every canonical stage exactly once.
- Never uses the assigned reference UUID.

- [ ] **Step 1: Obtain separate approval for Phase B**

Do not proceed based only on Phase A approval. The operator must approve one new disposable VM or physical workstation and confirm that no production employee data will be placed on it.

- [ ] **Step 2: Complete autoinstall and automatic registration on the new target**

Acceptance prerequisites:

```text
new DMI UUID
UUID is not 53b03180-5d78-11f0-bd95-f027db877a00
new target has no assignment
registration reaches awaiting_assignment
preflight succeeds
```

Record the UUID without guessing it:

```bash
source <(sudo cat /root/alt-phase-2-3-rollout.env)

read -r -p 'New disposable machine UUID: ' NEW_UUID

python3 - "$NEW_UUID" <<'PY'
from __future__ import annotations

import re
import sys

value = sys.argv[1]
if not re.fullmatch(
    r"[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-"
    r"[0-9a-fA-F]{4}-[0-9a-fA-F]{12}",
    value,
):
    raise SystemExit("invalid UUID")
if value.lower() == "53b03180-5d78-11f0-bd95-f027db877a00":
    raise SystemExit("assigned reference UUID is forbidden")
print(value.lower())
PY

printf 'NEW_UUID=%s\n' "$NEW_UUID" \
  | sudo tee "$ROLLOUT_DIR/new-machine.env" >/dev/null
sudo chmod 0600 "$ROLLOUT_DIR/new-machine.env"

sudo -u altserver workstationctl --json machines show "$NEW_UUID" \
  | sudo tee "$ROLLOUT_DIR/new-machine-before.json" >/dev/null
```

- [ ] **Step 3: Create a non-secret fixed acceptance request**

```bash
source <(sudo cat /root/alt-phase-2-3-rollout.env)
source <(sudo cat "$ROLLOUT_DIR/new-machine.env")

sudo env NEW_UUID="$NEW_UUID" REQUEST="$ROLLOUT_DIR/new-machine-request.json" \
  python3 - <<'PY'
from __future__ import annotations

import json
import os
from pathlib import Path

request = {
    "machine_uuid": os.environ["NEW_UUID"].lower(),
    "employee_login": "phase23-test",
    "employee_full_name": "Phase 23 Test",
    "final_hostname": "alt-phase23-test",
    "profile": "standard",
}
path = Path(os.environ["REQUEST"])
path.write_text(
    json.dumps(request, ensure_ascii=False, indent=2) + "\n",
    encoding="utf-8",
)
path.chmod(0o600)
print(path)
PY
```

The request contains no password or password hash.

- [ ] **Step 4: Run preview and require success before provisioning**

```bash
source <(sudo cat /root/alt-phase-2-3-rollout.env)
source <(sudo cat "$ROLLOUT_DIR/new-machine.env")

sudo -u altserver workstationctl --json provision preview "$NEW_UUID" \
  --vars-file "$ROLLOUT_DIR/new-machine-request.json" \
  | sudo tee "$ROLLOUT_DIR/new-machine-preview.json" >/dev/null

sudo python3 - "$ROLLOUT_DIR/new-machine-preview.json" <<'PY'
from __future__ import annotations

import json
import sys
from pathlib import Path

payload = json.loads(Path(sys.argv[1]).read_text(encoding="utf-8"))
if payload.get("status") != "ok":
    raise SystemExit("preview did not return status=ok")
print("NEW_MACHINE_PREVIEW=PASS")
PY
```

Expected: `NEW_MACHINE_PREVIEW=PASS`.

- [ ] **Step 5: Start exactly one provision job**

```bash
source <(sudo cat /root/alt-phase-2-3-rollout.env)
source <(sudo cat "$ROLLOUT_DIR/new-machine.env")

sudo workstationctl --json provision start "$NEW_UUID" \
  --vars-file "$ROLLOUT_DIR/new-machine-request.json" \
  | sudo tee "$ROLLOUT_DIR/new-machine-start.json" >/dev/null

JOB_ID="$(sudo python3 - "$ROLLOUT_DIR/new-machine-start.json" <<'PY'
from __future__ import annotations

import json
import sys
from pathlib import Path

payload = json.loads(Path(sys.argv[1]).read_text(encoding="utf-8"))
if payload.get("status") != "ok":
    raise SystemExit("provision start did not return status=ok")
job = payload.get("job") or payload.get("provision") or payload
job_id = job.get("job_id") if isinstance(job, dict) else None
if not isinstance(job_id, str) or not job_id:
    raise SystemExit("job_id is missing")
print(job_id)
PY
)"

printf 'JOB_ID=%s\n' "$JOB_ID" \
  | sudo tee "$ROLLOUT_DIR/new-machine-job.env" >/dev/null
sudo chmod 0600 "$ROLLOUT_DIR/new-machine-job.env"

echo "JOB_ID=$JOB_ID"
```

Do not run `provision start` a second time.

- [ ] **Step 6: Poll the existing job until terminal state**

```bash
source <(sudo cat /root/alt-phase-2-3-rollout.env)
source <(sudo cat "$ROLLOUT_DIR/new-machine-job.env")

for attempt in $(seq 1 180); do
  sudo -u altserver workstationctl --json jobs status "$JOB_ID" \
    > /tmp/phase-2-3-job-status.json

  STATE="$(python3 - <<'PY'
from __future__ import annotations

import json
from pathlib import Path

payload = json.loads(
    Path("/tmp/phase-2-3-job-status.json").read_text(encoding="utf-8")
)
job = payload["job"]
print(job["state"])
PY
)"

  printf 'attempt=%s state=%s\n' "$attempt" "$STATE"
  if [ "$STATE" = 'successful' ] || [ "$STATE" = 'failed' ]; then
    break
  fi
  sleep 10
done

sudo install -o root -g root -m 0600 \
  /tmp/phase-2-3-job-status.json \
  "$ROLLOUT_DIR/new-machine-final-job.json"
rm -f /tmp/phase-2-3-job-status.json

test "$STATE" = 'successful'
```

Expected: terminal state is `successful`. If it is `failed`, preserve the evidence and stop; do not create another job until the failure is reviewed.

- [ ] **Step 7: Verify exact canonical stage history**

```bash
source <(sudo cat /root/alt-phase-2-3-rollout.env)

sudo python3 - "$ROLLOUT_DIR/new-machine-final-job.json" <<'PY'
from __future__ import annotations

import json
import sys
from datetime import datetime
from pathlib import Path

expected = [
    "created",
    "launching",
    "validating",
    "connecting",
    "identity",
    "employee",
    "login_screen",
    "verifying",
    "recording",
    "complete",
]
payload = json.loads(Path(sys.argv[1]).read_text(encoding="utf-8"))
job = payload["job"]
history = job["stage_history"]
observed = [item["stage"] for item in history]
if job["state"] != "successful":
    raise SystemExit(f"unexpected state: {job['state']}")
if job["stage"] != "complete":
    raise SystemExit(f"unexpected final stage: {job['stage']}")
if observed != expected:
    raise SystemExit(f"unexpected stage history: {observed}")
for item in history:
    if set(item) != {"stage", "entered_at"}:
        raise SystemExit(f"unexpected history fields: {item}")
    timestamp = datetime.fromisoformat(item["entered_at"])
    if timestamp.tzinfo is None:
        raise SystemExit(f"history timestamp has no timezone: {item}")
print("LIVE_STAGE_HISTORY=PASS")
for item in history:
    print(item["stage"], item["entered_at"])
PY
```

Expected: `LIVE_STAGE_HISTORY=PASS` followed by the ten canonical stages in order.

- [ ] **Step 8: Verify assignment, reboot, and graphical login**

```bash
source <(sudo cat /root/alt-phase-2-3-rollout.env)
source <(sudo cat "$ROLLOUT_DIR/new-machine.env")

sudo -u altserver workstationctl --json machines show "$NEW_UUID" \
  | sudo tee "$ROLLOUT_DIR/new-machine-assigned.json" >/dev/null

sudo python3 - "$ROLLOUT_DIR/new-machine-assigned.json" <<'PY'
from __future__ import annotations

import json
import sys
from pathlib import Path

payload = json.loads(Path(sys.argv[1]).read_text(encoding="utf-8"))
if payload.get("status") != "ok":
    raise SystemExit("machine show did not return status=ok")
machine = payload.get("machine")
if not isinstance(machine, dict):
    raise SystemExit("machine payload is missing")
if machine.get("status") != "assigned":
    raise SystemExit(f"machine is not assigned: {machine.get('status')}")
print("CONTROLLER_ASSIGNMENT=PASS")
PY
```

Then reboot only the new disposable target, verify LightDM shows the intended employee, log in graphically, and verify Plasma opens. Do not reboot or reprovision the assigned reference machine.

- [ ] **Step 9: Verify repeat-provision protection**

```bash
source <(sudo cat /root/alt-phase-2-3-rollout.env)
source <(sudo cat "$ROLLOUT_DIR/new-machine.env")

set +e
sudo -u altserver workstationctl --json provision preview "$NEW_UUID" \
  --vars-file "$ROLLOUT_DIR/new-machine-request.json" \
  | sudo tee "$ROLLOUT_DIR/new-machine-repeat-preview.json" >/dev/null
RC=${PIPESTATUS[0]}
set -e

sudo python3 - "$ROLLOUT_DIR/new-machine-repeat-preview.json" "$RC" <<'PY'
from __future__ import annotations

import json
import sys
from pathlib import Path

payload = json.loads(Path(sys.argv[1]).read_text(encoding="utf-8"))
rc = int(sys.argv[2])
if rc == 0:
    raise SystemExit("repeat preview unexpectedly succeeded")
error = payload.get("error")
if not isinstance(error, dict) or error.get("code") != "machine_already_assigned":
    raise SystemExit(f"unexpected repeat-preview result: {payload}")
print("REPEAT_PROVISION_PROTECTION=PASS")
PY
```

Expected: `REPEAT_PROVISION_PROTECTION=PASS`.

---

### Task 12: Final Acceptance and Backup Retention Decision

**Files:**
- Review: `$ROLLOUT_DIR`
- No automatic deletion of evidence or backup archives.

**Interfaces:**
- Produces the final Phase 2.3 rollout decision.
- Leaves rollback archives under `/root` until the operator explicitly adopts a retention policy.

- [ ] **Step 1: Verify the final acceptance matrix**

```text
Phase A controller rollout explicitly accepted
approved source SHA installed
165-test final gate passed
old jobs removed only from approved manifest
assignments remained byte-identical during Phase A
Vault and controller permissions remained healthy
cleanup and reconciliation both checked zero immediately after install
registration services returned to their original states
new disposable machine reached awaiting_assignment
preview succeeded
one and only one provision job started
job finished successful/complete
stage_history exactly matched all ten canonical stages
controller assignment exists
reboot and graphical LightDM/Plasma login succeeded
repeat preview returned machine_already_assigned
assigned reference UUID was never provisioned
```

- [ ] **Step 2: Record the final evidence bundle checksum**

```bash
source <(sudo cat /root/alt-phase-2-3-rollout.env)

sudo find "$ROLLOUT_DIR" \
  -maxdepth 1 -type f ! -name 'final-evidence-sha256.txt' \
  -print0 \
  | sudo sort -z \
  | sudo xargs -0 -r sha256sum \
  | sudo tee "$ROLLOUT_DIR/final-evidence-sha256.txt" >/dev/null

sudo chmod -R go-rwx "$ROLLOUT_DIR"
echo "FINAL_EVIDENCE=$ROLLOUT_DIR"
```

- [ ] **Step 3: Retain backups until a separate cleanup approval**

Do not automatically delete:

```text
$ROLLOUT_DIR/jobs-before.tar.gz
$ROLLOUT_DIR/runtime-before.tar.gz
$ROLLOUT_DIR/old-jobs-approved.json
$ROLLOUT_DIR/backup-sha256.txt
```

Backup expiration and deletion are a separate operator decision. Never place these root-only runtime archives in Git.

---

## Final Acceptance Matrix

| Requirement | Evidence |
| --- | --- |
| Exact verified source installed | `repository.txt`, installed-content comparisons |
| No unreviewed job deletion | approved JSON manifest and status SHA-256 checks |
| No active job interrupted | active-unit audit and terminal-state manifest validation |
| Complete rollback available | runtime and jobs archives plus `backup-sha256.txt` |
| Secrets excluded from backup | runtime archive path inspection |
| Assignments untouched | before/after SHA-256 manifests |
| Strict schema healthy | cleanup and reconciliation `checked=0` |
| Controller operational | Vault, permissions, machine list, service checks |
| Complete real stage order | `new-machine-final-job.json` and history validator |
| Existing assigned target protected | explicit UUID guard and repeat-provision test |

## Explicitly Deferred

```text
Plasma configuration capture and Ansible role
OpenVPN or network configuration
web UI and constrained HTTP API
release/reassignment workflow
migration of old job JSON
retention automation
reconciliation-on-boot automation
progress percentage and ETA
production multi-machine rollout
```
