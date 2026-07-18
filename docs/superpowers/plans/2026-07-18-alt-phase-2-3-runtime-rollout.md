# ALT Phase 2.3 Controlled Runtime Rollout Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:executing-plans to execute this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Install the verified Phase 2.3 structured job-stage implementation on the ALT deployment controller with complete rollback evidence, then validate the full ten-stage history on one new disposable workstation.

**Architecture:** The rollout has two separate approvals. Phase A updates only the controller: audit, maintenance freeze, reviewed old-job removal, backups, installation, read-only smoke checks, and explicit acceptance or rollback. Phase B is a later live acceptance on a new clean machine; no live provisioning is allowed during Phase A.

**Tech Stack:** Bash, Python 3 standard library, systemd, Ansible Core, SHA-256 manifests, GNU tar, JSON controller state.

## Global Constraints

- Worktree: `/home/altserver/web_ovpn-src/.worktrees/alt-workstation-mvp`.
- Verified runtime base: `51b8e7dd3bba3b3c2e52cce3906fdd021acf3587`.
- `HEAD` may contain documentation-only rollout-plan commits after the verified runtime base.
- Immediately before rollout, local `HEAD` must equal `origin/feat/alt-workstation-provisioning-mvp`.
- `git diff VERIFIED_RUNTIME_BASE..HEAD -- deploy/alt-linux tests/alt_linux` must be empty. Any runtime or ALT-test change requires a new complete final gate and a new verified runtime base.
- The complete gate must still pass on current `HEAD`: all ALT tests, Python compile, both Bash syntax checks, both Ansible syntax checks, `git diff --check`, and clean worktree.
- Do not start Phase A without explicit operator approval.
- Do not delete any job before displaying and approving its exact manifest.
- Do not assume there are exactly four old jobs. The audit result is authoritative.
- Refuse rollout if any job is active, already uses `stage_history`, has an unexpected state, changes after approval, or is stored through an unsafe filesystem entry.
- Never print, copy, archive, checksum, or expose decrypted Vault data, password hashes, `.ansible-vault-pass`, or private SSH keys.
- Do not include the active Vault, Vault password file, private SSH key, or assignments in runtime backup archives.
- Assignment files must remain byte-identical; compare only path names and SHA-256 values.
- Do not run `jobs cleanup --apply` during this rollout.
- Do not run `provision start` during Phase A.
- Never provision assigned UUID `53b03180-5d78-11f0-bd95-f027db877a00` again.
- Phase B must use a new disposable target with a different UUID.
- Do not mix Plasma configuration, OpenVPN, netctl, Network Observer, web UI, release/reassignment, or unrelated Ansible roles into this rollout.
- Every command output must be retained in a root-only evidence directory.
- On install failure, file mismatch, assignment checksum change, unhealthy Vault/permissions, nonzero job count after cleanup/reconcile, or required service failure: stop and execute rollback. Do not rerun the installer over an uncertain state.

---

## Runtime Paths Changed by the Installer

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

State intentionally changed before installation:

```text
/var/lib/alt-deploy/jobs/
```

State that must remain unchanged:

```text
/var/lib/alt-deploy/assignments/
/home/altserver/ansible/group_vars/vault.yml
/home/altserver/.ansible-vault-pass
/home/altserver/.ssh/id_ed25519
```

---

### Task 1: Pin the Runtime Tree and Create the Evidence Directory

**Files:**
- Read: repository worktree
- Create: `/root/alt-phase-2-3-rollout.env`
- Create: `/root/alt-phase-2-3-rollout-<timestamp>/`

**Interfaces:**
- Produces `ROLLOUT_DIR`, `WORKTREE`, `VERIFIED_RUNTIME_BASE`, and `ROLLOUT_HEAD`.
- Proves current runtime/test files are identical to the verified runtime base.

- [ ] **Step 1: Verify local/remote identity and runtime-tree equivalence**

```bash
cd /home/altserver/web_ovpn-src/.worktrees/alt-workstation-mvp || exit 1

git fetch origin feat/alt-workstation-provisioning-mvp || exit 1

VERIFIED_RUNTIME_BASE=51b8e7dd3bba3b3c2e52cce3906fdd021acf3587
HEAD_SHA="$(git rev-parse HEAD)"
REMOTE_SHA="$(git rev-parse origin/feat/alt-workstation-provisioning-mvp)"

printf 'VERIFIED_RUNTIME_BASE=%s\nHEAD_SHA=%s\nREMOTE_SHA=%s\n' \
  "$VERIFIED_RUNTIME_BASE" "$HEAD_SHA" "$REMOTE_SHA"

test "$HEAD_SHA" = "$REMOTE_SHA"
test -z "$(git status --short)"
git diff --quiet "$VERIFIED_RUNTIME_BASE"..HEAD -- \
  deploy/alt-linux \
  tests/alt_linux
```

Expected: local and remote SHA match, worktree is clean, and runtime/test diff exits `0`. Documentation-only plan commits are permitted.

- [ ] **Step 2: Create root-only rollout metadata**

```bash
STAMP="$(date +%Y%m%d-%H%M%S)"
ROLLOUT_DIR="/root/alt-phase-2-3-rollout-${STAMP}"
ROLLOUT_HEAD="$(git rev-parse HEAD)"

sudo install -d -o root -g root -m 0700 "$ROLLOUT_DIR"

printf '%s\n' \
  "ROLLOUT_DIR=${ROLLOUT_DIR}" \
  "WORKTREE=/home/altserver/web_ovpn-src/.worktrees/alt-workstation-mvp" \
  "VERIFIED_RUNTIME_BASE=51b8e7dd3bba3b3c2e52cce3906fdd021acf3587" \
  "ROLLOUT_HEAD=${ROLLOUT_HEAD}" \
  | sudo tee /root/alt-phase-2-3-rollout.env >/dev/null

sudo chmod 0600 /root/alt-phase-2-3-rollout.env
sudo cat /root/alt-phase-2-3-rollout.env
```

- [ ] **Step 3: Save repository evidence**

```bash
source <(sudo cat /root/alt-phase-2-3-rollout.env)
cd "$WORKTREE" || exit 1

{
  git status --short
  git log -1 --format='commit=%H%nsubject=%s%nauthor=%an <%ae>%ndate=%aI'
  git diff --stat "$VERIFIED_RUNTIME_BASE"..HEAD
} | sudo tee "$ROLLOUT_DIR/repository.txt" >/dev/null

sudo chmod 0600 "$ROLLOUT_DIR/repository.txt"
```

---

### Task 2: Re-run the Complete Gate Before Any Runtime Mutation

**Files:**
- Read: `deploy/alt-linux/**`, `tests/alt_linux/**`
- Create: `$ROLLOUT_DIR/pre-rollout-gate/`

**Interfaces:**
- Produces fresh verification evidence for the exact current worktree.

- [ ] **Step 1: Execute the full gate**

```bash
source <(sudo cat /root/alt-phase-2-3-rollout.env)
cd "$WORKTREE" || exit 1

TMP_LOG_DIR="/tmp/alt-phase-2-3-pre-rollout-$$"
FINAL_LOG_DIR="$ROLLOUT_DIR/pre-rollout-gate"
install -d -m 0700 "$TMP_LOG_DIR"
sudo install -d -o root -g root -m 0700 "$FINAL_LOG_DIR"
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
  FAIL=1
  STATUS_RC=1
  git status --short >"$TMP_LOG_DIR/status.log"
else
  STATUS_RC=0
  : >"$TMP_LOG_DIR/status.log"
fi

printf 'status_RC=%s\nFINAL_GATE_RC=%s\n' "$STATUS_RC" "$FAIL"

sudo cp -a "$TMP_LOG_DIR/." "$FINAL_LOG_DIR/"
sudo chmod -R go-rwx "$FINAL_LOG_DIR"

if [ "$FAIL" -ne 0 ]; then
  echo 'PRE_ROLLOUT_GATE=FAIL'
  exit 1
fi

echo 'PRE_ROLLOUT_GATE=PASS'
tail -n 12 "$TMP_LOG_DIR/tests.log"
```

Expected: every RC is `0`, worktree is clean, and the ALT suite reports `165 passed` unless a later separately verified test-only change legitimately updates the count.

- [ ] **Step 2: Stop on any nonzero result**

No audit, backup, deletion, or installation follows a failed gate.

---

### Task 3: Read-only Controller Audit and Preview Manifest

**Files:**
- Read: jobs, assignments, registrations, service state
- Create: `$ROLLOUT_DIR/old-jobs-preview.json`
- Create: `$ROLLOUT_DIR/assignment-sha256-before.txt`

**Interfaces:**
- Refuses active jobs, new-schema jobs, unsafe entries, malformed JSON, and unexpected states.
- Does not mutate runtime.

- [ ] **Step 1: Record service and activity state**

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

Expected: both counts are zero. Otherwise stop without interrupting active work.

- [ ] **Step 2: Verify current Vault and permission health**

```bash
source <(sudo cat /root/alt-phase-2-3-rollout.env)

sudo -u altserver workstationctl --json vault check \
  | sudo tee "$ROLLOUT_DIR/vault-before.json" >/dev/null
sudo -u altserver workstationctl --json controller permissions \
  | sudo tee "$ROLLOUT_DIR/permissions-before.json" >/dev/null

sudo python3 - "$ROLLOUT_DIR" <<'PY'
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

- [ ] **Step 3: Generate the non-mutating old-job manifest**

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
manifest = rollout / "old-jobs-preview.json"
summary = rollout / "old-jobs-preview.txt"
job_id_re = re.compile(r"^job-\d{8}T\d{6}Z-[0-9a-f]{8}$")
terminal = {"successful", "failed"}
active = {"queued", "running"}
records: list[dict[str, str]] = []

if not stat.S_ISDIR(root.lstat().st_mode):
    raise SystemExit(f"unsafe jobs root: {root}")

with os.scandir(root) as entries:
    for entry in sorted(entries, key=lambda item: item.name):
        if not job_id_re.fullmatch(entry.name):
            raise SystemExit(f"unexpected jobs entry: {entry.name}")
        if not entry.is_dir(follow_symlinks=False):
            raise SystemExit(f"unsafe job entry: {entry.name}")

        status_path = Path(entry.path) / "status.json"
        if not stat.S_ISREG(status_path.lstat().st_mode):
            raise SystemExit(f"unsafe status file: {status_path}")
        raw = status_path.read_bytes()
        payload = json.loads(raw)
        if not isinstance(payload, dict):
            raise SystemExit(f"status is not an object: {status_path}")

        job_id = str(payload.get("job_id") or "")
        state = str(payload.get("state") or "")
        stage = str(payload.get("stage") or "")
        if job_id != entry.name:
            raise SystemExit(f"job ID mismatch: {entry.name} != {job_id}")
        if state in active:
            raise SystemExit(f"active job blocks rollout: {job_id} state={state}")
        if state not in terminal:
            raise SystemExit(f"unexpected job state: {job_id} state={state}")
        if "stage_history" in payload:
            raise SystemExit(f"new-schema job blocks rollout: {job_id}")

        records.append(
            {
                "job_id": job_id,
                "state": state,
                "stage": stage,
                "status_sha256": hashlib.sha256(raw).hexdigest(),
            }
        )

manifest.write_text(
    json.dumps(records, ensure_ascii=False, indent=2) + "\n",
    encoding="utf-8",
)
summary.write_text(
    "\n".join(
        [
            f"OLD_JOB_COUNT={len(records)}",
            *[
                "REVIEW "
                f"{item['job_id']} state={item['state']} stage={item['stage']} "
                f"status_sha256={item['status_sha256']}"
                for item in records
            ],
        ]
    )
    + "\n",
    encoding="utf-8",
)
os.chmod(manifest, 0o600)
os.chmod(summary, 0o600)
print(summary.read_text(encoding="utf-8"), end="")
print(f"MANIFEST={manifest}")
PY
```

Zero old jobs is valid. The count must not be assumed in advance.

- [ ] **Step 4: Record assignment checksums without printing assignment contents**

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

---

### Task 4: Explicit Manifest Approval Gate

**Files:**
- Review: preview manifest and summary
- Create after approval: `$ROLLOUT_DIR/old-jobs-approved.json`

**Interfaces:**
- No deletion occurs in this task.
- Produces the immutable manifest consumed by backup validation and deletion.

- [ ] **Step 1: Display the exact manifest**

```bash
source <(sudo cat /root/alt-phase-2-3-rollout.env)
sudo cat "$ROLLOUT_DIR/old-jobs-preview.txt"
sudo cat "$ROLLOUT_DIR/old-jobs-preview.json"
```

- [ ] **Step 2: Obtain explicit approval for every exact job ID and the observed count**

A generic “delete old jobs” approval is insufficient. Stop until the current manifest is explicitly approved.

- [ ] **Step 3: Freeze the approved manifest**

```bash
source <(sudo cat /root/alt-phase-2-3-rollout.env)

sudo install -o root -g root -m 0600 \
  "$ROLLOUT_DIR/old-jobs-preview.json" \
  "$ROLLOUT_DIR/old-jobs-approved.json"

sudo sha256sum "$ROLLOUT_DIR/old-jobs-approved.json" \
  | sudo tee "$ROLLOUT_DIR/old-jobs-approved.sha256" >/dev/null

sudo cat "$ROLLOUT_DIR/old-jobs-approved.sha256"
```

---

### Task 5: Maintenance Freeze and Complete Backup

**Files:**
- Create: jobs and runtime archives
- Create: runtime path list and archive checksums

**Interfaces:**
- Stops new registration intake and pending processing.
- Requires no active provisioning unit or pending registration.
- Backs up every installer-mutated path while excluding secrets and assignments.

- [ ] **Step 1: Enter the maintenance freeze**

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

- [ ] **Step 2: Revalidate the approved job set and checksums**

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
records = json.loads(
    (rollout / "old-jobs-approved.json").read_text(encoding="utf-8")
)
job_id_re = re.compile(r"^job-\d{8}T\d{6}Z-[0-9a-f]{8}$")
terminal = {"successful", "failed"}
approved_ids: set[str] = set()

if not isinstance(records, list):
    raise SystemExit("approved manifest is not a list")

for item in records:
    if not isinstance(item, dict):
        raise SystemExit("manifest item is not an object")
    if set(item) != {"job_id", "state", "stage", "status_sha256"}:
        raise SystemExit("manifest item has unexpected fields")
    job_id = str(item["job_id"])
    if not job_id_re.fullmatch(job_id) or job_id in approved_ids:
        raise SystemExit(f"invalid or duplicate job ID: {job_id}")
    approved_ids.add(job_id)

    job_dir = root / job_id
    if not stat.S_ISDIR(job_dir.lstat().st_mode):
        raise SystemExit(f"approved job is unsafe: {job_id}")
    status_path = job_dir / "status.json"
    if not stat.S_ISREG(status_path.lstat().st_mode):
        raise SystemExit(f"approved status is unsafe: {job_id}")
    raw = status_path.read_bytes()
    if hashlib.sha256(raw).hexdigest() != item["status_sha256"]:
        raise SystemExit(f"approved status changed: {job_id}")
    payload = json.loads(raw)
    if payload.get("state") not in terminal:
        raise SystemExit(f"approved job is not terminal: {job_id}")
    if "stage_history" in payload:
        raise SystemExit(f"approved job now uses new schema: {job_id}")

current_ids: set[str] = set()
with os.scandir(root) as entries:
    for entry in entries:
        if not job_id_re.fullmatch(entry.name):
            raise SystemExit(f"unexpected jobs entry: {entry.name}")
        current_ids.add(entry.name)

if current_ids != approved_ids:
    raise SystemExit(
        f"job set changed: approved={sorted(approved_ids)} "
        f"current={sorted(current_ids)}"
    )

print(f"APPROVED_JOB_REVALIDATION=PASS count={len(records)}")
PY
```

- [ ] **Step 3: Back up the complete jobs directory**

```bash
source <(sudo cat /root/alt-phase-2-3-rollout.env)

sudo tar -C / -czpf "$ROLLOUT_DIR/jobs-before.tar.gz" \
  var/lib/alt-deploy/jobs
sudo chmod 0600 "$ROLLOUT_DIR/jobs-before.tar.gz"
sudo tar -tzf "$ROLLOUT_DIR/jobs-before.tar.gz" \
  | sudo tee "$ROLLOUT_DIR/jobs-backup-contents.txt" >/dev/null
```

- [ ] **Step 4: Build the runtime backup list**

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
```

- [ ] **Step 5: Back up installer-mutated runtime paths and verify exclusions**

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

---

### Task 6: Delete Only the Approved Old Jobs

**Files:**
- Delete: only directories listed in the approved manifest
- Preserve: assignments and all other runtime state

**Interfaces:**
- Revalidates status checksum immediately before deletion.
- Uses no-follow traversal.

- [ ] **Step 1: Remove approved jobs**

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
records = json.loads(
    (rollout / "old-jobs-approved.json").read_text(encoding="utf-8")
)
job_id_re = re.compile(r"^job-\d{8}T\d{6}Z-[0-9a-f]{8}$")
terminal = {"successful", "failed"}


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

for item in records:
    job_id = str(item["job_id"])
    if not job_id_re.fullmatch(job_id):
        raise SystemExit(f"invalid job ID: {job_id}")
    job_dir = root / job_id
    if job_dir.parent != root:
        raise SystemExit(f"escaped job path: {job_dir}")
    if not stat.S_ISDIR(job_dir.lstat().st_mode):
        raise SystemExit(f"unsafe job directory: {job_id}")
    status_path = job_dir / "status.json"
    if not stat.S_ISREG(status_path.lstat().st_mode):
        raise SystemExit(f"unsafe status file: {job_id}")
    raw = status_path.read_bytes()
    if hashlib.sha256(raw).hexdigest() != item["status_sha256"]:
        raise SystemExit(f"status changed before deletion: {job_id}")
    payload = json.loads(raw)
    if payload.get("state") not in terminal:
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
        "unexpected jobs remain: "
        + ", ".join(sorted(path.name for path in remaining))
    )
print(f"OLD_JOB_REMOVAL=PASS count={len(records)}")
PY
```

- [ ] **Step 2: Verify assignments did not change**

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

---

### Task 7: Install the Verified Runtime Once

**Files:**
- Execute: `deploy/alt-linux/install-control-plane.sh`

**Interfaces:**
- Installs current `HEAD`, whose runtime/test tree was proven identical to `VERIFIED_RUNTIME_BASE`.
- Runs embedded compile, ALT tests, and Ansible syntax checks.

- [ ] **Step 1: Recheck source immediately before installation**

```bash
source <(sudo cat /root/alt-phase-2-3-rollout.env)
cd "$WORKTREE" || exit 1

test "$(git rev-parse HEAD)" = "$ROLLOUT_HEAD"
test "$(git rev-parse origin/feat/alt-workstation-provisioning-mvp)" = "$ROLLOUT_HEAD"
test -z "$(git status --short)"
git diff --quiet "$VERIFIED_RUNTIME_BASE"..HEAD -- \
  deploy/alt-linux \
  tests/alt_linux
```

- [ ] **Step 2: Execute installer and capture exact exit code**

```bash
source <(sudo cat /root/alt-phase-2-3-rollout.env)
cd "$WORKTREE" || exit 1

set -o pipefail
sudo bash deploy/alt-linux/install-control-plane.sh \
  2>&1 \
  | sudo tee "$ROLLOUT_DIR/install.log"
INSTALL_RC=${PIPESTATUS[0]}

printf 'INSTALL_RC=%s\n' "$INSTALL_RC" \
  | sudo tee "$ROLLOUT_DIR/install-result.txt"

if [ "$INSTALL_RC" -ne 0 ]; then
  echo 'INSTALL=FAIL; EXECUTE TASK 10 ROLLBACK'
  exit 1
fi

echo 'INSTALL=PASS'
```

Do not rerun the installer after failure. Roll back first.

---

### Task 8: Installed-content Verification and Read-only Smoke Checks

**Files:**
- Read: installed runtime
- Create: post-install evidence JSON

**Interfaces:**
- Proves installed content equals repository source.
- Proves strict job readers operate with an empty job store.
- Does not create a provisioning job.

- [ ] **Step 1: Compare installed runtime with repository source**

```bash
source <(sudo cat /root/alt-phase-2-3-rollout.env)
cd "$WORKTREE" || exit 1

sudo test -x /usr/local/sbin/workstationctl
sudo test -x /usr/local/libexec/alt-provision-worker
sudo test -x /usr/local/libexec/alt-job-stage

sudo cmp -s deploy/alt-linux/control/workstationctl \
  /usr/local/sbin/workstationctl
sudo cmp -s deploy/alt-linux/control/alt-provision-worker \
  /usr/local/libexec/alt-provision-worker
sudo cmp -s deploy/alt-linux/control/alt-job-stage \
  /usr/local/libexec/alt-job-stage
sudo cmp -s deploy/alt-linux/api/process_pending.py \
  /opt/alt-deploy-api/process_pending.py

sudo diff -qr --exclude='__pycache__' --exclude='*.pyc' \
  deploy/alt-linux/control/alt_deploy \
  /opt/alt-deploy-control/alt_deploy
sudo diff -qr deploy/alt-linux/ansible/playbooks \
  /home/altserver/ansible/playbooks
sudo diff -qr deploy/alt-linux/ansible/roles \
  /home/altserver/ansible/roles
sudo cmp -s deploy/alt-linux/ansible/ansible.cfg \
  /home/altserver/ansible/ansible.cfg
sudo cmp -s deploy/alt-linux/ansible/group_vars/all.yml \
  /home/altserver/ansible/group_vars/all.yml

echo 'INSTALLED_CONTENT=PASS'
```

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
import json
import sys
from pathlib import Path

root = Path(sys.argv[1])
files = {
    name: json.loads((root / filename).read_text(encoding="utf-8"))
    for name, filename in {
        "vault": "post-install-vault.json",
        "permissions": "post-install-permissions.json",
        "cleanup": "post-install-cleanup.json",
        "reconcile": "post-install-reconcile.json",
        "machines": "post-install-machines.json",
    }.items()
}
for name, payload in files.items():
    if payload.get("status") != "ok":
        raise SystemExit(f"{name} did not return status=ok")

cleanup_report = files["cleanup"].get("cleanup") or files["cleanup"].get("retention")
if not isinstance(cleanup_report, dict) or cleanup_report.get("checked") != 0:
    raise SystemExit(f"cleanup report is not empty: {cleanup_report}")

reconciliation = files["reconcile"].get("reconciliation")
if not isinstance(reconciliation, dict) or reconciliation.get("checked") != 0:
    raise SystemExit(f"reconciliation report is not empty: {reconciliation}")

print("POST_INSTALL_JSON_SMOKE=PASS")
PY
```

- [ ] **Step 3: Verify assignments remain byte-identical**

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

- [ ] **Step 4: Restore pre-rollout service states**

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

sudo systemctl --failed --no-legend \
  | sudo tee "$ROLLOUT_DIR/failed-units-after.txt" >/dev/null
sudo journalctl \
  -u alt-deploy-process.path \
  -u alt-deploy-process.service \
  --since '-10 minutes' --no-pager \
  | sudo tee "$ROLLOUT_DIR/process-journal-after.txt" >/dev/null
```

Review failed units and recent process logs. Any new failed ALT deployment unit blocks Phase A acceptance.

- [ ] **Step 5: Stop for explicit Phase A review**

```bash
source <(sudo cat /root/alt-phase-2-3-rollout.env)
sudo chmod -R go-rwx "$ROLLOUT_DIR"
echo "PHASE_A_EVIDENCE=$ROLLOUT_DIR"
echo 'PHASE_A_CONTROLLER_ROLLOUT=READY_FOR_REVIEW'
```

Do not proceed automatically to live provisioning.

---

### Task 9: Phase A Acceptance Gate

**Files:**
- Review: evidence directory

**Interfaces:**
- Produces explicit decision: accept controller rollout or execute rollback.

- [ ] **Step 1: Review required evidence**

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

- [ ] **Step 2: Accept only when every condition is true**

```text
runtime/test tree matches verified base
complete pre-rollout gate passed
only approved old jobs were removed
jobs and runtime backups exist and checksums are recorded
installer exited 0
installed files match source
Vault status=ok
controller permissions status=ok
cleanup checked=0
reconciliation checked=0
assignments are byte-identical
service states were restored
no new failed ALT deployment unit exists
```

Retain both backup archives until Phase B is complete and reviewed.

---

### Task 10: Roll Back Phase A on Any Failure

**Files:**
- Restore: runtime and jobs archives
- Preserve: assignments and secrets

**Interfaces:**
- Removes newly installed managed paths before restoring the old archive, avoiding leftover Phase 2.3 files.

- [ ] **Step 1: Stop registration and processing**

```bash
source <(sudo cat /root/alt-phase-2-3-rollout.env)
sudo systemctl stop alt-deploy-register.service
sudo systemctl stop alt-deploy-process.path
sudo systemctl stop alt-deploy-process.service || true
```

- [ ] **Step 2: Verify backup checksums**

```bash
source <(sudo cat /root/alt-phase-2-3-rollout.env)
sudo sha256sum -c "$ROLLOUT_DIR/backup-sha256.txt"
```

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

- [ ] **Step 4: Restore runtime and jobs**

```bash
source <(sudo cat /root/alt-phase-2-3-rollout.env)

sudo tar -C / -xzpf "$ROLLOUT_DIR/runtime-before.tar.gz"
sudo rm -rf /var/lib/alt-deploy/jobs
sudo tar -C / -xzpf "$ROLLOUT_DIR/jobs-before.tar.gz"
```

- [ ] **Step 5: Verify assignments still match the baseline**

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

- [ ] **Step 6: Restore service states**

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

sudo -u altserver workstationctl --json vault check
sudo -u altserver workstationctl --json controller permissions
sudo -u altserver workstationctl --json machines list

echo 'PHASE_A_ROLLBACK=COMPLETE'
```

Do not retry Phase A until the failure cause is understood and separately approved.

---

### Task 11: Separate Live Acceptance on a New Disposable Machine

**Files:**
- Create as `altserver`: `/home/altserver/phase-2-3-new-machine-request.json`
- Create evidence: `$ROLLOUT_DIR/new-machine-*.json`
- Modify: one new disposable target only

**Interfaces:**
- Requires explicit Phase B approval after accepted Phase A.
- Produces a real successful ten-stage history.

- [ ] **Step 1: Approve a new disposable target**

Required conditions:

```text
new clean VM or physical workstation
no production employee data
UUID differs from 53b03180-5d78-11f0-bd95-f027db877a00
machine is unassigned
registration and preflight reach awaiting_assignment
```

- [ ] **Step 2: Record and validate the new UUID**

```bash
source <(sudo cat /root/alt-phase-2-3-rollout.env)
read -r -p 'New disposable machine UUID: ' NEW_UUID

python3 - "$NEW_UUID" <<'PY'
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

- [ ] **Step 3: Create an altserver-readable non-secret request**

```bash
source <(sudo cat /root/alt-phase-2-3-rollout.env)
source <(sudo cat "$ROLLOUT_DIR/new-machine.env")

REQUEST_FILE=/home/altserver/phase-2-3-new-machine-request.json

sudo -u altserver env NEW_UUID="$NEW_UUID" REQUEST_FILE="$REQUEST_FILE" \
  python3 - <<'PY'
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
path = Path(os.environ["REQUEST_FILE"])
path.write_text(
    json.dumps(request, ensure_ascii=False, indent=2) + "\n",
    encoding="utf-8",
)
path.chmod(0o600)
print(path)
PY

sudo install -o root -g root -m 0600 \
  "$REQUEST_FILE" \
  "$ROLLOUT_DIR/new-machine-request.json"
```

The request contains no password or password hash.

- [ ] **Step 4: Run preview and require success**

```bash
source <(sudo cat /root/alt-phase-2-3-rollout.env)
source <(sudo cat "$ROLLOUT_DIR/new-machine.env")
REQUEST_FILE=/home/altserver/phase-2-3-new-machine-request.json

sudo -u altserver workstationctl --json provision preview "$NEW_UUID" \
  --vars-file "$REQUEST_FILE" \
  | sudo tee "$ROLLOUT_DIR/new-machine-preview.json" >/dev/null

sudo python3 - "$ROLLOUT_DIR/new-machine-preview.json" <<'PY'
import json
import sys
from pathlib import Path

payload = json.loads(Path(sys.argv[1]).read_text(encoding="utf-8"))
if payload.get("status") != "ok":
    raise SystemExit("preview did not return status=ok")
print("NEW_MACHINE_PREVIEW=PASS")
PY
```

- [ ] **Step 5: Start exactly one job**

```bash
source <(sudo cat /root/alt-phase-2-3-rollout.env)
source <(sudo cat "$ROLLOUT_DIR/new-machine.env")
REQUEST_FILE=/home/altserver/phase-2-3-new-machine-request.json

sudo workstationctl --json provision start "$NEW_UUID" \
  --vars-file "$REQUEST_FILE" \
  | sudo tee "$ROLLOUT_DIR/new-machine-start.json" >/dev/null

JOB_ID="$(sudo python3 - "$ROLLOUT_DIR/new-machine-start.json" <<'PY'
import json
import sys
from pathlib import Path

payload = json.loads(Path(sys.argv[1]).read_text(encoding="utf-8"))
if payload.get("status") != "ok":
    raise SystemExit("provision start did not return status=ok")
container = payload.get("job") or payload.get("provision") or payload
job_id = container.get("job_id") if isinstance(container, dict) else None
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

- [ ] **Step 6: Poll the existing job to a terminal state**

```bash
source <(sudo cat /root/alt-phase-2-3-rollout.env)
source <(sudo cat "$ROLLOUT_DIR/new-machine-job.env")

STATE=''
for attempt in $(seq 1 180); do
  sudo -u altserver workstationctl --json jobs status "$JOB_ID" \
    > /tmp/phase-2-3-job-status.json

  STATE="$(python3 - <<'PY'
import json
from pathlib import Path

payload = json.loads(
    Path("/tmp/phase-2-3-job-status.json").read_text(encoding="utf-8")
)
print(payload["job"]["state"])
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

If the job fails, preserve evidence and stop. Do not create another job until the failure is reviewed.

- [ ] **Step 7: Verify the exact canonical history**

```bash
source <(sudo cat /root/alt-phase-2-3-rollout.env)

sudo python3 - "$ROLLOUT_DIR/new-machine-final-job.json" <<'PY'
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
    raise SystemExit(f"unexpected history: {observed}")
for item in history:
    if set(item) != {"stage", "entered_at"}:
        raise SystemExit(f"unexpected history fields: {item}")
    parsed = datetime.fromisoformat(item["entered_at"])
    if parsed.tzinfo is None:
        raise SystemExit(f"timestamp has no timezone: {item}")
print("LIVE_STAGE_HISTORY=PASS")
for item in history:
    print(item["stage"], item["entered_at"])
PY
```

- [ ] **Step 8: Verify assignment and graphical reboot acceptance**

```bash
source <(sudo cat /root/alt-phase-2-3-rollout.env)
source <(sudo cat "$ROLLOUT_DIR/new-machine.env")

sudo -u altserver workstationctl --json machines show "$NEW_UUID" \
  | sudo tee "$ROLLOUT_DIR/new-machine-assigned.json" >/dev/null

sudo python3 - "$ROLLOUT_DIR/new-machine-assigned.json" <<'PY'
import json
import sys
from pathlib import Path

payload = json.loads(Path(sys.argv[1]).read_text(encoding="utf-8"))
if payload.get("status") != "ok":
    raise SystemExit("machine show did not return status=ok")
machine = payload.get("machine")
if not isinstance(machine, dict) or machine.get("status") != "assigned":
    raise SystemExit(f"machine is not assigned: {machine}")
print("CONTROLLER_ASSIGNMENT=PASS")
PY
```

Then reboot only the new disposable target, verify LightDM account visibility, log in as the acceptance user, and verify Plasma opens. Do not touch the assigned reference target.

- [ ] **Step 9: Verify repeat-provision protection**

```bash
source <(sudo cat /root/alt-phase-2-3-rollout.env)
source <(sudo cat "$ROLLOUT_DIR/new-machine.env")
REQUEST_FILE=/home/altserver/phase-2-3-new-machine-request.json

set +e
set -o pipefail
sudo -u altserver workstationctl --json provision preview "$NEW_UUID" \
  --vars-file "$REQUEST_FILE" \
  | sudo tee "$ROLLOUT_DIR/new-machine-repeat-preview.json" >/dev/null
RC=${PIPESTATUS[0]}
set -e

sudo python3 - "$ROLLOUT_DIR/new-machine-repeat-preview.json" "$RC" <<'PY'
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

- [ ] **Step 10: Remove the temporary altserver request after evidence is saved**

```bash
sudo rm -f /home/altserver/phase-2-3-new-machine-request.json
```

---

### Task 12: Final Evidence and Backup Retention

**Files:**
- Review: evidence directory
- Retain: rollback archives until separate cleanup approval

**Interfaces:**
- Produces final acceptance evidence without placing runtime data in Git.

- [ ] **Step 1: Review the final acceptance matrix**

```text
Phase A explicitly accepted
runtime/test tree matched verified base
complete gate passed
only approved old jobs removed
assignments remained byte-identical
Vault and permissions remained healthy
cleanup and reconciliation checked zero after install
required service states restored
new disposable machine used
one provision job started
job reached successful/complete
stage_history exactly matched all ten canonical stages
controller assignment exists
graphical LightDM/Plasma login succeeded
repeat preview returned machine_already_assigned
reference UUID was never provisioned
```

- [ ] **Step 2: Create a final evidence checksum manifest**

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

- [ ] **Step 3: Retain rollback archives**

Do not automatically delete:

```text
$ROLLOUT_DIR/jobs-before.tar.gz
$ROLLOUT_DIR/runtime-before.tar.gz
$ROLLOUT_DIR/old-jobs-approved.json
$ROLLOUT_DIR/backup-sha256.txt
```

Archive expiry and deletion require a separate operator decision. Never commit these files to Git.

---

## Final Acceptance Matrix

| Requirement | Evidence |
| --- | --- |
| Verified runtime installed | source-tree equivalence, complete gate, installed-content comparisons |
| No unreviewed job deletion | approved manifest and per-status SHA-256 checks |
| No active work interrupted | pending and active-unit audits |
| Complete rollback | jobs/runtime archives and backup checksum manifest |
| Secrets excluded | explicit runtime archive content inspection |
| Assignments untouched | before/after checksum manifests |
| Strict schema operational | cleanup and reconciliation both `checked=0` |
| Controller healthy | Vault, permissions, machines, services, journal evidence |
| Full real stage order | final job JSON and canonical-history validator |
| Existing assigned machine protected | UUID guard and repeat-provision test |

## Explicitly Deferred

```text
Plasma configuration capture and Ansible role
OpenVPN and network changes
web UI and constrained API
release/reassignment
old-job migration
progress percentage and ETA
automatic cleanup or reconciliation services
production multi-machine rollout
```
