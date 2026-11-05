# ALT OR-3P4 Local Codex SSH Execution Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use `superpowers:executing-plans` or `superpowers:subagent-driven-development` and execute this document task by task. Checkboxes are the authoritative progress record.

**Goal:** Complete the remaining ALT controller fixes, verify the exact reviewed generation, and deploy it to `192.168.100.17` from a local Codex session using ordinary OpenSSH commands. No Codex CLI, agent, daemon, or OpenAI credential is installed on the controller.

**Architecture:** Source editing, tests, Git commits, PR review, and GitHub CI happen in the local `web_ovpn` repository. The existing issue-30 commits currently located in a controller worktree are first pushed to GitHub through an explicitly reviewed SSH command and then fetched into the local repository. Every production deployment is bound to an exact merge commit: the controller fetches that commit from GitHub into a detached worktree, verifies it, installs the backup tool, creates and rehearses one fresh rollback bundle, and only then runs `install-control-plane.sh` with the exact backup ID. Local Codex uses SSH only as an execution transport.

**Tech stack:** Local Codex app or IDE integration; a local POSIX shell, preferably WSL2 when the workstation is Windows; OpenSSH; Git and Git worktrees; GitHub PR/CI; Python 3.12; pytest; Bash; systemd; Ansible; the existing OR-3P3 `alt-deploy-backup` utility; the existing OR-3P4 installer.

---

## Non-Negotiable Boundaries

- Codex runs on the operator workstation only.
- Do not install Codex, Codex CLI, an agent runtime, an OpenAI API key, or an OpenAI login on `192.168.100.17`.
- Do not use editor synchronization, `scp`, `rsync`, or a tar archive to deploy tracked source. Source reaches the controller only through an exact GitHub commit.
- Do not edit tracked source files directly on the controller. Controller worktrees are verification and deployment checkouts only.
- All controller access uses `altserver@192.168.100.17` with `StrictHostKeyChecking=yes`, `ForwardAgent=no`, and `ClearAllForwardings=yes`.
- Never accept a new controller host key without comparing its fingerprint through an already trusted out-of-band channel.
- Never place an SSH passphrase, sudo password, Vault password, employee password, password hash, private key, decrypted Vault data, or secret file contents in a command, environment variable, prompt, log, Git commit, or GitHub comment.
- The human operator types interactive sudo and SSH-key passphrases directly into the terminal.
- Every remote mutation requires an explicit human approval immediately before execution.
- Controller remains `192.168.100.17`. The OpenVPN/web host `192.168.100.30` is outside this rollout and must not receive controller Vault or SSH private-key material.
- Do not contact, modify, reboot, re-register, archive, release, or reprovision the accepted reference workstation `192.168.101.111`, UUID `cc6f1a81-54b8-47c9-95de-2ac29ee4fbb7`.
- Do not install while any provision job is active, a pending registration exists, the registration processor is active, Vault or controller permissions are unhealthy, or a rollout/restore transaction is non-terminal.
- Do not manually delete or rewrite jobs, assignments, registrations, Vault files, SSH identity, ISO metadata, backup bundles, rollout state, restore journals, or guard permits.
- Every code change uses TDD, focused tests, the complete affected module, the complete ALT suite, GitHub CI, review, and a clean worktree before merge.
- Every rollout uses one exact merged commit and one exact newly created, verified, rehearsed backup ID. Never select the newest backup implicitly.
- After a successful rehearsal, do not run public `verify` again. Rehearsal evidence is bound to the exact `verification.json` bytes.
- A failed rehearsal tree is incident evidence. Preserve it until its defect is merged, installed, and a new backup rehearses successfully.
- A failed post-mutation rollout leaves `alt-deploy-guard.service` authoritative. Do not manually start guarded services.
- Run one remote mutation at a time and inspect the complete exit status before continuing.
- Merge only after explicit human approval and fresh CI.

---

## Verified Starting Point to Reconfirm

The executor must verify all of the following before relying on them:

- GitHub issue `#30` describes the OR-3P3 rehearsal defect that conflates registration directory state with machine business status.
- The issue-30 TDD commits currently exist in controller worktree `/home/altserver/web_ovpn-src/.worktrees/or3p3-registration-status-fix`:
  - RED: `3b386b63fd67281f56507de1d76b65326d35e791`;
  - GREEN: `796cda2395c7af2a011f44e12096c76092ac69fe`;
  - base: `b0ae92c62406eacc5b2c1ed638d2396ff89f0b56`.
- Those commits change only:
  - `deploy/alt-linux/backup/alt_deploy_backup/state_validation.py`;
  - `tests/alt_linux/test_or3p3_backup_rehearsal.py`.
- The post-commit OR-3P3 rehearsal module result is `7 passed`.
- The controller ALT suite has ten known test-harness failures that reproduce on the unchanged base:
  - one dependency-isolation failure caused by `/bin` resolving into `/usr/bin`;
  - nine failures caused by the portable `altserver` fixture omitting `pw_name`.
- The existing failed rehearsal bundle is `backup-20260723T133400Z-2b5c8ee3`.
- Its bounded diagnostics file is `/root/or3p4-20260723T061042Z/post-hotfix-registration-diagnostics.json` with SHA-256 `2ead9b49834bc96008e89c3262c7dbaea27b0776058180d5e18e1ac35eba7ae5`.
- Its failed tree is `/var/tmp/alt-deploy-restore-test/backup-20260723T133400Z-2b5c8ee3` and its bundle has no `rehearsal.json`.
- The controller repository root is `/home/altserver/web_ovpn-src`.

Any mismatch is a stop condition. Capture a fresh read-only audit and adapt the plan before mutation.

---

## Planned Repository Changes

### Issue #30

- Modify `deploy/alt-linux/backup/alt_deploy_backup/state_validation.py` only to remove the invalid `payload.status == registration directory` requirement.
- Modify `tests/alt_linux/test_or3p3_backup_rehearsal.py` to prove that `status=awaiting_assignment` is valid in an active registration directory.

### Controller test-harness portability

- Modify `tests/alt_linux/conftest.py` to include `pw_name="altserver"` in the portable account fixture.
- Modify `tests/alt_linux/support/installer_sandbox.py` to start the test shell through absolute `/bin/bash` and install a fake `bash` command in the sandbox PATH.
- Modify `tests/alt_linux/test_install_assets.py` so the missing-dependency test uses only the sandbox fake-bin directory in `PATH`.

### Rollout closure

- Create `docs/verification/ALT_OR3P4_SSH_CONTROLLER_ROLLOUT_2026-07-24.md` after successful acceptance.
- Update `docs/ALT_WORKSTATION_PROVISIONING_CONTEXT.md`.
- Update `docs/ALT_WORKSTATION_PROVISIONING_NEXT_STEPS.md`.

No deployment CLI, SSH wrapper, persistent controller agent, or server-side Codex installation is added.

---

## Execution Gates

| Gate | Required result | Failure action |
| --- | --- | --- |
| Local environment | POSIX shell, clean repository, OpenSSH available | stop and repair local environment |
| SSH identity | pinned host key, `altserver`, expected controller hostname | stop and verify out of band |
| Issue #30 | exact two-file change, CI success, merged | do not start portability work |
| Portability | exact three test-file change, controller ALT suite exit `0`, CI success, merged | do not create rollout checkout |
| Remote source | exact merge SHA, clean detached worktree, syntax and full ALT suite exit `0` | no runtime mutation |
| Quiescence | zero active jobs, zero pending records, processor inactive, no transient units | wait or resolve operational state |
| OR-3P3 | new exact backup ID, verification success, rehearsal success, evidence binding valid | preserve evidence; do not install |
| OR-3P4 | installer exit `0`, readiness success | leave guard authoritative; use recovery procedure |
| Preservation | protected trees byte/metadata identical | no provisioning; investigate or restore |
| Acceptance | new disposable UUID, successful complete job, visual login, repeat protection | no pilot expansion |

---

## Task 1: Establish the Local Codex and SSH Contract

**Files:** none.

- [ ] **Step 1: Open the repository in a local POSIX shell**

On Windows, run these commands inside WSL2. Do not run the rollout from a native shell that cannot preserve Bash quoting semantics.

```bash
set -Eeuo pipefail

LOCAL_REPO="$(git rev-parse --show-toplevel)"
cd "$LOCAL_REPO"

if [[ -x "$LOCAL_REPO/.venv/bin/python" ]]; then
    PYTHON_BIN="$LOCAL_REPO/.venv/bin/python"
else
    PYTHON_BIN="$(command -v python3)"
fi

CONTROLLER='altserver@192.168.100.17'
SSH_OPTS=(
    -o StrictHostKeyChecking=yes
    -o ForwardAgent=no
    -o ClearAllForwardings=yes
    -o ConnectTimeout=10
)

printf 'LOCAL_REPO=%s\n' "$LOCAL_REPO"
printf 'PYTHON_BIN=%s\n' "$PYTHON_BIN"
printf 'LOCAL_BRANCH=%s\n' "$(git branch --show-current)"
printf 'LOCAL_HEAD=%s\n' "$(git rev-parse HEAD)"
git status --short
```

Expected: the local `web_ovpn` repository and no unrelated uncommitted changes.

- [ ] **Step 2: Verify the local SSH client and approved identity**

```bash
command -v ssh
command -v ssh-keygen
ssh -V
ssh-add -l
```

If the key is not loaded, the human operator runs `ssh-add` interactively. Codex must not receive the passphrase.

- [ ] **Step 3: Inspect effective SSH configuration**

```bash
ssh -G "$CONTROLLER" |
  awk '$1 ~ /^(hostname|user|port|identityfile|forwardagent|stricthostkeychecking|userknownhostsfile)$/ {print}'
```

Required: host `192.168.100.17`, user `altserver`, agent forwarding disabled, and strict host-key checking not set to `no` or `accept-new`.

- [ ] **Step 4: Verify the pinned host key**

```bash
ssh-keygen -F 192.168.100.17
```

If no trusted entry exists, stop. Obtain the controller ED25519 fingerprint through its console or another already trusted channel:

```bash
sudo ssh-keygen -lf /etc/ssh/ssh_host_ed25519_key.pub
```

Compare the fingerprint before adding a host-key entry. `ssh-keyscan` alone is not identity proof.

- [ ] **Step 5: Run a strict read-only SSH check**

```bash
ssh -o BatchMode=yes "${SSH_OPTS[@]}" "$CONTROLLER" \
  'set -Eeuo pipefail
   printf "REMOTE_USER=%s\n" "$(id -un)"
   printf "REMOTE_UID=%s\n" "$(id -u)"
   printf "REMOTE_HOSTNAME=%s\n" "$(hostname -f)"
   printf "REMOTE_KERNEL=%s\n" "$(uname -r)"'
```

Expected: `REMOTE_USER=altserver`, UID `1000`, and the known controller hostname, currently `sosn.alt.adm`.

- [ ] **Step 6: Verify sudo interactively**

```bash
ssh -tt "${SSH_OPTS[@]}" "$CONTROLLER" \
  'sudo -v && sudo -n true && echo REMOTE_SUDO_READY=PASS'
```

The human operator types the password directly if prompted.

- [ ] **Step 7: Record the execution model in the Codex task log**

```text
Development workspace: local web_ovpn repository
Remote execution transport: OpenSSH to altserver@192.168.100.17
Server-side Codex or Codex CLI: prohibited
Source transfer: exact GitHub commits only
Agent forwarding: disabled
```

---

## Task 2: Publish the Existing Issue-30 TDD History from the Controller

**Files:** existing two-file issue-30 change only.

- [ ] **Step 1: Verify the controller worktree and exact history read-only**

```bash
RED_COMMIT='3b386b63fd67281f56507de1d76b65326d35e791'
GREEN_COMMIT='796cda2395c7af2a011f44e12096c76092ac69fe'
BASE_COMMIT='b0ae92c62406eacc5b2c1ed638d2396ff89f0b56'
REMOTE_FIX_BRANCH='fix/or3p3-registration-status-contract-20260724'
REMOTE_FIX_WORKTREE='/home/altserver/web_ovpn-src/.worktrees/or3p3-registration-status-fix'

ssh -o BatchMode=yes "${SSH_OPTS[@]}" "$CONTROLLER" \
  "set -Eeuo pipefail
   WORKTREE='$REMOTE_FIX_WORKTREE'
   RED='$RED_COMMIT'
   GREEN='$GREEN_COMMIT'
   BASE='$BASE_COMMIT'

   test \"\$(git -C \"\$WORKTREE\" rev-parse HEAD)\" = \"\$GREEN\"
   test \"\$(git -C \"\$WORKTREE\" rev-parse HEAD^)\" = \"\$RED\"
   test \"\$(git -C \"\$WORKTREE\" rev-parse HEAD^^)\" = \"\$BASE\"
   test -z \"\$(git -C \"\$WORKTREE\" status --porcelain)\"
   git -C \"\$WORKTREE\" diff --check \"\$BASE..\$GREEN\"
   git -C \"\$WORKTREE\" diff --name-only \"\$BASE..\$GREEN\" | sort"
```

Expected files only:

```text
deploy/alt-linux/backup/alt_deploy_backup/state_validation.py
tests/alt_linux/test_or3p3_backup_rehearsal.py
```

- [ ] **Step 2: Run fresh focused and module tests on the controller worktree**

```bash
ssh -o BatchMode=yes "${SSH_OPTS[@]}" "$CONTROLLER" \
  "set -Eeuo pipefail
   cd '$REMOTE_FIX_WORKTREE'
   PYTHONDONTWRITEBYTECODE=1 python3 -m pytest -q \
     tests/alt_linux/test_or3p3_backup_rehearsal.py::test_rehearsal_accepts_machine_status_distinct_from_registration_state
   PYTHONDONTWRITEBYTECODE=1 python3 -m pytest -q \
     tests/alt_linux/test_or3p3_backup_rehearsal.py"
```

Expected: focused `1 passed`; module `7 passed`.

- [ ] **Step 3: Reconfirm the RED commit in a temporary controller worktree**

```bash
ssh -o BatchMode=yes "${SSH_OPTS[@]}" "$CONTROLLER" \
  "set -uo pipefail
   REPO=/home/altserver/web_ovpn-src
   WORKTREE=\"\$REPO/.worktrees/or3p3-registration-status-red-recheck\"
   RED='$RED_COMMIT'

   test ! -e \"\$WORKTREE\"
   git -C \"\$REPO\" worktree add --detach \"\$WORKTREE\" \"\$RED\"
   set +e
   (cd \"\$WORKTREE\" && PYTHONDONTWRITEBYTECODE=1 python3 -m pytest -q \
     tests/alt_linux/test_or3p3_backup_rehearsal.py::test_rehearsal_accepts_machine_status_distinct_from_registration_state)
   RC=\$?
   set -e
   git -C \"\$REPO\" worktree remove \"\$WORKTREE\"
   printf 'RED_RECHECK_EXIT_CODE=%s\n' \"\$RC\"
   test \"\$RC\" -eq 1"
```

Expected failure: `Registration identity or generation is invalid`.

- [ ] **Step 4: Push the exact GREEN commit from the controller to a review branch**

This is a remote Git mutation and requires approval. The human operator may type the controller Git SSH-key passphrase.

```bash
ssh -tt "${SSH_OPTS[@]}" "$CONTROLLER" \
  "set -Eeuo pipefail
   WORKTREE='$REMOTE_FIX_WORKTREE'
   GREEN='$GREEN_COMMIT'
   BRANCH='$REMOTE_FIX_BRANCH'

   if git -C \"\$WORKTREE\" ls-remote --exit-code --heads origin \"\$BRANCH\" >/dev/null 2>&1; then
       echo REMOTE_REVIEW_BRANCH_ALREADY_EXISTS
       exit 20
   fi

   git -C \"\$WORKTREE\" push origin \
     \"\$GREEN:refs/heads/\$BRANCH\"
   git -C \"\$WORKTREE\" fetch origin \"\$BRANCH\"
   test \"\$(git -C \"\$WORKTREE\" rev-parse \"origin/\$BRANCH\")\" = \"\$GREEN\"
   echo ISSUE30_BRANCH_PUSHED=PASS"
```

- [ ] **Step 5: Fetch the branch into the local repository and create a local review worktree**

```bash
cd "$LOCAL_REPO"
git fetch origin "$REMOTE_FIX_BRANCH"

test "$(git rev-parse "origin/$REMOTE_FIX_BRANCH")" = "$GREEN_COMMIT"

LOCAL_FIX_WORKTREE="$LOCAL_REPO/.worktrees/or3p3-registration-status-review"
test ! -e "$LOCAL_FIX_WORKTREE"

git worktree add --detach \
  "$LOCAL_FIX_WORKTREE" \
  "origin/$REMOTE_FIX_BRANCH"

cd "$LOCAL_FIX_WORKTREE"
test "$(git rev-parse HEAD)" = "$GREEN_COMMIT"
test -z "$(git status --porcelain)"

PYTHONDONTWRITEBYTECODE=1 "$PYTHON_BIN" -m pytest -q \
  tests/alt_linux/test_or3p3_backup_rehearsal.py
```

Expected: `7 passed`.

- [ ] **Step 6: Open the issue-30 PR**

Use GitHub connector or browser:

```text
Title: fix: decouple machine status from registration state in rehearsal
Base: main
Head: fix/or3p3-registration-status-contract-20260724
Body includes: Fixes #30, RED/GREEN SHAs, exact two-file scope, controller diagnostics path and SHA-256, focused/module results, and confirmation that no live registration was changed.
```

Do not merge yet.

---

## Task 3: Review, Verify, and Merge Issue #30

- [ ] Confirm changed files are exactly the validator and rehearsal test.
- [ ] Confirm production diff only removes payload-status extraction and `status != state`.
- [ ] Confirm regular-file, bounded JSON, duplicate-key, identity, filename, and registration-generation checks remain fail-closed.
- [ ] Wait for all focused and full-regression GitHub jobs and inspect job output or artifacts.
- [ ] After explicit approval, merge with the repository’s normal merge-commit strategy.
- [ ] Record `REGISTRATION_STATUS_MERGE_SHA`.
- [ ] Verify locally:

```bash
cd "$LOCAL_REPO"
git fetch --prune origin main
git merge-base --is-ancestor \
  "$REGISTRATION_STATUS_MERGE_SHA" \
  origin/main
```

Expected exit `0`.

---

## Task 4: Reproduce and Fix the Controller Test-Harness Failures

**Files:**

- `tests/alt_linux/conftest.py`
- `tests/alt_linux/support/installer_sandbox.py`
- `tests/alt_linux/test_install_assets.py`

- [ ] **Step 1: Create a detached baseline worktree on the controller**

```bash
ssh -tt "${SSH_OPTS[@]}" "$CONTROLLER" \
  "set -Eeuo pipefail
   REPO=/home/altserver/web_ovpn-src
   WORKTREE=\"\$REPO/.worktrees/or3p4-portability-red\"
   COMMIT='$REGISTRATION_STATUS_MERGE_SHA'

   test ! -e \"\$WORKTREE\"
   git -C \"\$REPO\" fetch --prune origin main
   git -C \"\$REPO\" cat-file -e \"\${COMMIT}^{commit}\"
   git -C \"\$REPO\" worktree add --detach \"\$WORKTREE\" \"\$COMMIT\"
   test -z \"\$(git -C \"\$WORKTREE\" status --porcelain)\"
   echo PORTABILITY_RED_WORKTREE=PASS"
```

- [ ] **Step 2: Run and preserve the exact ten RED tests**

```bash
ssh -o BatchMode=yes "${SSH_OPTS[@]}" "$CONTROLLER" \
  'set -uo pipefail
   WORKTREE=/home/altserver/web_ovpn-src/.worktrees/or3p4-portability-red
   LOG=/tmp/or3p4-portability-red.log
   cd "$WORKTREE"

   PYTHONDONTWRITEBYTECODE=1 python3 -m pytest -q --tb=short \
     tests/alt_linux/test_install_assets.py::test_missing_dependency_is_reported_before_runtime_mutation \
     tests/alt_linux/test_machine_archive_service.py::test_apply_archives_exact_bytes \
     tests/alt_linux/test_machine_archive_service.py::test_assigned_machine_changes_nothing \
     tests/alt_linux/test_machine_archive_service.py::test_busy_machine_changes_nothing_and_redacts \
     tests/alt_linux/test_machine_archive_service.py::test_copy_failure_leaves_source_active \
     tests/alt_linux/test_machine_archive_service.py::test_postcommit_failure_hides_generation_and_reuses_id \
     tests/alt_linux/test_machine_archive_service.py::test_completed_repeat_returns_already_archived \
     tests/alt_linux/test_machine_archive_service.py::test_preview_reports_completed_archive_without_mutation \
     tests/alt_linux/test_machine_archive_service.py::test_newer_generation_at_source_path_is_not_deleted \
     tests/alt_linux/test_machine_archive_service.py::test_later_generation_creates_new_archive_id \
     >"$LOG" 2>&1
   RC=$?
   cat "$LOG"
   printf "PORTABILITY_RED_EXIT_CODE=%s\n" "$RC"
   exit "$RC"'
```

Expected: exit `1`, one missing-dependency assertion, and nine missing-`pw_name` errors.

Preserve the log after interactive approval:

```bash
ssh -tt "${SSH_OPTS[@]}" "$CONTROLLER" \
  'sudo /bin/bash -s' <<'REMOTE_BASH'
set -Eeuo pipefail
EVIDENCE=/root/alt-or3p4-ssh-portability-red-20260724
install -d -o root -g root -m 0700 "$EVIDENCE"
install -o root -g root -m 0600 \
  /tmp/or3p4-portability-red.log \
  "$EVIDENCE/failures.log"
sha256sum "$EVIDENCE/failures.log"
REMOTE_BASH
```

- [ ] **Step 3: Create a local portability worktree from current reviewed main**

```bash
cd "$LOCAL_REPO"
git fetch --prune origin main

git merge-base --is-ancestor \
  "$REGISTRATION_STATUS_MERGE_SHA" \
  origin/main

PORTABILITY_BRANCH='fix/alt-controller-test-harness-portability-20260724'
PORTABILITY_WORKTREE="$LOCAL_REPO/.worktrees/alt-controller-test-portability"

test ! -e "$PORTABILITY_WORKTREE"
git show-ref --verify --quiet \
  "refs/heads/$PORTABILITY_BRANCH" && exit 20 || true

git worktree add \
  -b "$PORTABILITY_BRANCH" \
  "$PORTABILITY_WORKTREE" \
  origin/main
```

- [ ] **Step 4: Apply the minimal test-harness fix**

In `tests/alt_linux/conftest.py`, make the fixture return:

```python
return types.SimpleNamespace(
    pw_name="altserver",
    pw_uid=os.getuid(),
    pw_gid=os.getgid(),
)
```

In `tests/alt_linux/support/installer_sandbox.py`:

```python
# Start the synthetic shell independently of child PATH.
["/bin/bash", "-c", command]
```

and add:

```python
self._fake_script(
    "bash",
    'exec /bin/bash "$@"\n',
)
```

In `tests/alt_linux/test_install_assets.py`, use:

```python
completed = sandbox.run_library(
    PATH=str(sandbox.fake_bin),
)
```

Do not modify production code under `deploy/alt-linux/`.

- [ ] **Step 5: Run local GREEN verification**

```bash
cd "$PORTABILITY_WORKTREE"
git diff --check

PYTHONDONTWRITEBYTECODE=1 "$PYTHON_BIN" -m pytest -q \
  tests/alt_linux/test_install_assets.py::test_missing_dependency_is_reported_before_runtime_mutation \
  tests/alt_linux/test_machine_archive_service.py

PYTHONDONTWRITEBYTECODE=1 "$PYTHON_BIN" -m pytest -q \
  tests/alt_linux
```

Expected: exit `0` for both commands.

- [ ] **Step 6: Commit and push the exact three-file change**

```bash
git add -- \
  tests/alt_linux/conftest.py \
  tests/alt_linux/support/installer_sandbox.py \
  tests/alt_linux/test_install_assets.py

git diff --cached --check

test "$(git diff --cached --name-only | wc -l)" = "3"

git commit -m \
  "test: make ALT controller verification portable"

PORTABILITY_COMMIT="$(git rev-parse HEAD)"
test -z "$(git status --porcelain)"

git push -u origin "$PORTABILITY_BRANCH"
```

- [ ] **Step 7: Prove GREEN on the real controller before opening the PR**

```bash
ssh -tt "${SSH_OPTS[@]}" "$CONTROLLER" \
  "set -Eeuo pipefail
   REPO=/home/altserver/web_ovpn-src
   WORKTREE=\"\$REPO/.worktrees/or3p4-portability-green\"
   BRANCH='$PORTABILITY_BRANCH'
   COMMIT='$PORTABILITY_COMMIT'

   test ! -e \"\$WORKTREE\"
   git -C \"\$REPO\" fetch origin \"\$BRANCH\"
   git -C \"\$REPO\" cat-file -e \"\${COMMIT}^{commit}\"
   git -C \"\$REPO\" worktree add --detach \"\$WORKTREE\" \"\$COMMIT\"
   test -z \"\$(git -C \"\$WORKTREE\" status --porcelain)\"
   echo PORTABILITY_GREEN_WORKTREE=PASS"
```

Run the exact ten tests and then the complete ALT suite:

```bash
ssh -o BatchMode=yes "${SSH_OPTS[@]}" "$CONTROLLER" \
  'set -Eeuo pipefail
   WORKTREE=/home/altserver/web_ovpn-src/.worktrees/or3p4-portability-green
   cd "$WORKTREE"

   PYTHONDONTWRITEBYTECODE=1 python3 -m pytest -q --tb=short \
     tests/alt_linux/test_install_assets.py::test_missing_dependency_is_reported_before_runtime_mutation \
     tests/alt_linux/test_machine_archive_service.py::test_apply_archives_exact_bytes \
     tests/alt_linux/test_machine_archive_service.py::test_assigned_machine_changes_nothing \
     tests/alt_linux/test_machine_archive_service.py::test_busy_machine_changes_nothing_and_redacts \
     tests/alt_linux/test_machine_archive_service.py::test_copy_failure_leaves_source_active \
     tests/alt_linux/test_machine_archive_service.py::test_postcommit_failure_hides_generation_and_reuses_id \
     tests/alt_linux/test_machine_archive_service.py::test_completed_repeat_returns_already_archived \
     tests/alt_linux/test_machine_archive_service.py::test_preview_reports_completed_archive_without_mutation \
     tests/alt_linux/test_machine_archive_service.py::test_newer_generation_at_source_path_is_not_deleted \
     tests/alt_linux/test_machine_archive_service.py::test_later_generation_creates_new_archive_id

   PYTHONDONTWRITEBYTECODE=1 python3 -m pytest -q tests/alt_linux'
```

Expected: selected `10 passed`; complete ALT suite exit `0`.

- [ ] **Step 8: Open, review, and merge the portability PR**

```text
Title: test: make ALT controller verification portable
Base: main
Head: fix/alt-controller-test-harness-portability-20260724
Scope: the exact three test-harness files only
Evidence: baseline ten failures; controller selected tests GREEN; controller full ALT suite GREEN; no production runtime mutation
```

Wait for all GitHub CI jobs. Merge only after explicit approval. Record `PORTABILITY_MERGE_SHA` and set:

```bash
ROLLOUT_COMMIT="$PORTABILITY_MERGE_SHA"
```

Verify both prerequisite merges are ancestors of the rollout commit:

```bash
cd "$LOCAL_REPO"
git fetch --prune origin main

git merge-base --is-ancestor \
  "$REGISTRATION_STATUS_MERGE_SHA" \
  "$ROLLOUT_COMMIT"

git merge-base --is-ancestor \
  "$PORTABILITY_MERGE_SHA" \
  origin/main
```

---

## Task 5: Create and Verify the Exact Controller Rollout Worktree

- [ ] **Step 1: Fetch the exact merged commit on the controller**

```bash
ssh -tt "${SSH_OPTS[@]}" "$CONTROLLER" \
  "set -Eeuo pipefail
   REPO=/home/altserver/web_ovpn-src
   COMMIT='$ROLLOUT_COMMIT'

   git -C \"\$REPO\" fetch --prune origin main
   git -C \"\$REPO\" cat-file -e \"\${COMMIT}^{commit}\"
   git -C \"\$REPO\" merge-base --is-ancestor \"\$COMMIT\" origin/main
   echo ROLLOUT_COMMIT_AVAILABLE=PASS"
```

- [ ] **Step 2: Create a unique detached rollout worktree**

```bash
SHORT_SHA="${ROLLOUT_COMMIT:0:12}"
REMOTE_ROLLOUT_WORKTREE="/home/altserver/web_ovpn-src/.worktrees/or3p4-ssh-$SHORT_SHA"

ssh -o BatchMode=yes "${SSH_OPTS[@]}" "$CONTROLLER" \
  "set -Eeuo pipefail
   REPO=/home/altserver/web_ovpn-src
   WORKTREE='$REMOTE_ROLLOUT_WORKTREE'
   COMMIT='$ROLLOUT_COMMIT'

   test ! -e \"\$WORKTREE\"
   git -C \"\$REPO\" worktree add --detach \"\$WORKTREE\" \"\$COMMIT\"
   test \"\$(git -C \"\$WORKTREE\" rev-parse HEAD)\" = \"\$COMMIT\"
   test -z \"\$(git -C \"\$WORKTREE\" status --porcelain)\"
   printf 'REMOTE_ROLLOUT_WORKTREE=%s\n' \"\$WORKTREE\"
   printf 'REMOTE_ROLLOUT_HEAD=%s\n' \"\$COMMIT\""
```

- [ ] **Step 3: Run complete controller-side repository verification before mutation**

```bash
ssh -o BatchMode=yes "${SSH_OPTS[@]}" "$CONTROLLER" \
  "set -Eeuo pipefail
   cd '$REMOTE_ROLLOUT_WORKTREE'

   PYTHONDONTWRITEBYTECODE=1 python3 -m pytest -q tests/alt_linux

   python3 -m py_compile \
     deploy/alt-linux/control/alt_deploy/*.py \
     deploy/alt-linux/api/static_server.py \
     deploy/alt-linux/api/register_api.py \
     deploy/alt-linux/api/process_pending.py \
     deploy/alt-linux/backup/alt_deploy_backup/*.py

   bash -n deploy/alt-linux/install-backup-tool.sh
   bash -n deploy/alt-linux/install-control-plane.sh
   bash -n deploy/alt-linux/install-control-plane-args.sh
   bash -n deploy/alt-linux/install-control-plane-lib.sh
   bash -n deploy/alt-linux/bootstrap/bootstrap.sh
   bash -n deploy/alt-linux/bootstrap/alt-bootstrap-register

   git diff --check
   test -z \"\$(git status --porcelain)\"
   echo REMOTE_SOURCE_VERIFICATION=PASS"
```

Required: complete ALT suite exit `0`. No backup-tool or control-plane path has been changed yet.

---

## Task 6: Create Root-Only Evidence and Prove Controller Quiescence

- [ ] **Step 1: Create a unique rollout record**

```bash
ssh -tt "${SSH_OPTS[@]}" "$CONTROLLER" \
  "sudo /bin/bash -s" <<REMOTE_BASH
set -Eeuo pipefail

ROLLOUT_ID="alt-or3p4-ssh-\$(date -u +%Y%m%dT%H%M%SZ)"
EVIDENCE="/root/\$ROLLOUT_ID"
ENV_FILE=/root/alt-or3p4-ssh-rollout.env

install -d -o root -g root -m 0700 "\$EVIDENCE"
test ! -e "\$ENV_FILE"

{
    printf 'ROLLOUT_ID=%q\n' "\$ROLLOUT_ID"
    printf 'EVIDENCE=%q\n' "\$EVIDENCE"
    printf 'WORKTREE=%q\n' '$REMOTE_ROLLOUT_WORKTREE'
    printf 'COMMIT=%q\n' '$ROLLOUT_COMMIT'
    printf 'CONTROLLER=%q\n' '192.168.100.17'
    printf 'REFERENCE_WORKSTATION=%q\n' '192.168.101.111'
} >"\$ENV_FILE"

chmod 0600 "\$ENV_FILE"
printf 'ROLLOUT_ID=%s\n' "\$ROLLOUT_ID"
printf 'EVIDENCE=%s\n' "\$EVIDENCE"
REMOTE_BASH
```

The unquoted local heredoc is intentional: local `REMOTE_ROLLOUT_WORKTREE` and `ROLLOUT_COMMIT` are inserted, while every remote variable is escaped.

- [ ] **Step 2: Capture read-only identity, disk, inode, and Git evidence**

```bash
ssh -tt "${SSH_OPTS[@]}" "$CONTROLLER" \
  'sudo /bin/bash -s' <<'REMOTE_BASH'
set -Eeuo pipefail
source /root/alt-or3p4-ssh-rollout.env

OUT="$EVIDENCE/pre-rollout-context.txt"

test "$(git -C "$WORKTREE" rev-parse HEAD)" = "$COMMIT"
test -z "$(git -C "$WORKTREE" status --porcelain)"

{
    printf 'utc_time=%s\n' "$(date -u --iso-8601=seconds)"
    printf 'hostname=%s\n' "$(hostname -f)"
    printf 'kernel=%s\n' "$(uname -r)"
    printf 'operator=%s\n' "$(id -un)"
    printf 'repository_commit=%s\n' "$COMMIT"
    printf '%s\n' '--- space ---'
    df -h / /var /home/altserver /srv/alt-deploy /opt /etc/systemd/system /var/backups
    printf '%s\n' '--- inodes ---'
    df -i / /var
} >"$OUT"

chmod 0600 "$OUT"
sha256sum "$OUT"
REMOTE_BASH
```

- [ ] **Step 3: Capture and validate public controller health**

```bash
ssh -tt "${SSH_OPTS[@]}" "$CONTROLLER" \
  'sudo /bin/bash -s' <<'REMOTE_BASH'
set -Eeuo pipefail
source /root/alt-or3p4-ssh-rollout.env

sudo -u altserver workstationctl --json jobs active \
  >"$EVIDENCE/jobs-active.json"
sudo -u altserver workstationctl --json vault check \
  >"$EVIDENCE/vault-check.json"
sudo -u altserver workstationctl --json controller permissions \
  >"$EVIDENCE/controller-permissions.json"

chmod 0600 \
  "$EVIDENCE/jobs-active.json" \
  "$EVIDENCE/vault-check.json" \
  "$EVIDENCE/controller-permissions.json"

python3 - "$EVIDENCE" <<'PY'
import json
import sys
from pathlib import Path

root = Path(sys.argv[1])
jobs = json.loads((root / "jobs-active.json").read_text())
vault = json.loads((root / "vault-check.json").read_text())
permissions = json.loads((root / "controller-permissions.json").read_text())

assert jobs["status"] == "ok"
assert jobs["count"] == 0
assert jobs["active_jobs"] == []
assert vault["status"] == "ok"
assert permissions["status"] == "ok"
print("CONTROLLER_PUBLIC_HEALTH=PASS")
PY
REMOTE_BASH
```

- [ ] **Step 4: Prove pending queue, processor, transient units, and rollout state are idle**

```bash
ssh -tt "${SSH_OPTS[@]}" "$CONTROLLER" \
  'sudo /bin/bash -s' <<'REMOTE_BASH'
set -Eeuo pipefail
source /root/alt-or3p4-ssh-rollout.env

PENDING_COUNT="$(
  find /srv/alt-deploy/registration/pending \
    -maxdepth 1 -type f -name '*.json' -printf '.' | wc -c
)"
PROCESS_STATE="$(systemctl is-active alt-deploy-process.service || true)"
TRANSIENT_COUNT="$(
  systemctl list-units --all --plain --no-legend \
    'alt-provision-*.service' | wc -l
)"

printf '%s\n' \
  "PENDING_COUNT=$PENDING_COUNT" \
  "PROCESS_STATE=$PROCESS_STATE" \
  "TRANSIENT_COUNT=$TRANSIENT_COUNT" \
  >"$EVIDENCE/quiescence.txt"
chmod 0600 "$EVIDENCE/quiescence.txt"

test "$PENDING_COUNT" = "0"
test "$PROCESS_STATE" = "inactive"
test "$TRANSIENT_COUNT" = "0"

test ! -e /var/lib/alt-deploy-backup/rollout.json

test -z "$(
  find /var/backups/alt-deploy/.restore-transactions \
    -mindepth 1 -maxdepth 1 -type d -print 2>/dev/null || true
)"

echo CONTROLLER_QUIESCENCE=PASS
REMOTE_BASH
```

If completed restore journals are intentionally retained, replace the final emptiness assertion with a bounded check that every journal is terminal. Do not delete a journal to satisfy the gate.

- [ ] **Step 5: Preserve the old failed rehearsal metadata**

```bash
ssh -tt "${SSH_OPTS[@]}" "$CONTROLLER" \
  'sudo /bin/bash -s' <<'REMOTE_BASH'
set -Eeuo pipefail
source /root/alt-or3p4-ssh-rollout.env

OLD_BACKUP_ID=backup-20260723T133400Z-2b5c8ee3
OLD_BUNDLE="/var/backups/alt-deploy/$OLD_BACKUP_ID"
OLD_TREE="/var/tmp/alt-deploy-restore-test/$OLD_BACKUP_ID"
DIAGNOSTICS=/root/or3p4-20260723T061042Z/post-hotfix-registration-diagnostics.json
EXPECTED_SHA=2ead9b49834bc96008e89c3262c7dbaea27b0776058180d5e18e1ac35eba7ae5

test -d "$OLD_BUNDLE"
test -f "$OLD_BUNDLE/verification.json"
test ! -e "$OLD_BUNDLE/rehearsal.json"
test -d "$OLD_TREE"
test ! -L "$OLD_TREE"
test "$(stat -c '%U:%G:%a' "$OLD_TREE")" = root:root:700
test "$(sha256sum "$DIAGNOSTICS" | awk '{print $1}')" = "$EXPECTED_SHA"

{
    printf 'OLD_BACKUP_ID=%s\n' "$OLD_BACKUP_ID"
    printf 'OLD_BUNDLE=%s\n' "$OLD_BUNDLE"
    printf 'OLD_FAILED_TREE=%s\n' "$OLD_TREE"
    printf 'OLD_DIAGNOSTICS_SHA256=%s\n' "$EXPECTED_SHA"
    printf 'OLD_BACKUP_REUSABLE=no\n'
} >"$EVIDENCE/previous-failed-rehearsal.txt"
chmod 0600 "$EVIDENCE/previous-failed-rehearsal.txt"

echo PREVIOUS_FAILED_REHEARSAL_PRESERVED=PASS
REMOTE_BASH
```

Keep the old failed tree through installation and post-install readiness.

---

## Task 7: Install the Exact Backup-Tool Generation

This mutates only the backup-tool-owned paths and requires explicit approval.

- [ ] **Step 1: Install and verify source identity**

```bash
ssh -tt "${SSH_OPTS[@]}" "$CONTROLLER" \
  'sudo /bin/bash -s' <<'REMOTE_BASH'
set -Eeuo pipefail
source /root/alt-or3p4-ssh-rollout.env

LOG="$EVIDENCE/install-backup-tool.log"
SOURCE_VALIDATOR="$WORKTREE/deploy/alt-linux/backup/alt_deploy_backup/state_validation.py"
INSTALLED_VALIDATOR=/opt/alt-deploy-backup/alt_deploy_backup/state_validation.py

test "$(git -C "$WORKTREE" rev-parse HEAD)" = "$COMMIT"
test -z "$(git -C "$WORKTREE" status --porcelain)"

{
    printf 'INSTALL_COMMIT=%s\n' "$COMMIT"
    bash "$WORKTREE/deploy/alt-linux/install-backup-tool.sh"
    systemctl daemon-reload

    test -x /usr/local/sbin/alt-deploy-backup
    test -f /etc/systemd/system/alt-deploy-guard.service
    test -f "$INSTALLED_VALIDATOR"

    SOURCE_SHA="$(sha256sum "$SOURCE_VALIDATOR" | awk '{print $1}')"
    INSTALLED_SHA="$(sha256sum "$INSTALLED_VALIDATOR" | awk '{print $1}')"
    test "$SOURCE_SHA" = "$INSTALLED_SHA"

    printf 'SOURCE_VALIDATOR_SHA256=%s\n' "$SOURCE_SHA"
    printf 'INSTALLED_VALIDATOR_SHA256=%s\n' "$INSTALLED_SHA"
    stat -c '%U:%G %a %n' \
      /usr/local/sbin/alt-deploy-backup \
      /opt/alt-deploy-backup \
      /var/lib/alt-deploy-backup \
      /var/backups/alt-deploy \
      /etc/systemd/system/alt-deploy-guard.service

    /usr/local/sbin/alt-deploy-backup guard
    echo BACKUP_TOOL_INSTALL=PASS
} 2>&1 | tee "$LOG"

chmod 0600 "$LOG"
REMOTE_BASH
```

Expected: exit `0`, source and installed validator hashes identical, and guard result `control_plane_allowed`.

---

## Task 8: Create, Verify, and Rehearse One Fresh Rollback Bundle

- [ ] **Step 1: Create one exact bundle**

```bash
ssh -tt "${SSH_OPTS[@]}" "$CONTROLLER" \
  'sudo /bin/bash -s' <<'REMOTE_BASH'
set -Eeuo pipefail
source /root/alt-or3p4-ssh-rollout.env

CREATE_JSON="$EVIDENCE/backup-create.json"
CREATE_ERR="$EVIDENCE/backup-create.stderr"
test ! -e "$CREATE_JSON"
test ! -e "$CREATE_ERR"

/usr/local/sbin/alt-deploy-backup create \
  >"$CREATE_JSON" \
  2>"$CREATE_ERR"
chmod 0600 "$CREATE_JSON" "$CREATE_ERR"
cat "$CREATE_JSON"

mapfile -t VALUES < <(
  python3 - "$CREATE_JSON" <<'PY'
import json
import re
import sys
from pathlib import Path

payload = json.loads(Path(sys.argv[1]).read_text())
assert payload["status"] == "ok"
assert payload["result"] == "backup_created"
assert payload["services_restored"] is True
assert payload["component_count"] == 6
assert re.fullmatch(
    r"backup-[0-9]{8}T[0-9]{6}Z-[0-9a-f]{8}",
    payload["backup_id"],
)
assert re.fullmatch(r"[0-9a-f]{64}", payload["manifest_sha256"])
print(payload["backup_id"])
print(payload["manifest_sha256"])
PY
)

BACKUP_ID="${VALUES[0]}"
MANIFEST_SHA256="${VALUES[1]}"

test "$BACKUP_ID" != "backup-20260723T133400Z-2b5c8ee3"
test -d "/var/backups/alt-deploy/$BACKUP_ID"
test ! -L "/var/backups/alt-deploy/$BACKUP_ID"

{
    printf 'BACKUP_ID=%q\n' "$BACKUP_ID"
    printf 'MANIFEST_SHA256=%q\n' "$MANIFEST_SHA256"
} >>/root/alt-or3p4-ssh-rollout.env

printf 'BACKUP_ID=%s\n' "$BACKUP_ID"
printf 'MANIFEST_SHA256=%s\n' "$MANIFEST_SHA256"
REMOTE_BASH
```

- [ ] **Step 2: Run exactly one explicit verification**

```bash
ssh -tt "${SSH_OPTS[@]}" "$CONTROLLER" \
  'sudo /bin/bash -s' <<'REMOTE_BASH'
set -Eeuo pipefail
source /root/alt-or3p4-ssh-rollout.env

VERIFY_JSON="$EVIDENCE/backup-verify.json"
/usr/local/sbin/alt-deploy-backup verify "$BACKUP_ID" >"$VERIFY_JSON"
chmod 0600 "$VERIFY_JSON"
cat "$VERIFY_JSON"

python3 - "$VERIFY_JSON" "$BACKUP_ID" "$MANIFEST_SHA256" <<'PY'
import json
import sys
from pathlib import Path

payload = json.loads(Path(sys.argv[1]).read_text())
assert payload["status"] == "ok"
assert payload["result"] == "backup_verified"
assert payload["backup_id"] == sys.argv[2]
assert payload["manifest_sha256"] == sys.argv[3]
assert payload["component_count"] == 6
PY
REMOTE_BASH
```

- [ ] **Step 3: Run exactly one isolated rehearsal**

```bash
ssh -tt "${SSH_OPTS[@]}" "$CONTROLLER" \
  'sudo /bin/bash -s' <<'REMOTE_BASH'
set -Eeuo pipefail
source /root/alt-or3p4-ssh-rollout.env

REHEARSE_JSON="$EVIDENCE/backup-rehearse.json"
/usr/local/sbin/alt-deploy-backup rehearse "$BACKUP_ID" >"$REHEARSE_JSON"
chmod 0600 "$REHEARSE_JSON"
cat "$REHEARSE_JSON"

python3 - "$REHEARSE_JSON" "$BACKUP_ID" "$MANIFEST_SHA256" <<'PY'
import json
import sys
from pathlib import Path

payload = json.loads(Path(sys.argv[1]).read_text())
assert payload["status"] == "ok"
assert payload["result"] == "backup_rehearsed"
assert payload["backup_id"] == sys.argv[2]
assert payload["manifest_sha256"] == sys.argv[3]
assert payload["rehearsal_passed"] is True
assert type(payload["check_count"]) is int
assert payload["check_count"] >= 10
PY

test ! -e "/var/tmp/alt-deploy-restore-test/$BACKUP_ID"
test -f "/var/backups/alt-deploy/$BACKUP_ID/verification.json"
test -f "/var/backups/alt-deploy/$BACKUP_ID/rehearsal.json"
REMOTE_BASH
```

If rehearsal fails, stop immediately. Preserve the new failed tree and open a separate defect. Do not run `verify`, `rehearse`, or the installer again.

- [ ] **Step 4: Check eligibility read-only and bind evidence hashes**

```bash
ssh -tt "${SSH_OPTS[@]}" "$CONTROLLER" \
  'sudo /bin/bash -s' <<'REMOTE_BASH'
set -Eeuo pipefail
source /root/alt-or3p4-ssh-rollout.env

STATUS_JSON="$EVIDENCE/backup-rehearse-status.json"
/usr/local/sbin/alt-deploy-backup rehearse-status "$BACKUP_ID" >"$STATUS_JSON"
chmod 0600 "$STATUS_JSON"
cat "$STATUS_JSON"

BUNDLE="/var/backups/alt-deploy/$BACKUP_ID"
VERIFICATION_SHA256="$(sha256sum "$BUNDLE/verification.json" | awk '{print $1}')"
REHEARSAL_SHA256="$(sha256sum "$BUNDLE/rehearsal.json" | awk '{print $1}')"

python3 - "$BUNDLE/rehearsal.json" "$VERIFICATION_SHA256" <<'PY'
import json
import sys
from pathlib import Path

payload = json.loads(Path(sys.argv[1]).read_text())
assert payload["status"] == "ok"
assert payload["verification_sha256"] == sys.argv[2]
PY

{
    printf 'VERIFICATION_SHA256=%q\n' "$VERIFICATION_SHA256"
    printf 'REHEARSAL_SHA256=%q\n' "$REHEARSAL_SHA256"
} >>/root/alt-or3p4-ssh-rollout.env

printf 'VERIFICATION_SHA256=%s\n' "$VERIFICATION_SHA256"
printf 'REHEARSAL_SHA256=%s\n' "$REHEARSAL_SHA256"
echo FRESH_ROLLBACK_BUNDLE=PASS
REMOTE_BASH
```

Do not invoke public `verify` again after this step.

---

## Task 9: Capture Exact Pre-Install Preservation Evidence

- [ ] **Step 1: Inventory protected files and trees**

```bash
ssh -tt "${SSH_OPTS[@]}" "$CONTROLLER" \
  'sudo /bin/bash -s' <<'REMOTE_BASH'
set -Eeuo pipefail
source /root/alt-or3p4-ssh-rollout.env

python3 - "$EVIDENCE/pre-install-preservation.json" <<'PY'
import hashlib
import json
import os
import stat
import sys
from pathlib import Path

output = Path(sys.argv[1])
protected_files = (
    Path("/home/altserver/ansible/group_vars/vault.yml"),
    Path("/home/altserver/.ansible-vault-pass"),
    Path("/home/altserver/.ssh/id_ed25519"),
    Path("/srv/alt-deploy/bootstrap/ansible_authorized_keys"),
    Path("/srv/alt-deploy/metadata/autoinstall.scm"),
    Path("/srv/alt-deploy/metadata/vm-profile.scm"),
    Path("/srv/alt-deploy/metadata/pkg-groups.tar"),
    Path("/srv/alt-deploy/metadata/install-scripts.tar"),
)
protected_roots = (
    Path("/var/lib/alt-deploy/jobs"),
    Path("/var/lib/alt-deploy/assignments"),
    Path("/srv/alt-deploy/registration"),
)

def digest(path: Path) -> str:
    value = hashlib.sha256()
    with path.open("rb") as stream:
        while chunk := stream.read(1024 * 1024):
            value.update(chunk)
    return value.hexdigest()


def describe(path: Path, label: str) -> dict[str, object]:
    metadata = path.lstat()
    mode = stat.S_IMODE(metadata.st_mode)
    record: dict[str, object] = {
        "path": label,
        "uid": metadata.st_uid,
        "gid": metadata.st_gid,
        "mode": f"{mode:04o}",
    }
    if stat.S_ISREG(metadata.st_mode):
        record.update({
            "type": "regular",
            "size": metadata.st_size,
            "sha256": digest(path),
        })
    elif stat.S_ISDIR(metadata.st_mode):
        record["type"] = "directory"
    elif stat.S_ISLNK(metadata.st_mode):
        record.update({"type": "symlink", "target": os.readlink(path)})
    else:
        raise SystemExit(f"unexpected protected object: {path}")
    return record

records = []
for path in protected_files:
    records.append(describe(path, str(path)))

for root in protected_roots:
    records.append(describe(root, str(root)))
    for path in sorted(root.rglob("*")):
        records.append(describe(path, str(path)))

output.write_text(
    json.dumps(records, ensure_ascii=False, indent=2, sort_keys=True) + "\n",
    encoding="utf-8",
)
os.chmod(output, 0o600)
print(f"PRESERVATION_RECORD_COUNT={len(records)}")
PY

sha256sum "$EVIDENCE/pre-install-preservation.json"
REMOTE_BASH
```

This captures hashes and metadata, never file contents.

- [ ] **Step 2: Present the final mutation summary and wait for approval**

```text
Target: 192.168.100.17
Source: exact COMMIT in /root/alt-or3p4-ssh-rollout.env
Rollback: exact BACKUP_ID in the same file
Command: deploy/alt-linux/install-control-plane.sh --rollback-backup-id BACKUP_ID
Temporary maintenance stop: alt-deploy-process.path, alt-deploy-register.service, alt-deploy-http.service
Accepted workstation contacted: no
Failure boundary: alt-deploy-guard.service and the fresh OR-3P3 bundle
```

---

## Task 10: Install the Exact Control-Plane Generation

This is the principal production mutation and requires explicit approval.

- [ ] **Step 1: Run the public installer exactly once**

```bash
ssh -tt "${SSH_OPTS[@]}" "$CONTROLLER" \
  'sudo /bin/bash -s' <<'REMOTE_BASH'
set -uo pipefail
source /root/alt-or3p4-ssh-rollout.env

LOG="$EVIDENCE/install-control-plane.log"
set +e
bash "$WORKTREE/deploy/alt-linux/install-control-plane.sh" \
  --rollback-backup-id "$BACKUP_ID" \
  >"$LOG" 2>&1
INSTALL_RC=$?
set -e

chmod 0600 "$LOG"
cat "$LOG"
printf 'INSTALL_EXIT_CODE=%s\n' "$INSTALL_RC"

if (( INSTALL_RC != 0 )); then
    echo CONTROL_PLANE_INSTALL=FAILED
    exit "$INSTALL_RC"
fi

echo CONTROL_PLANE_INSTALL=PASS
REMOTE_BASH
```

Expected: exit `0` and `ALT deployment control plane installed successfully`.

On failure after maintenance:

1. do not manually start guarded services;
2. preserve the complete installer log and `/var/lib/alt-deploy-backup/rollout.json`;
3. inspect bounded backup audit records;
4. run `alt-deploy-backup restore "$BACKUP_ID"` only after explicit recovery approval;
5. if restore returns `restore_manual_recovery_required`, preserve the returned `RESTORE_ID`, correct only the external cause, and run `alt-deploy-backup recover "$RESTORE_ID"` once;
6. if recovery remains manual, stop and follow the OR-3P3 reviewed manual-recovery procedure.

---

## Task 11: Prove Readiness, Preservation, and Installed Source Identity

- [ ] **Step 1: Run installed public health checks**

```bash
ssh -tt "${SSH_OPTS[@]}" "$CONTROLLER" \
  'sudo /bin/bash -s' <<'REMOTE_BASH'
set -Eeuo pipefail
source /root/alt-or3p4-ssh-rollout.env

sudo -u altserver workstationctl --json jobs active \
  >"$EVIDENCE/jobs-active-after.json"
sudo -u altserver workstationctl --json controller readiness \
  >"$EVIDENCE/controller-readiness-after.json"
sudo -u altserver workstationctl --json vault check \
  >"$EVIDENCE/vault-check-after.json"
sudo -u altserver workstationctl --json controller permissions \
  >"$EVIDENCE/controller-permissions-after.json"

chmod 0600 "$EVIDENCE"/*-after.json

python3 - "$EVIDENCE" <<'PY'
import json
import sys
from pathlib import Path

root = Path(sys.argv[1])
jobs = json.loads((root / "jobs-active-after.json").read_text())
readiness = json.loads((root / "controller-readiness-after.json").read_text())
vault = json.loads((root / "vault-check-after.json").read_text())
permissions = json.loads((root / "controller-permissions-after.json").read_text())

assert jobs["status"] == "ok"
assert jobs["count"] == 0
assert readiness["status"] == "ok"
assert vault["status"] == "ok"
assert permissions["status"] == "ok"
print("POST_INSTALL_PUBLIC_HEALTH=PASS")
PY
REMOTE_BASH
```

- [ ] **Step 2: Verify exact unit states**

```bash
ssh -o BatchMode=yes "${SSH_OPTS[@]}" "$CONTROLLER" \
  'set -Eeuo pipefail
   test "$(systemctl is-active alt-deploy-http.service)" = active
   test "$(systemctl is-active alt-deploy-register.service)" = active
   test "$(systemctl is-active alt-deploy-process.path)" = active
   test "$(systemctl is-active alt-deploy-process.service || true)" = inactive
   test "$(systemctl is-enabled alt-deploy-http.service)" = enabled
   test "$(systemctl is-enabled alt-deploy-register.service)" = enabled
   test "$(systemctl is-enabled alt-deploy-process.path)" = enabled
   echo POST_INSTALL_UNITS=PASS'
```

- [ ] **Step 3: Rebuild the protected inventory and compare it byte-for-byte**

Use the same Python inventory algorithm from Task 9, writing to `$EVIDENCE/post-install-preservation.json`, then run:

```bash
ssh -tt "${SSH_OPTS[@]}" "$CONTROLLER" \
  'sudo /bin/bash -s' <<'REMOTE_BASH'
set -Eeuo pipefail
source /root/alt-or3p4-ssh-rollout.env

# Re-run the exact Task 9 inventory program with this output path:
#   $EVIDENCE/post-install-preservation.json
# Do not alter the protected_files or protected_roots lists.

test -f "$EVIDENCE/post-install-preservation.json"
cmp -s \
  "$EVIDENCE/pre-install-preservation.json" \
  "$EVIDENCE/post-install-preservation.json"

echo POST_INSTALL_PRESERVATION=PASS
REMOTE_BASH
```

The executor must paste the exact Task 9 Python block, changing only the output filename. This is not permission to replace the check with file counts.

- [ ] **Step 4: Compare every installed source file managed by the installer**

```bash
ssh -tt "${SSH_OPTS[@]}" "$CONTROLLER" \
  'sudo /bin/bash -s' <<'REMOTE_BASH'
set -Eeuo pipefail
source /root/alt-or3p4-ssh-rollout.env

python3 - "$WORKTREE" <<'PY'
import hashlib
import stat
import sys
from pathlib import Path

worktree = Path(sys.argv[1])
alt = worktree / "deploy" / "alt-linux"

pairs: list[tuple[Path, Path]] = []


def add_file(source: Path, target: Path) -> None:
    pairs.append((source, target))


def add_tree(source_root: Path, target_root: Path) -> None:
    for source in sorted(source_root.rglob("*")):
        if source.is_symlink():
            raise SystemExit(f"source symlink is not permitted: {source}")
        if source.is_file():
            add_file(source, target_root / source.relative_to(source_root))

add_tree(
    alt / "control" / "alt_deploy",
    Path("/opt/alt-deploy-control/alt_deploy"),
)
add_file(alt / "control" / "workstationctl", Path("/usr/local/sbin/workstationctl"))
add_file(alt / "control" / "alt-provision-worker", Path("/usr/local/libexec/alt-provision-worker"))
add_file(alt / "control" / "alt-job-stage", Path("/usr/local/libexec/alt-job-stage"))

for name in ("static_server.py", "register_api.py", "process_pending.py"):
    add_file(alt / "api" / name, Path("/opt/alt-deploy-api") / name)

for name in (
    "alt-deploy-http.service",
    "alt-deploy-register.service",
    "alt-deploy-process.path",
    "alt-deploy-process.service",
):
    add_file(alt / "systemd" / name, Path("/etc/systemd/system") / name)

for name in ("bootstrap.sh", "alt-bootstrap-register"):
    add_file(alt / "bootstrap" / name, Path("/srv/alt-deploy/bootstrap") / name)

add_file(alt / "ansible" / "ansible.cfg", Path("/home/altserver/ansible/ansible.cfg"))
add_file(alt / "ansible" / "group_vars" / "all.yml", Path("/home/altserver/ansible/group_vars/all.yml"))
add_tree(alt / "ansible" / "playbooks", Path("/home/altserver/ansible/playbooks"))
add_tree(alt / "ansible" / "roles", Path("/home/altserver/ansible/roles"))


def digest(path: Path) -> str:
    value = hashlib.sha256()
    with path.open("rb") as stream:
        while chunk := stream.read(1024 * 1024):
            value.update(chunk)
    return value.hexdigest()

for source, target in pairs:
    source_stat = source.lstat()
    target_stat = target.lstat()
    if not stat.S_ISREG(source_stat.st_mode) or not stat.S_ISREG(target_stat.st_mode):
        raise SystemExit(f"non-regular source mapping: {source} -> {target}")
    if digest(source) != digest(target):
        raise SystemExit(f"installed bytes differ: {source} -> {target}")

print(f"INSTALLED_SOURCE_FILE_COUNT={len(pairs)}")
print("INSTALLED_SOURCE_IDENTITY=PASS")
PY

test -z "$(git -C "$WORKTREE" status --porcelain)"
REMOTE_BASH
```

This hash mapping, not a non-existent repository marker, proves the installed source identity.

- [ ] **Step 5: Keep the fresh backup**

Do not delete the successful fresh bundle. It remains the approved rollback generation until the rollback window is explicitly closed after disposable-machine acceptance.

---

## Task 12: Clean Only the Old Failed Rehearsal Tree

Run this only after every Task 11 check passes. Preserve the old bundle and diagnostics.

- [ ] **Step 1: Revalidate the exact cleanup target**

```bash
ssh -tt "${SSH_OPTS[@]}" "$CONTROLLER" \
  'sudo /bin/bash -s' <<'REMOTE_BASH'
set -Eeuo pipefail
source /root/alt-or3p4-ssh-rollout.env

OLD_BACKUP_ID=backup-20260723T133400Z-2b5c8ee3
TARGET="/var/tmp/alt-deploy-restore-test/$OLD_BACKUP_ID"
DIAGNOSTICS=/root/or3p4-20260723T061042Z/post-hotfix-registration-diagnostics.json
EXPECTED_SHA=2ead9b49834bc96008e89c3262c7dbaea27b0776058180d5e18e1ac35eba7ae5

test -d "$TARGET"
test ! -L "$TARGET"
test "$(stat -c '%U:%G:%a' "$TARGET")" = root:root:700
test "$(sha256sum "$DIAGNOSTICS" | awk '{print $1}')" = "$EXPECTED_SHA"
test -f "/var/backups/alt-deploy/$OLD_BACKUP_ID/verification.json"
test ! -e "/var/backups/alt-deploy/$OLD_BACKUP_ID/rehearsal.json"

echo OLD_FAILED_TREE_CLEANUP_PRECHECK=PASS
REMOTE_BASH
```

- [ ] **Step 2: Use the installed safe cleanup implementation**

```bash
ssh -tt "${SSH_OPTS[@]}" "$CONTROLLER" \
  'sudo /bin/bash -s' <<'REMOTE_BASH'
set -Eeuo pipefail
source /root/alt-or3p4-ssh-rollout.env

TARGET=/var/tmp/alt-deploy-restore-test/backup-20260723T133400Z-2b5c8ee3

PYTHONPATH=/opt/alt-deploy-backup \
PYTHONDONTWRITEBYTECODE=1 \
python3 - "$TARGET" <<'PY'
from pathlib import Path
import sys

from alt_deploy_backup.rehearsal import RehearsalService
from alt_deploy_backup.repository import BackupRepository
from alt_deploy_backup.settings import BackupSettings

path = Path(sys.argv[1])
expected = Path(
    "/var/tmp/alt-deploy-restore-test/backup-20260723T133400Z-2b5c8ee3"
)
assert path == expected
service = RehearsalService(BackupRepository(BackupSettings.from_env()))
service._ensure_private_root()
service._remove_tree(path)
assert not path.exists()
print("OLD_FAILED_REHEARSAL_TREE_REMOVED=PASS")
PY

{
    printf 'removed_tree=%s\n' "$TARGET"
    printf 'removed_at=%s\n' "$(date -u --iso-8601=seconds)"
    printf 'old_bundle_preserved=yes\n'
} >"$EVIDENCE/old-failed-rehearsal-cleanup.txt"
chmod 0600 "$EVIDENCE/old-failed-rehearsal-cleanup.txt"
REMOTE_BASH
```

Do not delete the old backup bundle.

---

## Task 13: Accept One New Disposable ALT Workstation

- [ ] **Step 1: Require a genuinely disposable target**

The human operator confirms the target is a clean VM or physical machine and is not `192.168.101.111` or its UUID.

- [ ] **Step 2: Wait for automatic registration and inspect machines read-only**

```bash
ssh -o BatchMode=yes "${SSH_OPTS[@]}" "$CONTROLLER" \
  'sudo -u altserver workstationctl --json machines list'
```

- [ ] **Step 3: Capture and validate the selected UUID locally**

```bash
read -r -p 'Approved disposable machine UUID: ' TARGET_UUID
[[ "$TARGET_UUID" =~ ^[0-9a-fA-F-]{8,64}$ ]]
TARGET_UUID="${TARGET_UUID,,}"
test "$TARGET_UUID" != \
  'cc6f1a81-54b8-47c9-95de-2ac29ee4fbb7'
```

- [ ] **Step 4: Show the selected machine and run preflight**

```bash
ssh -o BatchMode=yes "${SSH_OPTS[@]}" "$CONTROLLER" \
  "set -Eeuo pipefail
   sudo -u altserver workstationctl --json machines show '$TARGET_UUID'
   sudo -u altserver workstationctl --json preflight '$TARGET_UUID'"
```

Required final machine status: `awaiting_assignment`.

- [ ] **Step 5: Collect the approved non-secret assignment fields locally**

```bash
read -r -p 'Employee login: ' EMPLOYEE_LOGIN
read -r -p 'Employee full name: ' EMPLOYEE_FULL_NAME
read -r -p 'Final hostname: ' FINAL_HOSTNAME

[[ "$EMPLOYEE_LOGIN" =~ ^[a-z0-9][a-z0-9_-]*[a-z0-9]$ ]]
[[ "$FINAL_HOSTNAME" =~ ^[a-z0-9][a-z0-9-]*[a-z0-9]$ ]]
test -n "$EMPLOYEE_FULL_NAME"
```

No password or password hash is part of the request.

- [ ] **Step 6: Create one private request readable by `altserver` and root**

```bash
REQUEST_JSON="$(
  TARGET_UUID="$TARGET_UUID" \
  EMPLOYEE_LOGIN="$EMPLOYEE_LOGIN" \
  EMPLOYEE_FULL_NAME="$EMPLOYEE_FULL_NAME" \
  FINAL_HOSTNAME="$FINAL_HOSTNAME" \
  python3 - <<'PY'
import json
import os

print(json.dumps({
    "machine_uuid": os.environ["TARGET_UUID"],
    "employee_login": os.environ["EMPLOYEE_LOGIN"],
    "employee_full_name": os.environ["EMPLOYEE_FULL_NAME"],
    "final_hostname": os.environ["FINAL_HOSTNAME"],
    "profile": "standard",
}, ensure_ascii=False, sort_keys=True))
PY
)"

REQUEST_B64="$(printf '%s' "$REQUEST_JSON" | base64 -w0)"
REMOTE_REQUEST="/home/altserver/.local/state/alt-deploy/requests/or3p4-$TARGET_UUID.json"

ssh -tt "${SSH_OPTS[@]}" "$CONTROLLER" \
  "sudo /bin/bash -c '
    set -Eeuo pipefail
    REQUEST_DIR=/home/altserver/.local/state/alt-deploy/requests
    REQUEST='$REMOTE_REQUEST'
    install -d -o altserver -g altserver -m 0700 \"\$REQUEST_DIR\"
    test ! -e \"\$REQUEST\"
    printf %s '$REQUEST_B64' | base64 -d >\"\$REQUEST\"
    chown altserver:altserver \"\$REQUEST\"
    chmod 0600 \"\$REQUEST\"
    sudo -u altserver python3 -m json.tool \"\$REQUEST\" >/dev/null
    echo REQUEST_FILE_READY=PASS
  '"
```

The file contains no password and is readable only by `altserver` and root.

- [ ] **Step 7: Run preview and review every returned field**

```bash
ssh -tt "${SSH_OPTS[@]}" "$CONTROLLER" \
  "sudo -u altserver workstationctl --json provision preview '$TARGET_UUID' \
     --vars-file '$REMOTE_REQUEST'"
```

Do not continue until the human operator approves UUID, login, full name, final hostname, profile, and the previewed actions.

- [ ] **Step 8: Start provisioning once**

```bash
ssh -tt "${SSH_OPTS[@]}" "$CONTROLLER" \
  "sudo workstationctl --json provision start '$TARGET_UUID' \
     --vars-file '$REMOTE_REQUEST'"
```

Record the returned `JOB_ID`.

- [ ] **Step 9: Monitor structured status and bounded logs**

```bash
ssh -o BatchMode=yes "${SSH_OPTS[@]}" "$CONTROLLER" \
  "sudo -u altserver workstationctl --json jobs status '$JOB_ID'"

ssh -o BatchMode=yes "${SSH_OPTS[@]}" "$CONTROLLER" \
  "sudo -u altserver workstationctl --json jobs log '$JOB_ID'"
```

Required final result:

```text
state=successful
stage=complete
complete ten-stage monotonic stage_history
assignment created only after final verification
```

- [ ] **Step 10: Perform reboot and visual acceptance**

The human operator verifies on the disposable target:

- LightDM active;
- technical `ansible` account hidden;
- employee account visible;
- graphical KDE Plasma login succeeds;
- employee has no sudo/wheel privilege;
- final hostname is correct.

- [ ] **Step 11: Verify assignment and repeat protection**

Run `machines show`, `jobs status`, and the approved assignment checks. Confirm that repeat provisioning is rejected with `machine_already_assigned`. Do not remove the assignment to test this.

- [ ] **Step 12: Remove only the non-secret request file**

```bash
ssh -tt "${SSH_OPTS[@]}" "$CONTROLLER" \
  "sudo rm -f -- '$REMOTE_REQUEST'"
```

Do not delete the job or assignment.

---

## Task 14: Write and Merge the Sanitized Rollout Closure

**Files:**

- Create `docs/verification/ALT_OR3P4_SSH_CONTROLLER_ROLLOUT_2026-07-24.md`.
- Modify `docs/ALT_WORKSTATION_PROVISIONING_CONTEXT.md`.
- Modify `docs/ALT_WORKSTATION_PROVISIONING_NEXT_STEPS.md`.

- [ ] **Step 1: Create the closure document locally**

Include only sanitized evidence:

```text
controller: 192.168.100.17
execution model: local Codex plus ordinary OpenSSH
server-side Codex installation: none
exact issue-30 and portability PRs
exact installed rollout merge SHA
local, CI, and controller test results
fresh backup ID and manifest SHA-256
verification/rehearsal evidence binding result
installer exit result
post-install readiness result
unit states
protected-state preservation result
installed source-file hash comparison result
old failed rehearsal tree cleanup result
new disposable target acceptance result
repeat-provision rejection result
rollback-bundle retention decision
```

Exclude passwords, password hashes, private keys, Vault contents, secret identities, private job-log content, and unnecessary employee data.

- [ ] **Step 2: Update the authoritative context**

Mark OR-3P4 complete only if Tasks 10 through 13 succeeded. Keep `.17` as controller and `.30` as the future thin UI/API consumer.

- [ ] **Step 3: Update next steps**

The next project is a separate design and plan for:

```text
constrained read-only controller API on 192.168.100.17
allowlisted access from 192.168.100.30
web_ovpn ALT device source
UUID-first correlation with MAC, IP, and hostname evidence
later separately approved preview/start operations
```

Do not implement the API or web integration in this rollout plan.

- [ ] **Step 4: Verify and publish closure docs**

```bash
git diff --check
PYTHONDONTWRITEBYTECODE=1 "$PYTHON_BIN" -m pytest -q tests/alt_linux
PYTHONDONTWRITEBYTECODE=1 "$PYTHON_BIN" -m pytest -q

git add -- \
  docs/verification/ALT_OR3P4_SSH_CONTROLLER_ROLLOUT_2026-07-24.md \
  docs/ALT_WORKSTATION_PROVISIONING_CONTEXT.md \
  docs/ALT_WORKSTATION_PROVISIONING_NEXT_STEPS.md

git commit -m \
  "docs: record ALT OR-3P4 SSH controller rollout"
git push -u origin HEAD
```

Open a documentation PR, inspect fresh CI, and merge only after explicit approval.

---

## Failure and Recovery Matrix

### Failure before backup-tool installation

- No control-plane runtime mutation has occurred.
- Preserve logs and correct the source, SSH, or test issue in a reviewed PR.

### Failure during backup creation

- Preserve command JSON and `/var/log/alt-deploy-backup.log`.
- Confirm prior service states were restored.
- Do not run OR-3P4.

### Failure during rehearsal

- Preserve `/var/tmp/alt-deploy-restore-test/$BACKUP_ID`.
- Preserve the bundle and its `verification.json`.
- Do not rerun `verify` or `rehearse` until a reviewed fix is installed and the failed tree is explicitly handled.

### Installer failure before maintenance

- Verify no managed runtime path changed.
- Preserve the installer log and current service states.

### Installer failure after maintenance or activation

- Do not manually start guarded services.
- Preserve rollout state, guard evidence, installer output, and backup audit records.
- Use only the exact fresh `$BACKUP_ID` for reviewed restore.

### Restore returns `restore_manual_recovery_required`

- Preserve the returned `$RESTORE_ID`.
- Leave maintenance services stopped.
- Do not delete journals, permits, rollback siblings, pre-restore generations, or rollout state.
- Correct only the external cause and run `alt-deploy-backup recover "$RESTORE_ID"` once.
- If recovery remains manual, stop and perform reviewed recovery from the recorded pre-restore generation.

---

## Codex Handoff Prompt

```text
Execute docs/superpowers/plans/2026-07-24-alt-or3p4-local-codex-ssh-execution.md task by task.

Work in the local web_ovpn repository. Use a POSIX shell, preferably WSL2 on Windows. Do not install Codex, Codex CLI, an agent, or OpenAI credentials on 192.168.100.17. Use ordinary local ssh commands to altserver@192.168.100.17. Do not deploy source with scp, rsync, tar, or editor synchronization. Push reviewed commits to GitHub, merge them, and make the controller fetch the exact merge SHA into a detached worktree.

The issue-30 commits currently live in the controller worktree and must first be verified and pushed to GitHub through SSH, then fetched locally. Before every remote mutation, show the target, exact command, mutated paths, expected effect, rollback boundary, and stop conditions, then wait for my explicit approval. I will type sudo and SSH-key passphrases directly.

Never print or store passwords, Vault data, password hashes, private keys, or secret contents. Keep 192.168.101.111 and UUID cc6f1a81-54b8-47c9-95de-2ac29ee4fbb7 immutable. Do not install the control plane until issue #30 and the controller test-portability PR are merged, the exact controller ALT suite passes with exit 0, quiescence is healthy, and one fresh exact backup has been created, verified, rehearsed, and checked read-only.

Use TDD, clean worktrees, exact commit SHAs, GitHub CI, root-only evidence, and one remote mutation at a time. Stop on any unexpected output, dirty worktree, active job, pending registration, failed rehearsal, guard block, preservation mismatch, or readiness failure.
```

---

## Self-Review

- [x] Local development and controller execution are separated.
- [x] Existing issue-30 commits are correctly transferred from the controller through GitHub before local work continues.
- [x] No Codex or deployment CLI is installed on the controller.
- [x] Source deployment is bound to exact reviewed Git commits.
- [x] The ten controller-only test-harness failures are fixed before installer execution.
- [x] The full ALT suite must pass on the real `altserver` environment.
- [x] OR-3P3 exact-ID, verification, rehearsal, evidence-binding, guard, and recovery rules are preserved.
- [x] Protected controller state is compared by complete path, metadata, size, and SHA-256 inventory rather than file counts.
- [x] Installed source identity is proven by source-to-destination hash mapping rather than an assumed commit marker.
- [x] The disposable provision request is readable by `altserver` and root without weakening secret paths.
- [x] The accepted reference workstation remains immutable.
- [x] Human approval is required before every privileged mutation.
- [x] Failure and recovery paths use concrete shell variables, not unresolved placeholders.
- [x] Web integration remains a separate future design and implementation plan.
