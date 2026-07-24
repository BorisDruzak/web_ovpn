# ALT OR-3P4 Local Codex SSH Controller Rollout Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Finish the known ALT controller blockers, verify the exact reviewed generation, and deploy it to `192.168.100.17` from a local Codex session that executes ordinary OpenSSH commands without installing Codex, Codex CLI, or any agent runtime on the controller.

**Architecture:** Development, Git operations, review, and GitHub CI happen in the local repository. GitHub commit identity is the source-transfer boundary: after merge, the controller fetches the exact merge commit and checks it out in a detached worktree under `/home/altserver/web_ovpn-src/.worktrees/`; no uncommitted local tree is copied to production. Codex invokes `ssh` from the local terminal for read-only checks and explicitly approved mutations; root operations use remote `sudo`, evidence is written under a new root-only rollout directory, and the existing OR-3P3 backup/guard boundary remains authoritative.

**Tech Stack:** Local Codex app or IDE integration, local Git worktrees, OpenSSH client, GitHub connector/browser, Python 3.12, pytest, Bash, systemd, Ansible, the existing `alt-deploy-backup` utility, and the existing `install-control-plane.sh` installer.

## Global Constraints

- Codex runs only on the operator workstation. Do not install Codex, Codex CLI, an agent daemon, or an OpenAI credential on `192.168.100.17`.
- All controller access is through local OpenSSH commands to `altserver@192.168.100.17`.
- Do not use a Codex Remote SSH project for this rollout; the local repository remains the development workspace and `ssh` is an execution transport only.
- Do not copy a local source directory to the controller with `scp`, `rsync`, tar archives, or editor synchronization. The controller must fetch and check out an exact merged Git commit.
- Do not edit tracked source files directly on the controller. Controller worktrees are verification and deployment checkouts only.
- Use `StrictHostKeyChecking=yes`, disable agent forwarding, and never accept a new host key without an out-of-band fingerprint comparison.
- Never place an SSH passphrase, sudo password, Vault password, employee password, password hash, private key, or decrypted Vault data in a command, environment variable, prompt, log, plan, Git commit, or GitHub comment.
- A human operator must approve every remote mutating phase and type any interactive sudo or SSH-key passphrase directly into the terminal.
- The controller remains `192.168.100.17`; the OpenVPN/web host `192.168.100.30` is outside this plan and must not receive controller Vault or SSH private-key material.
- Do not contact, modify, reboot, re-register, archive, release, or reprovision the accepted reference workstation `192.168.101.111` / `cc6f1a81-54b8-47c9-95de-2ac29ee4fbb7`.
- Do not start installation while any provision job is `queued` or `running`, a pending registration exists, the registration processor is active, Vault or controller permissions are unhealthy, or a rollout/restore transaction is non-terminal.
- Do not delete or rewrite jobs, assignments, registrations, Vault files, SSH identity, ISO metadata, backup bundles, or restore journals manually.
- Every development change uses TDD, a focused test, the complete affected module, the complete ALT suite, GitHub CI, and a clean worktree before merge.
- Every deployment uses one exact merged commit and one exact newly created, verified, rehearsed backup ID. Never select the newest backup implicitly.
- Do not run public `verify` after a successful rehearsal; rehearsal evidence is bound to the exact `verification.json` bytes.
- A failed rehearsal preserves its private extracted tree for diagnosis. Do not rerun it until the root cause is fixed and the failed tree has been explicitly reviewed.
- A failed post-mutation rollout leaves the guard authoritative. Do not manually start ALT services around `alt-deploy-guard.service`.
- A real restore is reserved for a failed guarded rollout or a separately approved recovery exercise; it is not part of the normal pre-rollout proof.
- Execute one remote mutation at a time. Read and record the complete exit status before continuing.
- Merge remains prohibited until explicit human approval after fresh CI and review.

---

## Current Starting State

The executor must verify rather than assume this state:

- Issue `#30` records the rehearsal defect that incorrectly equates registration directory state with machine business status.
- Local TDD commits already exist:
  - RED: `3b386b63fd67281f56507de1d76b65326d35e791`;
  - GREEN: `796cda2395c7af2a011f44e12096c76092ac69fe`.
- The GREEN commit changes only:
  - `deploy/alt-linux/backup/alt_deploy_backup/state_validation.py`;
  - `tests/alt_linux/test_or3p3_backup_rehearsal.py`.
- The post-commit rehearsal module result is `7 passed`.
- Controller-local full ALT testing currently exposes ten pre-existing test-harness failures:
  - one merged-`/usr` dependency-isolation failure in `test_install_assets.py`;
  - nine `pw_name` fixture failures in `test_machine_archive_service.py`.
- Those same ten failures reproduce on the unchanged base commit and therefore are not caused by issue `#30`, but they still block the real installer because `install-control-plane.sh` runs `tests/alt_linux` before mutation.
- The current failed backup rehearsal is associated with `backup-20260723T133400Z-2b5c8ee3`.
- Its bounded registration diagnostics are stored at `/root/or3p4-20260723T061042Z/post-hotfix-registration-diagnostics.json` with SHA-256 `2ead9b49834bc96008e89c3262c7dbaea27b0776058180d5e18e1ac35eba7ae5`.
- The corresponding failed rehearsal tree should still exist at `/var/tmp/alt-deploy-restore-test/backup-20260723T133400Z-2b5c8ee3` and `rehearsal.json` should be absent from the bundle.
- The controller repository root is `/home/altserver/web_ovpn-src`.

Any mismatch is a stop condition requiring a fresh read-only audit before this plan is adapted.

---

## Planned File Structure

### Existing issue #30 change

- Modify: `deploy/alt-linux/backup/alt_deploy_backup/state_validation.py` — stop treating payload `status` as the registration directory state.
- Modify: `tests/alt_linux/test_or3p3_backup_rehearsal.py` — prove `status=awaiting_assignment` is valid in an active registration directory.

### Controller test-harness portability change

- Modify: `tests/alt_linux/conftest.py` — provide the complete `pw_name` field in the portable `altserver` account fixture.
- Modify: `tests/alt_linux/support/installer_sandbox.py` — invoke the test shell through absolute `/bin/bash` and provide a fake `bash` command inside the isolated dependency PATH.
- Modify: `tests/alt_linux/test_install_assets.py` — isolate dependency discovery with `PATH` equal to the sandbox fake-bin directory instead of appending `/bin`, which aliases `/usr/bin` on ALT.

### Rollout closure documentation

- Create after successful rollout: `docs/verification/ALT_OR3P4_SSH_CONTROLLER_ROLLOUT_2026-07-24.md` — sanitized commit, backup, test, readiness, service, preservation, and acceptance evidence.
- Modify after successful rollout: `docs/ALT_WORKSTATION_PROVISIONING_CONTEXT.md` — record the installed controller generation and completed OR-3P4 gate.
- Modify after successful rollout: `docs/ALT_WORKSTATION_PROVISIONING_NEXT_STEPS.md` — move the next work to disposable-machine acceptance and the later constrained API integration.

No SSH wrapper, custom deployment CLI, persistent local credential file, controller agent, or server-side Codex installation is added.

---

## Execution Gates

| Gate | Required result | On failure |
| --- | --- | --- |
| Local source | clean worktree; expected commits and files | stop and reconcile Git state |
| GitHub review | focused and full CI successful | do not merge |
| SSH identity | pinned host key; `altserver`; expected controller | stop; verify out of band |
| Remote repository tests | complete `tests/alt_linux` exit `0` | do not install backup tool or control plane |
| Controller quiescence | zero active jobs, no pending records, processor inactive | wait or resolve operational state |
| OR-3P3 backup | new exact ID; verify and rehearsal successful | preserve evidence; do not install |
| OR-3P4 installer | exit `0`; readiness successful | keep guard; follow incident/restore path |
| Post-install | readiness healthy; state preserved | no provisioning; investigate or restore |
| Disposable acceptance | new UUID; successful complete job; visual login | no pilot expansion |

---

### Task 1: Establish the Local Codex and SSH Execution Contract

**Files:**
- Modify: none.

**Interfaces:**
- Produces: `LOCAL_REPO`, the local repository root.
- Produces: `CONTROLLER=altserver@192.168.100.17`.
- Produces: a verified SSH transport with strict host-key checking and no agent forwarding.

- [ ] **Step 1: Verify the local project root and clean main checkout**

Run locally from the Codex project:

```bash
set -Eeuo pipefail

LOCAL_REPO="$(git rev-parse --show-toplevel)"
cd "$LOCAL_REPO"

printf 'LOCAL_REPO=%s\n' "$LOCAL_REPO"
printf 'CURRENT_BRANCH=%s\n' "$(git branch --show-current)"
printf 'CURRENT_HEAD=%s\n' "$(git rev-parse HEAD)"
git status --short
```

Expected: `LOCAL_REPO` is the `web_ovpn` clone. Do not continue from a repository with unrelated uncommitted changes.

- [ ] **Step 2: Verify the local SSH client and loaded key identities**

```bash
command -v ssh
command -v ssh-keygen
ssh -V
ssh-add -l
```

Expected: at least one approved local identity is loaded into the SSH agent. If no identity is loaded, the human operator runs `ssh-add` interactively; Codex must not request or record the passphrase.

- [ ] **Step 3: Inspect effective SSH configuration without connecting**

```bash
CONTROLLER='altserver@192.168.100.17'

ssh -G "$CONTROLLER" |
  awk '$1 ~ /^(hostname|user|port|identityfile|forwardagent|stricthostkeychecking|userknownhostsfile)$/ {print}'
```

Required values:

```text
hostname 192.168.100.17
user altserver
forwardagent no
```

`stricthostkeychecking` must not be `no` or `accept-new` for the rollout command set.

- [ ] **Step 4: Verify the pinned host key**

```bash
ssh-keygen -F 192.168.100.17
```

If no entry exists, stop. The human operator must obtain the controller ED25519 host-key fingerprint from the controller console or another already trusted channel using:

```bash
sudo ssh-keygen -lf /etc/ssh/ssh_host_ed25519_key.pub
```

Only after comparing that fingerprint may the operator add the scanned public key to the selected `known_hosts` file. `ssh-keyscan` output alone is not proof of identity.

- [ ] **Step 5: Run a strict read-only connection test**

```bash
ssh \
  -o BatchMode=yes \
  -o StrictHostKeyChecking=yes \
  -o ForwardAgent=no \
  -o ClearAllForwardings=yes \
  -o ConnectTimeout=10 \
  "$CONTROLLER" \
  'set -Eeuo pipefail
   printf "REMOTE_USER=%s\n" "$(id -un)"
   printf "REMOTE_UID=%s\n" "$(id -u)"
   printf "REMOTE_HOSTNAME=%s\n" "$(hostname -f)"
   printf "REMOTE_KERNEL=%s\n" "$(uname -r)"'
```

Expected: `REMOTE_USER=altserver`, `REMOTE_UID=1000`, and the host identity matches the known controller, currently `sosn.alt.adm`. A different hostname requires explicit human confirmation before continuing.

- [ ] **Step 6: Establish an interactive sudo approval session**

```bash
ssh \
  -tt \
  -o StrictHostKeyChecking=yes \
  -o ForwardAgent=no \
  -o ClearAllForwardings=yes \
  "$CONTROLLER" \
  'sudo -v && sudo -n true && echo REMOTE_SUDO_READY=PASS'
```

The human operator types the sudo password directly if prompted. Do not store it. Expected: `REMOTE_SUDO_READY=PASS`.

- [ ] **Step 7: Record the transport decision**

The Codex task log must state:

```text
Execution model: local repository and local Codex
Remote transport: OpenSSH to altserver@192.168.100.17
Server-side Codex/CLI installation: prohibited
Source transfer: exact GitHub merge commit only
Agent forwarding: disabled
```

No commit is created for this task.

---

### Task 2: Verify and Publish the Existing Issue #30 TDD Branch

**Files:**
- Existing modified file: `deploy/alt-linux/backup/alt_deploy_backup/state_validation.py`.
- Existing modified file: `tests/alt_linux/test_or3p3_backup_rehearsal.py`.

**Interfaces:**
- Consumes: local commits `3b386b63fd67281f56507de1d76b65326d35e791` and `796cda2395c7af2a011f44e12096c76092ac69fe`.
- Produces: remote branch `fix/or3p3-registration-status-contract-20260724`.
- Produces: an open PR linked to issue `#30`.

- [ ] **Step 1: Locate the existing local worktree by branch name**

```bash
cd "$LOCAL_REPO"

HOTFIX_BRANCH='work/or3p3-registration-status-contract-20260723'
HOTFIX_WORKTREE="$({
  git worktree list --porcelain
} | awk -v branch="refs/heads/$HOTFIX_BRANCH" '
  $1 == "worktree" { path = $2 }
  $1 == "branch" && $2 == branch { print path }
')"

test -n "$HOTFIX_WORKTREE"
test -d "$HOTFIX_WORKTREE"
printf 'HOTFIX_WORKTREE=%s\n' "$HOTFIX_WORKTREE"
```

- [ ] **Step 2: Verify exact commit history and clean state**

```bash
RED_COMMIT='3b386b63fd67281f56507de1d76b65326d35e791'
GREEN_COMMIT='796cda2395c7af2a011f44e12096c76092ac69fe'
BASE_COMMIT='b0ae92c62406eacc5b2c1ed638d2396ff89f0b56'

cd "$HOTFIX_WORKTREE"

test "$(git rev-parse HEAD)" = "$GREEN_COMMIT"
test "$(git rev-parse HEAD^)" = "$RED_COMMIT"
test "$(git rev-parse HEAD^^)" = "$BASE_COMMIT"
test -z "$(git status --porcelain)"

git diff --check "$BASE_COMMIT..$GREEN_COMMIT"

git diff --name-only "$BASE_COMMIT..$GREEN_COMMIT" | sort
```

Expected files, and no others:

```text
deploy/alt-linux/backup/alt_deploy_backup/state_validation.py
tests/alt_linux/test_or3p3_backup_rehearsal.py
```

- [ ] **Step 3: Run fresh local focused and module verification**

```bash
PYTHONDONTWRITEBYTECODE=1 python3 -m pytest -q \
  tests/alt_linux/test_or3p3_backup_rehearsal.py::test_rehearsal_accepts_machine_status_distinct_from_registration_state

PYTHONDONTWRITEBYTECODE=1 python3 -m pytest -q \
  tests/alt_linux/test_or3p3_backup_rehearsal.py
```

Expected: focused `1 passed`; module `7 passed`; both exit `0`.

- [ ] **Step 4: Verify the RED commit independently**

```bash
RED_VERIFY_DIR="$(mktemp -d)"
trap 'rm -rf "$RED_VERIFY_DIR"' EXIT

git worktree add --detach "$RED_VERIFY_DIR/worktree" "$RED_COMMIT"

set +e
(
  cd "$RED_VERIFY_DIR/worktree"
  PYTHONDONTWRITEBYTECODE=1 python3 -m pytest -q \
    tests/alt_linux/test_or3p3_backup_rehearsal.py::test_rehearsal_accepts_machine_status_distinct_from_registration_state
)
RED_RC=$?
set -e

test "$RED_RC" -eq 1
git worktree remove "$RED_VERIFY_DIR/worktree"
trap - EXIT
rm -rf "$RED_VERIFY_DIR"
```

Expected failure: `Registration identity or generation is invalid`.

- [ ] **Step 5: Push the exact local history to a review branch**

```bash
REMOTE_BRANCH='fix/or3p3-registration-status-contract-20260724'

git push origin \
  "$GREEN_COMMIT:refs/heads/$REMOTE_BRANCH"

git fetch origin "$REMOTE_BRANCH"
test "$(git rev-parse "origin/$REMOTE_BRANCH")" = "$GREEN_COMMIT"
```

The operator may type the local Git SSH-key passphrase interactively. Do not place it in an environment variable.

- [ ] **Step 6: Open the PR through the GitHub connector or browser**

Use exact metadata:

```text
Title: fix: decouple machine status from registration state in rehearsal
Base: main
Head: fix/or3p3-registration-status-contract-20260724
Issue: Fixes #30
```

The body must include:

- the two controller records that reproduced the defect;
- RED and GREEN commit SHAs;
- focused and module results;
- the controller diagnostic file path and SHA-256;
- the rule that no live registration file was modified;
- the rule that OR-3P4 remains blocked until the controller suite is portable and a fresh backup rehearses successfully.

Do not merge in this task.

---

### Task 3: Review, Verify, and Merge Issue #30

**Files:**
- Modify: none beyond the PR branch.

**Interfaces:**
- Produces: `REGISTRATION_STATUS_PR_NUMBER`.
- Produces: `REGISTRATION_STATUS_MERGE_SHA`.

- [ ] **Step 1: Verify the PR file scope**

Through the GitHub connector, confirm the changed-file list is exactly:

```text
deploy/alt-linux/backup/alt_deploy_backup/state_validation.py
tests/alt_linux/test_or3p3_backup_rehearsal.py
```

- [ ] **Step 2: Inspect the production diff**

Required production change:

```python
# Remove only the extraction and equality check for payload status.
# Retain identity, filename binding, regular-file, bounded JSON,
# duplicate-key, and registration_id validation.
```

Reject any unrelated refactor, runtime behavior change, fixture weakening, or controller-state migration.

- [ ] **Step 3: Wait for all GitHub checks**

Required:

```text
focused workflow: success
context/full-regression workflow: success
runtime/full-regression workflow: success
```

Read job output or artifacts rather than relying only on the aggregate badge.

- [ ] **Step 4: Merge only after explicit human approval**

Use the repository’s normal merge-commit strategy. Record the returned merge SHA as `REGISTRATION_STATUS_MERGE_SHA`.

- [ ] **Step 5: Verify the merge commit is reachable from `main`**

```bash
cd "$LOCAL_REPO"
git fetch --prune origin main

git merge-base --is-ancestor \
  "$REGISTRATION_STATUS_MERGE_SHA" \
  origin/main
```

Expected exit `0`.

---

### Task 4: Reproduce the Ten Controller-Only Test-Harness Failures Through SSH

**Files:**
- Modify: none.

**Interfaces:**
- Consumes: `REGISTRATION_STATUS_MERGE_SHA`.
- Produces: root-owned baseline evidence for the ten controller failures.
- Produces: a detached remote baseline worktree.

- [ ] **Step 1: Create a detached controller worktree at the issue #30 merge**

Run locally through SSH:

```bash
ssh -tt \
  -o StrictHostKeyChecking=yes \
  -o ForwardAgent=no \
  -o ClearAllForwardings=yes \
  "$CONTROLLER" \
  "set -Eeuo pipefail
   REPO=/home/altserver/web_ovpn-src
   WORKTREE=\"\$REPO/.worktrees/or3p4-portability-red\"
   COMMIT='$REGISTRATION_STATUS_MERGE_SHA'

   test ! -e \"\$WORKTREE\"
   git -C \"\$REPO\" fetch --prune origin main
   git -C \"\$REPO\" cat-file -e \"\${COMMIT}^{commit}\"
   git -C \"\$REPO\" worktree add --detach \"\$WORKTREE\" \"\$COMMIT\"
   test \"\$(git -C \"\$WORKTREE\" rev-parse HEAD)\" = \"\$COMMIT\"
   test -z \"\$(git -C \"\$WORKTREE\" status --porcelain)\"
   echo PORTABILITY_RED_WORKTREE=PASS"
```

The remote GitHub SSH-key passphrase may require the human operator.

- [ ] **Step 2: Create a bounded baseline evidence directory**

```bash
ssh -tt \
  -o StrictHostKeyChecking=yes \
  -o ForwardAgent=no \
  -o ClearAllForwardings=yes \
  "$CONTROLLER" \
  'sudo /bin/bash -c '\''
    set -Eeuo pipefail
    EVIDENCE=/root/alt-or3p4-ssh-portability-red-20260724
    test ! -e "$EVIDENCE"
    install -d -o root -g root -m 0700 "$EVIDENCE"
    printf "EVIDENCE=%s\n" "$EVIDENCE"
  '\'''
```

- [ ] **Step 3: Run the exact ten failing tests as the real `altserver` user**

```bash
ssh \
  -o BatchMode=yes \
  -o StrictHostKeyChecking=yes \
  -o ForwardAgent=no \
  -o ClearAllForwardings=yes \
  "$CONTROLLER" \
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

Expected exit `1`, one `assert 0 != 0`, and nine `SimpleNamespace` errors for missing `pw_name`.

- [ ] **Step 4: Preserve the baseline log without exposing secrets**

```bash
ssh -tt \
  -o StrictHostKeyChecking=yes \
  -o ForwardAgent=no \
  -o ClearAllForwardings=yes \
  "$CONTROLLER" \
  'sudo /bin/bash -c '\''
    set -Eeuo pipefail
    SRC=/tmp/or3p4-portability-red.log
    DST=/root/alt-or3p4-ssh-portability-red-20260724/failures.log
    test -f "$SRC"
    install -o root -g root -m 0600 "$SRC" "$DST"
    sha256sum "$DST"
  '\'''
```

No controller runtime or production state is changed by this task.

---

### Task 5: Make the ALT Test Harness Portable on the Real Controller

**Files:**
- Modify: `tests/alt_linux/conftest.py`.
- Modify: `tests/alt_linux/support/installer_sandbox.py`.
- Modify: `tests/alt_linux/test_install_assets.py`.

**Interfaces:**
- Consumes: fresh RED evidence from Task 4.
- Produces: local branch `fix/alt-controller-test-harness-portability-20260724`.
- Produces: a controller-side GREEN test result with no production mutation.

- [ ] **Step 1: Create an isolated local worktree from the issue #30 merge**

```bash
cd "$LOCAL_REPO"

PORTABILITY_BRANCH='fix/alt-controller-test-harness-portability-20260724'
PORTABILITY_WORKTREE="$LOCAL_REPO/.worktrees/alt-controller-test-portability"

test ! -e "$PORTABILITY_WORKTREE"
git show-ref --verify --quiet "refs/heads/$PORTABILITY_BRANCH" && exit 20 || true

git worktree add \
  -b "$PORTABILITY_BRANCH" \
  "$PORTABILITY_WORKTREE" \
  "$REGISTRATION_STATUS_MERGE_SHA"

cd "$PORTABILITY_WORKTREE"
test -z "$(git status --porcelain)"
```

- [ ] **Step 2: Add the missing account-name field**

Change the `altserver` fixture in `tests/alt_linux/conftest.py` from:

```python
return types.SimpleNamespace(
    pw_uid=os.getuid(),
    pw_gid=os.getgid(),
)
```

to:

```python
return types.SimpleNamespace(
    pw_name="altserver",
    pw_uid=os.getuid(),
    pw_gid=os.getgid(),
)
```

This is a test-fixture correction. Do not change `resolve_operator_identity()` production behavior.

- [ ] **Step 3: Make the installer sandbox independent of the environment PATH**

In `tests/alt_linux/support/installer_sandbox.py`, change the shell process invocation from:

```python
["bash", "-c", command]
```

to:

```python
["/bin/bash", "-c", command]
```

Add a fake `bash` command alongside the other required fake commands:

```python
self._fake_script(
    "bash",
    'exec /bin/bash "$@"\n',
)
```

The absolute runner allows the test process to start even when the child `PATH` contains only the sandbox. The fake command satisfies the installer’s explicit `command -v bash` dependency check.

- [ ] **Step 4: Isolate the missing-dependency test from merged `/usr`**

In `tests/alt_linux/test_install_assets.py`, replace:

```python
completed = sandbox.run_library(
    PATH=f"{sandbox.fake_bin}:/bin",
)
```

with:

```python
completed = sandbox.run_library(
    PATH=str(sandbox.fake_bin),
)
```

This prevents a real `/bin/ansible-vault` from leaking into the synthetic test on systems where `/bin` resolves to `/usr/bin`.

- [ ] **Step 5: Run local focused tests**

```bash
cd "$PORTABILITY_WORKTREE"

git diff --check

PYTHONDONTWRITEBYTECODE=1 python3 -m pytest -q \
  tests/alt_linux/test_install_assets.py::test_missing_dependency_is_reported_before_runtime_mutation \
  tests/alt_linux/test_machine_archive_service.py
```

Expected: all selected tests pass.

- [ ] **Step 6: Commit the minimal test-harness change**

```bash
git add -- \
  tests/alt_linux/conftest.py \
  tests/alt_linux/support/installer_sandbox.py \
  tests/alt_linux/test_install_assets.py

git diff --cached --check

git commit -m \
  "test: make ALT installer harness portable on controller"

PORTABILITY_COMMIT="$(git rev-parse HEAD)"
printf 'PORTABILITY_COMMIT=%s\n' "$PORTABILITY_COMMIT"
test -z "$(git status --porcelain)"
```

- [ ] **Step 7: Push the branch and fetch it into a new detached controller worktree**

```bash
git push -u origin "$PORTABILITY_BRANCH"
```

Then through SSH:

```bash
ssh -tt \
  -o StrictHostKeyChecking=yes \
  -o ForwardAgent=no \
  -o ClearAllForwardings=yes \
  "$CONTROLLER" \
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

- [ ] **Step 8: Run the exact ten tests on the controller and observe GREEN**

```bash
ssh \
  -o BatchMode=yes \
  -o StrictHostKeyChecking=yes \
  -o ForwardAgent=no \
  -o ClearAllForwardings=yes \
  "$CONTROLLER" \
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
     tests/alt_linux/test_machine_archive_service.py::test_later_generation_creates_new_archive_id'
```

Expected: `10 passed`, exit `0`.

- [ ] **Step 9: Run the complete ALT suite on the controller branch worktree**

```bash
ssh \
  -o BatchMode=yes \
  -o StrictHostKeyChecking=yes \
  -o ForwardAgent=no \
  -o ClearAllForwardings=yes \
  "$CONTROLLER" \
  'set -Eeuo pipefail
   WORKTREE=/home/altserver/web_ovpn-src/.worktrees/or3p4-portability-green
   cd "$WORKTREE"
   PYTHONDONTWRITEBYTECODE=1 python3 -m pytest -q tests/alt_linux'
```

Expected: exit `0`, no failed tests.

- [ ] **Step 10: Open a separate portability PR**

Use exact metadata:

```text
Title: test: make ALT controller verification portable
Base: main
Head: fix/alt-controller-test-harness-portability-20260724
```

The body must state:

- the ten failures reproduce on the unchanged issue #30 merge;
- production code is unchanged;
- `/bin -> /usr/bin` caused the dependency leak;
- the portable `altserver` fixture omitted `pw_name`;
- exact ten-test controller GREEN result;
- complete controller ALT-suite GREEN result;
- no controller runtime or production state was modified.

---

### Task 6: Verify and Merge the Controller Portability PR

**Files:**
- Modify: none beyond the PR branch.

**Interfaces:**
- Produces: `PORTABILITY_MERGE_SHA`.
- Defines: `ROLLOUT_COMMIT=$PORTABILITY_MERGE_SHA`.

- [ ] **Step 1: Review exact file scope**

Expected changed files:

```text
tests/alt_linux/conftest.py
tests/alt_linux/support/installer_sandbox.py
tests/alt_linux/test_install_assets.py
```

Production files under `deploy/alt-linux/` must be unchanged in this PR.

- [ ] **Step 2: Wait for GitHub CI and inspect complete results**

Required:

```text
focused workflows: success
all full-regression jobs: success
```

- [ ] **Step 3: Merge after explicit human approval**

Record the merge commit as `PORTABILITY_MERGE_SHA` and set:

```bash
ROLLOUT_COMMIT="$PORTABILITY_MERGE_SHA"
```

- [ ] **Step 4: Verify both prerequisite merges are ancestors**

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

Both commands must return `0`.

---

### Task 7: Create the Exact SSH Rollout Worktree on `192.168.100.17`

**Files:**
- Modify: controller Git metadata and a new worktree under `/home/altserver/web_ovpn-src/.worktrees/` only.

**Interfaces:**
- Consumes: `ROLLOUT_COMMIT`.
- Produces: `REMOTE_ROLLOUT_WORKTREE`.

- [ ] **Step 1: Fetch and verify the exact commit**

```bash
ssh -tt \
  -o StrictHostKeyChecking=yes \
  -o ForwardAgent=no \
  -o ClearAllForwardings=yes \
  "$CONTROLLER" \
  "set -Eeuo pipefail
   REPO=/home/altserver/web_ovpn-src
   COMMIT='$ROLLOUT_COMMIT'

   git -C \"\$REPO\" fetch --prune origin main
   git -C \"\$REPO\" cat-file -e \"\${COMMIT}^{commit}\"
   git -C \"\$REPO\" merge-base --is-ancestor \"\$COMMIT\" origin/main
   printf 'REMOTE_COMMIT_AVAILABLE=%s\n' \"\$COMMIT\""
```

- [ ] **Step 2: Create a unique detached rollout worktree**

```bash
SHORT_SHA="${ROLLOUT_COMMIT:0:12}"
REMOTE_ROLLOUT_WORKTREE="/home/altserver/web_ovpn-src/.worktrees/or3p4-ssh-$SHORT_SHA"

ssh \
  -o BatchMode=yes \
  -o StrictHostKeyChecking=yes \
  -o ForwardAgent=no \
  -o ClearAllForwardings=yes \
  "$CONTROLLER" \
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

- [ ] **Step 3: Prove the expected issue #30 code is present**

```bash
ssh \
  -o BatchMode=yes \
  -o StrictHostKeyChecking=yes \
  -o ForwardAgent=no \
  -o ClearAllForwardings=yes \
  "$CONTROLLER" \
  "set -Eeuo pipefail
   FILE='$REMOTE_ROLLOUT_WORKTREE/deploy/alt-linux/backup/alt_deploy_backup/state_validation.py'
   ! grep -Fq 'or status != state' \"\$FILE\"
   ! grep -Fq 'payload.get(\"status\") or state' \"\$FILE\"
   echo REGISTRATION_STATUS_CONTRACT_PRESENT=PASS"
```

---

### Task 8: Run Complete Remote Repository Verification Before Any Runtime Mutation

**Files:**
- Modify: test caches may be created under the detached worktree; no production path is changed.

**Interfaces:**
- Consumes: `REMOTE_ROLLOUT_WORKTREE`.
- Produces: a complete controller verification log and exit `0`.

- [ ] **Step 1: Run the complete ALT suite as `altserver`**

```bash
ssh \
  -o BatchMode=yes \
  -o StrictHostKeyChecking=yes \
  -o ForwardAgent=no \
  -o ClearAllForwardings=yes \
  "$CONTROLLER" \
  "set -Eeuo pipefail
   cd '$REMOTE_ROLLOUT_WORKTREE'
   PYTHONDONTWRITEBYTECODE=1 python3 -m pytest -q tests/alt_linux"
```

Expected: exit `0`, no failed tests. This gate must pass before installing the backup tool.

- [ ] **Step 2: Run source syntax checks**

```bash
ssh \
  -o BatchMode=yes \
  -o StrictHostKeyChecking=yes \
  -o ForwardAgent=no \
  -o ClearAllForwardings=yes \
  "$CONTROLLER" \
  "set -Eeuo pipefail
   cd '$REMOTE_ROLLOUT_WORKTREE'

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

- [ ] **Step 3: Do not run the control-plane installer yet**

The task log must explicitly record:

```text
Runtime mutation performed: no
Backup tool updated: no
Control plane installed: no
Accepted workstation contacted: no
```

---

### Task 9: Create a New Root-Owned SSH Rollout Evidence Record

**Files:**
- Create remotely: `/root/alt-or3p4-ssh-<UTC timestamp>/`.
- Create remotely: `/root/alt-or3p4-ssh-rollout.env`.

**Interfaces:**
- Produces: `ROLLOUT_ID`, `EVIDENCE`, and `REMOTE_ENV_FILE`.

- [ ] **Step 1: Create the evidence directory and environment file**

```bash
ssh -tt \
  -o StrictHostKeyChecking=yes \
  -o ForwardAgent=no \
  -o ClearAllForwardings=yes \
  "$CONTROLLER" \
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
printf 'REMOTE_ENV_FILE=%s\n' "\$ENV_FILE"
REMOTE_BASH
```

- [ ] **Step 2: Read back only the non-secret rollout fields**

```bash
ssh -tt \
  -o StrictHostKeyChecking=yes \
  -o ForwardAgent=no \
  -o ClearAllForwardings=yes \
  "$CONTROLLER" \
  'sudo grep -E "^(ROLLOUT_ID|EVIDENCE|WORKTREE|COMMIT|CONTROLLER|REFERENCE_WORKSTATION)=" /root/alt-or3p4-ssh-rollout.env'
```

---

### Task 10: Capture the Complete Read-Only Controller Pre-Rollout Audit

**Files:**
- Create remotely under `$EVIDENCE`: bounded JSON/text audit files.

**Interfaces:**
- Consumes: `/root/alt-or3p4-ssh-rollout.env`.
- Produces: pre-rollout evidence proving quiescence and safe prerequisites.

- [ ] **Step 1: Capture identity, disk, inode, Git, and systemd state**

```bash
ssh -tt \
  -o StrictHostKeyChecking=yes \
  -o ForwardAgent=no \
  -o ClearAllForwardings=yes \
  "$CONTROLLER" \
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
    printf '%s\n' '--- units ---'
    systemctl is-active alt-deploy-http.service || true
    systemctl is-active alt-deploy-register.service || true
    systemctl is-active alt-deploy-process.path || true
    systemctl is-active alt-deploy-process.service || true
    systemctl list-units --all --plain --no-legend 'alt-provision-*.service' || true
} >"$OUT"

chmod 0600 "$OUT"
sha256sum "$OUT"
REMOTE_BASH
```

- [ ] **Step 2: Capture the public controller health commands**

```bash
ssh -tt \
  -o StrictHostKeyChecking=yes \
  -o ForwardAgent=no \
  -o ClearAllForwardings=yes \
  "$CONTROLLER" \
  'sudo /bin/bash -s' <<'REMOTE_BASH'
set -Eeuo pipefail
source /root/alt-or3p4-ssh-rollout.env

sudo -u altserver workstationctl --json jobs active \
  >"$EVIDENCE/jobs-active.json"

sudo -u altserver workstationctl --json vault check \
  >"$EVIDENCE/vault-check.json"

sudo -u altserver workstationctl --json controller permissions \
  >"$EVIDENCE/controller-permissions.json"

sudo -u altserver workstationctl --json controller readiness \
  >"$EVIDENCE/controller-readiness-before.json" || true

chmod 0600 \
  "$EVIDENCE/jobs-active.json" \
  "$EVIDENCE/vault-check.json" \
  "$EVIDENCE/controller-permissions.json" \
  "$EVIDENCE/controller-readiness-before.json"

python3 - "$EVIDENCE" <<'PY'
import json
import sys
from pathlib import Path

root = Path(sys.argv[1])

jobs = json.loads((root / "jobs-active.json").read_text())
assert jobs["status"] == "ok"
assert jobs["count"] == 0
assert jobs["active_jobs"] == []

vault = json.loads((root / "vault-check.json").read_text())
assert vault["status"] == "ok"

permissions = json.loads(
    (root / "controller-permissions.json").read_text()
)
assert permissions["status"] == "ok"

print("CONTROLLER_PUBLIC_HEALTH=PASS")
PY
REMOTE_BASH
```

- [ ] **Step 3: Prove the pending queue and processor are idle**

```bash
ssh -tt \
  -o StrictHostKeyChecking=yes \
  -o ForwardAgent=no \
  -o ClearAllForwardings=yes \
  "$CONTROLLER" \
  'sudo /bin/bash -s' <<'REMOTE_BASH'
set -Eeuo pipefail
source /root/alt-or3p4-ssh-rollout.env

PENDING_COUNT="$(
  find /srv/alt-deploy/registration/pending \
    -maxdepth 1 -type f -name '*.json' -printf '.' |
  wc -c
)"

PROCESS_STATE="$(systemctl is-active alt-deploy-process.service || true)"
TRANSIENT_COUNT="$(
  systemctl list-units --all --plain --no-legend \
    'alt-provision-*.service' |
  wc -l
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

echo CONTROLLER_QUIESCENCE=PASS
REMOTE_BASH
```

Any failure blocks Tasks 11–13.

---

### Task 11: Preserve the Existing Failed Rehearsal as Incident Evidence

**Files:**
- Read existing bundle and failed tree.
- Create additional bounded metadata under the new `$EVIDENCE` directory.

**Interfaces:**
- Produces: proof that the old failed backup is diagnostic only and will not be reused.

- [ ] **Step 1: Verify the known diagnostics hash and old bundle state**

```bash
ssh -tt \
  -o StrictHostKeyChecking=yes \
  -o ForwardAgent=no \
  -o ClearAllForwardings=yes \
  "$CONTROLLER" \
  'sudo /bin/bash -s' <<'REMOTE_BASH'
set -Eeuo pipefail
source /root/alt-or3p4-ssh-rollout.env

OLD_BACKUP_ID=backup-20260723T133400Z-2b5c8ee3
OLD_BUNDLE="/var/backups/alt-deploy/$OLD_BACKUP_ID"
OLD_TREE="/var/tmp/alt-deploy-restore-test/$OLD_BACKUP_ID"
OLD_DIAGNOSTICS=/root/or3p4-20260723T061042Z/post-hotfix-registration-diagnostics.json
EXPECTED_DIAGNOSTICS_SHA=2ead9b49834bc96008e89c3262c7dbaea27b0776058180d5e18e1ac35eba7ae5

test -d "$OLD_BUNDLE"
test ! -L "$OLD_BUNDLE"
test -f "$OLD_BUNDLE/verification.json"
test ! -e "$OLD_BUNDLE/rehearsal.json"
test -d "$OLD_TREE"
test ! -L "$OLD_TREE"
test -f "$OLD_DIAGNOSTICS"

test "$(sha256sum "$OLD_DIAGNOSTICS" | awk '{print $1}')" = \
  "$EXPECTED_DIAGNOSTICS_SHA"

{
    printf 'OLD_BACKUP_ID=%s\n' "$OLD_BACKUP_ID"
    printf 'OLD_BUNDLE=%s\n' "$OLD_BUNDLE"
    printf 'OLD_FAILED_TREE=%s\n' "$OLD_TREE"
    printf 'OLD_DIAGNOSTICS=%s\n' "$OLD_DIAGNOSTICS"
    printf 'OLD_DIAGNOSTICS_SHA256=%s\n' "$EXPECTED_DIAGNOSTICS_SHA"
    printf 'OLD_BACKUP_REUSABLE=no\n'
} >"$EVIDENCE/previous-failed-rehearsal.txt"

chmod 0600 "$EVIDENCE/previous-failed-rehearsal.txt"
echo PREVIOUS_FAILED_REHEARSAL_PRESERVED=PASS
REMOTE_BASH
```

- [ ] **Step 2: Do not delete the old tree yet**

The old failed tree remains preserved through backup-tool installation, fresh backup creation, fresh rehearsal, and OR-3P4 installation. It is cleaned only after successful post-install readiness in Task 15.

---

### Task 12: Install the Exact Merged Backup Tool Generation Through SSH

**Files:**
- Mutate only the paths owned by `install-backup-tool.sh`:
  - `/usr/local/sbin/alt-deploy-backup`;
  - `/opt/alt-deploy-backup`;
  - `/etc/systemd/system/alt-deploy-guard.service`;
  - private backup state/log paths as defined by the installer.

**Interfaces:**
- Consumes: exact `WORKTREE` and `COMMIT` from the root environment file.
- Produces: installed backup package byte-identical to the merged source.

- [ ] **Step 1: Reconfirm the mutation gate**

Codex presents the exact command and expected paths to the human operator. Continue only after explicit approval.

- [ ] **Step 2: Run the dedicated backup-tool installer**

```bash
ssh -tt \
  -o StrictHostKeyChecking=yes \
  -o ForwardAgent=no \
  -o ClearAllForwardings=yes \
  "$CONTROLLER" \
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

Expected: installer exit `0`, source and installed validator SHA-256 values identical, and guard result `control_plane_allowed`.

- [ ] **Step 3: Do not run the control-plane installer**

A fresh successful backup is still mandatory.

---

### Task 13: Create, Verify, and Rehearse a Fresh Rollback Bundle

**Files:**
- Create one new bundle under `/var/backups/alt-deploy/`.
- Create verification and rehearsal evidence within that exact bundle.
- Append `BACKUP_ID` and evidence hashes to `/root/alt-or3p4-ssh-rollout.env`.

**Interfaces:**
- Produces: `BACKUP_ID`, `MANIFEST_SHA256`, `VERIFICATION_SHA256`, and `REHEARSAL_SHA256`.

- [ ] **Step 1: Create one coordinated backup and capture its exact JSON**

```bash
ssh -tt \
  -o StrictHostKeyChecking=yes \
  -o ForwardAgent=no \
  -o ClearAllForwardings=yes \
  "$CONTROLLER" \
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
ssh -tt \
  -o StrictHostKeyChecking=yes \
  -o ForwardAgent=no \
  -o ClearAllForwardings=yes \
  "$CONTROLLER" \
  'sudo /bin/bash -s' <<'REMOTE_BASH'
set -Eeuo pipefail
source /root/alt-or3p4-ssh-rollout.env

VERIFY_JSON="$EVIDENCE/backup-verify.json"
/usr/local/sbin/alt-deploy-backup verify "$BACKUP_ID" \
  >"$VERIFY_JSON"
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

- [ ] **Step 3: Run one isolated rehearsal**

```bash
ssh -tt \
  -o StrictHostKeyChecking=yes \
  -o ForwardAgent=no \
  -o ClearAllForwardings=yes \
  "$CONTROLLER" \
  'sudo /bin/bash -s' <<'REMOTE_BASH'
set -Eeuo pipefail
source /root/alt-or3p4-ssh-rollout.env

REHEARSE_JSON="$EVIDENCE/backup-rehearse.json"
/usr/local/sbin/alt-deploy-backup rehearse "$BACKUP_ID" \
  >"$REHEARSE_JSON"
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

If rehearsal fails, stop. Preserve the new failed tree and open a separate defect. Do not run the installer.

- [ ] **Step 4: Run the read-only rehearsal status check and bind evidence hashes**

```bash
ssh -tt \
  -o StrictHostKeyChecking=yes \
  -o ForwardAgent=no \
  -o ClearAllForwardings=yes \
  "$CONTROLLER" \
  'sudo /bin/bash -s' <<'REMOTE_BASH'
set -Eeuo pipefail
source /root/alt-or3p4-ssh-rollout.env

STATUS_JSON="$EVIDENCE/backup-rehearse-status.json"
/usr/local/sbin/alt-deploy-backup rehearse-status "$BACKUP_ID" \
  >"$STATUS_JSON"
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

Do not invoke `verify` again after this point.

---

### Task 14: Install the Exact Control-Plane Generation Using the Fresh Backup ID

**Files:**
- Mutate only the paths managed by the existing control-plane installer.
- Preserve active Vault, SSH identity, jobs, assignments, registrations, metadata, and all backup-tool paths.

**Interfaces:**
- Consumes: `WORKTREE`, `COMMIT`, and `BACKUP_ID` from `/root/alt-or3p4-ssh-rollout.env`.
- Produces: installed OR-3P4 control plane or an explicit guarded failure.

- [ ] **Step 1: Capture preservation metadata immediately before installation**

```bash
ssh -tt \
  -o StrictHostKeyChecking=yes \
  -o ForwardAgent=no \
  -o ClearAllForwardings=yes \
  "$CONTROLLER" \
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

paths = [
    Path("/home/altserver/ansible/group_vars/vault.yml"),
    Path("/home/altserver/.ansible-vault-pass"),
    Path("/home/altserver/.ssh/id_ed25519"),
    Path("/srv/alt-deploy/bootstrap/ansible_authorized_keys"),
]

def digest(path: Path) -> str:
    value = hashlib.sha256()
    with path.open("rb") as stream:
        while chunk := stream.read(1024 * 1024):
            value.update(chunk)
    return value.hexdigest()

records = {}
for path in paths:
    metadata = path.lstat()
    assert stat.S_ISREG(metadata.st_mode)
    records[str(path)] = {
        "uid": metadata.st_uid,
        "gid": metadata.st_gid,
        "mode": f"{stat.S_IMODE(metadata.st_mode):04o}",
        "size": metadata.st_size,
        "sha256": digest(path),
    }

for root in (
    Path("/var/lib/alt-deploy/jobs"),
    Path("/var/lib/alt-deploy/assignments"),
    Path("/srv/alt-deploy/registration"),
):
    records[str(root)] = {
        "regular_file_count": sum(
            1 for item in root.rglob("*")
            if item.is_file() and not item.is_symlink()
        )
    }

output = Path(sys.argv[1])
output.write_text(json.dumps(records, indent=2, sort_keys=True) + "\n")
os.chmod(output, 0o600)
PY
REMOTE_BASH
```

This evidence contains hashes but not secret contents. Keep it root-only and do not commit it.

- [ ] **Step 2: Present the final mutation summary for human approval**

Codex prints:

```text
Target: 192.168.100.17
Commit: exact COMMIT from /root/alt-or3p4-ssh-rollout.env
Rollback backup: exact BACKUP_ID from the same file
Installer: deploy/alt-linux/install-control-plane.sh
Expected maintenance services stopped temporarily:
  alt-deploy-process.path
  alt-deploy-register.service
  alt-deploy-http.service
Accepted workstation contacted: no
```

Wait for explicit approval.

- [ ] **Step 3: Run the public installer once**

```bash
ssh -tt \
  -o StrictHostKeyChecking=yes \
  -o ForwardAgent=no \
  -o ClearAllForwardings=yes \
  "$CONTROLLER" \
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

Expected: `CONTROL_PLANE_INSTALL=PASS`, exit `0`.

If the installer fails after entering maintenance:

1. do not manually start the ALT units;
2. retain the rollout marker and complete log;
3. inspect the bounded error and backup audit log;
4. run `restore "$BACKUP_ID"` only after explicit recovery approval;
5. if restore reports `restore_manual_recovery_required`, stop and follow the OR-3P3 manual-recovery runbook.

---

### Task 15: Prove Post-Install Readiness and Preservation

**Files:**
- Create bounded post-install evidence under `$EVIDENCE`.
- Do not create a provisioning job.

**Interfaces:**
- Produces: controller readiness proof and byte-preservation proof.

- [ ] **Step 1: Run installed public health checks**

```bash
ssh -tt \
  -o StrictHostKeyChecking=yes \
  -o ForwardAgent=no \
  -o ClearAllForwardings=yes \
  "$CONTROLLER" \
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
assert jobs["status"] == "ok"
assert jobs["count"] == 0

readiness = json.loads(
    (root / "controller-readiness-after.json").read_text()
)
assert readiness["status"] == "ok"

vault = json.loads((root / "vault-check-after.json").read_text())
assert vault["status"] == "ok"

permissions = json.loads(
    (root / "controller-permissions-after.json").read_text()
)
assert permissions["status"] == "ok"

print("POST_INSTALL_PUBLIC_HEALTH=PASS")
PY
REMOTE_BASH
```

- [ ] **Step 2: Verify exact unit states**

```bash
ssh \
  -o BatchMode=yes \
  -o StrictHostKeyChecking=yes \
  -o ForwardAgent=no \
  -o ClearAllForwardings=yes \
  "$CONTROLLER" \
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

- [ ] **Step 3: Compare preservation metadata**

```bash
ssh -tt \
  -o StrictHostKeyChecking=yes \
  -o ForwardAgent=no \
  -o ClearAllForwardings=yes \
  "$CONTROLLER" \
  'sudo /bin/bash -s' <<'REMOTE_BASH'
set -Eeuo pipefail
source /root/alt-or3p4-ssh-rollout.env

python3 - "$EVIDENCE/pre-install-preservation.json" <<'PY'
import hashlib
import json
import stat
import sys
from pathlib import Path

before = json.loads(Path(sys.argv[1]).read_text())

def digest(path: Path) -> str:
    value = hashlib.sha256()
    with path.open("rb") as stream:
        while chunk := stream.read(1024 * 1024):
            value.update(chunk)
    return value.hexdigest()

for raw_path, expected in before.items():
    path = Path(raw_path)
    if "sha256" in expected:
        metadata = path.lstat()
        assert stat.S_ISREG(metadata.st_mode)
        assert metadata.st_uid == expected["uid"]
        assert metadata.st_gid == expected["gid"]
        assert f"{stat.S_IMODE(metadata.st_mode):04o}" == expected["mode"]
        assert metadata.st_size == expected["size"]
        assert digest(path) == expected["sha256"]
    else:
        current = sum(
            1 for item in path.rglob("*")
            if item.is_file() and not item.is_symlink()
        )
        assert current == expected["regular_file_count"]

print("POST_INSTALL_PRESERVATION=PASS")
PY
REMOTE_BASH
```

- [ ] **Step 4: Confirm exact installed source identity**

```bash
ssh -tt \
  -o StrictHostKeyChecking=yes \
  -o ForwardAgent=no \
  -o ClearAllForwardings=yes \
  "$CONTROLLER" \
  'sudo /bin/bash -s' <<'REMOTE_BASH'
set -Eeuo pipefail
source /root/alt-or3p4-ssh-rollout.env

test "$(cat /opt/alt-deploy-control/.repository-commit)" = "$COMMIT"
test -z "$(git -C "$WORKTREE" status --porcelain)"

echo INSTALLED_REPOSITORY_COMMIT=PASS
REMOTE_BASH
```

If the installed commit marker is not already part of the installer contract, do not create it manually; instead compare installed file hashes against the exact source tree and record that limitation in the closure document.

- [ ] **Step 5: Keep the fresh rollback bundle**

Do not delete the successful fresh bundle. It remains the approved rollback generation until the rollback window is explicitly closed after disposable-machine acceptance.

---

### Task 16: Clean Only the Old Failed Rehearsal Tree After Successful OR-3P4

**Files:**
- Remove only `/var/tmp/alt-deploy-restore-test/backup-20260723T133400Z-2b5c8ee3`.
- Preserve its bundle and all diagnostics.

**Interfaces:**
- Consumes: successful Task 15 readiness and preservation evidence.
- Produces: a bounded cleanup record.

- [ ] **Step 1: Reverify the exact target and diagnostics**

```bash
ssh -tt \
  -o StrictHostKeyChecking=yes \
  -o ForwardAgent=no \
  -o ClearAllForwardings=yes \
  "$CONTROLLER" \
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

- [ ] **Step 2: Remove the exact tree through the installed safe cleanup implementation**

```bash
ssh -tt \
  -o StrictHostKeyChecking=yes \
  -o ForwardAgent=no \
  -o ClearAllForwardings=yes \
  "$CONTROLLER" \
  'sudo /bin/bash -s' <<'REMOTE_BASH'
set -Eeuo pipefail
source /root/alt-or3p4-ssh-rollout.env

OLD_BACKUP_ID=backup-20260723T133400Z-2b5c8ee3
TARGET="/var/tmp/alt-deploy-restore-test/$OLD_BACKUP_ID"

PYTHONPATH=/opt/alt-deploy-backup \
PYTHONDONTWRITEBYTECODE=1 \
python3 - "$TARGET" <<'PY'
from pathlib import Path
import sys

from alt_deploy_backup.rehearsal import RehearsalService
from alt_deploy_backup.repository import BackupRepository
from alt_deploy_backup.settings import BackupSettings

path = Path(sys.argv[1])
expected = (
    Path("/var/tmp/alt-deploy-restore-test")
    / "backup-20260723T133400Z-2b5c8ee3"
)
assert path == expected

service = RehearsalService(
    BackupRepository(BackupSettings.from_env())
)
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

Do not delete `backup-20260723T133400Z-2b5c8ee3` in this task.

---

### Task 17: Accept One New Disposable ALT Workstation Through the Installed Controller

**Files:**
- Create one non-secret provision request JSON under a root-controlled temporary path on the controller.
- Create one normal provision job and assignment for a new disposable machine.

**Interfaces:**
- Produces: `TARGET_UUID`, `JOB_ID`, successful assignment, reboot/visual evidence, and repeat-provision rejection.

- [ ] **Step 1: Require a new disposable target**

The human operator confirms the target is a clean disposable VM or physical machine and is not the accepted reference workstation.

- [ ] **Step 2: Wait for automatic registration and list machines read-only**

```bash
ssh \
  -o BatchMode=yes \
  -o StrictHostKeyChecking=yes \
  -o ForwardAgent=no \
  -o ClearAllForwardings=yes \
  "$CONTROLLER" \
  'sudo -u altserver workstationctl --json machines list'
```

- [ ] **Step 3: Capture and validate the human-approved UUID**

Run locally:

```bash
read -r -p 'Approved disposable machine UUID: ' TARGET_UUID

[[ "$TARGET_UUID" =~ ^[0-9a-fA-F-]{8,64}$ ]]
test "${TARGET_UUID,,}" != \
  'cc6f1a81-54b8-47c9-95de-2ac29ee4fbb7'

TARGET_UUID="${TARGET_UUID,,}"
printf 'TARGET_UUID=%s\n' "$TARGET_UUID"
```

- [ ] **Step 4: Show the selected machine and run preflight**

```bash
ssh \
  -o BatchMode=yes \
  -o StrictHostKeyChecking=yes \
  -o ForwardAgent=no \
  -o ClearAllForwardings=yes \
  "$CONTROLLER" \
  "set -Eeuo pipefail
   sudo -u altserver workstationctl --json machines show '$TARGET_UUID'
   sudo -u altserver workstationctl --json preflight '$TARGET_UUID'"
```

Expected final machine status: `awaiting_assignment`.

- [ ] **Step 5: Collect the approved assignment fields interactively**

```bash
read -r -p 'Employee login: ' EMPLOYEE_LOGIN
read -r -p 'Employee full name: ' EMPLOYEE_FULL_NAME
read -r -p 'Final hostname: ' FINAL_HOSTNAME

[[ "$EMPLOYEE_LOGIN" =~ ^[a-z0-9][a-z0-9_-]*[a-z0-9]$ ]]
[[ "$FINAL_HOSTNAME" =~ ^[a-z0-9][a-z0-9-]*[a-z0-9]$ ]]
test -n "$EMPLOYEE_FULL_NAME"
```

No password is entered or stored in the request.

- [ ] **Step 6: Create a private non-secret request file on the controller**

```bash
REQUEST_B64="$(
  TARGET_UUID="$TARGET_UUID" \
  EMPLOYEE_LOGIN="$EMPLOYEE_LOGIN" \
  EMPLOYEE_FULL_NAME="$EMPLOYEE_FULL_NAME" \
  FINAL_HOSTNAME="$FINAL_HOSTNAME" \
  python3 - <<'PY' | base64 -w0
import json
import os

payload = {
    "machine_uuid": os.environ["TARGET_UUID"],
    "employee_login": os.environ["EMPLOYEE_LOGIN"],
    "employee_full_name": os.environ["EMPLOYEE_FULL_NAME"],
    "final_hostname": os.environ["FINAL_HOSTNAME"],
    "profile": "standard",
}
print(json.dumps(payload, ensure_ascii=False, sort_keys=True))
PY
)"

ssh -tt \
  -o StrictHostKeyChecking=yes \
  -o ForwardAgent=no \
  -o ClearAllForwardings=yes \
  "$CONTROLLER" \
  "sudo /bin/bash -c '
    set -Eeuo pipefail
    REQUEST=/root/alt-or3p4-disposable-request.json
    test ! -e \"\$REQUEST\"
    printf %s '$REQUEST_B64' | base64 -d >\"\$REQUEST\"
    chown root:root \"\$REQUEST\"
    chmod 0600 \"\$REQUEST\"
    python3 -m json.tool \"\$REQUEST\" >/dev/null
    echo REQUEST_FILE_READY=PASS
  '"
```

- [ ] **Step 7: Run preview and review every field**

```bash
ssh -tt \
  -o StrictHostKeyChecking=yes \
  -o ForwardAgent=no \
  -o ClearAllForwardings=yes \
  "$CONTROLLER" \
  "sudo -u altserver workstationctl --json provision preview '$TARGET_UUID' \
     --vars-file /root/alt-or3p4-disposable-request.json"
```

If `altserver` cannot read the root-owned request, copy the non-secret request to a temporary `altserver:altserver 0600` path under `/home/altserver` for preview, then remove that temporary copy after job creation. Do not weaken Vault or SSH-key permissions.

- [ ] **Step 8: Start provisioning only after explicit preview approval**

```bash
ssh -tt \
  -o StrictHostKeyChecking=yes \
  -o ForwardAgent=no \
  -o ClearAllForwardings=yes \
  "$CONTROLLER" \
  "sudo workstationctl --json provision start '$TARGET_UUID' \
     --vars-file /root/alt-or3p4-disposable-request.json"
```

Capture the returned `job_id` as `JOB_ID`.

- [ ] **Step 9: Monitor status and bounded logs**

```bash
ssh \
  -o BatchMode=yes \
  -o StrictHostKeyChecking=yes \
  -o ForwardAgent=no \
  -o ClearAllForwardings=yes \
  "$CONTROLLER" \
  "sudo -u altserver workstationctl --json jobs status '$JOB_ID'"

ssh \
  -o BatchMode=yes \
  -o StrictHostKeyChecking=yes \
  -o ForwardAgent=no \
  -o ClearAllForwardings=yes \
  "$CONTROLLER" \
  "sudo -u altserver workstationctl --json jobs log '$JOB_ID'"
```

Required final result:

```text
state=successful
stage=complete
complete ten-stage monotonic stage_history
assignment written only after verification
```

- [ ] **Step 10: Reboot the disposable target and perform visual acceptance**

The human operator, not Codex, verifies:

- LightDM is active;
- the technical `ansible` account is hidden;
- the employee account is visible;
- graphical login to KDE Plasma succeeds;
- the employee has no sudo/wheel privilege;
- the final hostname is correct.

- [ ] **Step 11: Verify server/target assignment and repeat protection**

Run `machines show`, job status, and assignment checks. Then run `provision preview` or the approved non-mutating repeat check and confirm a repeat start would be rejected with `machine_already_assigned`. Do not bypass that protection.

- [ ] **Step 12: Remove the temporary request files**

Delete only the non-secret temporary request JSON after all evidence is captured. Do not delete the job or assignment.

---

### Task 18: Write and Merge the Sanitized OR-3P4 SSH Rollout Closure

**Files:**
- Create: `docs/verification/ALT_OR3P4_SSH_CONTROLLER_ROLLOUT_2026-07-24.md`.
- Modify: `docs/ALT_WORKSTATION_PROVISIONING_CONTEXT.md`.
- Modify: `docs/ALT_WORKSTATION_PROVISIONING_NEXT_STEPS.md`.

**Interfaces:**
- Consumes: exact merge SHA, backup ID, manifest SHA-256, test results, readiness results, preservation proof, and disposable-machine acceptance.
- Produces: repository-visible operational closure without secrets.

- [ ] **Step 1: Create the closure document locally**

The document must contain:

```text
controller: 192.168.100.17
execution model: local Codex + OpenSSH, no server-side Codex installation
exact installed merge commit
issue #30 PR and portability PR
local/CI/controller test results
fresh backup ID and manifest SHA-256
verification/rehearsal evidence binding status
installer exit status
post-install readiness status
expected unit states
preservation checks for Vault, Vault password file, SSH private key, jobs,
assignments, and registrations
old failed rehearsal tree cleanup status
new disposable target acceptance result
repeat-provision rejection result
rollback bundle retention decision
```

Do not include:

```text
passwords
password hashes
private keys
Vault contents
private job logs
employee-sensitive data beyond the approved sanitized acceptance fields
```

- [ ] **Step 2: Update the operational context**

Record that OR-3P4 is complete only if Tasks 14–17 succeeded. Keep `192.168.100.17` as the controller and `192.168.100.30` as the future thin UI/API consumer.

- [ ] **Step 3: Update next steps**

The next stage is a separate design and implementation plan for:

```text
constrained read-only controller API on 192.168.100.17
allowlisted access from 192.168.100.30
web_ovpn ALT device source and UUID/MAC correlation
later separately approved preview/start operations
```

Do not implement that API or web integration in this plan.

- [ ] **Step 4: Run documentation and repository verification**

```bash
git diff --check
PYTHONDONTWRITEBYTECODE=1 python3 -m pytest -q tests/alt_linux
PYTHONDONTWRITEBYTECODE=1 python3 -m pytest -q
```

Expected: exit `0` for all commands in the normal local/CI environment.

- [ ] **Step 5: Commit, push, open a documentation PR, and wait for CI**

```bash
git add -- \
  docs/verification/ALT_OR3P4_SSH_CONTROLLER_ROLLOUT_2026-07-24.md \
  docs/ALT_WORKSTATION_PROVISIONING_CONTEXT.md \
  docs/ALT_WORKSTATION_PROVISIONING_NEXT_STEPS.md

git commit -m \
  "docs: record ALT OR-3P4 SSH controller rollout"

git push -u origin HEAD
```

Merge only after fresh CI and explicit human approval.

---

## Failure and Recovery Matrix

### Failure before backup-tool installation

- No production runtime mutation has occurred.
- Preserve logs and fix the source/SSH/test issue in a new PR.
- Do not continue with stale assumptions.

### Failure during fresh backup creation

- The backup tool restores prior service state before returning.
- Preserve command JSON and `/var/log/alt-deploy-backup.log`.
- Do not run OR-3P4.

### Failure during rehearsal

- Preserve `/var/tmp/alt-deploy-restore-test/<backup-id>`.
- Preserve the bundle and `verification.json`.
- Do not run `verify` or `rehearse` again until a reviewed fix is installed and the failed tree is explicitly handled.
- Open a separate issue with bounded diagnostics.

### Installer failure before maintenance

- No controller runtime path should have changed.
- Preserve installer output and confirm services remain in their prior state.

### Installer failure after maintenance or activation

- Do not manually start services.
- Preserve `/var/lib/alt-deploy-backup/rollout.json` and the installer log.
- Use the exact fresh `BACKUP_ID` for the reviewed restore command.

### Restore returns `restore_manual_recovery_required`

- Leave maintenance services stopped.
- Do not delete the journal, permits, rollback siblings, pre-restore generation, or rollout marker.
- Run `recover <restore-id>` once only after correcting the external cause.
- If recovery remains manual, stop and perform reviewed recovery from the recorded pre-restore generation.

---

## Codex Execution Prompt

Use this prompt when handing the plan to a new local Codex thread:

```text
Execute docs/superpowers/plans/2026-07-24-alt-or3p4-local-codex-ssh-rollout.md task by task.

You are running locally in the web_ovpn repository. Do not install Codex, Codex CLI, an agent, or OpenAI credentials on 192.168.100.17. Use ordinary local ssh commands to altserver@192.168.100.17. Do not use scp/rsync to deploy source; push reviewed commits to GitHub, merge them, and make the controller fetch the exact merge SHA into a detached worktree.

Before every remote mutation, show the exact target, command, paths, expected effects, rollback boundary, and stop conditions, then wait for my explicit approval. Never place passwords, passphrases, Vault data, hashes from Vault, or private keys in commands or logs. I will type interactive sudo or SSH-key passphrases directly.

Keep 192.168.101.111 immutable. Do not contact it. Do not install the control plane until issue #30 is merged, the controller test-harness portability PR is merged, the exact controller ALT suite passes with exit 0, controller quiescence is healthy, and a new exact backup has been created, verified, rehearsed, and checked read-only.

Use TDD, clean worktrees, frequent commits, GitHub CI, exact commit SHAs, root-only evidence, and one remote mutation at a time. Stop immediately on any unexpected output, dirty worktree, active job, pending registration, failed rehearsal, guard block, or readiness failure.
```

---

## Plan Self-Review Checklist

- [x] Local development and SSH execution are explicitly separated.
- [x] No Codex or custom deployment CLI is installed on the controller.
- [x] Source transfer is bound to exact reviewed Git commits.
- [x] Issue #30 closure is included.
- [x] The ten controller-only test failures are fixed before the installer is allowed to run.
- [x] Controller tests are proven on the actual `altserver` environment through SSH.
- [x] OR-3P3 create/verify/rehearse and exact-ID rules are preserved.
- [x] The accepted reference workstation remains immutable.
- [x] Human approval gates exist before every privileged mutation.
- [x] Passwords, Vault contents, hashes, and private keys are excluded from logs and Git.
- [x] Failure, guard, restore, and manual-recovery paths are explicit.
- [x] Disposable-machine acceptance is included.
- [x] Web integration is kept as a separate future plan.
- [x] No placeholder implementation step or unspecified test command remains.
