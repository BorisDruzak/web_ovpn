# Mandatory Review Notes for the Local Codex SSH Execution Plan

These notes are part of the execution contract for `2026-07-24-alt-or3p4-local-codex-ssh-execution.md`. They remove the remaining shell and workflow ambiguity found during self-review.

## 1. SSH agent inspection must not terminate the shell

When Task 1 is executed under `set -e`, inspect the agent with:

```bash
if ! ssh-add -l; then
    echo 'No approved SSH identity is currently loaded.' >&2
    echo 'The human operator must run ssh-add interactively.' >&2
    exit 20
fi
```

Do not replace this with an automatic key import and do not expose the key passphrase.

## 2. RED recheck must retain strict mode outside the expected test failure

Use this strict-mode form for Task 2, Step 3:

```bash
ssh -o BatchMode=yes "${SSH_OPTS[@]}" "$CONTROLLER" \
  "set -Eeuo pipefail
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

Any failure before or after the expected pytest failure remains fatal.

## 3. Preservation inventory must use one immutable helper for both captures

During Task 9, save the exact inline inventory program from the plan as:

```text
$EVIDENCE/capture-preservation.py
```

Required metadata:

```text
owner=root
 group=root
mode=0700
regular file
not a symlink
```

Invoke it before installation:

```bash
python3 "$EVIDENCE/capture-preservation.py" \
  "$EVIDENCE/pre-install-preservation.json"
```

Invoke the same file after installation:

```bash
python3 "$EVIDENCE/capture-preservation.py" \
  "$EVIDENCE/post-install-preservation.json"
```

Before the second invocation, verify the helper hash against the value captured immediately after its creation. Then compare the two JSON files with `cmp -s`. Do not paste, regenerate, edit, or simplify the helper between captures, and do not replace the tree inventory with file counts.

## 4. Rollout closure documentation uses a fresh local branch

Before Task 14 changes documentation, create a clean local worktree from the exact current `origin/main`:

```bash
cd "$LOCAL_REPO"
git fetch --prune origin main

CLOSURE_BRANCH='docs/alt-or3p4-ssh-rollout-closure-20260724'
CLOSURE_WORKTREE="$LOCAL_REPO/.worktrees/alt-or3p4-ssh-rollout-closure"

test ! -e "$CLOSURE_WORKTREE"
git show-ref --verify --quiet \
  "refs/heads/$CLOSURE_BRANCH" && exit 20 || true

git worktree add \
  -b "$CLOSURE_BRANCH" \
  "$CLOSURE_WORKTREE" \
  origin/main

cd "$CLOSURE_WORKTREE"
test -z "$(git status --porcelain)"
```

Create and commit closure documents only in that worktree. Do not reuse the issue-30, portability, plan, or rollout verification worktrees.

## 5. Precedence

Where these notes differ from the main execution plan, these notes take precedence. All other gates, commands, preservation requirements, and stop conditions in the main plan remain unchanged.
