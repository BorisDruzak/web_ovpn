# ALT Interactive Bootstrap Input Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Make `start-bootstrap.sh` collect and confirm a valid final hostname on the user workstation before collecting the AD login and starting technical bootstrap.

**Architecture:** Keep the existing noninteractive `bootstrap.sh` and registration API unchanged. Add small shell functions to `start-bootstrap.sh` for canonical hostname validation, confirmation, local hostname mutation, and read-back verification. The controller still validates the registered hostname and AD UPN before domain join.

**Tech Stack:** Bash, `hostnamectl`, existing pytest ALT test suite.

## Global Constraints

- Hostname rule: `^(lin|alt|win|deb)-[a-z][0-9]?-(pc[1-9][0-9]*)$`.
- User interaction occurs only in the terminal on the newly installed ALT workstation.
- Require explicit `y` confirmation before either using or changing a hostname.
- Request only hostname and AD login/UPN; do not prompt for AD/domain/Vault/local passwords.
- Preserve direct `bootstrap.sh`, managed ISO, and existing registration retry behavior.

---

### Task 1: Define the interactive-launcher contract in tests

**Files:**
- Modify: `tests/alt_linux/test_start_bootstrap_launcher.py`
- Modify: `deploy/alt-linux/bootstrap/start-bootstrap.sh`

**Interfaces:**
- Consumes: `hostnamectl --static`, stdin, `ALT_FINAL_HOSTNAME` optional noninteractive override.
- Produces: an exported, confirmed final hostname for `bootstrap.sh` registration.

- [ ] **Step 1: Write failing launcher contract tests**

```python
def test_launcher_collects_and_confirms_hostname_before_ad_user() -> None:
    text = LAUNCHER.read_text(encoding="utf-8")
    assert 'hostnamectl --static' in text
    assert 'Hostname must match:' in text
    assert 'Apply hostname' in text
    assert text.index('hostnamectl --static') < text.index(
        'read -r -p "AD user (login or UPN): "'
    )

def test_launcher_never_prompts_for_any_password() -> None:
    text = LAUNCHER.read_text(encoding="utf-8")
    assert "read -s" not in text
    assert "password" not in text.lower()
```

- [ ] **Step 2: Run the focused launcher test and verify it fails**

Run: `python3 -m pytest -q tests/alt_linux/test_start_bootstrap_launcher.py -p no:cacheprovider`

Expected: FAIL because the existing launcher does not inspect or confirm a hostname.

- [ ] **Step 3: Add minimal hostname interaction functions**

```bash
HOSTNAME_RE='^(lin|alt|win|deb)-[a-z][0-9]?-(pc[1-9][0-9]*)$'

confirm_hostname() {
    local candidate=$1 answer
    read -r -p "Apply hostname ${candidate}? [y/N]: " answer
    [[ ${answer,,} == y ]]
}
```

Normalize to lowercase, loop on invalid input, confirm the current valid name,
call `hostnamectl set-hostname` only after confirmation of a different name,
and require a static-hostname read-back match before moving to UPN collection.

- [ ] **Step 4: Re-run focused launcher tests**

Run: `python3 -m pytest -q tests/alt_linux/test_start_bootstrap_launcher.py -p no:cacheprovider`

Expected: PASS.

- [ ] **Step 5: Commit the implementation**

```bash
git add deploy/alt-linux/bootstrap/start-bootstrap.sh tests/alt_linux/test_start_bootstrap_launcher.py
git commit -m "feat(alt): collect confirmed hostname in launcher"
```

### Task 2: Verify documentation and deployment assets

**Files:**
- Modify: `docs/runbooks/alt-manual-bootstrap-mvp.md`
- Test: `tests/alt_linux/test_manual_bootstrap_mvp_docs.py`

**Interfaces:**
- Consumes: operator manual bootstrap command.
- Produces: documented prompt contract matching `start-bootstrap.sh`.

- [ ] **Step 1: Write a failing runbook assertion**

```python
assert "The launcher validates and confirms the final hostname" in text
assert "The operator enters only the hostname and AD login" in text
```

- [ ] **Step 2: Run the focused documentation test and verify it fails**

Run: `python3 -m pytest -q tests/alt_linux/test_manual_bootstrap_mvp_docs.py -p no:cacheprovider`

Expected: FAIL because the interactive prompt contract is not documented.

- [ ] **Step 3: Document the two prompts and no-password boundary**

Add a short runbook paragraph after the launcher command. State that hostname
is checked and confirmed before bootstrap, AD UPN is the only other prompt,
and domain/realm/OU/password values are controller-owned.

- [ ] **Step 4: Re-run documentation and launcher tests**

Run: `python3 -m pytest -q tests/alt_linux/test_start_bootstrap_launcher.py tests/alt_linux/test_manual_bootstrap_mvp_docs.py -p no:cacheprovider`

Expected: PASS.

- [ ] **Step 5: Commit documentation**

```bash
git add docs/runbooks/alt-manual-bootstrap-mvp.md tests/alt_linux/test_manual_bootstrap_mvp_docs.py
git commit -m "docs(alt): describe interactive bootstrap prompts"
```

### Task 3: Full verification and controller deployment

**Files:**
- Modify: no additional production files.

**Interfaces:**
- Consumes: controller source tree and existing guarded installer.
- Produces: deployed launcher reachable at `/bootstrap/start-bootstrap.sh`.

- [ ] **Step 1: Verify shell syntax and focused tests**

Run:

```bash
bash -n deploy/alt-linux/bootstrap/start-bootstrap.sh
python3 -m pytest -q tests/alt_linux/test_start_bootstrap_launcher.py tests/alt_linux/test_manual_bootstrap_mvp_docs.py -p no:cacheprovider
```

Expected: both commands exit 0.

- [ ] **Step 2: Run the full ALT test suite on the Linux controller as root**

Run:

```bash
sudo -n env PYTHONPATH=/home/altserver/alt-manual-rollout-browser-store/control \
  python3 -m pytest -q /home/altserver/alt-manual-rollout-browser-store/tests/alt_linux -p no:cacheprovider
```

Expected: no failures; existing skipped tests are allowed.

- [ ] **Step 3: Deploy through the guarded installer and verify readiness**

Run the existing `install-control-plane.sh` with the current rollback backup
ID. Confirm its journal contains `ALT deployment control plane installed
successfully`, then verify controller readiness and the HTTP copy of
`start-bootstrap.sh`.

- [ ] **Step 4: Commit and push verification-ready changes**

```bash
git status --short
git push origin codex/alt-resilience-integration
```
