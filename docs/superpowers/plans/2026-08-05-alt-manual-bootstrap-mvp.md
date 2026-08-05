# ALT Manual Bootstrap MVP Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Provide a documented, repeatable pilot-only path for a manually installed ALT Workstation K 11.x computer to register with the controller and then be configured by controller-side Ansible, without changing either ISO installation path.

**Architecture:** The operator installs ALT manually and creates `osn-admin` locally. The operator downloads the already-published bootstrap script from controller `192.168.100.17`, runs it through `sudo` while bypassing HTTP proxy settings for the internal controller address, and the script prepares `ansible`, SSH, sudo and registration. Only the controller may subsequently run Ansible domain configuration; the manual workstation never receives Vault material or an Ansible playbook.

**Tech Stack:** Bash, curl, ALT Workstation K 11.x, controller `workstationctl`, Ansible, pytest.

## Global Constraints

- This is a pilot-only temporary manual path; the strategic installation mechanism remains managed ISO.
- Do not delete or modify managed ISO, its boot menu, its install-agent, the legacy `ai curl=...` mechanism, `autoinstall.scm`, or `vm-profile.scm`.
- The workstation is installed manually by an operator, including local `osn-admin` creation.
- The shared `osn-admin` pilot password is entered only at the local `sudo` prompt. It must not be written to Git, bootstrap, Ansible, Vault, request JSON, logs, shell arguments, or documentation examples.
- HTTP without SHA-256 is explicitly accepted for this pilot path only on trusted provisioning network `192.168.100.0/23`.
- The manual download and bootstrap process must use direct controller access, bypassing configured HTTP proxies.
- Bootstrap must create or retain only the technical `ansible` account, controller SSH authorization, passwordless sudo and registration state; it must not perform domain join or software installation.
- Domain join and workstation software installation run only from controller `192.168.100.17` through allowlisted Ansible playbooks.
- Existing bootstrap reruns must remain safe: after base completion, rerun may retry registration but must not reinstall packages or create a second technical account.
- No test may contact production AD, create a domain computer object, or write a physical target disk.

---

## File Structure

- Create: `docs/runbooks/alt-manual-bootstrap-mvp.md` — operator runbook: scope, prerequisites, exact non-secret command, controller handoff, verification and recovery boundaries.
- Create: `tests/alt_linux/test_manual_bootstrap_mvp_docs.py` — checks that the runbook preserves the non-secret direct-download contract and ISO boundaries.
- Modify: `tests/alt_linux/test_bootstrap_register_integration.py` — asserts that the shared bootstrap remains a registration-only, safe-rerun mechanism and contains no domain/Vault actions.
- Modify: `docs/ALT_LINUX_AUTOINSTALL.md` — marks legacy autoinstall as a separate legacy mechanism and links to the manual MVP runbook; it must not change legacy instructions or disk policy.

### Task 1: Lock the manual MVP boundary in an executable documentation test

**Files:**
- Create: `tests/alt_linux/test_manual_bootstrap_mvp_docs.py`

**Interfaces:**
- Consumes: `docs/runbooks/alt-manual-bootstrap-mvp.md` as UTF-8 Markdown.
- Produces: a pytest contract that rejects accidental introduction of passwords, Vault, direct Ansible execution or ISO mutation into the manual workflow.

- [ ] **Step 1: Write the failing test**

```python
from pathlib import Path


ROOT = Path(__file__).resolve().parents[2]
RUNBOOK = ROOT / "docs" / "runbooks" / "alt-manual-bootstrap-mvp.md"


def test_manual_mvp_runbook_preserves_the_controller_boundary() -> None:
    text = RUNBOOK.read_text(encoding="utf-8")

    assert "curl --noproxy '*' -fsS" in text
    assert "sudo env no_proxy=192.168.100.17" in text
    assert "http://192.168.100.17:8087/bootstrap/bootstrap.sh" in text
    assert "Domain join and software installation are controller-only." in text
    assert "managed ISO" in text
    assert "ai curl=" in text
    for forbidden in ("vault_ad_join_password", "ansible-playbook", "osn-admin password"):
        assert forbidden not in text
```

- [ ] **Step 2: Run the test to verify it fails because the runbook does not exist**

Run: `python -m pytest -q tests/alt_linux/test_manual_bootstrap_mvp_docs.py`

Expected: FAIL with `FileNotFoundError` for `docs/runbooks/alt-manual-bootstrap-mvp.md`.

- [ ] **Step 3: Create the manual operator runbook with the exact safe command**

Create `docs/runbooks/alt-manual-bootstrap-mvp.md` with these mandatory sections and text:

```markdown
# Manual ALT bootstrap MVP

This temporary pilot path starts after a manual ALT Workstation K 11.x installation. It does not replace managed ISO or legacy `ai curl=` autoinstall.

## Preconditions

- The computer is on trusted provisioning network `192.168.100.0/23`.
- ALT Workstation K 11.x is already installed manually.
- The operator created and can use local administrator `osn-admin`.
- A default route reaches `192.168.100.17`.

## Run on the workstation

```bash
curl --noproxy '*' -fsS --connect-timeout 5 --max-time 30 \
  http://192.168.100.17:8087/bootstrap/bootstrap.sh \
  -o /tmp/alt-bootstrap.sh && \
sudo env no_proxy=192.168.100.17 NO_PROXY=192.168.100.17 \
  bash /tmp/alt-bootstrap.sh
```

The local sudo prompt is the only place where the pilot local-administrator password is entered. Do not put it in a command, file, request or log.

Domain join and software installation are controller-only.
```

Add a recovery section stating that a rerun is safe, and an explicit statement that it does not repair intentionally deleted SSH keys or sudoers files. Add a security section stating that HTTP without SHA-256 is accepted only for this trusted pilot network.

- [ ] **Step 4: Run the new test to verify it passes**

Run: `python -m pytest -q tests/alt_linux/test_manual_bootstrap_mvp_docs.py`

Expected: PASS.

- [ ] **Step 5: Commit the documentation contract**

```bash
git add tests/alt_linux/test_manual_bootstrap_mvp_docs.py docs/runbooks/alt-manual-bootstrap-mvp.md
git commit -m "docs(alt): define manual bootstrap MVP"
```

### Task 2: Preserve bootstrap as a non-secret registration-only action

**Files:**
- Modify: `tests/alt_linux/test_bootstrap_register_integration.py`

**Interfaces:**
- Consumes: `deploy/alt-linux/bootstrap/bootstrap.sh`.
- Produces: a test guarantee that the manual path relies on registration bootstrap only and cannot silently become a domain or Vault execution path.

- [ ] **Step 1: Write the failing bootstrap contract test**

Append this test to `tests/alt_linux/test_bootstrap_register_integration.py`:

```python
def test_bootstrap_remains_non_secret_and_registration_only() -> None:
    source = BOOTSTRAP.read_text(encoding="utf-8")

    assert 'ANSIBLE_USER="ansible"' in source
    assert 'touch "${MARKER}"' in source
    assert 'if [[ -f "${MARKER}" ]]' in source
    assert 'register_machine' in source
    for forbidden in (
        "ansible-playbook",
        "system-auth write ad",
        "vault_ad_join_password",
        "vault.yml",
        "domain_join",
    ):
        assert forbidden not in source
```

- [ ] **Step 2: Run the focused test module**

Run: `python -m pytest -q tests/alt_linux/test_bootstrap_register_integration.py`

Expected: PASS. If a forbidden string is present, stop and remove the domain/Vault behavior from bootstrap rather than weakening this test.

- [ ] **Step 3: Verify current safe-rerun semantics without changing the shared bootstrap**

Review the existing marker branch and retain these facts:

```bash
if [[ -f "${MARKER}" ]]; then
    if [[ ! -f "${REGISTER_MARKER}" ]]; then
        register_machine
    else
        echo "Machine already registered"
    fi
    exit 0
fi
```

Do not modify `bootstrap.sh`; this task documents and protects its present idempotence boundary so legacy `ai curl=` users are unaffected.

- [ ] **Step 4: Run the bootstrap and registration suites**

Run: `python -m pytest -q tests/alt_linux/test_bootstrap_register_integration.py tests/alt_linux/test_alt_bootstrap_register.py`

Expected: PASS.

- [ ] **Step 5: Commit the bootstrap boundary test**

```bash
git add tests/alt_linux/test_bootstrap_register_integration.py
git commit -m "test(alt): protect manual bootstrap boundary"
```

### Task 3: Document the controller handoff and keep ISO paths separate

**Files:**
- Modify: `docs/ALT_LINUX_AUTOINSTALL.md`
- Modify: `docs/runbooks/alt-manual-bootstrap-mvp.md`

**Interfaces:**
- Consumes: the registered machine UUID emitted by the controller registration process.
- Produces: an unambiguous operator decision: manual MVP bootstrap or ISO workflow, never both for one installation.

- [ ] **Step 1: Add a failing documentation assertion for ISO separation**

Extend `tests/alt_linux/test_manual_bootstrap_mvp_docs.py`:

```python
AUTOINSTALL_CONTEXT = ROOT / "docs" / "ALT_LINUX_AUTOINSTALL.md"


def test_autoinstall_context_links_to_manual_mvp_without_replacing_legacy_path() -> None:
    text = AUTOINSTALL_CONTEXT.read_text(encoding="utf-8")

    assert "Manual bootstrap MVP" in text
    assert "runbooks/alt-manual-bootstrap-mvp.md" in text
    assert "ai curl=http://192.168.100.17:8087/metadata/" in text
```

- [ ] **Step 2: Run the focused documentation test to verify it fails**

Run: `python -m pytest -q tests/alt_linux/test_manual_bootstrap_mvp_docs.py`

Expected: FAIL because the manual MVP link is absent from `docs/ALT_LINUX_AUTOINSTALL.md`.

- [ ] **Step 3: Add a small, explicit manual-MVP section to the autoinstall context**

Insert directly before `## Autoinstall boot`:

```markdown
## Manual bootstrap MVP

For pilot hardware installed manually, use [Manual bootstrap MVP](runbooks/alt-manual-bootstrap-mvp.md). This path begins only after ALT is installed and does not select, repartition or erase a disk. It is separate from both the legacy `ai curl=` autoinstall and managed ISO workflows.
```

In the runbook, add this controller handoff section:

```markdown
## Controller handoff

After registration is ready, an authorized controller operator runs preflight, preview and configuration. The workstation operator does not run Ansible, `system-auth`, or any domain join command.

```bash
sudo /usr/local/sbin/workstationctl preflight <machine-uuid>
sudo /usr/local/sbin/workstationctl configure preview <machine-uuid> --vars-file <request.json>
sudo /usr/local/sbin/workstationctl configure start <machine-uuid> --vars-file <request.json>
```
```

- [ ] **Step 4: Run documentation tests**

Run: `python -m pytest -q tests/alt_linux/test_manual_bootstrap_mvp_docs.py`

Expected: PASS.

- [ ] **Step 5: Commit the workflow separation documentation**

```bash
git add docs/ALT_LINUX_AUTOINSTALL.md docs/runbooks/alt-manual-bootstrap-mvp.md tests/alt_linux/test_manual_bootstrap_mvp_docs.py
git commit -m "docs(alt): separate manual bootstrap from ISO workflows"
```

### Task 4: Perform the non-destructive manual-MVP acceptance on a disposable workstation

**Files:**
- Modify: `docs/runbooks/alt-manual-bootstrap-mvp.md`

**Interfaces:**
- Consumes: one manually installed disposable ALT Workstation K 11.x VM or pilot machine, its registration UUID, and controller health endpoints.
- Produces: retained non-secret evidence that the manual bootstrap, controller registration and safe rerun completed before domain configuration is authorised.

- [ ] **Step 1: Add an acceptance checklist to the runbook**

Add this exact checklist:

```markdown
## Pilot acceptance

1. Confirm controller endpoints from the workstation:

   ```bash
   curl --noproxy '*' -fsS http://192.168.100.17:8087/health
   curl --noproxy '*' -fsS http://192.168.100.17:8088/health
   ```

2. Run the manual bootstrap command once and record only its exit status and registration UUID.
3. Run the same command a second time. It must exit zero and print either `Machine registration completed` or `Machine already registered`.
4. On the controller, verify the machine is ready:

   ```bash
   sudo /usr/local/sbin/workstationctl machines list
   sudo /usr/local/sbin/workstationctl preflight <machine-uuid>
   ```

5. Do not run `configure start` until preview shows the expected UUID and target IP.
```

- [ ] **Step 2: Run documentation tests after the checklist addition**

Run: `python -m pytest -q tests/alt_linux/test_manual_bootstrap_mvp_docs.py`

Expected: PASS.

- [ ] **Step 3: Run the full ALT regression suite before pilot use**

Run: `python -m pytest -q tests/alt_linux`

Expected: PASS with only already-accepted skips.

- [ ] **Step 4: Execute the checklist on a disposable VM or explicitly designated pilot machine**

Expected evidence:

```text
HTTP 200 or health JSON from ports 8087 and 8088
first bootstrap exit status: 0
second bootstrap exit status: 0
controller machine state: ready or awaiting_assignment after successful preflight
```

Do not include local administrator passwords, Vault contents, controller private keys, registration request files, or Ansible logs in the evidence.

- [ ] **Step 5: Commit the acceptance checklist and record the external pilot result outside Git**

```bash
git add docs/runbooks/alt-manual-bootstrap-mvp.md
git commit -m "docs(alt): add manual bootstrap pilot acceptance"
```

Record the pilot date, machine UUID, outcome and controller `run_id` in the approved operations system, not in the repository.

## Spec Coverage Review

- Manual ALT installation with local `osn-admin`: Tasks 1 and 4 document the prerequisite and ensure no password appears in automation.
- No password in Git/bootstrap/Ansible/Vault/request/logs: Task 1 provides the explicit operator boundary and documentation test; Task 2 prevents domain/Vault operations inside bootstrap.
- HTTP without SHA-256 for pilot only: Task 1 documents the accepted scope and trusted VLAN.
- Bootstrap prepares only `ansible`, SSH, sudo and registration: Task 2 locks the shared bootstrap boundary; Task 4 validates the resulting registration.
- Controller-only domain join and software installation: Tasks 1 and 3 document the controller handoff and command boundary.
- Existing managed ISO and legacy `ai curl=` paths unchanged: Tasks 2 and 3 explicitly prohibit source changes and retain the legacy documentation line.
- Safe repeated manual invocation: Tasks 2 and 4 protect and exercise the marker-based rerun behavior.

## Placeholder Scan

The plan contains no deferred implementation markers. Every code, command, path, test target and expected result required for implementation is written above.

## Type Consistency Review

The documentation contract uses the existing `bootstrap.sh`, `workstationctl preflight`, `workstationctl configure preview`, and `workstationctl configure start` interfaces. It introduces no new runtime types, endpoint names or command arguments.

## Execution Handoff

Plan complete and saved to `docs/superpowers/plans/2026-08-05-alt-manual-bootstrap-mvp.md`. Two execution options:

1. **Subagent-Driven (recommended)** — dispatch a fresh subagent per task and review between tasks.
2. **Inline Execution** — execute tasks in this session using executing-plans, with checkpoints for review.
