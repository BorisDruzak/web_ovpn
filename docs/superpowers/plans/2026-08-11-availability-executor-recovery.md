# Availability Executor Recovery Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Recover a CIDR availability run from one transient parallel worker failure while retaining fail-closed persistence and a reusable collection lock.

**Architecture:** The normal path remains a bounded 64-worker bucket. An unexpected parallel worker error causes exactly one bounded sequential retry over the same deterministic targets. Only a completed retry publishes results; public output remains sanitized while the journal receives allow-listed phase and error-class fields.

**Tech Stack:** Python 3, `concurrent.futures`, SQLite, pytest, systemd journal.

## Global Constraints

- Do not expose targets, command output, exception messages, credentials, or raw sockets through CLI/API output.
- Never publish partial availability results after an unrecoverable executor failure.
- Retain 64 workers, one-second per-method bounds, and the 90-second bucket deadline.
- Do not alter network-device configuration.

---

### Task 1: Add failing regressions

**Files:**
- Modify: `tests/test_netctl_availability.py`
- Modify: `tests/test_netctl_cli.py`

**Interfaces:**
- Consumes: `_collect_bucket(targets, executor)` and `CollectLock(db_url)`.
- Produces: coverage for transient worker recovery, persistent failure, safe logging, and unlock after failed availability collection.

- [ ] **Step 1: Write failing tests**

```python
def test_collect_bucket_retries_a_transient_parallel_worker_error(monkeypatch):
    result, error = availability._collect_bucket(targets, executor)
    assert error == ""
    assert len(result) == len(targets)

def test_collect_bucket_keeps_executor_error_when_retry_fails(monkeypatch):
    result, error = availability._collect_bucket(targets, executor)
    assert result is None
    assert error == "executor_error"

def test_availability_failure_releases_collect_lock(tmp_path, monkeypatch):
    assert cli.dispatch(parser.parse_args(["--db", db_url, "availability", "collect"]))[0] == 1
    with CollectLock(db_url):
        pass
```

- [ ] **Step 2: Verify red**

Run: `pytest tests/test_netctl_availability.py -k "transient_parallel_worker or retry_fails" tests/test_netctl_cli.py -k "availability_failure_releases" -q`

Expected: failure because no retry exists.

### Task 2: Add bounded recovery

**Files:**
- Modify: `netctl/availability.py`
- Test: `tests/test_netctl_availability.py`

**Interfaces:**
- Consumes: `ProbeTarget`, `ProbeExecutor`, `_collect_bucket`.
- Produces: complete results after a successful retry or existing sanitized failure strings.

- [ ] **Step 1: Implement the minimal helper and retry path**

```python
parallel, error = _collect_bucket_once(targets, executor, parallel=True)
if not error:
    return parallel, ""
retry, retry_error = _collect_bucket_once(targets, executor, parallel=False)
if not retry_error:
    return retry, ""
return None, retry_error
```

The helper must never log targets or raw exception text. Log only phase and an allow-listed class.

- [ ] **Step 2: Verify green**

Run: `pytest tests/test_netctl_availability.py -k "transient_parallel_worker or retry_fails" tests/test_netctl_cli.py -k "availability_failure_releases" -q`

Expected: PASS.

- [ ] **Step 3: Run focused suites**

Run: `pytest tests/test_netctl_availability.py tests/test_netctl_cli.py -q`

Expected: PASS.

### Task 3: Deploy and operationally verify

**Files:**
- Deploy verified files from this worktree to `/opt/openvpn-web`.

**Interfaces:**
- Consumes: committed implementation and current Netctl units.
- Produces: successful timer collection, no stale lock, and diagnostics only for persistent availability faults.

- [ ] **Step 1: Deploy the verified application files using the established server procedure.**
- [ ] **Step 2: Run `sudo /usr/local/sbin/netctl --json availability collect` and verify sanitized output.**
- [ ] **Step 3: Verify `netctl-collect.timer` is active and no lock remains after collection.**
