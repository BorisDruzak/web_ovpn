# Collection Lock Recovery Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use `superpowers:subagent-driven-development` (recommended) or `superpowers:executing-plans` to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Reclaim only orphaned collection locks so an interrupted Network Observer run cannot block future collections.

**Architecture:** `CollectLock` writes a PID plus Linux start-time token. On an exclusive-create collision it verifies the recorded owner: a matching live owner fails closed; a dead, PID-reused, malformed, or dead legacy owner is reclaimed and exclusive creation is retried once.

**Tech Stack:** Python 3 standard library and pytest.

## Global Constraints

- Do not change router, OpenVPN, source, secret, or timer configuration.
- Never allow two live collections into the critical section.
- New locks contain PID and Linux start-time token; matching live owner returns `collection already running`.
- Legacy PID-only locks are live only while their PID exists.
- Perform one bounded creation retry; do not loop indefinitely.
- Tests must mock process evidence instead of reading real `/proc`.

---

### Task 1: Implement safe orphaned-lock recovery

**Files:**

- Modify: `netctl/collect_lock.py`
- Modify: `tests/test_netctl_cli.py`

**Interfaces:**

- `CollectLock.__enter__() -> CollectLock` owns a fresh lock or raises `RuntimeError("collection already running")`.
- Internal helpers: `_process_start_time(pid: int) -> str | None`, `_read_owner(path: Path) -> tuple[int, str | None] | None`, `_is_live_owner(pid: int, start_time: str | None) -> bool`.

- [ ] **Step 1: Write failing tests**

Add focused tests with `monkeypatch` covering:

```python
def test_collect_lock_reclaims_absent_owner(tmp_path, monkeypatch):
    db_url = f"sqlite:///{tmp_path / 'netctl.sqlite'}"
    lock_path = collect_lock_path(db_url)
    lock_path.write_text("123 10", encoding="ascii")
    monkeypatch.setattr("netctl.collect_lock._process_start_time", lambda pid: None)

    with CollectLock(db_url):
        assert lock_path.read_text(encoding="ascii").startswith(f"{os.getpid()} ")


def test_collect_lock_rejects_matching_live_owner(tmp_path, monkeypatch):
    db_url = f"sqlite:///{tmp_path / 'netctl.sqlite'}"
    lock_path = collect_lock_path(db_url)
    lock_path.write_text("123 10", encoding="ascii")
    monkeypatch.setattr("netctl.collect_lock._process_start_time", lambda pid: "10")

    with pytest.raises(RuntimeError, match="collection already running"):
        CollectLock(db_url).__enter__()
```

Also cover PID reuse (`"123 10"` versus observed `"11"`), legacy PID-only records with present and absent owner, malformed record, and a retry collision that remains `collection already running`.

- [ ] **Step 2: Verify RED**

Run:

```powershell
pytest -q tests/test_netctl_cli.py -k "collect_lock"
```

Expected: stale and PID-reused records fail because the existing implementation treats every present lock file as live.

- [ ] **Step 3: Add minimal recovery implementation**

Implement strict parsing and process evidence:

```python
def _process_start_time(pid: int) -> str | None:
    try:
        fields = Path(f"/proc/{pid}/stat").read_text(encoding="ascii").split()
    except (FileNotFoundError, PermissionError, OSError, UnicodeDecodeError):
        return None
    return fields[21] if len(fields) > 21 and fields[21].isdigit() else None


def _is_live_owner(pid: int, start_time: str | None) -> bool:
    observed = _process_start_time(pid)
    return observed is not None and (start_time is None or observed == start_time)
```

Write new records as `"<pid> <start_time>\n"`. If a local start-time cannot be read, fail closed. On a collision reclaim only owners for which `_is_live_owner()` is false, then retry `O_EXCL` once.

- [ ] **Step 4: Verify GREEN**

Run:

```powershell
pytest -q tests/test_netctl_cli.py -k "collect_lock"
```

Expected: matching live owner is rejected; dead, reused, legacy-dead, and malformed records are reclaimed.

- [ ] **Step 5: Run regression checks**

```powershell
pytest -q tests/test_netctl_cli.py tests/test_netctl_runtime_writer.py
git diff --check
```

Expected: tests pass and the diff check has no output.

- [ ] **Step 6: Commit**

```powershell
git add netctl/collect_lock.py tests/test_netctl_cli.py
git commit -m "fix: recover orphaned collection locks"
```

## Deployment verification

1. Merge the verified branch to `main` and deploy the exact commit using an explicit installer source directory.
2. Keep `netctl-collect.timer` disabled throughout deployment.
3. Confirm one manual hEX collection succeeds after deployment without changing RouterOS configuration.
