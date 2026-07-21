# ALT OR-3P2 Machine Registry Lifecycle Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Add audited machine-registration archival and register-only re-registration while preventing assignments, active jobs, interrupted archive cleanup, or stale pending processors from creating conflicting controller state.

**Architecture:** Add focused lifecycle, archive-persistence, archive-service, and registration-admission boundaries under the existing `alt_deploy` package. Use registration generations plus a durable archive commit marker to provide logical atomicity across `/srv/alt-deploy` and `/var/lib/alt-deploy`; all mutating lifecycle operations share `workstationctl.lock`. Keep long-running SSH/Ansible work outside the lock, and make the standalone API programs thin adapters over the installed control package.

**Tech Stack:** Python 3.11+, stdlib dataclasses, pathlib, hashlib, secrets, fcntl, stat, pwd, argparse, `http.server`, Bash, curl, systemd sandboxing, pytest, synthetic filesystem tests, fake PATH tests, and existing Ansible syntax checks.

## Global Constraints

- Base implementation branch: `feat/alt-or3p2-machine-registry-lifecycle-20260721` at design commit `7d2effc3b9dc4e5a69c8aba2ae1c61ca8b23c685`.
- Approved specification: `docs/superpowers/specs/2026-07-21-alt-or3p2-machine-registry-lifecycle-design.md`.
- Use TDD and commit after each independently reviewable task.
- Re-registration is initiated locally with `sudo alt-bootstrap-register`; the controller archive command never contacts a workstation.
- Archive every matching active registration record from `pending`, `ready`, and `failed` in one operation.
- Preview is read-only. Apply requires EUID `0` and a validated non-empty `--reason` of at most 500 Unicode code points with no control characters.
- Assigned machines fail with `machine_assigned`; active `queued` or `running` jobs fail with `machine_busy` and expose only `job_id`, `state`, and `stage`.
- Existing job history, logs, assignments, Vault state, SSH identity, known hosts, and ISO-derived assets remain unchanged.
- Source registration bytes are preserved exactly in the protected archive; do not reserialize archived records.
- Archive state lives only under `/var/lib/alt-deploy/machine-archives`, mode `0700`, owned by `altserver:altserver`; archive files use mode `0600`.
- `manifest.json` and `commit.json` are immutable after durable creation. Mutable cleanup phase remains only in `transaction.json`.
- Archive apply holds the existing global lock continuously from authoritative recheck through copy, commit, source cleanup, and final archive rename.
- No lock is held during SSH wait, host-key scan, Ansible ping, or preflight.
- A committed archive hides only its exact registration generations. A later generation with a new `registration_id` remains visible.
- Legacy records without `registration_id` use `legacy-sha256:<digest of exact source bytes>` and are never rewritten merely to add an identifier.
- There is no archive restore, assignment release, reassignment, job deletion, or worker cancellation in OR-3P2.
- Do not access controller `192.168.100.17` or reference workstation `192.168.101.111` during implementation or CI.
- Do not install OR-3P2 on the live controller until OR-3P3 backup/restore is approved and executed.
- Use only synthetic identities, temporary roots, fake commands, loopback-only HTTP tests, and CI-safe Vault fixtures.
- Remove temporary CI workflows and patch helpers before marking the PR Ready for review.
- Do not merge without explicit user confirmation.

## File Map

**Create production:**

- `deploy/alt-linux/control/alt_deploy/machine_lifecycle.py` — normalized physical identity, registration generation parsing, safe active-record discovery, lifecycle snapshots, blockers, and committed-generation lookup.
- `deploy/alt-linux/control/alt_deploy/machine_archive.py` — durable archive repository, transaction state machine, preview/apply service, reason validation, operator audit, cleanup resume, and idempotency.
- `deploy/alt-linux/control/alt_deploy/registration_admission.py` — shared `/register` admission and atomic pending-record creation.
- `deploy/alt-linux/bootstrap/alt-bootstrap-register` — workstation-side registration-only helper.

**Modify production:**

- `deploy/alt-linux/control/alt_deploy/config.py`
- `deploy/alt-linux/control/alt_deploy/locks.py`
- `deploy/alt-linux/control/alt_deploy/registry.py`
- `deploy/alt-linux/control/alt_deploy/cli.py`
- `deploy/alt-linux/control/alt_deploy/controller_readiness.py`
- `deploy/alt-linux/api/register_api.py`
- `deploy/alt-linux/api/process_pending.py`
- `deploy/alt-linux/bootstrap/bootstrap.sh`
- `deploy/alt-linux/install-control-plane-lib.sh`
- `deploy/alt-linux/systemd/alt-deploy-register.service`
- `deploy/alt-linux/systemd/alt-deploy-process.service`

**Create tests/support:**

- `tests/alt_linux/support/lifecycle_fixtures.py`
- `tests/alt_linux/test_machine_lifecycle.py`
- `tests/alt_linux/test_machine_archive_repository.py`
- `tests/alt_linux/test_machine_archive_service.py`
- `tests/alt_linux/test_machine_archive_cli.py`
- `tests/alt_linux/test_registration_admission.py`
- `tests/alt_linux/test_register_api.py`
- `tests/alt_linux/test_alt_bootstrap_register.py`

**Modify tests:**

- `tests/alt_linux/support/controller_sandbox.py`
- `tests/alt_linux/support/installer_sandbox.py`
- `tests/alt_linux/test_registry_cli.py`
- `tests/alt_linux/test_process_pending.py`
- `tests/alt_linux/test_install_assets.py`
- `tests/alt_linux/test_or3p1_controller_readiness.py`
- `tests/alt_linux/test_or3p1_controller_readiness_failures.py`
- `tests/alt_linux/test_or3p1_installer.py`
- `tests/alt_linux/test_installer_registration_permissions.py`

**Create/modify documentation:**

- Create: `docs/ALT_OR3P2_MACHINE_REGISTRY_LIFECYCLE.md`
- Modify: `deploy/alt-linux/README.md`
- Modify: `docs/ALT_WORKSTATION_PROVISIONING_CONTEXT.md`
- Modify: `docs/ALT_WORKSTATION_PROVISIONING_NEXT_STEPS.md`
- Modify: `docs/ALT_OR3P1_PILOT_ROLLOUT.md`

---

### Task 1: Add lifecycle paths, safe lock opening, generation identity, and test fixtures

**Files:**

- Modify: `deploy/alt-linux/control/alt_deploy/config.py`
- Modify: `deploy/alt-linux/control/alt_deploy/locks.py`
- Create: `deploy/alt-linux/control/alt_deploy/machine_lifecycle.py`
- Create: `tests/alt_linux/support/lifecycle_fixtures.py`
- Modify: `tests/alt_linux/support/controller_sandbox.py`
- Create: `tests/alt_linux/test_machine_lifecycle.py`

**Interfaces:**

- Consumes: existing `Settings.state_root`, `Settings.registration_root`, `ControlError`, `AssignmentRepository`, `JobRepository`, and `ACTIVE_STATES`.
- Produces:
  - `Settings.machine_archives_dir -> Path`.
  - `Settings.archive_transactions_dir -> Path`.
  - `RegistrationGeneration(value: str, legacy: bool)`.
  - `RegistrationCandidate(path, registration_state, machine_key, machine_uuid, hostname, ip, mac, registered_at, status, generation, raw_bytes, payload)`.
  - `MachineIdentity(machine_key: str, machine_uuid: str, mac: str)`.
  - `MachineLifecycleSnapshot(identity, candidates, assignment, active_job, completed_archive_id, cleanup_archive_id)`.
  - `registration_generation(payload, raw_bytes) -> RegistrationGeneration`.
  - `load_registration_candidate(path, registration_state) -> RegistrationCandidate`.
  - `exclusive_lock(path)` that refuses symlinks and non-regular lock objects.

- [ ] **Step 1: Write failing path-property and generation tests**

Add these tests to `tests/alt_linux/test_machine_lifecycle.py`:

```python
from alt_deploy.machine_lifecycle import registration_generation


def test_settings_derive_archive_paths(controller_sandbox) -> None:
    settings = controller_sandbox.settings
    assert settings.machine_archives_dir == settings.state_root / "machine-archives"
    assert settings.archive_transactions_dir == (
        settings.state_root / "machine-archives" / ".transactions"
    )


def test_registration_generation_prefers_valid_registration_id() -> None:
    result = registration_generation(
        {"registration_id": "reg-0123456789abcdef0123456789abcdef"},
        b'{"registration_id":"reg-0123456789abcdef0123456789abcdef"}\n',
    )
    assert result.value == "reg-0123456789abcdef0123456789abcdef"
    assert result.legacy is False


def test_registration_generation_uses_exact_legacy_bytes() -> None:
    first = registration_generation({"machine_key": "a"}, b'{"machine_key":"a"}\n')
    second = registration_generation({"machine_key": "a"}, b'{ "machine_key": "a" }\n')
    assert first.value.startswith("legacy-sha256:")
    assert second.value.startswith("legacy-sha256:")
    assert first.value != second.value
    assert first.legacy is True
```

Run:

```bash
python -m pytest -q tests/alt_linux/test_machine_lifecycle.py \
  -k 'settings_derive_archive_paths or registration_generation'
```

Expected: FAIL because the properties and module do not exist.

- [ ] **Step 2: Add derived `Settings` properties without breaking existing constructors**

Append to `Settings` rather than adding required dataclass constructor fields:

```python
@property
def machine_archives_dir(self) -> Path:
    return self.state_root / "machine-archives"

@property
def archive_transactions_dir(self) -> Path:
    return self.machine_archives_dir / ".transactions"
```

This preserves every existing `Settings(...)` fixture.

- [ ] **Step 3: Add generation and candidate dataclasses**

Create `machine_lifecycle.py` with these public definitions:

```python
from __future__ import annotations

import hashlib
import json
import os
import re
import stat
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from .errors import ControlError

REGISTRATION_ID_RE = re.compile(r"^reg-[0-9a-f]{32}$")
ACTIVE_REGISTRATION_STATES = ("pending", "ready", "failed")


@dataclass(frozen=True)
class RegistrationGeneration:
    value: str
    legacy: bool


@dataclass(frozen=True)
class MachineIdentity:
    machine_key: str
    machine_uuid: str
    mac: str


@dataclass(frozen=True)
class RegistrationCandidate:
    path: Path
    registration_state: str
    machine_key: str
    machine_uuid: str
    hostname: str
    ip: str
    mac: str
    registered_at: str
    status: str
    generation: RegistrationGeneration
    raw_bytes: bytes
    payload: dict[str, Any]


def registration_generation(
    payload: dict[str, Any],
    raw_bytes: bytes,
) -> RegistrationGeneration:
    value = str(payload.get("registration_id") or "").strip().lower()
    if value:
        if not REGISTRATION_ID_RE.fullmatch(value):
            raise ControlError(
                code="machine_record_invalid",
                message="Registration record has an invalid generation identifier",
                exit_code=4,
            )
        return RegistrationGeneration(value=value, legacy=False)
    digest = hashlib.sha256(raw_bytes).hexdigest()
    return RegistrationGeneration(value=f"legacy-sha256:{digest}", legacy=True)
```

Implement `load_registration_candidate()` with `lstat`, regular-file validation, `os.open(..., O_NOFOLLOW)` when available, `fstat`, bounded full read, JSON-object validation, normalized identity, and directory-supplied `registration_state`. Do not require payload `status` to equal the directory name.

- [ ] **Step 4: Add exact candidate safety tests**

Add named tests with these assertions:

```python
def test_ready_directory_accepts_awaiting_assignment_status(tmp_path: Path) -> None:
    path = write_registration(
        tmp_path,
        state="ready",
        status="awaiting_assignment",
        registration_id="reg-11111111111111111111111111111111",
    )
    candidate = load_registration_candidate(path, "ready")
    assert candidate.registration_state == "ready"
    assert candidate.status == "awaiting_assignment"


def test_candidate_rejects_symlink(tmp_path: Path) -> None:
    target = write_registration(tmp_path, state="ready")
    link = tmp_path / "ready" / "linked.json"
    link.symlink_to(target)
    with pytest.raises(ControlError) as exc:
        load_registration_candidate(link, "ready")
    assert exc.value.code == "machine_record_unsafe"


def test_candidate_rejects_non_object_json(tmp_path: Path) -> None:
    path = tmp_path / "ready" / "bad.json"
    path.parent.mkdir(parents=True)
    path.write_text("[]\n", encoding="utf-8")
    with pytest.raises(ControlError) as exc:
        load_registration_candidate(path, "ready")
    assert exc.value.code == "machine_record_invalid"
```

Also test invalid `registration_id`, missing identity, UUID normalization, MAC normalization, and byte preservation.

- [ ] **Step 5: Harden the shared lock against symlinks and non-regular files**

Replace `Path.open("a+")` with descriptor-based opening:

```python
flags = os.O_RDWR | os.O_CREAT
if hasattr(os, "O_NOFOLLOW"):
    flags |= os.O_NOFOLLOW
try:
    descriptor = os.open(path, flags, 0o600)
except OSError as exc:
    raise ControlError(
        code="controller_lock_unsafe",
        message="Controller lifecycle lock cannot be opened safely",
        exit_code=6,
    ) from exc

with os.fdopen(descriptor, "a+", encoding="utf-8") as handle:
    metadata = os.fstat(handle.fileno())
    if not stat.S_ISREG(metadata.st_mode):
        raise ControlError(
            code="controller_lock_unsafe",
            message="Controller lifecycle lock is not a regular file",
            exit_code=6,
        )
    os.fchmod(handle.fileno(), 0o600)
    fcntl.flock(handle.fileno(), fcntl.LOCK_EX)
    try:
        yield
    finally:
        fcntl.flock(handle.fileno(), fcntl.LOCK_UN)
```

Add tests proving a symlink lock fails before the body executes and a regular lock remains mode `0600`.

- [ ] **Step 6: Add reusable synthetic lifecycle fixtures**

Create `tests/alt_linux/support/lifecycle_fixtures.py` with:

```python
TEST_MACHINE_UUID = "53b03180-5d78-11f0-bd95-f027db877a00"
TEST_MACHINE_MAC = "c0:9b:f4:62:54:e5"
TEST_REGISTRATION_ID = "reg-11111111111111111111111111111111"


def registration_payload(
    *,
    machine_uuid: str = TEST_MACHINE_UUID,
    registration_id: str | None = TEST_REGISTRATION_ID,
    status: str = "pending",
    registered_at: str = "2026-07-21T12:00:00+00:00",
) -> dict[str, object]:
    payload: dict[str, object] = {
        "machine_key": machine_uuid,
        "uuid": machine_uuid,
        "hostname": "alt-lifecycle-test",
        "ip": "192.0.2.56",
        "mac": TEST_MACHINE_MAC,
        "registered_at": registered_at,
        "status": status,
    }
    if registration_id is not None:
        payload["registration_id"] = registration_id
    return payload
```

Add `write_registration(settings, state, payload, filename=None) -> Path` that writes deterministic UTF-8 JSON mode `0600` and returns the path. Extend `ControllerSandbox.register_machine()` with optional `registration_id` while preserving existing call sites.

- [ ] **Step 7: Run focused and regression tests, then commit**

```bash
python -m pytest -q \
  tests/alt_linux/test_machine_lifecycle.py \
  tests/alt_linux/test_provision_preview.py \
  tests/alt_linux/test_provision_start.py \
  tests/alt_linux/test_registry_cli.py

git add \
  deploy/alt-linux/control/alt_deploy/config.py \
  deploy/alt-linux/control/alt_deploy/locks.py \
  deploy/alt-linux/control/alt_deploy/machine_lifecycle.py \
  tests/alt_linux/support/lifecycle_fixtures.py \
  tests/alt_linux/support/controller_sandbox.py \
  tests/alt_linux/test_machine_lifecycle.py

git commit -m "feat: add ALT registration lifecycle primitives"
```

Expected: all selected tests PASS.

---

### Task 2: Implement protected archive persistence and durable transaction mechanics

**Files:**

- Create: `deploy/alt-linux/control/alt_deploy/machine_archive.py`
- Create: `tests/alt_linux/test_machine_archive_repository.py`

**Interfaces:**

- Consumes: `Settings.machine_archives_dir`, `Settings.archive_transactions_dir`, `RegistrationCandidate`, `ensure_private_dir`, and `ControlError`.
- Produces:
  - `ArchiveRecordPlan(state, source_path, archive_name, generation, size, sha256)`.
  - `ArchiveTransaction(archive_id, directory, phase, machine_key, machine_uuid, record_plans)`.
  - `MachineArchiveRepository.allocate_archive_id() -> str`.
  - `MachineArchiveRepository.prepare(...) -> ArchiveTransaction`.
  - `MachineArchiveRepository.copy_and_verify(transaction, candidates, manifest) -> ArchiveTransaction`.
  - `MachineArchiveRepository.commit(transaction) -> ArchiveTransaction`.
  - `MachineArchiveRepository.cleanup_sources(transaction) -> ArchiveTransaction`.
  - `MachineArchiveRepository.finalize(transaction) -> Path`.
  - `MachineArchiveRepository.find_committed_for_generation(generation) -> str | None`.
  - `MachineArchiveRepository.find_latest_for_machine(machine_key) -> dict[str, object] | None`.

- [ ] **Step 1: Write failing repository-layout and permission tests**

```python
def test_prepare_creates_private_transaction_without_commit(
    tmp_path: Path,
    controller_sandbox,
) -> None:
    repository = MachineArchiveRepository(controller_sandbox.settings)
    transaction = repository.prepare(
        archive_id="archive-20260721T120000Z-11111111",
        machine_key=TEST_MACHINE_UUID,
        machine_uuid=TEST_MACHINE_UUID,
        planned_sources=[("ready", Path("/synthetic/ready.json"))],
    )
    assert transaction.phase == "prepared"
    assert stat.S_IMODE(transaction.directory.stat().st_mode) == 0o700
    assert (transaction.directory / "transaction.json").is_file()
    assert not (transaction.directory / "commit.json").exists()


def test_archive_root_rejects_symlink(controller_sandbox) -> None:
    settings = controller_sandbox.settings
    target = settings.state_root / "elsewhere"
    target.mkdir(parents=True)
    settings.machine_archives_dir.parent.mkdir(parents=True, exist_ok=True)
    settings.machine_archives_dir.symlink_to(target, target_is_directory=True)
    with pytest.raises(ControlError) as exc:
        MachineArchiveRepository(settings).list_committed()
    assert exc.value.code == "machine_archive_invalid"
```

Run:

```bash
python -m pytest -q tests/alt_linux/test_machine_archive_repository.py
```

Expected: FAIL because `MachineArchiveRepository` does not exist.

- [ ] **Step 2: Add immutable and mutable archive schemas**

Define constants and dataclasses:

```python
ARCHIVE_SCHEMA_VERSION = 1
ARCHIVE_ID_RE = re.compile(r"^archive-\d{8}T\d{6}Z-[0-9a-f]{8}$")
TRANSACTION_PHASES = {"prepared", "copied", "committed", "cleaned", "aborted"}


@dataclass(frozen=True)
class ArchiveRecordPlan:
    state: str
    source_path: Path
    archive_name: str
    generation: str
    size: int
    sha256: str


@dataclass(frozen=True)
class ArchiveTransaction:
    archive_id: str
    directory: Path
    phase: str
    machine_key: str
    machine_uuid: str
    record_plans: tuple[ArchiveRecordPlan, ...]
```

Use one canonical archive filename per state: `pending.json`, `ready.json`, `failed.json`. Duplicate candidates for the same state are rejected before persistence.

- [ ] **Step 3: Add durable no-follow write helpers**

Inside `machine_archive.py`, implement focused private helpers:

```python
def _fsync_directory(path: Path) -> None:
    flags = os.O_RDONLY
    if hasattr(os, "O_DIRECTORY"):
        flags |= os.O_DIRECTORY
    descriptor = os.open(path, flags)
    try:
        os.fsync(descriptor)
    finally:
        os.close(descriptor)


def _durable_write_json(path: Path, payload: Mapping[str, object]) -> None:
    temporary = path.parent / f".{path.name}.{os.getpid()}.tmp"
    encoded = (
        json.dumps(dict(payload), ensure_ascii=False, indent=2) + "\n"
    ).encode("utf-8")
    flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL
    if hasattr(os, "O_NOFOLLOW"):
        flags |= os.O_NOFOLLOW
    descriptor = os.open(temporary, flags, 0o600)
    try:
        with os.fdopen(descriptor, "wb", closefd=False) as handle:
            handle.write(encoded)
            handle.flush()
            os.fsync(handle.fileno())
        os.replace(temporary, path)
        _fsync_directory(path.parent)
    finally:
        try:
            os.close(descriptor)
        except OSError:
            pass
        temporary.unlink(missing_ok=True)
```

Implement exact-byte copying with source `O_NOFOLLOW`, destination `O_EXCL|O_NOFOLLOW`, SHA-256 during copy, destination fsync, reopen verification, and directory fsync.

- [ ] **Step 4: Implement transaction phase writes and immutable commit evidence**

Required payload shapes:

```python
transaction_payload = {
    "schema_version": ARCHIVE_SCHEMA_VERSION,
    "archive_id": archive_id,
    "machine_key": machine_key,
    "machine_uuid": machine_uuid,
    "phase": phase,
    "planned_sources": planned_sources,
    "updated_at": utc_now(),
}

commit_payload = {
    "schema_version": ARCHIVE_SCHEMA_VERSION,
    "archive_id": archive_id,
    "machine_uuid": machine_uuid,
    "machine_key": machine_key,
    "registration_generations": [plan.generation for plan in plans],
    "committed_at": utc_now(),
    "manifest_sha256": manifest_digest,
}
```

`manifest.json` is written once after all copied records verify. `commit.json` uses exclusive creation and is never replaced. A pre-existing commit with different bytes is `machine_archive_invalid`.

- [ ] **Step 5: Add copy, commit, cleanup, and finalization tests**

Add tests proving:

```python
def test_copy_preserves_exact_bytes_and_manifest_hash(...):
    original = source.read_bytes()
    copied = transaction.directory / "records" / "ready.json"
    assert copied.read_bytes() == original
    entry = json.loads((transaction.directory / "manifest.json").read_text())["records"][0]
    assert entry["size"] == len(original)
    assert entry["sha256"] == hashlib.sha256(original).hexdigest()


def test_commit_marker_makes_generation_discoverable(...):
    committed = repository.commit(transaction)
    assert committed.phase == "committed"
    assert repository.find_committed_for_generation(TEST_REGISTRATION_ID) == transaction.archive_id


def test_cleanup_refuses_newer_generation_at_same_source_path(...):
    repository.commit(transaction)
    write_registration(..., registration_id="reg-22222222222222222222222222222222")
    with pytest.raises(ControlError) as exc:
        repository.cleanup_sources(transaction)
    assert exc.value.code == "machine_archive_cleanup_required"
    assert source.is_file()
```

Also prove malformed `transaction.json`, malformed `manifest.json`, symlinked commit, wrong manifest hash, unexpected archive child type, and final rename within the archive filesystem fail closed.

- [ ] **Step 6: Run and commit**

```bash
python -m pytest -q tests/alt_linux/test_machine_archive_repository.py

git add \
  deploy/alt-linux/control/alt_deploy/machine_archive.py \
  tests/alt_linux/test_machine_archive_repository.py

git commit -m "feat: add durable ALT machine archive storage"
```

Expected: PASS.

---

### Task 3: Add lifecycle guard, blockers, active-generation discovery, and registry filtering

**Files:**

- Modify: `deploy/alt-linux/control/alt_deploy/machine_lifecycle.py`
- Modify: `deploy/alt-linux/control/alt_deploy/registry.py`
- Modify: `tests/alt_linux/test_machine_lifecycle.py`
- Modify: `tests/alt_linux/test_registry_cli.py`

**Interfaces:**

- Consumes: `MachineArchiveRepository`, `AssignmentRepository`, `JobRepository.active_for_machine()`, and registration candidate primitives.
- Produces:
  - `MachineLifecycleGuard.discover(identifier) -> tuple[RegistrationCandidate, ...]`.
  - `MachineLifecycleGuard.snapshot_for_removal(identifier) -> MachineLifecycleSnapshot`.
  - `MachineLifecycleGuard.assert_removal_allowed(snapshot) -> None`.
  - `MachineLifecycleGuard.generation_is_committed(generation) -> bool`.
  - `MachineLifecycleGuard.assert_generation_active(candidate) -> None`.
  - generation-aware `MachineRepository.list()` and `get()`.

- [ ] **Step 1: Write failing discovery and blocker tests**

```python
def test_discovery_collects_all_states_for_same_machine(controller_sandbox) -> None:
    write_registration(controller_sandbox.settings, "pending", registration_payload(
        registration_id="reg-11111111111111111111111111111111"
    ))
    write_registration(controller_sandbox.settings, "ready", registration_payload(
        registration_id="reg-22222222222222222222222222222222"
    ))
    write_registration(controller_sandbox.settings, "failed", registration_payload(
        registration_id="reg-33333333333333333333333333333333"
    ))
    snapshot = MachineLifecycleGuard(controller_sandbox.settings).snapshot_for_removal(
        TEST_MACHINE_UUID
    )
    assert [candidate.registration_state for candidate in snapshot.candidates] == [
        "pending", "ready", "failed"
    ]


def test_assigned_machine_is_blocked(controller_sandbox) -> None:
    candidate = write_registration(...)
    AssignmentRepository(controller_sandbox.settings).write(TEST_MACHINE_UUID, assignment_payload())
    guard = MachineLifecycleGuard(controller_sandbox.settings)
    snapshot = guard.snapshot_for_removal(TEST_MACHINE_UUID)
    with pytest.raises(ControlError) as exc:
        guard.assert_removal_allowed(snapshot)
    assert exc.value.code == "machine_assigned"


def test_busy_machine_exposes_safe_job_fields_only(controller_sandbox) -> None:
    job = JobRepository(controller_sandbox.settings).create(provision_request())
    snapshot = MachineLifecycleGuard(controller_sandbox.settings).snapshot_for_removal(
        TEST_MACHINE_UUID
    )
    with pytest.raises(ControlError) as exc:
        MachineLifecycleGuard(controller_sandbox.settings).assert_removal_allowed(snapshot)
    assert exc.value.code == "machine_busy"
    assert set(exc.value.details) == {"job_id", "state", "stage"}
    assert exc.value.details["job_id"] == job.job_id
```

Expected: FAIL because the guard methods do not exist.

- [ ] **Step 2: Implement two-pass candidate discovery**

Use this algorithm exactly:

1. Normalize the requested identifier to lowercase.
2. Inspect exact filenames `<state>/<identifier>.json`; an unsafe or malformed exact path fails closed.
3. Safely scan regular `*.json` files in all three states; skip malformed non-exact files because they cannot be attributed to the selected machine.
4. Select valid records whose normalized `machine_key` or resolved physical UUID equals the requested identifier.
5. Resolve one canonical `MachineIdentity` from the selected candidates.
6. Include every other valid record matching that physical identity, even under a non-canonical filename.
7. Reject conflicts in UUID, machine key, MAC, generation, or multiple records in one state with `machine_identity_conflict`.
8. Sort candidates in state order `pending`, `ready`, `failed`.

Do not reuse `MachineRepository.list()` inside the guard; that would create a circular dependency after registry filtering is added.

- [ ] **Step 3: Implement blockers and malformed-store behavior**

```python
def assert_removal_allowed(self, snapshot: MachineLifecycleSnapshot) -> None:
    if snapshot.assignment is not None:
        raise ControlError(
            code="machine_assigned",
            message="Machine has an active assignment",
            exit_code=4,
            details={"machine_uuid": snapshot.identity.machine_uuid},
        )
    if snapshot.active_job is not None:
        raise ControlError(
            code="machine_busy",
            message="Machine has an active provision job",
            exit_code=4,
            details={
                "job_id": snapshot.active_job.job_id,
                "state": snapshot.active_job.state,
                "stage": snapshot.active_job.stage,
            },
        )
    if snapshot.cleanup_archive_id is not None:
        raise ControlError(
            code="machine_archive_cleanup_required",
            message="Machine archive cleanup is incomplete",
            exit_code=4,
            details={"archive_id": snapshot.cleanup_archive_id},
        )
```

Malformed real jobs and malformed assignment/archive state propagate as fail-closed `ControlError`; never convert them to an empty blocker result.

- [ ] **Step 4: Filter exact committed generations in `MachineRepository`**

Refactor record loading to obtain exact bytes and generation identity before selection. Exclude a record only when:

```python
archive_repository.find_committed_for_generation(
    candidate.generation.value
) is not None
```

Then construct `MachineRecord` from `candidate.payload`, retaining the existing newest-record sort and assignment/job overlays. A committed old generation plus an active new generation must return the new record.

- [ ] **Step 5: Add committed-generation registry tests**

```python
def test_committed_old_generation_is_hidden(settings) -> None:
    old = write_registration(settings, "ready", registration_payload(
        registration_id="reg-11111111111111111111111111111111"
    ))
    commit_generation(settings, generation="reg-11111111111111111111111111111111")
    assert MachineRepository(settings).list() == []


def test_new_generation_is_visible_after_old_archive(settings) -> None:
    commit_generation(settings, generation="reg-11111111111111111111111111111111")
    write_registration(settings, "pending", registration_payload(
        registration_id="reg-22222222222222222222222222222222"
    ))
    machines = MachineRepository(settings).list()
    assert len(machines) == 1
    assert machines[0].raw["registration_id"] == (
        "reg-22222222222222222222222222222222"
    )
```

Also test legacy fingerprints, malformed archive state, assigned status overlay, malformed-job fail-closed behavior, and current newest-duplicate precedence.

- [ ] **Step 6: Run and commit**

```bash
python -m pytest -q \
  tests/alt_linux/test_machine_lifecycle.py \
  tests/alt_linux/test_registry_cli.py

git add \
  deploy/alt-linux/control/alt_deploy/machine_lifecycle.py \
  deploy/alt-linux/control/alt_deploy/registry.py \
  tests/alt_linux/test_machine_lifecycle.py \
  tests/alt_linux/test_registry_cli.py

git commit -m "feat: enforce ALT machine lifecycle blockers"
```

Expected: PASS.

---

### Task 4: Implement archive preview, apply, audit, recovery, and idempotency

**Files:**

- Modify: `deploy/alt-linux/control/alt_deploy/machine_archive.py`
- Create: `tests/alt_linux/test_machine_archive_service.py`

**Interfaces:**

- Consumes: `MachineLifecycleGuard`, `MachineArchiveRepository`, `exclusive_lock`, and lifecycle dataclasses.
- Produces:
  - `ArchivePreview.to_public_dict() -> dict[str, object]`.
  - `ArchiveResult.to_public_dict() -> dict[str, object]`.
  - `MachineArchiveService.preview(identifier) -> ArchivePreview`.
  - `MachineArchiveService.apply(identifier, reason, operator_env=None) -> ArchiveResult`.
  - `validate_archive_reason(reason) -> str`.
  - `resolve_operator_identity(environ) -> tuple[int, str]`.

- [ ] **Step 1: Write failing preview and success-path tests**

```python
def test_preview_is_read_only_and_reports_all_states(controller_sandbox) -> None:
    write_registration(... state="pending" ...)
    write_registration(... state="failed" ...)
    before = snapshot_tree(controller_sandbox.root)
    preview = MachineArchiveService(controller_sandbox.settings).preview(TEST_MACHINE_UUID)
    assert preview.to_public_dict() == {
        "machine_uuid": TEST_MACHINE_UUID,
        "machine_key": TEST_MACHINE_UUID,
        "source_states": ["pending", "failed"],
        "record_count": 2,
        "assignment_present": False,
        "active_job": None,
        "action": "archive_registration_records",
    }
    assert snapshot_tree(controller_sandbox.root) == before


def test_apply_archives_exact_bytes_and_removes_active_records(controller_sandbox) -> None:
    source = write_registration(... state="ready" ...)
    original = source.read_bytes()
    result = MachineArchiveService(controller_sandbox.settings).apply(
        TEST_MACHINE_UUID,
        "Переустановка тестовой машины",
        operator_env={"SUDO_UID": str(os.getuid()), "SUDO_USER": getpass.getuser()},
    )
    assert result.result == "archived"
    assert not source.exists()
    archived = (
        controller_sandbox.settings.machine_archives_dir
        / result.archive_id
        / "records"
        / "ready.json"
    )
    assert archived.read_bytes() == original
```

Expected: FAIL because the service does not exist.

- [ ] **Step 2: Implement reason and operator validation**

```python
def validate_archive_reason(reason: str) -> str:
    normalized = reason.strip()
    if (
        not normalized
        or len(normalized) > 500
        or any(unicodedata.category(char).startswith("C") for char in normalized)
    ):
        raise ControlError(
            code="invalid_archive_reason",
            message="Archive reason is invalid",
            exit_code=4,
        )
    return normalized
```

`resolve_operator_identity()` must trust `SUDO_UID` and `SUDO_USER` only when both parse and `pwd.getpwnam(SUDO_USER).pw_uid == int(SUDO_UID)`. Otherwise use real UID/account, then effective UID/account. Do not accept an arbitrary environment username.

- [ ] **Step 3: Implement preview without lock or mutation**

Preview performs guard discovery, archive-state validation, assignment/job checks, and returns `already_archived` information only when there is no active generation and a completed archive exists. It creates no directories, IDs, or files.

- [ ] **Step 4: Implement locked apply transaction**

Use one continuous lock scope:

```python
with exclusive_lock(self.settings.lock_file):
    snapshot = self.guard.snapshot_for_removal(identifier)
    if not snapshot.candidates:
        existing = self.archives.find_latest_for_machine(snapshot.identity.machine_key)
        if existing is not None:
            return ArchiveResult.already_archived(existing)
        raise machine_not_found(identifier)

    self.guard.assert_removal_allowed(snapshot)
    transaction = self.archives.find_resumable(snapshot.identity.machine_key)
    if transaction is None:
        transaction = self.archives.prepare(...)
        transaction = self.archives.copy_and_verify(...)
        transaction = self.archives.commit(transaction)
    transaction = self.archives.cleanup_sources(transaction)
    self.archives.finalize(transaction)
    return ArchiveResult.archived(transaction)
```

The service must never allocate a second archive ID for a committed transaction. A valid abandoned precommit transaction may be removed and restarted; malformed or ambiguous state fails with `machine_archive_invalid`.

- [ ] **Step 5: Add blocker and precommit-failure tests**

Add exact named tests:

- `test_preview_rejects_assigned_machine_without_mutation`.
- `test_apply_rejects_assigned_machine_without_mutation`.
- `test_preview_rejects_busy_machine_with_safe_fields_only`.
- `test_apply_rejects_busy_machine_with_safe_fields_only`.
- `test_apply_rejects_empty_control_character_and_overlong_reasons`.
- `test_malformed_exact_record_blocks_whole_operation`.
- `test_symlink_candidate_blocks_whole_operation`.
- `test_identity_conflict_blocks_whole_operation`.
- `test_copy_failure_leaves_active_records_visible_and_unmodified`.
- `test_manifest_failure_leaves_active_records_visible_and_unmodified`.

Use monkeypatch on repository methods to inject copy/manifest failures. Assert no source is removed and no committed generation is visible.

- [ ] **Step 6: Add postcommit recovery and idempotency tests**

```python
def test_postcommit_cleanup_failure_hides_generation_and_reuses_id(...):
    first = service.apply(... injected_cleanup_failure ...)
    assert first_error.code == "machine_archive_cleanup_required"
    committed_id = first_error.details["archive_id"]
    assert MachineRepository(settings).list() == []

    second = service.apply(TEST_MACHINE_UUID, "same reason", operator_env=...)
    assert second.archive_id == committed_id
    assert second.result == "archived"


def test_completed_repeat_returns_already_archived_without_new_state(...):
    first = service.apply(...)
    before = snapshot_tree(settings.machine_archives_dir)
    second = service.apply(TEST_MACHINE_UUID, "repeat", operator_env=...)
    assert second.result == "already_archived"
    assert second.archive_id == first.archive_id
    assert snapshot_tree(settings.machine_archives_dir) == before
```

Also prove cleanup does not delete a newer generation placed at the same source path and returns `machine_archive_cleanup_required` with only `archive_id`.

- [ ] **Step 7: Run and commit**

```bash
python -m pytest -q \
  tests/alt_linux/test_machine_archive_repository.py \
  tests/alt_linux/test_machine_archive_service.py

git add \
  deploy/alt-linux/control/alt_deploy/machine_archive.py \
  tests/alt_linux/test_machine_archive_service.py

git commit -m "feat: archive ALT machine registrations safely"
```

Expected: PASS.

---

### Task 5: Expose root-gated CLI preview and apply contracts

**Files:**

- Modify: `deploy/alt-linux/control/alt_deploy/cli.py`
- Create: `tests/alt_linux/test_machine_archive_cli.py`

**Interfaces:**

- Consumes: `MachineArchiveService.preview()` and `.apply()`.
- Produces:
  - `workstationctl --json machines remove preview <identifier>`.
  - `workstationctl --json machines remove apply <identifier> --reason <text>`.

- [ ] **Step 1: Write failing parser and preview test**

```python
def test_remove_preview_returns_public_contract(settings) -> None:
    write_registration(settings, "ready", registration_payload(status="awaiting_assignment"))
    rc, payload = run_cli(
        ["--json", "machines", "remove", "preview", TEST_MACHINE_UUID],
        settings,
    )
    assert rc == 0
    assert payload["status"] == "ok"
    assert payload["preview"]["machine_uuid"] == TEST_MACHINE_UUID
    assert payload["preview"]["source_states"] == ["ready"]
    assert payload["preview"]["record_count"] == 1
```

Run:

```bash
python -m pytest -q tests/alt_linux/test_machine_archive_cli.py::test_remove_preview_returns_public_contract
```

Expected: FAIL because `remove` is unknown.

- [ ] **Step 2: Add nested parser**

```python
remove = machine_commands.add_parser("remove")
remove_commands = remove.add_subparsers(
    dest="machine_remove_command",
    required=True,
)
remove_preview = remove_commands.add_parser("preview")
remove_preview.add_argument("machine_identifier")
remove_apply = remove_commands.add_parser("apply")
remove_apply.add_argument("machine_identifier")
remove_apply.add_argument("--reason", required=True)
```

- [ ] **Step 3: Add dispatch with authorization before service mutation**

```python
elif (
    parsed.command == "machines"
    and parsed.machine_command == "remove"
    and parsed.machine_remove_command == "preview"
):
    payload = {
        "status": "ok",
        "preview": MachineArchiveService(active_settings)
        .preview(parsed.machine_identifier)
        .to_public_dict(),
    }
elif (
    parsed.command == "machines"
    and parsed.machine_command == "remove"
    and parsed.machine_remove_command == "apply"
):
    if os.geteuid() != 0:
        raise ControlError(
            code="root_required",
            message="Machine archive apply must be executed as root",
            exit_code=6,
        )
    payload = {
        "status": "ok",
        "archive": MachineArchiveService(active_settings)
        .apply(parsed.machine_identifier, parsed.reason)
        .to_public_dict(),
    }
```

- [ ] **Step 4: Add exact CLI error and mutation tests**

Add:

```python
def test_remove_apply_requires_root_before_service_construction(monkeypatch, settings):
    monkeypatch.setattr(os, "geteuid", lambda: 1000)
    before = snapshot_tree(settings.state_root.parent)
    rc, payload = run_cli([...], settings)
    assert rc == 6
    assert payload["error"]["code"] == "root_required"
    assert snapshot_tree(settings.state_root.parent) == before
```

Also assert:

- invalid reason returns `invalid_archive_reason` and no state change;
- assigned returns `machine_assigned`;
- busy returns only safe details;
- successful apply returns exact `archive` key set;
- repeated apply returns `result=already_archived` and original ID;
- preview produces no archive directory;
- non-JSON mode writes only safe `ERROR [code]: message` to stderr.

- [ ] **Step 5: Run and commit**

```bash
python -m pytest -q tests/alt_linux/test_machine_archive_cli.py

git add \
  deploy/alt-linux/control/alt_deploy/cli.py \
  tests/alt_linux/test_machine_archive_cli.py

git commit -m "feat: expose ALT machine archive commands"
```

Expected: PASS.

---

### Task 6: Add registration admission and refactor `/register` into a thin adapter

**Files:**

- Create: `deploy/alt-linux/control/alt_deploy/registration_admission.py`
- Modify: `deploy/alt-linux/api/register_api.py`
- Modify: `deploy/alt-linux/systemd/alt-deploy-register.service`
- Create: `tests/alt_linux/test_registration_admission.py`
- Create: `tests/alt_linux/test_register_api.py`

**Interfaces:**

- Consumes: `MachineLifecycleGuard`, `MachineArchiveRepository`, `exclusive_lock`, `atomic_write_json`, `Settings`.
- Produces:
  - `RegistrationRequest(hostname, mac, machine_uuid, ip)`.
  - `RegistrationDecision(http_status: int, payload: dict[str, object])`.
  - `RegistrationAdmissionService.admit(request) -> RegistrationDecision`.
  - `register_api.handle_registration(payload, client_ip, settings) -> tuple[int, dict[str, object]]`.

- [ ] **Step 1: Write failing new-registration and idempotent-registration tests**

```python
def test_new_registration_gets_controller_generation(controller_sandbox) -> None:
    decision = RegistrationAdmissionService(controller_sandbox.settings).admit(
        RegistrationRequest(
            hostname="alt-lifecycle-test",
            mac=TEST_MACHINE_MAC,
            machine_uuid=TEST_MACHINE_UUID,
            ip="192.0.2.56",
        )
    )
    assert decision.http_status == 201
    assert decision.payload["status"] == "registered"
    registration_id = str(decision.payload["registration_id"])
    assert re.fullmatch(r"reg-[0-9a-f]{32}", registration_id)
    pending = read_json(
        controller_sandbox.settings.registration_root
        / "pending"
        / f"{TEST_MACHINE_UUID}.json"
    )
    assert pending["registration_id"] == registration_id


def test_active_consistent_registration_is_not_overwritten(controller_sandbox) -> None:
    path = write_registration(...)
    before = path.read_bytes()
    decision = RegistrationAdmissionService(controller_sandbox.settings).admit(...)
    assert decision.http_status == 200
    assert decision.payload["status"] == "already_registered"
    assert path.read_bytes() == before
```

Expected: FAIL because the service does not exist.

- [ ] **Step 2: Implement request and decision dataclasses**

```python
@dataclass(frozen=True)
class RegistrationRequest:
    hostname: str
    mac: str
    machine_uuid: str
    ip: str

    @property
    def machine_key(self) -> str:
        return self.machine_uuid or self.mac.replace(":", "")


@dataclass(frozen=True)
class RegistrationDecision:
    http_status: int
    payload: dict[str, object]
```

The HTTP adapter retains existing hostname, MAC, UUID, source network, JSON, content-length, and payload-size validation. The service receives normalized validated values.

- [ ] **Step 3: Implement admission under the shared lock**

Inside `admit()`:

1. Acquire `exclusive_lock(settings.lock_file)`.
2. Discover active records and relevant archive state for `request.machine_key`.
3. Fail assigned with `machine_assigned`.
4. Fail active job with `machine_busy` safe details.
5. Fail committed incomplete cleanup with `machine_archive_cleanup_required` and `archive_id`.
6. If a consistent active candidate exists, return HTTP `200 already_registered` without rewriting any byte or timestamp.
7. If active identity conflicts with the request, raise `machine_identity_conflict`.
8. Allocate `registration_id = "reg-" + secrets.token_hex(16)` only for a new generation.
9. Atomically write `pending/<machine_key>.json` mode `0600`.
10. Return HTTP `201 registered`.

The pending payload is:

```python
record = {
    "machine_key": request.machine_key,
    "hostname": request.hostname,
    "ip": request.ip,
    "mac": request.mac,
    "uuid": request.machine_uuid,
    "registration_id": registration_id,
    "registered_at": utc_now(),
    "status": "pending",
}
```

- [ ] **Step 4: Add lifecycle conflict and concurrency tests**

Add tests proving:

- assignment returns `machine_assigned` and no pending file;
- active job returns `machine_busy` with exact safe detail keys;
- committed incomplete cleanup returns `machine_archive_cleanup_required`;
- completed old archive accepts a new generation;
- new generation differs from old committed generation;
- malformed active/archive state fails closed;
- two concurrent admissions serialize through the lock and produce one generation, with responses `201 registered` and `200 already_registered`;
- a legacy active record returns `already_registered`, omits `registration_id`, and includes `legacy: true`.

- [ ] **Step 5: Refactor API validation into a pure adapter function**

In `register_api.py`, retain the `BaseHTTPRequestHandler` but add:

```python
def handle_registration(
    payload: object,
    client_ip: str,
    settings: Settings,
) -> tuple[int, dict[str, object]]:
    if not isinstance(payload, dict):
        return 400, {"status": "invalid_json_object"}
    # existing field regex validation remains here
    try:
        decision = RegistrationAdmissionService(settings).admit(
            RegistrationRequest(...)
        )
    except ControlError as exc:
        status = {
            "machine_assigned": 409,
            "machine_busy": 409,
            "machine_archive_cleanup_required": 409,
            "machine_identity_conflict": 409,
            "machine_record_invalid": 409,
            "machine_record_unsafe": 409,
            "machine_archive_invalid": 409,
            "registration_storage_failed": 500,
            "controller_lock_unsafe": 500,
        }.get(exc.code, 500)
        return status, exc.to_dict()
    return decision.http_status, decision.payload
```

`RegisterHandler.do_POST()` parses the bounded body, calls this function, and sends the returned status/body. Do not return filesystem paths, tracebacks, or raw exceptions.

- [ ] **Step 6: Add API adapter and loopback handler tests**

`tests/alt_linux/test_register_api.py` must load the script using `importlib.util`, pass a temporary `Settings`, and test:

- `201 registered` response body;
- `200 already_registered` with unchanged bytes;
- `409 machine_assigned`;
- `409 machine_busy` safe fields;
- `409 machine_archive_cleanup_required`;
- existing `400 invalid_hostname`, `invalid_mac`, `invalid_uuid`;
- existing `403 forbidden` source network behavior;
- existing `413 invalid_payload_size`;
- unexpected storage exception becomes safe HTTP `500` with no absolute temporary path.

Use a loopback-only ephemeral `ThreadingHTTPServer(("127.0.0.1", 0), handler)` for one end-to-end handler test; shut it down in `finally`.

- [ ] **Step 7: Update registration systemd sandbox**

Add:

```ini
Environment=PYTHONPATH=/opt/alt-deploy-control
ReadWritePaths=/srv/alt-deploy/registration
ReadWritePaths=/var/lib/alt-deploy
```

Keep `User=altserver`, `Group=altserver`, `NoNewPrivileges=true`, `PrivateTmp=true`, and `ProtectSystem=strict`. The state-root write allowance is required for the shared lock; service policy still prevents writes outside the two approved roots.

- [ ] **Step 8: Run and commit**

```bash
python -m pytest -q \
  tests/alt_linux/test_registration_admission.py \
  tests/alt_linux/test_register_api.py

python3 -m py_compile \
  deploy/alt-linux/control/alt_deploy/registration_admission.py \
  deploy/alt-linux/api/register_api.py

git add \
  deploy/alt-linux/control/alt_deploy/registration_admission.py \
  deploy/alt-linux/api/register_api.py \
  deploy/alt-linux/systemd/alt-deploy-register.service \
  tests/alt_linux/test_registration_admission.py \
  tests/alt_linux/test_register_api.py

git commit -m "feat: gate ALT workstation registration lifecycle"
```

Expected: PASS.

---

### Task 7: Prevent pending processing from resurrecting an archived generation

**Files:**

- Modify: `deploy/alt-linux/api/process_pending.py`
- Modify: `deploy/alt-linux/systemd/alt-deploy-process.service`
- Modify: `tests/alt_linux/test_process_pending.py`

**Interfaces:**

- Consumes: `Settings.from_env()`, `MachineLifecycleGuard`, `exclusive_lock`, captured `RegistrationGeneration`.
- Produces:
  - long-running target work outside the global lock;
  - locked finalization to `ready` or `failed` only when the captured generation remains active and uncommitted.

- [ ] **Step 1: Write failing archive-first success-suppression test**

```python
def test_committed_generation_cannot_finalize_ready(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    module, pending_dir, ready_dir, failed_dir = prepare_module(tmp_path, monkeypatch)
    pending = write_pending_record(
        pending_dir,
        registration_id="reg-11111111111111111111111111111111",
    )

    def fake_run(command, *, timeout=60):
        if command[0] == module.WORKSTATIONCTL:
            commit_generation(
                module.settings,
                generation="reg-11111111111111111111111111111111",
            )
            return successful_preflight(command)
        return successful_transport(command)

    monkeypatch.setattr(module, "run_command", fake_run)
    module.process_record(pending)
    assert not (ready_dir / pending.name).exists()
    assert not (failed_dir / pending.name).exists()
```

Expected: FAIL because current code writes `ready` after preflight.

- [ ] **Step 2: Replace global path-only policy with `Settings` plus installed package imports**

At module startup:

```python
from alt_deploy.config import Settings
from alt_deploy.errors import ControlError
from alt_deploy.locks import exclusive_lock
from alt_deploy.machine_lifecycle import (
    MachineLifecycleGuard,
    load_registration_candidate,
)

SETTINGS = Settings.from_env()
PENDING_DIR = SETTINGS.registration_root / "pending"
READY_DIR = SETTINGS.registration_root / "ready"
FAILED_DIR = SETTINGS.registration_root / "failed"
KNOWN_HOSTS = SETTINGS.known_hosts_file
PRIVATE_KEY = SETTINGS.private_key_file
```

Keep environment-overridable `WORKSTATIONCTL` compatibility.

- [ ] **Step 3: Split long-running work from locked finalization**

Load the candidate and capture `generation.value` before target work. Replace unconditional `save_record()` with:

```python
def finalize_record(
    source_path: Path,
    record: dict[str, object],
    destination_dir: Path,
    captured_generation: str,
) -> bool:
    with exclusive_lock(SETTINGS.lock_file):
        guard = MachineLifecycleGuard(SETTINGS)
        current = load_registration_candidate(source_path, "pending")
        if current.generation.value != captured_generation:
            return False
        if guard.generation_is_committed(current.generation.value):
            return False
        save_record(source_path, record, destination_dir)
        return True
```

If the source no longer exists after an archive cleanup, return `False` without recreating it. If a newer generation exists at the same path, return `False` without deleting or replacing it.

- [ ] **Step 4: Protect both success and failure paths**

`process_record()` calls `finalize_record(..., READY_DIR, captured_generation)` after success. `mark_failed()` accepts the captured generation and calls the same locked finalizer for `FAILED_DIR`. Invalid JSON that cannot establish a generation keeps the current safe behavior of removing the malformed pending file, but only after verifying it is a regular non-symlink exact pending object.

- [ ] **Step 5: Add ordering and lock-duration tests**

Add tests:

- committed generation cannot create `ready`;
- committed generation cannot create `failed`;
- processor-first `ready` result remains discoverable and archivable;
- old generation suppression does not suppress a newer generation;
- source replacement with newer generation is untouched;
- `wait_for_ssh`, `ssh-keyscan`, Ansible ping, and preflight execute while no global lock is held;
- finalization executes while the lock is held;
- existing proxy-disable assertion remains true.

Instrument lock state with a test context manager that flips a boolean; assert the boolean is false inside fake long-running commands and true inside a monkeypatched final write.

- [ ] **Step 6: Update processor systemd sandbox**

Add:

```ini
Environment=PYTHONPATH=/opt/alt-deploy-control
ReadWritePaths=/srv/alt-deploy/registration
ReadWritePaths=/home/altserver/.ssh
ReadWritePaths=/var/lib/alt-deploy
```

Keep the existing oneshot user/group and protection directives.

- [ ] **Step 7: Run and commit**

```bash
python -m pytest -q tests/alt_linux/test_process_pending.py
python3 -m py_compile deploy/alt-linux/api/process_pending.py

git add \
  deploy/alt-linux/api/process_pending.py \
  deploy/alt-linux/systemd/alt-deploy-process.service \
  tests/alt_linux/test_process_pending.py

git commit -m "fix: suppress stale ALT registration finalization"
```

Expected: PASS.

---

### Task 8: Add the workstation register-only helper and integrate bootstrap

**Files:**

- Create: `deploy/alt-linux/bootstrap/alt-bootstrap-register`
- Modify: `deploy/alt-linux/bootstrap/bootstrap.sh`
- Create: `tests/alt_linux/test_alt_bootstrap_register.py`
- Modify: `tests/alt_linux/test_install_assets.py`

**Interfaces:**

- Consumes: registration API at `ALT_DEPLOY_REGISTER_URL`, default `http://192.168.100.17:8088/register`.
- Produces: `/usr/local/sbin/alt-bootstrap-register` on newly bootstrapped workstations.

- [ ] **Step 1: Write failing helper safety and success tests**

Use fake `ip`, `hostname`, `curl`, and `python3` through a temporary PATH:

```python
def test_helper_posts_identity_and_accepts_registered(tmp_path: Path) -> None:
    result, calls = run_helper(
        tmp_path,
        http_status=201,
        response={
            "status": "registered",
            "machine_key": TEST_MACHINE_UUID,
            "registration_id": TEST_REGISTRATION_ID,
            "ip": "192.0.2.56",
        },
    )
    assert result.returncode == 0
    request = calls.single_curl_request()
    assert request.url.endswith("/register")
    assert json.loads(request.body) == {
        "hostname": "alt-lifecycle-test",
        "mac": TEST_MACHINE_MAC,
        "uuid": TEST_MACHINE_UUID,
    }


def test_helper_does_not_run_bootstrap_mutations(tmp_path: Path) -> None:
    result, calls = run_helper(tmp_path, http_status=200, response={"status": "already_registered"})
    assert result.returncode == 0
    assert calls.names().isdisjoint({
        "apt-get", "useradd", "usermod", "systemctl", "visudo", "chown"
    })
```

Expected: FAIL because the helper is absent.

- [ ] **Step 2: Implement strict root-only helper**

Required shell structure:

```bash
#!/bin/bash
set -Eeuo pipefail

REGISTER_URL=${ALT_DEPLOY_REGISTER_URL:-http://192.168.100.17:8088/register}

if [[ ${EUID} -ne 0 ]]; then
    echo "Run as root" >&2
    exit 6
fi
```

Determine interface with `ip -o route show default`, read MAC from `/sys/class/net/${iface}/address`, hostname with `hostname -s`, and optional UUID from `/sys/class/dmi/id/product_uuid`.

Construct JSON with Python arguments, not shell interpolation:

```bash
payload=$(python3 - "${hostname_value}" "${mac_value}" "${uuid_value}" <<'PY'
import json
import sys
print(json.dumps({
    "hostname": sys.argv[1].strip().lower(),
    "mac": sys.argv[2].strip().lower(),
    "uuid": sys.argv[3].strip().lower(),
}, ensure_ascii=False))
PY
)
```

Use a mode-`0600` temporary response file, `curl --silent --show-error --connect-timeout 5 --max-time 15 --output ... --write-out '%{http_code}'`, print the body, parse JSON, and exit `0` only for:

- HTTP `201` with `status=registered`;
- HTTP `200` with `status=already_registered`.

All other HTTP status, malformed JSON, or network failure exits non-zero. Always remove the temporary file through `trap`.

- [ ] **Step 3: Add conflict, malformed-response, and no-marker tests**

Add tests proving:

- non-root exits `6` before network command;
- no default interface exits non-zero;
- missing MAC exits non-zero;
- DMI UUID may be empty;
- HTTP `409 machine_assigned` prints safe body and exits non-zero;
- HTTP `409 machine_busy` prints safe body and exits non-zero;
- malformed JSON exits non-zero;
- network failure exits non-zero;
- helper never reads, removes, or writes `/var/lib/alt-bootstrap-completed` or `/var/lib/alt-bootstrap-registered`.

- [ ] **Step 4: Refactor bootstrap to install and invoke the helper**

Add constants:

```bash
REGISTER_HELPER_URL="${DEPLOY_URL}/bootstrap/alt-bootstrap-register"
REGISTER_HELPER_TARGET="/usr/local/sbin/alt-bootstrap-register"
```

Add:

```bash
install_registration_helper() {
    local temporary
    temporary=$(mktemp)
    trap 'rm -f "${temporary}"' RETURN
    curl --fail --silent --show-error \
        --connect-timeout 5 --max-time 15 \
        "${REGISTER_HELPER_URL}" -o "${temporary}"
    [[ -s "${temporary}" ]]
    bash -n "${temporary}"
    install -o root -g root -m 0755 \
        "${temporary}" "${REGISTER_HELPER_TARGET}"
}
```

Replace the embedded `register_machine()` implementation with:

```bash
register_machine() {
    install_registration_helper
    "${REGISTER_HELPER_TARGET}"
    touch "${REGISTER_MARKER}"
}
```

The registration marker is written only after helper exit `0`. In the already-completed branch, a missing registration marker still calls `register_machine`; a present marker does not call the helper.

- [ ] **Step 5: Add bootstrap source-order tests**

In `test_install_assets.py`, assert:

- helper source exists and starts with strict Bash;
- bootstrap references helper URL and target;
- helper installation occurs before invocation;
- completion marker occurs before registration on the initial path;
- registration marker occurs after helper invocation;
- embedded curl POST logic is absent from `bootstrap.sh`;
- helper passes `bash -n`.

- [ ] **Step 6: Run and commit**

```bash
python -m pytest -q \
  tests/alt_linux/test_alt_bootstrap_register.py \
  tests/alt_linux/test_install_assets.py

bash -n deploy/alt-linux/bootstrap/alt-bootstrap-register
bash -n deploy/alt-linux/bootstrap/bootstrap.sh

git add \
  deploy/alt-linux/bootstrap/alt-bootstrap-register \
  deploy/alt-linux/bootstrap/bootstrap.sh \
  tests/alt_linux/test_alt_bootstrap_register.py \
  tests/alt_linux/test_install_assets.py

git commit -m "feat: add ALT register-only workstation helper"
```

Expected: PASS.

---

### Task 9: Extend installer, readiness, state preservation, and systemd asset checks

**Files:**

- Modify: `deploy/alt-linux/install-control-plane-lib.sh`
- Modify: `deploy/alt-linux/control/alt_deploy/controller_readiness.py`
- Modify: `tests/alt_linux/support/installer_sandbox.py`
- Modify: `tests/alt_linux/test_install_assets.py`
- Modify: `tests/alt_linux/test_or3p1_controller_readiness.py`
- Modify: `tests/alt_linux/test_or3p1_controller_readiness_failures.py`
- Modify: `tests/alt_linux/test_or3p1_installer.py`
- Modify: `tests/alt_linux/test_installer_registration_permissions.py`

**Interfaces:**

- Consumes: OR-3P1 installer phases and readiness structure.
- Produces:
  - published `/srv/alt-deploy/bootstrap/alt-bootstrap-register`.
  - private archive and transaction directories.
  - installed lifecycle modules through package copy.
  - syntax validation for both bootstrap scripts.
  - readiness check for served helper file and loopback endpoint.
  - preservation of pre-existing archives.

- [ ] **Step 1: Write failing installer-publication and archive-preservation tests**

Extend `InstallerSandbox._seed_runtime_state()` with:

```python
"/var/lib/alt-deploy/machine-archives/archive-20260721T120000Z-11111111/manifest.json": "{\"sentinel\":true}\n",
"/var/lib/alt-deploy/machine-archives/archive-20260721T120000Z-11111111/commit.json": "{\"sentinel\":true}\n",
"/var/lib/alt-deploy/machine-archives/archive-20260721T120000Z-11111111/records/ready.json": "sentinel archived bytes\n",
```

Add:

```python
def test_installer_publishes_register_helper_and_preserves_archives(tmp_path: Path) -> None:
    sandbox = InstallerSandbox.create(tmp_path)
    archive_before = sandbox.destination(
        "/var/lib/alt-deploy/machine-archives/archive-20260721T120000Z-11111111"
    )
    before = {str(path.relative_to(archive_before)): path.read_bytes()
              for path in archive_before.rglob("*") if path.is_file()}
    result = sandbox.run_library()
    assert result.returncode == 0, result.stderr
    assert sandbox.destination(
        "/srv/alt-deploy/bootstrap/alt-bootstrap-register"
    ).read_bytes() == (
        ALT_ROOT / "bootstrap" / "alt-bootstrap-register"
    ).read_bytes()
    after = {str(path.relative_to(archive_before)): path.read_bytes()
             for path in archive_before.rglob("*") if path.is_file()}
    assert after == before
```

Expected: FAIL because the helper and archive roots are not installed.

- [ ] **Step 2: Extend source validation and repository verification**

Add helper source to `required_files`. Add:

```bash
bash -n "${ALT_ROOT}/bootstrap/bootstrap.sh"
bash -n "${ALT_ROOT}/bootstrap/alt-bootstrap-register"
```

The existing wildcard `py_compile` covers the new Python modules. Keep complete `tests/alt_linux` execution before maintenance.

- [ ] **Step 3: Create private archive roots without recursive mutation**

Extend `ensure_private_state_directories()`:

```bash
"$(install_destination "${root_prefix}" /var/lib/alt-deploy/machine-archives)" \
"$(install_destination "${root_prefix}" /var/lib/alt-deploy/machine-archives/.transactions)"
```

Do not add recursive `chown`, `chmod`, `rm`, or `cp` for archive contents. Existing files remain byte-identical.

- [ ] **Step 4: Publish helper with registration runtime**

Add:

```bash
install -o root -g root -m 0644 \
    "${ALT_ROOT}/bootstrap/alt-bootstrap-register" \
    "${bootstrap_root}/alt-bootstrap-register"
```

The served source is `0644`; the workstation bootstrap installs it as `0755`.

- [ ] **Step 5: Extend readiness static assets and loopback checks**

Add:

```python
STATIC_FILES["register_helper"] = Path(
    "/srv/alt-deploy/bootstrap/alt-bootstrap-register"
)
```

`static_assets_ok()` runs `bash -n` for both `bootstrap` and `register_helper`. Add loopback URL:

```text
http://127.0.0.1:8087/bootstrap/alt-bootstrap-register
```

Readiness still returns only booleans and fixed check names; do not expose response bodies or script contents.

- [ ] **Step 6: Assert systemd unit runtime access contracts**

In installer/permission tests, assert installed units contain:

```ini
Environment=PYTHONPATH=/opt/alt-deploy-control
ReadWritePaths=/var/lib/alt-deploy
```

and preserve existing `User=altserver`, `Group=altserver`, `ProtectSystem=strict`, and registration/SSH write paths.

- [ ] **Step 7: Run focused installer/readiness tests**

```bash
python -m pytest -q \
  tests/alt_linux/test_install_assets.py \
  tests/alt_linux/test_installer_registration_permissions.py \
  tests/alt_linux/test_or3p1_controller_readiness.py \
  tests/alt_linux/test_or3p1_controller_readiness_failures.py \
  tests/alt_linux/test_or3p1_installer.py
```

Expected: PASS.

- [ ] **Step 8: Commit installer/readiness changes**

```bash
git add \
  deploy/alt-linux/install-control-plane-lib.sh \
  deploy/alt-linux/control/alt_deploy/controller_readiness.py \
  deploy/alt-linux/systemd/alt-deploy-register.service \
  deploy/alt-linux/systemd/alt-deploy-process.service \
  tests/alt_linux/support/installer_sandbox.py \
  tests/alt_linux/test_install_assets.py \
  tests/alt_linux/test_installer_registration_permissions.py \
  tests/alt_linux/test_or3p1_controller_readiness.py \
  tests/alt_linux/test_or3p1_controller_readiness_failures.py \
  tests/alt_linux/test_or3p1_installer.py

git commit -m "feat: install ALT machine lifecycle runtime"
```

---

### Task 10: Document operations, run full verification, review, and prepare the PR

**Files:**

- Create: `docs/ALT_OR3P2_MACHINE_REGISTRY_LIFECYCLE.md`
- Modify: `deploy/alt-linux/README.md`
- Modify: `docs/ALT_WORKSTATION_PROVISIONING_CONTEXT.md`
- Modify: `docs/ALT_WORKSTATION_PROVISIONING_NEXT_STEPS.md`
- Modify: `docs/ALT_OR3P1_PILOT_ROLLOUT.md`
- Create after verification: `docs/superpowers/plans/2026-07-21-alt-or3p2-verification.md`

**Interfaces:**

- Consumes: completed CLI/API/helper/installer contracts.
- Produces: operator runbook, current-state handoff, verification evidence, and a reviewable PR that remains unmerged.

- [ ] **Step 1: Write the operator runbook**

`docs/ALT_OR3P2_MACHINE_REGISTRY_LIFECYCLE.md` must include exact commands:

```bash
sudo -u altserver workstationctl --json \
  machines remove preview <machine-uuid>

sudo workstationctl --json \
  machines remove apply <machine-uuid> \
  --reason "Переустановка тестовой машины"

sudo alt-bootstrap-register
```

Document:

- active paths and protected archive paths;
- preview read-only behavior;
- root/reason requirements;
- `machine_assigned`, `machine_busy`, `machine_archive_cleanup_required`, `already_archived`, and `already_registered` outcomes;
- no restore and no assignment release;
- cleanup resume procedure: rerun the same apply command and investigate if cleanup remains blocked;
- old/new registration generation distinction;
- helper does not reinstall packages or alter SSH/sudoers/users;
- existing workstations do not receive the helper automatically;
- OR-3P3 gate before live installation;
- prohibition on using `192.168.101.111`;
- next acceptance target must be a new disposable unassigned machine or VM.

- [ ] **Step 2: Update current context and roadmap**

Update the three existing context/roadmap documents so they state:

```text
OR-3P1: merged
OR-3P2: implemented in repository after this PR, not installed live
OR-3P3: next mandatory step
OR-3P4: blocked until OR-3P3
```

Keep the root-run static HTTP exposure item separate; do not claim OR-3P2 fixes it.

- [ ] **Step 3: Run focused OR-3P2 tests**

```bash
python -m pytest -q \
  tests/alt_linux/test_machine_lifecycle.py \
  tests/alt_linux/test_machine_archive_repository.py \
  tests/alt_linux/test_machine_archive_service.py \
  tests/alt_linux/test_machine_archive_cli.py \
  tests/alt_linux/test_registration_admission.py \
  tests/alt_linux/test_register_api.py \
  tests/alt_linux/test_process_pending.py \
  tests/alt_linux/test_alt_bootstrap_register.py \
  tests/alt_linux/test_install_assets.py \
  tests/alt_linux/test_installer_registration_permissions.py \
  tests/alt_linux/test_or3p1_controller_readiness.py \
  tests/alt_linux/test_or3p1_controller_readiness_failures.py \
  tests/alt_linux/test_or3p1_installer.py
```

Expected: PASS with no skipped OR-3P2 contract tests.

- [ ] **Step 4: Run the complete ALT and repository suites**

```bash
python -m pytest -q tests/alt_linux
python -m pytest -q
```

Expected: PASS. Record exact pass/warning counts and durations.

- [ ] **Step 5: Run static and syntax verification**

```bash
python3 -m py_compile \
  deploy/alt-linux/control/alt_deploy/*.py \
  deploy/alt-linux/api/register_api.py \
  deploy/alt-linux/api/process_pending.py \
  deploy/alt-linux/control/alt-job-stage

bash -n deploy/alt-linux/install-control-plane.sh
bash -n deploy/alt-linux/install-control-plane-lib.sh
bash -n deploy/alt-linux/bootstrap/bootstrap.sh
bash -n deploy/alt-linux/bootstrap/alt-bootstrap-register

git diff --check origin/main...HEAD
```

Run both Ansible syntax checks with the established CI-safe Vault fixture:

```bash
ANSIBLE_CONFIG=deploy/alt-linux/ansible/ansible.cfg \
ansible-playbook --syntax-check \
  deploy/alt-linux/ansible/playbooks/01-preflight.yml

ANSIBLE_CONFIG=deploy/alt-linux/ansible/ansible.cfg \
ansible-playbook --syntax-check \
  deploy/alt-linux/ansible/playbooks/02-provision-account.yml
```

Expected: all PASS.

- [ ] **Step 6: Prove prohibited operations are absent**

Search the OR-3P2 diff and tests. Record evidence that:

- no target SSH invocation was added to archive CLI/service;
- no assignment file deletion exists;
- no job directory/log deletion exists;
- no Vault/private-key content enters fixtures or output;
- no controller or reference-workstation IP is contacted by tests;
- helper does not run package, user, SSH, sudoers, preflight, or provisioning commands;
- installer never recursively mutates existing archive contents.

Use:

```bash
git diff --unified=0 origin/main...HEAD -- \
  deploy/alt-linux/control \
  deploy/alt-linux/api \
  deploy/alt-linux/bootstrap \
  deploy/alt-linux/install-control-plane-lib.sh
```

- [ ] **Step 7: Create verification evidence document**

Create `docs/superpowers/plans/2026-07-21-alt-or3p2-verification.md` containing:

- branch source SHA;
- tested merge ref against current `main`;
- focused test counts/duration;
- ALT suite counts/duration;
- full repository counts/warnings/duration;
- Python/Bash/Ansible/diff-check results;
- exact safety boundary statement;
- confirmation that no temporary workflow or fixture remains.

Do not invent counts; copy them from completed command output.

- [ ] **Step 8: Commit documentation and evidence**

```bash
git add \
  deploy/alt-linux/README.md \
  docs/ALT_OR3P2_MACHINE_REGISTRY_LIFECYCLE.md \
  docs/ALT_OR3P1_PILOT_ROLLOUT.md \
  docs/ALT_WORKSTATION_PROVISIONING_CONTEXT.md \
  docs/ALT_WORKSTATION_PROVISIONING_NEXT_STEPS.md \
  docs/superpowers/plans/2026-07-21-alt-or3p2-verification.md

git commit -m "docs: document ALT machine registry lifecycle"
```

- [ ] **Step 9: Request two-stage code review**

Use `superpowers:requesting-code-review` after all tests pass:

1. specification-compliance review against `docs/superpowers/specs/2026-07-21-alt-or3p2-machine-registry-lifecycle-design.md`;
2. code-quality/safety review focused on no-follow filesystem access, lock scope, generation matching, postcommit recovery, systemd permissions, and output redaction.

Address every actionable issue through TDD and rerun affected plus full suites.

- [ ] **Step 10: Open a draft PR and verify the clean head**

PR title:

```text
feat: add ALT machine registry lifecycle
```

PR body must summarize:

- archive preview/apply contracts;
- generation-aware logical atomicity;
- blockers and safe errors;
- registration admission and pending race protection;
- register-only helper;
- installer/readiness changes;
- complete verification evidence;
- no live controller/reference-machine access;
- OR-3P3 gate;
- explicit `Do not merge without explicit user confirmation.`

Run standard repository workflows on the final clean head. Remove any temporary dedicated verification workflow and CI-only fixture, then rerun the standard workflows if the head changed.

- [ ] **Step 11: Mark Ready only after clean verification**

Before changing draft state, verify:

```bash
git status --short
git diff --check origin/main...HEAD
```

Expected: clean worktree and no whitespace errors. Confirm the PR head SHA matches the verified SHA and all required checks are successful. Do not merge.
