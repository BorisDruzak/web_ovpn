# ALT OR-3P2 Implementation Plan Amendment

**Status:** normative plan correction
**Date:** 2026-07-21
**Applies to:** `docs/superpowers/plans/2026-07-21-alt-or3p2-machine-registry-lifecycle.md`
**Design authority:** `docs/superpowers/specs/2026-07-21-alt-or3p2-machine-registry-lifecycle-design.md`

This amendment resolves interface and test-harness gaps found during implementation-plan self-review. Where this document conflicts with the main plan, this document controls. It does not change the approved product scope.

## 1. Archive transaction carries immutable audit input

`ArchiveTransaction` must include the audit data required to create `manifest.json` without relying on an undeclared local variable:

```python
@dataclass(frozen=True)
class ArchiveTransaction:
    archive_id: str
    directory: Path
    phase: str
    machine_key: str
    machine_uuid: str
    audit: dict[str, object]
    record_plans: tuple[ArchiveRecordPlan, ...]
```

`prepare()` validates and stores exactly:

```python
{
    "reason": str,
    "operator_uid": int,
    "operator_username": str,
    "archived_at": str,
}
```

Every subsequent phase reloads this audit map from validated `transaction.json`. `manifest.json` is written from `transaction.audit` and is never rewritten.

## 2. Lifecycle guard exposes separate removal and registration snapshots

Task 3 must produce these additional interfaces:

```python
@dataclass(frozen=True)
class RegistrationLifecycleSnapshot:
    identity: MachineIdentity
    candidates: tuple[RegistrationCandidate, ...]
    assignment: dict[str, object] | None
    active_job: JobRecord | None
    cleanup_archive_id: str | None


class MachineLifecycleGuard:
    def snapshot_for_registration(
        self,
        *,
        machine_key: str,
        machine_uuid: str,
        mac: str,
    ) -> RegistrationLifecycleSnapshot:
        ...

    def assert_registration_allowed(
        self,
        snapshot: RegistrationLifecycleSnapshot,
    ) -> None:
        ...
```

The method bodies must implement these exact rules:

1. Resolve the requested identity from normalized UUID when non-empty, otherwise normalized machine key.
2. Discover active records matching UUID or machine key.
3. Reject an active record whose UUID, machine key, or non-empty MAC conflicts with the request using `machine_identity_conflict`.
4. Read assignment and active job for the resolved machine identity.
5. Read committed incomplete cleanup for either machine UUID or machine key.
6. `assert_registration_allowed()` raises `machine_assigned`, `machine_busy`, or `machine_archive_cleanup_required` with the approved safe details.
7. A completed archive with no incomplete cleanup does not block registration.

The ellipses above indicate method bodies in this interface declaration only; implementation must contain the seven concrete rules and no placeholder statement.

`snapshot_for_removal(identifier)` must behave as follows when no active candidate exists:

- if one completed archive matches UUID or machine key, build `MachineIdentity` from its validated manifest;
- if one committed incomplete transaction matches, build identity from its validated transaction and set `cleanup_archive_id`;
- if no archive state matches, raise `machine_not_found` exit `3`;
- if multiple conflicting archive identities match, raise `machine_archive_invalid`.

## 3. Apply resumes committed cleanup before normal blockers

The control flow shown in Task 4 is corrected. A committed transaction is already the authoritative archive decision, so apply must resume it before calling normal removal blockers:

```python
def apply(
    self,
    identifier: str,
    reason: str,
    *,
    operator_env: Mapping[str, str] | None = None,
) -> ArchiveResult:
    validated_reason = validate_archive_reason(reason)
    operator_uid, operator_username = resolve_operator_identity(
        dict(operator_env or os.environ)
    )
    with exclusive_lock(self.settings.lock_file):
        resumable = self.archives.find_resumable(identifier)
        if resumable is not None:
            cleaned = self.archives.cleanup_sources(resumable)
            self.archives.finalize(cleaned)
            return ArchiveResult(
                result="archived",
                archive_id=cleaned.archive_id,
                machine_uuid=cleaned.machine_uuid,
                machine_key=cleaned.machine_key,
                source_states=tuple(
                    plan.state for plan in cleaned.record_plans
                ),
            )

        snapshot = self.guard.snapshot_for_removal(identifier)
        if not snapshot.candidates:
            completed = self.archives.find_latest_completed(identifier)
            if completed is None:
                raise ControlError(
                    code="machine_not_found",
                    message=f"Machine not found: {identifier.strip().lower()}",
                    exit_code=3,
                )
            return ArchiveResult(
                result="already_archived",
                archive_id=str(completed["archive_id"]),
                machine_uuid=str(completed["machine_uuid"]),
                machine_key=str(completed["machine_key"]),
                source_states=tuple(completed["source_states"]),
            )

        self.guard.assert_removal_allowed(snapshot)
        transaction = self.archives.prepare(
            snapshot.identity,
            snapshot.candidates,
            {
                "reason": validated_reason,
                "operator_uid": operator_uid,
                "operator_username": operator_username,
                "archived_at": utc_now(),
            },
        )
        copied = self.archives.copy_and_verify(
            transaction,
            snapshot.candidates,
        )
        committed = self.archives.commit(copied)
        cleaned = self.archives.cleanup_sources(committed)
        self.archives.finalize(cleaned)
        return ArchiveResult(
            result="archived",
            archive_id=cleaned.archive_id,
            machine_uuid=cleaned.machine_uuid,
            machine_key=cleaned.machine_key,
            source_states=tuple(
                plan.state for plan in cleaned.record_plans
            ),
        )
```

`find_resumable(identifier)` and `find_latest_completed(identifier)` match either normalized `machine_uuid` or `machine_key` from validated state.

Preview does not resume cleanup. It returns `machine_archive_cleanup_required` with the existing archive ID.

## 4. Required test-support helpers

Add these helpers to `tests/alt_linux/support/lifecycle_fixtures.py` when Task 2 introduces archive persistence:

```python
from alt_deploy.machine_archive_repository import (
    ArchiveTransaction,
    MachineArchiveRepository,
)
from alt_deploy.registration_records import (
    MachineIdentity,
    load_registration_candidate,
)


def snapshot_tree(root: Path) -> dict[str, tuple[str, bytes | None]]:
    result: dict[str, tuple[str, bytes | None]] = {}
    if not root.exists():
        return result
    for path in sorted(root.rglob("*")):
        relative = str(path.relative_to(root))
        if path.is_symlink():
            result[relative] = ("symlink", os.readlink(path).encode("utf-8"))
        elif path.is_file():
            result[relative] = ("file", path.read_bytes())
        elif path.is_dir():
            result[relative] = ("directory", None)
        else:
            result[relative] = ("other", None)
    return result


def commit_candidate_without_cleanup(
    settings: Settings,
    source: Path,
    state: str,
) -> ArchiveTransaction:
    candidate = load_registration_candidate(source, state)
    repository = MachineArchiveRepository(settings)
    transaction = repository.prepare(
        MachineIdentity(
            machine_key=candidate.machine_key,
            machine_uuid=candidate.machine_uuid,
            mac=candidate.mac,
        ),
        (candidate,),
        {
            "reason": "Synthetic archive fixture",
            "operator_uid": os.getuid(),
            "operator_username": "test-operator",
            "archived_at": "2026-07-21T12:00:00+00:00",
        },
    )
    copied = repository.copy_and_verify(transaction, (candidate,))
    return repository.commit(copied)


def complete_candidate_archive(
    settings: Settings,
    source: Path,
    state: str,
) -> ArchiveTransaction:
    repository = MachineArchiveRepository(settings)
    committed = commit_candidate_without_cleanup(settings, source, state)
    cleaned = repository.cleanup_sources(committed)
    repository.finalize(cleaned)
    return cleaned
```

Use `commit_candidate_without_cleanup()` in registry-filter and pending-race tests. Use `complete_candidate_archive()` in new-registration-after-completed-archive tests.

Inside `tests/alt_linux/test_machine_archive_repository.py`, define these local helpers rather than referencing undeclared names:

```python
def prepare_source(
    tmp_path: Path,
    state: str = "ready",
) -> tuple[ControllerSandbox, Path, MachineArchiveRepository, ArchiveTransaction]:
    sandbox = make_controller_sandbox(tmp_path)
    source = write_registration(
        sandbox.settings,
        state,
        registration_payload(
            status="awaiting_assignment" if state == "ready" else state
        ),
    )
    candidate = load_registration_candidate(source, state)
    repository = MachineArchiveRepository(sandbox.settings)
    transaction = repository.prepare(
        MachineIdentity(
            machine_key=candidate.machine_key,
            machine_uuid=candidate.machine_uuid,
            mac=candidate.mac,
        ),
        (candidate,),
        {
            "reason": "Synthetic repository test",
            "operator_uid": os.getuid(),
            "operator_username": "test-operator",
            "archived_at": "2026-07-21T12:00:00+00:00",
        },
    )
    return sandbox, source, repository, transaction


def commit_source(
    tmp_path: Path,
    state: str = "ready",
) -> tuple[ControllerSandbox, Path, MachineArchiveRepository, ArchiveTransaction]:
    sandbox, source, repository, transaction = prepare_source(tmp_path, state)
    candidate = load_registration_candidate(source, state)
    copied = repository.copy_and_verify(transaction, (candidate,))
    committed = repository.commit(copied)
    return sandbox, source, repository, committed
```

## 5. Register-only helper uses a fakeable root check

Task 8 must use `id -u`, not Bash's immutable `EUID`, so positive tests can provide a fake `id` command without running CI as root:

```bash
if [[ $(id -u) -ne 0 ]]; then
    echo "Run as root" >&2
    exit 6
fi
```

The fake-PATH harness must provide:

- `id -u` returning configured UID;
- `ip -o route show default` returning `default via 192.0.2.1 dev lo`;
- `hostname -s` returning `alt-lifecycle-test`;
- `cat /sys/class/net/lo/address` returning the synthetic MAC;
- `cat /sys/class/dmi/id/product_uuid` returning the synthetic UUID when requested;
- `curl` that records URL/body, writes configured JSON to the `--output` path, and prints the configured HTTP code for `--write-out`.

Positive tests configure fake UID `0`; the non-root test configures fake UID `1000` and asserts curl was not called.

## 6. Pending processor test runner uses concrete command outcomes

In `tests/alt_linux/test_process_pending.py`, add:

```python
def successful_run_command(module):
    def run(
        command: list[str],
        *,
        timeout: int = 60,
    ) -> subprocess.CompletedProcess[str]:
        if command[0] == module.SSH_KEYGEN:
            return subprocess.CompletedProcess(command, 0, "", "")
        if command[0] == module.SSH_KEYSCAN:
            return subprocess.CompletedProcess(
                command,
                0,
                "192.0.2.56 ssh-ed25519 AAAATEST\n",
                "",
            )
        if command[0] == module.ANSIBLE:
            return subprocess.CompletedProcess(
                command,
                0,
                '192.0.2.56 | SUCCESS => {"ping":"pong"}\n',
                "",
            )
        if command[0] == module.WORKSTATIONCTL:
            return subprocess.CompletedProcess(
                command,
                0,
                json.dumps({
                    "status": "ok",
                    "machine_uuid": TEST_MACHINE_UUID,
                    "preflight": {
                        "status": "ok",
                        "checks": {"uuid": True},
                    },
                }),
                "",
            )
        raise AssertionError(f"Unexpected command: {command}")
    return run
```

The archive-first test calls `commit_candidate_without_cleanup(module.SETTINGS, pending, "pending")` before `process_record()`.

## 7. Self-review acceptance

The combined main plan and this amendment are ready for execution when:

- no production module imports a higher-level module that imports it back;
- every referenced test helper is defined in the plan or this amendment;
- `ArchiveTransaction.audit` is present in every constructor and reload path;
- apply resumes committed cleanup before normal blockers;
- registration snapshot methods are implemented as explicit interfaces;
- helper positive tests do not require a root CI runner;
- no task contacts the controller or reference workstation;
- no implementation or PR merge begins without the execution choice and later explicit merge confirmation.
