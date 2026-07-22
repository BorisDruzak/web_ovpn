# ALT OR-3P3 Coordinated Backup and Restore Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Build and verify a root-only, same-controller coordinated backup, rehearsal, and full restore boundary that must succeed before OR-3P4 may mutate the live ALT provisioning control plane.

**Architecture:** Add an independent Python package under `deploy/alt-linux/backup/` with its own CLI wrapper and minimal installer. The package captures six exact component archives, a strict manifest, safe secret identities, unit state, and durable verification/rehearsal evidence; restore uses same-filesystem staging, a durable transaction journal, a complete pre-restore generation, and automatic reversal. The existing control-plane installer gains only an explicit pre-mutation rollback-bundle gate and must preserve all backup-tool paths.

**Tech Stack:** Python 3 standard library, GNU tar, zstd, systemctl/systemd-analyze, ansible-playbook, ssh-keygen, Bash installers, pytest, existing ALT Linux synthetic filesystem test harnesses.

## Global Constraints

- Recovery level is coordinated rollback on the same controller; total controller loss is out of scope.
- Controller `192.168.100.17` and workstation `192.168.101.111` must not be accessed by repository tests, CI, or implementation work.
- `/home/altserver/ansible/group_vars/vault.yml`, `/home/altserver/.ansible-vault-pass`, and `/home/altserver/.ssh/id_ed25519` are never archived or printed.
- The backup utility is independent of `/opt/alt-deploy-control` and imports no `alt_deploy` runtime module.
- Every public command requires effective UID `0` and emits exactly one JSON object.
- Backup root is `/var/backups/alt-deploy`; published bundle directories are `root:root 0700`, files are `root:root 0600`.
- Backup IDs match `backup-YYYYMMDDTHHMMSSZ-<8 lowercase hex>` exactly.
- Bundle components are exactly `runtime.tar.zst`, `systemd.tar.zst`, `ansible.tar.zst`, `controller-state.tar.zst`, `registration-state.tar.zst`, and `deployment-assets.tar.zst` plus `manifest.json`; only `verification.json` and `rehearsal.json` may be added later.
- Restore always restores all six components. No selective restore option or component flag is permitted.
- No automatic retention or bulk deletion is permitted.
- `create` and `restore` hold the existing controller lifecycle lock continuously through the critical capture/transaction section.
- The backup tool is installed first through `deploy/alt-linux/install-backup-tool.sh`; the control-plane installer never overwrites its executable, package, private state, logs, or bundles.
- OR-3P4 must provide `--rollback-backup-id <backup-id>` explicitly; no newest-backup selection is permitted.
- Merge remains prohibited until explicit user confirmation after fresh CI and review.

---

## Planned File Structure

### New backup package

- `deploy/alt-linux/backup/alt-deploy-backup` — installed Python entrypoint.
- `deploy/alt-linux/backup/alt_deploy_backup/__init__.py` — package version.
- `deploy/alt-linux/backup/alt_deploy_backup/errors.py` — stable public error object.
- `deploy/alt-linux/backup/alt_deploy_backup/settings.py` — exact paths, commands, component inventory, environment overrides for tests.
- `deploy/alt-linux/backup/alt_deploy_backup/jsonio.py` — strict JSON read and durable atomic JSON writes.
- `deploy/alt-linux/backup/alt_deploy_backup/fs.py` — no-follow reads, safe directory/file validation, fsync, contained deletion, source inventory.
- `deploy/alt-linux/backup/alt_deploy_backup/locks.py` — root operation lock and independent adapter for the existing lifecycle lock.
- `deploy/alt-linux/backup/alt_deploy_backup/audit.py` — bounded root-only operation log.
- `deploy/alt-linux/backup/alt_deploy_backup/secrets.py` — fingerprint key, Vault identity, Vault-password HMAC, SSH public fingerprint.
- `deploy/alt-linux/backup/alt_deploy_backup/systemd.py` — managed-unit capture, maintenance stop, exact state restoration.
- `deploy/alt-linux/backup/alt_deploy_backup/quiescence.py` — strict active-job, transient-unit, pending-registration, processor checks.
- `deploy/alt-linux/backup/alt_deploy_backup/components.py` — six immutable component specifications and exclusion policy.
- `deploy/alt-linux/backup/alt_deploy_backup/manifest.py` — strict manifest and evidence schemas.
- `deploy/alt-linux/backup/alt_deploy_backup/archive.py` — tar.zst creation and archive-member validation.
- `deploy/alt-linux/backup/alt_deploy_backup/repository.py` — create, verify, list, delete, publication.
- `deploy/alt-linux/backup/alt_deploy_backup/state_validation.py` — independent strict readers used during rehearsal/restore health checks.
- `deploy/alt-linux/backup/alt_deploy_backup/rehearsal.py` — isolated extraction and syntax/state verification.
- `deploy/alt-linux/backup/alt_deploy_backup/restore_journal.py` — durable restore phases and transaction evidence.
- `deploy/alt-linux/backup/alt_deploy_backup/restore.py` — full staging, installation, health checks, and reversal.
- `deploy/alt-linux/backup/alt_deploy_backup/cli.py` — command parsing and orchestration.
- `deploy/alt-linux/install-backup-tool.sh` — bootstrap-safe minimal installer.

### Existing files modified

- `deploy/alt-linux/install-control-plane.sh` — parse exact rollback backup ID.
- `deploy/alt-linux/install-control-plane-lib.sh` — invoke installed backup tool before mutation and preserve backup paths.
- `deploy/alt-linux/README.md` — operator interface and safety boundary.
- `docs/ALT_OR3P1_PILOT_ROLLOUT.md` — exact OR-3P3 gate.
- `docs/ALT_WORKSTATION_PROVISIONING_CONTEXT.md` — current operational source of truth.
- `docs/ALT_WORKSTATION_PROVISIONING_NEXT_STEPS.md` — OR-3P3 completion and OR-3P4 sequence.

### New tests

- `tests/alt_linux/support/backup_sandbox.py`
- `tests/alt_linux/test_or3p3_backup_cli.py`
- `tests/alt_linux/test_or3p3_backup_fs.py`
- `tests/alt_linux/test_or3p3_backup_secrets.py`
- `tests/alt_linux/test_or3p3_backup_systemd.py`
- `tests/alt_linux/test_or3p3_backup_manifest.py`
- `tests/alt_linux/test_or3p3_backup_archive.py`
- `tests/alt_linux/test_or3p3_backup_create.py`
- `tests/alt_linux/test_or3p3_backup_verify_list_delete.py`
- `tests/alt_linux/test_or3p3_backup_rehearsal.py`
- `tests/alt_linux/test_or3p3_backup_restore.py`
- `tests/alt_linux/test_or3p3_backup_installer.py`
- `tests/alt_linux/test_or3p3_control_plane_gate.py`

---

### Task 1: Independent Package, Settings, Errors, CLI Skeleton, and Test Sandbox

**Files:**
- Create: `deploy/alt-linux/backup/alt-deploy-backup`
- Create: `deploy/alt-linux/backup/alt_deploy_backup/__init__.py`
- Create: `deploy/alt-linux/backup/alt_deploy_backup/errors.py`
- Create: `deploy/alt-linux/backup/alt_deploy_backup/settings.py`
- Create: `deploy/alt-linux/backup/alt_deploy_backup/cli.py`
- Create: `tests/alt_linux/support/backup_sandbox.py`
- Create: `tests/alt_linux/test_or3p3_backup_cli.py`

**Interfaces:**
- Produces: `BackupError(code: str, message: str, exit_code: int, details: dict[str, object])`.
- Produces: `BackupSettings.from_env(environ: Mapping[str, str] | None = None) -> BackupSettings`.
- Produces: `cli.main(argv: Sequence[str] | None = None, *, environ: Mapping[str, str] | None = None, effective_uid: int | None = None) -> int`.
- Produces: `BackupSandbox.create(tmp_path: Path) -> BackupSandbox` with an isolated controller root and fake command directory.

- [ ] **Step 1: Write failing root-only and parser tests**

```python
from __future__ import annotations

import json
from pathlib import Path

from support.backup_sandbox import BackupSandbox


def test_cli_rejects_non_root_before_service_construction(tmp_path: Path) -> None:
    sandbox = BackupSandbox.create(tmp_path)

    result = sandbox.run_cli("list", effective_uid=1000)

    assert result.returncode == 6
    assert json.loads(result.stdout) == {
        "status": "error",
        "error": {
            "code": "backup_not_root",
            "message": "Backup operation requires root",
        },
    }
    assert sandbox.command_log() == []


def test_cli_requires_exact_backup_id_for_verify(tmp_path: Path) -> None:
    sandbox = BackupSandbox.create(tmp_path)

    result = sandbox.run_cli("verify", effective_uid=0)

    assert result.returncode == 2
    assert json.loads(result.stdout)["error"]["code"] == "backup_usage"
```

- [ ] **Step 2: Run the focused test and observe RED**

Run:

```bash
.venv/bin/python -m pytest -q \
  tests/alt_linux/test_or3p3_backup_cli.py
```

Expected: collection fails because `support.backup_sandbox` and `alt_deploy_backup` do not exist.

- [ ] **Step 3: Add exact package version and public error model**

```python
# deploy/alt-linux/backup/alt_deploy_backup/__init__.py
__version__ = "1.0.0"
```

```python
# deploy/alt-linux/backup/alt_deploy_backup/errors.py
from __future__ import annotations

from dataclasses import dataclass, field


@dataclass
class BackupError(Exception):
    code: str
    message: str
    exit_code: int = 1
    details: dict[str, object] = field(default_factory=dict)

    def to_dict(self) -> dict[str, object]:
        error: dict[str, object] = {
            "code": self.code,
            "message": self.message,
        }
        if self.details:
            error["details"] = dict(self.details)
        return {"status": "error", "error": error}
```

- [ ] **Step 4: Add immutable settings with exact production defaults and test overrides**

```python
# deploy/alt-linux/backup/alt_deploy_backup/settings.py
from __future__ import annotations

import os
from dataclasses import dataclass
from pathlib import Path
from typing import Mapping


@dataclass(frozen=True)
class BackupSettings:
    backup_root: Path
    private_state_root: Path
    rehearsal_root: Path
    operation_lock: Path
    lifecycle_lock: Path
    log_file: Path
    registration_root: Path
    controller_state_root: Path
    ansible_root: Path
    vault_file: Path
    vault_password_file: Path
    ssh_private_key: Path
    runtime_control_root: Path
    runtime_api_root: Path
    workstationctl_path: Path
    worker_path: Path
    stage_helper_path: Path
    systemd_root: Path
    bootstrap_root: Path
    metadata_root: Path
    service_user: str
    service_group: str

    @classmethod
    def from_env(
        cls,
        environ: Mapping[str, str] | None = None,
    ) -> "BackupSettings":
        env = os.environ if environ is None else environ
        root = Path(env.get("ALT_DEPLOY_BACKUP_TEST_ROOT", "/"))

        def rooted(path: str) -> Path:
            return Path(path) if root == Path("/") else root / path.lstrip("/")

        return cls(
            backup_root=rooted("/var/backups/alt-deploy"),
            private_state_root=rooted("/var/lib/alt-deploy-backup"),
            rehearsal_root=rooted("/var/tmp/alt-deploy-restore-test"),
            operation_lock=rooted("/run/lock/alt-deploy-backup.lock"),
            lifecycle_lock=rooted("/var/lib/alt-deploy/workstationctl.lock"),
            log_file=rooted("/var/log/alt-deploy-backup.log"),
            registration_root=rooted("/srv/alt-deploy/registration"),
            controller_state_root=rooted("/var/lib/alt-deploy"),
            ansible_root=rooted("/home/altserver/ansible"),
            vault_file=rooted("/home/altserver/ansible/group_vars/vault.yml"),
            vault_password_file=rooted("/home/altserver/.ansible-vault-pass"),
            ssh_private_key=rooted("/home/altserver/.ssh/id_ed25519"),
            runtime_control_root=rooted("/opt/alt-deploy-control"),
            runtime_api_root=rooted("/opt/alt-deploy-api"),
            workstationctl_path=rooted("/usr/local/sbin/workstationctl"),
            worker_path=rooted("/usr/local/libexec/alt-provision-worker"),
            stage_helper_path=rooted("/usr/local/libexec/alt-job-stage"),
            systemd_root=rooted("/etc/systemd/system"),
            bootstrap_root=rooted("/srv/alt-deploy/bootstrap"),
            metadata_root=rooted("/srv/alt-deploy/metadata"),
            service_user=env.get("ALT_DEPLOY_SERVICE_USER", "altserver"),
            service_group=env.get("ALT_DEPLOY_SERVICE_GROUP", "altserver"),
        )
```

- [ ] **Step 5: Add the installed entrypoint and CLI dispatch boundary**

```python
# deploy/alt-linux/backup/alt-deploy-backup
#!/usr/bin/python3
from __future__ import annotations

import sys
from pathlib import Path

sys.path.insert(0, str(Path("/opt/alt-deploy-backup")))

from alt_deploy_backup.cli import main

raise SystemExit(main())
```

```python
# deploy/alt-linux/backup/alt_deploy_backup/cli.py
from __future__ import annotations

import json
import os
import sys
from collections.abc import Mapping, Sequence

from .errors import BackupError

COMMANDS_WITHOUT_ID = {"create", "list"}
COMMANDS_WITH_ID = {"verify", "rehearse", "restore", "delete"}


def _parse(argv: Sequence[str]) -> tuple[str, str | None]:
    if len(argv) == 1 and argv[0] in COMMANDS_WITHOUT_ID:
        return argv[0], None
    if len(argv) == 2 and argv[0] in COMMANDS_WITH_ID:
        return argv[0], argv[1]
    raise BackupError("backup_usage", "Invalid backup command", 2)


def main(
    argv: Sequence[str] | None = None,
    *,
    environ: Mapping[str, str] | None = None,
    effective_uid: int | None = None,
) -> int:
    args = list(sys.argv[1:] if argv is None else argv)
    uid = os.geteuid() if effective_uid is None else effective_uid
    try:
        if uid != 0:
            raise BackupError(
                "backup_not_root",
                "Backup operation requires root",
                6,
            )
        command, backup_id = _parse(args)
        payload = {
            "status": "ok",
            "command": command,
            "backup_id": backup_id,
        }
        print(json.dumps(payload, ensure_ascii=False))
        return 0
    except BackupError as exc:
        print(json.dumps(exc.to_dict(), ensure_ascii=False))
        return exc.exit_code
```

- [ ] **Step 6: Add a subprocess-based sandbox that imports source code only**

`BackupSandbox.run_cli()` must set `PYTHONPATH=deploy/alt-linux/backup`, set `ALT_DEPLOY_BACKUP_TEST_ROOT` to the synthetic root, inject `ALT_DEPLOY_BACKUP_EFFECTIVE_UID`, and invoke `python -m alt_deploy_backup.cli`. The module `if __name__ == "__main__"` branch must call `main(effective_uid=int(env override))` only for tests.

- [ ] **Step 7: Run focused tests and compile the new package**

Run:

```bash
.venv/bin/python -m pytest -q \
  tests/alt_linux/test_or3p3_backup_cli.py
python3 -m py_compile \
  deploy/alt-linux/backup/alt_deploy_backup/*.py \
  deploy/alt-linux/backup/alt-deploy-backup
```

Expected: all focused tests pass and compilation exits `0`.

- [ ] **Step 8: Commit Task 1**

```bash
git add \
  deploy/alt-linux/backup \
  tests/alt_linux/support/backup_sandbox.py \
  tests/alt_linux/test_or3p3_backup_cli.py
git commit -m "feat: add OR-3P3 backup command foundation"
```

---

### Task 2: Safe Filesystem Primitives, Durable JSON, Operation Lock, Lifecycle Lock, and Audit Log

**Files:**
- Create: `deploy/alt-linux/backup/alt_deploy_backup/jsonio.py`
- Create: `deploy/alt-linux/backup/alt_deploy_backup/fs.py`
- Create: `deploy/alt-linux/backup/alt_deploy_backup/locks.py`
- Create: `deploy/alt-linux/backup/alt_deploy_backup/audit.py`
- Modify: `tests/alt_linux/support/backup_sandbox.py`
- Create: `tests/alt_linux/test_or3p3_backup_fs.py`

**Interfaces:**
- Produces: `read_regular_bytes(path: Path, *, max_bytes: int | None = None) -> bytes`.
- Produces: `atomic_write_json(path: Path, payload: Mapping[str, object], *, mode: int = 0o600) -> None`.
- Produces: `validate_private_directory(path: Path, *, uid: int, gid: int, mode: int) -> None`.
- Produces: `source_inventory(paths: Sequence[Path]) -> tuple[InventoryEntry, ...]`.
- Produces: `exclusive_operation_lock(settings: BackupSettings) -> Iterator[None]` using non-blocking flock.
- Produces: `exclusive_lifecycle_lock(settings: BackupSettings) -> Iterator[None]` using blocking flock on the existing lock.
- Produces: `AuditLog.write(event: str, **safe_fields: object) -> None`.

- [ ] **Step 1: Write unsafe-link, atomic-write, and lock tests**

```python
def test_read_regular_bytes_rejects_symlink(tmp_path: Path) -> None:
    target = tmp_path / "target"
    target.write_bytes(b"secret")
    link = tmp_path / "link"
    link.symlink_to(target)

    with pytest.raises(BackupError) as error:
        read_regular_bytes(link)

    assert error.value.code == "backup_source_unsafe"


def test_operation_lock_is_non_blocking(tmp_path: Path) -> None:
    sandbox = BackupSandbox.create(tmp_path)
    with exclusive_operation_lock(sandbox.settings):
        with pytest.raises(BackupError) as error:
            with exclusive_operation_lock(sandbox.settings):
                pass
    assert error.value.code == "backup_lock_busy"


def test_atomic_json_replaces_complete_file(tmp_path: Path) -> None:
    destination = tmp_path / "record.json"
    atomic_write_json(destination, {"status": "ok"})
    assert destination.read_bytes() == b'{\n  "status": "ok"\n}\n'
    assert stat.S_IMODE(destination.stat().st_mode) == 0o600
```

- [ ] **Step 2: Run RED**

```bash
.venv/bin/python -m pytest -q \
  tests/alt_linux/test_or3p3_backup_fs.py
```

Expected: imports fail for the new filesystem and lock modules.

- [ ] **Step 3: Implement no-follow stable reads and strict directory validation**

Use `lstat`, `os.open(..., O_NOFOLLOW)`, `fstat`, and post-read inode/device/size comparison. Reject non-regular files, ownership mismatch, mode mismatch, oversized files, and path parents that are symlinks with `backup_source_unsafe`.

Core entry type:

```python
@dataclass(frozen=True)
class InventoryEntry:
    path: str
    kind: str
    device: int
    inode: int
    size: int
    mtime_ns: int
    ctime_ns: int
```

`source_inventory()` must sort by absolute path string and must record directories, regular files, and approved internal symlinks without dereferencing external targets.

- [ ] **Step 4: Implement durable JSON and fsync helpers**

`atomic_write_json()` must create a private temporary sibling using `O_CREAT|O_EXCL|O_NOFOLLOW`, write all bytes, `fsync()` the descriptor, `os.replace()`, and `fsync()` the parent. Temporary cleanup must not follow links.

- [ ] **Step 5: Implement both lock adapters**

```python
@contextmanager
def exclusive_operation_lock(settings: BackupSettings) -> Iterator[None]:
    with _flock(
        settings.operation_lock,
        non_blocking=True,
        error_code="backup_lock_busy",
        create_uid=0,
        create_gid=0,
    ):
        yield


@contextmanager
def exclusive_lifecycle_lock(settings: BackupSettings) -> Iterator[None]:
    with _flock(
        settings.lifecycle_lock,
        non_blocking=False,
        error_code="controller_lock_unsafe",
        create_uid=None,
        create_gid=None,
    ):
        yield
```

The lifecycle adapter may open the existing file but must not create it, chown it, or change its mode.

- [ ] **Step 6: Implement bounded audit records**

`AuditLog.write()` must append one JSON line with UTC timestamp, event, operation ID, command, backup ID, phase, error code, and safe unit/check names only. It must reject values longer than 500 characters and keys outside an allowlist. Open the log with no-follow semantics, enforce `root:root 0600`, append, and fsync.

- [ ] **Step 7: Run focused and neighboring lock tests**

```bash
.venv/bin/python -m pytest -q \
  tests/alt_linux/test_or3p3_backup_fs.py \
  tests/alt_linux/test_machine_archive_root_safety.py \
  tests/alt_linux/test_registration_admission.py
```

Expected: all pass.

- [ ] **Step 8: Commit Task 2**

```bash
git add \
  deploy/alt-linux/backup/alt_deploy_backup/jsonio.py \
  deploy/alt-linux/backup/alt_deploy_backup/fs.py \
  deploy/alt-linux/backup/alt_deploy_backup/locks.py \
  deploy/alt-linux/backup/alt_deploy_backup/audit.py \
  tests/alt_linux/support/backup_sandbox.py \
  tests/alt_linux/test_or3p3_backup_fs.py
git commit -m "feat: add safe backup filesystem boundaries"
```

---

### Task 3: Secret Identity Provider and Persistent Fingerprint Key

**Files:**
- Create: `deploy/alt-linux/backup/alt_deploy_backup/secrets.py`
- Modify: `deploy/alt-linux/backup/alt_deploy_backup/settings.py`
- Modify: `tests/alt_linux/support/backup_sandbox.py`
- Create: `tests/alt_linux/test_or3p3_backup_secrets.py`

**Interfaces:**
- Produces: `SecretIdentity(path: str, kind: str, uid: int, gid: int, owner: str, group: str, mode: int, size: int, identity: str)`.
- Produces: `FingerprintKeyStore.ensure() -> bytes` at `/var/lib/alt-deploy-backup/fingerprint.key`.
- Produces: `SecretIdentityProvider.capture() -> tuple[SecretIdentity, ...]`.
- Produces: `SecretIdentityProvider.assert_matches(expected: Sequence[SecretIdentity]) -> None`.

- [ ] **Step 1: Write HMAC, Vault, SSH fingerprint, and preservation tests**

```python
def test_vault_password_identity_is_hmac_not_plain_hash(tmp_path: Path) -> None:
    sandbox = BackupSandbox.create(tmp_path)
    sandbox.seed_secrets(vault_password=b"fixture-password\n")
    provider = sandbox.secret_provider()

    identities = {item.kind: item for item in provider.capture()}

    assert identities["vault_password"].identity.startswith("hmac-sha256:")
    assert hashlib.sha256(b"fixture-password\n").hexdigest() not in (
        identities["vault_password"].identity
    )


def test_ssh_identity_uses_public_fingerprint(tmp_path: Path) -> None:
    sandbox = BackupSandbox.create(tmp_path)
    sandbox.seed_secrets()
    sandbox.fake_ssh_fingerprint("SHA256:test-public-fingerprint")

    identities = {item.kind: item for item in sandbox.secret_provider().capture()}

    assert identities["ssh_private_key"].identity == (
        "ssh-public-fingerprint:SHA256:test-public-fingerprint"
    )


def test_existing_fingerprint_key_is_never_replaced(tmp_path: Path) -> None:
    sandbox = BackupSandbox.create(tmp_path)
    key_path = sandbox.settings.fingerprint_key
    key_path.parent.mkdir(parents=True)
    key_path.write_bytes(b"x" * 32)

    assert sandbox.fingerprint_store().ensure() == b"x" * 32
    assert key_path.read_bytes() == b"x" * 32
```

- [ ] **Step 2: Run RED**

```bash
.venv/bin/python -m pytest -q \
  tests/alt_linux/test_or3p3_backup_secrets.py
```

- [ ] **Step 3: Add settings for fingerprint key and command paths**

Add exact fields:

```python
fingerprint_key: Path
ssh_keygen_path: Path
ansible_playbook_path: Path
systemctl_path: Path
systemd_analyze_path: Path
tar_path: Path
zstd_path: Path
```

Production defaults are `/var/lib/alt-deploy-backup/fingerprint.key`, `/usr/bin/ssh-keygen`, `/usr/bin/ansible-playbook`, `/usr/bin/systemctl`, `/usr/bin/systemd-analyze`, `/usr/bin/tar`, and `/usr/bin/zstd`.

- [ ] **Step 4: Implement fingerprint-key creation**

Use 32 bytes from `secrets.token_bytes(32)`, durable create with `O_EXCL|O_NOFOLLOW`, `root:root 0600`, file fsync, parent fsync. Existing key must be exactly 32 bytes, regular, root-owned, and mode `0600`.

- [ ] **Step 5: Implement the three identity mechanisms**

```python
def vault_identity(raw: bytes) -> str:
    if not raw.startswith(b"$ANSIBLE_VAULT;"):
        raise BackupError("backup_secret_invalid", "Vault file is invalid", 4)
    return "sha256:" + hashlib.sha256(raw).hexdigest()


def password_identity(raw: bytes, key: bytes) -> str:
    digest = hmac.new(key, raw, hashlib.sha256).hexdigest()
    return "hmac-sha256:" + digest
```

For the SSH key, run exactly:

```text
ssh-keygen -y -f <private-key>
ssh-keygen -lf - -E sha256
```

Capture only the `SHA256:...` token. Never persist stdout containing the public key.

- [ ] **Step 6: Implement stable metadata checks and matching**

Expected production metadata:

```text
vault.yml             altserver:altserver 0600
.ansible-vault-pass   altserver:altserver 0600
id_ed25519            altserver:altserver 0600
fingerprint.key       root:root           0600
```

`assert_matches()` compares path, kind, UID/GID, mode, size, and identity with constant-time comparison for HMAC and hash strings.

- [ ] **Step 7: Run focused tests and verify no raw secret text is serialized**

```bash
.venv/bin/python -m pytest -q \
  tests/alt_linux/test_or3p3_backup_secrets.py
```

Expected: pass; test must scan serialized identities and audit log for seeded secret bytes.

- [ ] **Step 8: Commit Task 3**

```bash
git add \
  deploy/alt-linux/backup/alt_deploy_backup/settings.py \
  deploy/alt-linux/backup/alt_deploy_backup/secrets.py \
  tests/alt_linux/support/backup_sandbox.py \
  tests/alt_linux/test_or3p3_backup_secrets.py
git commit -m "feat: add safe backup secret identities"
```

---

### Task 4: Managed Systemd State and Quiescence Gates

**Files:**
- Create: `deploy/alt-linux/backup/alt_deploy_backup/systemd.py`
- Create: `deploy/alt-linux/backup/alt_deploy_backup/quiescence.py`
- Modify: `tests/alt_linux/support/backup_sandbox.py`
- Create: `tests/alt_linux/test_or3p3_backup_systemd.py`

**Interfaces:**
- Produces: `UnitState(name: str, load_state: str, enabled_state: str, active_state: str, sub_state: str, failed: bool)`.
- Produces: `SystemdManager.capture() -> tuple[UnitState, ...]`.
- Produces: `SystemdManager.stop_maintenance() -> None`.
- Produces: `SystemdManager.restore(states: Sequence[UnitState], *, activate_health_services: bool) -> None`.
- Produces: `QuiescenceChecker.assert_quiescent() -> QuiescenceSnapshot`.

- [ ] **Step 1: Write exact state restoration and refusal tests**

```python
def test_restore_reproduces_enabled_and_active_states(tmp_path: Path) -> None:
    sandbox = BackupSandbox.create(tmp_path)
    sandbox.set_unit_state("alt-deploy-http.service", enabled="enabled", active="active")
    sandbox.set_unit_state("alt-deploy-register.service", enabled="disabled", active="inactive")
    sandbox.set_unit_state("alt-deploy-process.path", enabled="enabled", active="active")

    manager = sandbox.systemd_manager()
    states = manager.capture()
    manager.stop_maintenance()
    manager.restore(states, activate_health_services=True)

    assert sandbox.unit_state("alt-deploy-http.service") == ("enabled", "active")
    assert sandbox.unit_state("alt-deploy-register.service") == ("disabled", "inactive")
    assert sandbox.unit_state("alt-deploy-process.path") == ("enabled", "active")


def test_quiescence_rejects_active_job(tmp_path: Path) -> None:
    sandbox = BackupSandbox.create(tmp_path)
    sandbox.seed_job(state="running", stage="connecting")

    with pytest.raises(BackupError) as error:
        sandbox.quiescence_checker().assert_quiescent()

    assert error.value.code == "backup_active_jobs"
```

- [ ] **Step 2: Run RED**

```bash
.venv/bin/python -m pytest -q \
  tests/alt_linux/test_or3p3_backup_systemd.py
```

- [ ] **Step 3: Implement strict systemctl query adapter**

For each exact managed unit, execute:

```text
systemctl show <unit> --property=LoadState --property=ActiveState --property=SubState --value
systemctl is-enabled <unit>
systemctl is-failed <unit>
```

Treat `not-found` as an allowed recorded absence. Any malformed output is `backup_preflight_failed`.

- [ ] **Step 4: Implement maintenance stop and exact restoration**

Stop order:

```text
alt-deploy-process.path
alt-deploy-register.service
alt-deploy-http.service
```

Restore enablement with `enable`/`disable`, then start HTTP and registration services recorded active, perform caller-supplied health checks, and start `alt-deploy-process.path` last. Never start `alt-deploy-process.service`.

- [ ] **Step 5: Implement independent strict quiescence readers**

`QuiescenceChecker` must:

1. inspect every direct child job directory under `/var/lib/alt-deploy/jobs`;
2. read `status.json` no-follow with a bounded size;
3. reject malformed jobs as `backup_preflight_failed`;
4. reject `state in {"queued", "running"}` as `backup_active_jobs` with only job ID/state/stage;
5. reject active `alt-provision-*.service` units;
6. reject any regular `*.json` direct child of registration `pending`;
7. reject an active `alt-deploy-process.service`.

Return a snapshot containing sorted active-job IDs, pending filenames, processor state, and transient units, but no file contents.

- [ ] **Step 6: Run focused and existing active-job tests**

```bash
.venv/bin/python -m pytest -q \
  tests/alt_linux/test_or3p3_backup_systemd.py \
  tests/alt_linux/test_jobs_active.py \
  tests/alt_linux/test_or3p1_controller_readiness.py
```

- [ ] **Step 7: Commit Task 4**

```bash
git add \
  deploy/alt-linux/backup/alt_deploy_backup/systemd.py \
  deploy/alt-linux/backup/alt_deploy_backup/quiescence.py \
  tests/alt_linux/support/backup_sandbox.py \
  tests/alt_linux/test_or3p3_backup_systemd.py
git commit -m "feat: add backup maintenance and quiescence gates"
```

---

### Task 5: Component Inventory and Strict Manifest Schema

**Files:**
- Create: `deploy/alt-linux/backup/alt_deploy_backup/components.py`
- Create: `deploy/alt-linux/backup/alt_deploy_backup/manifest.py`
- Create: `tests/alt_linux/test_or3p3_backup_manifest.py`

**Interfaces:**
- Produces: immutable `ComponentSpec(name, filename, namespace, paths, excludes)`.
- Produces: `component_specs(settings: BackupSettings) -> tuple[ComponentSpec, ...]` in exact restore order.
- Produces: `BackupManifest.to_dict() -> dict[str, object]`.
- Produces: `parse_manifest(raw: bytes) -> BackupManifest` with exact-key rejection.
- Produces: `VerificationEvidence` and `RehearsalEvidence` strict schemas.

- [ ] **Step 1: Write exact component and unknown-key rejection tests**

```python
def test_component_set_and_order_are_exact(tmp_path: Path) -> None:
    settings = BackupSandbox.create(tmp_path).settings

    assert [spec.filename for spec in component_specs(settings)] == [
        "runtime.tar.zst",
        "systemd.tar.zst",
        "ansible.tar.zst",
        "controller-state.tar.zst",
        "registration-state.tar.zst",
        "deployment-assets.tar.zst",
    ]


def test_manifest_rejects_unknown_top_level_key(valid_manifest: dict[str, object]) -> None:
    valid_manifest["unexpected"] = True

    with pytest.raises(BackupError) as error:
        parse_manifest(json.dumps(valid_manifest).encode())

    assert error.value.code == "backup_manifest_invalid"
```

- [ ] **Step 2: Run RED**

```bash
.venv/bin/python -m pytest -q \
  tests/alt_linux/test_or3p3_backup_manifest.py
```

- [ ] **Step 3: Define six component specifications**

Required namespaces and source paths:

```python
(
    ComponentSpec("runtime", "runtime.tar.zst", "runtime", (...), ()),
    ComponentSpec("systemd", "systemd.tar.zst", "systemd", (...), ()),
    ComponentSpec(
        "ansible",
        "ansible.tar.zst",
        "ansible",
        (settings.ansible_root,),
        (settings.vault_file,),
    ),
    ComponentSpec("controller_state", "controller-state.tar.zst", "controller-state", (settings.controller_state_root,), ()),
    ComponentSpec("registration_state", "registration-state.tar.zst", "registration-state", (settings.registration_root,), ()),
    ComponentSpec("deployment_assets", "deployment-assets.tar.zst", "deployment-assets", (settings.bootstrap_root, settings.metadata_root), ()),
)
```

Runtime and systemd specs must include each exact managed path separately so presence/absence is recorded per path.

- [ ] **Step 4: Implement strict dataclasses and schema parsing**

Manifest top-level keys are exactly:

```text
schema_version
utility_version
backup_id
created_at
controller
components
systemd_units
secret_identities
preflight
restore_order
```

Each component record contains exactly:

```text
name filename namespace size_bytes sha256 paths archive_format
```

Each path record contains exactly:

```text
absolute_path present uid gid owner group mode kind
```

Validate timestamp timezone awareness, SHA-256 lowercase hex, unique names/files, exact restore order, exact component count, and backup-ID syntax.

- [ ] **Step 5: Implement evidence schemas bound to current bytes**

`VerificationEvidence` includes exact manifest SHA-256 and component hashes. `RehearsalEvidence` includes exact manifest SHA-256, verification-record SHA-256, utility version, schema version, safe secret identities, passed check IDs, and UTC completion time.

- [ ] **Step 6: Run tests and a round-trip property test**

```bash
.venv/bin/python -m pytest -q \
  tests/alt_linux/test_or3p3_backup_manifest.py
```

Expected: `parse_manifest(manifest.to_bytes()).to_dict() == manifest.to_dict()`.

- [ ] **Step 7: Commit Task 5**

```bash
git add \
  deploy/alt-linux/backup/alt_deploy_backup/components.py \
  deploy/alt-linux/backup/alt_deploy_backup/manifest.py \
  tests/alt_linux/test_or3p3_backup_manifest.py
git commit -m "feat: define OR-3P3 bundle manifest"
```

---

### Task 6: tar.zst Capture and Fail-Closed Archive Inspection

**Files:**
- Create: `deploy/alt-linux/backup/alt_deploy_backup/archive.py`
- Modify: `tests/alt_linux/support/backup_sandbox.py`
- Create: `tests/alt_linux/test_or3p3_backup_archive.py`

**Interfaces:**
- Produces: `ArchiveEngine.capture(spec: ComponentSpec, destination: Path) -> ComponentRecord`.
- Produces: `ArchiveEngine.inspect(spec: ComponentSpec, archive_path: Path) -> ArchiveInspection`.
- Produces: `ArchiveEngine.extract_for_rehearsal(spec, archive_path, destination) -> None`.
- Consumes: safe filesystem primitives, component specs, and command paths from settings.

- [ ] **Step 1: Write traversal, external-link, special-file, and secret-exclusion tests**

```python
@pytest.mark.parametrize(
    ("member_name", "link_name"),
    [
        ("/absolute", ""),
        ("runtime/../../escape", ""),
        ("runtime/link", "/etc/shadow"),
        ("runtime/hard", "../../outside"),
    ],
)
def test_archive_inspection_rejects_unsafe_members(
    tmp_path: Path,
    member_name: str,
    link_name: str,
) -> None:
    sandbox = BackupSandbox.create(tmp_path)
    archive = sandbox.make_tar_zst(member_name=member_name, link_name=link_name)

    with pytest.raises(BackupError) as error:
        sandbox.archive_engine().inspect(sandbox.runtime_spec(), archive)

    assert error.value.code == "backup_integrity_failed"


def test_ansible_archive_excludes_vault(tmp_path: Path) -> None:
    sandbox = BackupSandbox.create(tmp_path)
    sandbox.seed_ansible_tree()

    record = sandbox.archive_engine().capture(
        sandbox.ansible_spec(),
        sandbox.tmp_bundle / "ansible.tar.zst",
    )
    inspection = sandbox.archive_engine().inspect(
        sandbox.ansible_spec(),
        sandbox.tmp_bundle / "ansible.tar.zst",
    )

    assert record.size_bytes > 0
    assert not any("vault.yml" in member.name for member in inspection.members)
```

- [ ] **Step 2: Run RED**

```bash
.venv/bin/python -m pytest -q \
  tests/alt_linux/test_or3p3_backup_archive.py
```

- [ ] **Step 3: Implement capture through explicit file lists**

Do not interpolate untrusted paths into shell strings. Build a NUL-delimited explicit list of relative source entries under a private staging directory. Invoke GNU tar as an argv sequence with numeric ownership, ACL/xattr support when available, no recursion through unsafe links, and archive output piped to zstd. Write to a temporary regular file, fsync, rename, and fsync parent.

Capture must compare `source_inventory()` immediately before and after each component. Any change is `backup_component_failed` and the archive is deleted.

- [ ] **Step 4: Implement inspection without extraction**

Use Python `tarfile` over a zstd decompression subprocess. For every member:

- normalize with `PurePosixPath`;
- reject absolute, empty, `.`, or `..` components;
- require the first path component to equal the spec namespace;
- reject block/char devices, FIFO, and unsupported special types;
- for symlink and hardlink members, resolve the target lexically relative to the member parent and require containment in the same namespace;
- enforce unique member names and bounded member count/size.

- [ ] **Step 5: Implement rehearsal extraction as inspected-then-extract**

First inspect the complete archive. Extract regular files/directories and approved links manually beneath the destination with dirfd/no-follow checks. Clear setuid/setgid bits. Never call `tar -xf` directly into the rehearsal tree.

- [ ] **Step 6: Run archive tests and scan archives for seeded secret bytes**

```bash
.venv/bin/python -m pytest -q \
  tests/alt_linux/test_or3p3_backup_archive.py
```

- [ ] **Step 7: Commit Task 6**

```bash
git add \
  deploy/alt-linux/backup/alt_deploy_backup/archive.py \
  tests/alt_linux/support/backup_sandbox.py \
  tests/alt_linux/test_or3p3_backup_archive.py
git commit -m "feat: add safe OR-3P3 component archives"
```

---

### Task 7: Coordinated Backup Creation and Atomic Publication

**Files:**
- Create: `deploy/alt-linux/backup/alt_deploy_backup/repository.py`
- Modify: `deploy/alt-linux/backup/alt_deploy_backup/cli.py`
- Modify: `tests/alt_linux/support/backup_sandbox.py`
- Create: `tests/alt_linux/test_or3p3_backup_create.py`

**Interfaces:**
- Produces: `BackupRepository.create() -> CreateResult`.
- Produces: `CreateResult(backup_id: str, manifest_sha256: str, component_count: int, services_restored: bool)`.
- Consumes: operation lock, quiescence checker, systemd manager, lifecycle lock, secret provider, archive engine, manifest schema, audit log.

- [ ] **Step 1: Write service-recovery, lifecycle-lock, and non-publication tests**

```python
def test_create_publishes_only_after_all_components_verify(tmp_path: Path) -> None:
    sandbox = BackupSandbox.create(tmp_path)
    sandbox.seed_complete_controller()

    result = sandbox.repository().create()

    bundle = sandbox.settings.backup_root / result.backup_id
    assert bundle.is_dir()
    assert sorted(path.name for path in bundle.iterdir()) == [
        "ansible.tar.zst",
        "controller-state.tar.zst",
        "deployment-assets.tar.zst",
        "manifest.json",
        "registration-state.tar.zst",
        "runtime.tar.zst",
        "systemd.tar.zst",
    ]
    assert not list(sandbox.settings.backup_root.glob(".creating-*"))


def test_create_failure_restores_units_and_does_not_publish(tmp_path: Path) -> None:
    sandbox = BackupSandbox.create(tmp_path)
    sandbox.seed_complete_controller()
    sandbox.fail_component("controller_state")
    before = sandbox.managed_unit_snapshot()

    with pytest.raises(BackupError):
        sandbox.repository().create()

    assert sandbox.managed_unit_snapshot() == before
    assert sandbox.published_backups() == []


def test_create_holds_lifecycle_lock_during_capture(tmp_path: Path) -> None:
    sandbox = BackupSandbox.create(tmp_path)
    sandbox.seed_complete_controller()
    sandbox.observe_lifecycle_lock_during_component_capture()

    sandbox.repository().create()

    assert sandbox.lifecycle_lock_observed_for_all_components()
```

- [ ] **Step 2: Run RED**

```bash
.venv/bin/python -m pytest -q \
  tests/alt_linux/test_or3p3_backup_create.py
```

- [ ] **Step 3: Implement preflight and maintenance orchestration**

Exact order:

1. take operation lock;
2. validate root-owned backup/state/log/lock roots;
3. validate required command executables;
4. capture secrets;
5. assert quiescent;
6. capture managed unit states;
7. stop maintenance units;
8. acquire lifecycle lock;
9. repeat secrets and quiescence;
10. capture pre-inventory;
11. create six components in `.creating-<backup-id>`;
12. capture post-inventory and require equality;
13. create manifest;
14. run the same structural validator used by `verify` without writing evidence;
15. atomically publish and fsync backup root;
16. release lifecycle lock;
17. restore original unit state;
18. return public result.

All failure paths after service stop must enter unit-state recovery in `finally`.

- [ ] **Step 4: Implement exact backup ID allocation and private temporary root**

Generate UTC second precision plus `secrets.token_hex(4)`. Retry collisions up to 20 times. Reject any pre-existing symlink or non-directory at candidate paths.

- [ ] **Step 5: Wire CLI `create`**

Success JSON:

```json
{
  "status": "ok",
  "result": "backup_created",
  "backup_id": "backup-20260722T120000Z-a1b2c3d4",
  "component_count": 6,
  "manifest_sha256": "<64 lowercase hex>",
  "services_restored": true
}
```

Do not expose source filenames beyond component names.

- [ ] **Step 6: Run focused and OR-3P1/OR-3P2 safety regressions**

```bash
.venv/bin/python -m pytest -q \
  tests/alt_linux/test_or3p3_backup_create.py \
  tests/alt_linux/test_process_pending_lifecycle.py \
  tests/alt_linux/test_machine_archive_service.py
```

- [ ] **Step 7: Commit Task 7**

```bash
git add \
  deploy/alt-linux/backup/alt_deploy_backup/repository.py \
  deploy/alt-linux/backup/alt_deploy_backup/cli.py \
  tests/alt_linux/support/backup_sandbox.py \
  tests/alt_linux/test_or3p3_backup_create.py
git commit -m "feat: create coordinated controller backups"
```

---

### Task 8: Verify, List, Evidence Invalidation, and Safe Delete

**Files:**
- Modify: `deploy/alt-linux/backup/alt_deploy_backup/repository.py`
- Modify: `deploy/alt-linux/backup/alt_deploy_backup/cli.py`
- Create: `tests/alt_linux/test_or3p3_backup_verify_list_delete.py`

**Interfaces:**
- Produces: `BackupRepository.verify(backup_id: str, *, write_evidence: bool = True) -> VerifyResult`.
- Produces: `BackupRepository.list() -> tuple[BackupSummary, ...]`.
- Produces: `BackupRepository.delete(backup_id: str) -> DeleteResult`.

- [ ] **Step 1: Write corruption, mutation invalidation, corrupted delete, and containment tests**

```python
def test_verify_detects_component_corruption(tmp_path: Path) -> None:
    sandbox = BackupSandbox.create(tmp_path)
    backup_id = sandbox.create_valid_backup()
    component = sandbox.bundle(backup_id) / "runtime.tar.zst"
    component.write_bytes(component.read_bytes() + b"corrupt")

    with pytest.raises(BackupError) as error:
        sandbox.repository().verify(backup_id)

    assert error.value.code == "backup_integrity_failed"


def test_bundle_mutation_invalidates_existing_evidence(tmp_path: Path) -> None:
    sandbox = BackupSandbox.create(tmp_path)
    backup_id = sandbox.create_verified_backup()
    manifest = sandbox.bundle(backup_id) / "manifest.json"
    manifest.write_bytes(manifest.read_bytes() + b" ")

    summary = sandbox.repository().list()[0]

    assert summary.verified is False
    assert summary.rehearsed is False


def test_delete_allows_corrupt_safe_direct_child(tmp_path: Path) -> None:
    sandbox = BackupSandbox.create(tmp_path)
    backup_id = sandbox.create_valid_backup()
    (sandbox.bundle(backup_id) / "manifest.json").write_text("broken")

    result = sandbox.repository().delete(backup_id)

    assert result.backup_id == backup_id
    assert not sandbox.bundle(backup_id).exists()
```

- [ ] **Step 2: Run RED**

```bash
.venv/bin/python -m pytest -q \
  tests/alt_linux/test_or3p3_backup_verify_list_delete.py
```

- [ ] **Step 3: Implement verification**

`verify()` must validate direct-child containment, owner/mode/type, exact top-level set, manifest schema, current secret identities, archive hashes/sizes, zstd readability, member safety, and expected path presence. Only after all checks pass, atomically write `verification.json` bound to manifest and component bytes.

- [ ] **Step 4: Implement list without trusting evidence files**

For each safe direct child matching the backup-ID regex, parse the manifest. Compute current manifest hash and compare it to `verification.json` and `rehearsal.json`. Report invalid directories separately with `valid=false` and a safe error code. Never recurse into `.creating-*`, `.restore-transactions`, or `pre-restore-*`.

- [ ] **Step 5: Implement contained deletion**

Require exact regex and a direct child of backup root. Reject symlink target, root itself, nested paths, `.`/`..`, active restore references, and wrong owner/mode. Walk using lstat and unlink/rmdir without following symlinks. Return only deleted byte count and ID.

- [ ] **Step 6: Wire CLI commands and exact result names**

```text
verify -> backup_verified
list   -> backups_listed
delete -> backup_deleted
```

- [ ] **Step 7: Run focused tests**

```bash
.venv/bin/python -m pytest -q \
  tests/alt_linux/test_or3p3_backup_verify_list_delete.py
```

- [ ] **Step 8: Commit Task 8**

```bash
git add \
  deploy/alt-linux/backup/alt_deploy_backup/repository.py \
  deploy/alt-linux/backup/alt_deploy_backup/cli.py \
  tests/alt_linux/test_or3p3_backup_verify_list_delete.py
git commit -m "feat: verify and manage backup bundles"
```

---

### Task 9: Independent State Validators and Isolated Restore Rehearsal

**Files:**
- Create: `deploy/alt-linux/backup/alt_deploy_backup/state_validation.py`
- Create: `deploy/alt-linux/backup/alt_deploy_backup/rehearsal.py`
- Modify: `deploy/alt-linux/backup/alt_deploy_backup/cli.py`
- Create: `tests/alt_linux/test_or3p3_backup_rehearsal.py`

**Interfaces:**
- Produces: `StateValidator.validate_tree(rehearsal_root: Path, manifest: BackupManifest) -> tuple[str, ...]`.
- Produces: `RehearsalService.rehearse(backup_id: str) -> RehearsalResult`.

- [ ] **Step 1: Write confinement, syntax, malformed-state, and evidence tests**

```python
def test_rehearsal_never_writes_production_paths(tmp_path: Path) -> None:
    sandbox = BackupSandbox.create(tmp_path)
    backup_id = sandbox.create_verified_backup()
    before = sandbox.production_snapshot()

    result = sandbox.rehearsal_service().rehearse(backup_id)

    assert result.status == "ok"
    assert sandbox.production_snapshot() == before
    assert not (sandbox.settings.rehearsal_root / backup_id).exists()


def test_rehearsal_rejects_malformed_job_state(tmp_path: Path) -> None:
    sandbox = BackupSandbox.create(tmp_path)
    backup_id = sandbox.create_verified_backup(
        controller_state_mutator=lambda root: (
            root / "jobs/job-bad/status.json"
        ).write_text("{}")
    )

    with pytest.raises(BackupError) as error:
        sandbox.rehearsal_service().rehearse(backup_id)

    assert error.value.code == "backup_rehearsal_failed"
    assert (sandbox.settings.rehearsal_root / backup_id).is_dir()
```

- [ ] **Step 2: Run RED**

```bash
.venv/bin/python -m pytest -q \
  tests/alt_linux/test_or3p3_backup_rehearsal.py
```

- [ ] **Step 3: Implement strict independent state readers**

Validate without importing `alt_deploy`:

- job directory ID and `request.json`/`status.json`/optional `result.json`/stage history shape;
- assignment JSON identity fields;
- pending/ready/failed registration record identity and generation shape;
- machine archive transaction, manifest, commit marker, hash binding, and unique committed generation;
- no symlink or oversized JSON input.

Return check IDs only, not payload contents.

- [ ] **Step 4: Implement rehearsal orchestration**

Exact order:

1. call `repository.verify(backup_id)`;
2. recreate private rehearsal root only if an old failed root is explicitly removed by safe contained deletion;
3. extract all six components under `<rehearsal>/<backup-id>/<namespace>`;
4. validate ownership/modes against manifest metadata;
5. compile restored Python;
6. run `bash -n` on restored shell entrypoints;
7. run `systemd-analyze verify` on restored unit files;
8. run both Ansible syntax checks against staged playbooks while passing live Vault paths externally;
9. run strict state validators;
10. scan entire rehearsal tree for prohibited secret paths and seeded secret bytes;
11. atomically write `rehearsal.json` into the bundle;
12. delete successful rehearsal tree safely.

- [ ] **Step 5: Bind rehearsal evidence to verification evidence**

`rehearsal.json` must include SHA-256 of `verification.json`. A later verification rewrite, manifest mutation, or component mutation invalidates rehearsal eligibility.

- [ ] **Step 6: Wire CLI `rehearse`**

Success result contains backup ID, manifest hash, check count, and `rehearsal_passed=true` only.

- [ ] **Step 7: Run focused tests and existing archive regressions**

```bash
.venv/bin/python -m pytest -q \
  tests/alt_linux/test_or3p3_backup_rehearsal.py \
  tests/alt_linux/test_machine_archive_repository.py \
  tests/alt_linux/test_registration_records.py
```

- [ ] **Step 8: Commit Task 9**

```bash
git add \
  deploy/alt-linux/backup/alt_deploy_backup/state_validation.py \
  deploy/alt-linux/backup/alt_deploy_backup/rehearsal.py \
  deploy/alt-linux/backup/alt_deploy_backup/cli.py \
  tests/alt_linux/test_or3p3_backup_rehearsal.py
git commit -m "feat: add isolated backup restore rehearsal"
```

---

### Task 10: Durable Restore Journal, Staging, and Pre-Restore Generation

**Files:**
- Create: `deploy/alt-linux/backup/alt_deploy_backup/restore_journal.py`
- Create: `deploy/alt-linux/backup/alt_deploy_backup/restore.py`
- Create: `tests/alt_linux/test_or3p3_backup_restore.py`

**Interfaces:**
- Produces: `RestoreJournal.create(...) -> RestoreJournal`.
- Produces: `RestoreJournal.transition(expected: str, target: str, evidence: Mapping[str, object]) -> None`.
- Produces: `RestoreService.stage(backup_id: str, transaction: RestoreJournal) -> StagedGeneration`.
- Produces: `RestoreService.create_pre_restore_snapshot(transaction: RestoreJournal) -> PreRestoreGeneration`.

- [ ] **Step 1: Write phase-order, staging-failure, and complete-snapshot tests**

```python
def test_restore_journal_rejects_skipped_phase(tmp_path: Path) -> None:
    journal = make_restore_journal(tmp_path)

    with pytest.raises(BackupError) as error:
        journal.transition("prepared", "installed", {})

    assert error.value.code == "restore_staging_failed"


def test_staging_failure_does_not_change_production(tmp_path: Path) -> None:
    sandbox = BackupSandbox.create(tmp_path)
    backup_id = sandbox.create_rehearsed_backup()
    sandbox.fail_restore_staging("registration_state")
    before = sandbox.production_snapshot()

    with pytest.raises(BackupError) as error:
        sandbox.restore_service().restore(backup_id)

    assert error.value.code == "restore_staging_failed"
    assert sandbox.production_snapshot() == before


def test_pre_restore_generation_covers_all_six_components(tmp_path: Path) -> None:
    sandbox = BackupSandbox.create(tmp_path)
    backup_id = sandbox.create_rehearsed_backup()
    transaction = sandbox.prepare_restore(backup_id)

    snapshot = sandbox.restore_service().create_pre_restore_snapshot(transaction)

    assert set(snapshot.components) == {
        "runtime", "systemd", "ansible", "controller_state",
        "registration_state", "deployment_assets",
    }
```

- [ ] **Step 2: Run RED**

```bash
.venv/bin/python -m pytest -q \
  tests/alt_linux/test_or3p3_backup_restore.py -k \
  'journal or staging or pre_restore'
```

- [ ] **Step 3: Implement strict restore phases**

Allowed transitions are exactly:

```python
{
    "prepared": "staged",
    "staged": "services_stopped",
    "services_stopped": "originals_moved",
    "originals_moved": "installed",
    "installed": "daemon_reloaded",
    "daemon_reloaded": "health_checked",
    "health_checked": "committed",
}
```

`rolled_back` and `manual_recovery_required` are terminal failure transitions allowed only after `originals_moved`. Every transition is an atomic JSON replace plus directory fsync.

- [ ] **Step 4: Implement complete pre-restore capture**

Use the same component specs and archive engine as normal backup creation, but store under `pre-restore-<timestamp>/<restore-id>/`. It is never listed as a normal backup and receives a transaction-specific manifest with current unit states and secret identities.

- [ ] **Step 5: Implement same-filesystem staging layout**

For each final source path, create a hidden sibling staging directory/file on the same filesystem. Validate archive provenance, extracted namespace, exact path presence/absence, metadata, and free space. Insert current `vault.yml` into staged Ansible only after identity recheck. Never stage the Vault password or SSH private key.

- [ ] **Step 6: Run focused restore preparation tests**

```bash
.venv/bin/python -m pytest -q \
  tests/alt_linux/test_or3p3_backup_restore.py -k \
  'journal or staging or pre_restore'
```

- [ ] **Step 7: Commit Task 10**

```bash
git add \
  deploy/alt-linux/backup/alt_deploy_backup/restore_journal.py \
  deploy/alt-linux/backup/alt_deploy_backup/restore.py \
  tests/alt_linux/test_or3p3_backup_restore.py
git commit -m "feat: add durable OR-3P3 restore preparation"
```

---

### Task 11: Full Restore Installation, Health Checks, and Automatic Reversal

**Files:**
- Modify: `deploy/alt-linux/backup/alt_deploy_backup/restore.py`
- Modify: `deploy/alt-linux/backup/alt_deploy_backup/cli.py`
- Modify: `tests/alt_linux/test_or3p3_backup_restore.py`

**Interfaces:**
- Produces: `RestoreService.restore(backup_id: str) -> RestoreResult`.
- Produces: `RestoreResult(backup_id: str, phase: str, services_restored: bool, rollback_performed: bool)`.

- [ ] **Step 1: Write all-component success, health rollback, rollback failure, and absent-path tests**

```python
def test_restore_replaces_all_components_and_uses_backup_unit_state(tmp_path: Path) -> None:
    sandbox = BackupSandbox.create(tmp_path)
    backup_id = sandbox.create_rehearsed_backup()
    expected = sandbox.bundle_generation_snapshot(backup_id)
    sandbox.mutate_every_production_component()

    result = sandbox.restore_service().restore(backup_id)

    assert result.phase == "committed"
    assert sandbox.production_snapshot() == expected
    assert sandbox.managed_unit_snapshot() == sandbox.bundle_unit_snapshot(backup_id)


def test_health_failure_rolls_back_to_pre_restore_generation(tmp_path: Path) -> None:
    sandbox = BackupSandbox.create(tmp_path)
    backup_id = sandbox.create_rehearsed_backup()
    sandbox.mutate_every_production_component()
    before = sandbox.production_snapshot()
    sandbox.fail_restore_health_check("ansible_syntax")

    with pytest.raises(BackupError) as error:
        sandbox.restore_service().restore(backup_id)

    assert error.value.code == "restore_health_check_failed"
    assert sandbox.production_snapshot() == before
    assert sandbox.latest_restore_phase() == "rolled_back"


def test_failed_rollback_stops_maintenance_units(tmp_path: Path) -> None:
    sandbox = BackupSandbox.create(tmp_path)
    backup_id = sandbox.create_rehearsed_backup()
    sandbox.fail_restore_health_check("runtime_syntax")
    sandbox.fail_restore_rollback()

    with pytest.raises(BackupError) as error:
        sandbox.restore_service().restore(backup_id)

    assert error.value.code == "restore_manual_recovery_required"
    assert sandbox.maintenance_units_are_stopped()
    assert sandbox.latest_restore_phase() == "manual_recovery_required"
```

- [ ] **Step 2: Run RED**

```bash
.venv/bin/python -m pytest -q \
  tests/alt_linux/test_or3p3_backup_restore.py
```

- [ ] **Step 3: Implement exact restore eligibility**

Before service mutation, require current verify, matching `verification.json`, matching `rehearsal.json`, compatible schema/tool version, matching secrets, quiescence, normal published backup ID, and no active transaction using the bundle.

- [ ] **Step 4: Implement coordinated replacement**

Take operation lock, capture pre-restore unit state, stop maintenance units, take lifecycle lock, repeat eligibility, create pre-restore generation, stage all paths, then for each exact managed path:

1. rename current object to a transaction rollback sibling;
2. rename staged object into place, or install no replacement when backup recorded absence;
3. fsync each parent;
4. record path evidence in the journal.

Do not claim global atomicity across filesystems.

- [ ] **Step 5: Implement post-install health and service activation**

Run `daemon-reload`; reconstruct enablement; validate runtime Python/shell syntax, permissions, secret identities, unit loadability, Ansible syntax, state readers, and no active/pending inconsistency. Start HTTP and registration services only if recorded active, check loopback health, then start path unit last. Verify final states exactly.

- [ ] **Step 6: Implement automatic reversal**

Any failure after `originals_moved` must:

1. stop maintenance units;
2. reverse installed objects using journal path evidence and the pre-restore generation;
3. run `daemon-reload`;
4. restore the unit states captured immediately before restore;
5. run bounded proof checks against pre-restore hashes/inventory;
6. mark `rolled_back` only after proof succeeds.

If any proof fails, mark `manual_recovery_required`, keep units stopped, and raise `restore_manual_recovery_required` with restore ID only.

- [ ] **Step 7: Wire CLI `restore`**

Success JSON must contain `result=backup_restored`, backup ID, terminal phase, services restored, and `rollback_performed=false`. No `--component` or equivalent parser branch may exist.

- [ ] **Step 8: Run focused restore and full OR-3P3 tests so far**

```bash
.venv/bin/python -m pytest -q \
  tests/alt_linux/test_or3p3_backup_*.py
```

- [ ] **Step 9: Commit Task 11**

```bash
git add \
  deploy/alt-linux/backup/alt_deploy_backup/restore.py \
  deploy/alt-linux/backup/alt_deploy_backup/cli.py \
  tests/alt_linux/test_or3p3_backup_restore.py
git commit -m "feat: restore complete OR-3P3 backup generations"
```

---

### Task 12: Dedicated Backup-Tool Installer and OR-3P4 Control-Plane Gate

**Files:**
- Create: `deploy/alt-linux/install-backup-tool.sh`
- Modify: `deploy/alt-linux/install-control-plane.sh`
- Modify: `deploy/alt-linux/install-control-plane-lib.sh`
- Modify: `tests/alt_linux/support/installer_sandbox.py`
- Create: `tests/alt_linux/test_or3p3_backup_installer.py`
- Create: `tests/alt_linux/test_or3p3_control_plane_gate.py`

**Interfaces:**
- Produces: `install-backup-tool.sh [<synthetic-root-only-in-tests>]` with no control-plane service mutation.
- Changes: `install_control_plane_main(root_prefix: str, rollback_backup_id: str) -> None`.
- Adds: `validate_rollback_backup(root_prefix: str, backup_id: str) -> None` before any mutating installer function.

- [ ] **Step 1: Write installer publication, preservation, and explicit-gate tests**

```python
def test_backup_installer_publishes_only_backup_assets(tmp_path: Path) -> None:
    sandbox = BackupInstallerSandbox.create(tmp_path)
    before = sandbox.control_plane_snapshot()

    result = sandbox.run()

    assert result.returncode == 0, result.stderr
    assert sandbox.destination("/usr/local/sbin/alt-deploy-backup").stat().st_mode & 0o777 == 0o750
    assert sandbox.destination("/opt/alt-deploy-backup/alt_deploy_backup").is_dir()
    assert sandbox.control_plane_snapshot() == before
    assert not sandbox.systemctl_mutations()


def test_backup_installer_preserves_bundles_log_and_fingerprint_key(tmp_path: Path) -> None:
    sandbox = BackupInstallerSandbox.create(tmp_path)
    sentinels = sandbox.seed_existing_backup_state()

    result = sandbox.run()

    assert result.returncode == 0
    assert sandbox.read_sentinels() == sentinels


def test_control_plane_installer_requires_explicit_verified_backup_before_mutation(tmp_path: Path) -> None:
    sandbox = InstallerSandbox.create(tmp_path)
    before = sandbox.protected_snapshot()

    result = sandbox.run_library(rollback_backup_id="")

    assert result.returncode != 0
    assert "rollback backup ID" in result.stderr
    assert sandbox.protected_snapshot() == before
    assert sandbox.mutation_commands(sandbox.commands()) == []
```

- [ ] **Step 2: Run RED**

```bash
.venv/bin/python -m pytest -q \
  tests/alt_linux/test_or3p3_backup_installer.py \
  tests/alt_linux/test_or3p3_control_plane_gate.py
```

- [ ] **Step 3: Implement minimal backup-tool installer**

Preflight must require root, Python, install, cp, sha256sum, tar, zstd, systemctl, systemd-analyze, ansible-playbook, ssh-keygen, and source files. Compile package and shell-check wrapper before mutation. Install package as root directories `0750`, files `0640`, wrapper `0750`; create private state/backup roots `0700` and log `0600`; create fingerprint key only through installed utility validation. Never stop services or touch control-plane roots.

- [ ] **Step 4: Parse `--rollback-backup-id` in the public control-plane installer**

Accepted invocation is exactly:

```bash
sudo bash deploy/alt-linux/install-control-plane.sh \
  --rollback-backup-id backup-20260722T120000Z-a1b2c3d4
```

Reject missing value, duplicate flag, unknown flag, positional arguments, and invalid backup-ID syntax before sourcing mutation functions.

- [ ] **Step 5: Add installed backup eligibility call before repository verification and maintenance**

Resolve the executable under `root_prefix` for synthetic tests. Invoke:

```text
alt-deploy-backup verify <backup-id>
alt-deploy-backup rehearse-status <backup-id>
```

Do not rerun full rehearsal during installer preflight. Add an internal read-only CLI command `rehearse-status` that is not advertised as an operator mutation and returns success only when current verify/rehearsal evidence, current bytes, compatibility, and secret identities match.

- [ ] **Step 6: Preserve backup-tool paths explicitly**

Add regression assertions that `install-control-plane-lib.sh` contains no `rm`, `cp`, `install`, `chown`, or `chmod` target under:

```text
/usr/local/sbin/alt-deploy-backup
/opt/alt-deploy-backup
/var/lib/alt-deploy-backup
/var/backups/alt-deploy
/var/log/alt-deploy-backup.log
```

- [ ] **Step 7: Run installer and existing preservation regressions**

```bash
.venv/bin/python -m pytest -q \
  tests/alt_linux/test_or3p3_backup_installer.py \
  tests/alt_linux/test_or3p3_control_plane_gate.py \
  tests/alt_linux/test_installer_preflight.py \
  tests/alt_linux/test_installer_preservation.py \
  tests/alt_linux/test_or3p2_installer_runtime.py
bash -n deploy/alt-linux/install-backup-tool.sh
bash -n deploy/alt-linux/install-control-plane.sh
bash -n deploy/alt-linux/install-control-plane-lib.sh
```

- [ ] **Step 8: Commit Task 12**

```bash
git add \
  deploy/alt-linux/install-backup-tool.sh \
  deploy/alt-linux/install-control-plane.sh \
  deploy/alt-linux/install-control-plane-lib.sh \
  deploy/alt-linux/backup \
  tests/alt_linux/support/installer_sandbox.py \
  tests/alt_linux/test_or3p3_backup_installer.py \
  tests/alt_linux/test_or3p3_control_plane_gate.py
git commit -m "feat: gate control-plane rollout on OR-3P3 backup"
```

---

### Task 13: Operator Runbook, Context Synchronization, Final Verification, and Review Gate

**Files:**
- Create: `docs/ALT_OR3P3_COORDINATED_BACKUP_RESTORE.md`
- Modify: `deploy/alt-linux/README.md`
- Modify: `docs/ALT_OR3P1_PILOT_ROLLOUT.md`
- Modify: `docs/ALT_WORKSTATION_PROVISIONING_CONTEXT.md`
- Modify: `docs/ALT_WORKSTATION_PROVISIONING_NEXT_STEPS.md`
- Create: `docs/superpowers/plans/2026-07-22-alt-or3p3-progress.md`
- Create: `docs/superpowers/plans/2026-07-22-alt-or3p3-verification.md`

**Interfaces:**
- Produces: exact operator commands for install, create, verify, rehearse, list, delete, restore, and OR-3P4 gate.
- Produces: repository evidence and explicit live-operation boundary.

- [ ] **Step 1: Write the operator runbook**

The runbook must include, in this exact order:

1. scope and same-controller assumption;
2. immutable workstation warning;
3. dedicated installer command;
4. safe preflight checks;
5. `create`, `verify`, and `rehearse` commands;
6. how to capture the exact backup ID;
7. how to interpret `verification.json` and `rehearsal.json` without opening archives;
8. OR-3P4 invocation with exact backup ID;
9. emergency full restore command and expected maintenance behavior;
10. `restore_manual_recovery_required` response procedure;
11. safe delete procedure;
12. paths and permissions;
13. explicit statement that a real restore is not executed before OR-3P4.

- [ ] **Step 2: Synchronize current context documents**

Replace obsolete text saying OR-3P3 is merely pending with:

```text
Repository implementation: complete only after PR verification and merge.
Operational gate: complete only after install-backup-tool, create, verify, and rehearse on 192.168.100.17.
OR-3P4: blocked until the exact successful backup ID is supplied to install-control-plane.sh.
```

Do not claim the live operational gate is complete during repository development.

- [ ] **Step 3: Update progress ledger after every implementation task**

Each task entry records RED command/result, GREEN command/result, commit range, and review findings. The ledger must contain no secret path contents or synthetic secret values.

- [ ] **Step 4: Run fresh focused OR-3P3 verification**

```bash
.venv/bin/python -m pytest -q \
  tests/alt_linux/test_or3p3_backup_cli.py \
  tests/alt_linux/test_or3p3_backup_fs.py \
  tests/alt_linux/test_or3p3_backup_secrets.py \
  tests/alt_linux/test_or3p3_backup_systemd.py \
  tests/alt_linux/test_or3p3_backup_manifest.py \
  tests/alt_linux/test_or3p3_backup_archive.py \
  tests/alt_linux/test_or3p3_backup_create.py \
  tests/alt_linux/test_or3p3_backup_verify_list_delete.py \
  tests/alt_linux/test_or3p3_backup_rehearsal.py \
  tests/alt_linux/test_or3p3_backup_restore.py \
  tests/alt_linux/test_or3p3_backup_installer.py \
  tests/alt_linux/test_or3p3_control_plane_gate.py
```

Expected: zero failures.

- [ ] **Step 5: Run complete ALT Linux suite**

```bash
.venv/bin/python -m pytest -q tests/alt_linux
```

Expected: zero failures.

- [ ] **Step 6: Run complete repository suite**

```bash
.venv/bin/python -m pytest -q
```

Expected: zero failures; existing unrelated deprecation warnings may remain and must be counted in evidence.

- [ ] **Step 7: Run static, shell, systemd, and Ansible gates**

```bash
python3 -m py_compile \
  deploy/alt-linux/backup/alt_deploy_backup/*.py \
  deploy/alt-linux/backup/alt-deploy-backup \
  deploy/alt-linux/control/alt_deploy/*.py \
  deploy/alt-linux/api/register_api.py \
  deploy/alt-linux/api/process_pending.py

bash -n deploy/alt-linux/install-backup-tool.sh
bash -n deploy/alt-linux/install-control-plane.sh
bash -n deploy/alt-linux/install-control-plane-lib.sh
bash -n deploy/alt-linux/bootstrap/bootstrap.sh
bash -n deploy/alt-linux/bootstrap/alt-bootstrap-register

systemd-analyze verify \
  deploy/alt-linux/systemd/alt-deploy-http.service \
  deploy/alt-linux/systemd/alt-deploy-register.service \
  deploy/alt-linux/systemd/alt-deploy-process.path \
  deploy/alt-linux/systemd/alt-deploy-process.service

ANSIBLE_CONFIG="$PWD/deploy/alt-linux/ansible/ansible.cfg" \
  ansible-playbook --syntax-check \
  deploy/alt-linux/ansible/playbooks/01-preflight.yml

ANSIBLE_CONFIG="$PWD/deploy/alt-linux/ansible/ansible.cfg" \
  ansible-playbook --syntax-check \
  deploy/alt-linux/ansible/playbooks/02-provision-account.yml

git diff --check origin/main...HEAD
test -z "$(git status --short)"
```

Expected: every command exits `0`, except known environment-specific `systemd-analyze` warnings must be investigated rather than ignored.

- [ ] **Step 8: Perform whole-branch review against the approved spec**

Review at minimum:

- no import from `/opt/alt-deploy-control` or source `alt_deploy` package;
- no secret bytes in archives, logs, JSON, tests, or artifacts;
- lifecycle lock held throughout create/restore critical section;
- exact six-component restore with no partial flags;
- durable evidence invalidation after mutation;
- automatic rollback proof and manual-recovery fail-closed state;
- dedicated installer does not mutate control-plane runtime;
- control-plane installer gate occurs before any mutation;
- backup-tool paths preserved;
- no controller/workstation network access;
- no Critical or Important findings remain.

- [ ] **Step 9: Commit documentation and verification evidence**

```bash
git add \
  deploy/alt-linux/README.md \
  docs/ALT_OR3P3_COORDINATED_BACKUP_RESTORE.md \
  docs/ALT_OR3P1_PILOT_ROLLOUT.md \
  docs/ALT_WORKSTATION_PROVISIONING_CONTEXT.md \
  docs/ALT_WORKSTATION_PROVISIONING_NEXT_STEPS.md \
  docs/superpowers/plans/2026-07-22-alt-or3p3-progress.md \
  docs/superpowers/plans/2026-07-22-alt-or3p3-verification.md
git commit -m "docs: finalize OR-3P3 backup and restore evidence"
```

- [ ] **Step 10: Open a draft PR and do not merge**

PR title:

```text
feat: add coordinated ALT controller backup and restore
```

PR body must state:

- repository tests and exact counts;
- no access to `192.168.100.17` or `192.168.101.111`;
- live gate still requires dedicated installer, create, verify, and rehearsal;
- real restore was not run;
- OR-3P4 remains blocked;
- do not merge without explicit user confirmation.
