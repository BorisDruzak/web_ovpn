# ALT OR-3P3 Implementation Plan — Self-Review Amendment

**Date:** 2026-07-22  
**Status:** normative; this file overrides the conflicting portions of `2026-07-22-alt-or3p3-coordinated-backup-restore.md`.

## 1. Read-only eligibility must not rewrite verification evidence

The base plan's Task 12 sequence that invokes public `verify` immediately before checking rehearsal is replaced.

Reason: a successful `verify` may write a new timestamped `verification.json`. Because `rehearsal.json` is cryptographically bound to the exact verification-record bytes, rewriting the record would invalidate a previously successful rehearsal.

### Correct interfaces

```python
class BackupRepository:
    def verify(
        self,
        backup_id: str,
        *,
        write_evidence: bool,
    ) -> VerifyResult:
        ...

    def assert_rehearsed_eligibility(
        self,
        backup_id: str,
    ) -> EligibilityResult:
        ...
```

Public operator command:

```text
alt-deploy-backup verify <backup-id>
```

calls:

```python
repository.verify(backup_id, write_evidence=True)
```

Rehearsal calls the same once with `write_evidence=True`, then writes `rehearsal.json` bound to the resulting `verification.json` SHA-256.

Restore eligibility and the OR-3P4 installer gate call only:

```python
repository.assert_rehearsed_eligibility(backup_id)
```

This method:

1. performs full current byte, structure, archive, schema, and secret verification with `write_evidence=False`;
2. reads the existing `verification.json` without replacing it;
3. proves that its manifest and component hashes equal current bytes;
4. reads `rehearsal.json` without replacing it;
5. proves that it references the exact current verification-record SHA-256 and manifest SHA-256;
6. proves schema and utility compatibility;
7. returns success without modifying the bundle.

### Correct installer invocation

`install-control-plane.sh` invokes exactly one read-only command before any mutation:

```text
/usr/local/sbin/alt-deploy-backup rehearse-status <backup-id>
```

`rehearse-status` is an internal root-only eligibility command. It emits one JSON object, performs no rehearsal extraction, and calls `assert_rehearsed_eligibility()` only. The public runbook does not present it as an operator workflow command.

### Required regression test

```python
def test_rehearse_status_is_byte_identical_for_bundle_evidence(
    tmp_path: Path,
) -> None:
    sandbox = BackupSandbox.create(tmp_path)
    backup_id = sandbox.create_rehearsed_backup()
    verification = sandbox.bundle(backup_id) / "verification.json"
    rehearsal = sandbox.bundle(backup_id) / "rehearsal.json"
    before = (verification.read_bytes(), rehearsal.read_bytes())

    result = sandbox.run_cli(
        "rehearse-status",
        backup_id,
        effective_uid=0,
    )

    assert result.returncode == 0
    assert (verification.read_bytes(), rehearsal.read_bytes()) == before
```

## 2. Public backup installer accepts no synthetic-root argument

The base plan's Task 12 statement `install-backup-tool.sh [<synthetic-root-only-in-tests>]` is replaced by two source files:

```text
deploy/alt-linux/install-backup-tool.sh
deploy/alt-linux/install-backup-tool-lib.sh
```

The public script accepts no arguments:

```bash
#!/bin/bash
set -Eeuo pipefail

if [[ ${EUID} -ne 0 ]]; then
    echo "Run as root" >&2
    exit 1
fi

REPO_ROOT=$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)
ALT_ROOT="${REPO_ROOT}/deploy/alt-linux"
source "${ALT_ROOT}/install-backup-tool-lib.sh"
install_backup_tool_main ""
```

Synthetic tests source the library directly and call:

```bash
install_backup_tool_main "${SYNTHETIC_ROOT}"
```

The library uses `install_destination(root_prefix, absolute_path)` in the same pattern as `install-control-plane-lib.sh`. The public installer rejects every positional argument before sourcing mutation functions.

### Correct file-map additions

- Create: `deploy/alt-linux/install-backup-tool-lib.sh`.
- Create: `tests/alt_linux/support/backup_installer_sandbox.py`.
- The existing `InstallerSandbox` remains focused on the control-plane installer.

### Required regression tests

```python
def test_public_backup_installer_rejects_arguments_before_mutation(
    tmp_path: Path,
) -> None:
    sandbox = BackupInstallerSandbox.create(tmp_path)

    result = sandbox.run_public("unexpected")

    assert result.returncode != 0
    assert sandbox.mutation_commands() == []


def test_backup_installer_library_supports_synthetic_root(
    tmp_path: Path,
) -> None:
    sandbox = BackupInstallerSandbox.create(tmp_path)

    result = sandbox.run_library()

    assert result.returncode == 0
    assert sandbox.destination(
        "/usr/local/sbin/alt-deploy-backup"
    ).is_file()
```

## 3. Synthetic tests must not require host UID 0 or a real altserver account

Production validation remains exact: root-owned objects require UID/GID `0`, and service-owned objects use the actual `pwd.getpwnam("altserver")` UID/GID.

Test environments may substitute identities only when all of these conditions are true:

1. `ALT_DEPLOY_BACKUP_TEST_MODE=1`;
2. `ALT_DEPLOY_BACKUP_TEST_ROOT` is present and is not `/`;
3. expected identity overrides are decimal non-negative integers;
4. the CLI is invoked against the synthetic root.

### Correct settings additions

```python
@dataclass(frozen=True)
class BackupSettings:
    # existing paths...
    expected_root_uid: int
    expected_root_gid: int
    expected_service_uid: int
    expected_service_gid: int
    test_mode: bool
```

Resolver:

```python
def _identity_values(
    env: Mapping[str, str],
    root: Path,
) -> tuple[int, int, int, int, bool]:
    test_mode = env.get("ALT_DEPLOY_BACKUP_TEST_MODE") == "1"
    if test_mode:
        if root == Path("/"):
            raise ValueError("Test mode requires a synthetic root")
        return (
            int(env["ALT_DEPLOY_BACKUP_EXPECTED_ROOT_UID"]),
            int(env["ALT_DEPLOY_BACKUP_EXPECTED_ROOT_GID"]),
            int(env["ALT_DEPLOY_BACKUP_EXPECTED_SERVICE_UID"]),
            int(env["ALT_DEPLOY_BACKUP_EXPECTED_SERVICE_GID"]),
            True,
        )

    if any(key.startswith("ALT_DEPLOY_BACKUP_EXPECTED_") for key in env):
        raise ValueError("Identity overrides require test mode")
    account = pwd.getpwnam(env.get("ALT_DEPLOY_SERVICE_USER", "altserver"))
    return 0, 0, account.pw_uid, account.pw_gid, False
```

In the sandbox, all four expected IDs are set to the current test process UID/GID. Production code must never honor these overrides when the root is `/`.

### Required security tests

```python
def test_identity_override_is_rejected_for_production_root() -> None:
    environment = {
        "ALT_DEPLOY_BACKUP_TEST_MODE": "1",
        "ALT_DEPLOY_BACKUP_TEST_ROOT": "/",
        "ALT_DEPLOY_BACKUP_EXPECTED_ROOT_UID": "1000",
        "ALT_DEPLOY_BACKUP_EXPECTED_ROOT_GID": "1000",
        "ALT_DEPLOY_BACKUP_EXPECTED_SERVICE_UID": "1000",
        "ALT_DEPLOY_BACKUP_EXPECTED_SERVICE_GID": "1000",
    }

    with pytest.raises(ValueError):
        BackupSettings.from_env(environment)


def test_production_mode_rejects_identity_override() -> None:
    environment = {
        "ALT_DEPLOY_BACKUP_EXPECTED_ROOT_UID": "1000",
    }

    with pytest.raises(ValueError):
        BackupSettings.from_env(environment)
```

## 4. Task precedence

When executing the base plan:

- Task 1 must include the identity model from Section 3.
- Task 2 filesystem owner/mode checks must use the resolved expected IDs, never hard-coded test process assumptions.
- Tasks 8, 9, and 11 must use `verify(write_evidence=False)` for eligibility checks.
- Task 12 must use the installer split from Section 2 and the single read-only `rehearse-status` call from Section 1.
- Task 13 static checks must include:

```bash
bash -n deploy/alt-linux/install-backup-tool.sh
bash -n deploy/alt-linux/install-backup-tool-lib.sh
```

No other task or requirement is changed by this amendment.
