from __future__ import annotations

import hashlib
import importlib.util
import json
import os
from pathlib import Path
import subprocess
import sys
from types import ModuleType

import pytest


REPO_ROOT = Path(__file__).resolve().parents[1]
RELEASE_ROOT = REPO_ROOT / "deploy" / "alt-linux" / "release"
ROLLOUT = RELEASE_ROOT / "rollout-install-execution-v2.sh"
PILOT_VERIFIER = RELEASE_ROOT / "verify-install-execution-pilot.py"
RUNBOOK = REPO_ROOT / "docs" / "runbooks" / "alt-install-execution-v2.md"
PILOT_TEMPLATE = (
    REPO_ROOT
    / "docs"
    / "verification"
    / "alt-install-execution-v2-pilot-template.md"
)
BACKUP_ID = "backup-20260729T120000Z-11111111"
SOURCE_COMMIT = "a" * 40
SOURCE_ISO_BYTES = b"pinned-source-iso\n"
SOURCE_ISO_SHA256 = hashlib.sha256(SOURCE_ISO_BYTES).hexdigest()
MANAGED_ISO_BYTES = b"immutable-managed-v2-iso\n"
MANAGED_ISO_SHA256 = hashlib.sha256(MANAGED_ISO_BYTES).hexdigest()
RELEASE_ID = "20260729T120000Z-aaaaaaaaaaaa"
EXISTING_V1_UNIT = (
    "[Service]\n"
    "ExecStart=/usr/bin/python3 /opt/alt-install-session-api/current/"
    "api/install_session_server.py --listen-address 192.168.100.17 "
    "--listen-port 18090\n"
)


def _bash() -> Path:
    candidates = (
        Path(r"C:\Program Files\Git\bin\bash.exe"),
        Path(r"C:\Program Files\Git\usr\bin\bash.exe"),
        Path("/bin/bash"),
    )
    for candidate in candidates:
        if candidate.exists():
            return candidate
    raise AssertionError("bash is required for rollout contract tests")


def _pilot_module() -> ModuleType:
    if not PILOT_VERIFIER.is_file():
        raise AssertionError("pilot verifier is absent")
    spec = importlib.util.spec_from_file_location(
        "verify_install_execution_pilot", PILOT_VERIFIER
    )
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


def _pilot_record(**overrides: object) -> dict[str, object]:
    record: dict[str, object] = {
        "schema_version": 1,
        "asset_id": "ALT-WS-017",
        "dmi_uuid": "550e8400-e29b-41d4-a716-446655440000",
        "disk": {
            "fingerprint": "sha256:" + "d" * 64,
            "path": "/dev/disk/by-id/ata-PILOT-DISK-017",
        },
        "iso_sha256": MANAGED_ISO_SHA256,
        "maintenance_window": {
            "starts_at": "2026-08-01T06:00:00Z",
            "ends_at": "2026-08-01T07:00:00Z",
        },
        "rollback_owner": "Boris Druzhak",
    }
    record.update(overrides)
    return record


def _validate_pilot_record(
    path: Path, *, expected_iso_sha256: str = MANAGED_ISO_SHA256
) -> object:
    module = _pilot_module()
    return module.validate_pilot_record(
        path, expected_iso_sha256=expected_iso_sha256
    )


def test_pilot_requires_asset_disk_iso_window_and_owner(
    tmp_path: Path,
) -> None:
    path = tmp_path / "missing-window.json"
    record = _pilot_record()
    del record["maintenance_window"]
    path.write_text(json.dumps(record), encoding="utf-8")

    result = _validate_pilot_record(path)

    assert result.code == "pilot_window_missing"
    assert result.valid is False


@pytest.mark.parametrize(
    ("mutation", "expected_code"),
    (
        ({"asset_id": None}, "pilot_asset_id_invalid"),
        ({"dmi_uuid": "not-a-uuid"}, "pilot_dmi_uuid_invalid"),
        ({"disk": None}, "pilot_disk_missing"),
        ({"iso_sha256": None}, "pilot_iso_digest_invalid"),
        ({"rollback_owner": ""}, "pilot_rollback_owner_invalid"),
    ),
)
def test_pilot_rejects_missing_or_ambiguous_identity(
    tmp_path: Path,
    mutation: dict[str, object],
    expected_code: str,
) -> None:
    path = tmp_path / "pilot.json"
    path.write_text(
        json.dumps(_pilot_record(**mutation)), encoding="utf-8"
    )

    result = _validate_pilot_record(path)

    assert result.code == expected_code
    assert result.valid is False


@pytest.mark.parametrize(
    ("disk", "expected_code"),
    (
        (
            {
                "fingerprint": "sha256:" + "d" * 63,
                "path": "/dev/disk/by-id/ata-PILOT-DISK-017",
            },
            "pilot_disk_fingerprint_invalid",
        ),
        (
            {
                "fingerprint": "sha256:" + "d" * 64,
                "path": "PILOT-DISK-017",
            },
            "pilot_disk_path_invalid",
        ),
        (
            {
                "fingerprint": "sha256:" + "d" * 64,
                "path": "/dev/disk/by-id/../sda",
            },
            "pilot_disk_path_invalid",
        ),
    ),
)
def test_pilot_requires_exact_disk_fingerprint_and_path(
    tmp_path: Path,
    disk: dict[str, str],
    expected_code: str,
) -> None:
    path = tmp_path / "pilot.json"
    path.write_text(
        json.dumps(_pilot_record(disk=disk)), encoding="utf-8"
    )

    result = _validate_pilot_record(path)

    assert result.code == expected_code
    assert result.valid is False


def test_pilot_binds_exact_iso_and_ordered_utc_window(
    tmp_path: Path,
) -> None:
    path = tmp_path / "pilot.json"
    path.write_text(json.dumps(_pilot_record()), encoding="utf-8")
    wrong_iso = _validate_pilot_record(
        path, expected_iso_sha256="e" * 64
    )
    reversed_window = _pilot_record(
        maintenance_window={
            "starts_at": "2026-08-01T07:00:00Z",
            "ends_at": "2026-08-01T06:00:00Z",
        }
    )
    path.write_text(json.dumps(reversed_window), encoding="utf-8")

    invalid_window = _validate_pilot_record(path)

    assert wrong_iso.code == "pilot_iso_digest_mismatch"
    assert invalid_window.code == "pilot_window_invalid"


def test_pilot_is_strict_validation_only_and_never_opens_disk(
    tmp_path: Path,
) -> None:
    missing_disk_path = (
        "/dev/disk/by-id/this-device-must-not-exist-task7"
    )
    record = _pilot_record(
        disk={
            "fingerprint": "sha256:" + "d" * 64,
            "path": missing_disk_path,
        }
    )
    path = tmp_path / "pilot.json"
    path.write_text(json.dumps(record), encoding="utf-8")

    result = _validate_pilot_record(path)

    assert result.valid is True
    assert result.code == "pilot_record_valid"
    assert result.record["disk"]["path"] == missing_disk_path
    assert "authorization" not in result.record
    unauthorized = dict(record)
    unauthorized["authorize_execution"] = True
    path.write_text(json.dumps(unauthorized), encoding="utf-8")
    rejected = _validate_pilot_record(path)
    assert rejected.code == "pilot_fields_invalid"


def test_pilot_cli_emits_only_validation_receipt(tmp_path: Path) -> None:
    path = tmp_path / "pilot.json"
    path.write_text(json.dumps(_pilot_record()), encoding="utf-8")

    completed = subprocess.run(
        [
            sys.executable,
            str(PILOT_VERIFIER),
            "--record",
            str(path),
            "--expected-iso-sha256",
            MANAGED_ISO_SHA256,
        ],
        check=False,
        capture_output=True,
        text=True,
    )

    assert completed.returncode == 0, completed.stderr
    output = json.loads(completed.stdout)
    assert output == {
        "code": "pilot_record_valid",
        "pilot_record_sha256": hashlib.sha256(
            path.read_bytes()
        ).hexdigest(),
        "result": "valid",
        "schema_version": 1,
        "validation_only": True,
    }


class RolloutSandbox:
    def __init__(self, tmp_path: Path) -> None:
        self.root = tmp_path / "controller-root"
        self.fake_bin = tmp_path / "fake-bin"
        self.builder = tmp_path / "fake-release-builder.sh"
        self.installer = tmp_path / "fake-v2-installer.sh"
        self.task6_support = tmp_path / "fake-task6-support.py"
        self.command_log = tmp_path / "commands.log"
        self.root.mkdir()
        self.fake_bin.mkdir()
        self._seed()
        self._install_fakes()

    def destination(self, absolute_path: str) -> Path:
        return self.root / absolute_path.lstrip("/")

    def _write(self, absolute_path: str, content: str) -> Path:
        path = self.destination(absolute_path)
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(content, encoding="utf-8")
        return path

    def _executable(self, path: Path, text: str) -> None:
        path.write_text(text, encoding="utf-8")
        path.chmod(0o755)

    def _seed(self) -> None:
        self._write(
            "/etc/systemd/system/alt-install-session.service",
            EXISTING_V1_UNIT,
        )
        self.destination(
            "/var/lib/alt-deploy/install-sessions"
        ).mkdir(parents=True)
        backup = self.destination(
            "/usr/local/sbin/alt-deploy-backup"
        )
        backup.parent.mkdir(parents=True, exist_ok=True)
        self._executable(
            backup,
            """#!/bin/bash
set -Eeuo pipefail
printf 'backup %s\n' "$*" >> "$ROLLOUT_COMMAND_LOG"
if [[ ${ROLLOUT_BACKUP_STATE:-rehearsed} != rehearsed ]]; then
  printf '%s\n' '{"status":"error","result":"backup_not_rehearsed"}'
  exit 4
fi
printf '{"status":"ok","result":"backup_rehearsed","backup_id":"%s","manifest_sha256":"%064d","verification_sha256":"%064d"}\n' "$2" 0 1
""",
        )
        self.source_iso = self.root / "source.iso"
        self.source_iso.write_bytes(SOURCE_ISO_BYTES)
        self.public_key = self.root / "controller-public-key.json"
        self.public_key.write_text(
            json.dumps(
                {
                    "key_id": "sha256:" + "1" * 64,
                    "public_key": "fixture",
                }
            ),
            encoding="utf-8",
        )
        self.execution_ca = self.root / "execution-ca.pem"
        self.execution_ca.write_text(
            "-----BEGIN CERTIFICATE-----\nMAA=\n"
            "-----END CERTIFICATE-----\n",
            encoding="ascii",
        )
        self.go = self.root / "go"
        self._executable(self.go, "#!/bin/bash\nexit 0\n")
        self.iso_dir = self.root / "iso"
        self.iso_dir.mkdir()
        self.task6_evidence = self.root / "task6-public-evidence"
        self.task6_evidence.mkdir()
        (self.task6_evidence / "acceptance-receipt.json").write_text(
            json.dumps(
                {
                    "acceptance_scope": "generic-ovmf-disposable",
                    "artifacts": {
                        "iso": {"sha256": MANAGED_ISO_SHA256},
                        "sentinel": {"after_sha256": "2" * 64},
                        "target": {"after_sha256": "3" * 64},
                    },
                    "controller": {
                        "execution_id": "session:execution-0001",
                        "session_id": "session",
                        "state": "installed",
                    },
                    "postflight": {"iso_attached": False},
                    "result": "pass",
                    "run": {
                        "run_id": "run-" + "4" * 64,
                        "trust_anchor_key_id": "sha256:" + "5" * 64,
                    },
                    "schema_version": 2,
                    "target_disk": "/dev/vda",
                    "writes": {
                        "before_authorization": {
                            "target_write_bytes": 0,
                            "sentinel_write_bytes": 0,
                        },
                        "after_install": {
                            "target_write_bytes": 8192,
                            "sentinel_write_bytes": 0,
                        },
                    },
                },
                sort_keys=True,
            )
            + "\n",
            encoding="utf-8",
        )
        task6_receipt = (
            self.task6_evidence / "acceptance-receipt.json"
        ).read_bytes()
        (self.task6_evidence / "evidence-index.json").write_text(
            json.dumps(
                {
                    "receipt_sha256": hashlib.sha256(
                        task6_receipt
                    ).hexdigest(),
                    "schema_version": 1,
                },
                sort_keys=True,
            )
            + "\n",
            encoding="utf-8",
        )
        self.pilot_record = self.root / "pilot.json"
        self.pilot_record.write_text(
            json.dumps(_pilot_record()), encoding="utf-8"
        )
        self.receipt = self.root / "production-receipt.json"

    def _fake_command(self, name: str, body: str) -> None:
        self._executable(
            self.fake_bin / name,
            "#!/bin/bash\nset -Eeuo pipefail\n"
            f"printf '{name} %s\\n' \"$*\" >> \"$ROLLOUT_COMMAND_LOG\"\n"
            + body,
        )

    def _install_fakes(self) -> None:
        python = Path(sys.executable).as_posix().replace("C:/", "/c/")
        self._executable(
            self.fake_bin / "python3",
            f"""#!/bin/bash
set -Eeuo pipefail
if [[ ${{1:-}} == *verify-install-execution-pilot.py ]]; then
  "{python}" "$@"
  status=$?
  if [[ $status == 0 &&
        ${{ROLLOUT_REPLACE_PILOT_AFTER_VALIDATION:-0}} == 1 ]]; then
    "{python}" - "$ROLLOUT_PILOT_ORIGINAL" <<'PY'
import json, sys
path = sys.argv[1]
value = json.load(open(path, encoding="utf-8"))
value["asset_id"] = "ALT-WS-REPLACED"
value["rollback_owner"] = "Replacement Operator"
open(path, "w", encoding="utf-8").write(json.dumps(value))
PY
  fi
  exit "$status"
fi
exec "{python}" "$@"
""",
        )
        self._fake_command(
            "git",
            """if [[ ${1:-} == -C ]]; then shift 2; fi
case "${1:-}" in
  fetch) exit "${ROLLOUT_GIT_FETCH_RC:-0}" ;;
  rev-parse)
    case "${*: -1}" in
      HEAD\\^\\{commit\\}) printf '%s\n' "${ROLLOUT_GIT_HEAD:-$ROLLOUT_SOURCE_COMMIT}" ;;
      refs/remotes/origin/main\\^\\{commit\\}) printf '%s\n' "${ROLLOUT_MAIN_COMMIT:-$ROLLOUT_SOURCE_COMMIT}" ;;
      *) printf '%s\n' "$ROLLOUT_SOURCE_COMMIT" ;;
    esac
    ;;
  merge-base) exit "${ROLLOUT_GIT_MERGE_RC:-0}" ;;
  status) printf '%s' "${ROLLOUT_GIT_STATUS:-}" ;;
  *) exit 2 ;;
esac
""",
        )
        self._fake_command(
            "systemctl",
            """state="$ROLLOUT_ROOT/run/service-state"
unit="$ROLLOUT_ROOT/etc/systemd/system/alt-install-execution.service"
case "${1:-}" in
  cat) cat "$unit" ;;
  is-enabled)
    grep -q '^enabled ' "$state" && { printf 'enabled\n'; exit 0; }
    printf 'disabled\n'; exit 1 ;;
  is-active)
    grep -q ' active$' "$state" && { printf 'active\n'; exit 0; }
    printf 'inactive\n'; exit 3 ;;
  enable)
    if [[ ${2:-} == --now ]]; then
      printf 'enabled active\n' > "$state"
    else
      sed -E 's/^[^ ]+/enabled/' "$state" > "$state.new"
      mv "$state.new" "$state"
    fi ;;
  disable)
    if [[ ${2:-} == --now ]]; then
      printf 'disabled inactive\n' > "$state"
    else
      sed -E 's/^[^ ]+/disabled/' "$state" > "$state.new"
      mv "$state.new" "$state"
    fi ;;
  start) sed -E 's/ [^ ]+$/ active/' "$state" > "$state.new"; mv "$state.new" "$state" ;;
  stop)
    [[ ${ROLLOUT_SYSTEMCTL_STOP_FAIL:-0} != 1 ]] || exit 1
    sed -E 's/ [^ ]+$/ inactive/' "$state" > "$state.new"
    mv "$state.new" "$state" ;;
  daemon-reload) ;;
  *) exit 2 ;;
esac
""",
        )
        self._fake_command(
            "flock",
            """case "${1:-}" in
  --exclusive)
    if [[ ${ROLLOUT_CREATE_ACTIVE_ON_LOCK:-0} == 1 ]]; then
      active="$ROLLOUT_ROOT/var/lib/alt-deploy/install-sessions/raced/status.json"
      mkdir -p "$(dirname "$active")"
      printf '%s\n' '{"execution":{"state":"authorized"}}' > "$active"
    fi
    exit "${ROLLOUT_FLOCK_ACQUIRE_RC:-0}" ;;
  --unlock) exit "${ROLLOUT_FLOCK_UNLOCK_RC:-0}" ;;
  *) exit 2 ;;
esac
""",
        )
        self._fake_command(
            "curl",
            """if [[ ${ROLLOUT_HEALTH_STATE:-ok} == ok ]]; then
  printf '%s' '{"schema_version":1,"service":"alt-install-execution","status":"ok"}'
else
  printf '%s' '{"schema_version":1,"service":"alt-install-execution","status":"starting"}'
fi
""",
        )
        self.destination("/run").mkdir(parents=True, exist_ok=True)
        self._write("/run/service-state", "disabled inactive\n")
        self._executable(
            self.installer,
            """#!/bin/bash
set -Eeuo pipefail
printf 'installer %s\n' "$*" >> "$ROLLOUT_COMMAND_LOG"
release="$ROLLOUT_ROOT/opt/alt-install-execution-api/releases/new-release"
current="$ROLLOUT_ROOT/opt/alt-install-execution-api/current"
unit="$ROLLOUT_ROOT/etc/systemd/system/alt-install-execution.service"
mkdir -p "$release" "$(dirname "$unit")"
printf 'staged-v2\n' > "$release/runtime"
MSYS=winsymlinks:nativestrict ln -s "$release" "$current"
cat > "$unit" <<'EOF'
[Service]
ExecStart=/usr/bin/python3 /opt/alt-install-execution-api/current/api/install_execution_server.py --listen-address 192.168.100.17 --listen-port 18092
EOF
printf 'enabled active\n' > "$ROLLOUT_ROOT/run/service-state"
""",
        )
        self._executable(
            self.builder,
            """#!/bin/bash
set -Eeuo pipefail
printf 'builder %s\n' "$*" >> "$ROLLOUT_COMMAND_LOG"
release_id= iso_dir=
while (($#)); do
  case "$1" in
    --release-id) release_id=$2; shift 2 ;;
    --iso-dir) iso_dir=$2; shift 2 ;;
    *) shift 2 ;;
  esac
done
output="$iso_dir/alt-kworkstation-11.4-agent-v2-$release_id.iso"
sidecar="$output.build-manifest.json"
[[ ! -e "$output" && ! -e "$sidecar" ]] || exit 1
printf 'immutable-managed-v2-iso\n' > "$output"
cat > "$sidecar" <<EOF
{"build_id":"release-$release_id","controller_url":"https://192.168.100.17:18092","format":"alt-install-agent-managed-iso-v2","helper_sha256":"${ROLLOUT_HELPER_SHA256}","managed_initrd_sha256":"${ROLLOUT_INITRD_SHA256}","managed_iso_sha256":"${ROLLOUT_MANAGED_ISO_SHA256}","payload_manifest_sha256":"${ROLLOUT_MANIFEST_SHA256}","public_key_id":"sha256:${ROLLOUT_PUBLIC_KEY_HEX}","public_key_sha256":"${ROLLOUT_PUBLIC_KEY_SHA256}","source_iso_sha256":"${ROLLOUT_SOURCE_ISO_SHA256}"}
EOF
printf 'release_iso=%s\nrelease_sidecar=%s\n' "$output" "$sidecar"
""",
        )
        self.task6_support.write_text(
            """from __future__ import annotations
import os
import sys

if sys.argv[1:3] != ["verify-public-evidence", "--evidence-dir"]:
    raise SystemExit(2)
if os.environ.get("ROLLOUT_TASK6_VERIFY", "pass") != "pass":
    print("Task 6 receipt rejected", file=sys.stderr)
    raise SystemExit(1)
with open(os.environ["ROLLOUT_COMMAND_LOG"], "a", encoding="utf-8") as log:
    log.write(f"task6-verify {sys.argv[3]}\\n")
if os.environ.get("ROLLOUT_REPLACE_TASK6_AFTER_VALIDATION") == "1":
    import json
    from pathlib import Path

    path = (
        Path(os.environ["ROLLOUT_TASK6_ORIGINAL"])
        / "acceptance-receipt.json"
    )
    value = json.loads(path.read_text(encoding="utf-8"))
    value["run"]["run_id"] = "run-" + "f" * 64
    value["writes"]["after_install"]["target_write_bytes"] = 16384
    path.write_text(
        json.dumps(value, sort_keys=True) + "\\n", encoding="utf-8"
    )
print("public_evidence=verified")
""",
            encoding="utf-8",
        )

    def _args(self) -> list[str]:
        return [
            "--backup-id",
            BACKUP_ID,
            "--source-commit",
            SOURCE_COMMIT,
            "--source-iso",
            self.source_iso.as_posix(),
            "--source-iso-sha256",
            SOURCE_ISO_SHA256,
            "--managed-iso-sha256",
            MANAGED_ISO_SHA256,
            "--release-id",
            RELEASE_ID,
            "--iso-dir",
            self.iso_dir.as_posix(),
            "--public-key",
            self.public_key.as_posix(),
            "--execution-ca",
            self.execution_ca.as_posix(),
            "--go",
            self.go.as_posix(),
            "--task6-evidence-dir",
            self.task6_evidence.as_posix(),
            "--pilot-record",
            self.pilot_record.as_posix(),
            "--receipt",
            self.receipt.as_posix(),
        ]

    def run(
        self,
        *,
        backup_state: str = "rehearsed",
        health_state: str = "ok",
        task6_verify: str = "pass",
        overrides: dict[str, str] | None = None,
    ) -> subprocess.CompletedProcess[str]:
        if not ROLLOUT.is_file():
            raise AssertionError("rollout gate is absent")
        environment = os.environ.copy()
        environment.update(
            {
                "ROLLOUT_BACKUP_STATE": backup_state,
                "ROLLOUT_COMMAND_LOG": str(self.command_log),
                "ROLLOUT_GIT_HEAD": SOURCE_COMMIT,
                "ROLLOUT_HEALTH_STATE": health_state,
                "ROLLOUT_HELPER_SHA256": "6" * 64,
                "ROLLOUT_INITRD_SHA256": "7" * 64,
                "ROLLOUT_MANAGED_ISO_SHA256": MANAGED_ISO_SHA256,
                "ROLLOUT_MANIFEST_SHA256": "8" * 64,
                "ROLLOUT_PILOT_ORIGINAL": self.pilot_record.as_posix(),
                "ROLLOUT_PUBLIC_KEY_HEX": "1" * 64,
                "ROLLOUT_PUBLIC_KEY_SHA256": "9" * 64,
                "ROLLOUT_ROOT": self.root.as_posix(),
                "ROLLOUT_SOURCE_COMMIT": SOURCE_COMMIT,
                "ROLLOUT_SOURCE_ISO_SHA256": SOURCE_ISO_SHA256,
                "ROLLOUT_TASK6_ORIGINAL": self.task6_evidence.as_posix(),
                "ROLLOUT_TASK6_VERIFY": task6_verify,
            }
        )
        if overrides:
            environment.update(overrides)
        command = [
            str(_bash()),
            "-c",
            (
                'PATH="$1:$PATH"; export PATH; shift; '
                'source "$1"; shift; '
                'rollout_install_execution_v2_main '
                '"$1" "$2" "$3" "$4" "$5" "${@:6}"'
            ),
            "task7-rollout",
            self.fake_bin.as_posix().replace("C:/", "/c/"),
            ROLLOUT.as_posix(),
            self.root.as_posix(),
            self.builder.as_posix(),
            self.installer.as_posix(),
            self.task6_support.as_posix(),
            PILOT_VERIFIER.as_posix(),
            *self._args(),
        ]
        return subprocess.run(
            command,
            cwd=REPO_ROOT,
            env=environment,
            check=False,
            capture_output=True,
            text=True,
        )

    def commands(self) -> list[str]:
        if not self.command_log.exists():
            return []
        return self.command_log.read_text(encoding="utf-8").splitlines()


def test_rollout_stops_before_mutation_without_rehearsed_backup(
    tmp_path: Path,
) -> None:
    sandbox = RolloutSandbox(tmp_path)
    before = sandbox.destination(
        "/etc/systemd/system/alt-install-session.service"
    ).read_bytes()

    completed = sandbox.run(backup_state="not_rehearsed")

    assert completed.returncode != 0
    assert "rehearsed backup" in completed.stderr.lower()
    assert not sandbox.destination(
        "/etc/systemd/system/alt-install-execution.service"
    ).exists()
    assert (
        sandbox.destination(
            "/etc/systemd/system/alt-install-session.service"
        ).read_bytes()
        == before
    )
    assert not sandbox.receipt.exists()
    assert not any(command.startswith("installer ") for command in sandbox.commands())


def test_rollout_rejects_active_execution_before_mutation(
    tmp_path: Path,
) -> None:
    sandbox = RolloutSandbox(tmp_path)
    session = sandbox.destination(
        "/var/lib/alt-deploy/install-sessions/active/status.json"
    )
    session.parent.mkdir()
    session.write_text(
        json.dumps({"execution": {"state": "authorized"}}),
        encoding="utf-8",
    )

    completed = sandbox.run()

    assert completed.returncode != 0
    assert "active execution session" in completed.stderr.lower()
    assert not any(command.startswith("installer ") for command in sandbox.commands())


@pytest.mark.parametrize(
    ("overrides", "expected_error"),
    (
        ({"ROLLOUT_GIT_HEAD": "b" * 40}, "exact head"),
        ({"ROLLOUT_GIT_MERGE_RC": "1"}, "merged"),
        ({"ROLLOUT_GIT_STATUS": " M deploy/alt-linux/api/x.py\n"}, "clean"),
    ),
)
def test_rollout_requires_exact_clean_merged_commit_before_mutation(
    tmp_path: Path,
    overrides: dict[str, str],
    expected_error: str,
) -> None:
    sandbox = RolloutSandbox(tmp_path)

    completed = sandbox.run(overrides=overrides)

    assert completed.returncode != 0
    assert expected_error in completed.stderr.lower()
    assert not any(command.startswith("installer ") for command in sandbox.commands())


def test_rollout_requires_source_iso_digest_before_mutation(
    tmp_path: Path,
) -> None:
    sandbox = RolloutSandbox(tmp_path)
    sandbox.source_iso.write_bytes(b"replaced-source")

    completed = sandbox.run()

    assert completed.returncode != 0
    assert "source iso" in completed.stderr.lower()
    assert not any(command.startswith("installer ") for command in sandbox.commands())


def test_rollout_requires_pilot_bound_to_managed_iso_before_mutation(
    tmp_path: Path,
) -> None:
    sandbox = RolloutSandbox(tmp_path)
    record = _pilot_record(iso_sha256="e" * 64)
    sandbox.pilot_record.write_text(json.dumps(record), encoding="utf-8")

    completed = sandbox.run()

    assert completed.returncode != 0
    assert "pilot" in completed.stderr.lower()
    assert not any(command.startswith("installer ") for command in sandbox.commands())


def test_rollout_health_failure_restores_only_staged_v2_runtime(
    tmp_path: Path,
) -> None:
    sandbox = RolloutSandbox(tmp_path)
    v1 = sandbox.destination(
        "/etc/systemd/system/alt-install-session.service"
    )
    before_v1 = v1.read_bytes()

    completed = sandbox.run(health_state="starting")

    assert completed.returncode != 0
    assert "health" in completed.stderr.lower()
    assert not sandbox.destination(
        "/etc/systemd/system/alt-install-execution.service"
    ).exists()
    assert not sandbox.destination(
        "/opt/alt-install-execution-api/current"
    ).exists()
    assert not sandbox.destination(
        "/opt/alt-install-execution-api/releases/new-release"
    ).exists()
    assert v1.read_bytes() == before_v1
    assert not any(command.startswith("builder ") for command in sandbox.commands())
    assert not sandbox.receipt.exists()


def test_rollout_uses_validated_pilot_snapshot_after_source_replacement(
    tmp_path: Path,
) -> None:
    sandbox = RolloutSandbox(tmp_path)
    pilot_before = sandbox.pilot_record.read_bytes()

    completed = sandbox.run(
        overrides={"ROLLOUT_REPLACE_PILOT_AFTER_VALIDATION": "1"}
    )

    assert completed.returncode == 0, completed.stderr
    assert json.loads(
        sandbox.pilot_record.read_text(encoding="utf-8")
    )["asset_id"] == "ALT-WS-REPLACED"
    receipt = json.loads(sandbox.receipt.read_text(encoding="utf-8"))
    assert receipt["pilot"]["asset_id"] == "ALT-WS-017"
    assert receipt["pilot"]["record_sha256"] == hashlib.sha256(
        pilot_before
    ).hexdigest()


def test_rollout_uses_verified_task6_snapshot_after_source_replacement(
    tmp_path: Path,
) -> None:
    sandbox = RolloutSandbox(tmp_path)
    task6_before = (
        sandbox.task6_evidence / "acceptance-receipt.json"
    ).read_bytes()

    completed = sandbox.run(
        overrides={"ROLLOUT_REPLACE_TASK6_AFTER_VALIDATION": "1"}
    )

    assert completed.returncode == 0, completed.stderr
    replaced = json.loads(
        (
            sandbox.task6_evidence / "acceptance-receipt.json"
        ).read_text(encoding="utf-8")
    )
    assert replaced["writes"]["after_install"]["target_write_bytes"] == 16384
    receipt = json.loads(sandbox.receipt.read_text(encoding="utf-8"))
    assert (
        receipt["task6"]["writes"]["after_install"]["target_write_bytes"]
        == 8192
    )
    assert receipt["task6"]["receipt_sha256"] == hashlib.sha256(
        task6_before
    ).hexdigest()
    task6_commands = [
        command
        for command in sandbox.commands()
        if command.startswith("task6-verify ")
    ]
    assert len(task6_commands) == 1
    assert sandbox.task6_evidence.as_posix() not in task6_commands[0]


def test_rollout_final_session_scan_runs_under_canonical_lock(
    tmp_path: Path,
) -> None:
    sandbox = RolloutSandbox(tmp_path)

    completed = sandbox.run(
        overrides={"ROLLOUT_CREATE_ACTIVE_ON_LOCK": "1"}
    )

    assert completed.returncode != 0
    assert "active execution session" in completed.stderr.lower()
    assert any(
        command.startswith("flock --exclusive ")
        for command in sandbox.commands()
    )
    assert not any(
        command.startswith("installer ") for command in sandbox.commands()
    )


def test_rollout_holds_session_lock_through_v2_health_boundary(
    tmp_path: Path,
) -> None:
    sandbox = RolloutSandbox(tmp_path)

    completed = sandbox.run()

    assert completed.returncode == 0, completed.stderr
    commands = sandbox.commands()
    lock = next(
        index
        for index, command in enumerate(commands)
        if command.startswith("flock --exclusive ")
    )
    installer = next(
        index
        for index, command in enumerate(commands)
        if command.startswith("installer ")
    )
    health = next(
        index
        for index, command in enumerate(commands)
        if command.startswith("curl ")
    )
    unlock = next(
        index
        for index, command in enumerate(commands)
        if command.startswith("flock --unlock ")
    )
    assert lock < installer < health < unlock


def test_rollback_failure_is_reported_and_preserves_live_staged_runtime(
    tmp_path: Path,
) -> None:
    sandbox = RolloutSandbox(tmp_path)

    completed = sandbox.run(
        health_state="starting",
        overrides={"ROLLOUT_SYSTEMCTL_STOP_FAIL": "1"},
    )

    assert completed.returncode != 0
    assert "rollback failed" in completed.stderr.lower()
    assert sandbox.destination(
        "/opt/alt-install-execution-api/releases/new-release"
    ).exists()
    assert sandbox.destination(
        "/etc/systemd/system/alt-install-execution.service"
    ).exists()
    assert not any(
        command.startswith("systemctl start ")
        for command in sandbox.commands()
    )
    assert not sandbox.receipt.exists()


def test_task6_failure_preserves_immutable_iso_but_restores_v2_runtime(
    tmp_path: Path,
) -> None:
    sandbox = RolloutSandbox(tmp_path)

    completed = sandbox.run(task6_verify="fail")

    published = (
        sandbox.iso_dir
        / f"alt-kworkstation-11.4-agent-v2-{RELEASE_ID}.iso"
    )
    assert completed.returncode != 0
    assert "task 6" in completed.stderr.lower()
    assert published.read_bytes() == MANAGED_ISO_BYTES
    assert not sandbox.destination(
        "/etc/systemd/system/alt-install-execution.service"
    ).exists()
    assert not sandbox.destination(
        "/opt/alt-install-execution-api/releases/new-release"
    ).exists()
    assert not sandbox.receipt.exists()


def test_rollout_never_overwrites_existing_immutable_v2_iso(
    tmp_path: Path,
) -> None:
    sandbox = RolloutSandbox(tmp_path)
    published = (
        sandbox.iso_dir
        / f"alt-kworkstation-11.4-agent-v2-{RELEASE_ID}.iso"
    )
    published.write_bytes(b"existing-immutable-release")

    completed = sandbox.run()

    assert completed.returncode != 0
    assert published.read_bytes() == b"existing-immutable-release"
    assert not sandbox.receipt.exists()
    assert not sandbox.destination(
        "/opt/alt-install-execution-api/releases/new-release"
    ).exists()


def test_rollout_produces_receipt_only_after_all_gates(
    tmp_path: Path,
) -> None:
    sandbox = RolloutSandbox(tmp_path)
    v1 = sandbox.destination(
        "/etc/systemd/system/alt-install-session.service"
    )
    before_v1 = v1.read_bytes()

    completed = sandbox.run()

    assert completed.returncode == 0, completed.stderr
    receipt = json.loads(sandbox.receipt.read_text(encoding="utf-8"))
    assert receipt["result"] == "pass"
    assert receipt["source_commit"] == SOURCE_COMMIT
    assert receipt["backup"]["backup_id"] == BACKUP_ID
    assert receipt["controller"] == {
        "health": {
            "schema_version": 1,
            "service": "alt-install-execution",
            "status": "ok",
        },
        "listener": "192.168.100.17:18092",
        "transport": "tls",
        "unit": "alt-install-execution.service",
    }
    assert receipt["iso"]["managed_iso_sha256"] == MANAGED_ISO_SHA256
    assert receipt["iso"]["source_iso_sha256"] == SOURCE_ISO_SHA256
    assert receipt["pilot"]["validation_only"] is True
    assert receipt["pilot"]["asset_id"] == "ALT-WS-017"
    assert receipt["task6"]["result"] == "pass"
    assert receipt["task6"]["writes"] == {
        "after_install": {
            "sentinel_write_bytes": 0,
            "target_write_bytes": 8192,
        },
        "before_authorization": {
            "sentinel_write_bytes": 0,
            "target_write_bytes": 0,
        },
    }
    assert receipt["v1"] == {
        "endpoint": "192.168.100.17:18090",
        "mode": "no-write",
        "status": "unchanged",
    }
    assert v1.read_bytes() == before_v1
    assert not any(
        "alt-install-session.service" in command
        for command in sandbox.commands()
    )
    assert "18090" not in "\n".join(sandbox.commands())


def test_rollout_refuses_to_replace_production_receipt(
    tmp_path: Path,
) -> None:
    sandbox = RolloutSandbox(tmp_path)
    sandbox.receipt.write_text("existing-receipt\n", encoding="utf-8")

    completed = sandbox.run()

    assert completed.returncode != 0
    assert sandbox.receipt.read_text(encoding="utf-8") == "existing-receipt\n"
    assert not any(command.startswith("installer ") for command in sandbox.commands())


def test_task7_documentation_keeps_pilot_validation_only() -> None:
    assert RUNBOOK.is_file()
    assert PILOT_TEMPLATE.is_file()
    runbook = RUNBOOK.read_text(encoding="utf-8")
    template = PILOT_TEMPLATE.read_text(encoding="utf-8")

    for text in (runbook, template):
        assert "validation-only" in text.lower()
        assert "192.168.100.17:18092" in text
        assert "192.168.100.17:18090" in text
        assert "does not authorize" in text.lower()
    assert "no post-write rollback" in runbook.lower()
    assert "Task 6" in runbook
    assert "backup" in runbook.lower()
    assert "DMI UUID" in template
    assert "disk fingerprint" in template.lower()
    assert "maintenance" in template.lower()
    assert "rollback owner" in template.lower()
