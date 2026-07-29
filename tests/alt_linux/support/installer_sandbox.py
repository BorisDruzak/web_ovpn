from __future__ import annotations

import json
import os
import shlex
import shutil
import subprocess
import sys
from dataclasses import dataclass
from pathlib import Path


REPO_ROOT = Path(__file__).resolve().parents[3]
ALT_ROOT = REPO_ROOT / "deploy" / "alt-linux"
LIBRARY_PATH = ALT_ROOT / "install-control-plane-lib.sh"
PUBLIC_INSTALLER = ALT_ROOT / "install-control-plane.sh"
INSTALL_SESSION_INSTALLER = ALT_ROOT / "install-install-session-api.sh"
DEFAULT_ROLLBACK_BACKUP_ID = "backup-20260722T120000Z-11111111"


@dataclass
class InstallerSandbox:
    root: Path
    fake_bin: Path
    command_log: Path

    @classmethod
    def create(cls, tmp_path: Path) -> "InstallerSandbox":
        sandbox = cls(
            root=tmp_path / "controller-root",
            fake_bin=tmp_path / "fake-bin",
            command_log=tmp_path / "commands.jsonl",
        )
        sandbox.root.mkdir()
        sandbox.fake_bin.mkdir()
        sandbox._seed_runtime_state()
        sandbox._install_fakes()
        sandbox._install_backup_tool_fake()
        return sandbox

    def destination(self, absolute_path: str) -> Path:
        return self.root / absolute_path.lstrip("/")

    def _write(self, absolute_path: str, content: str) -> Path:
        path = self.destination(absolute_path)
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(content, encoding="utf-8")
        return path

    def _seed_runtime_state(self) -> None:
        files = {
            "/home/altserver/ansible/group_vars/vault.yml": "$ANSIBLE_VAULT;1.1;AES256\nfixture\n",
            "/home/altserver/.ansible-vault-pass": "fixture-pass\n",
            "/home/altserver/.ssh/id_ed25519": "fixture-private-key\n",
            "/home/altserver/.ssh/id_ed25519.pub": "fixture-public-key\n",
            "/home/altserver/.ssh/known_hosts_autoinstall": "fixture-host-key\n",
            "/srv/alt-deploy/bootstrap/ansible_authorized_keys": "ssh-ed25519 fixture\n",
            "/srv/alt-deploy/metadata/autoinstall.scm": "fixture-autoinstall\n",
            "/srv/alt-deploy/metadata/vm-profile.scm": "fixture-vm-profile\n",
            "/srv/alt-deploy/metadata/pkg-groups.tar": "fixture-pkg-groups\n",
            "/srv/alt-deploy/metadata/install-scripts.tar": "fixture-install-scripts\n",
            "/var/lib/alt-deploy/jobs/job-20260721T120000Z-11111111/request.json": "{}\n",
            "/var/lib/alt-deploy/jobs/job-20260721T120000Z-11111111/status.json": "{}\n",
            "/var/lib/alt-deploy/jobs/job-20260721T120000Z-11111111/ansible.log": "fixture-log\n",
            "/var/lib/alt-deploy/assignments/fixture.json": "{}\n",
            "/srv/alt-deploy/registration/ready/fixture.json": "{}\n",
            "/srv/alt-deploy/registration/failed/fixture.json": "{}\n",
        }
        for path, content in files.items():
            self._write(path, content)
        self.destination(
            "/srv/alt-deploy/registration/pending"
        ).mkdir(parents=True, exist_ok=True)
        self.destination(
            "/home/altserver/.ssh/id_ed25519"
        ).chmod(0o600)

    def _fake_script(self, name: str, body: str) -> None:
        path = self.fake_bin / name
        path.write_text(
            "#!/bin/bash\nset -Eeuo pipefail\n"
            "{ printf '%q ' " + shlex.quote(name)
            + " \"$@\"; printf '\\n'; } >> \"${INSTALLER_COMMAND_LOG}\"\n"
            + body,
            encoding="utf-8",
        )
        path.chmod(0o755)

    def _install_backup_tool_fake(self) -> None:
        path = self.destination("/usr/local/sbin/alt-deploy-backup")
        path.parent.mkdir(parents=True, exist_ok=True)
        script = r'''#!/bin/bash
set -Eeuo pipefail
{ printf '%q ' alt-deploy-backup "$@"; printf '\n'; } >> "$INSTALLER_COMMAND_LOG"
command=${1:-}
case "${command}" in
  rehearse-status)
    if [[ ${INSTALLER_BACKUP_STATUS_RC:-0} != 0 ]]; then
      exit "${INSTALLER_BACKUP_STATUS_RC}"
    fi
    if [[ -n ${INSTALLER_BACKUP_STATUS_PAYLOAD:-} ]]; then
      printf '%s\n' "${INSTALLER_BACKUP_STATUS_PAYLOAD}"
    else
      printf '{"status":"ok","result":"backup_rehearsed","backup_id":"%s","manifest_sha256":"%064d","verification_sha256":"%064d"}\n' "${2:-}" 0 0
    fi
    exit 0
    ;;
  rollout-begin) exit "${INSTALLER_ROLLOUT_BEGIN_RC:-0}" ;;
  rollout-authorize) exit "${INSTALLER_ROLLOUT_AUTHORIZE_RC:-0}" ;;
  rollout-revoke) exit "${INSTALLER_ROLLOUT_REVOKE_RC:-0}" ;;
  rollout-complete) exit "${INSTALLER_ROLLOUT_COMPLETE_RC:-0}" ;;
esac
exit 2
'''
        path.write_text(
            script,
            encoding="utf-8",
        )
        path.chmod(0o750)
        guard = self.destination(
            "/etc/systemd/system/alt-deploy-guard.service"
        )
        guard.parent.mkdir(parents=True, exist_ok=True)
        guard.write_text("[Service]\nType=oneshot\n", encoding="utf-8")
        guard.chmod(0o644)

    def _install_fakes(self) -> None:
        self._fake_script(
            "id",
            "[[ ${1:-} == altserver ]] && exit 0\nexec /usr/bin/id \"$@\"\n",
        )
        self._fake_script(
            "sudo",
            "case \" $* \" in\n"
            "  *\" jobs active \"*) printf '%s\\n' \"$INSTALLER_JOBS_JSON\"; exit \"${INSTALLER_JOBS_RC:-0}\" ;;\n"
            "  *\" vault check \"*) exit \"${INSTALLER_VAULT_RC:-0}\" ;;\n"
            "  *\" controller permissions \"*) exit \"${INSTALLER_PERMISSIONS_RC:-0}\" ;;\n"
            "  *\" test -r \"*) exit \"${INSTALLER_STATIC_READABLE_RC:-0}\" ;;\n"
            "  *\" controller readiness \"*)\n"
            "    if [[ -n ${INSTALLER_READINESS_FAILS_BEFORE_SUCCESS:-} ]]; then\n"
            "      count=0\n"
            "      [[ -f ${INSTALLER_READINESS_COUNTER:?} ]] && count=$(cat \"$INSTALLER_READINESS_COUNTER\")\n"
            "      if (( count < INSTALLER_READINESS_FAILS_BEFORE_SUCCESS )); then\n"
            "        printf '%s\\n' \"$((count + 1))\" > \"$INSTALLER_READINESS_COUNTER\"\n"
            "        exit 11\n"
            "      fi\n"
            "    fi\n"
            "    exit \"${INSTALLER_READINESS_RC:-0}\" ;;\n"
            "esac\nexit 0\n",
        )
        self._fake_script(
            "systemctl",
            "if [[ ${1:-} == is-active && ${3:-} == alt-deploy-process.service ]]; then\n"
            "  [[ ${INSTALLER_PROCESS_ACTIVE:-0} == 1 ]] && exit 0\n"
            "  exit 3\n"
            "fi\n"
            "if [[ ${1:-} == show ]]; then printf 'loaded\\n'; fi\n"
            "exit 0\n",
        )
        self._fake_script(
            "stat",
            "if [[ ${1:-} == -c && ${2:-} == '%u %g %a' ]]; then\n"
            "  exec /usr/bin/stat \"$@\"\n"
            "fi\n"
            "if [[ ${INSTALLER_STAT_UNSAFE:-0} == 1 ]]; then\n"
            "  printf '644 root root\\n'\n"
            "else\n"
            "  printf '600 altserver altserver\\n'\n"
            "fi\n",
        )
        self._fake_script(
            "python3",
            "if [[ ${1:-} == -c ]]; then exec "
            + shlex.quote(sys.executable)
            + " \"$@\"; fi\nexit \"${INSTALLER_PYTHON_RC:-0}\"\n",
        )
        self._fake_script(
            "install",
            "directory_mode=0\nmode=\nargs=()\n"
            "while (( $# )); do\n"
            "  case \"$1\" in\n"
            "    -d) directory_mode=1; shift ;;\n"
            "    -o|-g) shift 2 ;;\n"
            "    -m) mode=$2; shift 2 ;;\n"
            "    --) shift; while (( $# )); do args+=(\"$1\"); shift; done ;;\n"
            "    *) args+=(\"$1\"); shift ;;\n"
            "  esac\n"
            "done\n"
            "if (( directory_mode )); then\n"
            "  for path in \"${args[@]}\"; do\n"
            "    mkdir -p \"$path\"\n"
            "    [[ -n $mode ]] && /bin/chmod \"$mode\" \"$path\"\n"
            "  done\n"
            "  exit 0\n"
            "fi\n"
            "(( ${#args[@]} >= 2 )) || exit 2\n"
            "source=${args[${#args[@]}-2]}\n"
            "destination=${args[${#args[@]}-1]}\n"
            "mkdir -p \"$(dirname \"$destination\")\"\n"
            "/bin/cp \"$source\" \"$destination\"\n"
            "[[ -n $mode ]] && /bin/chmod \"$mode\" \"$destination\"\n",
        )
        self._fake_script("cp", "exec /bin/cp \"$@\"\n")
        self._fake_script("rm", "exec /bin/rm \"$@\"\n")
        self._fake_script("chmod", "exec /bin/chmod \"$@\"\n")
        self._fake_script("find", "exec /usr/bin/find \"$@\"\n")
        self._fake_script("chown", "exit 0\n")
        for name in (
            "ansible-playbook",
            "ansible-vault",
            "systemd-run",
            "ssh",
            "ssh-keyscan",
            "mkpasswd",
        ):
            self._fake_script(name, "exit 0\n")

    def environment(self, **overrides: str) -> dict[str, str]:
        environment = os.environ.copy()
        environment.update(
            {
                "PATH": f"{self.fake_bin}:{environment['PATH']}",
                "INSTALLER_COMMAND_LOG": str(self.command_log),
                "ALT_DEPLOY_BACKUP_EXPECTED_ROOT_UID": str(
                    getattr(os, "getuid", lambda: 0)()
                ),
                "ALT_DEPLOY_BACKUP_EXPECTED_ROOT_GID": str(
                    getattr(os, "getgid", lambda: 0)()
                ),
                "INSTALLER_JOBS_JSON": json.dumps(
                    {
                        "status": "ok",
                        "active_jobs": [],
                        "count": 0,
                    }
                ),
            }
        )
        environment.update(overrides)
        return environment

    def _run_function(
        self,
        function_name: str,
        *arguments: str,
        **overrides: str,
    ) -> subprocess.CompletedProcess[str]:
        rendered = " ".join(
            json.dumps(value)
            for value in (str(self.root), *arguments)
        )
        command = (
            "set -Eeuo pipefail; "
            f"REPO_ROOT={json.dumps(str(REPO_ROOT))}; "
            f"ALT_ROOT={json.dumps(str(ALT_ROOT))}; "
            f"source {json.dumps(str(LIBRARY_PATH))}; "
            f"{function_name} {rendered}"
        )
        return subprocess.run(
            ["/bin/bash", "-c", command],
            text=True,
            capture_output=True,
            check=False,
            cwd=REPO_ROOT,
            env=self.environment(**overrides),
        )

    def run_prechecks(
        self,
        *,
        rollback_backup_id: str = DEFAULT_ROLLBACK_BACKUP_ID,
        **overrides: str,
    ) -> subprocess.CompletedProcess[str]:
        return self._run_function(
            "install_control_plane_prechecks",
            rollback_backup_id,
            **overrides,
        )

    def run_library(
        self,
        *,
        rollback_backup_id: str = DEFAULT_ROLLBACK_BACKUP_ID,
        **overrides: str,
    ) -> subprocess.CompletedProcess[str]:
        return self._run_function(
            "install_control_plane_main",
            rollback_backup_id,
            **overrides,
        )

    def commands(self) -> list[list[str]]:
        if not self.command_log.exists():
            return []
        return [
            shlex.split(line)
            for line in self.command_log.read_text(
                encoding="utf-8"
            ).splitlines()
            if line
        ]

    def protected_snapshot(self) -> dict[str, bytes]:
        roots = (
            self.destination("/home/altserver"),
            self.destination("/var/lib/alt-deploy"),
            self.destination("/srv/alt-deploy"),
        )
        result: dict[str, bytes] = {}
        for root in roots:
            if not root.exists():
                continue
            for path in sorted(root.rglob("*")):
                if path.is_file():
                    result[str(path.relative_to(self.root))] = path.read_bytes()
        return result

    def seed_pending(self) -> Path:
        return self._write(
            "/srv/alt-deploy/registration/pending/pending.json",
            "{}\n",
        )

    @staticmethod
    def mutation_commands(commands: list[list[str]]) -> list[list[str]]:
        mutations: list[list[str]] = []
        for command in commands:
            if not command:
                continue
            if command[0] in {
                "install",
                "cp",
                "rm",
                "chown",
                "chmod",
                "find",
            }:
                mutations.append(command)
            elif command[0] == "systemctl" and len(command) > 1:
                if command[1] in {
                    "stop",
                    "restart",
                    "enable",
                    "disable",
                    "daemon-reload",
                }:
                    mutations.append(command)
            elif command[0] == "alt-deploy-backup" and len(command) > 1:
                if command[1].startswith("rollout-"):
                    mutations.append(command)
        return mutations


@dataclass
class InstallSessionInstallerSandbox(InstallerSandbox):
    service_state: Path
    health_counter: Path

    @staticmethod
    def _bash_path(path: Path) -> str:
        rendered = path.resolve().as_posix()
        if len(rendered) >= 3 and rendered[1:3] == ":/":
            return f"/{rendered[0].lower()}/{rendered[3:]}"
        return rendered

    @classmethod
    def create(cls, tmp_path: Path) -> "InstallSessionInstallerSandbox":
        sandbox = cls(
            root=tmp_path / "install-session-root",
            fake_bin=tmp_path / "install-session-fake-bin",
            command_log=tmp_path / "install-session-commands.jsonl",
            service_state=tmp_path / "install-session-service-state",
            health_counter=tmp_path / "install-session-health-counter",
        )
        sandbox.root.mkdir()
        sandbox.fake_bin.mkdir()
        sandbox._seed_runtime_state()
        sandbox._install_fakes()
        sandbox._install_backup_tool_fake()
        sandbox._seed_install_session_state()
        return sandbox

    def _seed_install_session_state(self) -> None:
        private_key = self._write(
            "/var/lib/alt-deploy-secrets/install-plan-ed25519.pem",
            "fixture-install-signing-private-key\n",
        )
        private_key.chmod(0o600)
        public_key = self._write(
            "/etc/alt-deploy/install-plan-ed25519.pub",
            '{"fixture":"install-signing-public-key"}\n',
        )
        public_key.chmod(0o644)
        previous = self.destination(
            "/opt/alt-install-session-api/releases/existing-release"
        )
        previous.mkdir(parents=True)
        (previous / "marker").write_text("existing\n", encoding="utf-8")
        current = self.destination("/opt/alt-install-session-api/current")
        current.parent.mkdir(parents=True, exist_ok=True)
        current.symlink_to(
            self._bash_path(previous), target_is_directory=True
        )
        unit = self.destination(
            "/etc/systemd/system/alt-install-session.service"
        )
        unit.parent.mkdir(parents=True, exist_ok=True)
        unit.write_text("[Service]\nExecStart=/existing\n", encoding="utf-8")
        self.service_state.write_bytes(b"enabled active\n")

    def _install_fakes(self) -> None:
        super()._install_fakes()
        self._fake_script(
            "python3",
            "if [[ ${1:-} == -c ]]; then exec "
            + shlex.quote(Path(sys.executable).as_posix())
            + " \"$@\"; fi\n"
            "exit \"${INSTALL_SESSION_KEY_INIT_RC:-0}\"\n",
        )
        self._fake_script(
            "systemctl",
            r'''state_file=${INSTALL_SESSION_SERVICE_STATE:?}
read -r enabled active < "$state_file"
action=${1:-}
unit=${@: -1}
case "$action" in
  is-enabled)
    status=${INSTALL_SESSION_IS_ENABLED_STATUS:-$enabled}
    printf '%s\n' "$status"
    if [[ -n ${INSTALL_SESSION_IS_ENABLED_RC+x} ]]; then
      exit "$INSTALL_SESSION_IS_ENABLED_RC"
    fi
    [[ $unit == alt-install-session.service && $status == enabled ]]
    ;;
  is-active)
    status=${INSTALL_SESSION_IS_ACTIVE_STATUS:-$active}
    printf '%s\n' "$status"
    if [[ -n ${INSTALL_SESSION_IS_ACTIVE_RC+x} ]]; then
      exit "$INSTALL_SESSION_IS_ACTIVE_RC"
    fi
    [[ $unit == alt-install-session.service && $status == active ]] && exit 0
    exit 3
    ;;
  enable)
    [[ $unit == alt-install-session.service ]] || exit 90
    enabled=enabled
    if [[ " $* " == *" --now "* ]]; then
      active=active
      if [[ ${INSTALL_SESSION_ACTIVATION_RC:-0} != 0 ]]; then
        active=inactive
        printf '%s %s\n' "$enabled" "$active" > "$state_file"
        exit "${INSTALL_SESSION_ACTIVATION_RC}"
      fi
    fi
    printf '%s %s\n' "$enabled" "$active" > "$state_file"
    ;;
  disable)
    [[ $unit == alt-install-session.service ]] || exit 90
    enabled=disabled
    [[ " $* " == *" --now "* ]] && active=inactive
    printf '%s %s\n' "$enabled" "$active" > "$state_file"
    ;;
  start)
    [[ $unit == alt-install-session.service ]] || exit 90
    active=active
    printf '%s %s\n' "$enabled" "$active" > "$state_file"
    ;;
  stop)
    [[ $unit == alt-install-session.service ]] || exit 90
    active=inactive
    printf '%s %s\n' "$enabled" "$active" > "$state_file"
    ;;
  daemon-reload) ;;
  *) exit 0 ;;
esac
''',
        )
        self._fake_script(
            "ss",
            "if [[ ${INSTALL_SESSION_SS_RC:-0} != 0 ]]; then\n"
            "  exit \"$INSTALL_SESSION_SS_RC\"\n"
            "fi\n"
            "printf '%s' \"${INSTALL_SESSION_SS_OUTPUT:-}\"\n",
        )
        self._fake_script(
            "awk",
            "if [[ -n ${INSTALL_SESSION_AWK_RC+x} ]]; then\n"
            "  exit \"$INSTALL_SESSION_AWK_RC\"\n"
            "fi\n"
            "exec /usr/bin/awk \"$@\"\n",
        )
        self._fake_script(
            "curl",
            "counter_file=${INSTALL_SESSION_HEALTH_COUNTER:?}\n"
            "count=0\n"
            "[[ -f $counter_file ]] && count=$(<\"$counter_file\")\n"
            "count=$((count + 1))\n"
            "printf '%s\\n' \"$count\" > \"$counter_file\"\n"
            "if [[ ${INSTALL_SESSION_HEALTH_RC:-0} != 0 ]]; then\n"
            "  exit \"${INSTALL_SESSION_HEALTH_RC}\"\n"
            "fi\n"
            "if (( count <= ${INSTALL_SESSION_HEALTH_FAILS_BEFORE_SUCCESS:-0} )); then\n"
            "  printf '%s\\n' "
            "'{\"schema_version\":1,\"service\":"
            "\"alt-install-session\",\"status\":\"starting\"}'\n"
            "  exit 0\n"
            "fi\n"
            "if [[ -n ${INSTALL_SESSION_HEALTH_PAYLOAD+x} ]]; then\n"
            "  printf '%s\\n' \"$INSTALL_SESSION_HEALTH_PAYLOAD\"\n"
            "else\n"
            "  printf '%s\\n' "
            "'{\"schema_version\":1,\"service\":"
            "\"alt-install-session\",\"status\":\"ok\"}'\n"
            "fi\n",
        )
        self._fake_script(
            "flock",
            "exit \"${INSTALL_SESSION_FLOCK_RC:-0}\"\n",
        )
        self._fake_script("sleep", "exit 0\n")
        self._fake_script(
            "stat",
            r'''if [[ ${1:-} == -c && ${2:-} == '%U %G %a' ]]; then
  path=${@: -1}
  case "$path" in
    */alt-install-session-installer.lock)
      [[ ${INSTALL_SESSION_INSTALLER_LOCK_STAT_UNSAFE:-0} == 1 ]] &&
        printf 'root root 666\n' ||
        printf 'root root 600\n'
      ;;
    */install-sessions.lock)
      [[ ${INSTALL_SESSION_STORAGE_STAT_UNSAFE:-0} == 1 ]] &&
        printf 'root root 644\n' ||
        printf 'altserver altserver 600\n'
      ;;
    */install-sessions)
      [[ ${INSTALL_SESSION_STORAGE_STAT_UNSAFE:-0} == 1 ]] &&
        printf 'root root 755\n' ||
        printf 'altserver altserver 700\n'
      ;;
    *) exec /usr/bin/stat "$@" ;;
  esac
  exit 0
fi
if [[ ${1:-} == -c && ${2:-} == '%u %g %a' ]]; then
  exec /usr/bin/stat "$@"
fi
if [[ ${INSTALLER_STAT_UNSAFE:-0} == 1 ]]; then
  printf '644 root root\n'
else
  printf '600 altserver altserver\n'
fi
''',
        )
        self._fake_script("mv", "exec /bin/mv \"$@\"\n")
        self._fake_script(
            "ln",
            "args=(\"$@\")\n"
            "target=${args[${#args[@]}-2]}\n"
            "link=${args[${#args[@]}-1]}\n"
            "windows_link=$(cygpath -w \"$link\")\n"
            "exec "
            + shlex.quote(Path(sys.executable).as_posix())
            + " -c 'import os, sys; os.symlink("
            "sys.argv[1], sys.argv[2], target_is_directory=True)' "
            '"$target" "$windows_link"\n',
        )
        self._fake_script("readlink", "exec /usr/bin/readlink \"$@\"\n")

    def environment(self, **overrides: str) -> dict[str, str]:
        environment = super().environment(
            INSTALL_SESSION_SERVICE_STATE=self._bash_path(
                self.service_state
            ),
            INSTALL_SESSION_HEALTH_COUNTER=self._bash_path(
                self.health_counter
            ),
        )
        environment["PATH"] = (
            f"{self._bash_path(self.fake_bin)}:{os.environ['PATH']}"
        )
        environment["INSTALLER_COMMAND_LOG"] = self._bash_path(
            self.command_log
        )
        environment.update(overrides)
        return environment

    def run_install(
        self,
        *,
        rollback_backup_id: str = DEFAULT_ROLLBACK_BACKUP_ID,
        **overrides: str,
    ) -> subprocess.CompletedProcess[str]:
        command = (
            "set -Eeuo pipefail; "
            f"export PATH={json.dumps(self._bash_path(self.fake_bin))}:"
            '"/usr/bin:/bin"; '
            f"source {json.dumps(self._bash_path(INSTALL_SESSION_INSTALLER))}; "
            "install_session_api_main "
            f"{json.dumps(self._bash_path(self.root))} "
            f"--rollback-backup-id {json.dumps(rollback_backup_id)}"
        )
        bash = shutil.which("bash") or "/bin/bash"
        return subprocess.run(
            [bash, "-c", command],
            text=True,
            capture_output=True,
            check=False,
            cwd=REPO_ROOT,
            env=self.environment(**overrides),
        )

    def run_rollback(
        self,
        **overrides: str,
    ) -> subprocess.CompletedProcess[str]:
        command = (
            "set -Eeuo pipefail; "
            f"export PATH={json.dumps(self._bash_path(self.fake_bin))}:"
            '"/usr/bin:/bin"; '
            f"source {json.dumps(self._bash_path(INSTALL_SESSION_INSTALLER))}; "
            "install_session_api_main "
            f"{json.dumps(self._bash_path(self.root))} --rollback"
        )
        bash = shutil.which("bash") or "/bin/bash"
        return subprocess.run(
            [bash, "-c", command],
            text=True,
            capture_output=True,
            check=False,
            cwd=REPO_ROOT,
            env=self.environment(**overrides),
        )

    def current_target(self) -> str:
        target = os.readlink(
            self.destination("/opt/alt-install-session-api/current")
        )
        rendered = target.replace("\\", "/")
        if rendered.startswith("//?/") and len(rendered) >= 7:
            drive = rendered[4].lower()
            rendered = f"/{drive}/{rendered[7:]}"
        return rendered

    def unit_text(self) -> str:
        return self.destination(
            "/etc/systemd/system/alt-install-session.service"
        ).read_text(encoding="utf-8")

    def service_status(self) -> tuple[str, str]:
        enabled, active = self.service_state.read_text(
            encoding="utf-8"
        ).split()
        return enabled, active

    def protected_snapshot(self) -> dict[str, bytes]:
        result = super().protected_snapshot()
        for root in (
            self.destination("/var/lib/alt-deploy-secrets"),
            self.destination("/etc/alt-deploy"),
        ):
            if not root.exists():
                continue
            for path in sorted(root.rglob("*")):
                if path.is_file():
                    result[str(path.relative_to(self.root))] = (
                        path.read_bytes()
                    )
        return result
