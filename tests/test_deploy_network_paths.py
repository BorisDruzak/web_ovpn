import json
from pathlib import Path
import shutil
import subprocess

import pytest


def test_installer_only_installs_role_only_path_sample_when_absent():
    installer = Path("deploy/install-openvpn-web.sh").read_text(encoding="utf-8")
    sample = Path("deploy/network-paths.json.sample").read_text(encoding="utf-8")
    assert "network-paths.json.sample" in installer
    assert "192.168." not in sample


def test_installer_does_not_enable_network_collection_timer():
    installer = Path("deploy/install-openvpn-web.sh").read_text(encoding="utf-8")
    assert "enable --now netctl-collect.timer" not in installer


def test_installer_does_not_create_or_enable_routeros_sources():
    installer = Path("deploy/install-openvpn-web.sh").read_text(encoding="utf-8")
    assert "192.168." not in installer
    assert "mikrotik-main.yaml" not in installer
    assert "mikrotik-hex.yaml" not in installer
    assert "enabled: true" not in installer


def test_default_deployment_verification_does_not_require_collection_timer():
    deployment = Path("docs/DEPLOYMENT.md").read_text(encoding="utf-8")
    default_verification = deployment.split("After deployment:", 1)[1].split("```", 2)[1]
    assert "systemctl is-active netctl-collect.timer" not in default_verification
    assert "separately approved timer activation" in deployment


def test_deployment_docs_require_operator_to_provision_routeros_source():
    deployment = Path("docs/DEPLOYMENT.md").read_text(encoding="utf-8")
    assert "The installer creates `/etc/netctl/sources.d/mikrotik-hex.yaml`" not in deployment
    assert "approved operator must provision `/etc/netctl/sources.d/mikrotik-hex.yaml`" in deployment


def test_clean_host_installer_bootstraps_only_empty_netctl_infrastructure():
    installer = Path("deploy/install-openvpn-web.sh").read_text(encoding="utf-8")

    assert "install -d -m 0750 -o netctl -g netctl /var/lib/netctl" in installer
    assert "install -d -m 0750 -o root -g netctl /etc/netctl /etc/netctl/sources.d" in installer
    for forbidden in (
        "/etc/netctl/secrets.env",
        "sources.d/mikrotik",
        "netctl --json collect",
        "enable --now netctl-collect.timer",
    ):
        assert forbidden not in installer


def test_installer_bootstraps_an_empty_role_only_server_registry():
    installer = Path("deploy/install-openvpn-web.sh").read_text(encoding="utf-8")
    sample_path = Path("deploy/server-roles.json.sample")

    assert json.loads(sample_path.read_text(encoding="utf-8")) == {"roles": []}
    assert "server-roles.json.sample" in installer


def _netctl_bootstrap_program(installer: str) -> str:
    validation_body = installer.split("validate_netctl_directory() {", 1)[1].split(
        "\n}\n\nSRC=", 1
    )[0]
    validation = "validate_netctl_directory() {" + validation_body + "\n}"
    bootstrap_tail = installer.split(
        "if ! sudo_cmd test -e /var/lib/netctl", 1
    )[1].split('\n\nsudo_cmd mkdir -p "$APP"', 1)[0]
    bootstrap = "if ! sudo_cmd test -e /var/lib/netctl" + bootstrap_tail
    bootstrap = bootstrap.replace("/var/lib/netctl", '"$STATE_DIR"')
    bootstrap = bootstrap.replace("/etc/netctl", '"$CONFIG_DIR"')
    return validation + "\n" + bootstrap


def _run_legacy_netctl_bootstrap(tmp_path: Path, config_metadata: str):
    bash = shutil.which("bash")
    if bash is None:
        pytest.skip("bash is required to execute the installer bootstrap")
    installer = Path("deploy/install-openvpn-web.sh").read_text(encoding="utf-8")
    state_dir = tmp_path / "state"
    config_dir = tmp_path / "config"
    sources_dir = config_dir / "sources.d"
    sources_dir.mkdir(parents=True)
    state_dir.mkdir()
    sentinel = sources_dir / "existing-source.yaml"
    sentinel.write_text("preserve", encoding="utf-8")
    log = tmp_path / "mutations.log"
    program = r'''
set -euo pipefail
to_posix() {
  if command -v cygpath >/dev/null 2>&1; then
    cygpath -u "$1"
  elif command -v wslpath >/dev/null 2>&1; then
    wslpath -u "$1"
  else
    printf '%s\n' "$1"
  fi
}
STATE_DIR="$(to_posix "$1")"
CONFIG_DIR="$(to_posix "$2")"
MUTATION_LOG="$(to_posix "$3")"
CONFIG_METADATA="$4"
declare -A METADATA
METADATA["$STATE_DIR"]="netctl:netctl:750"
METADATA["$CONFIG_DIR"]="$CONFIG_METADATA"
METADATA["$CONFIG_DIR/sources.d"]="$CONFIG_METADATA"
sudo_cmd() {
  local command_name="$1"
  shift
  case "$command_name" in
    test|readlink)
      command "$command_name" "$@"
      ;;
    stat)
      local path="${@: -1}"
      printf '%s\n' "${METADATA[$path]}"
      ;;
    chown)
      local owner_group="$1" path="$2" current="${METADATA[$2]}"
      METADATA["$path"]="$owner_group:${current##*:}"
      printf 'chown %s %s\n' "$owner_group" "$path" >> "$MUTATION_LOG"
      ;;
    chmod)
      local mode="${1#0}" path="$2" current="${METADATA[$2]}"
      METADATA["$path"]="${current%:*}:$mode"
      printf 'chmod %s %s\n' "$mode" "$path" >> "$MUTATION_LOG"
      ;;
    *)
      command "$command_name" "$@"
      ;;
  esac
}
''' + _netctl_bootstrap_program(installer) + r'''
[[ "${METADATA[$CONFIG_DIR]}" == "root:netctl:750" ]]
[[ "${METADATA[$CONFIG_DIR/sources.d]}" == "root:netctl:750" ]]
test -f "$CONFIG_DIR/sources.d/existing-source.yaml"
'''
    result = subprocess.run(
        [bash, "-c", program, "netctl-bootstrap", str(state_dir), str(config_dir), str(log), config_metadata],
        text=True,
        encoding="utf-8",
        errors="replace",
        capture_output=True,
        check=False,
    )
    return result, log, sentinel


def test_legacy_root_owned_netctl_directories_are_safely_migrated_in_place(tmp_path):
    result, log, sentinel = _run_legacy_netctl_bootstrap(tmp_path / "legacy", "root:root:755")

    assert result.returncode == 0, result.stderr
    assert sentinel.read_text(encoding="utf-8") == "preserve"
    mutations = log.read_text(encoding="utf-8")
    assert mutations.count("chown root:netctl") == 2
    assert mutations.count("chmod 750") == 2


def test_unsafe_netctl_directory_metadata_is_rejected_without_mutation(tmp_path):
    result, log, sentinel = _run_legacy_netctl_bootstrap(tmp_path / "unsafe", "root:root:777")

    assert result.returncode == 2
    assert sentinel.read_text(encoding="utf-8") == "preserve"
    assert not log.exists()
