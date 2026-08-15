import os
import stat
import subprocess
from pathlib import Path


ROOT = Path(__file__).resolve().parents[2]
LAUNCHER = ROOT / "deploy" / "alt-linux" / "bootstrap" / "start-bootstrap.sh"


def _write_executable(path: Path, content: str) -> None:
    path.write_text(content, encoding="utf-8")
    path.chmod(path.stat().st_mode | stat.S_IXUSR)


def _run_launcher(
    tmp_path: Path,
    *,
    hostname: str,
    answers: str,
    readback_override: str | None = None,
) -> tuple[subprocess.CompletedProcess[str], str, list[str], Path]:
    fake_bin = tmp_path / "bin"
    fake_bin.mkdir()
    hostname_file = tmp_path / "hostname"
    hostname_file.write_text(f"{hostname}\n", encoding="utf-8")
    hostname_log = tmp_path / "hostname.log"
    capture_file = tmp_path / "bootstrap-capture"
    curl_log = tmp_path / "curl.log"

    _write_executable(
        fake_bin / "hostnamectl",
        """#!/bin/sh
case "$1" in
  --static)
    if [ -n "${HOSTNAME_READBACK_OVERRIDE:-}" ] && [ -s "$HOSTNAME_LOG" ]; then
      printf '%s\\n' "$HOSTNAME_READBACK_OVERRIDE"
    else
      cat "$HOSTNAME_FILE"
    fi
    ;;
  set-hostname)
    printf '%s\\n' "$2" > "$HOSTNAME_FILE"
    printf '%s\\n' "$2" >> "$HOSTNAME_LOG"
    ;;
  *) exit 64 ;;
esac
""",
    )
    _write_executable(
        fake_bin / "curl",
        """#!/bin/sh
output=''
while [ "$#" -gt 0 ]; do
  if [ "$1" = '-o' ]; then
    output="$2"
    shift 2
    continue
  fi
  shift
done
printf 'called\\n' >> "$CURL_LOG"
cat > "$output" <<'BOOTSTRAP'
#!/bin/sh
printf '%s|%s\\n' "$ALT_ASSIGNED_DOMAIN_USER" "$(hostnamectl --static)" > "$CAPTURE_FILE"
BOOTSTRAP
""",
    )
    environment = os.environ | {
        "PATH": f"{fake_bin}{os.pathsep}{os.environ['PATH']}",
        "HOSTNAME_FILE": str(hostname_file),
        "HOSTNAME_LOG": str(hostname_log),
        "CAPTURE_FILE": str(capture_file),
        "CURL_LOG": str(curl_log),
        "HOSTNAME_READBACK_OVERRIDE": readback_override or "",
    }
    result = subprocess.run(
        ["bash", str(LAUNCHER)],
        input=answers,
        text=True,
        capture_output=True,
        cwd=tmp_path,
        env=environment,
        check=False,
    )
    mutations = (
        hostname_log.read_text(encoding="utf-8").splitlines()
        if hostname_log.exists()
        else []
    )
    return (
        result,
        hostname_file.read_text(encoding="utf-8").strip(),
        mutations,
        capture_file,
    )


def test_launcher_falls_back_to_su_when_clean_alt_has_no_sudo() -> None:
    text = LAUNCHER.read_text(encoding="utf-8")

    assert 'command -v sudo >/dev/null 2>&1' in text
    assert 'exec sudo -- bash "$0"' in text
    assert 'command -v su >/dev/null 2>&1' in text
    assert 'exec su -c "exec bash ${quoted_launcher}"' in text
    assert "Run this launcher through sudo as root." not in text


def test_launcher_falls_back_to_su_when_sudo_exists_but_is_not_authorized() -> None:
    text = LAUNCHER.read_text(encoding="utf-8")

    assert "if sudo -v; then" in text
    assert "sudo is unavailable for the current user; falling back to su." in text
    assert text.index("if sudo -v; then") < text.index(
        'exec su -c "exec bash ${quoted_launcher}"'
    )


def test_launcher_collects_a_non_secret_assigned_ad_user_before_bootstrap() -> None:
    text = LAUNCHER.read_text(encoding="utf-8")

    assert 'read -r -p "AD user (login or UPN): "' in text
    assert "ASSIGNED_DOMAIN_USER_RE=" in text
    assert 'ALT_ASSIGNED_DOMAIN_USER="${assigned_domain_user}"' in text
    assert 'exec bash "${bootstrap_path}"' in text
    assert "read -s" not in text
    assert "ALT_ASSIGNED_DOMAIN_PASSWORD" not in text


def test_launcher_replaces_invalid_hostname_only_after_confirmation(
    tmp_path: Path,
) -> None:
    result, hostname, mutations, capture = _run_launcher(
        tmp_path,
        hostname="alt-install-temporary",
        answers="ALT-A1-PC3\ny\nAlt-Test-2\n",
    )

    assert result.returncode == 0, result.stderr
    assert hostname == "alt-a1-pc3"
    assert mutations == ["alt-a1-pc3"]
    assert capture.read_text(encoding="utf-8") == (
        "alt-test-2@sosnadmin.local|alt-a1-pc3\n"
    )


def test_launcher_uses_confirmed_valid_hostname_without_mutation(
    tmp_path: Path,
) -> None:
    result, hostname, mutations, capture = _run_launcher(
        tmp_path,
        hostname="alt-a1-pc3",
        answers="y\nAlt-Test-2\n",
    )

    assert result.returncode == 0, result.stderr
    assert hostname == "alt-a1-pc3"
    assert mutations == []
    assert capture.read_text(encoding="utf-8") == (
        "alt-test-2@sosnadmin.local|alt-a1-pc3\n"
    )


def test_launcher_preserves_a_valid_assigned_ad_user_upn(
    tmp_path: Path,
) -> None:
    result, hostname, mutations, capture = _run_launcher(
        tmp_path,
        hostname="alt-a1-pc3",
        answers="y\nAlt-Test-User@sosnadmin.local\n",
    )

    assert result.returncode == 0, result.stderr
    assert hostname == "alt-a1-pc3"
    assert mutations == []
    assert capture.read_text(encoding="utf-8") == (
        "alt-test-user@sosnadmin.local|alt-a1-pc3\n"
    )


def test_launcher_cancels_before_bootstrap_when_hostname_is_not_confirmed(
    tmp_path: Path,
) -> None:
    result, hostname, mutations, capture = _run_launcher(
        tmp_path,
        hostname="alt-a1-pc3",
        answers="n\n",
    )

    assert result.returncode != 0
    assert hostname == "alt-a1-pc3"
    assert mutations == []
    assert not capture.exists()


def test_launcher_stops_before_bootstrap_when_hostname_readback_mismatches(
    tmp_path: Path,
) -> None:
    result, hostname, mutations, capture = _run_launcher(
        tmp_path,
        hostname="alt-install-temporary",
        answers="alt-a1-pc3\ny\n",
        readback_override="alt-a1-pc4",
    )

    assert result.returncode != 0
    assert "Hostname read-back verification failed." in result.stderr
    assert hostname == "alt-a1-pc3"
    assert mutations == ["alt-a1-pc3"]
    assert not capture.exists()
