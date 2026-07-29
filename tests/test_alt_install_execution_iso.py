from __future__ import annotations

from pathlib import Path
import re
import subprocess


REPO_ROOT = Path(__file__).resolve().parents[1]
ISO_ROOT = REPO_ROOT / "deploy" / "alt-linux" / "iso" / "agent-v2"
BUILDER = ISO_ROOT / "build-managed-iso.sh"
VERIFIER = ISO_ROOT / "verify-managed-iso.sh"
GRUB_PATCH = ISO_ROOT / "boot-menu" / "grub.cfg.patch"
ISOLINUX_PATCH = ISO_ROOT / "boot-menu" / "isolinux.cfg.patch"
GATE = (
    ISO_ROOT
    / "initrd-overlay"
    / "lib"
    / "initrd"
    / "post"
    / "network-up"
    / "99-alt-install-execution-v2"
)
V1_ISO_ROOT = REPO_ROOT / "deploy" / "alt-linux" / "iso" / "agent-v1"
RELEASE_BUILDER = (
    REPO_ROOT
    / "deploy"
    / "alt-linux"
    / "release"
    / "build-managed-iso-release.sh"
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
    raise AssertionError("bash is required for the managed ISO contract tests")


def _original_file_from_patch(patch: Path) -> str:
    """Reconstruct the original hunk ranges so patch(1) exercises the diff."""
    lines = patch.read_text(encoding="utf-8").splitlines()
    original: dict[int, str] = {1: "set default=harddisk"}
    original_line = 0
    in_hunk = False
    for line in lines:
        match = re.match(r"^@@ -([0-9]+)(?:,[0-9]+)? \+", line)
        if match:
            original_line = int(match.group(1))
            in_hunk = True
            continue
        if not in_hunk or line.startswith("\\"):
            continue
        if line.startswith((" ", "-")):
            value = line[1:]
            previous = original.get(original_line)
            if previous is not None and previous != value:
                raise AssertionError(
                    f"overlapping patch hunks disagree at line {original_line}"
                )
            original[original_line] = value
            original_line += 1
        elif not line.startswith("+"):
            in_hunk = False
    maximum = max(original)
    return "\n".join(
        original.get(number, f"# untouched upstream line {number}")
        for number in range(1, maximum + 1)
    ) + "\n"


def _apply_menu_patches(
    fixture: Path, grub_patch: Path, isolinux_patch: Path
) -> Path:
    grub = fixture / "boot" / "grub" / "grub.cfg"
    isolinux = fixture / "syslinux" / "isolinux.cfg"
    grub.parent.mkdir(parents=True)
    isolinux.parent.mkdir(parents=True)
    grub.write_text(_original_file_from_patch(grub_patch), encoding="utf-8")
    isolinux.write_text(
        _original_file_from_patch(isolinux_patch), encoding="utf-8"
    )
    for patch in (grub_patch, isolinux_patch):
        completed = subprocess.run(
            [
                str(_bash()),
                "-lc",
                f"patch --fuzz=0 -d '{fixture.as_posix()}' -p1 "
                f"< '{patch.as_posix()}'",
            ],
            cwd=REPO_ROOT,
            check=False,
            capture_output=True,
            text=True,
        )
        assert completed.returncode == 0, completed.stderr
    return fixture


def build_v2_fixture(tmp_path: Path) -> Path:
    assert BUILDER.is_file()
    assert VERIFIER.is_file()
    assert GRUB_PATCH.is_file()
    assert ISOLINUX_PATCH.is_file()
    return _apply_menu_patches(
        tmp_path / "iso", GRUB_PATCH, ISOLINUX_PATCH
    )


def extract(fixture: Path, iso_path: str) -> str:
    return (fixture / iso_path.lstrip("/")).read_text(encoding="utf-8")


def _builder_inputs(tmp_path: Path) -> dict[str, Path]:
    source = tmp_path / "alt-kworkstation-11.4-install-x86_64.iso"
    helper = tmp_path / "alt-install-helper"
    public_key = tmp_path / "controller-public-key.json"
    ca_certificate = tmp_path / "execution-ca.pem"
    source.write_bytes(b"pinned-source-fixture")
    helper.write_bytes(b"static-helper-fixture")
    public_key.write_text("{}", encoding="utf-8")
    ca_certificate.write_text(
        "-----BEGIN CERTIFICATE-----\nMAA=\n"
        "-----END CERTIFICATE-----\n",
        encoding="ascii",
    )
    return {
        "source": source,
        "helper": helper,
        "public_key": public_key,
        "ca_certificate": ca_certificate,
        "output": tmp_path / "managed.iso",
    }


def _run_builder(paths: dict[str, Path], controller_url: str) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        [
            str(_bash()),
            BUILDER.as_posix(),
            "--source",
            paths["source"].as_posix(),
            "--output",
            paths["output"].as_posix(),
            "--helper",
            paths["helper"].as_posix(),
            "--public-key",
            paths["public_key"].as_posix(),
            "--ca-certificate",
            paths["ca_certificate"].as_posix(),
            "--build-id",
            "release-20260729T120000Z-deadbee",
            "--controller-url",
            controller_url,
        ],
        cwd=REPO_ROOT,
        check=False,
        capture_output=True,
        text=True,
    )


def test_v2_iso_has_opt_in_execution_menu_and_loopback_metadata(
    tmp_path: Path,
) -> None:
    grub = extract(build_v2_fixture(tmp_path), "/boot/grub/grub.cfg")
    assert (
        'menuentry "Signed-plan installation [ROOT APPROVAL REQUIRED]"'
        in grub
    )
    assert "ai curl=http://127.0.0.1:18192" in grub
    assert "set default=harddisk" in grub
    assert "curl=http://192.168.100.17" not in grub


def test_v2_menu_is_uefi_only_non_default_and_preserves_v1(
    tmp_path: Path,
) -> None:
    v2_fixture = build_v2_fixture(tmp_path / "v2")
    v1_fixture = _apply_menu_patches(
        tmp_path / "v1",
        V1_ISO_ROOT / "boot-menu" / "grub.cfg.patch",
        V1_ISO_ROOT / "boot-menu" / "isolinux.cfg.patch",
    )
    grub = extract(v2_fixture, "/boot/grub/grub.cfg")
    isolinux = extract(v2_fixture, "/syslinux/isolinux.cfg")
    v1_grub = extract(v1_fixture, "/boot/grub/grub.cfg").replace(
        "__ALT_INSTALL_CONTROLLER_URL__", "http://192.168.100.17:18090"
    )
    entry = 'menuentry "Signed-plan installation [ROOT APPROVAL REQUIRED]"'

    assert grub.count(entry) == 1
    entry_offset = grub.index(entry)
    efi_start = grub.rfind(
        'if [ "$grub_platform" = "efi" ]; then', 0, entry_offset
    )
    efi_end = grub.find("\nfi\n", entry_offset)
    assert 0 <= efi_start < entry_offset < efi_end
    assert "sosnadmin.mode=agent-v2" in grub[entry_offset:efi_end]
    assert "systemd.unit=install2.target" in grub[entry_offset:efi_end]
    assert "ip=dhcp" in grub[entry_offset:efi_end]
    assert "console=ttyS0,115200" in grub[entry_offset:efi_end]
    assert "savedefault" not in grub[entry_offset:efi_end]
    assert "Normal ALT installation" in grub
    assert 'menuentry "Signed-plan preflight [DRY RUN]"' in grub
    assert (
        "sosnadmin.mode=agent-v1 "
        "sosnadmin.controller=http://192.168.100.17:18090"
    ) in grub
    assert "Normal ALT installation" in v1_grub
    assert 'menuentry "Signed-plan preflight [DRY RUN]"' in v1_grub
    assert isolinux == extract(
        v1_fixture, "/syslinux/isolinux.cfg"
    )
    assert "default harddisk" in isolinux


def test_v2_builder_rejects_every_controller_except_fixed_tls_endpoint(
    tmp_path: Path,
) -> None:
    paths = _builder_inputs(tmp_path)
    completed = _run_builder(paths, "http://192.168.100.17:18092")

    assert completed.returncode == 1
    assert "Controller URL is invalid" in completed.stderr
    assert not paths["output"].exists()
    assert not Path(
        f"{paths['output']}.build-manifest.json"
    ).exists()


def test_v2_builder_never_replaces_an_existing_output(
    tmp_path: Path,
) -> None:
    paths = _builder_inputs(tmp_path)
    paths["output"].write_bytes(b"immutable-release")

    completed = _run_builder(paths, "https://192.168.100.17:18092")

    assert completed.returncode == 1
    assert "Output already exists" in completed.stderr
    assert paths["output"].read_bytes() == b"immutable-release"


def test_v2_builder_never_allows_source_as_output(tmp_path: Path) -> None:
    paths = _builder_inputs(tmp_path)
    original = paths["source"].read_bytes()
    paths["output"] = paths["source"]

    completed = _run_builder(paths, "https://192.168.100.17:18092")

    assert completed.returncode == 1
    assert "Source and output paths must differ" in completed.stderr
    assert paths["source"].read_bytes() == original


def test_v2_gate_runs_only_for_the_explicit_v2_mode(tmp_path: Path) -> None:
    assert GATE.is_file()
    cmdline = tmp_path / "cmdline"
    agent = tmp_path / "agent"
    log = tmp_path / "agent.log"
    agent.write_text(
        "#!/bin/bash\nprintf 'started\\n' > \"$ALT_INSTALL_TEST_LOG\"\n",
        encoding="utf-8",
        newline="\n",
    )
    agent.chmod(0o755)
    environment = {
        "ALT_INSTALL_CMDLINE_FILE": cmdline.as_posix(),
        "ALT_INSTALL_EXECUTION_AGENT": agent.as_posix(),
        "ALT_INSTALL_TEST_LOG": log.as_posix(),
    }
    cmdline.write_text("quiet sosnadmin.mode=agent-v1\n", encoding="utf-8")
    first = subprocess.run(
        [str(_bash()), GATE.as_posix()],
        cwd=REPO_ROOT,
        env=environment,
        check=False,
        capture_output=True,
        text=True,
    )
    assert first.returncode == 0, first.stderr
    assert not log.exists()

    cmdline.write_text(
        "quiet sosnadmin.mode=agent-v2 "
        "sosnadmin.controller=https://192.168.100.17:18092\n",
        encoding="utf-8",
    )
    second = subprocess.run(
        [str(_bash()), GATE.as_posix()],
        cwd=REPO_ROOT,
        env=environment,
        check=False,
        capture_output=True,
        text=True,
    )
    assert second.returncode == 0, second.stderr
    assert log.read_text(encoding="utf-8") == "started\n"


def test_v2_iso_contract_embeds_only_public_identity_material() -> None:
    builder = BUILDER.read_text(encoding="utf-8")
    verifier = VERIFIER.read_text(encoding="utf-8")
    expected_assets = (
        "execution-ca.pem",
        "public-key.json",
        "source_iso.json",
        "execution-controller-url",
        "managed_iso_size_bytes",
        "payload.sha256",
        "alt-install-helper",
        "alt-install-agent-v2/alt-install-execution-agent",
        "usr/libexec/alt-install-agent",
    )
    for asset in expected_assets:
        assert asset in builder
        assert asset in verifier
    for script in (builder, verifier):
        assert "PRIVATE KEY" in script
        assert "password" in script.lower()
        assert "credential" in script.lower()
        assert "secret" in script.lower()
    assert "alt-install-agent-managed-iso-v2" in builder
    assert "alt-install-agent-managed-iso-v2" in verifier
    assert "Managed ISO size fixed point did not converge" in builder
    assert "sha256sum -c" in verifier
    assert "stat -c '%a'" in verifier


def test_release_builder_adds_v2_only_by_explicit_opt_in() -> None:
    release = RELEASE_BUILDER.read_text(encoding="utf-8")

    assert "agent_version=agent-v1" in release
    assert "--agent-version" in release
    assert "--execution-ca" in release
    assert "alt-kworkstation-11.4-agent-v1-$release_id.iso" in release
    assert "alt-kworkstation-11.4-agent-v2-$release_id.iso" in release
    assert "https://192.168.100.17:18092" in release
    assert "http://192.168.100.17:18090" in release
