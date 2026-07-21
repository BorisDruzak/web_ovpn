from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]


def test_installer_never_uses_or_prints_temporary_credentials() -> None:
    text = (ROOT / "deploy" / "install-openvpn-web.sh").read_text(encoding="utf-8")

    assert "/tmp/openvpn-web-admin-password.txt" not in text
    assert "/tmp/openvpn-web-api-token.txt" not in text
    assert "cat /tmp/openvpn-web-admin-password.txt" not in text
    assert "ADMIN_PASSWORD=%s" not in text
    assert "OPENVPN_WEB_API_TOKEN=%s" not in text
    assert 'TMP_ENV="$(mktemp)"' not in text
    assert 'mktemp -p /etc/openvpn-web' in text
    assert 'sudo_cmd cat "$ENV_PATH" > "$TMP_ENV"' not in text
    assert "sudo_cmd sh -c 'cat \"$1\" > \"$2\"' sh \"$ENV_PATH\" \"$TMP_ENV\"" in text
