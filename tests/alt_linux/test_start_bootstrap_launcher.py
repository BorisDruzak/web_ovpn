from pathlib import Path


ROOT = Path(__file__).resolve().parents[2]
LAUNCHER = ROOT / "deploy" / "alt-linux" / "bootstrap" / "start-bootstrap.sh"


def test_launcher_falls_back_to_su_when_clean_alt_has_no_sudo() -> None:
    text = LAUNCHER.read_text(encoding="utf-8")

    assert 'command -v sudo >/dev/null 2>&1' in text
    assert 'exec sudo -- bash "$0"' in text
    assert 'command -v su >/dev/null 2>&1' in text
    assert 'exec su -c "exec bash ${quoted_launcher}"' in text
    assert "Run this launcher through sudo as root." not in text
