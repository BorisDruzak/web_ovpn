from pathlib import Path


ROOT = Path(__file__).resolve().parents[2]
RUNBOOK = ROOT / "docs" / "runbooks" / "alt-manual-bootstrap-mvp.md"


def test_manual_mvp_runbook_preserves_the_controller_boundary() -> None:
    text = RUNBOOK.read_text(encoding="utf-8")

    assert "curl --noproxy '*' -fsS" in text
    assert "sudo env no_proxy=192.168.100.17" in text
    assert "http://192.168.100.17:8087/bootstrap/bootstrap.sh" in text
    assert "Domain join and software installation are controller-only." in text
    assert "managed ISO" in text
    assert "ai curl=" in text
    for forbidden in ("vault_ad_join_password", "ansible-playbook", "osn-admin password"):
        assert forbidden not in text
