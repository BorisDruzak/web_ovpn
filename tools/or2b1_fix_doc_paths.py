from pathlib import Path

paths = (
    Path(
        "docs/superpowers/specs/"
        "2026-07-20-alt-or2b1-vault-health-gate-design.md"
    ),
    Path(
        "docs/superpowers/plans/"
        "2026-07-20-alt-or2b1-vault-health-gate.md"
    ),
)

old = "tests/alt_linux/test_vault_health.py"
new = "tests/alt_linux/test_vault_check.py"

for path in paths:
    text = path.read_text(encoding="utf-8")
    count = text.count(old)
    if count < 1:
        raise SystemExit(f"expected obsolete path in {path}")
    path.write_text(text.replace(old, new), encoding="utf-8")
