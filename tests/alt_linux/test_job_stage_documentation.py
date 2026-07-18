from __future__ import annotations

from pathlib import Path


REPO_ROOT = Path(__file__).resolve().parents[2]


def normalized(relative_path: str) -> str:
    return " ".join(
        (
            REPO_ROOT / relative_path
        ).read_text(encoding="utf-8").split()
    )


def test_structured_stage_contract_is_documented() -> None:
    required = {
        "deploy/alt-linux/README.md": (
            (
                "created launching validating connecting "
                "identity employee login_screen verifying "
                "recording complete"
            ),
            "stage_history",
            "/usr/local/libexec/alt-job-stage",
            "No automatic migration",
        ),
        "docs/ALT_WORKSTATION_PROVISIONING_CONTEXT.md": (
            "Phase 2.3 structured job stages",
            "failure preserves the last reached stage",
            "stage_history",
            "No automatic migration",
        ),
        "docs/ALT_WORKSTATION_PROVISIONING_NEXT_STEPS.md": (
            "### 2.3 More precise job stages",
            "Status: implemented",
            "recording",
            "complete",
        ),
    }

    for relative_path, fragments in required.items():
        content = normalized(relative_path)
        for fragment in fragments:
            assert fragment in content, (
                "Missing stage documentation in "
                f"{relative_path}: {fragment}"
            )
