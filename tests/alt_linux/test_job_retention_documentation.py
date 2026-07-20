from __future__ import annotations

from pathlib import Path


REPO_ROOT = Path(__file__).resolve().parents[2]


def normalized(relative_path: str) -> str:
    content = (REPO_ROOT / relative_path).read_text(
        encoding="utf-8"
    )
    return " ".join(content.split())


def test_job_retention_operating_contract_is_documented() -> None:
    required_by_file = {
        "deploy/alt-linux/README.md": (
            "workstationctl --json jobs cleanup",
            "workstationctl --json jobs cleanup --apply",
            "90 days",
            "14 days",
            "ansible.log.gz",
            "No automatic cleanup service",
        ),
        "docs/ALT_WORKSTATION_PROVISIONING_CONTEXT.md": (
            "Phase 2.2 job and log retention",
            "job_retention.py",
            "successful and failed jobs are retained for 90 days",
            "logs are archived after 14 days",
            "assignment records are retained independently",
            "No automatic cleanup service",
        ),
        "docs/ALT_WORKSTATION_PROVISIONING_NEXT_STEPS.md": (
            "### 2.2 Job and log retention",
            "Status: implemented",
            "workstationctl --json jobs cleanup",
            "workstationctl --json jobs cleanup --apply",
            "No automatic cleanup service",
        ),
    }

    for relative_path, fragments in required_by_file.items():
        content = normalized(relative_path)
        for fragment in fragments:
            assert fragment in content, (
                f"Missing documented retention contract in "
                f"{relative_path}: {fragment}"
            )
