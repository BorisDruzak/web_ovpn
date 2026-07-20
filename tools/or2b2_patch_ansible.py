from pathlib import Path

path = Path("deploy/alt-linux/control/alt_deploy/ansible.py")
text = path.read_text(encoding="utf-8")

old = '''        if missing:
            raise ControlError(
                code="provision_not_configured",
                message=(
                    "ALT workstation provisioning "
                    "is not fully configured"
                ),
                exit_code=7,
                details={"missing": missing},
            )
'''
new = '''        helper = self.settings.job_stage_helper_path
        not_executable = []
        if helper.is_file() and not os.access(helper, os.X_OK):
            not_executable.append(
                {
                    "name": "job_stage_helper",
                    "path": str(helper),
                }
            )

        details: dict[str, object] = {}
        if missing:
            details["missing"] = missing
        if not_executable:
            details["not_executable"] = not_executable

        if details:
            raise ControlError(
                code="provision_not_configured",
                message=(
                    "ALT workstation provisioning "
                    "is not fully configured"
                ),
                exit_code=7,
                details=details,
            )
'''

if text.count(old) != 1:
    raise SystemExit("expected provision configuration block exactly once")
path.write_text(text.replace(old, new, 1), encoding="utf-8")
