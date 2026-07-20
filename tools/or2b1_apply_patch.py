from pathlib import Path

path = Path("deploy/alt-linux/control/alt_deploy/provision.py")
text = path.read_text(encoding="utf-8")

old_import = "from .registry import MachineRepository\n"
new_import = (
    "from .registry import MachineRepository\n"
    "from .vault import VaultHealthChecker\n"
)

old_block = '''    def _validate_vault(self) -> None:
        missing = [
            str(path)
            for path in (
                self.vault_file,
                self.vault_password_file,
            )
            if not path.is_file()
        ]

        if missing:
            raise ControlError(
                code="vault_not_configured",
                message=(
                    "Ansible Vault is not configured "
                    "for workstation provisioning"
                ),
                exit_code=4,
                details={"missing": missing},
            )

        try:
            with self.vault_file.open(
                "r",
                encoding="utf-8",
            ) as handle:
                vault_header = handle.readline(256).strip()
        except (OSError, UnicodeError) as exc:
            raise ControlError(
                code="vault_not_configured",
                message=(
                    "Ansible Vault file cannot be read"
                ),
                exit_code=4,
                details={
                    "path": str(self.vault_file),
                },
            ) from exc

        if not vault_header.startswith(
            "$ANSIBLE_VAULT;"
        ):
            raise ControlError(
                code="vault_not_configured",
                message=(
                    "Ansible Vault file is not encrypted"
                ),
                exit_code=4,
                details={
                    "path": str(self.vault_file),
                },
            )
'''

new_block = '''    def _validate_vault(self) -> None:
        try:
            VaultHealthChecker(self.settings).check()
        except ControlError as exc:
            if exc.code != "vault_unhealthy":
                raise

            checks = dict(exc.details.get("checks") or {})
            details: dict[str, object] = {"checks": checks}

            missing: list[str] = []
            if not checks.get("vault_file_exists", False):
                missing.append(str(self.vault_file))
            if not checks.get("password_file_exists", False):
                missing.append(str(self.vault_password_file))

            if missing:
                details["missing"] = missing
            elif not checks.get("vault_header", False):
                details["path"] = str(self.vault_file)

            raise ControlError(
                code="vault_not_configured",
                message=(
                    "Ansible Vault is not configured "
                    "for workstation provisioning"
                ),
                exit_code=4,
                details=details,
            ) from exc
'''

if text.count(old_import) != 1:
    raise SystemExit("expected MachineRepository import exactly once")
if text.count(old_block) != 1:
    raise SystemExit("expected shallow _validate_vault block exactly once")

text = text.replace(old_import, new_import, 1)
text = text.replace(old_block, new_block, 1)
path.write_text(text, encoding="utf-8")
