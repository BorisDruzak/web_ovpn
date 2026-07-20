from pathlib import Path

path = Path("tests/alt_linux/test_provision_preview.py")
text = path.read_text(encoding="utf-8")

vault_write = '''    vault_file.write_text(
        "$ANSIBLE_VAULT;1.1;AES256\\nfixture\\n",
        encoding="utf-8",
    )
'''
vault_write_with_mode = vault_write + "    vault_file.chmod(0o600)\n"

password_write = '''    vault_password_file.write_text(
        "test-vault-password\\n",
        encoding="utf-8",
    )
'''
password_write_with_mode = (
    password_write + "    vault_password_file.chmod(0o600)\n"
)

if text.count(vault_write) != 1:
    raise SystemExit("expected legacy vault write exactly once")
if text.count(password_write) != 1:
    raise SystemExit("expected legacy password write exactly once")

text = text.replace(vault_write, vault_write_with_mode, 1)
text = text.replace(password_write, password_write_with_mode, 1)
path.write_text(text, encoding="utf-8")
