from pathlib import Path
import subprocess
import shutil

import pytest

ROOT = Path(__file__).resolve().parents[2]


def test_provisioning_is_only_an_administrator_bootstrap_with_protected_input():
    text = (ROOT/'deploy/alt-linux/provision-directory-observer.ps1').read_text()
    assert 'ObserverCredentialPath' in text and 'Import-Clixml' in text
    assert 'Assert-ProtectedFile' in text and 'ExpectedSid' in text
    assert 'allowedAttributesEffective' in text and 'allowedChildClassesEffective' in text and 'sDRightsEffective' in text
    assert 'ms-DS-MachineAccountQuota' in text and 'tokenGroups' in text
    assert 'ActiveDirectoryAccessRule' in text and 'AccessControlType]::Deny' in text
    assert 'DeleteChild' in text and 'WriteDacl' in text and 'ExtendedRight' in text
    assert 'Set-ADDomain' not in text and 'RemoveAccessRule' not in text and 'Add-DnsServerResourceRecord' not in text
    assert 'ConvertTo-Json' in text and 'Write-Host' not in text
    sample = (ROOT/'deploy/alt-linux/directory-observer.json.sample').read_text()
    assert 'readonly-vault' in sample and 'join-vault' not in sample


def test_powershell_bootstrap_parses_on_windows():
    executable = shutil.which('pwsh') or shutil.which('powershell.exe')
    if not executable: pytest.skip('PowerShell parser is verified separately on Windows')
    path = str(ROOT/'deploy/alt-linux/provision-directory-observer.ps1').replace("'", "''")
    command = "$tokens=$null; $errors=$null; [System.Management.Automation.Language.Parser]::ParseFile('" + path + "',[ref]$tokens,[ref]$errors) | Out-Null; if($errors.Count){exit 1}"
    assert subprocess.run([executable, '-NoProfile', '-NonInteractive', '-Command', command], capture_output=True).returncode == 0
