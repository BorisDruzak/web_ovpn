# Synthetic policy/application tests. No LDAP or infrastructure connection.
$ErrorActionPreference='Stop'
. (Join-Path $PSScriptRoot '../../deploy/alt-linux/provision-directory-observer.ps1') -FunctionsOnly
$sid='S-1-5-21-101-202-303-1001'
$domainUsers='S-1-5-21-101-202-303-513'
$marker='Managed workstation directory observer v1'
$checks=0
function Must-Reject([scriptblock]$Action, [string]$Code) {
    try { & $Action; throw 'test_expected_rejection' } catch { if ($_.Exception.Message -ne $Code) { throw } }
    $script:checks++
}
Assert-ObserverIdentity $sid $sid @($domainUsers) 513 $marker; $checks++
Must-Reject { Assert-ObserverIdentity $sid 'S-1-5-21-101-202-303-1002' @($domainUsers) 513 $marker } 'observer_identity_collision'
Must-Reject { Assert-ObserverIdentity $sid '' @($domainUsers) 513 $marker } 'observer_identity_collision'
Must-Reject { Assert-ObserverIdentity $sid $sid @($domainUsers) 513 'unmanaged' } 'observer_identity_collision'
Must-Reject { Assert-ObserverIdentity $sid $sid @($domainUsers,'S-1-5-21-101-202-303-512') 513 $marker } 'observer_membership_unsafe'
Must-Reject { Assert-ObserverIdentity $sid $sid @($domainUsers) 512 $marker } 'observer_membership_unsafe'
$readonly=[pscustomobject]@{Properties=@{sdrightseffective=@(0)}}
Assert-ObserverEffectiveRows @($readonly); $checks++
Must-Reject { Assert-ObserverEffectiveRows @([pscustomobject]@{Properties=@{}}) } 'observer_effective_rights_unknown'
foreach ($property in @('allowedattributeseffective','allowedchildclasseseffective')) {
    $facts=@{sdrightseffective=@(0)}; $facts[$property]=@('synthetic-write')
    Must-Reject { Assert-ObserverEffectiveRows @([pscustomobject]@{Properties=$facts}) } 'observer_effective_write_detected'
}
Must-Reject { Assert-ObserverEffectiveRows @([pscustomobject]@{Properties=@{sdrightseffective=@(4)}}) } 'observer_effective_write_detected'
$identity=[Security.Principal.SecurityIdentifier]::new($sid)
$write=[DirectoryServices.ActiveDirectoryRights]::WriteProperty -bor [DirectoryServices.ActiveDirectoryRights]::ExtendedRight
$acl=[DirectoryServices.ActiveDirectorySecurity]::new()
$deny=[DirectoryServices.ActiveDirectoryAccessRule]::new($identity,$write,[Security.AccessControl.AccessControlType]::Deny,[DirectoryServices.ActiveDirectorySecurityInheritance]::All)
[void]$acl.AddAccessRule($deny)
$row=[pscustomobject]@{Properties=@{ntsecuritydescriptor=@(,$acl.GetSecurityDescriptorBinaryForm())}}
if (-not (Test-ObserverDenyProof $row $identity @($domainUsers) $write)) { throw 'test_deny_not_recognized' }; $checks++
$other=[Security.Principal.SecurityIdentifier]::new('S-1-5-21-101-202-303-1002')
if (Test-ObserverDenyProof $row $other @($domainUsers) $write) { throw 'test_other_sid_accepted' }; $checks++
$inherited=[DirectoryServices.ActiveDirectorySecurity]::new()
$inherited.SetSecurityDescriptorSddlForm("D:AI(A;;GA;;;AU)(D;CIID;WPCR;;;$sid)")
$inheritedRow=[pscustomobject]@{Properties=@{ntsecuritydescriptor=@(,$inherited.GetSecurityDescriptorBinaryForm())}}
if (Test-ObserverDenyProof $inheritedRow $identity @($domainUsers) $write) { throw 'test_explicit_allow_override_ignored' }; $checks++
$tokens=$null; $errors=$null
$ast=[Management.Automation.Language.Parser]::ParseFile((Join-Path $PSScriptRoot '../../deploy/alt-linux/provision-directory-observer.ps1'),[ref]$tokens,[ref]$errors)
if ($errors.Count) { throw 'test_powershell_parse_failed' }; $checks++
$native=$ast.Find({param($node) $node -is [Management.Automation.Language.StringConstantExpressionAst] -and $node.Value.Contains('public static class ObserverLsaPolicy')},$true)
if (-not $native) { throw 'test_native_reader_missing' }
Add-Type -TypeDefinition $native.Value; $checks++
# Exercise ACL addition against an in-memory entry and receipt recorder.
$script:trace=[Collections.Generic.List[string]]::new()
$script:Admin=$null
$script:OwnedAclChanges=[Collections.Generic.List[object]]::new()
$script:ObserverSid=$sid; $script:AccountDn='CN=observer,DC=example,DC=invalid'; $script:ConfigSha='synthetic'; $script:Scopes=@('OU=Workstations,DC=example,DC=invalid')
$entryAcl=[DirectoryServices.ActiveDirectorySecurity]::new()
[void]$entryAcl.AddAccessRule([DirectoryServices.ActiveDirectoryAccessRule]::new($other,[DirectoryServices.ActiveDirectoryRights]::ReadProperty,[Security.AccessControl.AccessControlType]::Allow))
$script:fake=[pscustomobject]@{Options=[pscustomobject]@{SecurityMasks=0};ObjectSecurity=$entryAcl}
$script:fake | Add-Member ScriptMethod CommitChanges { $script:trace.Add('commit') }
$script:fake | Add-Member ScriptMethod Dispose {}
function New-ObserverEntry { return $script:fake }
function Write-ObserverReceipt { param($Value) if (-not $Value.owned_acl_changes.Count) {throw 'test_missing_owned_ace'}; $script:trace.Add('receipt') }
Add-ObserverRule 'OU=Workstations,DC=example,DC=invalid' $identity $write ([Security.AccessControl.AccessControlType]::Deny)
if (($script:trace -join ',') -ne 'receipt,commit') { throw 'test_receipt_not_before_write' }; $checks++
Add-ObserverRule 'OU=Workstations,DC=example,DC=invalid' $identity $write ([Security.AccessControl.AccessControlType]::Deny)
if ($script:trace.Count -ne 2) { throw 'test_ace_not_idempotent' }; $checks++
$otherRules=@($script:fake.ObjectSecurity.GetAccessRules($true,$true,[Security.Principal.SecurityIdentifier]) | Where-Object {$_.IdentityReference.Value -eq $other.Value})
if ($otherRules.Count -ne 1 -or $otherRules[0].ActiveDirectoryRights -ne [DirectoryServices.ActiveDirectoryRights]::ReadProperty) { throw 'test_unrelated_ace_changed' }; $checks++
@{status='passed';checks=$checks;infrastructure_calls=0} | ConvertTo-Json -Compress
