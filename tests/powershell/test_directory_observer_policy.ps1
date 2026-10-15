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
Must-Reject { Test-ObserverMachineJoinReview $true @('S-1-5-11') @($sid,'S-1-5-11') $false } 'observer_machine_join_right_present'
$joinReview=Test-ObserverMachineJoinReview $true @('S-1-5-11') @($sid,'S-1-5-11') $true
if (-not $joinReview.exception_accepted -or -not $joinReview.inherited_machine_join -or $joinReview.assignee_sids[0] -ne 'S-1-5-11') { throw 'test_machine_join_exception_missing' }; $checks++
Must-Reject { Test-ObserverMachineJoinReview $true @($sid) @($sid,'S-1-5-11') $true } 'observer_machine_join_right_present'
$joinReview=Test-ObserverMachineJoinReview $true @('S-1-5-32-544') @($sid,'S-1-5-11') $false
if ($joinReview.exception_accepted -or $joinReview.inherited_machine_join) { throw 'test_unrelated_right_attributed' }; $checks++
$joinReview=Test-ObserverMachineJoinReview $false @('S-1-5-11') @($sid,'S-1-5-11') $false
if ($joinReview.exception_accepted -or $joinReview.inherited_machine_join) { throw 'test_zero_quota_exception_invented' }; $checks++
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
# Exercise the real PowerShell ADSI adapter without binding to a server.
# Its adapted LDAP attribute named Options hides the CLR configuration property.
$unbound=[DirectoryServices.DirectoryEntry]::new()
try {
    $options=Get-ObserverEntryOptions $unbound
    if ($options -isnot [DirectoryServices.DirectoryEntryConfiguration]) { throw 'test_adsi_options_shadowed' }
    $checks++
} finally { $unbound.Dispose() }
# Exercise ACL addition against an in-memory entry and receipt recorder.
$script:trace=[Collections.Generic.List[string]]::new()
$script:Admin=$null
$script:OwnedAclChanges=[Collections.Generic.List[object]]::new()
$script:ObserverSid=$sid; $script:AccountDn='CN=observer,DC=example,DC=invalid'; $script:ConfigSha='synthetic'; $script:Scopes=@('OU=Workstations,DC=example,DC=invalid')
$entryAcl=[DirectoryServices.ActiveDirectorySecurity]::new()
[void]$entryAcl.AddAccessRule([DirectoryServices.ActiveDirectoryAccessRule]::new($other,[DirectoryServices.ActiveDirectoryRights]::ReadProperty,[Security.AccessControl.AccessControlType]::Allow))
Add-Type -TypeDefinition @'
public class ObserverEntryDouble {
 public object Options {get;set;}
 public object ObjectSecurity {get;set;}
 public System.Collections.Generic.List<string> Trace {get;set;}
 public void CommitChanges() {Trace.Add("commit");}
 public void Dispose() {}
}
'@
$script:fake=[ObserverEntryDouble]::new()
$script:fake.Options=[pscustomobject]@{SecurityMasks=0}
$script:fake.ObjectSecurity=$entryAcl; $script:fake.Trace=$script:trace
function New-ObserverEntry { return $script:fake }
function Write-ObserverReceipt { param($Value) if (-not $Value.owned_acl_changes.Count) {throw 'test_missing_owned_ace'}; $script:trace.Add('receipt') }
Add-ObserverRule 'OU=Workstations,DC=example,DC=invalid' $identity $write ([Security.AccessControl.AccessControlType]::Deny)
if (($script:trace -join ',') -ne 'receipt,commit') { throw 'test_receipt_not_before_write' }; $checks++
Add-ObserverRule 'OU=Workstations,DC=example,DC=invalid' $identity $write ([Security.AccessControl.AccessControlType]::Deny)
if ($script:trace.Count -ne 2) { throw 'test_ace_not_idempotent' }; $checks++
$otherRules=@($script:fake.ObjectSecurity.GetAccessRules($true,$true,[Security.Principal.SecurityIdentifier]) | Where-Object {$_.IdentityReference.Value -eq $other.Value})
if ($otherRules.Count -ne 1 -or $otherRules[0].ActiveDirectoryRights -ne [DirectoryServices.ActiveDirectoryRights]::ReadProperty) { throw 'test_unrelated_ace_changed' }; $checks++
$script:identityQueries=[Collections.Generic.List[string]]::new()
function Read-ObserverRows {
    param($Base,$Filter,$Attributes,$Credential,[switch]$BaseOnly)
    if (-not $BaseOnly) {
        if ('tokenGroups' -in $Attributes) { throw 'test_tokengroups_requested_in_subtree' }
        $script:identityQueries.Add('resolve')
        return [pscustomobject]@{Properties=@{distinguishedname=@('CN=observer,DC=example,DC=invalid')}}
    }
    if ('tokenGroups' -notin $Attributes) { throw 'test_membership_not_requested_in_base' }
    $script:identityQueries.Add('base')
    return [pscustomobject]@{Properties=@{distinguishedname=@($Base);tokengroups=@($domainUsers)}}
}
foreach($attempt in 1..2) {
    $rows=@(Read-ObserverIdentity 'DC=example,DC=invalid' 'observer' @('distinguishedName','tokenGroups') $null)
    if ($rows.Count -ne 1 -or -not $rows[0].Properties.Contains('tokengroups')) { throw 'test_repeat_identity_missing' }
    $checks++
}
if (($script:identityQueries -join ',') -ne 'resolve,base,resolve,base') { throw 'test_identity_query_scope_wrong' }; $checks++
@{status='passed';checks=$checks;infrastructure_calls=0} | ConvertTo-Json -Compress
