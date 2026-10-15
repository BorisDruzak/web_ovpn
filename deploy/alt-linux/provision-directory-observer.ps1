#Requires -Version 5.1
[CmdletBinding()]
param(
    [string]$ConfigPath,
    [string]$AdminCredentialPath,
    [string]$ObserverCredentialPath,
    [string]$ReceiptPath,
    [string]$ExpectedSid,
    [switch]$Check,
    [switch]$FunctionsOnly
)
Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'
Add-Type -AssemblyName System.DirectoryServices

function Assert-ProtectedFile([string]$Path, [switch]$Directory, [int]$MaximumBytes=65536) {
    $item = Get-Item -LiteralPath $Path -Force
    if (($item.Attributes -band [IO.FileAttributes]::ReparsePoint) -or ($item.PSIsContainer -ne [bool]$Directory)) { throw 'observer_input_unsafe' }
    if (-not $Directory -and $item.Length -gt $MaximumBytes) { throw 'observer_input_unsafe' }
    $current = [Security.Principal.WindowsIdentity]::GetCurrent().User.Value
    $allowed = @($current, 'S-1-5-18', 'S-1-5-32-544')
    $acl = Get-Acl -LiteralPath $Path
    if ($acl.GetOwner([Security.Principal.SecurityIdentifier]).Value -notin $allowed) { throw 'observer_input_unsafe' }
    foreach ($rule in $acl.Access) {
        if ($rule.AccessControlType -eq [Security.AccessControl.AccessControlType]::Allow -and
            $rule.IdentityReference.Translate([Security.Principal.SecurityIdentifier]).Value -notin $allowed) { throw 'observer_input_unsafe' }
    }
    $parent = Split-Path -Parent $item.FullName
    if ($parent -and $parent -ne $item.FullName) {
        if ((Get-Item -LiteralPath $parent -Force).Attributes -band [IO.FileAttributes]::ReparsePoint) { throw 'observer_input_unsafe' }
    }
}

function Write-ObserverReceipt([hashtable]$Value) {
    Assert-ProtectedFile (Split-Path -Parent $ReceiptPath) -Directory
    $temporary = Join-Path (Split-Path -Parent $ReceiptPath) ([Guid]::NewGuid().ToString() + '.json')
    try {
        [IO.File]::WriteAllText($temporary, ($Value | ConvertTo-Json -Depth 8), [Text.UTF8Encoding]::new($false))
        Assert-ProtectedFile $temporary -MaximumBytes 16777216
        Move-Item -LiteralPath $temporary -Destination $ReceiptPath -Force
    } finally { if (Test-Path -LiteralPath $temporary) { Remove-Item -LiteralPath $temporary } }
}

function Assert-ObserverIdentity([string]$Sid, [string]$ReceiptSid, [string[]]$Groups, [int]$PrimaryGroup, [string]$Marker) {
    if (-not $ReceiptSid -or $Sid -cne $ReceiptSid -or $Marker -cne 'Managed workstation directory observer v1') { throw 'observer_identity_collision' }
    if ($PrimaryGroup -ne 513) { throw 'observer_membership_unsafe' }
    $domainUsers = $Sid.Substring(0, $Sid.LastIndexOf('-')) + '-513'
    if (@($Groups | Where-Object { $_ -notin @($domainUsers, 'S-1-5-32-545') }).Count) { throw 'observer_membership_unsafe' }
}

function Assert-ObserverEffectiveRows([object[]]$Rows) {
    if (-not $Rows.Count -or $Rows.Count -gt 10000) { throw 'observer_effective_rights_unknown' }
    foreach ($row in $Rows) {
        if (-not $row.Properties.Contains('sdrightseffective') -or $row.Properties['sdrightseffective'].Count -ne 1) { throw 'observer_effective_rights_unknown' }
        $attributes = if ($row.Properties.Contains('allowedattributeseffective')) { $row.Properties['allowedattributeseffective'].Count } else { 0 }
        $children = if ($row.Properties.Contains('allowedchildclasseseffective')) { $row.Properties['allowedchildclasseseffective'].Count } else { 0 }
        if ([int]$row.Properties['sdrightseffective'][0] -ne 0 -or $attributes -or $children) { throw 'observer_effective_write_detected' }
    }
}

function Test-ObserverDenyProof($Row, [Security.Principal.SecurityIdentifier]$Sid, [string[]]$TokenSids, [DirectoryServices.ActiveDirectoryRights]$Rights) {
    $p = $Row.Properties
    if (-not $p.Contains('ntsecuritydescriptor')) { throw 'observer_effective_rights_unknown' }
    $acl = [DirectoryServices.ActiveDirectorySecurity]::new()
    $acl.SetSecurityDescriptorBinaryForm([byte[]]$p['ntsecuritydescriptor'][0])
    if (-not $acl.AreAccessRulesCanonical) { throw 'observer_effective_rights_unknown' }
    $rules = @($acl.GetAccessRules($true, $true, [Security.Principal.SecurityIdentifier]))
    $denies = @($rules | Where-Object {
        $_.IdentityReference.Value -eq $Sid.Value -and $_.AccessControlType -eq [Security.AccessControl.AccessControlType]::Deny -and
        ($_.ActiveDirectoryRights -band $Rights) -eq $Rights -and $_.ObjectType -eq [Guid]::Empty -and
        -not ($_.PropagationFlags -band [Security.AccessControl.PropagationFlags]::InheritOnly)
    })
    if (-not $denies.Count) { return $false }
    if (@($denies | Where-Object { -not $_.IsInherited }).Count) { return $true }
    # Explicit object allows can override inherited denies. Account for everyone,
    # authenticated/network users, transitive groups and SELF on this account.
    $applicable = @($Sid.Value, 'S-1-1-0', 'S-1-5-11', 'S-1-5-2', 'S-1-18-1') + $TokenSids
    if ($p.Contains('objectsid') -and [Security.Principal.SecurityIdentifier]::new([byte[]]$p['objectsid'][0], 0).Value -eq $Sid.Value) { $applicable += 'S-1-5-10' }
    return -not @($rules | Where-Object {
        -not $_.IsInherited -and $_.AccessControlType -eq [Security.AccessControl.AccessControlType]::Allow -and
        $_.IdentityReference.Value -in $applicable -and
        (($_.ActiveDirectoryRights -band $Rights) -or ([long]$_.ActiveDirectoryRights -band 0x50000000))
    }).Count
}

function Test-ObserverProtectedReadProof($Row, [Security.Principal.SecurityIdentifier]$Sid, [string[]]$TokenSids, [DirectoryServices.ActiveDirectoryRights]$Rights) {
    # SDProp replaces protected objects' ACLs. Never change AdminSDHolder or
    # repeatedly stamp managed denies onto those objects. Prove no observer
    # write/ownership grant in the restored DACL instead. MS-ADTS unicodePwd:
    # Everyone's specific Change Password right requires the target's current
    # password; it is not the client's Force Change Password/reset authority.
    try {
        $p = $Row.Properties
        foreach ($name in @('ntsecuritydescriptor','objectsid','admincount','objectclass')) {
            if (-not $p.Contains($name) -or -not $p[$name].Count) { return $false }
        }
        if ($p['admincount'].Count -ne 1 -or [int]$p['admincount'][0] -ne 1 -or
            -not (@($p['objectclass']) -contains 'user' -or @($p['objectclass']) -contains 'group')) { return $false }
        $objectSid = [Security.Principal.SecurityIdentifier]::new([byte[]]$p['objectsid'][0],0)
        if ($objectSid.Value -eq $Sid.Value) { return $false }
        $raw = [Security.AccessControl.RawSecurityDescriptor]::new([byte[]]$p['ntsecuritydescriptor'][0],0)
        if (-not $raw.Owner -or -not $raw.DiscretionaryAcl -or
            -not ($raw.ControlFlags -band [Security.AccessControl.ControlFlags]::DiscretionaryAclPresent)) { return $false }
        $applicable = @($Sid.Value,'S-1-1-0','S-1-5-11','S-1-5-2','S-1-18-1') + $TokenSids
        if ($raw.Owner.Value -in $applicable) { return $false }
        $acl = [DirectoryServices.ActiveDirectorySecurity]::new()
        $acl.SetSecurityDescriptorBinaryForm([byte[]]$p['ntsecuritydescriptor'][0])
        if (-not $acl.AreAccessRulesProtected -or -not $acl.AreAccessRulesCanonical) { return $false }
        foreach ($rule in $acl.GetAccessRules($true,$true,[Security.Principal.SecurityIdentifier])) {
            if ($rule.AccessControlType -ne [Security.AccessControl.AccessControlType]::Allow -or
                $rule.IdentityReference.Value -notin $applicable -or
                -not (($rule.ActiveDirectoryRights -band $Rights) -or ([long]$rule.ActiveDirectoryRights -band 0x50000000))) { continue }
            if ($rule.IdentityReference.Value -ne 'S-1-1-0' -or
                $rule.ActiveDirectoryRights -ne [DirectoryServices.ActiveDirectoryRights]::ExtendedRight -or
                $rule.ObjectType -ne [Guid]'ab721a53-1e2f-11d0-9819-00aa0040529b') { return $false }
        }
        return $true
    } catch { return $false }
}

function Get-ObserverMachineJoinAssignees([string]$Server) {
    # Read-only LSA policy query under the current protected administrator session.
    # No domain policy or privilege assignment is changed.
    if (-not ('ObserverLsaPolicy' -as [type])) {
        Add-Type -TypeDefinition @'
using System;
using System.Runtime.InteropServices;
using System.Security.Principal;
public static class ObserverLsaPolicy {
 [StructLayout(LayoutKind.Sequential)] struct Text { public ushort Length, MaximumLength; public IntPtr Buffer; }
 [StructLayout(LayoutKind.Sequential)] struct Attr { public uint Length; public IntPtr Root, Name; public uint Attributes; public IntPtr Descriptor, Quality; }
 [DllImport("advapi32.dll")] static extern uint LsaOpenPolicy(ref Text system, ref Attr attr, uint access, out IntPtr policy);
 [DllImport("advapi32.dll")] static extern uint LsaEnumerateAccountsWithUserRight(IntPtr policy, ref Text right, out IntPtr buffer, out uint count);
 [DllImport("advapi32.dll")] static extern uint LsaFreeMemory(IntPtr buffer);
 [DllImport("advapi32.dll")] static extern uint LsaClose(IntPtr policy);
 static Text Make(string s) { return new Text { Length=checked((ushort)(s.Length*2)), MaximumLength=checked((ushort)((s.Length+1)*2)), Buffer=Marshal.StringToHGlobalUni(s) }; }
 public static string[] Read(string server) {
  Text system=Make("\\\\"+server), right=Make("SeMachineAccountPrivilege"); IntPtr policy=IntPtr.Zero, buffer=IntPtr.Zero;
  try {
   Attr attr=new Attr { Length=(uint)Marshal.SizeOf(typeof(Attr)) };
   if(LsaOpenPolicy(ref system,ref attr,0x801,out policy)!=0) throw new InvalidOperationException("observer_machine_join_right_unknown");
   uint count; uint status=LsaEnumerateAccountsWithUserRight(policy,ref right,out buffer,out count);
   if(status==0x8000001A) return new string[0];
   if(status!=0 || count>10000) throw new InvalidOperationException("observer_machine_join_right_unknown");
   string[] result=new string[count];
   for(int i=0;i<count;i++) result[i]=new SecurityIdentifier(Marshal.ReadIntPtr(buffer,i*IntPtr.Size)).Value;
   return result;
  } finally { if(buffer!=IntPtr.Zero)LsaFreeMemory(buffer); if(policy!=IntPtr.Zero)LsaClose(policy); Marshal.FreeHGlobal(system.Buffer); Marshal.FreeHGlobal(right.Buffer); }
 }
}
'@
    }
    return [ObserverLsaPolicy]::Read($Server)
}

function New-ObserverEntry([string]$Dn, [Management.Automation.PSCredential]$Credential) {
    $flags = [DirectoryServices.AuthenticationTypes]::Secure -bor [DirectoryServices.AuthenticationTypes]::Signing -bor [DirectoryServices.AuthenticationTypes]::Sealing -bor [DirectoryServices.AuthenticationTypes]::ServerBind
    if ($Credential) {
        # ADSI receives the password only in process memory; no argv, files or output.
        return [DirectoryServices.DirectoryEntry]::new("LDAP://$($script:Config.server)/$Dn", $Credential.UserName, $Credential.GetNetworkCredential().Password, $flags)
    }
    return [DirectoryServices.DirectoryEntry]::new("LDAP://$($script:Config.server)/$Dn", $null, $null, $flags)
}

function Read-ObserverRows([string]$Base, [string]$Filter, [string[]]$Attributes, [Management.Automation.PSCredential]$Credential, [switch]$BaseOnly) {
    $entry = New-ObserverEntry $Base $Credential
    $search = [DirectoryServices.DirectorySearcher]::new($entry)
    try {
        $search.Filter = $Filter
        $search.PageSize = 200
        $search.SizeLimit = 10001
        $search.ServerTimeLimit = [TimeSpan]::FromSeconds(120)
        $search.ClientTimeout = [TimeSpan]::FromSeconds(130)
        $search.ReferralChasing = [DirectoryServices.ReferralChasingOption]::None
        $search.SecurityMasks = [DirectoryServices.SecurityMasks]::Dacl -bor [DirectoryServices.SecurityMasks]::Owner
        $search.SearchScope = if ($BaseOnly) { [DirectoryServices.SearchScope]::Base } else { [DirectoryServices.SearchScope]::Subtree }
        foreach ($name in $Attributes) { [void]$search.PropertiesToLoad.Add($name) }
        $result = $search.FindAll()
        try {
            if ($result.Count -gt 10000) { throw 'observer_collection_limit' }
            # Copy result properties before disposing the unmanaged collection.
            foreach ($row in $result) {
                $properties = @{}
                foreach ($name in $row.Properties.PropertyNames) { $properties[$name] = @($row.Properties[$name]) }
                [pscustomobject]@{ Properties = $properties }
            }
        } finally { $result.Dispose() }
    } finally { $search.Dispose(); $entry.Dispose() }
}

function Get-ObserverEntryOptions($Entry) {
    # ADSI's PowerShell adapter exposes an LDAP attribute named Options;
    # explicitly select the underlying CLR configuration property.
    return $Entry.psbase.Options
}

function Add-ObserverRule([string]$Dn, [Security.Principal.SecurityIdentifier]$Sid, [DirectoryServices.ActiveDirectoryRights]$Rights, [Security.AccessControl.AccessControlType]$Type) {
    $entry = New-ObserverEntry $Dn $script:Admin
    try {
        (Get-ObserverEntryOptions $entry).SecurityMasks = [DirectoryServices.SecurityMasks]::Dacl
        $acl = $entry.ObjectSecurity
        $oldOther = @($acl.GetAccessRules($true, $true, [Security.Principal.SecurityIdentifier]) | Where-Object { $_.IdentityReference.Value -ne $Sid.Value } | ForEach-Object { $_.IdentityReference.Value + ':' + $_.ActiveDirectoryRights + ':' + $_.AccessControlType + ':' + $_.ObjectType + ':' + $_.InheritanceType + ':' + $_.InheritedObjectType + ':' + $_.IsInherited })
        $existing = @($acl.GetAccessRules($true, $false, [Security.Principal.SecurityIdentifier]) | Where-Object {
            $_.IdentityReference.Value -eq $Sid.Value -and $_.AccessControlType -eq $Type -and
            ($_.ActiveDirectoryRights -band $Rights) -eq $Rights -and $_.ObjectType -eq [Guid]::Empty -and
            $_.InheritanceType -eq [DirectoryServices.ActiveDirectorySecurityInheritance]::All
        })
        if (-not $existing.Count) {
            if (-not @($script:OwnedAclChanges | Where-Object { $_.dn -ieq $Dn }).Count) {
                $script:OwnedAclChanges.Add(@{dn=$Dn; before_sddl=$acl.GetSecurityDescriptorSddlForm([Security.AccessControl.AccessControlSections]::Access)})
                Write-ObserverReceipt @{schema_version=1; status='configuring'; sid=$script:ObserverSid; account_dn=$script:AccountDn;
                    config_sha256=$script:ConfigSha; owned_scopes=$script:Scopes; owned_acl_changes=@($script:OwnedAclChanges.ToArray())}
            }
            $rule = [DirectoryServices.ActiveDirectoryAccessRule]::new($Sid, $Rights, $Type, [DirectoryServices.ActiveDirectorySecurityInheritance]::All)
            [void]$acl.AddAccessRule($rule)
            $newOther = @($acl.GetAccessRules($true, $true, [Security.Principal.SecurityIdentifier]) | Where-Object { $_.IdentityReference.Value -ne $Sid.Value } | ForEach-Object { $_.IdentityReference.Value + ':' + $_.ActiveDirectoryRights + ':' + $_.AccessControlType + ':' + $_.ObjectType + ':' + $_.InheritanceType + ':' + $_.InheritedObjectType + ':' + $_.IsInherited })
            if (@(Compare-Object $oldOther $newOther).Count) { throw 'observer_unrelated_acl_change' }
            $entry.ObjectSecurity = $acl; $entry.CommitChanges()
        }
    } finally { $entry.Dispose() }
}

function Read-ObserverIdentity([string]$DomainBase, [string]$AccountName, [string[]]$Attributes, [Management.Automation.PSCredential]$Credential) {
    # tokenGroups is constructed by a BASE search, never a subtree projection.
    $matches = @(Read-ObserverRows $DomainBase "(&(objectClass=user)(sAMAccountName=$AccountName))" @('distinguishedName') $Credential)
    if ($matches.Count -gt 1) { throw 'observer_identity_collision' }
    if (-not $matches.Count) { return }
    if (-not $matches[0].Properties.Contains('distinguishedname')) { throw 'observer_identity_unknown' }
    $dn = [string]$matches[0].Properties['distinguishedname'][0]
    Read-ObserverRows $dn '(objectClass=*)' $Attributes $Credential -BaseOnly
}

function Test-ObserverMachineJoinReview([bool]$QuotaNonzero, [string[]]$Assignees, [string[]]$EffectiveSids, [bool]$AllowInherited) {
    $matches = @($Assignees | Where-Object { $QuotaNonzero -and $_ -in $EffectiveSids } | Select-Object -Unique)
    # The explicit exception covers only the standard Authenticated Users right.
    # Unknown LSA evidence and direct/other-group grants are never exempted.
    if ($matches.Count -and (-not $AllowInherited -or $matches.Count -ne 1 -or $matches[0] -ne 'S-1-5-11')) {
        throw 'observer_machine_join_right_present'
    }
    @{quota_nonzero=$QuotaNonzero; inherited_machine_join=($matches.Count -gt 0);
        exception_accepted=($matches.Count -gt 0 -and $AllowInherited); assignee_sids=$matches}
}

if ($FunctionsOnly) { return }
$managedAccount = $null
try {
    foreach ($path in @($ConfigPath, $ObserverCredentialPath)) { Assert-ProtectedFile $path }
    Assert-ProtectedFile (Split-Path -Parent $ReceiptPath) -Directory
    $script:Admin = $null
    if ($AdminCredentialPath) { Assert-ProtectedFile $AdminCredentialPath; $script:Admin = Import-Clixml -LiteralPath $AdminCredentialPath }
    $observer = Import-Clixml -LiteralPath $ObserverCredentialPath
    if ($observer -isnot [Management.Automation.PSCredential] -or ($script:Admin -and $script:Admin -isnot [Management.Automation.PSCredential])) { throw 'observer_credentials_invalid' }
    $script:Config = Get-Content -LiteralPath $ConfigPath -Raw | ConvertFrom-Json
    $hash = [Security.Cryptography.SHA256]::Create()
    try { $configSha = [BitConverter]::ToString($hash.ComputeHash([Text.Encoding]::UTF8.GetBytes(($script:Config | ConvertTo-Json -Depth 8 -Compress)))).Replace('-', '').ToLowerInvariant() } finally { $hash.Dispose() }
    $required = @('server', 'domain_base', 'account_path', 'account_name', 'upn', 'read_bases', 'dns_bases')
    $names = @($script:Config.PSObject.Properties.Name)
    if (@($names | Where-Object { $_ -notin ($required + @('allow_inherited_machine_join')) }).Count -or @($required | Where-Object { $_ -notin $names }).Count) { throw 'observer_config_invalid' }
    $allowInherited = $false
    if ('allow_inherited_machine_join' -in $names) {
        if ($script:Config.allow_inherited_machine_join -isnot [bool]) { throw 'observer_config_invalid' }
        $allowInherited = $script:Config.allow_inherited_machine_join
    }
    if ($script:Config.server -notmatch '^[a-zA-Z0-9.-]{1,253}$' -or $script:Config.account_name -notmatch '^[a-zA-Z][a-zA-Z0-9_.-]{2,19}$' -or
        $script:Config.domain_base -notmatch '^DC=[a-zA-Z0-9-]+(?:,DC=[a-zA-Z0-9-]+)+$' -or
        $observer.UserName -cne $script:Config.upn -or $script:Config.upn -notmatch '^[a-zA-Z0-9_.-]+@[a-zA-Z0-9.-]+$') { throw 'observer_config_invalid' }
    $scopes = @($script:Config.read_bases) + @($script:Config.dns_bases)
    if (-not $script:Config.read_bases.Count -or -not $script:Config.dns_bases.Count -or $scopes.Count -gt 64) { throw 'observer_config_invalid' }
    foreach ($dn in @($script:Config.account_path) + $scopes) {
        if ($dn -isnot [string] -or $dn.Length -gt 4096 -or $dn -match '[\x00-\x1f/]' -or -not $dn.EndsWith(',' + $script:Config.domain_base, [StringComparison]::OrdinalIgnoreCase)) { throw 'observer_config_invalid' }
    }
    $saved = $null
    if (Test-Path -LiteralPath $ReceiptPath) {
        Assert-ProtectedFile $ReceiptPath -MaximumBytes 16777216; $saved = Get-Content -LiteralPath $ReceiptPath -Raw | ConvertFrom-Json
        if ($saved.config_sha256 -cne $configSha) { throw 'observer_scope_changed' }
    }
    $identityAttributes = @('objectSid', 'distinguishedName', 'description', 'tokenGroups', 'primaryGroupID', 'userAccountControl', 'userPrincipalName', 'sIDHistory')
    $rows = @(Read-ObserverIdentity $script:Config.domain_base $script:Config.account_name $identityAttributes $script:Admin)
    if ($rows.Count -gt 1) { throw 'observer_identity_collision' }
    if (-not $rows.Count) {
        if ($Check -or $saved -or $ExpectedSid) { throw 'observer_identity_missing' }
        $parent = New-ObserverEntry $script:Config.account_path $script:Admin
        try {
            $managedAccount = $parent.Children.Add('CN=' + $script:Config.account_name, 'user')
            $managedAccount.Properties['sAMAccountName'].Value = $script:Config.account_name
            $managedAccount.Properties['userPrincipalName'].Value = $script:Config.upn
            $managedAccount.Properties['description'].Value = 'Managed workstation directory observer v1'
            $managedAccount.Properties['userAccountControl'].Value = 1049090 # NORMAL_ACCOUNT, ACCOUNTDISABLE, NOT_DELEGATED
            $managedAccount.CommitChanges(); $managedAccount.RefreshCache(@('objectSid', 'distinguishedName'))
            $sid = [Security.Principal.SecurityIdentifier]::new([byte[]]$managedAccount.Properties['objectSid'][0], 0)
            $saved = [pscustomobject]@{sid=$sid.Value; account_dn=[string]$managedAccount.Properties['distinguishedName'][0]}
            Write-ObserverReceipt @{schema_version=1; status='created_disabled'; sid=$saved.sid; account_dn=$saved.account_dn; owned_scopes=$scopes; config_sha256=$configSha}
            [void]$managedAccount.Invoke('SetPassword', @($observer.GetNetworkCredential().Password))
        } finally { $parent.Dispose() }
        $rows = @(Read-ObserverIdentity $script:Config.domain_base $script:Config.account_name $identityAttributes $script:Admin)
    }
    if (-not $saved -or $rows.Count -ne 1) { throw 'observer_identity_collision' }
    $p = $rows[0].Properties
    if (-not $p.Contains('tokengroups') -or -not $p['tokengroups'].Count -or $p.Contains('sidhistory')) { throw 'observer_membership_unknown' }
    $sid = [Security.Principal.SecurityIdentifier]::new([byte[]]$p['objectsid'][0], 0)
    if ($ExpectedSid -and $ExpectedSid -cne $sid.Value) { throw 'observer_identity_collision' }
    $groups = @($p['tokengroups'] | ForEach-Object { [Security.Principal.SecurityIdentifier]::new([byte[]]$_, 0).Value })
    Assert-ObserverIdentity $sid.Value $saved.sid $groups ([int]$p['primarygroupid'][0]) ([string]$p['description'][0])
    if ([string]$p['distinguishedname'][0] -cne $saved.account_dn -or [string]$p['userprincipalname'][0] -cne $script:Config.upn) { throw 'observer_identity_collision' }
    $accountDn = $saved.account_dn
    $script:OwnedAclChanges = [Collections.Generic.List[object]]::new()
    if ('owned_acl_changes' -in $saved.PSObject.Properties.Name) { foreach ($change in $saved.owned_acl_changes) { $script:OwnedAclChanges.Add($change) } }
    $script:ObserverSid=$sid.Value; $script:AccountDn=$accountDn; $script:ConfigSha=$configSha; $script:Scopes=$scopes
    if (-not $managedAccount) { $managedAccount = New-ObserverEntry $accountDn $script:Admin }
    $domain = @(Read-ObserverRows $script:Config.domain_base '(objectClass=*)' @('ms-DS-MachineAccountQuota') $script:Admin -BaseOnly)
    if ($domain.Count -ne 1 -or -not $domain[0].Properties.Contains('ms-ds-machineaccountquota')) { throw 'observer_quota_unknown' }
    $quotaNonzero = [int]$domain[0].Properties['ms-ds-machineaccountquota'][0] -gt 0
    $assignees = @()
    if ($quotaNonzero) {
        $assignees = @(Get-ObserverMachineJoinAssignees $script:Config.server)
    }
    $effectiveSids = @($sid.Value, 'S-1-1-0', 'S-1-5-11', 'S-1-5-2', 'S-1-18-1') + $groups
    $joinReview = Test-ObserverMachineJoinReview $quotaNonzero $assignees $effectiveSids $allowInherited
    $write = [DirectoryServices.ActiveDirectoryRights]::CreateChild -bor [DirectoryServices.ActiveDirectoryRights]::DeleteChild -bor
        [DirectoryServices.ActiveDirectoryRights]::Delete -bor [DirectoryServices.ActiveDirectoryRights]::DeleteTree -bor
        [DirectoryServices.ActiveDirectoryRights]::WriteProperty -bor [DirectoryServices.ActiveDirectoryRights]::Self -bor
        [DirectoryServices.ActiveDirectoryRights]::WriteDacl -bor [DirectoryServices.ActiveDirectoryRights]::WriteOwner -bor [DirectoryServices.ActiveDirectoryRights]::ExtendedRight
    $read = [DirectoryServices.ActiveDirectoryRights]::ListChildren -bor [DirectoryServices.ActiveDirectoryRights]::ReadProperty -bor [DirectoryServices.ActiveDirectoryRights]::ReadControl -bor [DirectoryServices.ActiveDirectoryRights]::ListObject
    if (-not $Check) {
        # Only this SID is restricted; domain quota, other principals and ACL inheritance stay unchanged.
        foreach ($dn in @($script:Config.domain_base, $accountDn) + $scopes | Select-Object -Unique) { Add-ObserverRule $dn $sid $write ([Security.AccessControl.AccessControlType]::Deny) }
        foreach ($dn in $scopes | Select-Object -Unique) { Add-ObserverRule $dn $sid $read ([Security.AccessControl.AccessControlType]::Allow) }
        $managedAccount.Properties['userAccountControl'].Value = 1049088
        $managedAccount.CommitChanges()
    }
    $effectiveAttributes = @('allowedAttributesEffective', 'allowedChildClassesEffective', 'sDRightsEffective', 'distinguishedName', 'nTSecurityDescriptor', 'objectSid', 'adminCount', 'objectClass')
    $checked = 0
    foreach ($dn in @($script:Config.domain_base) + $scopes | Select-Object -Unique) {
        $facts = @(Read-ObserverRows $dn '(objectClass=*)' $effectiveAttributes $observer -BaseOnly)
        Assert-ObserverEffectiveRows $facts; $checked += $facts.Count
    }
    foreach ($dn in $scopes | Select-Object -Unique) {
        $facts = @(Read-ObserverRows $dn '(objectClass=*)' $effectiveAttributes $observer)
        foreach ($fact in $facts) {
            if (-not (Test-ObserverDenyProof $fact $sid $groups $write) -and -not (Test-ObserverProtectedReadProof $fact $sid $groups $write)) {
                if ($Check) { throw 'observer_effective_rights_unknown' }
                # Only add this principal's deny on a conflicting object in an
                # approved scope; preserve every unrelated principal's ACEs.
                Add-ObserverRule ([string]$fact.Properties['distinguishedname'][0]) $sid $write ([Security.AccessControl.AccessControlType]::Deny)
            }
        }
        if (-not $Check) { $facts = @(Read-ObserverRows $dn '(objectClass=*)' $effectiveAttributes $observer) }
        foreach ($fact in $facts) { if (-not (Test-ObserverDenyProof $fact $sid $groups $write) -and -not (Test-ObserverProtectedReadProof $fact $sid $groups $write)) { throw 'observer_effective_rights_unknown' } }
        Assert-ObserverEffectiveRows $facts; $checked += $facts.Count
        if ($checked -gt 10000) { throw 'observer_collection_limit' }
    }
    if (-not $Check) { Write-ObserverReceipt @{schema_version=1; status='ready'; sid=$sid.Value; account_dn=$accountDn; owned_scopes=$scopes; config_sha256=$configSha;
        owned_acl_changes=@($script:OwnedAclChanges.ToArray()); checked_objects=$checked; quota_nonzero=$quotaNonzero;
        machine_join_review=$joinReview; checked_at=[DateTime]::UtcNow.ToString('o')} }
    @{status='ready'; identity_verified=$true; effective_readonly=(-not $joinReview.inherited_machine_join); directory_dns_readonly=$true;
        inherited_machine_join_exception=$joinReview.exception_accepted; checked_objects=$checked; quota_reviewed=$true; quota_nonzero=$quotaNonzero} | ConvertTo-Json -Compress
    exit 0
} catch {
    # Never print ADSI, credential, DN or server exception details. Existing SID
    # and owned ACEs remain in the protected receipt for explicit administration.
    if ($managedAccount -and -not $Check) {
        try { $managedAccount.Properties['userAccountControl'].Value = 1049090; $managedAccount.CommitChanges() } catch {}
    }
    $code = if ($_.Exception.Message -cmatch '^observer_[a-z_]+$') { $_.Exception.Message } else { 'observer_bootstrap_not_ready' }
    @{status='error'; code=$code} | ConvertTo-Json -Compress
    exit 1
} finally { if ($managedAccount) { $managedAccount.Dispose() } }
