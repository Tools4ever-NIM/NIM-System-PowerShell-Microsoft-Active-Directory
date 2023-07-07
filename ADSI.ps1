#
# ADSI.ps1 - Active Directory Services Interface PowerShell Script.
#
# ADSI implementation of PowerShell Active Directory Module functionality.
#


#
# Helper functions
#

$TerminalServicesAttributes = @(
    # int32
    'AllowLogon', 'BrokenConnectionAction', 'ConnectClientDrivesAtLogon', 'ConnectClientPrintersAtLogon', 'DefaultToMainPrinter',
    'EnableRemoteControl', 'MaxConnectionTime', 'MaxDisconnectionTime', 'MaxIdleTime', 'ReconnectionAction',

    # string
    'TerminalServicesHomeDirectory', 'TerminalServicesHomeDrive', 'TerminalServicesInitialProgram', 'TerminalServicesProfilePath',
    'TerminalServicesWorkDirectory'
)

$PropertyNamesMap = @{
    CannotChangePassword = 'nTSecurityDescriptor'
    ChangePasswordAtLogon = 'pwdLastSet'
    Enabled = 'userAccountControl'
    GroupCategory = 'groupType'
    GroupScope = 'groupType'
    PasswordExpirationDate = 'adsPath'
    PasswordNeverExpires = 'userAccountControl'
    PasswordNotRequired = 'userAccountControl'
    Path = 'distinguishedName'
}

foreach ($e in $Global:TerminalServicesAttributes) { $Global:PropertyNamesMap.Add($e, 'adsPath') }


function ConvertFrom-ADLargeInteger {
    param (
        [Parameter(Mandatory)] [object] $li
    )

    $high_part = $li.GetType().InvokeMember('HighPart', [System.Reflection.BindingFlags]::GetProperty, $null, $li, $null)
    $low_part  = $li.GetType().InvokeMember('LowPart',  [System.Reflection.BindingFlags]::GetProperty, $null, $li, $null)

    $bytes = [System.BitConverter]::GetBytes($high_part)
    $tmp   = [System.Byte[]]@(0,0,0,0,0,0,0,0)
    [System.Array]::Copy($bytes, 0, $tmp, 4, 4)
    $high_part = [System.BitConverter]::ToInt64($tmp, 0)

    $bytes = [System.BitConverter]::GetBytes($low_part)
    $low_part = [System.BitConverter]::ToUInt32($bytes, 0)
 
    return $low_part + $high_part
}


function ConvertTo-ADLargeInteger {
    param (
        [Parameter(Mandatory)] [Int64] $Number
    )

    $byte_array = [System.BitConverter]::GetBytes($Number)
    $high_part  = [System.BitConverter]::ToInt32($byte_array, 4)
    $low_part   = [System.BitConverter]::ToInt32($byte_array, 0)

    $li = New-Object -ComObject LargeInteger

    [void]$li.GetType().InvokeMember('HighPart', [System.Reflection.BindingFlags]::SetProperty, $null, $li, $high_part)
    [void]$li.GetType().InvokeMember('LowPart',  [System.Reflection.BindingFlags]::SetProperty, $null, $li, $low_part)

    return $li
}


if ($true) {
    # AD groupType bit definitions
    # -> https://docs.microsoft.com/en-us/windows/win32/adschema/a-grouptype

    New-Variable ADS_GROUP_SYSTEM_CREATED -ErrorAction Ignore -Option Constant -Value 0x00000001
    New-Variable ADS_GROUP_GLOBAL         -ErrorAction Ignore -Option Constant -Value 0x00000002
    New-Variable ADS_GROUP_DOMAINLOCAL    -ErrorAction Ignore -Option Constant -Value 0x00000004
    New-Variable ADS_GROUP_UNIVERSAL      -ErrorAction Ignore -Option Constant -Value 0x00000008
    New-Variable ADS_GROUP_APP_BASIC      -ErrorAction Ignore -Option Constant -Value 0x00000010
    New-Variable ADS_GROUP_APP_QUERY      -ErrorAction Ignore -Option Constant -Value 0x00000020
    New-Variable ADS_GROUP_SECURITY       -ErrorAction Ignore -Option Constant -Value 0x80000000


    # AD userAccountControl bit definitions
    # -> https://docs.microsoft.com/en-us/windows/win32/adschema/a-useraccountcontrol

    New-Variable ADS_UF_SCRIPT                                 -ErrorAction Ignore -Option Constant -Value 0x00000001
    New-Variable ADS_UF_ACCOUNTDISABLE                         -ErrorAction Ignore -Option Constant -Value 0x00000002
    New-Variable ADS_UF_HOMEDIR_REQUIRED                       -ErrorAction Ignore -Option Constant -Value 0x00000008
    New-Variable ADS_UF_LOCKOUT                                -ErrorAction Ignore -Option Constant -Value 0x00000010
    New-Variable ADS_UF_PASSWD_NOTREQD                         -ErrorAction Ignore -Option Constant -Value 0x00000020
    New-Variable ADS_UF_PASSWD_CANT_CHANGE                     -ErrorAction Ignore -Option Constant -Value 0x00000040
    New-Variable ADS_UF_ENCRYPTED_TEXT_PASSWORD_ALLOWED        -ErrorAction Ignore -Option Constant -Value 0x00000080
    New-Variable ADS_UF_TEMP_DUPLICATE_ACCOUNT                 -ErrorAction Ignore -Option Constant -Value 0x00000100
    New-Variable ADS_UF_NORMAL_ACCOUNT                         -ErrorAction Ignore -Option Constant -Value 0x00000200
    New-Variable ADS_UF_INTERDOMAIN_TRUST_ACCOUNT              -ErrorAction Ignore -Option Constant -Value 0x00000800
    New-Variable ADS_UF_WORKSTATION_TRUST_ACCOUNT              -ErrorAction Ignore -Option Constant -Value 0x00001000
    New-Variable ADS_UF_SERVER_TRUST_ACCOUNT                   -ErrorAction Ignore -Option Constant -Value 0x00002000
    New-Variable ADS_UF_NOT_USED_1                             -ErrorAction Ignore -Option Constant -Value 0x00004000
    New-Variable ADS_UF_NOT_USED_2                             -ErrorAction Ignore -Option Constant -Value 0x00008000
    New-Variable ADS_UF_DONT_EXPIRE_PASSWD                     -ErrorAction Ignore -Option Constant -Value 0x00010000
    New-Variable ADS_UF_MNS_LOGON_ACCOUNT                      -ErrorAction Ignore -Option Constant -Value 0x00020000	
    New-Variable ADS_UF_SMARTCARD_REQUIRED                     -ErrorAction Ignore -Option Constant -Value 0x00040000	
    New-Variable ADS_UF_TRUSTED_FOR_DELEGATION                 -ErrorAction Ignore -Option Constant -Value 0x00080000	
    New-Variable ADS_UF_NOT_DELEGATED                          -ErrorAction Ignore -Option Constant -Value 0x00100000	
    New-Variable ADS_UF_USE_DES_KEY_ONLY                       -ErrorAction Ignore -Option Constant -Value 0x00200000	
    New-Variable ADS_UF_DONT_REQUIRE_PREAUTH                   -ErrorAction Ignore -Option Constant -Value 0x00400000	
    New-Variable ADS_UF_PASSWORD_EXPIRED                       -ErrorAction Ignore -Option Constant -Value 0x00800000	
    New-Variable ADS_UF_TRUSTED_TO_AUTHENTICATE_FOR_DELEGATION -ErrorAction Ignore -Option Constant -Value 0x01000000	
}


function ConvertTo-GroupType {
	param(
        [int32] $OldValue = 0,
    	[Parameter(Mandatory)] [AllowEmptyString()] [string] $GroupCategory,
    	[Parameter(Mandatory)] [AllowEmptyString()] [string] $GroupScope
	)

    $c = switch ($GroupCategory) {
             ''             { if ($OldValue -eq 0) { $ADS_GROUP_SECURITY } else { $OldValue -band $ADS_GROUP_SECURITY }; break }
             'Security'     { $ADS_GROUP_SECURITY;    break }
             'Distribution' { 0;                      break }
             default        { throw 'GroupCategory out of range' }
         }

    $s = switch ($GroupScope) {
             ''             { if ($OldValue -eq 0) { $ADS_GROUP_GLOBAL } else { $OldValue -band ($ADS_GROUP_GLOBAL -bor $ADS_GROUP_DOMAINLOCAL -bor $ADS_GROUP_UNIVERSAL -bor $ADS_GROUP_APP_BASIC -bor $ADS_GROUP_APP_QUERY) }; break }
             'Global'       { $ADS_GROUP_GLOBAL;      break }
             'DomainLocal'  { $ADS_GROUP_DOMAINLOCAL; break }
             'Universal'    { $ADS_GROUP_UNIVERSAL;   break }
             'APP_BASIC'    { $ADS_GROUP_APP_BASIC;   break }
             'APP_QUERY'    { $ADS_GROUP_APP_QUERY;   break }
             default        { throw 'GroupScope out of range' }
         }

    return $c -bor $s
}


function Get-DirectoryServicesDirectoryEntry {
    param (
        [PSCredential] $Credential,
        [String] $Path
    )

    if ($Credential) {
        New-Object System.DirectoryServices.DirectoryEntry $Path, ($Credential.GetNetworkCredential().UserName), ($Credential.GetNetworkCredential().Password)
    }
    else {
        New-Object System.DirectoryServices.DirectoryEntry $Path
    }
}


function Get-CannotChangePassword {
    # https://docs.microsoft.com/en-us/windows/win32/adsi/reading-user-cannot-change-password-ldap-provider
	param(
    	[byte[]] $nTSecurityDescriptor
	)

    $change_password_guid = [guid]'{AB721A53-1E2F-11D0-9819-00AA0040529B}'

    $sid_everyone = [System.Security.Principal.SecurityIdentifier]'S-1-1-0'
    $sid_nt_authority_self = [System.Security.Principal.SecurityIdentifier]'S-1-5-10'

    $has_deny_everyone = $false
    $has_deny_self = $false

    $acl = (New-Object System.Security.AccessControl.RawSecurityDescriptor($nTSecurityDescriptor, 0)).DiscretionaryAcl

    foreach ($ace in $acl) {
        if ($ace.ObjectAceType -eq $change_password_guid) {
            if (!$has_deny_everyone -and $ace.SecurityIdentifier.Value -eq $sid_everyone) {
                if ($ace.AceType -eq 'AccessAllowedObject') { return $false }
                if ($ace.AceType -eq 'AccessDeniedObject') {
                    if ($has_deny_self) { return $true }
                    $has_deny_everyone = $true
                }
            }
            elseif (!$has_deny_self -and $ace.SecurityIdentifier.Value -eq $sid_nt_authority_self) {
                if ($ace.AceType -eq 'AccessAllowedObject') { return $false }
                if ($ace.AceType -eq 'AccessDeniedObject') {
                    if ($has_deny_everyone) { return $true }
                    $has_deny_self = $true
                }
            }
        }
    }

    return $false
}


function Set-CannotChangePassword {
    # https://docs.microsoft.com/en-us/dotnet/api/system.directoryservices.activedirectorysecurity?view=net-5.0
	param(
    	[System.DirectoryServices.ActiveDirectorySecurity] $ADSecurity,
        [bool] $State
	)

    $change_password_guid = [guid]'{AB721A53-1E2F-11D0-9819-00AA0040529B}'

    $sid_everyone = [System.Security.Principal.SecurityIdentifier]'S-1-1-0'
    $sid_nt_authority_self = [System.Security.Principal.SecurityIdentifier]'S-1-5-10'
    $accessMask = [System.DirectoryServices.ActiveDirectoryRights]::ExtendedRight

    $del_access_control_type = if ($State) { 'Allow' } else { 'Deny'  }
    $add_access_control_type = if ($State) { 'Deny'  } else { 'Allow' }

    $ADSecurity.RemoveAccessRule( (New-Object System.DirectoryServices.ActiveDirectoryAccessRule($sid_everyone,          $accessMask, $del_access_control_type, $change_password_guid))) >$null
    $ADSecurity.RemoveAccessRule( (New-Object System.DirectoryServices.ActiveDirectoryAccessRule($sid_nt_authority_self, $accessMask, $del_access_control_type, $change_password_guid))) >$null

    $ADSecurity.AddAccessRule(    (New-Object System.DirectoryServices.ActiveDirectoryAccessRule($sid_everyone,          $accessMask, $add_access_control_type, $change_password_guid))) >$null

    if ($add_access_control_type -ne 'Allow') {
        # This is how Active Directory Users and Computer works...
        $ADSecurity.AddAccessRule((New-Object System.DirectoryServices.ActiveDirectoryAccessRule($sid_nt_authority_self, $accessMask, $add_access_control_type, $change_password_guid))) >$null
    }
}


function Convert-ADPropertyCollection {
	param(
        [PSCredential] $Credential,
        [System.DirectoryServices.DirectoryEntry] $DirectoryEntry,
        [ValidateNotNull()] [String] $IdentityType,
    	[Parameter(Mandatory)] [ValidateNotNullorEmpty()] [string[]] $Properties,
    	[string[]] $SkipProperties,
    	[Parameter(ValueFromPipeline)] [AllowEmptyCollection()] $PropertyCollection
	)

    begin {
        $time_properties = @('accountexpires','badpasswordtime','lastlogoff','lastlogon','pwdlastset','usnchanged','usncreated')
        $group_scope_mask = ($ADS_GROUP_GLOBAL -bor $ADS_GROUP_DOMAINLOCAL -bor $ADS_GROUP_UNIVERSAL -bor $ADS_GROUP_APP_BASIC -bor $ADS_GROUP_APP_QUERY)
    }

	process {
        #
        # $PropertyCollection can be:
        #
        # - [System.DirectoryServices.ResultPropertyCollection] when called by Get-ADObject-ADSI(), or
        # - [System.DirectoryServices.PropertyCollection]       when called by PassThru of New-ADObject-ADSI() and Set-ADObject-ADSI()/Set-ADGroupMember-ADSI()
        #

        if (-not $PropertyCollection) { return }

        if ($Properties -eq '*') { $Properties = $PropertyCollection.PropertyNames }

        $object = [ordered]@{}

        foreach ($p in $Properties) {
            if ($p -eq 'AccountPassword' -or ($SkipProperties -and $SkipProperties.Contains($p))) { continue }

            $p_mapped = if ($Global:PropertyNamesMap[$p]) { $Global:PropertyNamesMap[$p] } else { $p }
            $value_collection = $PropertyCollection[$p_mapped]

            if ($time_properties.Contains($p.ToLower())) {
                $li = if ($value_collection[0] -is [System.__ComObject]) {
                          ConvertFrom-ADLargeInteger $value_collection[0]
                      }
                      else {
                          $value_collection[0]
                      }

                # https://social.technet.microsoft.com/wiki/contents/articles/31135.active-directory-large-integer-attributes.aspx
                $value = if ($li -eq 0 -or $li -gt [DateTime]::MaxValue.Ticks) {
                            ''    # '(never)' in Active Directory Users and Computers
                         }
                         else {
                            [DateTime]::FromFileTimeUtc($li)
                         }
            }
            elseif ($p -eq 'CannotChangePassword') {
                # $value_collection[0] is 'nTSecurityDescriptor'
                #
                # From https://flylib.com/books/en/1.434.1/com_interop_data_types.html :
                # - DirectoryEntry marshals security descriptors as a System.__ComObject data type
                # - DirectorySearcher marshals security descriptors in binary format as a byte array

                $byte_array = if ($value_collection[0] -is [System.__ComObject]) {
                    # $DirectoryEntry.ObjectSecurity accesses 'nTSecurityDescriptor' property
                    $DirectoryEntry.ObjectSecurity.GetSecurityDescriptorBinaryForm()
                }
                else {
                    $value_collection[0]
                }

                $value = Get-CannotChangePassword $byte_array
            }
            elseif ($p -eq 'ChangePasswordAtLogon') {
                # $value_collection[0] is 'pwdLastSet'
                $li = if ($value_collection[0] -is [System.__ComObject]) {
                          ConvertFrom-ADLargeInteger $value_collection[0]
                      }
                      else {
                          $value_collection[0]
                      }

                $value = ($li -eq 0 -or $li -gt [DateTime]::MaxValue.Ticks)
            }
            elseif ($p -eq 'distinguishedName') {
                if (!$IdentityType -or $IdentityType -eq 'distinguishedName') {
                    $value = $value_collection[0]
                }
                else {
                    # We really want the distinguishedName part
                    $value = @($value_collection -replace '^[^;]*;[^;]*;')[0]
                }
            }
            elseif ($p -eq 'Enabled') {
                # $value_collection[0] is 'userAccountControl'
                $value = (($value_collection[0] -band $ADS_UF_ACCOUNTDISABLE) -ne $ADS_UF_ACCOUNTDISABLE)
            }
            elseif ($p -eq 'GroupCategory') {
                # $value_collection[0] is 'groupType'
                $value = if (($value_collection[0] -band $ADS_GROUP_SECURITY) -eq $ADS_GROUP_SECURITY) { 'Security' } else { 'Distribution' }
            }
            elseif ($p -eq 'GroupScope') {
                # $value_collection[0] is 'groupType'
                $value = switch ($value_collection[0] -band $group_scope_mask) {
                            $ADS_GROUP_GLOBAL      { 'Global';      break }
                            $ADS_GROUP_DOMAINLOCAL { 'DomainLocal'; break }
                            $ADS_GROUP_UNIVERSAL   { 'Universal';   break }
                            $ADS_GROUP_APP_BASIC   { 'APP_BASIC';   break }
                            $ADS_GROUP_APP_QUERY   { 'APP_QUERY';   break }
                            default                { 'Other';       break }
                         }
            }
            elseif ($p -eq 'member') {
                if ($PropertyCollection -isnot [System.DirectoryServices.PropertyCollection]) {
                    # $PropertyCollection is a [System.DirectoryServices.ResultPropertyCollection]: Use as-is
                    $dirent = $null
                    $searcher = $null
                    $pc = $PropertyCollection
                }
                else {
                    # $PropertyCollection is a [System.DirectoryServices.PropertyCollection]: Get associated [System.DirectoryServices.ResultPropertyCollection]
                    $dirent = Get-DirectoryServicesDirectoryEntry $Credential $DirectoryEntry.path
                    $searcher = New-Object System.DirectoryServices.DirectorySearcher $dirent, '(objectClass=*)', $p, 'Base'

                    if (!$IdentityType -or $IdentityType -eq 'distinguishedName') {
                        $searcher.ExtendedDN = [System.DirectoryServices.ExtendedDN]::None
                    }
                    else {
                        # https://docs.microsoft.com/en-us/openspecs/windows_protocols/ms-adts/57056773-932c-4e55-9491-e13f49ba580c?redirectedfrom=MSDN
                        $searcher.ExtendedDN = [System.DirectoryServices.ExtendedDN]::Standard
                    }

                    $pc = $searcher.FindOne().Properties
                    $value_collection = $pc[$p]
                }

                # https://docs.microsoft.com/en-us/previous-versions/windows/desktop/ldap/searching-using-range-retrieval
                # Range-retrieval: exhaustively read attribute 'member;range=<start>-<end>'

                $value = New-Object System.Collections.ArrayList
                $member_range_property = $null
                $start = 0

                while ($true) {
                    if (!$IdentityType -or $IdentityType -eq 'distinguishedName') {
            	    	foreach ($m in $value_collection) {
                            # Remove empty entries
                            if ($m) { [void]$value.Add($m) }
                        }
                    }
                    else {
            	    	foreach ($m in $value_collection) {
                            # Remove empty entries
                            if ($m) { [void]$value.Add($m.Substring(6, 36)) }    # Extract GUID from <GUID=...>;...
                        }
                    }

                    if ($member_range_property) {
                        if ($member_range_property -match '^member;range=[0-9]*-\*$') {
                            # End-of-range: Exhausted
                            break
                        }

                        if (!$dirent) {
                            $dirent = Get-DirectoryServicesDirectoryEntry $Credential $PropertyCollection['adsPath'][0]
                        }

                        $inc   =  $value_collection.count
                        $start += $inc
                        $end   =  $start + $inc - 1

                        $member_range_property = "member;range=$($start)-$($end)"

                        if ($searcher) {
                            $searcher.Dispose()
                        }

                        $searcher = New-Object System.DirectoryServices.DirectorySearcher $dirent, '(objectClass=*)', $member_range_property, 'Base'

                        if (!$IdentityType -or $IdentityType -eq 'distinguishedName') {
                            $searcher.ExtendedDN = [System.DirectoryServices.ExtendedDN]::None
                        }
                        else {
                            # https://docs.microsoft.com/en-us/openspecs/windows_protocols/ms-adts/57056773-932c-4e55-9491-e13f49ba580c?redirectedfrom=MSDN
                            $searcher.ExtendedDN = [System.DirectoryServices.ExtendedDN]::Standard
                        }

                        $pc = $searcher.FindOne().Properties
                    }

                    $member_range_property = $pc.PropertyNames.Where({$_ -match '^member;range='})

                    if (!$member_range_property) {
                        # Member not present
                        break
                    }

                    $value_collection = $pc[$member_range_property][0]
                }

                if ($searcher) {
                    $searcher.Dispose()
                }
            }
            elseif ($p -eq 'nTSecurityDescriptor') {
                # Convert to SDDL
                $byte_array = if ($value_collection[0] -is [System.__ComObject]) {
                    # $DirectoryEntry.ObjectSecurity accesses 'nTSecurityDescriptor' property
                    $DirectoryEntry.ObjectSecurity.GetSecurityDescriptorBinaryForm()
                }
                else {
                    $value_collection[0]
                }

                $value = (New-Object System.Security.AccessControl.RawSecurityDescriptor($byte_array, 0)).GetSddlForm([System.Security.AccessControl.AccessControlSections]::All)
            }
            elseif ($p -eq 'objectClass') {
                # Get most specific value
                $value = $value_collection[$value_collection.Count - 1]
            }
            elseif ($p -eq 'objectGUID') {
                # Convert to string
                $value = (New-Object System.Guid(, $value_collection[0])).ToString()
            }
            elseif ($p -eq 'objectSID') {
                # Convert to string
                $value = (New-Object System.Security.Principal.SecurityIdentifier($value_collection[0], 0)).Value
            }
            elseif ($p -eq 'PasswordExpirationDate') {
                # $value_collection[0] is 'adsPath'
                $dirent = Get-DirectoryServicesDirectoryEntry $Credential $value_collection[0]

                try {
                    $value = $dirent.InvokeGet($p)
                }
                catch {
                    $value = $null
                }
            }
            elseif ($p -eq 'PasswordNeverExpires') {
                # $value_collection[0] is 'userAccountControl'
                $value = (($value_collection[0] -band $ADS_UF_DONT_EXPIRE_PASSWD) -ne 0)
            }
            elseif ($p -eq 'PasswordNotRequired') {
                # $value_collection[0] is 'userAccountControl'
                $value = (($value_collection[0] -band $ADS_UF_PASSWD_NOTREQD) -ne 0)
            }
            elseif ($p -eq 'Path') {
                # $value_collection[0] is 'distinguishedName'
                $value = $value_collection[0].Substring($value_collection[0].Replace('\\','  ').Replace('\,','  ').IndexOf(',') + 1)
            }
            elseif ($p -eq 'sidHistory') {
                # Convert to string[]
                $value = @()

    	    	foreach ($bin_sid in $value_collection) {
                    $value += (New-Object System.Security.Principal.SecurityIdentifier($bin_sid, 0)).Value
                }
            }
            elseif ($Global:TerminalServicesAttributes.Contains($p)) {
                # $value_collection[0] is 'adsPath'
                $dirent = Get-DirectoryServicesDirectoryEntry $Credential $value_collection[0]

                try {
                    $value = $dirent.InvokeGet($p)
                }
                catch {
                    # No attribute 'userParameters'
                    $value = $null
                }
            }
            elseif ($value_collection.Count -eq 0) {
                $value = $null
            }
            elseif ($value_collection.Count -eq 1) {
                $value = $value_collection[0]
            }
            else {
                $value = $value_collection
            }

            if ($value -is [DateTime]) {
                $value = $value.ToString('s')
            }

            $object[$p] = $value
        }

        New-Object -TypeName PSObject -Property $object
 	}
}


function Escape-CN {
    param (
    	[Parameter(Mandatory)] [string] $CN
    )

    # https://social.technet.microsoft.com/wiki/contents/articles/5312.active-directory-characters-to-escape.aspx
    return $CN -replace '([,\\#+<>;"=])|^( )|( )$', '\$1$2$3'
}


function Get-IdentityType {
    param (
        [string] $Identity
    )

    if ($Identity.Length -eq 36 -and $Identity.Substring(8, 1) -eq '-' -and $Identity.Substring(13, 1) -eq '-' -and $Identity.Substring(18, 1) -eq '-' -and $Identity.Substring(23, 1) -eq '-') {
        'objectGUID'
    }
    elseif ($Identity.Length -gt 4 -and $Identity.Substring(0, 4) -eq 'S-1-') {
        'objectSid'
    }
    elseif ($Identity.Length -gt 3 -and $Identity.Substring(0, 3) -eq 'CN=') {
        'distinguishedName'
    }
    elseif ($Identity.Length -gt 3 -and $Identity.Substring(0, 3) -eq 'OU=') {
        'path'
    }
    else {
        'other'
    }
}


function Make-UniversalIdentity {
    param (
        [string] $Identity
    )

    $identity_type = Get-IdentityType $Identity

    if ($identity_type -eq 'objectGUID') {
        "<GUID=$($Identity)>"
    }
    elseif ($identity_type -eq 'objectSid') {
        "<SID=$($Identity)>"
    }
    else {
        # distinguishedName / path / other
        $Identity
    }
}


function Make-LDAPPath {
    param (
        [string] $Server,
        [string] $Identity
    )

    $path = 'LDAP:/'

    if ($Server) {
        $path += '/' + $Server
    }

    $path + '/' + (Make-UniversalIdentity $Identity).Replace('/','\/')
}


#
# Generic CRUD functions
#

function New-ADObject-ADSI {
    param (
        [Parameter(Mandatory)] [String] $Class,
        [PSCredential] $Credential,
        [Parameter(Mandatory)] [String] $Name,
        [switch] $PassThru,
        [Parameter(Mandatory)] [AllowEmptyString()] [String] $Path,
        [Hashtable] $Properties,
        [String] $Server
    )

    $parent_dirent = Get-DirectoryServicesDirectoryEntry $Credential (Make-LDAPPath $Server $Path)

    # Children.Add does not generate an exception if creds are incorrect, for example
    #$dirent = $parent_dirent.Children.Add("CN=$CN", $Class)
    $dirent = $parent_dirent.Create($Class, "$(if ($Class -eq 'organizationalUnit') { 'OU' } else { 'CN' })=$(Escape-CN $Name)")

    foreach ($p in $Properties.Keys) {
        switch ($p) {
            'AccountExpires' {
                $li = ([DateTime]$Properties[$p]).ToFileTimeUtc()

                if ($dirent.Properties[$p]) { $dirent.Properties[$p].Clear() }
                $dirent.Properties[$p].Add((ConvertTo-ADLargeInteger $li)) >$null
                break
            }

            'AccountPassword' {
                # Do this after object is created
                break
            }

            'CannotChangePassword' {
                # Do this after object is created
                break
            }

            'ChangePasswordAtLogon' {
                # Do this after object is created
                break
            }

            'Enabled' {
                # Do this after object is created
                break
            }

            'GroupCategory' {
                # Combine with 'GroupScope' to 'groupType'
                break
            }

            'GroupScope' {
                # Combine with 'GroupCategory' to 'groupType'
                break
            }

            'PasswordNeverExpires' {
                # Do this after object is created
                break
            }

            'PasswordNotRequired' {
                # Do this after object is created
                break
            }

            { $p -in $Global:TerminalServicesAttributes } {
                $dirent.InvokeSet($_, $Properties[$p])
                break
            }

            'countryCode' {
                if ($dirent.Properties[$p]) { $dirent.Properties[$p].Clear() }
                if ($Properties[$p] -ne $null -and $Properties[$p] -ne '') {
                    $dirent.Properties[$p].Value = $Properties[$p]
                }
                break
            }

            default {
                if ($dirent.Properties[$p]) { $dirent.Properties[$p].Clear() }
                if ($Properties[$p] -ne $null -and $Properties[$p] -ne '') {
                    if ($Properties[$p] -is [array]) {
                        foreach ($e in $Properties[$p]) {
                            $dirent.Properties[$p].Add($e) >$null
                        }
                    }
                    else {
                        $dirent.Properties[$p].Add($Properties[$p]) >$null
                    }
                }
            }
        }
    }

    if ($class -eq 'user' -and -not $dirent.Properties.Contains('userAccountControl')) {
        $dirent.Properties['userAccountControl'].Add($ADS_UF_NORMAL_ACCOUNT -bor $ADS_UF_ACCOUNTDISABLE) >$null
    }

    if ($class -ne 'container' -and $class -ne 'organizationalUnit' -and -not $dirent.Properties['sAMAccountName']) {
        # Assure this property is set
        $dirent.Properties['sAMAccountName'].Add($Name) >$null
    }

    if ($Properties -and ($Properties.ContainsKey('GroupCategory') -or $Properties.ContainsKey('GroupScope'))) {
        # Overrule 'groupType' property
        if ($dirent.Properties['groupType']) { $dirent.Properties['groupType'].Clear() }

        $dirent.Properties['groupType'].Add((ConvertTo-GroupType -OldValue 0 -GroupCategory $Properties['GroupCategory'] -GroupScope $Properties['GroupScope'])) >$null
    }

    $dirent.CommitChanges()

    $additional_commit = $false

    if ($Properties) {
        # userAccountControl
        $new_uac_value = $dirent.Properties['userAccountControl'][0]

        if ($Properties.ContainsKey('Enabled')) {
            $new_uac_value = if ($Properties['Enabled']) {
                                 $new_uac_value -band (-bnot $ADS_UF_ACCOUNTDISABLE)
                             }
                             else {
                                 $new_uac_value -bor $ADS_UF_ACCOUNTDISABLE
                             }
        }

        if ($Properties.ContainsKey('PasswordNeverExpires')) {
            $new_uac_value = if ($Properties['PasswordNeverExpires']) {
                                 $new_uac_value -bor $ADS_UF_DONT_EXPIRE_PASSWD
                             }
                             else {
                                 $new_uac_value -band (-bnot $ADS_UF_DONT_EXPIRE_PASSWD)
                             }
        }

        if ($Properties.ContainsKey('PasswordNotRequired')) {
            $new_uac_value = if ($Properties['PasswordNotRequired']) {
                                 $new_uac_value -bor $ADS_UF_PASSWD_NOTREQD
                             }
                             else {
                                 $new_uac_value -band (-bnot $ADS_UF_PASSWD_NOTREQD)
                             }
        }

        if ($new_uac_value -ne $dirent.Properties['userAccountControl'][0]) {
            $dirent.Properties['userAccountControl'][0] = $new_uac_value
            $additional_commit = $true
        }

        # AccountPassword
        if ($Properties.ContainsKey('AccountPassword')) {
            $dirent.Invoke('SetPassword', $Properties['AccountPassword']) >$null
            $additional_commit = $true
        }

        # CannotChangePassword
        if ($Properties.ContainsKey('CannotChangePassword')) {
            # $dirent.ObjectSecurity accesses 'nTSecurityDescriptor' property
            Set-CannotChangePassword $dirent.ObjectSecurity $Properties['CannotChangePassword']
            $additional_commit = $true
        }

        # ChangePasswordAtLogon
        if ($Properties.ContainsKey('ChangePasswordAtLogon')) {
            $val = if ($Properties['ChangePasswordAtLogon']) { 0 } else { -1 }

            if ($dirent.Properties['pwdLastSet']) { $dirent.Properties['pwdLastSet'].Clear() }
            $dirent.Properties['pwdLastSet'].Add((ConvertTo-ADLargeInteger $val)) >$null

            $additional_commit = $true
        }
    }

    if ($additional_commit) {
        $dirent.CommitChanges()
    }

    if ($PassThru) {
        $additional_properties = @('distinguishedName', 'objectGUID')

        if ($dirent.Properties.Contains('objectSid')) {
            $additional_properties += 'objectSid'
        }

        $dirent.Properties | Convert-ADPropertyCollection -Credential $Credential -DirectoryEntry $dirent -Properties @($Properties.Keys + $additional_properties) | Add-Member -MemberType NoteProperty -Name 'adsPath' -Value $dirent.Path -PassThru
    }
}


function Get-ADRootDSE-ADSI {
    param (
        [PSCredential] $Credential,
        [String] $Server
    )

    Get-DirectoryServicesDirectoryEntry $Credential (Make-LDAPPath $Server 'RootDSE')
}


function Get-ADObjectSingleSearchBase-ADSI {
    param (
        [PSCredential] $Credential,
        [ValidateNotNull()] [String] $IdentityType,
        [Parameter(Mandatory)] [ValidateNotNullOrEmpty()] [String] $LDAPFilter,
        [ValidateNotNullOrEmpty()] [String[]] $Properties,
        [ValidateNotNullOrEmpty()] [Int32] $ResultPageSize = 256,
        [ValidateRange(1, [Int32]::MaxValue)] [Int32] $ResultSetSize,
        [ValidateNotNull()] $SearchBase,
        [System.DirectoryServices.SearchScope] $SearchScope = 'Subtree',
        [String] $Server
    )

    $searcher = New-Object System.DirectoryServices.DirectorySearcher

        #------------------------------------------------------
        # Configure System.DirectoryServices.DirectorySearcher
        #------------------------------------------------------

        # CacheResults: True
            #$searcher.CacheResults = $false

        # ClientTimeout: -00:00:01

        # PropertyNamesOnly: False

        # Filter:
            if ($LDAPFilter -ne '*') {
                $searcher.Filter = $LDAPFilter
            }

        # PageSize: 0
            if ($ResultPageSize -eq 0) { $ResultPageSize = 1 }
            $searcher.PageSize = $ResultPageSize

        # PropertiesToLoad: {}
            if (!$Properties) {
                # Use default property shortlist
                # https://social.technet.microsoft.com/wiki/contents/articles/12103.active-directory-get-adobject-default-and-extended-properties.aspx
                $Properties = @(
                    'distinguishedName'    # DistinguishedName
                    'Name'                 # Name
                    'objectClass'          # ObjectClass
                    'objectGUID'           # ObjectGUID
                )
            }

            if ($Properties -ne '*') {
                $searcher.PropertiesToLoad.Clear()

                foreach ($p in $Properties) {
                    $p_mapped = if ($Global:PropertyNamesMap[$p]) { $Global:PropertyNamesMap[$p] } else { $p }

                    if (-not $searcher.PropertiesToLoad.Contains($p_mapped)) {
                        [void]$searcher.PropertiesToLoad.Add($p_mapped)
                    }
                }
            }

        # ReferralChasing: External
            #$searcher.ReferralChasing = [DirectoryServices.ReferralChasingOption]::None

        # SearchScope: Subtree
            $searcher.SearchScope = $SearchScope

        # ServerPageTimeLimit: -00:00:01

        # ServerTimeLimit: -00:00:01

        # SizeLimit: 0

        # SearchRoot: System.DirectoryServices.DirectoryEntry
            ### {
            #$root = [ADSI]''
            #$searcher = New-Object System.DirectoryServices.DirectorySearcher($root)
            ### }

            ### { Connect to Global Catalog and setup searcher for the entire forest
            #$searcher = New-Object System.DirectoryServices.DirectorySearcher
            #[ADSI] $root_dse = 'LDAP://RootDSE'
            #$dirent = New-Object System.DirectoryServices.DirectoryEntry "GC://$($root_dse.rootDomainNamingContext)"
            #$searcher.SearchRoot = $dirent
            ### }

            ### {
            #$searcher = new-object System.DirectoryServices.DirectorySearcher 
            #$dirent = new-object System.DirectoryServices.DirectoryEntry 'LDAP://YOURDOMAIN/DC=yourdomain,DC=com', 'YOURDOMAIN\Administrator', '!Password!'
            #$dirent.RefreshCache()
            #$searcher.SearchRoot = $dirent

            ### }

            if ($Credential -or $Server -or $SearchBase -ne $null) {
                if ($Server -or $SearchBase -ne $null) {
                    $ldap_path = 'LDAP:/'

                    if ($Server) {
                        $ldap_path += '/' + $Server
                    }

                    if ($SearchBase -ne $null) {
                        if ($SearchBase -eq '') {
                            throw "$($MyInvocation.MyCommand) : An empty SearchBase is only supported while connected to a GlobalCatalog. (not implememnted)"
                        }

                        $ldap_path += '/' + $SearchBase.Replace('/','\/')
                    }
                }
                else {
                    $ldap_path = $searcher.SearchRoot.Path
                }

                $dirent = Get-DirectoryServicesDirectoryEntry $Credential $ldap_path

                #$dirent.RefreshCache()
                $searcher.SearchRoot = $dirent
            }

        # Sort: System.DirectoryServices.SortOption

        # Asynchronous: False

        # Tombstone: False

        # AttributeScopeQuery: 

        # DerefAlias: Never

        # SecurityMasks: None
        $searcher.SecurityMasks = [System.DirectoryServices.SecurityMasks]::Dacl -bor [System.DirectoryServices.SecurityMasks]::Group -bor [System.DirectoryServices.SecurityMasks]::Owner

        # Control the contents of the member attribute (distinguishedName or objectGUID)
        if (!$IdentityType -or $IdentityType -eq 'distinguishedName') {
            $searcher.ExtendedDN = [System.DirectoryServices.ExtendedDN]::None
        }
        else {
            # https://docs.microsoft.com/en-us/openspecs/windows_protocols/ms-adts/57056773-932c-4e55-9491-e13f49ba580c?redirectedfrom=MSDN
            $searcher.ExtendedDN = [System.DirectoryServices.ExtendedDN]::Standard
        }

        # DirectorySynchronization: 

        # VirtualListView: 

        # Site: 

        # Container: 


        #--------------------------------------------------------------------------------
        # Invoke System.DirectoryServices.DirectorySearcher.FindAll() and process result
        #--------------------------------------------------------------------------------

        $result_count = $ResultSetSize

        # https://stackoverflow.com/questions/47539373/dispose-of-searchresultcollection-after-foreach-object
        # "Because the object you're dealing with is an enumerator and not a pre-generated collection, it won't really matter"
        $rows = $searcher.FindAll()

            # Adding logging here causes additional memory consumption and worse performance

            if (!$ResultSetSize) {

                $rows.Properties | Convert-ADPropertyCollection -Credential $Credential -IdentityType $IdentityType -Properties $Properties

            }
            else {

                do {
                    $rows | ForEach-Object {
                        $_.Properties
                        if (--$result_count -eq 0) { break }
                    } | Convert-ADPropertyCollection -Credential $Credential -IdentityType $IdentityType -Properties $Properties
                } while ($false)

            }

        $rows.Dispose()

    $searcher.Dispose()
}


function Get-ADObject-ADSI {
    param (
        [PSCredential] $Credential,
        [ValidateNotNull()] [String] $IdentityType,
        [Parameter(Mandatory)] [ValidateNotNullOrEmpty()] [String] $LDAPFilter,
        [ValidateNotNullOrEmpty()] [String[]] $Properties,
        [ValidateNotNullOrEmpty()] [Int32] $ResultPageSize = 256,
        [ValidateRange(1, [Int32]::MaxValue)] [Int32] $ResultSetSize,
        [ValidateNotNull()] [String[]] $SearchBases,
        [System.DirectoryServices.SearchScope] $SearchScope = 'Subtree',
        [String] $Server
    )

    $args = @{
        # These parameters always have a value
        LDAPFilter = $LDAPFilter
        ResultPageSize = $ResultPageSize
        SearchScope = $SearchScope
    }

    if ($Credential) {
        $args.Credential = $Credential
    }

    if ($IdentityType) {
        $args.IdentityType = $IdentityType
    }

    if ($Properties) {
        $args.Properties = $Properties
    }

    if ($ResultSetSize) {
        $args.ResultSetSize = $ResultSetSize
    }

    if ($Server) {
        $args.Server = $Server
    }

    if ($SearchBases -eq $null) {
        Get-ADObjectSingleSearchBase-ADSI @args
    }
    else {
        foreach ($searchbase in $SearchBases) {
            Get-ADObjectSingleSearchBase-ADSI @args -SearchBase $searchbase
        }
    }
}


function Move-ADObject-ADSI {
    param (
        [PSCredential] $Credential,
        [Parameter(Mandatory)] [String] $DistinguishedName,      # Binding using objectGUID not allowed
        [Parameter(Mandatory)] [String] $TargetPath,
        [String] $Server
    )

    $dirent_src = Get-DirectoryServicesDirectoryEntry $Credential (Make-LDAPPath $Server $DistinguishedName)
    $dirent_trg = Get-DirectoryServicesDirectoryEntry $Credential (Make-LDAPPath $Server $TargetPath)

    if ($dirent_src.Properties.Count -eq 0) {
        $dirent_src.RefreshCache()
    }

    $dirent_src.MoveTo($dirent_trg)
    $dirent_trg.CommitChanges()
}


function Rename-ADObject-ADSI {
    param (
        [PSCredential] $Credential,
        [Parameter(Mandatory)] [String] $DistinguishedName,
        [Parameter(Mandatory)] [String] $NewName,
        [String] $Server
    )

    $dirent = Get-DirectoryServicesDirectoryEntry $Credential (Make-LDAPPath $Server $DistinguishedName)

    if ($dirent.Properties.Count -eq 0) {
        $dirent.RefreshCache()
    }

    $dirent.Rename($NewName)
    $dirent.CommitChanges()
}


function Set-ADObject-ADSI {
    param (
        [PSCredential] $Credential,
        [Parameter(Mandatory)] [String] $Identity,
        [switch] $PassThru,
        [Hashtable] $Properties,
        [String] $Server
    )

    if ($Properties -and ($Properties.ContainsKey('cn') -or $Properties.ContainsKey('Path'))) {
        $identity_type = Get-IdentityType $Identity

        if ($identity_type -eq 'distinguishedName') {
            $distinguished_name = $Identity
        }
        else {
            $dirent = Get-DirectoryServicesDirectoryEntry $Credential (Make-LDAPPath $Server $Identity)

            if ($dirent.Properties.Count -eq 0) {
                $dirent.RefreshCache()
            }

            $distinguished_name = $dirent.Properties['distinguishedName']
        }

        if ($Properties.ContainsKey('Path')) {
            $path_trg = $Properties['Path']
            $pos_path = $distinguished_name.Replace('\\','  ').Replace('\,','  ').IndexOf(',')
            $path_src = $distinguished_name.Substring($pos_path + 1)

            if ($path_trg -ne $path_src) {
                $args = @{}

                if ($Credential) {
                    $args.Credential = $Credential
                }

                if ($Server) {
                    $args.Server = $Server
                }

                Move-ADObject-ADSI @args -DistinguishedName $distinguished_name -TargetPath $path_trg

                $distinguished_name = $distinguished_name.Substring(0, $pos_path) + ',' + $path_trg

                if ($identity_type -eq 'distinguishedName') {
                    $Identity = $distinguished_name
                }
            }
        }

        if ($Properties.ContainsKey('cn')) {
            $new_name = 'CN=' + $Properties['cn']
            $pos_path = $distinguished_name.Replace('\\','  ').Replace('\,','  ').IndexOf(',')
            $new_dn   = $new_name + $distinguished_name.Substring($pos_path)

            if ($new_dn -ne $distinguished_name) {
                $args = @{}

                if ($Credential) {
                    $args.Credential = $Credential
                }

                if ($Server) {
                    $args.Server = $Server
                }

                Rename-ADObject-ADSI @args -DistinguishedName $distinguished_name -NewName $new_name

                $distinguished_name = $new_dn

                if ($identity_type -eq 'distinguishedName') {
                    $Identity = $distinguished_name
                }
            }
        }
    }

    $dirent = Get-DirectoryServicesDirectoryEntry $Credential (Make-LDAPPath $Server $Identity)

    if ($dirent.Properties.Count -eq 0) {
        $dirent.RefreshCache()
    }

    foreach ($p in $Properties.Keys) {
        switch ($p) {
            'AccountExpires' {
                $li = ([DateTime]$Properties[$p]).ToFileTimeUtc()

                if ($dirent.Properties[$p]) { $dirent.Properties[$p].Clear() }
                $dirent.Properties[$p].Add((ConvertTo-ADLargeInteger $li)) >$null
                break
            }

            'AccountPassword' {
                $dirent.Invoke('SetPassword', $Properties[$p]) >$null
                break
            }

            'CannotChangePassword' {
                # https://flylib.com/books/en/1.434.1/com_interop_data_types.html
                # $dirent.ObjectSecurity accesses 'nTSecurityDescriptor' property
                Set-CannotChangePassword $dirent.ObjectSecurity $Properties[$p]
                break
            }

            'ChangePasswordAtLogon' {
                $val = if ($Properties[$p]) { 0 } else { -1 }

                if ($dirent.Properties['pwdLastSet']) { $dirent.Properties['pwdLastSet'].Clear() }
                $dirent.Properties['pwdLastSet'].Add((ConvertTo-ADLargeInteger $val)) >$null
                break
            }

            'cn' {
                # Already handled above
                break
            }

            'Enabled' {
                # Do this after possible 'userAccountControl' is processed
                break
            }

            'GroupCategory' {
                # Combine with 'GroupScope' to 'groupType'
                break
            }

            'GroupScope' {
                # Combine with 'GroupCategory' to 'groupType'
                break
            }

            'PasswordNeverExpires' {
                # Do this after possible 'userAccountControl' is processed
                break
            }

            'PasswordNotRequired' {
                # Do this after possible 'userAccountControl' is processed
                break
            }

            'Path' {
                # Already handled above
                break
            }

            { $p -in $Global:TerminalServicesAttributes } {
                $dirent.InvokeSet($_, $Properties[$p])
                break
            }

            'countryCode' {
                if ($dirent.Properties[$p]) { $dirent.Properties[$p].Clear() }
                if ($Properties[$p] -ne $null -and $Properties[$p] -ne '') {
                    $dirent.Properties[$p].Value = $Properties[$p]
                }
                break
            }

            default {
                if ($dirent.Properties[$p]) { $dirent.Properties[$p].Clear() }
                if ($Properties[$p] -ne $null -and $Properties[$p] -ne '') {
                    if ($Properties[$p] -is [array]) {
                        foreach ($e in $Properties[$p]) {
                            $dirent.Properties[$p].Add($e) >$null
                        }
                    }
                    else {
                        $dirent.Properties[$p].Add($Properties[$p]) >$null
                    }
                }
            }
        }
    }

    if ($Properties) {
        # userAccountControl
        $new_uac_value = $dirent.Properties['userAccountControl'][0]

        if ($Properties.ContainsKey('Enabled')) {
            $new_uac_value = if ($Properties['Enabled']) {
                                 $new_uac_value -band (-bnot $ADS_UF_ACCOUNTDISABLE)
                             }
                             else {
                                 $new_uac_value -bor $ADS_UF_ACCOUNTDISABLE
                             }
        }

        if ($Properties.ContainsKey('PasswordNeverExpires')) {
            $new_uac_value = if ($Properties['PasswordNeverExpires']) {
                                 $new_uac_value -bor $ADS_UF_DONT_EXPIRE_PASSWD
                             }
                             else {
                                 $new_uac_value -band (-bnot $ADS_UF_DONT_EXPIRE_PASSWD)
                             }
        }

        if ($Properties.ContainsKey('PasswordNotRequired')) {
            $new_uac_value = if ($Properties['PasswordNotRequired']) {
                                 $new_uac_value -bor $ADS_UF_PASSWD_NOTREQD
                             }
                             else {
                                 $new_uac_value -band (-bnot $ADS_UF_PASSWD_NOTREQD)
                             }
        }

        $dirent.Properties['userAccountControl'][0] = $new_uac_value

        # groupType
        if ($Properties.ContainsKey('GroupCategory') -or $Properties.ContainsKey('GroupScope')) {
            $dirent.Properties['groupType'][0] = ConvertTo-GroupType -OldValue $dirent.Properties['groupType'][0] -GroupCategory $Properties['GroupCategory'] -GroupScope $Properties['GroupScope']
        }
    }

    $dirent.CommitChanges()

    if ($PassThru) {
        $additional_properties = @('distinguishedName', 'objectGUID')

        if ($dirent.Properties.Contains('objectSid')) {
            $additional_properties += 'objectSid'
        }

        $dirent.Properties | Convert-ADPropertyCollection -Credential $Credential -DirectoryEntry $dirent -Properties @($Properties.Keys + $additional_properties) | Add-Member -MemberType NoteProperty -Name 'adsPath' -Value $dirent.Path -PassThru
    }
}


function Set-ADGroupMember-ADSI {
    param (
        [PSCredential] $Credential,
        [Parameter(Mandatory)] [String] $Identity,
        [Parameter(Mandatory)] [AllowEmptyCollection()] [String[]] $MembersAdd,
        [Parameter(Mandatory)] [AllowEmptyCollection()] [String[]] $MembersRemove,
        [switch] $PassThru,
        [String] $Server
    )

    $dirent = Get-DirectoryServicesDirectoryEntry $Credential (Make-LDAPPath $Server $Identity)

    if ($dirent.Properties.Count -eq 0) {
        $dirent.RefreshCache()
    }

    $n = 0
    foreach ($m in $MembersAdd) {
        $dirent.Properties['member'].Add((Make-UniversalIdentity $m)) >$null

        $n++
        if ($n -eq 65535) {
            $dirent.CommitChanges()
            $n = 0
        }
    }

    foreach ($m in $MembersRemove) {
        $dirent.Properties['member'].Remove((Make-UniversalIdentity $m)) >$null

        $n++
        if ($n -eq 65535) {
            $dirent.CommitChanges()
            $n = 0
        }
    }

    if ($n -gt 0) {
        $dirent.CommitChanges()
    }

    if ($PassThru) {
        $dirent.Properties | Convert-ADPropertyCollection -Credential $Credential -DirectoryEntry $dirent -IdentityType (Get-IdentityType $Identity) -Properties '*' -SkipProperties 'member' | Add-Member -MemberType NoteProperty -Name 'adsPath' -Value $dirent.Path -PassThru
    }
}


function Remove-ADObject-ADSI {
    param (
        [PSCredential] $Credential,
        [Parameter(Mandatory)] [String] $Identity,
        [switch] $PassThru,
        [String] $Server
    )

    $dirent = Get-DirectoryServicesDirectoryEntry $Credential (Make-LDAPPath $Server $Identity)
    $dirent.DeleteTree()

    if ($PassThru) {
        @{
            (Get-IdentityType $Identity) = $Identity
        }
    }
}


#
# Object-specific CRUD functions
#

function New-ADUser-ADSI {
    param (
        [PSCredential] $Credential,
        [Parameter(Mandatory)] [String] $CN,
        [switch] $PassThru,
        [Parameter(Mandatory)] [AllowEmptyString()] [String] $Path,
        [Hashtable] $Properties,
        [String] $Server
    )

    $args = @{}

    if ($Credential) {
        $args.Credential = $Credential
    }

    if ($PassThru) {
        $args.PassThru = $true
    }

    if ($Properties) {
        $args.Properties = $Properties
    }

    if ($Server) {
        $args.Server = $Server
    }

    New-ADObject-ADSI -Class 'user' -Name $CN -Path $Path @args
}


function Get-ADUser-ADSI {
    param (
        [PSCredential] $Credential,
        [Parameter(Mandatory)] [ValidateNotNullOrEmpty()] [String] $LDAPFilter,
        [ValidateNotNullOrEmpty()] [String[]] $Properties,
        [ValidateNotNullOrEmpty()] [Int32] $ResultPageSize = 256,
        [ValidateRange(1, [Int32]::MaxValue)] [Int32] $ResultSetSize,
        [ValidateNotNull()] $SearchBases,
        [System.DirectoryServices.SearchScope] $SearchScope = 'Subtree',
        [String] $Server
    )

    $args = @{
        # These parameters always have a value
        ResultPageSize = $ResultPageSize
        SearchScope = $SearchScope
    }

    if ($Credential) {
        $args.Credential = $Credential
    }

    $args.LDAPFilter = '(&(objectCategory=person)(objectClass=user))'

    if ($LDAPFilter -ne '*') {
        $args.LDAPFilter = "(&$($args.LDAPFilter)($LDAPFilter))"
    }

    if (!$Properties) {
        # Use default property shortlist
        # https://social.technet.microsoft.com/wiki/contents/articles/12037.active-directory-get-aduser-default-and-extended-properties.aspx
        $Properties = @(
            'distinguishedName'    # DistinguishedName
            'Enabled'              # Enabled
            'givenName'            # GivenName
            'cn'                   # Name
            'objectClass'          # ObjectClass
            'objectGUID'           # ObjectGUID
            'sAMAccountName'       # SamAccountName
            'objectSid'            # SID
            'Path'
            'sn'                   # Surname
            'userPrincipalName'    # UserPrincipalName
        )
    }

    if ($Properties) {
        $args.Properties = $Properties
    }

    if ($ResultSetSize) {
        $args.ResultSetSize = $ResultSetSize
    }

    if ($SearchBases -ne $null) {
        $args.SearchBases = $SearchBases
    }

    if ($Server) {
        $args.Server = $Server
    }

    Get-ADObject-ADSI @args
}


function Set-ADUser-ADSI {
    param (
        [PSCredential] $Credential,
        [Parameter(Mandatory)] [String] $Identity,
        [switch] $PassThru,
        [Hashtable] $Properties,
        [String] $Server
    )

    $args = @{}

    if ($Credential) {
        $args.Credential = $Credential
    }

    if ($PassThru) {
        $args.PassThru = $true
    }

    if ($Properties) {
        $args.Properties = $Properties
    }

    if ($Server) {
        $args.Server = $Server
    }

    Set-ADObject-ADSI -Identity $Identity @args
}


function Remove-ADUser-ADSI {
    param (
        [PSCredential] $Credential,
        [Parameter(Mandatory)] [String] $Identity,
        [switch] $PassThru,
        [String] $Server
    )

    $args = @{}

    if ($Credential) {
        $args.Credential = $Credential
    }

    if ($PassThru) {
        $args.PassThru = $true
    }

    if ($Server) {
        $args.Server = $Server
    }

    Remove-ADObject-ADSI -Identity $Identity @args
}


function New-ADComputer-ADSI {
    param (
        [PSCredential] $Credential,
        [Parameter(Mandatory)] [String] $CN,
        [switch] $PassThru,
        [Parameter(Mandatory)] [AllowEmptyString()] [String] $Path,
        [Hashtable] $Properties,
        [String] $Server
    )

    $args = @{}

    if ($Credential) {
        $args.Credential = $Credential
    }

    if ($PassThru) {
        $args.PassThru = $true
    }

    if ($Properties) {
        $args.Properties = $Properties
    }

    if ($Server) {
        $args.Server = $Server
    }

    New-ADObject-ADSI -Class 'computer' -Name $CN -Path $Path @args
}


function Get-ADComputer-ADSI {
    param (
        [PSCredential] $Credential,
        [Parameter(Mandatory)] [ValidateNotNullOrEmpty()] [String] $LDAPFilter,
        [ValidateNotNullOrEmpty()] [String[]] $Properties,
        [ValidateNotNullOrEmpty()] [Int32] $ResultPageSize = 256,
        [ValidateRange(1, [Int32]::MaxValue)] [Int32] $ResultSetSize,
        [ValidateNotNull()] $SearchBases,
        [System.DirectoryServices.SearchScope] $SearchScope = 'Subtree',
        [String] $Server
    )

    $args = @{
        # These parameters always have a value
        ResultPageSize = $ResultPageSize
        SearchScope = $SearchScope
    }

    if ($Credential) {
        $args.Credential = $Credential
    }

    $args.LDAPFilter = '(objectClass=computer)'

    if ($LDAPFilter -ne '*') {
        $args.LDAPFilter = "(&$($args.LDAPFilter)($LDAPFilter))"
    }

    if (!$Properties) {
        # Use default property shortlist
        # https://social.technet.microsoft.com/wiki/contents/articles/12056.active-directory-get-adcomputer-default-and-extended-properties.aspx
        $Properties = @(
            'distinguishedName'    # DistinguishedName
            'dNSHostName'          # DNSHostName
            'Enabled'              # Enabled
            'cn'                   # Name
            'objectClass'          # ObjectClass
            'objectGUID'           # ObjectGUID
            'sAMAccountName'       # SamAccountName
            'objectSid'            # SID
            'Path'
            'userPrincipalName'    # UserPrincipalName
        )
    }

    if ($Properties) {
        $args.Properties = $Properties
    }

    if ($ResultSetSize) {
        $args.ResultSetSize = $ResultSetSize
    }

    if ($SearchBases -ne $null) {
        $args.SearchBases = $SearchBases
    }

    if ($Server) {
        $args.Server = $Server
    }

    Get-ADObject-ADSI @args
}


function Set-ADComputer-ADSI {
    param (
        [PSCredential] $Credential,
        [Parameter(Mandatory)] [String] $Identity,
        [switch] $PassThru,
        [Hashtable] $Properties,
        [String] $Server
    )

    $args = @{}

    if ($Credential) {
        $args.Credential = $Credential
    }

    if ($PassThru) {
        $args.PassThru = $true
    }

    if ($Properties) {
        $args.Properties = $Properties
    }

    if ($Server) {
        $args.Server = $Server
    }

    Set-ADObject-ADSI -Identity $Identity @args
}


function Remove-ADComputer-ADSI {
    param (
        [PSCredential] $Credential,
        [Parameter(Mandatory)] [String] $Identity,
        [switch] $PassThru,
        [String] $Server
    )

    $args = @{}

    if ($Credential) {
        $args.Credential = $Credential
    }

    if ($PassThru) {
        $args.PassThru = $true
    }

    if ($Server) {
        $args.Server = $Server
    }

    Remove-ADObject-ADSI -Identity $Identity @args
}


function New-ADGroup-ADSI {
    param (
        [PSCredential] $Credential,
        [Parameter(Mandatory)] [String] $CN,
        [switch] $PassThru,
        [Parameter(Mandatory)] [AllowEmptyString()] [String] $Path,
        [Hashtable] $Properties,
        [String] $Server
    )

    $args = @{}

    if ($Credential) {
        $args.Credential = $Credential
    }

    if ($PassThru) {
        $args.PassThru = $true
    }

    if ($Properties) {
        $args.Properties = $Properties
    }

    if ($Server) {
        $args.Server = $Server
    }

    New-ADObject-ADSI -Class 'group' -Name $CN -Path $Path @args
}


function Get-ADGroup-ADSI {
    param (
        [PSCredential] $Credential,
        [ValidateNotNull()] [String] $IdentityType,
        [Parameter(Mandatory)] [ValidateNotNullOrEmpty()] [String] $LDAPFilter,
        [ValidateNotNullOrEmpty()] [String[]] $Properties,
        [ValidateNotNullOrEmpty()] [Int32] $ResultPageSize = 256,
        [ValidateRange(1, [Int32]::MaxValue)] [Int32] $ResultSetSize,
        [ValidateNotNull()] $SearchBases,
        [System.DirectoryServices.SearchScope] $SearchScope = 'Subtree',
        [String] $Server
    )

    $args = @{
        # These parameters always have a value
        ResultPageSize = $ResultPageSize
        SearchScope = $SearchScope
    }

    if ($Credential) {
        $args.Credential = $Credential
    }

    if ($IdentityType) {
        # This controls the contents of the member attribute (distinguishedName or objectGUID)
        $args.IdentityType = $IdentityType
    }

    $args.LDAPFilter = '(objectClass=group)'

    if ($LDAPFilter -ne '*') {
        $args.LDAPFilter = "(&$($args.LDAPFilter)($LDAPFilter))"
    }

    if (!$Properties) {
        # Use default property shortlist
        # https://social.technet.microsoft.com/wiki/contents/articles/12079.active-directory-get-adgroup-default-and-extended-properties.aspx
        $Properties = @(
            'distinguishedName'    # DistinguishedName
            'GroupCategory'        # GroupCategory
            'GroupScope'           # GroupScope
            'cn'                   # Name
            'objectClass'          # ObjectClass
            'objectGUID'           # ObjectGUID
            'Path'
            'sAMAccountName'       # SamAccountName
            'objectSid'            # SID
         )
    }

    if ($Properties) {
        $args.Properties = $Properties
    }

    if ($ResultSetSize) {
        $args.ResultSetSize = $ResultSetSize
    }

    if ($SearchBases -ne $null) {
        $args.SearchBases = $SearchBases
    }

    if ($Server) {
        $args.Server = $Server
    }

    Get-ADObject-ADSI @args
}


function Set-ADGroup-ADSI {
    param (
        [PSCredential] $Credential,
        [Parameter(Mandatory)] [String] $Identity,
        [switch] $PassThru,
        [Hashtable] $Properties,
        [String] $Server
    )

    $args = @{}

    if ($Credential) {
        $args.Credential = $Credential
    }

    if ($PassThru) {
        $args.PassThru = $true
    }

    if ($Properties) {
        $args.Properties = $Properties
    }

    if ($Server) {
        $args.Server = $Server
    }

    Set-ADObject-ADSI -Identity $Identity @args
}


function Remove-ADGroup-ADSI {
    param (
        [PSCredential] $Credential,
        [Parameter(Mandatory)] [String] $Identity,
        [switch] $PassThru,
        [String] $Server
    )

    $args = @{}

    if ($Credential) {
        $args.Credential = $Credential
    }

    if ($PassThru) {
        $args.PassThru = $true
    }

    if ($Server) {
        $args.Server = $Server
    }

    Remove-ADObject-ADSI -Identity $Identity @args
}


function New-ADOrganizationalUnit-ADSI {
    param (
        [PSCredential] $Credential,
        [Parameter(Mandatory)] [String] $OU,
        [switch] $PassThru,
        [Parameter(Mandatory)] [AllowEmptyString()] [String] $Path,
        [Hashtable] $Properties,
        [String] $Server
    )

    $args = @{}

    if ($Credential) {
        $args.Credential = $Credential
    }

    if ($PassThru) {
        $args.PassThru = $true
    }

    if ($Properties) {
        $args.Properties = $Properties
    }

    if ($Server) {
        $args.Server = $Server
    }

    New-ADObject-ADSI -Class 'organizationalUnit' -Name $OU -Path $Path @args
}


function Get-ADOrganizationalUnit-ADSI {
    param (
        [PSCredential] $Credential,
        [switch] $IncludeContainers,
        [Parameter(Mandatory)] [ValidateNotNullOrEmpty()] [String] $LDAPFilter,
        [ValidateNotNullOrEmpty()] [String[]] $Properties,
        [ValidateNotNullOrEmpty()] [Int32] $ResultPageSize = 256,
        [ValidateRange(1, [Int32]::MaxValue)] [Int32] $ResultSetSize,
        [ValidateNotNull()] $SearchBases,
        [System.DirectoryServices.SearchScope] $SearchScope = 'Subtree',
        [String] $Server
    )

    $args = @{
        # These parameters always have a value
        ResultPageSize = $ResultPageSize
        SearchScope = $SearchScope
    }

    if ($Credential) {
        $args.Credential = $Credential
    }

    $args.LDAPFilter = '(objectClass=organizationalUnit)'

    if ($IncludeContainers) {
        $args.LDAPFilter = "(|$($args.LDAPFilter)(objectClass=container))"
    }

    if ($LDAPFilter -ne '*') {
        $args.LDAPFilter = "(&$($args.LDAPFilter)($LDAPFilter))"
    }

    if (!$Properties) {
        # Use default property shortlist
        # https://social.technet.microsoft.com/wiki/contents/articles/12089.active-directory-get-adorganizationalunit-default-and-extended-properties.aspx
        $Properties = @(
            'c'                    # Country
            'distinguishedName'    # DistinguishedName
            'gPLink'               # LinkedGroupPolicyObjects
            'l'                    # City
            'managedBy'            # ManagedBy
            'ou'                   # Name
            'objectClass'          # ObjectClass
            'objectGUID'           # ObjectGUID
            'Path'
            'postalCode'           # PostalCode
            'st'                   # State
            'streetAddress'        # StreetAddress
         )
    }

    if ($Properties) {
        $args.Properties = $Properties
    }

    if ($ResultSetSize) {
        $args.ResultSetSize = $ResultSetSize
    }

    if ($SearchBases -ne $null) {
        $args.SearchBases = $SearchBases
    }

    if ($Server) {
        $args.Server = $Server
    }

    Get-ADObject-ADSI @args
}


function Set-ADOrganizationalUnit-ADSI {
    param (
        [PSCredential] $Credential,
        [Parameter(Mandatory)] [String] $Identity,
        [switch] $PassThru,
        [Hashtable] $Properties,
        [String] $Server
    )

    $args = @{}

    if ($Credential) {
        $args.Credential = $Credential
    }

    if ($PassThru) {
        $args.PassThru = $true
    }

    if ($Properties) {
        $args.Properties = $Properties
    }

    if ($Server) {
        $args.Server = $Server
    }

    Set-ADObject-ADSI -Identity $Identity @args
}


function Remove-ADOrganizationalUnit-ADSI {
    param (
        [PSCredential] $Credential,
        [Parameter(Mandatory)] [String] $Identity,
        [switch] $PassThru,
        [String] $Server
    )

    $args = @{}

    if ($Credential) {
        $args.Credential = $Credential
    }

    if ($PassThru) {
        $args.PassThru = $true
    }

    if ($Server) {
        $args.Server = $Server
    }

    Remove-ADObject-ADSI -Identity $Identity @args
}
