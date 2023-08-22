#
# Active Directory.ps1 - IDM System PowerShell Script for Active Directory Services.
#
# Any IDM System PowerShell Script is dot-sourced in a separate PowerShell context, after
# dot-sourcing the IDM Generic PowerShell Script '../Generic.ps1'.
#


. "$PSScriptRoot\..\ADSI.ps1"


$Log_MaskableKeys = @(
    'Password',
    'accountPassword'
)


#
# System functions
#

function Idm-SystemInfo {
    param (
        # Operations
        [switch] $Connection,
        [switch] $TestConnection,
        [switch] $Configuration,
        # Parameters
        [string] $ConnectionParams
    )

    Log info "-Connection=$Connection -TestConnection=$TestConnection -Configuration=$Configuration -ConnectionParams='$ConnectionParams'"
    
    if ($Connection) {
        @(
            @{
                name = 'domain'
                type = 'textbox'
                label = 'Domain'
                tooltip = 'Domain to connect; empty for current domain'
                value = ''
            }
            @{
                name = 'use_svc_account_creds'
                type = 'checkbox'
                label = 'Use credentials of service account'
                value = $true
            }
            @{
                name = 'username'
                type = 'textbox'
                label = 'Username'
                label_indent = $true
                tooltip = 'User account name to access domain services'
                value = ''
                hidden = 'use_svc_account_creds'
            }
            @{
                name = 'password'
                type = 'textbox'
                password = $true
                label = 'Password'
                label_indent = $true
                tooltip = 'User account password to access domain services'
                value = ''
                hidden = 'use_svc_account_creds'
            }
            @{
                name = 'use_specific_server'
                type = 'checkbox'
                label = 'Use specific domain controller'
                value = $false
            }
            @{
                name = 'server'
                type = 'textbox'
                label = 'Name or IP address'
                label_indent = $true
                tooltip = 'Domain services instance to connect'
                value = ''
                hidden = '!use_specific_server'
            }
            @{
                name = 'nr_of_sessions'
                type = 'textbox'
                label = 'Max. number of simultaneous sessions'
                value = 5
            }
            @{
                name = 'sessions_idle_timeout'
                type = 'textbox'
                label = 'Session cleanup idle time (minutes)'
                tooltip = '0 disables session cleanup'
                value = 30
            }
        )
    }

    if ($TestConnection) {
        $connection_params = ConvertSystemParams -Connection $ConnectionParams

        Get-ADObject-ADSI @connection_params -LDAPFilter '*' -ResultSetSize 1 1>$null
    }

    if ($Configuration) {
        $connection_params = ConvertSystemParams -Connection $ConnectionParams

        $organizational_units = @( Get-ADOrganizationalUnit-ADSI @connection_params -Properties @('distinguishedName', 'canonicalName') -LDAPFilter '*' | Sort-Object -Property 'canonicalName' | ForEach-Object { @{ display = $_.canonicalName; value = $_.distinguishedName } } )

        @(
            @{
                name = "multi_searchbases"
                type = 'checkbox'
                label = "Multiple search bases"
                value = $false
            }
            @{
                name = 'searchbase'
                type = 'combo'
                label = 'Search base'
                label_indent = $true
                tooltip = 'Organization Unit to start searching on; empty or * searches all'
                table = @{
                    rows = @( @{ display = '*'; value = '*' } ) + $organizational_units
                    settings_combo = @{
                        display_column = 'display'
                        value_column = 'value'
                    }
                }
                value = '*'
                hidden = 'multi_searchbases'
            }
            @{
                name = 'searchbases'
                type = 'grid'
                label = 'Search bases'
                label_indent = $true
                tooltip = 'Organization Units to start searching on; empty searches all'
                table = @{
                    rows = $organizational_units
                    settings_grid = @{
                        selection = 'multiple'
                        key_column = 'value'
                        checkbox = $true
                        filter = $true
                        columns = @(
                            @{ name = 'display'; display_name = 'Organizational Unit' }
                        )
                    }
                }
                value = @()
                hidden = '!multi_searchbases'
            }
            @{
                name = 'resultpagesize'
                type = 'textbox'
                label = 'Result page size'
                tooltip = 'Number of rows to retrieve per request; 0 for unlimited'
                value = '0'
            }
        )
    }

    Log info "Done"
}


#
# CRUD functions
#

$Properties = @{
    # PowerShell AD Module default properties
    default = @{
        # https://social.technet.microsoft.com/wiki/contents/articles/12037.active-directory-get-aduser-default-and-extended-properties.aspx
        user = @(
            'distinguishedName'
            'Enabled'
            'givenName'
            'cn'
            'objectClass'
            'objectGUID'
            'path'
            'sAMAccountName'
            'objectSid'
            'sn'
            'userPrincipalName'
        )

        # https://social.technet.microsoft.com/wiki/contents/articles/12056.active-directory-get-adcomputer-default-and-extended-properties.aspx
        computer = @(
            'distinguishedName'
            'dNSHostName'
            'Enabled'
            'cn'
            'objectClass'
            'objectGUID'
            'path'
            'sAMAccountName'
            'objectSid'
            'userPrincipalName'
        )

        # https://social.technet.microsoft.com/wiki/contents/articles/12079.active-directory-get-adgroup-default-and-extended-properties.aspx
        group = @(
            'distinguishedName'
            'GroupCategory'
            'GroupScope'
            'cn'
            'objectClass'
            'objectGUID'
            'path'
            'sAMAccountName'
            'objectSid'
        )

        # https://social.technet.microsoft.com/wiki/contents/articles/12089.active-directory-get-adorganizationalunit-default-and-extended-properties.aspx
        organizationalUnit = @(
            'c'
            'distinguishedName'
            'gPLink'
            'l'
            'managedBy'
            'ou'
            'objectClass'
            'objectGUID'
            'path'
            'postalCode'
            'st'
            'streetAddress'
        )
    }

    # Non-native properties, introduced by a.o. PowerShell AD Module
    extra = @{
        user = @(
            'CannotChangePassword'
            'ChangePasswordAtLogon'
            'Enabled'
            'PasswordExpirationDate'
            'PasswordNeverExpires'
            'PasswordNotRequired'
            'path'
        )

        computer = @(
            'CannotChangePassword'
            'ChangePasswordAtLogon'
            'Enabled'
            'PasswordExpirationDate'
            'PasswordNeverExpires'
            'PasswordNotRequired'
            'path'
        )

        group = @(
            'GroupCategory'
            'GroupScope'
            'path'
        )

        organizationalUnit = @(
            'path'
        )
    }

    # Exclude, as current state of connector cannot process these
    exclude = @(
        'msds-memberOfTransitive'
        'msds-memberTransitive'
        'msds-tokenGroupNames'
        'msds-tokenGroupNamesGlobalAndUniversal'
        'msds-tokenGroupNamesNoGCAcceptable'
        'tokenGroups'
        'tokenGroupsGlobalAndUniversal'
        'tokenGroupsNoGCAcceptable'
        'tokenGroupsNoGCAcceptable'
    )

    # IDM-Selection based on practical experiences
    idm = @(
        'accountExpires'
        'c'
        'canonicalName'
        'co'
        'company'
        'department'
        'description'
        'employeeID'
        'employeeNumber'
        'extensionAttribute1'
        'extensionAttribute2'
        'extensionAttribute3'
        'extensionAttribute4'
        'extensionAttribute5'
        'extensionAttribute6'
        'extensionAttribute7'
        'extensionAttribute8'
        'extensionAttribute9'
        'extensionAttribute10'
        'extensionAttribute11'
        'extensionAttribute12'
        'extensionAttribute13'
        'extensionAttribute14'
        'extensionAttribute15'
        'givenName'
        'homeDirectory'
        'homeDrive'
        'homeMDB'
        'homePhone'
        'initials'
        'ipPhone'
        'l'
        'mail'
        'managedBy'
        'manager'
        'mailNickname'
        'mobile'
        'msExchHideFromAddressLists'
        'msExchRecipientTypeDetails'
        'msRTCSIP-UserEnabled'
        'msTSHomeDirectory'
        'msTSHomeDrive'
        'msTSProfilePath'
        'name'
        'objectSid'
        'ou'
        'pager'
        'physicalDeliveryOfficeName'
        'postalCode'
        'postOfficeBox'
        'profilePath'
        'proxyAddresses'
        'roomNumber'
        'scriptPath'
        'sn'
        'st'
        'streetAddress'
        'telephoneNumber'
        'title'
        'userPrincipalName'
        'wWWHomePage'
    )
}


function Idm-UserCreate {
    param (
        # Operations
        [switch] $GetMeta,
        # Parameters
        [string] $SystemParams,
        [string] $FunctionParams
    )

    Log info "-GetMeta=$GetMeta -SystemParams='$SystemParams' -FunctionParams='$FunctionParams'"

    if ($GetMeta) {
        #
        # Get meta data
        #

        @{
            semantics = 'create'
            parameters = @(
                @{ name = 'accountPassword';       allowance = 'optional'   }
                @{ name = 'adsPath';               allowance = 'prohibited' }
                @{ name = 'badPasswordTime';       allowance = 'prohibited' }
                @{ name = 'badPwdCount';           allowance = 'prohibited' }
                @{ name = 'cn';                    allowance = 'mandatory'  }
                @{ name = 'distinguishedName';     allowance = 'prohibited' }
                @{ name = 'dSCorePropagationData'; allowance = 'prohibited' }
                @{ name = 'instanceType';          allowance = 'prohibited' }
                @{ name = 'lastLogoff';            allowance = 'prohibited' }
                @{ name = 'lastLogon';             allowance = 'prohibited' }
                @{ name = 'logonCount';            allowance = 'prohibited' }
                @{ name = 'objectClass';           allowance = 'prohibited' }
                @{ name = 'objectGUID';            allowance = 'prohibited' }
                @{ name = 'objectSid';             allowance = 'prohibited' }
                @{ name = 'path';                  allowance = 'mandatory'  }
                @{ name = 'pwdLastSet';            allowance = 'prohibited' }
                @{ name = 'uSNChanged';            allowance = 'prohibited' }
                @{ name = 'uSNCreated';            allowance = 'prohibited' }
                @{ name = 'whenChanged';           allowance = 'prohibited' }
                @{ name = 'whenCreated';           allowance = 'prohibited' }
               #@{ name = '*';                     allowance = 'optional'   }
            )
        }
    }
    else {
        #
        # Execute function
        #

        $connection_params = ConvertSystemParams -Connection $SystemParams
        $function_params   = ConvertFrom-Json2 $FunctionParams

        $properties = $function_params.Clone()

        # These are passed as mandatory parameters
        $properties.Remove('path')
        $properties.Remove('cn')

        LogIO info "New-ADUser-ADSI" -In @connection_params -Path $function_params.path -CN $function_params.cn -Properties $properties
            $rv = New-ADUser-ADSI @connection_params -PassThru -Path $function_params.path -CN $function_params.cn -Properties $properties
        LogIO info "New-ADUser-ADSI" -Out $rv

        $rv
    }

    Log info "Done"
}


function Idm-UsersRead {
    param (
        # Operations
        [switch] $GetMeta,
        # Parameters
        [string] $SystemParams,
        [string] $FunctionParams
    )

    Log info "-GetMeta=$GetMeta -SystemParams='$SystemParams' -FunctionParams='$FunctionParams'"

    if ($GetMeta) {
        #
        # Get meta data
        #

        Get-ClassMetaData -SystemParams $SystemParams -Class 'user'
    }
    else {
        #
        # Execute function
        #

        $system_params   = ConvertSystemParams $SystemParams
        $function_params = ConvertFrom-Json2 $FunctionParams

        $filter = $function_params.filter

        if ($filter.length -eq 0) {
            # Avoid: Cannot validate argument on parameter 'Filter'. The argument is null or empty.
            # Provide an argument that is not null or empty, and then try the command again.
            $filter = '*'
        }

        $properties = $function_params.properties

        if ($properties.length -eq 0) {
            # Avoid: Cannot validate argument on parameter 'Properties'. The argument is null, empty,
            # or an element of the argument collection contains a null value. Supply a 
            $properties = $Global:Properties.default.user
        }

        # Assure identity key is the first column
        $properties = @('objectGUID') + @($properties | Where-Object { $_ -ne 'objectGUID' })

        LogIO info "Get-ADUser-ADSI" -In @system_params -LDAPFilter $filter -Properties $properties
        Get-ADUser-ADSI @system_params -LDAPFilter $filter -Properties $properties
    }

    Log info "Done"
}


function Idm-UserUpdate {
    param (
        # Operations
        [switch] $GetMeta,
        # Parameters
        [string] $SystemParams,
        [string] $FunctionParams
    )

    Log info "-GetMeta=$GetMeta -SystemParams='$SystemParams' -FunctionParams='$FunctionParams'"

    if ($GetMeta) {
        #
        # Get meta data
        #

        $out = @{
            semantics = 'update'
            parameters = @(
                @{ name = 'accountPassword';       allowance = 'optional'   }
                @{ name = 'adsPath';               allowance = 'prohibited' }
                @{ name = 'badPasswordTime';       allowance = 'prohibited' }
                @{ name = 'badPwdCount';           allowance = 'prohibited' }
                @{ name = 'distinguishedName';     allowance = 'prohibited' }   # Conditionally replaced below
                @{ name = 'dSCorePropagationData'; allowance = 'prohibited' }
                @{ name = 'instanceType';          allowance = 'prohibited' }
                @{ name = 'lastLogoff';            allowance = 'prohibited' }
                @{ name = 'lastLogon';             allowance = 'prohibited' }
                @{ name = 'logonCount';            allowance = 'prohibited' }
                @{ name = 'objectClass';           allowance = 'prohibited' }
                @{ name = 'objectGUID';            allowance = 'prohibited' }   # Conditionally replaced below
                @{ name = 'objectSid';             allowance = 'prohibited' }
                @{ name = 'pwdLastSet';            allowance = 'prohibited' }
                @{ name = 'uSNChanged';            allowance = 'prohibited' }
                @{ name = 'uSNCreated';            allowance = 'prohibited' }
                @{ name = 'whenChanged';           allowance = 'prohibited' }
                @{ name = 'whenCreated';           allowance = 'prohibited' }
               #@{ name = '*';                     allowance = 'optional'   }
            )
        }

        $out.parameters = @(@{ name = 'objectGUID'; allowance = 'mandatory' }) + @($out.parameters | Where-Object { $_.name -ne 'objectGUID' }) | Sort-Object { $_.name }
        $out
    }
    else {
        #
        # Execute function
        #

        $connection_params = ConvertSystemParams -Connection $SystemParams
        $function_params   = ConvertFrom-Json2 $FunctionParams

        $properties = $function_params.Clone()

        # These are passed as mandatory parameters
        $properties.Remove('objectGUID')

        LogIO info "Set-ADUser-ADSI" -In @connection_params -Identity $function_params.objectGUID -Properties $properties
            $rv = Set-ADUser-ADSI @connection_params -PassThru -Identity $function_params.objectGUID -Properties $properties
        LogIO info "Set-ADUser-ADSI" -Out $rv

        $rv
    }

    Log info "Done"
}


function Idm-UserDelete {
    param (
        # Operations
        [switch] $GetMeta,
        # Parameters
        [string] $SystemParams,
        [string] $FunctionParams
    )

    Log info "-GetMeta=$GetMeta -SystemParams='$SystemParams' -FunctionParams='$FunctionParams'"

    if ($GetMeta) {
        #
        # Get meta data
        #

        $out = @{
            semantics = 'delete'
            parameters = @(
                @{ name = '*'; allowance = 'prohibited' }
            )
        }

        $out.parameters = @(@{ name = 'objectGUID'; allowance = 'mandatory' }) + @($out.parameters | Where-Object { $_.name -ne 'objectGUID' }) | Sort-Object { $_.name }
        $out
    }
    else {
        #
        # Execute function
        #

        $connection_params = ConvertSystemParams -Connection $SystemParams
        $function_params   = ConvertFrom-Json2 $FunctionParams

        LogIO info "Remove-ADUser-ADSI" -In @connection_params -Identity $function_params.objectGUID
            $rv = Remove-ADUser-ADSI @connection_params -PassThru -Identity $function_params.objectGUID
        LogIO info "Remove-ADUser-ADSI" -Out $rv

        $rv
    }

    Log info "Done"
}


function Idm-ComputerCreate {
    param (
        # Operations
        [switch] $GetMeta,
        # Parameters
        [string] $SystemParams,
        [string] $FunctionParams
    )

    Log info "-GetMeta=$GetMeta -SystemParams='$SystemParams' -FunctionParams='$FunctionParams'"

    if ($GetMeta) {
        #
        # Get meta data
        #

        @{
            semantics = 'create'
            parameters = @(
                @{ name = 'accountPassword';       allowance = 'optional'   }
                @{ name = 'adsPath';               allowance = 'prohibited' }
                @{ name = 'badPasswordTime';       allowance = 'prohibited' }
                @{ name = 'badPwdCount';           allowance = 'prohibited' }
                @{ name = 'cn';                    allowance = 'mandatory'  }
                @{ name = 'distinguishedName';     allowance = 'prohibited' }
                @{ name = 'dSCorePropagationData'; allowance = 'prohibited' }
                @{ name = 'instanceType';          allowance = 'prohibited' }
                @{ name = 'lastLogoff';            allowance = 'prohibited' }
                @{ name = 'lastLogon';             allowance = 'prohibited' }
                @{ name = 'logonCount';            allowance = 'prohibited' }
                @{ name = 'objectClass';           allowance = 'prohibited' }
                @{ name = 'objectGUID';            allowance = 'prohibited' }
                @{ name = 'objectSid';             allowance = 'prohibited' }
                @{ name = 'path';                  allowance = 'mandatory'  }
                @{ name = 'pwdLastSet';            allowance = 'prohibited' }
                @{ name = 'uSNChanged';            allowance = 'prohibited' }
                @{ name = 'uSNCreated';            allowance = 'prohibited' }
                @{ name = 'whenChanged';           allowance = 'prohibited' }
                @{ name = 'whenCreated';           allowance = 'prohibited' }
               #@{ name = '*';                     allowance = 'optional'   }
            )
        }
    }
    else {
        #
        # Execute function
        #

        $connection_params = ConvertSystemParams -Connection $SystemParams
        $function_params   = ConvertFrom-Json2 $FunctionParams

        $properties = $function_params.Clone()

        # These are passed as mandatory parameters
        $properties.Remove('path')
        $properties.Remove('cn')

        LogIO info "New-ADComputer-ADSI" -In @connection_params -Path $function_params.path -CN $function_params.cn -Properties $properties
            $rv = New-ADComputer-ADSI @connection_params -PassThru -Path $function_params.path -CN $function_params.cn -Properties $properties
        LogIO info "New-ADComputer-ADSI" -Out $rv

        $rv
    }

    Log info "Done"
}


function Idm-ComputersRead {
    param (
        # Operations
        [switch] $GetMeta,
        # Parameters
        [string] $SystemParams,
        [string] $FunctionParams
    )

    Log info "-GetMeta=$GetMeta -SystemParams='$SystemParams' -FunctionParams='$FunctionParams'"

    if ($GetMeta) {
        #
        # Get meta data
        #

        Get-ClassMetaData -SystemParams $SystemParams -Class 'computer'
    }
    else {
        #
        # Execute function
        #

        $system_params   = ConvertSystemParams $SystemParams
        $function_params = ConvertFrom-Json2 $FunctionParams

        $filter = $function_params.filter

        if ($filter.length -eq 0) {
            # Avoid: Cannot validate argument on parameter 'Filter'. The argument is null or empty.
            # Provide an argument that is not null or empty, and then try the command again.
            $filter = '*'
        }

        $properties = $function_params.properties

        if ($properties.length -eq 0) {
            # Avoid: Cannot validate argument on parameter 'Properties'. The argument is null, empty,
            # or an element of the argument collection contains a null value. Supply a 
            $properties = $Global:Properties.default.computer
        }

        # Assure identity key is the first column
        $properties = @('objectGUID') + @($properties | Where-Object { $_ -ne 'objectGUID' })

        LogIO info "Get-ADComputer-ADSI" -In @system_params -LDAPFilter $filter -Properties $properties
        Get-ADComputer-ADSI @system_params -LDAPFilter $filter -Properties $properties
    }

    Log info "Done"
}


function Idm-ComputerUpdate {
    param (
        # Operations
        [switch] $GetMeta,
        # Parameters
        [string] $SystemParams,
        [string] $FunctionParams
    )

    Log info "-GetMeta=$GetMeta -SystemParams='$SystemParams' -FunctionParams='$FunctionParams'"

    if ($GetMeta) {
        #
        # Get meta data
        #

        $out = @{
            semantics = 'update'
            parameters = @(
                @{ name = 'accountPassword';       allowance = 'optional'   }
                @{ name = 'adsPath';               allowance = 'prohibited' }
                @{ name = 'badPasswordTime';       allowance = 'prohibited' }
                @{ name = 'badPwdCount';           allowance = 'prohibited' }
                @{ name = 'distinguishedName';     allowance = 'prohibited' }   # Conditionally replaced below
                @{ name = 'dSCorePropagationData'; allowance = 'prohibited' }
                @{ name = 'instanceType';          allowance = 'prohibited' }
                @{ name = 'lastLogoff';            allowance = 'prohibited' }
                @{ name = 'lastLogon';             allowance = 'prohibited' }
                @{ name = 'logonCount';            allowance = 'prohibited' }
                @{ name = 'objectClass';           allowance = 'prohibited' }
                @{ name = 'objectGUID';            allowance = 'prohibited' }   # Conditionally replaced below
                @{ name = 'objectSid';             allowance = 'prohibited' }
                @{ name = 'pwdLastSet';            allowance = 'prohibited' }
                @{ name = 'uSNChanged';            allowance = 'prohibited' }
                @{ name = 'uSNCreated';            allowance = 'prohibited' }
                @{ name = 'whenChanged';           allowance = 'prohibited' }
                @{ name = 'whenCreated';           allowance = 'prohibited' }
               #@{ name = '*';                     allowance = 'optional'   }
            )
        }

        $out.parameters = @(@{ name = 'objectGUID'; allowance = 'mandatory' }) + @($out.parameters | Where-Object { $_.name -ne 'objectGUID' }) | Sort-Object { $_.name }
        $out
    }
    else {
        #
        # Execute function
        #

        $connection_params = ConvertSystemParams -Connection $SystemParams
        $function_params   = ConvertFrom-Json2 $FunctionParams

        $properties = $function_params.Clone()

        # These are passed as mandatory parameters
        $properties.Remove('objectGUID')

        LogIO info "Set-ADComputer-ADSI" -In @connection_params -Identity $function_params.objectGUID -Properties $properties
            $rv = Set-ADComputer-ADSI @connection_params -PassThru -Identity $function_params.objectGUID -Properties $properties
        LogIO info "Set-ADComputer-ADSI" -Out $rv

        $rv
    }

    Log info "Done"
}


function Idm-ComputerDelete {
    param (
        # Operations
        [switch] $GetMeta,
        # Parameters
        [string] $SystemParams,
        [string] $FunctionParams
    )

    Log info "-GetMeta=$GetMeta -SystemParams='$SystemParams' -FunctionParams='$FunctionParams'"

    if ($GetMeta) {
        #
        # Get meta data
        #

        $out = @{
            semantics = 'delete'
            parameters = @(
                @{ name = '*'; allowance = 'prohibited' }
            )
        }

        $out.parameters = @(@{ name = 'objectGUID'; allowance = 'mandatory' }) + @($out.parameters | Where-Object { $_.name -ne 'objectGUID' }) | Sort-Object { $_.name }
        $out
    }
    else {
        #
        # Execute function
        #

        $connection_params = ConvertSystemParams -Connection $SystemParams
        $function_params   = ConvertFrom-Json2 $FunctionParams

        LogIO info "Remove-ADComputer-ADSI" -In @connection_params -Identity $function_params.objectGUID
            $rv = Remove-ADComputer-ADSI @connection_params -PassThru -Identity $function_params.objectGUID
        LogIO info "Remove-ADComputer-ADSI" -Out $rv

        $rv
    }

    Log info "Done"
}


function Idm-GroupCreate {
    param (
        # Operations
        [switch] $GetMeta,
        # Parameters
        [string] $SystemParams,
        [string] $FunctionParams
    )

    Log info "-GetMeta=$GetMeta -SystemParams='$SystemParams' -FunctionParams='$FunctionParams'"

    if ($GetMeta) {
        #
        # Get meta data
        #

        @{
            semantics = 'create'
            parameters = @(
                @{ name = 'adsPath';               allowance = 'prohibited' }
                @{ name = 'objectClass';           allowance = 'prohibited' }
                @{ name = 'objectGUID';            allowance = 'prohibited' }
                @{ name = 'objectSid';             allowance = 'prohibited' }
                @{ name = 'cn';                    allowance = 'mandatory'  }
                @{ name = 'distinguishedName';     allowance = 'prohibited' }
                @{ name = 'dSCorePropagationData'; allowance = 'prohibited' }
                @{ name = 'instanceType';          allowance = 'prohibited' }
                @{ name = 'path';                  allowance = 'mandatory'  }
                @{ name = 'uSNChanged';            allowance = 'prohibited' }
                @{ name = 'uSNCreated';            allowance = 'prohibited' }
                @{ name = 'whenChanged';           allowance = 'prohibited' }
                @{ name = 'whenCreated';           allowance = 'prohibited' }
               #@{ name = '*';                     allowance = 'optional'   }
            )
        }
    }
    else {
        #
        # Execute function
        #

        $connection_params = ConvertSystemParams -Connection $SystemParams
        $function_params   = ConvertFrom-Json2 $FunctionParams

        $properties = $function_params.Clone()

        # These are passed as mandatory parameters
        $properties.Remove('path')
        $properties.Remove('cn')

        LogIO info "New-ADGroup-ADSI" -In @connection_params -Path $function_params.path -CN $function_params.cn -Properties $properties
            $rv = New-ADGroup-ADSI @connection_params -PassThru -Path $function_params.path -CN $function_params.cn -Properties $properties
        LogIO info "New-ADGroup-ADSI" -Out $rv

        $rv
    }

    Log info "Done"
}


function Idm-GroupsRead {
    param (
        # Operations
        [switch] $GetMeta,
        # Parameters
        [string] $SystemParams,
        [string] $FunctionParams
    )

    Log info "-GetMeta=$GetMeta -SystemParams='$SystemParams' -FunctionParams='$FunctionParams'"

    if ($GetMeta) {
        #
        # Get meta data
        #

        Get-ClassMetaData -SystemParams $SystemParams -Class 'group'
    }
    else {
        #
        # Execute function
        #

        $system_params   = ConvertSystemParams $SystemParams
        $function_params = ConvertFrom-Json2 $FunctionParams

        $filter = $function_params.filter

        # Store filter for usage by other Idm functions
        $Global:Idm_GroupsRead_Filter = $filter

        if ($filter.length -eq 0) {
            # Avoid: Cannot validate argument on parameter 'Filter'. The argument is null or empty.
            # Provide an argument that is not null or empty, and then try the command again.
            $filter = '*'
        }

        $properties = $function_params.properties

        if ($properties.length -eq 0) {
            # Avoid: Cannot validate argument on parameter 'Properties'. The argument is null, empty,
            # or an element of the argument collection contains a null value. Supply a 
            $properties = $Global:Properties.default.group
        }

        # Assure identity key is the first column
        $properties = @('objectGUID') + @($properties | Where-Object { $_ -ne 'objectGUID' })

        LogIO info "Get-ADGroup-ADSI" -In @system_params -LDAPFilter $filter -Properties $properties
        Get-ADGroup-ADSI @system_params -LDAPFilter $filter -Properties $properties
    }

    Log info "Done"
}


function Idm-GroupUpdate {
    param (
        # Operations
        [switch] $GetMeta,
        # Parameters
        [string] $SystemParams,
        [string] $FunctionParams
    )

    Log info "-GetMeta=$GetMeta -SystemParams='$SystemParams' -FunctionParams='$FunctionParams'"

    if ($GetMeta) {
        #
        # Get meta data
        #

        $out = @{
            semantics = 'update'
            parameters = @(
                @{ name = 'adsPath';               allowance = 'prohibited' }
                @{ name = 'objectClass';           allowance = 'prohibited' }
                @{ name = 'objectGUID';            allowance = 'prohibited' }   # Conditionally replaced below
                @{ name = 'objectSid';             allowance = 'prohibited' }
                @{ name = 'distinguishedName';     allowance = 'prohibited' }   # Conditionally replaced below
                @{ name = 'dSCorePropagationData'; allowance = 'prohibited' }
                @{ name = 'instanceType';          allowance = 'prohibited' }
                @{ name = 'uSNChanged';            allowance = 'prohibited' }
                @{ name = 'uSNCreated';            allowance = 'prohibited' }
                @{ name = 'whenChanged';           allowance = 'prohibited' }
                @{ name = 'whenCreated';           allowance = 'prohibited' }
               #@{ name = '*';                     allowance = 'optional'   }
            )
        }

        $out.parameters = @(@{ name = 'objectGUID'; allowance = 'mandatory' }) + @($out.parameters | Where-Object { $_.name -ne 'objectGUID' }) | Sort-Object { $_.name }
        $out
    }
    else {
        #
        # Execute function
        #

        $connection_params = ConvertSystemParams -Connection $SystemParams
        $function_params   = ConvertFrom-Json2 $FunctionParams

        $properties = $function_params.Clone()

        # These are passed as mandatory parameters
        $properties.Remove('objectGUID')

        LogIO info "Set-ADGroup-ADSI" -In @connection_params -Identity $function_params.objectGUID -Properties $properties
            $rv = Set-ADGroup-ADSI @connection_params -PassThru -Identity $function_params.objectGUID -Properties $properties
        LogIO info "Set-ADGroup-ADSI" -Out $rv

        $rv
    }

    Log info "Done"
}


function Idm-GroupDelete {
    param (
        # Operations
        [switch] $GetMeta,
        # Parameters
        [string] $SystemParams,
        [string] $FunctionParams
    )

    Log info "-GetMeta=$GetMeta -SystemParams='$SystemParams' -FunctionParams='$FunctionParams'"

    if ($GetMeta) {
        #
        # Get meta data
        #

        $out = @{
            semantics = 'delete'
            parameters = @(
                @{ name = '*'; allowance = 'prohibited' }
            )
        }

        $out.parameters = @(@{ name = 'objectGUID'; allowance = 'mandatory' }) + @($out.parameters | Where-Object { $_.name -ne 'objectGUID' }) | Sort-Object { $_.name }
        $out
    }
    else {
        #
        # Execute function
        #

        $connection_params = ConvertSystemParams -Connection $SystemParams
        $function_params   = ConvertFrom-Json2 $FunctionParams

        LogIO info "Remove-ADGroup-ADSI" -In @connection_params -Identity $function_params.objectGUID
            $rv = Remove-ADGroup-ADSI @connection_params -PassThru -Identity $function_params.objectGUID
        LogIO info "Remove-ADGroup-ADSI" -Out $rv

        $rv
    }

    Log info "Done"
}


function Idm-MembershipsRead {
    param (
        # Operations
        [switch] $GetMeta,
        # Parameters
        [string] $SystemParams,
        [string] $FunctionParams
    )

    Log info "-GetMeta=$GetMeta -SystemParams='$SystemParams' -FunctionParams='$FunctionParams'"

    if ($GetMeta) {
        #
        # Get meta data
        #

        @()
    }
    else {
        #
        # Execute function
        #

        $system_params = ConvertSystemParams $SystemParams

        # Use same filter as Idm-GroupsRead
        $filter = $Global:Idm_GroupsRead_Filter

        if ($filter.length -eq 0) {
            # Avoid: Cannot validate argument on parameter 'Filter'. The argument is null or empty.
            # Provide an argument that is not null or empty, and then try the command again.
            $filter = '*'
        }

        $properties = @('objectGUID', 'member')

        # For recursive implementation, see:
        # -> https://www.petri.com/managing-active-directory-groups-adsi-powershell

        LogIO info "Get-ADGroup-ADSI" -In @system_params -LDAPFilter $filter -Properties $properties

        Get-ADGroup-ADSI @system_params -LDAPFilter $filter -Properties $properties | ForEach-Object {
            $group = $_.objectGUID
            $_.member | ForEach-Object {
                [PSCustomObject]@{ "group" = $group; "member" = $_.ToString() }
            }
        }
    }

    Log info "Done"
}


function Idm-MembershipCreate {
    param (
        # Operations
        [switch] $GetMeta,
        # Parameters
        [string] $SystemParams,
        [string] $FunctionParams
    )

    Log info "-GetMeta=$GetMeta -SystemParams='$SystemParams' -FunctionParams='$FunctionParams'"

    if ($GetMeta) {
        #
        # Get meta data
        #

        @{
            semantics = 'create'
            parameters = @(
                @{ name = "group";  allowance = 'mandatory'  }
                @{ name = "member"; allowance = 'mandatory'  }
                @{ name = '*';      allowance = 'prohibited' }
            )
        }
    }
    else {
        #
        # Execute function
        #

        $connection_params = ConvertSystemParams -Connection $SystemParams
        $function_params   = ConvertFrom-Json2 $FunctionParams

        LogIO info "Set-ADGroupMember-ADSI" -In @connection_params -Identity $function_params["group"] -MembersAdd @($function_params["member"]) -MembersRemove @()
            $rv = Set-ADGroupMember-ADSI -PassThru @connection_params -Identity $function_params["group"] -MembersAdd @($function_params["member"]) -MembersRemove @()
        LogIO info "Set-ADGroupMember-ADSI" -Out $rv

        $rv
    }

    Log info "Done"
}


function Idm-MembershipsUpdate {
    param (
        # Operations
        [switch] $GetMeta,
        # Parameters
        [string] $SystemParams,
        [string] $FunctionParams
    )

    Log info "-GetMeta=$GetMeta -SystemParams='$SystemParams' -FunctionParams='$FunctionParams'"

    if ($GetMeta) {
        #
        # Get meta data
        #

        @{
            semantics = 'memberships-update'
            parentTable = 'Groups'
        #    parameters = @(
        #        @{ name = 'group';  allowance = 'mandatory'  }
        #        @{ name = 'add';    allowance = 'mandatory'  }
        #        @{ name = 'remove'; allowance = 'mandatory'  }
        #        @{ name = '*';      allowance = 'prohibited' }
        #    )
        }
    }
    else {
        #
        # Execute function
        #

        $connection_params = ConvertSystemParams -Connection $SystemParams
        $function_params   = ConvertFrom-Json2 $FunctionParams

        # Force arrays
        $function_params.add    = @($function_params.add)
        $function_params.remove = @($function_params.remove)

        LogIO info "Set-ADGroupMember-ADSI" -In @connection_params -Identity $function_params.group -MembersAdd $function_params.add -MembersRemove $function_params.remove
            $rv = Set-ADGroupMember-ADSI -PassThru @connection_params -Identity $function_params.group -MembersAdd $function_params.add -MembersRemove $function_params.remove
        LogIO info "Set-ADGroupMember-ADSI" -Out $rv

        $rv
    }

    Log info "Done"
}


function Idm-MembershipDelete {
    param (
        # Operations
        [switch] $GetMeta,
        # Parameters
        [string] $SystemParams,
        [string] $FunctionParams
    )

    Log info "-GetMeta=$GetMeta -SystemParams='$SystemParams' -FunctionParams='$FunctionParams'"

    if ($GetMeta) {
        #
        # Get meta data
        #

        @{
            semantics = 'delete'
            parameters = @(
                @{ name = "group";  allowance = 'mandatory'  }
                @{ name = "member"; allowance = 'mandatory'  }
                @{ name = '*';      allowance = 'prohibited' }
            )
        }
    }
    else {
        #
        # Execute function
        #

        $connection_params = ConvertSystemParams -Connection $SystemParams
        $function_params   = ConvertFrom-Json2 $FunctionParams

        LogIO info "Set-ADGroupMember-ADSI" -In @connection_params -Identity $function_params["group"] -MembersAdd @() -MembersRemove @($function_params["member"])
            $rv = Set-ADGroupMember-ADSI -PassThru @connection_params -Identity $function_params["group"] -MembersAdd @() -MembersRemove @($function_params["member"])
        LogIO info "Set-ADGroupMember-ADSI" -Out $rv

        $rv
    }

    Log info "Done"
}


function Idm-OrganizationalUnitCreate {
    param (
        # Operations
        [switch] $GetMeta,
        # Parameters
        [string] $SystemParams,
        [string] $FunctionParams
    )

    Log info "-GetMeta=$GetMeta -SystemParams='$SystemParams' -FunctionParams='$FunctionParams'"

    if ($GetMeta) {
        #
        # Get meta data
        #

        @{
            semantics = 'create'
            parameters = @(
                @{ name = 'adsPath';               allowance = 'prohibited' }
                @{ name = 'objectClass';           allowance = 'prohibited' }
                @{ name = 'objectGUID';            allowance = 'prohibited' }
                @{ name = 'distinguishedName';     allowance = 'prohibited' }
                @{ name = 'dSCorePropagationData'; allowance = 'prohibited' }
                @{ name = 'instanceType';          allowance = 'prohibited' }
                @{ name = 'ou';                    allowance = 'mandatory'  }
                @{ name = 'path';                  allowance = 'mandatory'  }
                @{ name = 'uSNChanged';            allowance = 'prohibited' }
                @{ name = 'uSNCreated';            allowance = 'prohibited' }
                @{ name = 'whenChanged';           allowance = 'prohibited' }
                @{ name = 'whenCreated';           allowance = 'prohibited' }
               #@{ name = '*';                     allowance = 'optional'   }
            )
        }
    }
    else {
        #
        # Execute function
        #

        $connection_params = ConvertSystemParams -Connection $SystemParams
        $function_params   = ConvertFrom-Json2 $FunctionParams

        $properties = $function_params.Clone()

        # These are passed as mandatory parameters
        $properties.Remove('path')
        $properties.Remove('ou')

        LogIO info "New-ADOrganizationalUnit-ADSI" -In @connection_params -Path $function_params.path -OU_ $function_params.ou -Properties $properties
            $rv = New-ADOrganizationalUnit-ADSI @connection_params -PassThru -Path $function_params.path -OU $function_params.ou -Properties $properties
        LogIO info "New-ADOrganizationalUnit-ADSI" -Out $rv

        $rv
    }

    Log info "Done"
}


function Idm-OrganizationalUnitsRead {
    param (
        # Operations
        [switch] $GetMeta,
        # Parameters
        [string] $SystemParams,
        [string] $FunctionParams
    )

    Log info "-GetMeta=$GetMeta -SystemParams='$SystemParams' -FunctionParams='$FunctionParams'"

    if ($GetMeta) {
        #
        # Get meta data
        #

        Get-ClassMetaData -SystemParams $SystemParams -Class 'organizationalUnit'
    }
    else {
        #
        # Execute function
        #

        $system_params   = ConvertSystemParams $SystemParams
        $function_params = ConvertFrom-Json2 $FunctionParams

        if ($function_params.include_container_objects) {
            $system_params.IncludeContainers = $true
        }

        $filter = $function_params.filter

        if ($filter.length -eq 0) {
            # Avoid: Cannot validate argument on parameter 'Filter'. The argument is null or empty.
            # Provide an argument that is not null or empty, and then try the command again.
            $filter = '*'
        }

        $properties = $function_params.properties

        if ($properties.length -eq 0) {
            # Avoid: Cannot validate argument on parameter 'Properties'. The argument is null, empty,
            # or an element of the argument collection contains a null value. Supply a 
            $properties = $Global:Properties.default.organizationalUnit
        }

        # Assure identity key is the first column
        $properties = @('objectGUID') + @($properties | Where-Object { $_ -ne 'objectGUID' })

        LogIO info "Get-ADOrganizationalUnit-ADSI" -In @system_params -LDAPFilter $filter -Properties $properties
        Get-ADOrganizationalUnit-ADSI @system_params -LDAPFilter $filter -Properties $properties
    }

    Log info "Done"
}


function Idm-OrganizationalUnitUpdate {
    param (
        # Operations
        [switch] $GetMeta,
        # Parameters
        [string] $SystemParams,
        [string] $FunctionParams
    )

    Log info "-GetMeta=$GetMeta -SystemParams='$SystemParams' -FunctionParams='$FunctionParams'"

    if ($GetMeta) {
        #
        # Get meta data
        #

        $out = @{
            semantics = 'update'
            parameters = @(
                @{ name = 'adsPath';               allowance = 'prohibited' }
                @{ name = 'objectClass';           allowance = 'prohibited' }
                @{ name = 'objectGUID';            allowance = 'prohibited' }   # Conditionally replaced below
                @{ name = 'distinguishedName';     allowance = 'prohibited' }   # Conditionally replaced below
                @{ name = 'dSCorePropagationData'; allowance = 'prohibited' }
                @{ name = 'instanceType';          allowance = 'prohibited' }
                @{ name = 'ou';                    allowance = 'prohibited' }
                @{ name = 'uSNChanged';            allowance = 'prohibited' }
                @{ name = 'uSNCreated';            allowance = 'prohibited' }
                @{ name = 'whenChanged';           allowance = 'prohibited' }
                @{ name = 'whenCreated';           allowance = 'prohibited' }
               #@{ name = '*';                     allowance = 'optional'   }
            )
        }

        $out.parameters = @(@{ name = 'objectGUID'; allowance = 'mandatory' }) + @($out.parameters | Where-Object { $_.name -ne 'objectGUID' }) | Sort-Object { $_.name }
        $out
    }
    else {
        #
        # Execute function
        #

        $connection_params = ConvertSystemParams -Connection $SystemParams
        $function_params   = ConvertFrom-Json2 $FunctionParams

        $properties = $function_params.Clone()

        # These are passed as mandatory parameters
        $properties.Remove('objectGUID')

        LogIO info "Set-ADOrganizationalUnit-ADSI" -In @connection_params -Identity $function_params.objectGUID -Properties $properties
            $rv = Set-ADOrganizationalUnit-ADSI @connection_params -PassThru -Identity $function_params.objectGUID -Properties $properties
        LogIO info "Set-ADOrganizationalUnit-ADSI" -Out $rv

        $rv
    }

    Log info "Done"
}


function Idm-OrganizationalUnitDelete {
    param (
        # Operations
        [switch] $GetMeta,
        # Parameters
        [string] $SystemParams,
        [string] $FunctionParams
    )

    Log info "-GetMeta=$GetMeta -SystemParams='$SystemParams' -FunctionParams='$FunctionParams'"

    if ($GetMeta) {
        #
        # Get meta data
        #

        $out = @{
            semantics = 'delete'
            parameters = @(
                @{ name = '*'; allowance = 'prohibited' }
            )
        }

        $out.parameters = @(@{ name = 'objectGUID'; allowance = 'mandatory' }) + @($out.parameters | Where-Object { $_.name -ne 'objectGUID' }) | Sort-Object { $_.name }
        $out
    }
    else {
        #
        # Execute function
        #

        $connection_params = ConvertSystemParams -Connection $SystemParams
        $function_params   = ConvertFrom-Json2 $FunctionParams

        LogIO info "Remove-ADOrganizationalUnit-ADSI" -In @connection_params -Identity $function_params.objectGUID
            $rv = Remove-ADOrganizationalUnit-ADSI @connection_params -PassThru -Identity $function_params.objectGUID
        LogIO info "Remove-ADOrganizationalUnit-ADSI" -Out $rv

        $rv
    }

    Log info "Done"
}


#
# Helper functions
#

function ConvertSystemParams {
    param (
        [switch] $Connection,
        [switch] $Configuration,
        [string] $InputParams
    )

    $in_params = ConvertFrom-Json2 $InputParams

    $out_params = @{}

    if ($Connection -or -not $Configuration) {
        $out_params.Server = $in_params.domain

        if ($in_params.use_specific_server) {
            $out_params.Server = $in_params.server
        }

        if ($out_params.Server.length -eq 0) {
            # Avoid: Cannot validate argument on parameter 'Server'. The argument is null or empty.
            # Provide an argument that is not null or empty, and then try the command again.
            $out_params.Remove('Server')
        }

        if (-not $in_params.use_svc_account_creds) {
            $out_params.Credential = New-Object System.Management.Automation.PSCredential($in_params.username, (ConvertTo-SecureString $in_params.password -AsPlainText -Force))
        }
    }

    if ($Configuration -or -not $Connection) {

        if (! $in_params.multi_searchbases) {
            # User 'searchbase' parameter
            $out_params.SearchBases = if ($in_params.searchbase -eq '*' -or $in_params.searchbase.length -eq 0) { @() } else { @($in_params.searchbase) }
        }
        else {
            # User 'searchbases' parameter
            $out_params.SearchBases = $in_params.searchbases
        }

        if ($out_params.SearchBases.length -eq 0) {
            # Avoid: An empty SearchBase is only supported while connected to a GlobalCatalog
            $out_params.Remove('SearchBases')
        }

        $out_params.ResultPageSize = $in_params.resultpagesize

        if ($out_params.ResultPageSize -eq '0') {
            $out_params.Remove('ResultPageSize')
        }

        if ($out_params.ResultPageSize.length -eq 0) {
            $out_params.Remove('ResultPageSize')
        }
    }

    return $out_params
}


function Get-ADAttributes {
    #
    # Derived from: https://www.easy365manager.com/how-to-get-all-active-directory-user-object-attributes
    #
    # Other suggestion: https://www.neroblanco.co.uk/2017/09/get-possible-ad-attributes-user-group
    #

    param (
        [Parameter(Mandatory)] [String] $Class,
        [PSCredential] $Credential,
        [String] $Server
    )

    $connection_args = @{}

    if ($Credential) { $connection_args.Credential = $Credential }
    if ($Server)     { $connection_args.Server     = $Server }

    # Retrieve the class and any parent classes
    $class_name = $Class
    $class_list = [System.Collections.ArrayList]@()

    while ($true) {
        $class_obj = Get-ADObject-ADSI @connection_args -SearchBase (Get-ADRootDSE-ADSI @connection_args).SchemaNamingContext.ToString() -LDAPFilter "(ldapDisplayName=$class_name)" -Properties AuxiliaryClass, SystemAuxiliaryClass, mayContain, mustContain, systemMayContain, systemMustContain, subClassOf, ldapDisplayName
        $null = $class_list.Add($class_obj)

        if ($class_obj.subClassOf -eq $class_obj.ldapDisplayName) { break }

        $class_name = $class_obj.subClassOf
    }

    # For all classes in list, get auxiliary class attributes and direct attributes
    $attributes_list = [System.Collections.ArrayList]@()

    $class_list | ForEach-Object {
        $aux = @()
        $sys_aux = @()

        # Get Auxiliary class attributes
        if ($_.AuxiliaryClass) {
            $aux = $_.AuxiliaryClass | ForEach-Object { Get-ADObject-ADSI @connection_args -SearchBase (Get-ADRootDSE-ADSI @connection_args).SchemaNamingContext.ToString() -LDAPFilter "(ldapDisplayName=$_)" -Properties mayContain, mustContain, systemMayContain, systemMustContain } |
                Select-Object @{n = "Attributes"; e = { $_.mayContain + $_.mustContain + $_.systemMaycontain + $_.systemMustContain } } |
                Select-Object -ExpandProperty Attributes
        }

        # Get SystemAuxiliary class attributes
        if ($_.SystemAuxiliaryClass) {
            $sys_aux = $_.SystemAuxiliaryClass | ForEach-Object { Get-ADObject-ADSI @connection_args -SearchBase (Get-ADRootDSE-ADSI @connection_args).SchemaNamingContext.ToString() -LDAPFilter "(ldapDisplayName=$_)" -Properties MayContain, SystemMayContain, systemMustContain } |
                Select-Object @{n = "Attributes"; e = { $_.mayContain + $_.mustContain + $_.systemMaycontain + $_.systemMustContain } } |
                Select-Object -ExpandProperty Attributes
        }

        # Get direct attributes
        $attributes_list += $aux + $sys_aux + $_.mayContain + $_.mustContain + $_.systemMayContain + $_.systemMustContain
    }

    $attributes_list | Sort-Object -Unique
}


function Get-ClassMetaData {
    param (
        [string] $SystemParams,
        [string] $Class
    )

    $connection_params = ConvertSystemParams -Connection $SystemParams

    Log info "Getting attribute schema of class '$Class'"

    $all_properties  = @( Get-ADAttributes @connection_params -Class $Class )
    $all_properties += $Global:Properties.extra.$Class

    if ($Class -eq 'user') {
        $all_properties += $Global:TerminalServicesAttributes
    }

    $all_properties = $all_properties | Where-Object { $Global:Properties.exclude -notcontains $_ }

    $properties_rows = $all_properties | Sort-Object -Unique | ForEach-Object {
        $usage_hint = @()

        if ($Global:Properties.default.$Class -contains $_) {
            $usage_hint += 'Default'
        }

        if ($Global:Properties.idm -contains $_ -or $Global:Properties.extra.$Class -contains $_) {
            $usage_hint += 'IDM'
        }

        if ($Class -eq 'user') {
            if ($Global:TerminalServicesAttributes -contains $_) {
                $usage_hint += 'TS'
            }
        }

        @{ name = $_; usage_hint = ($usage_hint -join ' | ') }
    }

    $out = @()

    if ($Class -eq 'organizationalUnit') {
        $out += @{
            name = 'include_container_objects'
            type = 'checkbox'
            label = 'Include container objects'
            value = $false
        }
    }

    $out += @(
        @{
            name = 'filter'
            type = 'textbox'
            label = 'LDAP filter'
            tooltip = 'Search filter; empty or * matches anything'
            value = '*'
        }
        @{
            name = 'properties'
            type = 'grid'
            label = 'Properties'
            table = @{
                rows = @( $properties_rows )
                settings_grid = @{
                    selection = 'multiple'
                    key_column = 'name'
                    checkbox = $true
                    filter = $true
                    columns = @(
                        @{
                            name = 'name'
                            display_name = 'Name'
                        }
                        @{
                            name = 'usage_hint'
                            display_name = 'Usage hint'
                        }
                    )
                }
            }
            value = $Global:Properties.default.$Class
        }
    )

    $out
}
