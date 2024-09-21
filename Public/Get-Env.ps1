function Get-Env {
    <#
    .SYNOPSIS
    Gets an Environment Variable.

    .DESCRIPTION
    This will will get an environment variable based on the variable name
    and scope while accounting whether to expand the variable or not
    (e.g.: `%TEMP%`-> `C:\User\Username\AppData\Local\Temp`).

    Will provide a list of environment variable names based on the scope, when a wildchar is used This

    .NOTES
    This helper reduces the number of lines one would have to write to get
    environment variables, mainly when not expanding the variables is a
    must.

    HKCU:\Environment may not exist in all Windows OSes (such as Server Core).
    Process dumps the current environment variable names in memory /
    session. The other scopes refer to the registry values.

    .PARAMETER Name
    The environment variable you want to get the value from.

    .PARAMETER source
    .env file path from which to read variables.

    .PARAMETER Scope
    The environment variable target scope. This is `Process`, `User`, or
    `Machine`.

    .PARAMETER PreserveVariables
    A switch parameter stating whether you want to expand the variables or
    not. Defaults to false. Available in 0.9.10+.

    .PARAMETER IgnoredArguments
    Allows splatting with arguments that do not apply. Do not use directly.

    .EXAMPLE
    Get-Env -Name 'TEMP' -Scope User -PreserveVariables

    .EXAMPLE
    Get-Env -Name 'PATH' -Scope Machine

    .LINK
    Add-Env
    #>
    [CmdletBinding(DefaultParameterSetName = 'session')]
    [OutputType([string])]
    [Alias('Get-Envt')]
    param(
        [Parameter(Mandatory = $true, Position = 0, ParameterSetName = 'session')]
        [string]$Name,

        [Parameter(Mandatory = $true, Position = 0, ParameterSetName = 'file')]
        [ValidateNotNullOrEmpty()]
        [IO.FileInfo]$source,

        [Parameter(Mandatory = $true, Position = 1, ParameterSetName = '__AllparameterSets')]
        [System.EnvironmentVariableTarget]$Scope,

        [Parameter(Mandatory = $false, ParameterSetName = '__AllparameterSets')]
        [switch]$PreserveVariables = $false,

        # If specified the cmdlet will only read variables from .env files or other configured sources of env variables.
        [Parameter(Mandatory = $false, ParameterSetName = 'file')]
        [switch]$FromFilesOnly = $false
    )

    DynamicParam {
        $DynamicParams = [System.Management.Automation.RuntimeDefinedParameterDictionary]::new()
        #region IgnoredArguments
        $attributeCollection = [System.Collections.ObjectModel.Collection[System.Attribute]]::new()
        $attributes = [System.Management.Automation.ParameterAttribute]::new(); $attHash = @{
            Position                        = 3
            ParameterSetName                = '__AllParameterSets'
            Mandatory                       = $False
            ValueFromPipeline               = $true
            ValueFromPipelineByPropertyName = $true
            ValueFromRemainingArguments     = $true
            HelpMessage                     = 'Allows splatting with arguments that do not apply. Do not use directly.'
            DontShow                        = $False
        }; $attHash.Keys | ForEach-Object { $attributes.$_ = $attHash.$_ }
        $attributeCollection.Add($attributes)
        # $attributeCollection.Add([System.Management.Automation.ValidateSetAttribute]::new([System.Object[]]$ValidateSetOption))
        # $attributeCollection.Add([System.Management.Automation.ValidateRangeAttribute]::new([System.Int32[]]$ValidateRange))
        # $attributeCollection.Add([System.Management.Automation.ValidateNotNullOrEmptyAttribute]::new())
        # $attributeCollection.Add([System.Management.Automation.AliasAttribute]::new([System.String[]]$Aliases))
        $RuntimeParam = [System.Management.Automation.RuntimeDefinedParameter]::new("IgnoredArguments", [Object[]], $attributeCollection)
        $DynamicParams.Add("IgnoredArguments", $RuntimeParam)
        #endregion IgnoredArguments
        return $DynamicParams
    }

    begin {
        $PsCmdlet.MyInvocation.BoundParameters.GetEnumerator() | ForEach-Object { New-Variable -Name $_.Key -Value $_.Value -ea 'SilentlyContinue' }
        $result = $null
    }

    Process {
        if ($Name.Contains('*')) {
            switch ($Scope) {
                'User' { Get-Item 'HKCU:\Environment' -ErrorAction SilentlyContinue | Select-Object -ExpandProperty Property }
                'Machine' { Get-Item 'HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager\Environment' | Select-Object -ExpandProperty Property }
                'Process' { Get-ChildItem Env:\ | Select-Object -ExpandProperty Key }
                default { throw "Unsupported environment scope: $Scope" }
            }
        }

        [string] $MACHINE_ENVIRONMENT_REGISTRY_KEY_NAME = "SYSTEM\CurrentControlSet\Control\Session Manager\Environment\";
        [Microsoft.Win32.RegistryKey] $win32RegistryKey = [Microsoft.Win32.Registry]::LocalMachine.OpenSubKey($MACHINE_ENVIRONMENT_REGISTRY_KEY_NAME)
        if ($Scope -eq [System.EnvironmentVariableTarget]::User) {
            [string] $USER_ENVIRONMENT_REGISTRY_KEY_NAME = "Environment";
            [Microsoft.Win32.RegistryKey] $win32RegistryKey = [Microsoft.Win32.Registry]::CurrentUser.OpenSubKey($USER_ENVIRONMENT_REGISTRY_KEY_NAME)
        } elseif ($Scope -eq [System.EnvironmentVariableTarget]::Process) {
            return [Environment]::GetEnvironmentVariable($Name, $Scope)
        }

        [Microsoft.Win32.RegistryValueOptions] $registryValueOptions = [Microsoft.Win32.RegistryValueOptions]::None

        if ($PreserveVariables) {
            Out-Verbose "Choosing not to expand environment names"
            $registryValueOptions = [Microsoft.Win32.RegistryValueOptions]::DoNotExpandEnvironmentNames
        }
        try {
            #Out-Verbose "Getting environment variable $Name"
            if ($null -ne $win32RegistryKey) {
                # Some versions of Windows do not have HKCU:\Environment
                $result = $win32RegistryKey.GetValue($Name, [string]::Empty, $registryValueOptions)
            }
        } catch {
            Write-Debug "Unable to retrieve the $Name environment variable. Details: $_"
        } finally {
            if ($null -ne $win32RegistryKey) {
                $win32RegistryKey.Close()
            }
        }
        if ([string]::IsNullOrWhiteSpace(($result -as [string]))) {
            $result = [Environment]::GetEnvironmentVariable($Name, $Scope)
        }
    }

    end {
        return $result
    }
}
Set-Alias -Name 'Read-Envt' -Description 'Reads environment Variable(s) from a .env file.' -Value 'Get-Env -FromFilesOnly' -Option AllScope
Set-Alias -Name 'Read-Env' -Description 'Reads environment Variable(s) from a .env file.' -Value 'Get-Env -FromFilesOnly' -Option AllScope