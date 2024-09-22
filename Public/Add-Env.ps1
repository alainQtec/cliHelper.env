function Add-Env {
  # .SYNOPSIS
  #     Saves an environment variable.

  # .DESCRIPTION
  #     Saves an environment variable.
  #     On windows, You can check in C:\Windows\System32\SystemPropertiesAdvanced.exe to see if it took effect.

  # .INPUTS
  #     [string]

  # .OUTPUTS
  #     [void]

  # .EXAMPLE
  #     Add-Env -Name 'testvar' -Value '009'

  # .EXAMPLE
  #     Add-Env -Name 'path' -scope 'Machine' -value $rscriptPath

  # .NOTES
  #     **NOTE:** Administrative Access Required when using `-Scope 'Machine'.`
  # .LINK
  #     Add-Env
  [CmdletBinding(SupportsShouldProcess = $true, DefaultParameterSetName = 'session')]
  [Alias('Set-Env')]
  param (
    [Parameter(Mandatory = $true, Position = 0, ValueFromPipeline = $true, ValueFromPipelineByPropertyName = $true, ParameterSetName = 'session')]
    [ValidateNotNullOrWhiteSpace()]
    [string]$Name,

    [Parameter(Mandatory = $true, Position = 0, ParameterSetName = 'file')]
    [ValidateNotNullOrEmpty()]
    [IO.FileInfo]$source,

    [parameter(Mandatory = $false, Position = 1, ValueFromPipeline = $true, ValueFromPipelineByPropertyName = $true, ParameterSetName = 'session')]
    [string]$Value,

    [Parameter(Mandatory = $false, Position = 2, ValueFromPipeline = $true, ValueFromPipelineByPropertyName = $true, ParameterSetName = '__AllparameterSets')]
    [Alias('Target', 'variableType', 'Type')]
    [ValidateNotNullOrEmpty()]
    [System.EnvironmentVariableTarget]$Scope,

    [Parameter(Mandatory = $true, Position = 3, ParameterSetName = '__AllParameterSets')]
    [ValidateNotNullOrWhiteSpace()]
    [string]$OutFile
  )

  begin {
    [System.Management.Automation.ActionPreference]$eap = $ErrorActionPreference; $ErrorActionPreference = "SilentlyContinue"
    [System.Management.Automation.ActionPreference]$Ifp = $InformationPreference; $InformationPreference = "Continue"
    [bool]$Admin = $((New-Object Security.Principal.WindowsPrincipal $([Security.Principal.WindowsIdentity]::GetCurrent())).IsInRole([Security.Principal.WindowsBuiltinRole]::Administrator));
    if (-not $Admin) {
      Write-Warning "$fxn [!]  It seems You're not Admin"
      # exit
    }
    # This function only works on windows
    $IsLinuxEnv = (Get-Variable -Name "IsLinux" -ErrorAction Ignore) -and $IsLinux
    $IsMacOSEnv = (Get-Variable -Name "IsMacOS" -ErrorAction Ignore) -and $IsMacOS
    $IsWinEnv = !$IsLinuxEnv -and !$IsMacOSEnv
    if (-not $IsWinEnv) {
      return
    }
    # Log Invocation and Parameters used. ie: $($MyInvocation.MyCommand), $PSBoundParameters
    $fxn = ('[' + $MyInvocation.MyCommand.Name + ']')
    # First of all,  validate the scope:
    if ($PSBoundParameters.ContainsKey('Scope')) {
      $valid_scopes = $([System.EnvironmentVariableTarget].GetFields() | Where-Object { $_.FieldType.Name -eq 'EnvironmentVariableTarget' }).Name
      try {
        if ($Scope -in $valid_scopes) {
          [System.EnvironmentVariableTarget]$Scope = $Scope
        } else {
          Write-Debug "$fxn 🤖 The specified Scope Param is not valid, re-setting it to default_scope: 'Process'"
          $Scope = [System.EnvironmentVariableTarget]::Process
        }
      } catch [System.Management.Automation.ArgumentTransformationMetadataException], [System.Management.Automation.PSInvalidCastException] {
        Write-Info "$fxn [!]  Error: Invalid scope. Please Provide one of the following valid scopes: $valid_scopes"
        break
      } catch {
        Write-Info "$fxn [!]  Error: $($Error[0]) ($($MyInvocation.MyCommand.Name):$($_.InvocationInfo.ScriptLineNumber))"
        break
      }
    } else {
      Write-Debug "$fxn 🤖 Scope Param was not specified, setting it to default_scope: 'Process'"
      $Scope = [System.EnvironmentVariableTarget]::Process
    }
  }

  process {
    [string]$registryKey = if ($Scope -eq [System.EnvironmentVariableTarget]::User) { 'Environment' }else { "SYSTEM\CurrentControlSet\Control\Session Manager\Environment\" };
    if ($PSBoundParameters.Item('Name') -eq "Path") {
      if ($Scope -eq [System.EnvironmentVariableTarget]::Machine) {
        try {
          $dkey = "HKLM\DEFAULT"; $ntFl = "C:\Users\Default\NTUSER.DAT"
          if (!(Test-Path $dkey.Replace("\", ":"))) {
            if ($PSCmdlet.ShouldProcess("$fxn 🤖 Loading file $ntFl to the reg Key $dkey", "$dkey", 'reg load')) {
              $result = reg load $dkey $ntFl *>&1
            }
            if (!$?) {
              throw "Failed to load hive: $result"
            }
          }
          New-Variable -Name hive_is_connected -Value $true -Visibility Public
        } catch {
          throw $_.Exception
        }
        [string]$registryKey = 'DEFAULT\Environment'
      }
      $Name = 'PATH'
    }
    [string]$keyHive = if ($Scope -eq [System.EnvironmentVariableTarget]::User) { 'HKEY_CURRENT_USER' } else { 'HKEY_LOCAL_MACHINE' };
    [Microsoft.Win32.RegistryKey]$win32RegistryKey = if ($Scope -eq [System.EnvironmentVariableTarget]::User) { [Microsoft.Win32.Registry]::CurrentUser.OpenSubKey($registryKey) }else { [Microsoft.Win32.Registry]::LocalMachine.OpenSubKey($registryKey) };

    # _TODO: ADD wRITE aCCESS CHECKING: win32RegistryKey is null here if it the user was unable to get ReadWriteSubTree access.
    if ($null -eq $win32RegistryKey.OpenSubKey($registryKey, [Microsoft.Win32.RegistryKeyPermissionCheck]::ReadWriteSubTree)) {
      Write-Debug "$fxn [!]  No RegistryKeyReadWrite Permission."
    }
    [Microsoft.Win32.RegistryValueKind]$registryType = [Microsoft.Win32.RegistryValueKind]::String
    [Microsoft.Win32.RegistryValueKind]$registryType = Invoke-Command -ScriptBlock {
      try {
        if ($win32RegistryKey.GetValueNames() -contains $Name) { $win32RegistryKey.GetValueKind($Name) }elseif ($Name -eq 'PATH') { [Microsoft.Win32.RegistryValueKind]::ExpandString }else { [Microsoft.Win32.RegistryValueKind]::String }
      } catch {
        "Registry type for $Name doesn't yet exist" | Write-Information
        # Move on, Nothing to see here.
      }
    }
    Write-Debug "$fxn Env:variable Name       : $Name"
    Write-Debug "$fxn Env:variable value      : $value"
    Write-Debug "$fxn Env:variable Scope      : $Scope"
    Write-Debug "$fxn Registry type for `$Name : $registryType"
    Write-Debug "$fxn Registry keyHive        : $keyHive"
    Write-Debug "$fxn Registrykey             : $registryKey"
    if ($PSBoundParameters.Item('Name') -eq 'PATH') {
      $CurrentPath = & {
        try {
          [System.Environment]::GetEnvironmentVariable('PATH', "$Scope")
        } catch {
          # probably scope issues ?!
          $win32RegistryKey.GetValue('PATH', '', [Microsoft.Win32.RegistryValueOptions]::DoNotExpandEnvironmentNames).TrimEnd([System.IO.Path]::PathSeparator)
        }
      }
      # Evaluate new path
      $NewPathValue = if (($null -eq $Value) -or ($Value -eq '')) { $CurrentPath }else { [string]::Concat($value, [System.IO.Path]::PathSeparator, $CurrentPath) }
      # Keep current PathValueKind if possible/appropriate
      [Microsoft.Win32.RegistryValueKind]$PathValueKind = & {
        try {
          $win32RegistryKey.GetValueKind('PATH')
        } catch {
          [Microsoft.Win32.RegistryValueKind]::ExpandString
        }
      }
      # Upgrade PathValueKind to [Microsoft.Win32.RegistryValueKind]::ExpandString if appropriate
      if ($NewPathValue.Contains('%')) { $PathValueKind = [Microsoft.Win32.RegistryValueKind]::ExpandString }
      try {
        if ($PSCmdlet.ShouldProcess('PATH', "`$win32RegistryKey.SetValue('PATH', $NewPathValue, $PathValueKind)")) {
          [void]$win32RegistryKey.SetValue('PATH', $NewPathValue, $PathValueKind)
        }
        $win32RegistryKey.Handle.Close()
        Write-Debug "$fxn ✅ Added Path:Variable `"$Name`"."
      } catch [System.UnauthorizedAccessException] {
        throw (New-Object -TypeName 'System.Security.SecurityException' -ArgumentList 'Cannot write to the registry key')
      }
    } else {
      try {
        if ([Bool][System.Environment]::GetEnvironmentVariable("$Name", "$Scope")) {
          Write-Debug "$fxn [!]  Env:Variable `"$Name`" Already exist. Skipping..."
        } else {
          [System.Environment]::SetEnvironmentVariable($Name, $Value, $Scope);
          Write-Debug "$fxn ✅ Added Env:Variable `"$Name`"."
        }
      } catch {
        Write-Info "[INFO] : $fxn Encountered an unexpected sittuation`n"
        Write-Debug "$fxn [!]  Error: $($Error[0]) ($($MyInvocation.MyCommand.Name):$($_.InvocationInfo.ScriptLineNumber))"
        # This Will most likely catch [System.Management.Automation.MethodException]
        # ($Scope -eq $([System.EnvironmentVariableTarget]::Process)) -or ($null -eq $Value) -or ($Value -eq '')
      }
    }
    if ($hive_is_connected) {
      if ($PSCmdlet.ShouldProcess('HKLM\DEFAULT', 'reg unload')) { $result = reg unload "HKLM\DEFAULT" *>&1 }
    }
    #region    make_everything_refresh
    try { Update-SessionEnv }catch {
      Write-Info "[INFO] : $fxn Failed while refreshing Environment Objects and settings.`n$($_.Exception.Message)"
    }
    #endregion make_everything_refresh
    # _todo_  Update_SessionEnvironment
    # Set a user environment variable making the system refresh
    $setx.exe = "$($env:SystemRoot)\System32\setx.exe"
    if ($PSCmdlet.ShouldProcess('EnvLastPathUpdate', "$setx")) {
      & "$setx"EnvLastPathUpdate `"$((Get-Date).ToFileTime())`" | Out-Null
    }
    Write-Debug "$fxn 🤖 Updated `$env:EnvLastPathUpdate"
    if ($OutFile) {
      [dotEnv]::Update($OutFile, $Name, $Value)
    }
  }

  end {
    [System.GC]::Collect()
    $ErrorActionPreference = $eap;
    $InformationPreference = $Ifp;
  }
}