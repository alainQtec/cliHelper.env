function Add-Env {
  # .DESCRIPTION
  #     Saves an environment variable.
  # .EXAMPLE
  #     Set-Env -Name 'testvar' -Value '009'
  # .EXAMPLE
  #     Add-Env -Name 'path' -scope 'Machine' -value $rscriptPath
  # .NOTES
  #     **NOTE:** Administrative Access Required when using `-Scope 'Machine'.`  On windows
  #     You can check in C:\Windows\System32\SystemPropertiesAdvanced.exe to see if it took effect.
  # .LINK
  #     https://github.com/alainQtec/dotEnv/Public/Add-Env.ps1
  #
  [CmdletBinding(SupportsShouldProcess = $true, DefaultParameterSetName = 'session')]
  [OutputType([void])]
  [Alias('Set-Env')]
  param (
    [Parameter(Mandatory = $true, Position = 0, ParameterSetName = 'session')]
    [ValidateNotNullOrWhiteSpace()]
    [string]$Name,

    [Parameter(Mandatory = $true, Position = 0, ParameterSetName = 'fromfile')]
    [ValidateNotNullOrEmpty()]
    [IO.FileInfo]$source,

    [parameter(Mandatory = $false, Position = 1, ParameterSetName = 'session')]
    [AllowEmptyString()]
    [AllowNull()]
    [string]$Value,

    [Parameter(Mandatory = $false, Position = 2, ParameterSetName = '__AllparameterSets')]
    [System.EnvironmentVariableTarget]$Scope = "Process",

    [Parameter(Mandatory = $false, Position = 3, ParameterSetName = '__AllParameterSets')]
    [ValidateNotNullOrWhiteSpace()]
    [string]$OutFile
  )

  begin {
    [System.Management.Automation.ActionPreference]$eap = $ErrorActionPreference; $ErrorActionPreference = "SilentlyContinue"
    [System.Management.Automation.ActionPreference]$Ifp = $InformationPreference; $InformationPreference = "Continue"
    if ([dotEnv]::GetHostOs() -eq "Windows" -and ![dotEnv]::IsAdmin()) {
      Write-Warning "$fxn [!]  It seems You're not Admin"
      # exit
    }
  }

  process {
    if ($PSCmdlet.ParameterSetName -eq "fromfile") {
      [dotEnv]::Read($source.FullName).ForEach({
          if ($PSCmdlet.ShouldProcess("$Name@$Scope", "SetEnvironmentVariable")) {
            [dotEnv]::SetEnvironmentVariable($_.Name, $_.Value, $Scope)
          }
        }
      )
    } else {
      if ($PSCmdlet.ShouldProcess("$Name@$Scope", "SetEnvironmentVariable")) {
        [dotEnv]::SetEnvironmentVariable($Name, $Value, $Scope)
      }
    }
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