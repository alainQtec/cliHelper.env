function Get-Env {
  # .SYNOPSIS
  #   Gets an Environment Variable.
  # .DESCRIPTION
  #   This will will get an environment variable based on the variable name and scope.
  # .PARAMETER Name
  #   The environment variable you want to get the value from.
  # .PARAMETER source
  #   .env file path from which to read variables.
  # .PARAMETER Scope
  #   The environment variable target scope. This is `Process`, `User`, or `Machine`.
  # .EXAMPLE
  #   Get-Env *User_Id* -source ./.env
  #   > Name                                       Value
  #     ----                                       -----
  #     NEXT_PUBLIC_MTN_API_COLLECTION_USER_ID     lorem331acb
  #     NEXT_PUBLIC_MTN_API_DISBURSEMENT_USER_ID   ipsum110102
  #
  #   Reads all env variables from .env file and only returns those with User_Id in their name
  # .EXAMPLE
  #   Get-Env '*DISPLAY*' -Scope Process
  #   > Name                       Value
  #     ----                       -----
  #     DISPLAY                    :1
  #     ELM_DISPLAY                wl
  #     WAYLAND_DISPLAY            wayland-1
  #   Reads all env variables from Process scope and only returns those with DISPLAY in their name
  # .LINK
  #   https://github.com/alainQtec/dotEnv/Public/Get-Env.ps1
  [CmdletBinding(DefaultParameterSetName = 'session')]
  [OutputType([dotEntry[]])]
  param(
    [Parameter(Mandatory = $false, Position = 0, ParameterSetName = '__AllparameterSets')]
    [ValidateNotNullOrWhiteSpace()]
    [string]$Name = "*",

    [Parameter(Mandatory = $true, Position = 1, ParameterSetName = 'file')]
    [ValidateNotNullOrEmpty()]
    [string]$source,

    [Parameter(Mandatory = $false, Position = 1, ParameterSetName = 'session')]
    [System.EnvironmentVariableTarget]$Scope = 'Process',

    [Parameter(Mandatory = $false, ParameterSetName = 'file')]
    [switch]$Persist,

    [Parameter(Mandatory = $false, ParameterSetName = '__AllparameterSets')]
    [switch]$Force
  )

  begin {
    $PsCmdlet.MyInvocation.BoundParameters.GetEnumerator() | ForEach-Object { Set-Variable -Name $_.Key -Value $_.Value -ea 'SilentlyContinue' }
    if (!$source -and $Force.IsPresent) { $source = (Set-EnvFile -PassThru).FullName }
    $results = @()
  }

  Process {
    $fromFile = $PSCmdlet.ParameterSetName -eq "file"
    $vars = $(if ($fromFile) {
        $isp = [dotEnv]::IsPersisted(((Resolve-Path $source -ea Ignore).Path))
        $inc = [IO.File]::Exists([dotEnv]::Config.fallBack)
        if (($inc -and !$isp) -or ($isp -and $Force)) {
          [dotEnv]::Read($source)
        } else {
          [dotEnv]::vars.Process
        }
      } else {
        [dotEnv]::vars
      }
    )
    if (!$fromFile) {
      $vars = $(if ($PSBoundParameters.ContainsKey('scope')) {
          $vars.$scope
        } else {
          [enum]::GetNames([EnvironmentVariableTarget]).ForEach({ $vars.$_ })
        }
      )
    }
    if (!$fromFile -and $Force.IsPresent) {
      $nvars = [dotEnv]::Read($source)
      if ($nvars.count -gt 0) {
        $vars += $nvars; Set-Env -Entries $nvars;
      }
    }
    if ($Persist -and ![dotEnv]::IsPersisted($source)) {
      Set-Env -Entries $vars; [dotEnv]::Persist($source);
    }
    $results = $(if ($Name.Contains('*')) {
        $vars.Where({ $_.Name -like $Name })
      } else {
        $vars.Where({ $_.Name -eq $Name })
      }
    )
  }

  end {
    if (!$results -and !$fromFile) {
      # ie: When not found in scope, so we use (one-time) those from .env file
      if (![IO.File]::Exists([dotEnv]::Config.fallBack)) {
        [dotEnv]::Config.Set("fallBack", (Set-EnvFile -PassThru).FullName)
        $results = Get-Env -Name $Name -Scope $Scope
      } else {
        $results = Get-Env -Name $Name -Source ([dotEnv]::Config.fallBack) -Persist
        [dotEnv]::Config.Remove("fallback")
      }
    }
    return $results
  }
}