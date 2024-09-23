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

    [Parameter(Mandatory = $false, Position = 1, ParameterSetName = '__AllparameterSets')]
    [System.EnvironmentVariableTarget]$Scope
  )

  begin {
    $PsCmdlet.MyInvocation.BoundParameters.GetEnumerator() | ForEach-Object { New-Variable -Name $_.Key -Value $_.Value -ea 'SilentlyContinue' }
    $results = $null
  }

  Process {
    $fromFile = $PSCmdlet.ParameterSetName -eq "file"
    $vars = $(if ($fromFile) {
        [dotEnv]::Read($source)
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
    $results = $(if ($Name.Contains('*')) {
        $vars.Where({ $_.Name -like $Name })
      } else {
        $vars.Where({ $_.Name -eq $Name })
      }
    )
  }

  end {
    return $results
  }
}