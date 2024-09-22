function Write-Env {
  # .SYNOPSIS
  #   same as: Add-Env -outFile
  # .DESCRIPTION
  #   Write environment Variable(s) to a .env file, but does not set it.
  [CmdletBinding(DefaultParameterSetName = "path")]
  param (
    [Parameter(Mandatory = $true, Position = 0, ParameterSetName = 'kv')]
    [ValidateNotNullOrWhiteSpace()]
    [string]$Name,

    [Parameter(Mandatory = $true, Position = 0, ParameterSetName = 'entries')]
    [dotEntry[]]$Entries,

    [Parameter(Mandatory = $true, Position = 2, ParameterSetName = 'kv')]
    [string]$Value,
    [Parameter(Mandatory = $true, Position = 1, ParameterSetName = '__AllparameterSets')]
    [ValidateNotNullOrWhiteSpace()]
    [string]$Path
  )

  end {
    if ($PSCmdlet.ParameterSetName -eq "kv") {
      return [dotEnv]::Update($Path, $Name, $Value)
    } else {
      return [dotEnv]::Update($Entries, $Name, $Value)
    }
  }
}