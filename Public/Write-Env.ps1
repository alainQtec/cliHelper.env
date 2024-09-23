function Write-Env {
  # .SYNOPSIS
  #   same as: Add-Env -outFile
  # .DESCRIPTION
  #   Write environment Variable(s) to a .env file, but does not set it.
  [CmdletBinding(DefaultParameterSetName = "path")]
  param (
    [Parameter(Mandatory = $true, Position = 0, ParameterSetName = 'keyvalue')]
    [ValidateNotNullOrWhiteSpace()]
    [string]$Path,

    [Parameter(Mandatory = $true, Position = 1, ParameterSetName = 'keyvalue')]
    [ValidateNotNullOrWhiteSpace()]
    [string]$Name,

    [Parameter(Mandatory = $true, Position = 0, ParameterSetName = 'entries')]
    [dotEntry[]]$Entries,


    [Parameter(Mandatory = $true, Position = 2, ParameterSetName = '__AllparameterSets')]
    [string]$Value
  )

  end {
    if ($PSCmdlet.ParameterSetName -eq "keyvalue") {
      [dotEnv]::Update($Path, $Name, $Value)
    } else {
      $c = [dotEnv]::Update($Entries, $Name, $Value)
      [IO.File]::WriteAllText($Path, ($c.ForEach({ $_.ToString() }) | Out-String).Trim(), [System.Text.Encoding]::UTF8)
    }
  }
}