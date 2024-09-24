function Set-EnvFile {
  # .SYNOPSIS
  #   sets .env Path
  # .EXAMPLE
  #   Set-EnvFile .env
  [CmdletBinding(SupportsShouldProcess = $true)]
  param (
    [Parameter(Position = 0, Mandatory = $false, ValueFromPipeline = $true)]
    [string]$Path = "./.env",
    [switch]$PassThru
  )

  process {
    $p = Get-Item $Path -Force
    if ($p.Exists) {
      if ($PSCmdlet.ShouldProcess("$path", "SetEnvPath")) {
        [dotEnv]::Config.SetEnvPath($p.FullName)
      }
    } else {
      Write-Error "File not found: $Path"
    }
  }
  end {
    if ($PassThru) {
      return [dotEnv]::Config.EnvFile
    }
  }
}