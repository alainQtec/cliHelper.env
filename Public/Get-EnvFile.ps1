function Get-EnvFile {
  # .SYNOPSIS
  #   gets .env Path
  # .EXAMPLE
  #   Get-EnvFile
  [OutputType([System.IO.FileInfo])]
  param (
    [Parameter(Position = 0, Mandatory = $false, ValueFromPipeline = $true)]
    [string]$Path
  )
  process {
    if ($null -eq [dotenv].EnvFile) {
      [dotenv]::SetEnvFile()
    }
    if ([string]::IsNullOrWhiteSpace($Path)) {
      $Path = [dotenv].EnvFile
    }
    $p = Get-Item $Path -Force -ErrorAction Ignore
    if (!$p.Exists) {
      Write-Error "File not found: $Path"
    }
  }
  end {
    return $Path -as [System.IO.FileInfo]
  }
}