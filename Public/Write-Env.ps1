function Write-Env {
  # .SYNOPSIS
  #   same as: Add-Env -ToFilesOnly
  # .DESCRIPTION
  #   Write environment Variable(s) to a .env file, but does not set it.
  [CmdletBinding(DefaultParameterSetName = "path")]
  param (
    [Parameter(Mandatory = $true, Position = 0, ParameterSetName = 'path')]
    [ValidateNotNullOrWhiteSpace()]
    [string]$Path,
    [Parameter(Mandatory = $true, Position = 0, ParameterSetName = 'file')]
    [ValidateNotNullOrEmpty()]
    [IO.FileInfo]$source
  )

  end {
    if ($PSCmdlet.ParameterSetName -eq "path") {
      return Add-Env -ToFilesOnly -source ([IO.FileInfo]::new($source))
    }
    return Add-Env -ToFilesOnly
  }
}