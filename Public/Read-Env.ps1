function Read-Env {
  <#
  .SYNOPSIS
    Reads environment Variable(s) from a .env file.
  .DESCRIPTION
    Same as: Get-Env -FromFilesOnly
  .LINK
    Specify a URI to a help page, this will show when Get-Help -Online is used.
  .EXAMPLE
    Read-Env ./.env
  #>
  [CmdletBinding(DefaultParameterSetName = "path")]
  param (
    [Parameter(Mandatory = $true, Position = 0, ParameterSetName = 'path')]
    [ValidateNotNullOrEmpty()]
    [string]$Path,
    [Parameter(Mandatory = $true, Position = 0, ParameterSetName = 'file')]
    [ValidateNotNullOrEmpty()]
    [IO.FileInfo]$source
  )
  end {
    if ($PSCmdlet.ParameterSetName -eq "path") {
      return Get-Env -FromFilesOnly -source ([IO.FileInfo]::new($source))
    }
    return Get-Env -FromFilesOnly -source $source
  }
}