function Read-Env {
  # .SYNOPSIS
  #   Reads environment Variable(s) from a .env file.
  # .LINK
  #   https://github.com/alainQtec/cliHelper.env/Public/Read-Env.ps1
  # .EXAMPLE
  #   Read-Env ./.env
  # .EXAMPLE
  #   Read-Env | Set-Env
  [CmdletBinding(DefaultParameterSetName = "path")]
  param (
    [Parameter(Mandatory = $false, Position = 0, ParameterSetName = 'path')]
    [ValidateNotNullOrEmpty()]
    [string]$Path = [dotenv].EnvFile,
    [Parameter(Mandatory = $false, Position = 0, ParameterSetName = 'file')]
    [ValidateNotNullOrEmpty()]
    [IO.FileInfo]$File = [IO.FileInfo][dotenv].EnvFile
  )
  end {
    if ($PSCmdlet.ParameterSetName -eq "path") {
      return [dotenv]::Read($Path)
    }
    return [dotenv]::Read($File.FullName)
  }
}