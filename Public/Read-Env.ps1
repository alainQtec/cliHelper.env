function Read-Env {
  # .SYNOPSIS
  #   Reads environment Variable(s) from a .env file.
  # .LINK
  #   https://github.com/alainQtec/dotEnv/Public/Read-Env.ps1
  # .EXAMPLE
  #   Read-Env ./.env
  # .EXAMPLE
  #   Read-Env | Set-Env
  [CmdletBinding(DefaultParameterSetName = "path")]
  param (
    [Parameter(Mandatory = $false, Position = 0, ParameterSetName = 'path')]
    [ValidateNotNullOrEmpty()]
    [string]$Path = [dotenv]::FindEnvFile().fullname,
    [Parameter(Mandatory = $false, Position = 0, ParameterSetName = 'file')]
    [ValidateNotNullOrEmpty()]
    [IO.FileInfo]$File = [dotenv]::FindEnvFile()
  )
  end {
    if ($PSCmdlet.ParameterSetName -eq "path") {
      return [dotenv]::Read($Path)
    }
    return [dotenv]::Read($File.FullName)
  }
}