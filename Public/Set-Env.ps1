function Set-Env {
  # .DESCRIPTION
  #   Adds environment Variable(s) to the session in specified scope, even if they were already set.
  [CmdletBinding(SupportsShouldProcess = $true, DefaultParameterSetName = 'session')]
  param (
    [Parameter(Mandatory = $true, Position = 0, ValueFromPipeline = $true, ValueFromPipelineByPropertyName = $true, ParameterSetName = 'session')]
    [string]$Name,

    [Parameter(Mandatory = $true, Position = 0, ParameterSetName = 'file')]
    [IO.FileInfo]$source,

    [parameter(Mandatory = $false, Position = 1, ValueFromPipeline = $true, ValueFromPipelineByPropertyName = $true, ParameterSetName = 'session')]
    [string]$Value = '',

    [Parameter(Mandatory = $false, Position = 2, ValueFromPipeline = $true, ValueFromPipelineByPropertyName = $true, ParameterSetName = '__AllparameterSets')]
    [Alias('Target', 'variableType', 'Type')]
    [System.EnvironmentVariableTarget]$Scope = "Process",

    # If specified the cmdlet will only Write environment Variable(s) to a .env file.
    [Parameter(Mandatory = $false, ParameterSetName = 'file')]
    [switch]$ToFilesOnly
  )
  process {
    if ($PSCmdlet.ShouldProcess("localhost", "Set Environment variable")) {
      if ($PSCmdlet.ParameterSetName -eq "file") {
        return Add-Env -source $source -ToFilesOnly:$ToFilesOnly.IsPresent -Force
      } else {
        return Add-Env -Name $Name -value $Value -Scope $Scope -Force
      }
    }
  }
}