function Remove-Env {
  # .SYNOPSIS
  #   Removes a persistent environment variable.
  # .DESCRIPTION
  #   Removes an environment variable
  #   with the specified name and value. The variable can be scoped either to
  #   the User or to the Machine.
  # .EXAMPLE
  #   >
  #   Remove-Env -Name 'bob' -VariableType 'Machine'
  [CmdletBinding(SupportsShouldProcess = $true)]
  param(
    [parameter(Mandatory = $true, Position = 0)]
    [string]$Name,

    [parameter(Mandatory = $false, Position = 1)]
    [System.EnvironmentVariableTarget]$Scope = "Process"
  )

  process {
    if ($PSCmdlet.ShouldProcess("Target", "Operation")) {
      Add-Env -Name $Name -Value $null -Scope $Scope -Force
      # Set-Content Env:/$Name $null
    }
  }
}