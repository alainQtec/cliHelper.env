function Update-SessionEnv {

  # .SYNOPSIS
  #   A method to refresh session environment variables without having to reboot, restart the terminal or restart Explorer.exe
  # .DESCRIPTION
  #   When a package setup runs on Windows, the author of the package may add or update environment variables
  #   that affect how the program operates or is accessed. These modifications are frequently invisible
  #   to the current PowerShell session. This means that the user must launch a new PowerShell session before these settings take effect,
  #   which may leave the installed application inoperable until then.
  #   This function is useful for quickly refreshing the desktop, taskbar, icons, wallpaper, files, environmental variables and visual effects. (Thats the goal.)
  #   Example: You can Update environment variables in your current PowerShell session without restarting it.
  #   It uses a Win32 API to notify the system of any events that affect the shell and then flushes the system event buffer.
  #   It also posts a message that simulates an F5 keyboard input.
  #   The method does not issue an Explorer process restart because the system event buffer is flushed in the running environment using the Win32 API.
  #   It also refreshes system objects, like changed or modified registry keys, that normally require a system reboot.
  # .INPUTS
  #   None
  # .OUTPUTS
  #   None
  # .NOTES
  #   This function was written specifically for Windows; it does not throw errors on other platforms, but it is not required.
  # .EXAMPLE
  #   # Load the latest script
  #   . ([scriptblock]::Create((Invoke-RestMethod -Verbose:$false -Method Get https://api.github.com/gists/8b4ddc0302a9262cf7fc25e919227a2f).files.'Update_Session_Env.ps1'.content))
  #   Update-SessionEnv
  # .LINK
  #   https://github.com/alainQtec/dotEnv/public/Update-SessionEnv.ps1
  #
  [CmdletBinding(SupportsShouldProcess = $true)]
  [Alias('refreshEnv')]
  param (
    # Adds to Context Menu the shortcut to refresh Explorer
    [Parameter(Mandatory = $false, ValueFromPipeline = $false)]
    [switch]$AddtoContextMenu,
    # Removes from Context Menu the shortcut to refresh Explorer
    [Parameter(Mandatory = $false, ValueFromPipeline = $false)]
    [switch]$RemovefromContextMenu
  )

  begin {
    [System.Management.Automation.ActionPreference]$eap = $ErrorActionPreference; $ErrorActionPreference = "SilentlyContinue"
    [System.Management.Automation.ActionPreference]$DbP = $DebugPreference; $DebugPreference = 'Continue'
    [System.Management.Automation.ActionPreference]$Ifp = $InformationPreference; $InformationPreference = "Continue"
  }

  process {
    if ($PSCmdlet.ShouldProcess("Localhost", "refreshEnv")) {
      if ($AddtoContextMenu -or $RemovefromContextMenu) {
        [dotEnv]::refreshEnv([ctxOption]([int]!$AddtoContextMenu * [int]!$RemovefromContextMenu))
      } else {
        [dotEnv]::refreshEnv([ctxOption]::None)
      }
    }
  }

  end {
    $ErrorActionPreference = $eap;
    $InformationPreference = $Ifp;
    $DebugPreference = $DbP
  }
}