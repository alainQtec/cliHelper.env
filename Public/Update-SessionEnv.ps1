function Update-SessionEnv {
  <#
    .SYNOPSIS
        A method to refresh session environment variables without having to reboot, restart the terminal or restart Explorer.exe
    .DESCRIPTION
        When a package setup runs on Windows, the author of the package may add or update environment variables
        that affect how the program operates or is accessed. These modifications are frequently invisible
        to the current PowerShell session. This means that the user must launch a new PowerShell session before these settings take effect,
        which may leave the installed application inoperable until then.

        This function is useful for quickly refreshing the desktop, taskbar, icons, wallpaper, files, environmental variables and visual effects. (Thats the goal.)
        Example: You can Update environment variables in your current PowerShell session without restarting it.
        It uses a Win32 API to notify the system of any events that affect the shell and then flushes the system event buffer.
        It also posts a message that simulates an F5 keyboard input.
        The method does not issue an Explorer process restart because the system event buffer is flushed in the running environment using the Win32 API.
        It also refreshes system objects, like changed or modified registry keys, that normally require a system reboot.
    .INPUTS
        None
    .OUTPUTS
        None
    .NOTES
        This function was written specifically for Windows; it does not throw errors on other platforms, but it is not required.
    .EXAMPLE
        # Load the latest script
        . ([scriptblock]::Create((Invoke-RestMethod -Verbose:$false -Method Get https://api.github.com/gists/8b4ddc0302a9262cf7fc25e919227a2f).files.'Update_Session_Env.ps1'.content))
        Update-SessionEnv
    .LINK
        https://gist.github.com/alainQtec/8b4ddc0302a9262cf7fc25e919227a2f
  #>
  [CmdletBinding(SupportsShouldProcess)]
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
    $fxn = ('[' + $MyInvocation.MyCommand.Name + ']')
    $q = [char]34 # quote (Used to avoid escape chars)
    $nl = $([Environment]::NewLine)
    $IsLinuxEnv = (Get-Variable -Name "IsLinux" -ErrorAction Ignore) -and $IsLinux
    $IsMacOSEnv = (Get-Variable -Name "IsMacOS" -ErrorAction Ignore) -and $IsMacOS
    $IsWinEnv = !$IsLinuxEnv -and !$IsMacOSEnv
    [bool]$IsAdmin = $false
    if ($IsWinEnv) {
      Write-Warning "$fxn : [!]  This function only works on windows [!] "
      [bool]$IsAdmin = $((New-Object Security.Principal.WindowsPrincipal $([Security.Principal.WindowsIdentity]::GetCurrent())).IsInRole([Security.Principal.WindowsBuiltinRole]::Administrator));
    } elseif ($IsLinuxEnv) {
      # [ $(id -u) = 0 ] && echo "User is root" || echo "User is not root"
      # lets just assume ;}
      [bool]$IsAdmin = $true
    } elseif ($IsMacOSEnv) {
      # idk how to solve this one!
      [bool]$IsAdmin = $true
    }
    if ($IsWinEnv -and !$IsAdmin) {
      Write-Warning "$fxn : [!]  It seems You're not Admin [!] "
      break
    }
    if ($AddtoContextMenu -and $RemovefromContextMenu) {
      Write-Warning "$fxn : [!]  Your ContextMenu Parameters do Not make any sense! [!]  $nl🤖 Fixing them ..."
      $AddtoContextMenu = $false
      $RemovefromContextMenu = $true
    }
    $j_ = $([IO.Path]::PathSeparator)
    New-Variable -Name 'refresh' -Visibility Public -Value $([scriptblock]::Create({
          try {
            # Get all environment variables for the current "Process, System and User".
            $env_vars = [PSCustomObject]@{
              Process = [Environment]::GetEnvironmentVariables('Process')
              Machine = [Environment]::GetEnvironmentVariables('Machine')
              User    = [Environment]::GetEnvironmentVariables('User')
            }
            # Identify the entire list of environment variable names first
            $vNames = ($env_vars.Machine.Keys + $env_vars.User.Keys + $env_vars.Process.Keys + 'PSModulePath') | Sort-Object | Select-Object -Unique
            foreach ($var in $vNames) {
              $pieces = @()
              if ($IsWinEnv) {
                if ($var -eq "PSModulePath") {
                  if ($IsWinEnv -and $PSVersionTable.psversion -ge [System.Version]("4.0.0.0")) {
                    $pieces += [System.IO.Path]::Combine(${env:ProgramFiles}, 'WindowsPowerShell', 'Modules')
                  }
                  if (!($env_vars.User.ContainsKey($var))) {
                    $pieces += [System.IO.Path]::Combine($([environment]::GetFolderPath('MyDocuments')), 'WindowsPowerShell', 'Modules')
                  } else {
                    $pieces += $env_vars.User.$var -split "$j_"
                  }
                  if ($env_vars.Machine.ContainsKey($var)) {
                    $pieces += $env_vars.Machine.$var -split "$j_"
                  }
                } elseif ($var -eq "PATH") {
                  if ($env_vars.User.ContainsKey($var)) {
                    $pieces += $env_vars.User.$var -split "$j_"
                  }
                  if ($env_vars.Machine.ContainsKey($var)) {
                    $pieces += $env_vars.Machine.$var -split "$j_"
                  }
                }
                if ($env_vars.User.ContainsKey($var)) {
                  if ($PSCmdlet.ShouldProcess("$fxn [Refresh] Updating User variable $var in Process scope ✅", "$var", "SetEnvironmentVariable")) {
                    $([scriptblock]::Create("[Environment]::SetEnvironmentVariable('$var', '$($env_vars.User.$var)', 'Process')")).Invoke();
                  }
                } elseif ($env_vars.Machine.ContainsKey($var)) {
                  if ($PSCmdlet.ShouldProcess("$fxn [Refresh] Updating Machine variable $var in Process scope ✅", "$var", "SetEnvironmentVariable")) {
                    $([scriptblock]::Create("[Environment]::SetEnvironmentVariable('$var', '$($env_vars.Machine.$var)', 'Process')")).Invoke()
                  }
                } else {
                  Write-Verbose "$fxn [Refresh] No variable to update, 🤖 Moving on"
                }
              } else {
                if ($var -eq 'PSModulePath' -and !$env_vars.Process.ContainsKey($var)) {
                  $pieces += [IO.Path]::Combine(($profile | Split-Path), 'Modules')
                } elseif ($var -eq "PATH") {
                  if ($env_vars.Process.ContainsKey($var)) {
                    $pieces += $env_vars.Process.$var -split "$j_"
                  }
                }
              }
              if ($PSCmdlet.ShouldProcess("$fxn [Refresh] Updating $var variable in Process scope ✅", "$var", "SetEnvironmentVariable") -and $pieces.count -gt 0) {
                $([scriptblock]::Create("[Environment]::SetEnvironmentVariable('$var', '$($pieces -join $j_)', 'Process')")).Invoke();
              }
            }
            # Add all necessary namespaces
            [System.Management.Automation.ActionPreference]$DbP2 = $DebugPreference; $DebugPreference = 'SilentlyContinue' # turn off debugg for a while. (prevents spiting out all the C# code)
            if ($IsWinEnv) {
              $IsnmLoaded = [bool]("win32.nativemethods" -as [type])
              $IswxLoaded = [bool]("Win32API.Explorer" -as [type])
              if (!$IsnmLoaded -or !$IswxLoaded) { Write-Host "[INFO] " -NoNewline -ForegroundColor Green; Write-Host "$fxn ⏳ Loading required namespaces ..."; [Console]::Write($nl) }
              if (!$IsnmLoaded) {
                Add-Type -Namespace Win32 -Name NativeMethods -MemberDefinition '[DllImport("user32.dll", SetLastError = true, CharSet = CharSet.Auto)] public static extern IntPtr SendMessageTimeout(IntPtr hWnd, uint Msg, UIntPtr wParam, string lParam, uint fuFlags, uint uTimeout, out UIntPtr lpdwResult);'
              }
              if (!$IswxLoaded) {
                Add-Type 'using System; using System.Runtime.InteropServices; namespace Win32API { public class Explorer { private static readonly IntPtr HWND_BROADCAST = new IntPtr (0xffff); private static readonly IntPtr HWND_KEYBOARD = new IntPtr (65535); private static readonly UIntPtr WM_USER = new UIntPtr (41504); private const Int32 WM_SETTINGCHANGE = 0x1a; private const Int32 SMTO_ABORTIFHUNG = 0x0002; private const Int32 VK_F5 = 273; [DllImport ("shell32.dll", CharSet = CharSet.Auto, SetLastError = false)] private static extern Int32 SHChangeNotify (Int32 eventId, Int32 flags, IntPtr item1, IntPtr item2); [DllImport ("user32.dll", CharSet = CharSet.Auto, SetLastError = false)] private static extern IntPtr SendMessageTimeout (IntPtr hWnd, Int32 Msg, IntPtr wParam, String lParam, Int32 fuFlags, Int32 uTimeout, IntPtr lpdwResult); [DllImport ("user32.dll", CharSet = CharSet.Auto, SetLastError = false)] static extern bool SendNotifyMessage (IntPtr hWnd, UInt32 Msg, IntPtr wParam, String lParam); [DllImport ("user32.dll", CharSet = CharSet.Auto, SetLastError = false)] private static extern Int32 PostMessage (IntPtr hWnd, UInt32 Msg, UIntPtr wParam, IntPtr lParam); public static void RefreshEnvironment () { SHChangeNotify (0x8000000, 0x1000, IntPtr.Zero, IntPtr.Zero); SendMessageTimeout (HWND_BROADCAST, WM_SETTINGCHANGE, IntPtr.Zero, "Environment", SMTO_ABORTIFHUNG, 100, IntPtr.Zero); SendNotifyMessage (HWND_BROADCAST, WM_SETTINGCHANGE, IntPtr.Zero, "TraySettings"); } public static void RefreshShell () { PostMessage (HWND_KEYBOARD, VK_F5, WM_USER, IntPtr.Zero);}}}'
              } # Tiddy and updated version lives here: https://gist.github.com/alainQtec/e75089c849ccf5b02d0d1cfa6618fc3a/raw/2cdac0da416ea9f25a2e273d445c6a2d725bc6b7/Win32API.Explorer.cs
              $DebugPreference = $DbP2
              # Refresh all objects using Win32API. ie: sometimes explorer.exe just doesn't get the message that things were updated.
              $HWND_BROADCAST = [intptr]0xffff;
              $WM_SETTINGCHANGE = 0x1a;
              # RefreshEnvironment, RefreshShell and Notify all windows of environment block change
              $result = [uintptr]::zero;
              [Win32API.Explorer]::RefreshEnvironment();
              [Win32API.Explorer]::RefreshShell();
              [void][win32.nativemethods]::SendMessageTimeout($HWND_BROADCAST, $WM_SETTINGCHANGE, [uintptr]::Zero, "Environment", 2, 5000, [ref]$result);
            }
            [string[]]$valid_levels = [Enum]::GetNames([EnvironmentVariableTarget])
            [int]$c = 0
            [int]$t = $valid_levels.Count
            [Console]::Write($nl)
            foreach ($level in $valid_levels) {
              Write-Host "[INFO] " -NoNewline -ForegroundColor Green; Write-Host "$fxn [Refresh]  $c/$t Cleanning obsolete variabls in [$level] scope ..."
              foreach ($var_Name in $($env_vars.$level.Keys | Where-Object { $vNames -notcontains $_ })) {
                if ($PSCmdlet.ShouldProcess("$fxn [Refresh] Cleanning Env:Variable $var_Name in $level scope.", "$var_Name", "SetEnvironmentVariable")) {
                  $([scriptblock]::Create("[System.Environment]::SetEnvironmentVariable('$var_Name', `$null, [System.EnvironmentVariableTarget]::$level)")).Invoke();
                }
                if ($null -ne ${env:var_Name}) { Remove-Item -LiteralPath "${env:var_Name}" -Force -ErrorAction SilentlyContinue | Out-Null }
              }
              Write-Host "[INFO] " -NoNewline -ForegroundColor Green; Write-Host "$fxn [Refresh]  $c/$t Updating PATH variables in [$level] scope ..."
              $env_vars.$level.GetEnumerator() | ForEach-Object { if ($_.Name -match 'Path$') {
                  $_.Value = $(((Get-Content "Env:$($_.Name)") + "$j_$($_.Value)") -split $j_ | Select-Object -Unique) -join $j_
                  if ($PSCmdlet.ShouldProcess("$fxn [Refresh] Updating Env:Variable $($_.Name) in [$level] scope.", "$($_.Name)", "SetEnvironmentVariable")) {
                    $([scriptblock]::Create("[System.Environment]::SetEnvironmentVariable('$($_.Name)', '$($_.Value)', [System.EnvironmentVariableTarget]::$level)")).Invoke();
                  }
                }
              }
              $c++
              [Console]::Write($nl)
            }
          } catch {
            Write-Host "$fxn [!]  Unexpected Error while runung refreshScript."
            Write-Error $_.Exception -ErrorAction Continue # SHOULD LOG THIS
            Write-Host "$fxn [!]  [Mitigation] Using the Old 'Quick-refresh' method. (Still not reliable, but its better than just exiting without taking any action.) :"
            #Ordering is important here, $user comes after so we can override $machine
            foreach ($sc in @('Machine', 'Process', 'User')) {
              Write-Verbose "$fxn [Mitigation] [Refresh] ---------------- Refreshing $sc variables ..."
              $env_vars.$sc.Keys | ForEach-Object {
                $key = $_ ; $value = $env_vars.$sc[$key]
                if ($PSCmdlet.ShouldProcess("env:$key", "Set-Item")) {
                  Set-Item -Path "Env:$key" -Value $value
                }
              }
            }
            Write-Verbose "$fxn [Mitigation] [Refresh] ---------------- Refreshing PATH"
            $paths = 'Machine', 'User' | ForEach-Object { $([Environment]::GetEnvironmentVariable("PATH", "$_")) -split $j_ } | Select-Object -Unique
            $Env:PATH = $paths -join $j_
          }
        }
      )
    )
    New-Variable -Name 'CreateNewObjRefreshEnv' -Visibility Public -Value $([scriptblock]::Create({
          try {
            $TempFile = if ($null -eq (Get-Command New-TempFile -ErrorAction SilentlyContinue)) {
              $Fl = New-TemporaryFile; $rF = [System.IO.Path]::ChangeExtension($Fl.FullName, 'ps1'); [System.IO.File]::Move($Fl.FullName, $rF); Get-Item $rf
            } else {
              New-TempFile -Pref Refresh- -Ext ps1;
            }
            $((Get-Command -CommandType Function -Name $MyInvocation.MyCommand.Name).ScriptBlock) | Set-Content -Path $TempFile
            $([scriptblock]::Create("[System.Environment]::SetEnvironmentVariable('ObjectsRefreshScript', '$($TempFile.FullName)', [System.EnvironmentVariableTarget]::Process)")).Invoke();
            $([scriptblock]::Create("[System.Environment]::SetEnvironmentVariable('ObjectsRefreshScript', '$($TempFile.FullName)', [System.EnvironmentVariableTarget]::User)")).Invoke();
            Write-Verbose "$fxn 🤖 Updated refreshscript to $($TempFile.FullName)"
          } catch {
            Write-Verbose "$fxn [!]  Error while Setting Env:ObjectsRefreshScript to $TempFile"; [Console]::Write($nl)
            Write-Error $_.Exception
          }
        }
      )
    )
  }

  process {
    try {
      Write-Host "[INFO] " -NoNewline -ForegroundColor Green; Write-Host "$fxn Refreshing ..."; [Console]::Write($nl)
      Invoke-Command -ScriptBlock $refresh -ErrorAction Stop
      Write-Host "[INFO] " -NoNewline -ForegroundColor Green; Write-Host "$fxn [Refresh] Done Now everything should be refreshed."
    } catch {
      Write-Verbose "$fxn [!]  Unexpected Error while refreshing env:variables."; [Console]::Write($nl)
      Write-Error $_.Exception -ErrorAction Continue
    }
    try {
      if (![IO.File]::Exists($env:ObjectsRefreshScript)) {
        Write-Host "[INFO] " -NoNewline -ForegroundColor Green; Write-Host "$fxn ObjectsRefreshScript does not exist; 🤖 Creating new one ..."
        Invoke-Command -ScriptBlock $CreateNewObjRefreshEnv -ErrorAction Stop
        Write-Host "[INFO] " -NoNewline -ForegroundColor Green; Write-Host "$fxn Done."
        Write-Host "[INFO] " -NoNewline -ForegroundColor Green; Write-Host "$fxn Refreshing (again) ..."; [Console]::Write($nl)
        Invoke-Command -ScriptBlock $refresh -ErrorAction Stop
        Write-Host "[INFO] " -NoNewline -ForegroundColor Green; Write-Host "$fxn [Refresh] Done Now everything should be refreshed."
      }
      if ($IsWinEnv -and $AddtoContextMenu) {
        $reg_path = 'HKLM:\SOFTWARE\Classes\DesktopBackground\shell\Refresh Explorer'
        $kmd_Path = $(Join-Path $reg_path -ChildPath command)
        if (!$(Test-Path $reg_path -ErrorAction SilentlyContinue)) {
          if ($PSCmdlet.ShouldProcess("$kmd_Path", "New-Item")) {
            New-Item -Path $kmd_Path -ItemType Directory -Force | Out-Null
          }
        }
        if ($PSCmdlet.ShouldProcess("$reg_path and $kmd_Path", "New-ItemProperty")) {
          New-ItemProperty -Path $reg_path -Name 'Icon' -Value 'Explorer.exe' -PropertyType String -Force | Out-Null
          New-ItemProperty -Path $reg_path -Name 'Position' -Value 'Bottom' -PropertyType String -Force | Out-Null
          New-ItemProperty -Path $kmd_Path -Name '(default)' -Value "Powershell.exe -NoLogo -WindowStyle Hidden -NoProfile -NonInteractive -ExecutionPolicy Bypass -File $q$env:ObjectsRefreshScript$q" -PropertyType String -Force | Out-Null
        }
      }
      if ($IsWinEnv -and $RemovefromContextMenu) {
        Write-Verbose "$fxn ⏳ Removing Registry Keys.."
        if ($PSCmdlet.ShouldProcess("$reg_path", "Remove-Item")) {
          Remove-Item -Path $reg_path -Recurse -Force -ErrorAction SilentlyContinue
        }
        Remove-Item $env:ObjectsRefreshScript -Force -ErrorAction SilentlyContinue
        if ($PSCmdlet.ShouldProcess("ObjectsRefreshScript", "SetEnvironmentVariable")) {
          $([scriptblock]::Create("[System.Environment]::SetEnvironmentVariable('ObjectsRefreshScript', `$null, [System.EnvironmentVariableTarget]::Process)")).Invoke()
          $([scriptblock]::Create("[System.Environment]::SetEnvironmentVariable('ObjectsRefreshScript', `$null, [System.EnvironmentVariableTarget]::User)")).Invoke()
        }
      }
    } catch {
      Write-Verbose "$fxn [!]  Unexpected Error while fixing Contextmenu Registry:"; [Console]::Write($nl)
      Write-Error $_.Exception -ErrorAction Continue
    }
  }

  end {
    $ErrorActionPreference = $eap;
    $InformationPreference = $Ifp;
    $DebugPreference = $DbP
    Write-Host "[INFO] " -NoNewline -ForegroundColor Green; Write-Host "$fxn Complete."
  }
}