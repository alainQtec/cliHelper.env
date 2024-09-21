
enum ctxOption {
  Remove = 0
  Add = 1
  None = 2
}
enum dtActn {
  Assign
  Prefix
  Suffix
}

class dotEntry {
  [string]$Name
  [string]$Value
  hidden [dtActn]$Action
  dotEntry($n, $v, $a) {
    $this.Name = $n; $this.Action = $a; $this.Value = $v
  }
}

class vars {
  [Hashtable]$Process
  [Hashtable]$Machine
  [Hashtable]$User
  vars() {
    $this.Process = [Environment]::GetEnvironmentVariables('Process')
    $this.Machine = [Environment]::GetEnvironmentVariables('Machine')
    $this.User = [Environment]::GetEnvironmentVariables('User')
  }
  [void] Refresh() {
    $j_ = $([IO.Path]::PathSeparator)
    # Identify the entire list of environment variable names first
    try {
      foreach ($var in $this.ToString()) {
        $pieces = @()
        if ([EnvTools]::GetHostOs() -eq "Windows") {
          if ($var -eq "PSModulePath") {
            if ($(Get-Variable PSVersionTable -ValueOnly).psversion -ge [System.Version]("4.0.0.0")) {
              $pieces += [System.IO.Path]::Combine(${env:ProgramFiles}, 'WindowsPowerShell', 'Modules')
            }
            if (!($this.User.ContainsKey($var))) {
              $pieces += [System.IO.Path]::Combine($([environment]::GetFolderPath('MyDocuments')), 'WindowsPowerShell', 'Modules')
            } else {
              $pieces += $this.User.$var -split "$j_"
            }
            if ($this.Machine.ContainsKey($var)) {
              $pieces += $this.Machine.$var -split "$j_"
            }
          } elseif ($var -eq "PATH") {
            if ($this.User.ContainsKey($var)) {
              $pieces += $this.User.$var -split "$j_"
            }
            if ($this.Machine.ContainsKey($var)) {
              $pieces += $this.Machine.$var -split "$j_"
            }
          }
          if ($this.User.ContainsKey($var)) {
            $([scriptblock]::Create("[Environment]::SetEnvironmentVariable('$var', '$($this.User.$var)', 'Process')")).Invoke();
          } elseif ($this.Machine.ContainsKey($var)) {
            $([scriptblock]::Create("[Environment]::SetEnvironmentVariable('$var', '$($this.Machine.$var)', 'Process')")).Invoke()
          } else {
            Write-Verbose "   [Refresh] No variable to update, 🤖 Moving on"
          }
        } else {
          if ($var -eq 'PSModulePath' -and !$this.Process.ContainsKey($var)) {
            $pieces += [IO.Path]::Combine((Get-Variable profile -ValueOnly | Split-Path), 'Modules')
          } elseif ($var -eq "PATH") {
            if ($this.Process.ContainsKey($var)) {
              $pieces += $this.Process.$var -split "$j_"
            }
          }
        }
        Write-Verbose "   [Refresh] $var variable in Process scope ✅"
        $([scriptblock]::Create("[Environment]::SetEnvironmentVariable('$var', '$($pieces -join $j_)', 'Process')")).Invoke();
      }
      # Add all necessary namespaces
      [System.Management.Automation.ActionPreference]$DbP2 = $(Get-Variable DebugPreference -ValueOnly); $DebugPreference = 'SilentlyContinue' # turn off debugg for a while. (prevents spiting out all the C# code)
      if ([EnvTools]::GetHostOs() -eq "Windows") {
        $IsnmLoaded = [bool]("win32.nativemethods" -as [type])
        $IswxLoaded = [bool]("Win32API.Explorer" -as [type])
        if (!$IsnmLoaded -or !$IswxLoaded) { [EnvTools]::Log("⏳ Loading required namespaces ..."); [Console]::WriteLine() }
        if (!$IsnmLoaded) {
          Add-Type -Namespace Win32 -Name NativeMethods -MemberDefinition '[DllImport("user32.dll", SetLastError = true, CharSet = CharSet.Auto)] public static extern IntPtr SendMessageTimeout(IntPtr hWnd, uint Msg, UIntPtr wParam, string lParam, uint fuFlags, uint uTimeout, out UIntPtr lpdwResult);'
        }
        if (!$IswxLoaded) {
          Add-Type 'using System; using System.Runtime.InteropServices; namespace Win32API { public class Explorer { private static readonly IntPtr HWND_BROADCAST = new IntPtr (0xffff); private static readonly IntPtr HWND_KEYBOARD = new IntPtr (65535); private static readonly UIntPtr WM_USER = new UIntPtr (41504); private const Int32 WM_SETTINGCHANGE = 0x1a; private const Int32 SMTO_ABORTIFHUNG = 0x0002; private const Int32 VK_F5 = 273; [DllImport ("shell32.dll", CharSet = CharSet.Auto, SetLastError = false)] private static extern Int32 SHChangeNotify (Int32 eventId, Int32 flags, IntPtr item1, IntPtr item2); [DllImport ("user32.dll", CharSet = CharSet.Auto, SetLastError = false)] private static extern IntPtr SendMessageTimeout (IntPtr hWnd, Int32 Msg, IntPtr wParam, String lParam, Int32 fuFlags, Int32 uTimeout, IntPtr lpdwResult); [DllImport ("user32.dll", CharSet = CharSet.Auto, SetLastError = false)] static extern bool SendNotifyMessage (IntPtr hWnd, UInt32 Msg, IntPtr wParam, String lParam); [DllImport ("user32.dll", CharSet = CharSet.Auto, SetLastError = false)] private static extern Int32 PostMessage (IntPtr hWnd, UInt32 Msg, UIntPtr wParam, IntPtr lParam); public static void RefreshEnvironment () { SHChangeNotify (0x8000000, 0x1000, IntPtr.Zero, IntPtr.Zero); SendMessageTimeout (HWND_BROADCAST, WM_SETTINGCHANGE, IntPtr.Zero, "Environment", SMTO_ABORTIFHUNG, 100, IntPtr.Zero); SendNotifyMessage (HWND_BROADCAST, WM_SETTINGCHANGE, IntPtr.Zero, "TraySettings"); } public static void RefreshShell () { PostMessage (HWND_KEYBOARD, VK_F5, WM_USER, IntPtr.Zero);}}}'
        } # Tiddy and updated version lives here: https://gist.github.com/alainQtec/e75089c849ccf5b02d0d1cfa6618fc3a/raw/2cdac0da416ea9f25a2e273d445c6a2d725bc6b7/Win32API.Explorer.cs
        $DebugPreference = $DbP2
        # Refresh all objects using Win32API. ie: sometimes explorer.exe just doesn't get the message that things were updated.
        # RefreshEnvironment, RefreshShell and Notify all windows of environment block change
        [scriptblock]::Create("[Win32API.Explorer]::RefreshEnvironment(); [Win32API.Explorer]::RefreshShell()").Invoke()
        [scriptblock]::Create("`$HWND_BROADCAST = [intptr]0xffff; `$WM_SETTINGCHANGE = 0x1a; `$result = [uintptr]::zero; [void][win32.nativemethods]::SendMessageTimeout(`$HWND_BROADCAST, `$WM_SETTINGCHANGE, [uintptr]::Zero, 'Environment', 2, 5000, [ref]`$result)").Invoke()
      }
      [int]$c = 0; [string[]]$valid_levels = [Enum]::GetNames([EnvironmentVariableTarget])
      [int]$t = $valid_levels.Count
      [Console]::WriteLine()
      foreach ($level in $valid_levels) {
        [EnvTools]::Log("[Refresh]  $c/$t Cleanning obsolete variabls in [$level] scope ...");
        $obsoletes = $this."$level".Keys.Where({ $this.ToString() -notcontains $_ })
        if ($obsoletes) {
          foreach ($var_Name in $obsoletes) {
            Write-Verbose "   [Refresh] Cleanning Env:Variable $var_Name in $level scope."
            $([scriptblock]::Create("[System.Environment]::SetEnvironmentVariable('$var_Name', `$null, [System.EnvironmentVariableTarget]::$level)")).Invoke();
            if ($null -ne ${env:var_Name}) { Remove-Item -LiteralPath "${env:var_Name}" -Force -ErrorAction SilentlyContinue | Out-Null }
          }
        } else {
          [EnvTools]::Log("[Refresh]      No obsolete variables were found.  ✅");
        }
        $this.$level.Keys.ForEach({ Set-Item -Path "Env:$_" -Value $this.$level[$_] })
        $this.$level.GetEnumerator() | ForEach-Object { if ($_.Name -match '^Path$') {
            $_.Value = $(((Get-Content "env:$($_.Name)") + "$j_$($_.Value)") -split $j_ | Select-Object -Unique) -join $j_
            [EnvTools]::Log("[Refresh]  $c/$t Updating $($_.Name) variables in [$level] scope ...");
            [scriptblock]::Create("[System.Environment]::SetEnvironmentVariable('$($_.Name)', '$($_.Value)', [System.EnvironmentVariableTarget]::$level)").Invoke();
          }
        }
        $c++
        [Console]::WriteLine()
      }
    } catch {
      Write-Host "   [!]  Unexpected Error while runing refreshScript."
      Write-Host "   [!]  [Mitigation] Using the Old 'Quick-refresh' method. (Still not reliable, but its better than just exiting without taking any action.) :"
      Write-Verbose "   [Mitigation] [Refresh] ---------------- Refreshing PATH"
      $paths = 'Machine', 'User' | ForEach-Object { $([Environment]::GetEnvironmentVariable("PATH", "$_")) -split $j_ } | Select-Object -Unique
      $Env:PATH = $paths -join $j_
      throw $_.Exception
    }
  }
  [string[]] ToString() {
    return ($this.Machine.Keys + $this.User.Keys + $this.Process.Keys + 'PSModulePath') | Sort-Object | Select-Object -Unique
  }
}

class EnvTools {
  static [vars] $vars = [vars]::new()
  static [bool] $useverbose = (Get-Variable VerbosePreference -ValueOnly) -eq 'Continue'
  static [void] Log([string]$Message) {
    if ([EnvTools]::useverbose) { Write-Host "🔵 [dotEnv] " -NoNewline; Write-Host $Message -f Cyan }
  }
  static [void] refreshEnv() {
    [EnvTools]::refreshEnv([ctxOption]::None)
  }
  static [void] refreshEnv([ctxOption]$ctxOption) {
    $q = [char]34 # quote (Used to avoid escape chars)
    $hostOS = [EnvTools]::GetHostOs(); $IsWinEnv = $hostOS -eq "Windows"; [bool]$IsAdmin = $false
    if ($hostOS -eq "Windows") {
      Write-Warning "   : [!]  This function only works on windows [!] "
      [bool]$IsAdmin = $((New-Object Security.Principal.WindowsPrincipal $([Security.Principal.WindowsIdentity]::GetCurrent())).IsInRole([Security.Principal.WindowsBuiltinRole]::Administrator));
    } elseif ($hostOS -eq "Linux") {
      # [ $(id -u) = 0 ] && echo "User is root" || echo "User is not root"
      # lets just assume  for now;}
      # TODO: add isadmin implementation
      [bool]$IsAdmin = $true
    } elseif ($hostOS -eq "MacOsx") {
      # TODO: add fix
      Write-Warning "MacOsx !! idk how to solve this one!"
      [bool]$IsAdmin = $true
    }
    if ($hostOS -eq "Windows" -and !$IsAdmin) {
      Write-Warning "   : [!]  It seems You're not Admin [!] "
      break
    }
    # Get all environment variables for the current "Process, System and User".
    try {
      [EnvTools]::Log("Refreshing ..."); [Console]::WriteLine()
      [EnvTools]::vars.Refresh()
      [EnvTools]::Log("[Refresh]  Done Now everything should be refreshed.");
    } catch {
      Write-Verbose "   [!]  Unexpected Error while refreshing env:variables."; [Console]::WriteLine()
      throw $_.Exception
    }
    try {
      if (![IO.File]::Exists($env:ObjectsRefreshScript)) {
        [EnvTools]::Log("ObjectsRefreshScript does not exist; 🤖 Creating new one ...")
        [EnvTools]::CreateObjectsRefreshScript();
        [EnvTools]::Log("Done.");
        [EnvTools]::Log("Refreshing (again💀💀!) 🗿"); [Console]::WriteLine()
        [EnvTools]::vars.Refresh()
        [EnvTools]::Log("[Refresh]  Done Now everything should be refreshed.")
      }
      $reg_path = 'HKLM:\SOFTWARE\Classes\DesktopBackground\shell\Refresh Explorer'
      if ($IsWinEnv -and "$ctxOption" -eq "Add") {
        $kmd_Path = $(Join-Path $reg_path -ChildPath command)
        if (!$(Test-Path $reg_path -ErrorAction SilentlyContinue)) {
          New-Item -Path $kmd_Path -ItemType Directory -Force | Out-Null
        }
        New-ItemProperty -Path $reg_path -Name 'Icon' -Value 'Explorer.exe' -PropertyType String -Force | Out-Null
        New-ItemProperty -Path $reg_path -Name 'Position' -Value 'Bottom' -PropertyType String -Force | Out-Null
        New-ItemProperty -Path $kmd_Path -Name '(default)' -Value "Powershell.exe -NoLogo -WindowStyle Hidden -NoProfile -NonInteractive -ExecutionPolicy Bypass -File $q$env:ObjectsRefreshScript$q" -PropertyType String -Force | Out-Null
      }
      if ($IsWinEnv -and "$ctxOption" -eq "Remove") {
        Write-Verbose "   ⏳ Removing Registry Keys.."
        Remove-Item -Path $reg_path -Recurse -Force -ErrorAction SilentlyContinue
        Remove-Item $env:ObjectsRefreshScript -Force -ErrorAction SilentlyContinue
        [System.Environment]::SetEnvironmentVariable('ObjectsRefreshScript', $null, [System.EnvironmentVariableTarget]::Process)
        [System.Environment]::SetEnvironmentVariable('ObjectsRefreshScript', $null, [System.EnvironmentVariableTarget]::User)
      }
    } catch {
      Write-Verbose "   [!]  Unexpected Error while fixing Contextmenu Registry:"; [Console]::WriteLine()
      throw $_.Exception
    }
  }
  static [void] CreateObjectsRefreshScript() {
    # todo: Fix this method....
    $TempFile = $null; $ThisfnName = $(Get-Variable MyInvocation -ValueOnly).MyCommand.Name
    if ($null -eq $ThisfnName) { return }
    try {
      $Fl = New-TemporaryFile; $rF = [System.IO.Path]::ChangeExtension($Fl.FullName, 'ps1'); [System.IO.File]::Move($Fl.FullName, $rF);
      $TempFile = Get-Item $rf
      $((Get-Command -CommandType Function -Name $MyInvocation.MyCommand.Name).ScriptBlock) | Set-Content -Path $TempFile
      $([scriptblock]::Create("[System.Environment]::SetEnvironmentVariable('ObjectsRefreshScript', '$($TempFile.FullName)', [System.EnvironmentVariableTarget]::Process)")).Invoke();
      $([scriptblock]::Create("[System.Environment]::SetEnvironmentVariable('ObjectsRefreshScript', '$($TempFile.FullName)', [System.EnvironmentVariableTarget]::User)")).Invoke();
      [EnvTools]::Log("🤖 Updated refreshscript to $($TempFile.FullName)");
    } catch {
      Write-Verbose "   [!]  Error while Setting Env:ObjectsRefreshScript to $TempFile"; [Console]::WriteLine()
      throw $_.Exception
    }
  }
  static [string] GetHostOs() {
    return $(if ($(Get-Variable PSVersionTable -Value).PSVersion.Major -le 5 -or $(Get-Variable IsWindows -Value)) { "Windows" }elseif ($(Get-Variable IsLinux -Value)) { "Linux" }elseif ($(Get-Variable IsMacOS -Value)) { "macOS" }else { "UNKNOWN" });
  }
}