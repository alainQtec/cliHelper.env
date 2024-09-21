#!/usr/bin/env pwsh
using namespace System.Management.Automation.Language
using module Private/dotEnv.Config/dotEnv.Config.psm1
using module Private/dotEnv.Security/dotEnv.Security.psm1

#region    Classes
#Requires -Version 7

enum ctxOption {
  Remove = 0
  Add = 1
  None = 2
}

class dotEntry {
  [string]$Name
  [string]$Value
  [ValidateSet("Prefix", "Suffix", "Assign")][string]$Action
  dotEntry($n, $v, $a) {
    $this.Name = $n; $this.Action = $a; $this.Value = $v
  }
}

# .SYNOPSIS
#  Module main class
# .EXAMPLE
#  $value = [dotEnv]::Get("NEXT_PUBLIC_MTN_API_ENVIRONMENT")
class dotEnv {
  [EnvCfg] $config
  static hidden $X509CertHelper
  [System.Security.Cryptography.X509Certificates.X509Certificate2] $Cert
  static hidden [string]$VarName_Suffix = '7fb2e877_6c2b_406a_af40_e1d915c62cdf'
  static [bool] $useDebug = (Get-Variable DebugPreference -ValueOnly) -eq 'Continue'
  static [ValidateNotNullOrEmpty()][string]$path = [IO.Path]::Combine((Get-Location), ".env")
  # static hidden [ValidateNotNullOrEmpty()][string]$path_Secure = (Resolve-Path ./.env.secure -ea Ignore).Path
  dotEnv() {}
  static [void] Log([string]$Message) {
    if ([dotEnv]::useDebug) { Write-Host "🔵 [dotEnv] " -NoNewline; Write-Host $Message -f Cyan }
  }
  static [string] Get([string]$key) {
    [ValidateNotNullOrEmpty()][string]$key = $key
    return [dotEnv]::Read([dotEnv]::path).Where({ $_.Name -eq $key }).Value
  }
  static [dotEntry[]] Read([string]$EnvFile) {
    [ValidateNotNullOrEmpty()][string]$EnvFile = $EnvFile = $(Resolve-Path $EnvFile -ea Ignore).Path
    $res_Obj = @(); $content = [IO.File]::ReadAllLines($EnvFile)
    if ([string]::IsNullOrWhiteSpace($content)) {
      [dotEnv]::Log("The .env file is empty!");
      return $res_Obj
    }
    foreach ($line in $content) {
      if ([string]::IsNullOrWhiteSpace($line)) { continue }
      if ($line.StartsWith("#") -or $line.StartsWith("//")) {
        [dotEnv]::Log("Skipping comment: $line");
        continue
      }
      ($m, $d ) = switch -Wildcard ($line) {
        "*:=*" { "Prefix", ($line -split ":=", 2); Break }
        "*=:*" { "Suffix", ($line -split "=:", 2); Break }
        "*=*" { "Assign", ($line -split "=", 2); Break }
        Default {
          throw 'Unable to find Key value pair in line'
        }
      }
      $res_Obj += [dotEntry]::new($d[0].Trim(), $d[1].Trim(), $m)
    }
    return $res_Obj
  }
  static [void] Update([string]$EnvFile, [string]$Key, [string]$Value) {
    $content = [dotenv]::Read($EnvFile);
    $q = $content.Where({ $_.Name -eq $Key }); $s = ''
    $sb = [System.Text.StringBuilder]::new([IO.File]::ReadAllText($EnvFile));
    $ms = [PSObject]@{ Assign = '='; Prefix = ":="; Suffix = "=:" };
    if ($q.count -ne 0) {
      $s = $ms[$q.Action]
      $pa = "(?m)^($key{0}).*$" -f $s; $re = "$key{0}$value" -f $s
      $updatedContent = $sb.ToString() -replace $pa, $re
      [IO.File]::WriteAllText($EnvFile, $updatedContent)
    } else {
      throw [System.Exception]::new("key: $Key not found.")
    }
  }

  static [void] Set([string]$EnvFile) {
    [dotEnv]::Set([dotEnv]::Read($EnvFile))
  }
  static [void] Set([dotEntry[]]$Entries) {
    foreach ($item in $Entries) {
      switch ($item.Action) {
        "Assign" {
          [Environment]::SetEnvironmentVariable($item.Name, $item.value, "Process") | Out-Null
        }
        "Prefix" {
          $item.value = "{0};{1}" -f $item.value, [System.Environment]::GetEnvironmentVariable($item.Name)
          [Environment]::SetEnvironmentVariable($item.Name, $item.value, "Process") | Out-Null
        }
        "Suffix" {
          $item.value = "{1};{0}" -f $item.value, [System.Environment]::GetEnvironmentVariable($item.Name)
          [Environment]::SetEnvironmentVariable($item.Name, $item.value, "Process") | Out-Null
        }
        Default {
          throw [System.IO.InvalidDataException]::new()
        }
      }
    }
  }
  static [System.Object[]] RunAsync([scriptBlock]$command, [string]$StatusMsg) {
    # .SYNOPSIS
    #  Run Commands using Background Runspaces Instead of PSJobs For Better Performance
    $Comdresult = $null; [ValidateNotNullOrEmpty()][scriptBlock]$command = $command
    $PsInstance = [System.Management.Automation.PowerShell]::Create().AddScript($command)
    $job = $PsInstance.BeginInvoke();
    do {
      $ProgressPercent = if ([int]$job.TotalTime.TotalMilliseconds -ne 0) { [int]($job.RemainingTime.TotalMilliseconds / $job.TotalTime.TotalMilliseconds * 100) } else { 100 }
      Write-Progress -Activity "[dotEnv]" -Status "$StatusMsg" -PercentComplete $ProgressPercent
      Start-Sleep -Milliseconds 100
    } until ($job.IsCompleted)
    Write-Progress -Activity "[dotEnv]" -Status "command Complete." -PercentComplete 100
    if ($null -ne $PsInstance) {
      $Comdresult = $PsInstance.EndInvoke($job);
      $PsInstance.Dispose(); $PsInstance.Runspace.CloseAsync()
    }
    return $Comdresult
  }
  [guid] GetSessionId() {
    return [dotEnv]::GetSessionId($this)
  }
  static [guid] GetSessionId($HsmVault) {
    # .NOTES
    # - Creates fake guids, that are mainly used to create unique object names with a little bit of info added.
    $hash = $HsmVault.GetHashCode().ToString()
    return [guid]::new([System.BitConverter]::ToString([System.Text.Encoding]::UTF8.GetBytes(([string]::Concat(([char[]](97..102 + 65..70) | Get-Random -Count (16 - $hash.Length))) + $hash))).Replace("-", "").ToLower().Insert(8, "-").Insert(13, "-").Insert(18, "-").Insert(23, "-"))
  }
  static [bool] VerifyGetSessionId([guid]$guid, $HsmVault) {
    return $HsmVault.GetHashCode() -match $([string]::Concat([System.Text.Encoding]::UTF8.GetString($( {
              param([string]$HexString)
              $outputLength = $HexString.Length / 2;
              $output = [byte[]]::new($outputLength);
              $numeral = [char[]]::new(2);
              for ($i = 0; $i -lt $outputLength; $i++) {
                $HexString.CopyTo($i * 2, $numeral, 0, 2);
                $output[$i] = [Convert]::ToByte([string]::new($numeral), 16);
              }
              return $output;
            }.Invoke($guid.ToString().Replace('-', ''))
          )
        ).ToCharArray().Where({ $_ -as [int] -notin (97..102 + 65..70) })
      )
    )
  }
  static [bool] VerifyGetSessionId([string]$guid, $Source) {
    return [dotEnv]::VerifyGetSessionId([guid]$guid, $Source)
  }
  static [void] SetSessionCreds([guid]$sessionId) {
    [dotEnv]::SetSessionCreds([guid]$sessionId, $false)
  }
  static [void] SetSessionCreds([guid]$sessionId, [bool]$Force) {
    if (![string]::IsNullOrWhiteSpace([System.Environment]::GetEnvironmentVariable("$sessionId"))) { if (!$Force) { return } }
    [System.Environment]::SetEnvironmentVariable("$sessionId", $((Get-Credential -Message "Enter your Pfx Password" -Title "-----[[ PFX Password ]]-----" -UserName $env:username).GetNetworkCredential().SecurePassword | ConvertFrom-SecureString), [EnvironmentVariableTarget]::Process)
  }
  static [void] refreshEnv() {
    [dotEnv]::refreshEnv([ctxOption]::Remove)
  }
  static [void] refreshEnv([ctxOption]$ctxOption) {
    # $refrshrVarName = "refrshr_script_$([dotEnv]::VarName_Suffix)";
    # if (!$(Get-Variable $refrshrVarName -ValueOnly -Scope script -ErrorAction Ignore)) {
    #   Set-Variable -Name $refrshrVarName -Scope script -Option ReadOnly -Value ([scriptblock]::Create((Invoke-RestMethod -Verbose:$false -Method Get https://api.github.com/gists/8b4ddc0302a9262cf7fc25e919227a2f).files.'Update_Session_Env.ps1'.content));
    # }
    # $refrshr_script = Get-Variable $refrshrVarName -ValueOnly -Scope script
    # if ($refrshr_script) {
    #   Write-Host '[dotEnv] refreshing this Session Environment ...' -ForegroundColor Green
    #   . $refrshr_script; Update-SessionEnv
    # } else {
    #   throw "Failed to fetch refresher script!"
    # }
    $fxn = ('[' + $MyInvocation.MyCommand.Name + ']')
    $q = [char]34 # quote (Used to avoid escape chars)
    $refresh = $null; $CreateNewObjRefreshEnv = $null;
    $nl = $([Environment]::NewLine); $hostOS = [dotEnv]::GetHostOs(); $IsWinEnv = $hostOS -eq "Windows"; [bool]$IsAdmin = $false
    if ($hostOS -eq "Windows") {
      Write-Warning "$fxn : [!]  This function only works on windows [!] "
      [bool]$IsAdmin = $((New-Object Security.Principal.WindowsPrincipal $([Security.Principal.WindowsIdentity]::GetCurrent())).IsInRole([Security.Principal.WindowsBuiltinRole]::Administrator));
    } elseif ($hostOS -eq "Linux") {
      # [ $(id -u) = 0 ] && echo "User is root" || echo "User is not root"
      # lets just assume ;}
      [bool]$IsAdmin = $true
    } elseif ($hostOS -eq "MacOsx") {
      # TODO: add fix
      Write-Warning "MacOsx !! idk how to solve this one!"
      [bool]$IsAdmin = $true
    }
    if ($hostOS -eq "Windows" -and !$IsAdmin) {
      Write-Warning "$fxn : [!]  It seems You're not Admin [!] "
      break
    }
    $j_ = $([IO.Path]::PathSeparator)
    Set-Variable -Name 'refresh' -Visibility Public -Value $([scriptblock]::Create({
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
                  if ($(Get-Variable PSVersionTable -ValueOnly).psversion -ge [System.Version]("4.0.0.0")) {
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
                  $([scriptblock]::Create("[Environment]::SetEnvironmentVariable('$var', '$($env_vars.User.$var)', 'Process')")).Invoke();
                } elseif ($env_vars.Machine.ContainsKey($var)) {
                  $([scriptblock]::Create("[Environment]::SetEnvironmentVariable('$var', '$($env_vars.Machine.$var)', 'Process')")).Invoke()
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
              Write-Verbose "$fxn [Refresh] Updating $var variable in Process scope ✅"
              $([scriptblock]::Create("[Environment]::SetEnvironmentVariable('$var', '$($pieces -join $j_)', 'Process')")).Invoke();
            }
            # Add all necessary namespaces
            [System.Management.Automation.ActionPreference]$DbP2 = $DebugPreference; $DebugPreference = 'SilentlyContinue' # turn off debugg for a while. (prevents spiting out all the C# code)
            if ($IsWinEnv) {
              $IsnmLoaded = [bool]("win32.nativemethods" -as [type])
              $IswxLoaded = [bool]("Win32API.Explorer" -as [type])
              if (!$IsnmLoaded -or !$IswxLoaded) { [dotEnv]::Log("⏳ Loading required namespaces ..."); [Console]::Write($nl) }
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
            [string[]]$valid_levels = [Enum]::GetNames([EnvironmentVariableTarget])
            [int]$c = 0
            [int]$t = $valid_levels.Count
            [Console]::Write($nl)
            foreach ($level in $valid_levels) {
              [dotEnv]::Log("[Refresh]  $c/$t Cleanning obsolete variabls in [$level] scope ...");
              foreach ($var_Name in $($env_vars.$level.Keys | Where-Object { $vNames -notcontains $_ })) {
                Write-Verbose "$fxn [Refresh] Cleanning Env:Variable $var_Name in $level scope."
                $([scriptblock]::Create("[System.Environment]::SetEnvironmentVariable('$var_Name', `$null, [System.EnvironmentVariableTarget]::$level)")).Invoke();
                if ($null -ne ${env:var_Name}) { Remove-Item -LiteralPath "${env:var_Name}" -Force -ErrorAction SilentlyContinue | Out-Null }
              }
              [dotEnv]::Log("[Refresh]  $c/$t Updating PATH variables in [$level] scope ...");
              $env_vars.$level.GetEnumerator() | ForEach-Object { if ($_.Name -match 'Path$') {
                  $_.Value = $(((Get-Content "Env:$($_.Name)") + "$j_$($_.Value)") -split $j_ | Select-Object -Unique) -join $j_
                  Write-Verbose "$fxn [Refresh] Updating Env:Variable $($_.Name) in [$level] scope."
                  $([scriptblock]::Create("[System.Environment]::SetEnvironmentVariable('$($_.Name)', '$($_.Value)', [System.EnvironmentVariableTarget]::$level)")).Invoke();
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
    Set-Variable -Name 'CreateNewObjRefreshEnv' -Visibility Public -Value $([scriptblock]::Create({
          try {
            $TempFile = if ($null -eq (Get-Command New-TempFile -ErrorAction SilentlyContinue)) {
              $Fl = New-TemporaryFile; $rF = [System.IO.Path]::ChangeExtension($Fl.FullName, 'ps1'); [System.IO.File]::Move($Fl.FullName, $rF); Get-Item $rf
            } else {
              New-TempFile -Pref Refresh- -Ext ps1;
            }
            $((Get-Command -CommandType Function -Name $MyInvocation.MyCommand.Name).ScriptBlock) | Set-Content -Path $TempFile
            $([scriptblock]::Create("[System.Environment]::SetEnvironmentVariable('ObjectsRefreshScript', '$($TempFile.FullName)', [System.EnvironmentVariableTarget]::Process)")).Invoke();
            $([scriptblock]::Create("[System.Environment]::SetEnvironmentVariable('ObjectsRefreshScript', '$($TempFile.FullName)', [System.EnvironmentVariableTarget]::User)")).Invoke();
            [dotEnv]::Log("🤖 Updated refreshscript to $($TempFile.FullName)");
          } catch {
            Write-Verbose "$fxn [!]  Error while Setting Env:ObjectsRefreshScript to $TempFile"; [Console]::Write($nl)
            Write-Error $_.Exception
          }
        }
      )
    )
    try {
      [dotEnv]::Log("Refreshing ..."); [Console]::Write($nl)
      Invoke-Command -ScriptBlock $refresh -ErrorAction Stop
      [dotEnv]::Log("[Refresh] Done Now everything should be refreshed.");
    } catch {
      Write-Verbose "$fxn [!]  Unexpected Error while refreshing env:variables."; [Console]::Write($nl)
      Write-Error $_.Exception -ErrorAction Continue
    }
    try {
      if (![IO.File]::Exists($env:ObjectsRefreshScript)) {
        [dotEnv]::Log("ObjectsRefreshScript does not exist; 🤖 Creating new one ...")
        Invoke-Command -ScriptBlock $CreateNewObjRefreshEnv -ErrorAction Stop
        [dotEnv]::Log("Done.");
        [dotEnv]::Log("Refreshing (again) ..."); [Console]::Write($nl)
        Invoke-Command -ScriptBlock $refresh -ErrorAction Stop
        [dotEnv]::Log("[Refresh] Done Now everything should be refreshed.")
      }
      if ($IsWinEnv -and "$ctxOption" -eq "Add") {
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
      if ($IsWinEnv -and "$ctxOption" -eq "Remove") {
        Write-Verbose "$fxn ⏳ Removing Registry Keys.."
        if ($PSCmdlet.ShouldProcess("$reg_path", "Remove-Item")) {
          Remove-Item -Path $reg_path -Recurse -Force -ErrorAction SilentlyContinue
        }
        Remove-Item $env:ObjectsRefreshScript -Force -ErrorAction SilentlyContinue
        [System.Environment]::SetEnvironmentVariable('ObjectsRefreshScript', $null, [System.EnvironmentVariableTarget]::Process)
        [System.Environment]::SetEnvironmentVariable('ObjectsRefreshScript', $null, [System.EnvironmentVariableTarget]::User)
      }
    } catch {
      Write-Verbose "$fxn [!]  Unexpected Error while fixing Contextmenu Registry:"; [Console]::Write($nl)
      Write-Error $_.Exception -ErrorAction Continue
    }
  }
  static [System.Security.Cryptography.X509Certificates.X509Certificate2] CreateSelfSignedCertificate([EnvCfg]$EnvCfg, [string]$sessionId) {
    [dotEnv]::SetSessionCreds([guid]$sessionId)
    $X509VarName = "X509CertHelper_class_$([dotEnv]::VarName_Suffix)";
    if (!$(Get-Variable $X509VarName -ValueOnly -Scope script -ErrorAction Ignore)) {
      Write-Verbose "Fetching X509CertHelper class (One-time only)" -Verbose;
      Set-Variable -Name $X509VarName -Scope script -Option ReadOnly -Value ([scriptblock]::Create($((Invoke-RestMethod -Method Get https://api.github.com/gists/d8f277f1d830882c4927c144a99b70cd).files.'X509CertHelper.ps1'.content)));
    }
    $X509CertHelper_class = Get-Variable $X509VarName -ValueOnly -Scope script
    if ($X509CertHelper_class) { . $X509CertHelper_class; [dotEnv]::X509CertHelper = New-Object X509CertHelper }
    $Password = [System.Environment]::GetEnvironmentVariable($sessionId) | ConvertTo-SecureString
    return [dotEnv]::X509CertHelper::CreateSelfSignedCertificate("CN=$($EnvCfg.CertName)", $EnvCfg.PrivateCertFile, $Password, 2048, [System.DateTimeOffset]::Now.AddDays(-1).DateTime, [System.DateTimeOffset]::Now.AddDays($EnvCfg.CertExpirationDays).DateTime)
  }
  static hidden [void] Resolve_modules([string[]]$Names) {
    $varName = "resolver_script_$([dotEnv]::VarName_Suffix)";
    if (!$(Get-Variable $varName -ValueOnly -Scope script -ErrorAction Ignore)) {
      # Fetch it Once only, To Avoid spamming the github API :)
      Set-Variable -Name $varName -Scope script -Option ReadOnly -Value ([scriptblock]::Create($((Invoke-RestMethod -Method Get https://api.github.com/gists/7629f35f93ae89a525204bfd9931b366).files.'Resolve-Module.ps1'.content)))
    }
    $resolver_script = Get-Variable $varName -ValueOnly -Scope script
    if ($resolver_script) {
      . $resolver_script; Resolve-module -Name $Names
    } else {
      throw "Failed to fetch resolver script!"
    }
  }
  static [string] GetHostOs() {
    return $(if ($(Get-Variable PSVersionTable -Value).PSVersion.Major -le 5 -or $(Get-Variable IsWindows -Value)) { "Windows" }elseif ($(Get-Variable IsLinux -Value)) { "Linux" }elseif ($(Get-Variable IsMacOS -Value)) { "macOS" }else { "UNKNOWN" });
  }
}

#endregion Classes

# Types that will be available to users when they import the module.
$typestoExport = @(
  [dotEnv]
)
$TypeAcceleratorsClass = [psobject].Assembly.GetType('System.Management.Automation.TypeAccelerators')
foreach ($Type in $typestoExport) {
  if ($Type.FullName -in $TypeAcceleratorsClass::Get.Keys) {
    $Message = @(
      "Unable to register type accelerator '$($Type.FullName)'"
      'Accelerator already exists.'
    ) -join ' - '

    throw [System.Management.Automation.ErrorRecord]::new(
      [System.InvalidOperationException]::new($Message),
      'TypeAcceleratorAlreadyExists',
      [System.Management.Automation.ErrorCategory]::InvalidOperation,
      $Type.FullName
    )
  }
}
# Add type accelerators for every exportable type.
foreach ($Type in $typestoExport) {
  $TypeAcceleratorsClass::Add($Type.FullName, $Type)
}
# Remove type accelerators when the module is removed.
$MyInvocation.MyCommand.ScriptBlock.Module.OnRemove = {
  foreach ($Type in $typestoExport) {
    $TypeAcceleratorsClass::Remove($Type.FullName)
  }
}.GetNewClosure();

$Private = Get-ChildItem ([IO.Path]::Combine($PSScriptRoot, 'Private')) -Filter "*.ps1" -ErrorAction SilentlyContinue
$Public = Get-ChildItem ([IO.Path]::Combine($PSScriptRoot, 'Public')) -Filter "*.ps1" -ErrorAction SilentlyContinue
foreach ($file in ($Public + $Private)) {
  Try {
    if ([string]::IsNullOrWhiteSpace($file.fullname)) { continue }
    . "$($file.fullname)"
  } Catch {
    Write-Warning "Failed to import function $($file.BaseName): $_"
    $host.UI.WriteErrorLine($_)
  }
}

$Param = @{
  Function = $Public.BaseName
  Variable = 'localizedData'
  Cmdlet   = "*"
  Alias    = "*"
}
Export-ModuleMember @Param -Verbose