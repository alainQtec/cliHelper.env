#!/usr/bin/env pwsh
using namespace System.IO

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

#region classes
class CfgList {
  CfgList() {
    $this.PsObject.properties.add([psscriptproperty]::new('Count', [scriptblock]::Create({ ($this | Get-Member -Type *Property).count - 2 })))
    $this.PsObject.properties.add([psscriptproperty]::new('Keys', [scriptblock]::Create({ ($this | Get-Member -Type *Property).Name.Where({ $_ -notin ('Keys', 'Count') }) })))
  }
  CfgList([hashtable[]]$array) {
    $this.Add($array)
    $this.PsObject.properties.add([psscriptproperty]::new('Count', [scriptblock]::Create({ ($this | Get-Member -Type *Property).count - 2 })))
    $this.PsObject.properties.add([psscriptproperty]::new('Keys', [scriptblock]::Create({ ($this | Get-Member -Type *Property).Name.Where({ $_ -notin ('Keys', 'Count') }) })))
  }
  [void] Add([string]$key, [System.Object]$value) {
    [ValidateNotNullOrEmpty()][string]$key = $key
    if (!$this.Contains($key)) {
      $htab = [hashtable]::new(); $htab.Add($key, $value); $this.Add($htab)
    } else {
      Write-Warning "CfgList.Add() Skipped $Key. Key already exists."
    }
  }
  [void] Add([hashtable]$table) {
    [ValidateNotNullOrEmpty()][hashtable]$table = $table
    $Keys = $table.Keys | Where-Object { !$this.Contains($_) -and ($_.GetType().FullName -eq 'System.String' -or $_.GetType().BaseType.FullName -eq 'System.ValueType') }
    foreach ($key in $Keys) { $this | Add-Member -MemberType NoteProperty -Name $key -Value $table[$key] }
  }
  [void] Add([hashtable[]]$items) {
    foreach ($item in $items) { $this.Add($item) }
  }
  [void] Add([System.Collections.Generic.List[hashtable]]$items) {
    foreach ($item in $items) { $this.Add($item) }
  }
  [void] Set([string]$key, [System.Object]$value) {
    $htab = [hashtable]::new(); $htab.Add($key, $value)
    $this.Set($htab)
  }
  [void] Set([hashtable]$item) {
    $Keys = $item.Keys | Sort-Object -Unique
    foreach ($key in $Keys) {
      $value = $item[$key]
      [ValidateNotNullOrEmpty()][string]$key = $key
      [ValidateNotNullOrEmpty()][System.Object]$value = $value
      if ($this.psObject.Properties.Name.Contains([string]$key)) {
        $this."$key" = $value
      } else {
        $this.Add($key, $value)
      }
    }
  }
  [void] Set([System.Collections.Specialized.OrderedDictionary]$dict) {
    $dict.Keys.Foreach({ $this.Set($_, $dict["$_"]) });
  }
  [void] LoadJson([string]$FilePath) {
    $this.LoadJson($FilePath, [System.Text.Encoding]::UTF8)
  }
  [void] LoadJson([string]$FilePath, [System.Text.Encoding]$Encoding) {
    [ValidateNotNullOrEmpty()][string]$FilePath = $FilePath
    [ValidateNotNullOrEmpty()][System.Text.Encoding]$Encoding = $Encoding
    $ob = ConvertFrom-Json -InputObject $([IO.File]::ReadAllText($FilePath, $Encoding))
    $ob | Get-Member -Type NoteProperty | Select-Object Name | ForEach-Object {
      $key = $_.Name; $val = $ob.$key; $this.Set($key, $val);
    }
  }
  [bool] Contains([string]$Name) {
    [ValidateNotNullOrEmpty()][string]$Name = $Name
    return (($this | Get-Member -Type NoteProperty | Select-Object -ExpandProperty name) -contains "$Name")
  }
  [array] ToArray() {
    $array = @(); $props = $this | Get-Member -MemberType NoteProperty
    if ($null -eq $props) { return @() }
    $props.name | ForEach-Object { $array += @{ $_ = $this.$_ } }
    return $array
  }
  [string] ToJson() {
    return [string]($this | Select-Object -ExcludeProperty count | ConvertTo-Json)
  }
  [System.Collections.Specialized.OrderedDictionary] ToOrdered() {
    [System.Collections.Specialized.OrderedDictionary]$dict = @{}; $Keys = $this.PsObject.Properties.Where({ $_.Membertype -like "*Property" }).Name
    if ($Keys.Count -gt 0) {
      $Keys | ForEach-Object { [void]$dict.Add($_, $this."$_") }
    }
    return $dict
  }
  [string] ToString() {
    $r = $this.ToArray(); $s = ''
    $shortnr = [scriptblock]::Create({
        param([string]$str, [int]$MaxLength)
        while ($str.Length -gt $MaxLength) {
          $str = $str.Substring(0, [Math]::Floor(($str.Length * 4 / 5)))
        }
        return $str
      }
    )
    if ($r.Count -gt 1) {
      $b = $r[0]; $e = $r[-1]
      $0 = $shortnr.Invoke("{'$($b.Keys)' = '$($b.values.ToString())'}", 40)
      $1 = $shortnr.Invoke("{'$($e.Keys)' = '$($e.values.ToString())'}", 40)
      $s = "@($0 ... $1)"
    } elseif ($r.count -eq 1) {
      $0 = $shortnr.Invoke("{'$($r[0].Keys)' = '$($r[0].values.ToString())'}", 40)
      $s = "@($0)"
    } else {
      $s = '@()'
    }
    return $s
  }
}

class dotEntry {
  [ValidateNotNullOrWhiteSpace()][string]$Name
  [string]$Value
  hidden [dtActn]$Action
  dotEntry($n, $v, $a) {
    $this.Name = $n; $this.Action = $a; $this.Value = $v
  }
  [void] Set([string]$Name, [string]$value) {
    $this.Name = $Name; $this.Value = $value
  }
  [string] ToString() {
    $__str = '{0}{1}{2}' -f $this.Name, @{ Assign = '='; Prefix = ":="; Suffix = "=:" }["$($this.Action)"], $this.Value
    return $__str
  }
}

class EnvCfg {
  [ValidateNotNullOrEmpty()][string]$AzureServicePrincipalAppName
  [ValidateRange(1, 73000)][int]$CertExpirationDays
  [IO.FileInfo]$PrivateCertFile
  [IO.FileInfo]$PublicCertFile
  [bool]$KeepLocalPfxFiles
  [IO.FileInfo]$PfxFile

  EnvCfg() {
    $env = [System.IO.FileInfo]::New([IO.Path]::Combine($(Get-Variable executionContext -ValueOnly).SessionState.Path.CurrentLocation.Path, '.env'))
    if ($env.Exists) { $this.Set($env.FullName) }; $this.SetCertPath();
  }
  hidden [void] Set([string]$key, $value) {
    [ValidateNotNullOrEmpty()][string]$key = $key
    [ValidateNotNullOrEmpty()][System.Object]$value = $value
    if ($key.ToLower() -eq 'certpath') {
      $this.SetCertPath($value)
    } elseif ($this.psObject.Properties.Name.Contains([string]$key)) {
      $this."$key" = $value
    } else {
      $this.Add($key, $value)
    }
  }
  hidden [void] Set([string]$EnvFile) {
    if (!(Test-Path -Path $EnvFile -PathType Leaf -ErrorAction Ignore)) {
      throw [System.IO.FileNotFoundException]::New()
    }
    $dict = [System.Collections.Specialized.OrderedDictionary]::New(); [IO.File]::ReadAllLines($EnvFile).ForEach({
        if (![string]::IsNullOrWhiteSpace($_) -and $_[0] -notin ('#', '//')) {
                        ($m, $d ) = switch -Wildcard ($_) {
            "*:=*" { "Prefix", ($_ -split ":=", 2); Break }
            "*=:*" { "Suffix", ($_ -split "=:", 2); Break }
            "*=*" { "Assign", ($_ -split "=", 2); Break }
            Default {
              throw 'Unable to find Key value pair in line'
            }
          }
          [void]$dict.Add($d[0].Trim(), $d[1].Trim())
        }
      }
    )
    $this.Set($dict);
  }
  hidden [void] SetCertPath() {
    $this.SetCertPath($(if ([bool](Get-Variable IsLinux -ValueOnly -ErrorAction Ignore) -or [bool](Get-Variable IsMacOS -ValueOnly -ErrorAction Ignore)) {
          '/etc/ssl/private/'
        } elseif ([bool](Get-Variable IsWindows -ValueOnly -ErrorAction Ignore)) {
          [IO.Path]::Combine($env:CommonProgramFiles, 'SSL', 'Private')
        } else {
          $PSScriptRoot
        }
      )
    )
  }
  hidden [void] SetCertPath([string]$CertPath) {
    $this.PrivateCertFile = [IO.FileInfo][IO.Path]::Combine($CertPath, "$($this.CertName).key.pem");
    $this.PublicCertFile = [IO.FileInfo][IO.Path]::Combine($CertPath, "$($this.CertName).cert.pem")
    $this.PfxFile = [IO.FileInfo][IO.Path]::Combine($CertPath, "$($this.CertName).pfx")
  }
}

class vars {
  hidden [ValidateNotNullOrEmpty()][char]$p = [IO.Path]::PathSeparator
  static [ValidateNotNullOrEmpty()][string[]]$targets = [Enum]::GetNames([EnvironmentVariableTarget])
  vars() {
    $this.PsObject.properties.add([psscriptproperty]::new('Process', { $o = [Environment]::GetEnvironmentVariables('Process'); return  $o.keys.ForEach({ [dotEntry]::new($_, $o["$_"], "ASSIGN") }) }))
    $this.PsObject.properties.add([psscriptproperty]::new('Machine', { $o = [Environment]::GetEnvironmentVariables('Machine'); return  $o.keys.ForEach({ [dotEntry]::new($_, $o["$_"], "ASSIGN") }) }))
    $this.PsObject.properties.add([psscriptproperty]::new('User', { $o = [Environment]::GetEnvironmentVariables('User'); return  $o.keys.ForEach({ [dotEntry]::new($_, $o["$_"], "ASSIGN") }) }))
  }
  [void] Refresh() {
    [System.Management.Automation.ActionPreference]$DbP2 = $(Get-Variable DebugPreference -ValueOnly);
    $DebugPreference = 'SilentlyContinue' # turn off debug for a while. (prevents spiting out all the C# code)
    try {
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
        # Refresh all objects using Win32API. ie: sometimes explorer.exe just doesn't get the message that things were updated.
        # RefreshEnvironment, RefreshShell and Notify all windows of environment block change
        [scriptblock]::Create("[Win32API.Explorer]::RefreshEnvironment(); [Win32API.Explorer]::RefreshShell()").Invoke()
        [scriptblock]::Create("`$HWND_BROADCAST = [intptr]0xffff; `$WM_SETTINGCHANGE = 0x1a; `$result = [uintptr]::zero; [void][win32.nativemethods]::SendMessageTimeout(`$HWND_BROADCAST, `$WM_SETTINGCHANGE, [uintptr]::Zero, 'Environment', 2, 5000, [ref]`$result)").Invoke()
      }
      foreach ($target in [vars]::targets) {
        [EnvTools]::Log("[Refresh]  Updating variables in [$target] scope...");
        $currentVars = $this.$target
        if (!$currentVars) { continue }
        foreach ($key in $currentVars.Keys) {
          $value = $currentVars[$key];
          # TODO: Add a progressbar
          switch ($true) {
            ($key -eq 'Path') { [Environment]::SetEnvironmentVariable($key, [string]::Join($this.p, $this.getAllValues($key)), $target); break }
            ($key -eq "PSModulePath" -and [EnvTools]::GetHostOs() -eq "Windows") {
              $psm = @(); if ($(Get-Variable PSVersionTable -ValueOnly).psversion -ge [System.Version]("4.0.0.0")) {
                $psm += [System.IO.Path]::Combine(${env:ProgramFiles}, 'WindowsPowerShell', 'Modules')
              }
              if (!($this.User.ContainsKey($key))) {
                $psm += [System.IO.Path]::Combine($([environment]::GetFolderPath('MyDocuments')), 'WindowsPowerShell', 'Modules')
              } else {
                $psm += $this.User.$key -split $this.p
              }
              $psm += $this.getAllValues($key)
              [Environment]::SetEnvironmentVariable($key, [string]::Join($this.p, ($psm | Select-Object -Unique)), $target)
              break;
            }
            Default {
              [Environment]::SetEnvironmentVariable($key, $value, $target)
            }
          }
        }
      }
    } catch {
      Write-Host "   [!]  Unexpected Error while runing refreshScript."
      Write-Host "   [!]  [Mitigation] Using the Old 'Quick-refresh' method. (Still not reliable, but its better than just exiting without taking any action.) :"
      Write-Verbose "   [Mitigation] [Refresh] ---------------- Refreshing PATH"
      $paths = 'Machine', 'User' | ForEach-Object { $([Environment]::GetEnvironmentVariable("PATH", "$_")) -split $j_ } | Select-Object -Unique
      $Env:PATH = $paths -join $this.p
      throw $_.Exception
    } finally {
      $DebugPreference = $DbP2; $this.cleanUp()
    }
  }
  hidden [void] cleanUp() {
    [int]$c = 0; [int]$t = $this::targets.Count; [Console]::WriteLine()
    foreach ($target in [vars]::targets) {
      [EnvTools]::Log("[Refresh]  $c/$t Cleanning obsolete variables in [$target] scope ...");
      $obsoletes = $this.$target.Keys.Where({ $this.ToString() -notcontains $_ })
      if ($obsoletes) {
        foreach ($var_Name in $obsoletes) {
          Write-Verbose "   [Refresh] Cleanning Env:Variable $var_Name in $target scope."
          $([scriptblock]::Create("[System.Environment]::SetEnvironmentVariable('$var_Name', `$null, [System.EnvironmentVariableTarget]::$target)")).Invoke();
          if ($null -ne ${env:var_Name}) { Remove-Item -LiteralPath "${env:var_Name}" -Force -ErrorAction SilentlyContinue | Out-Null }
        }
      } else {
        [EnvTools]::Log("[Refresh]      No obsolete variables were found.  ✅");
      }
      $this.$target.Keys.ForEach({ Set-Item -Path "Env:$_" -Value $this.$target[$_] })
      $c++; [Console]::WriteLine()
    }
  }
  hidden [string[]] getAllValues([string]$Name) {
    $values = ($this::targets.ForEach({ [System.Environment]::GetEnvironmentVariable($Name.ToUpper(), $_) }) | Select-Object -Unique)
    if (!$values) { return @() }
    return $values
  }
  [string[]] ToString() {
    return ($this.Machine.Keys + $this.User.Keys + $this.Process.Keys + 'PSModulePath') | Sort-Object | Select-Object -Unique
  }
}

class EnvTools {
  [EnvCfg] $config
  static [vars] $vars = [vars]::new()
  static hidden $X509CertHelper
  static hidden [string]$VarName_Suffix = '7fb2e877_6c2b_406a_af40_e1d915c62cdf'
  static [bool] $useDebug = (Get-Variable DebugPreference -ValueOnly) -eq 'Continue'
  [System.Security.Cryptography.X509Certificates.X509Certificate2] $Cert

  static [void] refreshEnv() {
    [EnvTools]::refreshEnv([ctxOption]::None)
  }
  static [void] refreshEnv([ctxOption]$ctxOption) {
    try {
      $hostOS = [EnvTools]::GetHostOs(); $IsWinEnv = $hostOS -eq "Windows";
      if ($hostOS -eq "Windows" -and ![EnvTools]::IsAdmin()) {
        Write-Warning "   : [!]  It seems You're not Admin [!] "
        return
      }
      if ($hostOS -eq "Windows" -and ![IO.File]::Exists($env:ObjectsRefreshScript) -and "$ctxOption" -ne "Remove") {
        [EnvTools]::Log("ObjectsRefreshScript does not exist; Creating new one ...")
        [EnvTools]::CreateObjectsRefreshScript();
        [Console]::WriteLine()
      }
      [EnvTools]::vars.Refresh()
      [EnvTools]::Log("[Refresh]  Done Now everything should be refreshed.");
    } catch {
      Write-Verbose "   [!]  Unexpected Error while refreshing env:variables."; [Console]::WriteLine()
      throw $_.Exception
    } finally {
      if ($IsWinEnv) {
        $reg_path = 'HKLM:\SOFTWARE\Classes\DesktopBackground\shell\Refresh Explorer';
        if ("$ctxOption" -eq "Add") {
          $kmd_Path = [IO.Path]::Combine($reg_path, "command"); $q = [char]34 # quote (Used to avoid escape chars)
          if (!$(Test-Path $reg_path -ErrorAction SilentlyContinue)) {
            New-Item -Path $kmd_Path -ItemType Directory -Force | Out-Null
          }
          New-ItemProperty -Path $reg_path -Name 'Icon' -Value 'Explorer.exe' -PropertyType String -Force | Out-Null
          New-ItemProperty -Path $reg_path -Name 'Position' -Value 'Bottom' -PropertyType String -Force | Out-Null
          New-ItemProperty -Path $kmd_Path -Name '(default)' -Value "Powershell.exe -NoLogo -WindowStyle Hidden -NoProfile -NonInteractive -ExecutionPolicy Bypass -File $q$env:ObjectsRefreshScript$q" -PropertyType String -Force | Out-Null
        }
        if ("$ctxOption" -eq "Remove") {
          Write-Verbose "   ⏳ Removing Registry Keys.."
          Remove-Item -Path $reg_path -Recurse -Force -ErrorAction SilentlyContinue
          Remove-Item $env:ObjectsRefreshScript -Force -ErrorAction SilentlyContinue
          [System.Environment]::SetEnvironmentVariable('ObjectsRefreshScript', $null, [System.EnvironmentVariableTarget]::Process)
          [System.Environment]::SetEnvironmentVariable('ObjectsRefreshScript', $null, [System.EnvironmentVariableTarget]::User)
        }
      }
    }
  }
  static [void] SetEnvironmentVariable([string]$Name, [string]$Value, [System.EnvironmentVariableTarget]$Scope) {
    if ($Name.ToUpper().Equals("PATH") -and [EnvTools]::GetHostOs() -eq "Windows") {
      $hive_is_connected = $false
      ([Microsoft.Win32.RegistryKey]$win32RegistryKey, [string]$registryKey) = switch ($Scope) {
        "Machine" {
          $dkey = "HKLM\DEFAULT"; $ntFl = "C:\Users\Default\NTUSER.DAT"
          if (!(Test-Path $dkey.Replace("\", ":"))) {
            Write-Verbose "Loading file $ntFl to the reg Key $dkey"
            $r = reg load $dkey $ntFl *>&1
            if (!$?) { throw "Failed to load hive: $r" }
          }; $hive_is_connected = $true; $k = 'DEFAULT\Environment'
          [Microsoft.Win32.Registry]::LocalMachine.OpenSubKey($k), $k
          break;
        }
        "User" {
          $k = 'Environment'
          [Microsoft.Win32.Registry]::CurrentUser.OpenSubKey($k), $k; break;
        }
        Default {
          $k = 'SYSTEM\CurrentControlSet\Control\Session Manager\Environment\'
          [Microsoft.Win32.Registry]::LocalMachine.OpenSubKey($k), $k
        }
      }
      # "Write ACCESS CHECKING"..
      if ($null -eq $win32RegistryKey.OpenSubKey($registryKey, [Microsoft.Win32.RegistryKeyPermissionCheck]::ReadWriteSubTree)) {
        Write-Warning "[!]  No RegistryKeyReadWrite Permission."
      }
      try {
        $registryType = switch ($true) {
          $win32RegistryKey.GetValueNames().Contains($Name) { $win32RegistryKey.GetValueKind($Name); break }
          $Name.ToUpper().Equals("PATH") { [Microsoft.Win32.RegistryValueKind]::ExpandString; break }
          Default { [Microsoft.Win32.RegistryValueKind]::String }
        }
      } catch {
        throw "Error. Could not find reg type for $Name`n" + $_
      }
      $CurrentPath = & {
        # idk, probably scope issues
        try { [System.Environment]::GetEnvironmentVariable('PATH', "$Scope") } catch { $win32RegistryKey.GetValue('PATH', '', [Microsoft.Win32.RegistryValueOptions]::DoNotExpandEnvironmentNames).TrimEnd([System.IO.Path]::PathSeparator) }
      }
      $NewPathValue = if (($null -eq $Value) -or ($Value -eq '')) { $CurrentPath }else { [string]::Concat($value, [System.IO.Path]::PathSeparator, $CurrentPath) }
      if ($NewPathValue.Contains('%')) { $registryType = [Microsoft.Win32.RegistryValueKind]::ExpandString }
      [void]$win32RegistryKey.SetValue('PATH', $NewPathValue, $registryType)
      $win32RegistryKey.Handle.Close()
      Write-Verbose "✅ Added PATH:Variable `"$Value`"."
      if ($hive_is_connected) { if ($PSCmdlet.ShouldProcess('HKLM\DEFAULT', 'reg unload')) { $r = reg unload "HKLM\DEFAULT" *>&1 } }
      return
    }
    [System.Environment]::SetEnvironmentVariable($Name, $Value, $Scope);
    if ([Bool][System.Environment]::GetEnvironmentVariable("$Name", $Scope)) { Write-Verbose "✅ Added env:variable `"$Name`"." }
  }
  static [void] CreateObjectsRefreshScript() {
    $TempFile = $null;
    try {
      $Fl = New-TemporaryFile; $rF = [System.IO.Path]::ChangeExtension($Fl.FullName, 'ps1'); [System.IO.File]::Move($Fl.FullName, $rF);
      $TempFile = Get-Item $rf
      $rfScript = [scriptblock]::Create({
          Import-Module dotEnv; Update-SessionEnv
        }
      )
      $rfScript.ToString() | Set-Content -Path $TempFile
      $([scriptblock]::Create("[System.Environment]::SetEnvironmentVariable('ObjectsRefreshScript', '$($TempFile.FullName)', [System.EnvironmentVariableTarget]::Process)")).Invoke();
      $([scriptblock]::Create("[System.Environment]::SetEnvironmentVariable('ObjectsRefreshScript', '$($TempFile.FullName)', [System.EnvironmentVariableTarget]::User)")).Invoke();
      [EnvTools]::Log("Updated env:ObjectsRefreshScript to $($TempFile.FullName)");
    } catch {
      Write-Verbose "   [!]  Error while Setting env:ObjectsRefreshScript to $TempFile"; [Console]::WriteLine()
      throw $_.Exception
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
    return [EnvTools]::GetSessionId($this)
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
    return [EnvTools]::VerifyGetSessionId([guid]$guid, $Source)
  }
  static [void] SetSessionCreds([guid]$sessionId) {
    [EnvTools]::SetSessionCreds([guid]$sessionId, $false)
  }
  static [void] SetSessionCreds([guid]$sessionId, [bool]$Force) {
    if (![string]::IsNullOrWhiteSpace([System.Environment]::GetEnvironmentVariable("$sessionId"))) { if (!$Force) { return } }
    [System.Environment]::SetEnvironmentVariable("$sessionId", $((Get-Credential -Message "Enter your Pfx Password" -Title "-----[[ PFX Password ]]-----" -UserName $env:username).GetNetworkCredential().SecurePassword | ConvertFrom-SecureString), [EnvironmentVariableTarget]::Process)
  }
  static [System.Security.Cryptography.X509Certificates.X509Certificate2] CreateSelfSignedCertificate([EnvCfg]$EnvCfg, [string]$sessionId) {
    [EnvTools]::SetSessionCreds([guid]$sessionId)
    $X509VarName = "X509CertHelper_class_$([EnvTools]::VarName_Suffix)";
    if (!$(Get-Variable $X509VarName -ValueOnly -Scope script -ErrorAction Ignore)) {
      Write-Verbose "Fetching X509CertHelper class (One-time only)" -Verbose;
      Set-Variable -Name $X509VarName -Scope script -Option ReadOnly -Value ([scriptblock]::Create($((Invoke-RestMethod -Method Get https://api.github.com/gists/d8f277f1d830882c4927c144a99b70cd).files.'X509CertHelper.ps1'.content)));
    }
    $X509CertHelper_class = Get-Variable $X509VarName -ValueOnly -Scope script
    if ($X509CertHelper_class) { . $X509CertHelper_class; [EnvTools]::X509CertHelper = New-Object X509CertHelper }
    $Password = [System.Environment]::GetEnvironmentVariable($sessionId) | ConvertTo-SecureString
    return [EnvTools]::X509CertHelper::CreateSelfSignedCertificate("CN=$($EnvCfg.CertName)", $EnvCfg.PrivateCertFile, $Password, 2048, [System.DateTimeOffset]::Now.AddDays(-1).DateTime, [System.DateTimeOffset]::Now.AddDays($EnvCfg.CertExpirationDays).DateTime)
  }
  static hidden [void] Resolve_modules([string[]]$Names) {
    $varName = "resolver_script_$([EnvTools]::VarName_Suffix)";
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
  static [void] Log([string]$Message) {
    if ((Get-Variable VerbosePreference -ValueOnly) -eq 'Continue') { Write-Host "🔵 [dotEnv] " -NoNewline; Write-Host $Message -f Cyan }
  }
  static [string] GetHostOs() {
    return $(if ($(Get-Variable PSVersionTable -Value).PSVersion.Major -le 5 -or $(Get-Variable IsWindows -Value)) { "Windows" }elseif ($(Get-Variable IsLinux -Value)) { "Linux" }elseif ($(Get-Variable IsMacOS -Value)) { "macOS" }else { "UNKNOWN" });
  }
  static [bool] IsAdmin() {
    $hostOs = [EnvTools]::GetHostOs()
    $isAdmn = switch ($hostOS) {
      "Windows" { (New-Object Security.Principal.WindowsPrincipal $([Security.Principal.WindowsIdentity]::GetCurrent())).IsInRole([Security.Principal.WindowsBuiltinRole]::Administrator); break }
      "Linux" { (& id -u) -eq 0; break }
      "MacOsx" { Write-Warning "MacOsx !! idk how to solve this one!"; $false; break }
      Default {
        throw "UNSUPPORTED_OS"
      }
    }
    return $isAdmn
  }
}

#endregion classes

#region functions
function Set-dotEnvConfig {
  # .SYNOPSIS
  #     Supposed to run on-time, during module initial setup. It prepares Credentials to use when securing environment variables on local machine.
  # .DESCRIPTION
  #     Generates a secure hashed credential file and configuration for the dotEnv module.
  #     Has options to choose between DPAPI or AES encryption modes.
  #     DPAPI is more secure but requires to be run by the same user account on the same windows machine.
  #     AES is also secure but can be used when service account cannot be used to run in interactive mode.
  # .NOTES
  #     Information or caveats about the function e.g. 'This function is not supported in Linux'
  # .LINK
  #     Specify a URI to a help page, this will show when Get-Help -Online is used.
  # .EXAMPLE
  #     Set-dotEnvConfig
  #     Explanation of the function or its result. You can include multiple examples with additional .EXAMPLE lines
  [CmdletBinding(SupportsShouldProcess = $true)]
  [Alias("Initialize-dotEnv")]
  param ()

  process {
    if ($PSCmdlet.ShouldProcess("Localhost", "Initialize dotEnv")) {
      # do stuff here
      # Write-Host "Hello from Private/dotEnv.Config/Set-dotEnvConfig" -f Green
    }
  }

  end {
  }
}
#endregion functions