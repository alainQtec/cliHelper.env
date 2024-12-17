#!/usr/bin/env pwsh
using namespace System.IO
using namespace System.Management.Automation.Language

#Requires -Modules clihelper.xcrypt
#region    Classes

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
  [bool]$autoSync = $false
  EnvCfg() {}
  EnvCfg([hashtable[]]$items) { $this.Add($items) }
  [void] Add([string]$key, [System.Object]$value) {
    [ValidateNotNullOrEmpty()][string]$key = $key
    if (!$this.Contains($key)) {
      $htab = [hashtable]::new(); $htab.Add($key, $value); $this.Add($htab)
    } else {
      Write-Warning "Cfg.Add() Skipped $Key. Key already exists."
    }
  }
  [void] Add([hashtable]$item) {
    [ValidateNotNullOrEmpty()][hashtable]$item = $item
    $Keys = $item.Keys | Where-Object { !$this.Contains($_) -and ($_.GetType().FullName -eq 'System.String' -or $_.GetType().BaseType.FullName -eq 'System.ValueType') }
    foreach ($key in $Keys) { $this | Add-Member -MemberType NoteProperty -Name $key -Value $item[$key] }
  }
  [void] Add([hashtable[]]$items) {
    foreach ($item in $items) { $this.Add($item) }
  }
  [void] Add([System.Collections.Generic.List[hashtable]]$items) {
    foreach ($item in $items) { $this.Add($item) }
  }
  [void] Remove([string[]]$keys) {
    $keys.ForEach({ $this.PsObject.Properties.Remove($_) })
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
  [void] Set([string]$key, [System.Object]$value) {
    [ValidateNotNullOrEmpty()][string]$key = $key
    [AllowNull()][System.Object]$value = $value
    if ($this.psObject.Properties.Name.Contains([string]$key)) {
      $this."$key" = $value
    } else {
      $this.Add($key, $value)
    }
  }
  [void] Set([System.Collections.Specialized.OrderedDictionary]$dict) {
    $dict.Keys.Foreach({ $this.Set($_, $dict["$_"]) });
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
  [PSCustomObject] ToPsObject() {
    return ($this.ToJson() | ConvertFrom-Json)
  }
  [string] ToJson() {
    return [string]($this | Select-Object * | ConvertTo-Json)
  }
  [System.Collections.Specialized.OrderedDictionary] ToOrdered() {
    $dict = [System.Collections.Specialized.OrderedDictionary]::new(); $Keys = $this.PsObject.Properties.Where({ $_.Membertype -like "*Property" }).Name
    if ($Keys.Count -gt 0) {
      $Keys | ForEach-Object { [void]$dict.Add($_, $this."$_") }
    }
    return $dict
  }
  [void] Import([string]$FilePath) {
    $this.Import($FilePath, [System.Text.Encoding]::UTF8)
  }
  [void] Import([string]$FilePath, [System.Text.Encoding]$Encoding) {
    [ValidateNotNullOrEmpty()][string]$FilePath = $FilePath
    [ValidateNotNullOrEmpty()][System.Text.Encoding]$Encoding = $Encoding
    $this.Import($(ConvertFrom-Json -InputObject $([IO.File]::ReadAllText($FilePath, $Encoding))))
  }
  [void] Import([PSCustomObject]$Object) {
    [ValidateNotNullOrEmpty()][PSCustomObject]$Object = $Object
    $Object | Get-Member -Type NoteProperty | Select-Object Name | ForEach-Object {
      $key = $_.Name; $val = $Object.$key; if ($null -ne $val) {
        $t = $this.PsObject.Properties.Where({ $_.Name -eq $key })[0].TypeNameOfValue
        $this.Set($key, ($val -as $t));
      }
    }
  }
  [int] GetCount() {
    return ($this | Get-Member -Type *Property).count
  }
  [string[]] GetKeys() {
    return ($this | Get-Member -Type *Property).Name
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

class cert {
  [string]$Public
  [string]$Private
  [string]$KeepLocal = $false
  [string]$Pfx
}
class ProjectConfig : EnvCfg {
  [string]$Name
  [string]$publicKey = ""
  [string]$remoteGistUrl = ""
  [string[]]$allowedUserIds = @()
  [string] ToString() {
    return ($this | ConvertTo-Json)
  }
}

class UserConfig : EnvCfg {
  [ValidateNotNullOrWhiteSpace()][string]$UserName = [UserConfig]::GetUserName()
  [ValidateNotNullOrWhiteSpace()][string]$UserId
  [ValidateNotNullOrEmpty()][string[]]$projects
  [ValidateRange(0, 73000)][int]$ExpiryDays = 1
  [bool]$Use2FA = $false
  [cert]$cert
  UserConfig() : base() {
    [bool]$Is_Unix_Os = [bool](Get-Variable IsLinux -ValueOnly -ErrorAction Ignore) -or [bool](Get-Variable IsMacOS -ValueOnly -ErrorAction Ignore)
    [bool]$Is_Windows = [bool](Get-Variable IsWindows -ValueOnly -ErrorAction Ignore)
    [string]$CertPath = switch ($true) {
      $Is_Unix_Os { '/etc/ssl/private/'; break }
      $Is_Windows { [IO.Path]::Combine($env:CommonProgramFiles, 'SSL', 'Private'); break }
      Default { $PSScriptRoot }
    }
    $this.cert = New-Object cert -Property @{
      Public  = [IO.Path]::Combine($CertPath, "$($this.UserName).cert.pem")
      Private = [IO.Path]::Combine($CertPath, "$($this.UserName).key.pem");
      Pfx     = [IO.Path]::Combine($CertPath, "$($this.UserName).pfx")
    }
  }
  static [string] GetUserName() {
    $u = $env:USER; if (!$u) { $u = $env:USERNAME }; return $u
  }
  [string] ToString() {
    return ($this | ConvertTo-Json)
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
      if ([xcrypt]::Get_Host_Os() -eq "Windows") {
        $IsnmLoaded = [bool]("win32.nativemethods" -as [type])
        $IswxLoaded = [bool]("Win32API.Explorer" -as [type])
        if (!$IsnmLoaded -or !$IswxLoaded) { Write-Verbose "🔵 ⏳ Loading required namespaces ..."; [Console]::WriteLine() }
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
        Write-Verbose "🔵 [Refresh]  Updating variables in [$target] scope..."
        $currentVars = $this.$target
        if (!$currentVars) { continue }
        foreach ($key in $currentVars.Keys) {
          $value = $currentVars[$key];
          # TODO: Add a progressbar
          switch ($true) {
            ($key -eq 'Path') { [Environment]::SetEnvironmentVariable($key, [string]::Join($this.p, $this.getAllValues($key)), $target); break }
            ($key -eq "PSModulePath" -and [xcrypt]::Get_Host_Os() -eq "Windows") {
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
      Write-Verbose "🔵 [Refresh]  $c/$t Cleanning obsolete variables in [$target] scope ..."
      $obsoletes = $this.$target.Keys.Where({ $this.ToString() -notcontains $_ })
      if ($obsoletes) {
        foreach ($var_Name in $obsoletes) {
          Write-Verbose "🔵    [Refresh] Cleanning Env:Variable $var_Name in $target scope."
          $([scriptblock]::Create("[System.Environment]::SetEnvironmentVariable('$var_Name', `$null, [System.EnvironmentVariableTarget]::$target)")).Invoke();
          if ($null -ne ${env:var_Name}) { Remove-Item -LiteralPath "${env:var_Name}" -Force -ErrorAction SilentlyContinue | Out-Null }
        }
      } else {
        Write-Verbose "🔵 [Refresh]      No obsolete variables were found.  ✅"
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

# .SYNOPSIS
#  Module main class
class dotEnv {
  static $X509CertHelper
  static [vars] $vars = [vars]::new()
  static [EnvCfg] $config = [EnvCfg]::new(@{ User = [UserConfig]::new(); Project = [ProjectConfig]::new() })
  Static [IO.DirectoryInfo] $DataPath = [xcrypt]::Get_dataPath('dotEnv', 'Data')
  static hidden [string]$VarName_Suffix = [dotEnv].GUID.ToString().Replace('-', '_');
  static [bool] $useDebug = (Get-Variable DebugPreference -ValueOnly) -eq 'Continue'
  hidden [System.Security.Cryptography.X509Certificates.X509Certificate2] $Cert

  dotEnv() {
    [dotEnv]::SetEnvFile(); Set-EnvConfig
  }
  static [string] Get([string]$key) {
    [ValidateNotNullOrEmpty()][string]$key = $key
    return [dotEnv]::Read([dotEnv].EnvFile).Where({ $_.Name -eq $key }).Value
  }
  static [dotEntry[]] Read([string]$EnvFile) {
    [ValidateNotNullOrEmpty()][string]$EnvFile = $(Resolve-Path $EnvFile -ea Ignore).Path
    $res_Obj = @(); $content = [IO.File]::ReadAllLines($EnvFile)
    if ([string]::IsNullOrWhiteSpace($content)) {
      Write-Debug "The .env file is empty!"
      return $res_Obj
    }
    foreach ($line in $content) {
      if ([string]::IsNullOrWhiteSpace($line)) { continue }
      if ($line.StartsWith("#") -or $line.StartsWith("//")) {
        Write-Verbose "🔵 ~ comment: $([dotEnv]::sensor($line))"
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
  static [void] Update([IO.FileInfo]$EnvFile, [string]$Name, [string]$Value) {
    [dotEnv]::Update($EnvFile, $Name, $Value, $false)
  }
  static [void] Update([IO.FileInfo]$EnvFile, [string]$Name, [string]$Value, [bool]$StripComments) {
    $Entries = [dotenv]::Read($EnvFile.FullName);
    if ($StripComments) {
      [IO.File]::WriteAllText($EnvFile,
        $([dotEnv]::Update($Entries, $Name, $Value).ForEach({ $_.ToString() }) | Out-String).Trim(),
        [System.Text.Encoding]::UTF8
      )
    } else {
      $q = $Entries.Where({ $_.Name -eq $Name }); $s = ''
      $sb = [System.Text.StringBuilder]::new([IO.File]::ReadAllText($EnvFile.FullName));
      $ms = [PSObject]@{ Assign = '='; Prefix = ":="; Suffix = "=:" };
      if ($q.count -ne 0) {
        $s = $ms[$q.Action]
        $pa = "(?m)^($Name{0}).*$" -f $s; $re = "$Name{0}$value" -f $s
        $updatedContent = $sb.ToString() -replace $pa, $re
        [IO.File]::WriteAllText($EnvFile.FullName, $updatedContent)
      } else {
        Write-Debug "key $Name was not found. Addind new one ..."
        $Entries += [dotEntry]::new($Name, $Value, "Assign")
        [IO.File]::WriteAllText($EnvFile.FullName, $($Entries.ForEach({ $_.ToString() }) | Out-String))
      }
    }
  }
  static hidden [dotEntry[]] Update([dotEntry[]]$Entries, [string]$Name, [string]$Value) {
    return $Entries.ForEach({ if ($_.Name -eq $Name) { $_.Set($Name, $Value) } })
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
  static [void] StripComments([string]$EnvFile) {
    [dotEnv]::StripComments($EnvFile, [System.Text.Encoding]::UTF8)
  }
  static [void] StripComments([string]$EnvFile, [System.Text.Encoding]$Encoding) {
    [ValidateNotNullOrEmpty()][string]$EnvFile = $(Resolve-Path $EnvFile -ea Ignore).Path
    [string]$content = ([dotenv]::Read($EnvFile).ForEach({ $_.ToString() }) | Out-String).Trim()
    [IO.File]::WriteAllText($EnvFile, $content, $Encoding)
  }
  static [bool] IsPersisted([string]$source) {
    $p = @(); $p += [dotEnv]::Config.Persisted;
    return $p.Contains($source)
  }
  static [void] Persist([string]$source) {
    $p = @(); $p += [dotEnv]::Config.Persisted;
    if (!$p.Contains($source)) {
      $p += $source; [dotEnv]::Config.Set("Persisted", $p)
    }
  }
  static [void] Unpersist([string]$source) {
    $p = @(); $p += [dotEnv]::Config.Persisted;
    if (!$p.Contains($source)) {
      $p = $p.where({ $_ -ne $source })
      [dotEnv]::Config.Set("Persisted", $p)
    }
  }
  static [string] sensor([string]$str) {
    if ([string]::IsNullOrWhiteSpace($str)) { return $str }
    $_90 = [int][Math]::Floor($str.Length * .9)
    $_10 = [int][Math]::Floor($str.Length * .1)
    $_sr = ($str.Substring(0, $_10) + '░' * $_90)
    $_cs = "CENSORED"; if ($_sr.Length -gt 13) {
      $50l = [int][Math]::Floor($_sr.Length * .5)
      $_sr = $_sr.Substring(0, $50l - $_cs.Length) + $_cs + $_sr.Substring($50l + $_cs.Length)
    }
    return $_sr
  }
  static [void] SetEnvFile() {
    [dotEnv].PsObject.properties.add([psscriptproperty]::new('EnvFile', { return [IO.Path]::Combine($(Get-Variable executionContext -ValueOnly).SessionState.Path.CurrentLocation.Path, '.env') }))
    [dotEnv].PsObject.properties.add([psscriptproperty]::new('enc_envfile', { return [IO.Path]::Combine($(Get-Variable executionContext -ValueOnly).SessionState.Path.CurrentLocation.Path, '.env.enc') }))
  }
  static [void] refreshEnv() { [dotEnv]::refreshEnv([ctxOption]::None) }
  static [void] refreshEnv([ctxOption]$ctxOption) {
    try {
      $hostOS = [xcrypt]::Get_Host_Os(); $IsWinEnv = $hostOS -eq "Windows";
      if ($hostOS -eq "Windows" -and ![dotEnv]::IsAdmin()) {
        Write-Warning "   : [!]  It seems You're not Admin [!] "
        return
      }
      if ($hostOS -eq "Windows" -and ![IO.File]::Exists($env:ObjectsRefreshScript) -and "$ctxOption" -ne "Remove") {
        Write-Verbose "🔵 ObjectsRefreshScript does not exist; Creating new one ..."
        [dotEnv]::CreateObjectsRefreshScript();
        [Console]::WriteLine()
      }
      [dotEnv]::vars.Refresh()
      Write-Verbose "🔵 [Refresh]  Done Now everything should be refreshed."
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
    if ($Name.ToUpper().Equals("PATH") -and [xcrypt]::Get_Host_Os() -eq "Windows") {
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
      Write-Verbose "Added PATH:Variable `"$Value`"."
      if ($hive_is_connected) { if ($PSCmdlet.ShouldProcess('HKLM\DEFAULT', 'reg unload')) { $r = reg unload "HKLM\DEFAULT" *>&1 } }
      return
    }
    Set-Item -Path Env:/$Name -Value $Value -Force
    [System.Environment]::SetEnvironmentVariable($Name, $Value, $Scope);
    if ([Bool][System.Environment]::GetEnvironmentVariable("$Name", $Scope)) { Write-Verbose "Set env:variable `"$Name`"." }
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
      Write-Verbose "🔵 Updated env:ObjectsRefreshScript to $($TempFile.FullName)"
    } catch {
      Write-Verbose "   [!]  Error while Setting env:ObjectsRefreshScript to $TempFile"; [Console]::WriteLine()
      throw $_.Exception
    }
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
  static [System.Security.Cryptography.X509Certificates.X509Certificate2] CreateSelfSignedCertificate([UserConfig]$UserCfg, [string]$sessionId) {
    [dotEnv]::SetSessionCreds([guid]$sessionId); [void][dotEnv]::GetX509CertHelper();
    $Password = [System.Environment]::GetEnvironmentVariable($sessionId) | ConvertTo-SecureString
    return [dotEnv]::X509CertHelper::CreateSelfSignedCertificate("CN=$($UserCfg.UserName)", $UserCfg.cert.Private, $Password, 2048, [System.DateTimeOffset]::Now.AddDays(-1).DateTime, [System.DateTimeOffset]::Now.AddDays($UserCfg.ExpiryDays).DateTime)
  }
  static [Object] GetX509CertHelper() {
    $scriptNme = "X509CertHelper"; $X509VarName = "${scriptNme}_class_$([dotEnv]::VarName_Suffix)";
    if (!$(Get-Variable $X509VarName -ValueOnly -Scope script -ErrorAction Ignore)) {
      try {
        $IsGitHubActions = $env:CI -eq 'true' -and $null -ne $env:GITHUB_RUN_ID
        $IsNotInstalled = $(if ($IsGitHubActions) {
            $true # (fails due to github API rate limit) Set-Variable -Name $X509VarName -Scope script -Option ReadOnly -Value ([scriptblock]::Create($((Invoke-RestMethod -Method Get https://api.github.com/gists/d8f277f1d830882c4927c144a99b70cd).files."$scriptNme.ps1".content)))
          } else {
            $null -eq (Get-InstalledScript -Name $scriptNme -Verbose:$false -ErrorAction Ignore)[0]
          }
        )
        if ($IsNotInstalled) {
          Write-Host "[+] Installing script $scriptNme" -f Green
          [Net.ServicePointManager]::SecurityProtocol = [Net.ServicePointManager]::SecurityProtocol -bor [Net.SecurityProtocolType]::Tls12
          Set-PSRepository -Name 'PSGallery' -InstallationPolicy Trusted -Verbose:$false; Install-Script -Name $scriptNme -Verbose:$false
          $Private:XscrContent = ([IO.File]::ReadAllText([IO.Path]::Combine((Get-InstalledScript -Name $scriptNme).InstalledLocation, "$scriptNme.ps1")));
          Set-Variable -Name $X509VarName -Scope script -Option ReadOnly -Value ([scriptblock]::Create("$XscrContent"));
        }
      } catch {
        Write-Error "Unexpected error occurred: $($_.Exception); $($_.ScriptStackTrace)"
      }
    }
    $X509 = Get-Variable $X509VarName -ValueOnly -Scope script
    if ($X509) { . $X509; [dotEnv]::X509CertHelper = New-Object X509CertHelper }
    return [dotEnv]::X509CertHelper
  }
  static [bool] IsAdmin() {
    $hostOs = [xcrypt]::Get_Host_Os()
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

#endregion Classes

#region typeAccelerators
# Types that will be available to users when they import the module.
$typestoExport = @(
  [dotEnv]
)
$TypeAcceleratorsClass = [PsObject].Assembly.GetType('System.Management.Automation.TypeAccelerators')
foreach ($Type in $typestoExport) {
  if ($Type.FullName -in $TypeAcceleratorsClass::Get.Keys) {
    $Message = @(
      "Unable to register type accelerator '$($Type.FullName)'"
      'Accelerator already exists.'
    ) -join ' - '

    [System.Management.Automation.ErrorRecord]::new(
      [System.InvalidOperationException]::new($Message),
      'TypeAcceleratorAlreadyExists',
      [System.Management.Automation.ErrorCategory]::InvalidOperation,
      $Type.FullName
    ) | Write-Warning
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

$scripts = @();
$Public = Get-ChildItem "$PSScriptRoot/Public" -Filter "*.ps1" -Recurse -ErrorAction SilentlyContinue
$scripts += Get-ChildItem "$PSScriptRoot/Private" -Filter "*.ps1" -Recurse -ErrorAction SilentlyContinue
$scripts += $Public

foreach ($file in $scripts) {
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
  Cmdlet   = '*'
  Alias    = '*'
  Verbose  = $false
}
Export-ModuleMember @Param