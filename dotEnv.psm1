#!/usr/bin/env pwsh
using namespace System.Management.Automation.Language
using module Private/dotEnv.Crypto/dotEnv.Crypto.psm1
using module Private/dotEnv.Utils/dotEnv.Utils.psm1

#region    Classes
#Requires -Version 7
# .SYNOPSIS
#  Module main class
class dotEnv : EnvTools {
  dotEnv() { [dotEnv]::SetEnvFile() }
  static [string] Get([string]$key) {
    [ValidateNotNullOrEmpty()][string]$key = $key
    return [dotEnv]::Read([dotEnv].EnvFile).Where({ $_.Name -eq $key }).Value
  }
  static [dotEntry[]] Read([string]$EnvFile) {
    [ValidateNotNullOrEmpty()][string]$EnvFile = $(Resolve-Path $EnvFile -ea Ignore).Path
    $res_Obj = @(); $content = [IO.File]::ReadAllLines($EnvFile)
    if ([string]::IsNullOrWhiteSpace($content)) {
      [dotEnv]::Log("The .env file is empty!");
      return $res_Obj
    }
    foreach ($line in $content) {
      if ([string]::IsNullOrWhiteSpace($line)) { continue }
      if ($line.StartsWith("#") -or $line.StartsWith("//")) {
        [dotEnv]::Log("~ comment: $([dotEnv]::sensor($line))");
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
  static [void] Update([IO.File]$EnvFile, [string]$Name, [string]$Value) {
    [dotEnv]::Update($EnvFile, $Name, $Value, $false)
  }
  static [void] Update([IO.File]$EnvFile, [string]$Name, [string]$Value, [bool]$StripComments) {
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
        throw [System.Exception]::new("key: $Name not found.")
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
}

#endregion Classes

#region typeAccelerators
# Types that will be available to users when they import the module.
$typestoExport = @(
  [dotEnv],
  [UserConfig],
  [ProjectConfig]
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

#endregion typeAccelerators

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