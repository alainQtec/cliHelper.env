#!/usr/bin/env pwsh
using namespace System.Management.Automation.Language
using module Private/dotEnv.Common/dotEnv.Common.psm1
using module Private/dotEnv.Crypto/dotEnv.Crypto.psm1

#region    Classes
#Requires -Version 7
# .SYNOPSIS
#  Module main class
# .EXAMPLE
#  $value = [dotEnv]::Get("NEXT_PUBLIC_MTN_API_ENVIRONMENT")
class dotEnv : EnvTools {
  static [ValidateNotNullOrEmpty()][string]$path = [IO.Path]::Combine((Get-Location), ".env")
  static hidden [ValidateNotNullOrEmpty()][string]$path_Secure = [IO.Path]::Combine((Get-Location), ".env.secure")
  dotEnv() {}

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
}

#endregion Classes

#region typeAccelerators
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