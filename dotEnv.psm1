#!/usr/bin/env pwsh
using namespace System.Management.Automation.Language
using module Private/dotEnv.Config/dotEnv.Config.psm1
using module Private/dotEnv.Common/dotEnv.Common.psm1
using module Private/dotEnv.Crypto/dotEnv.Crypto.psm1

#region    Classes
#Requires -Version 7
# .SYNOPSIS
#  Module main class
# .EXAMPLE
#  $value = [dotEnv]::Get("NEXT_PUBLIC_MTN_API_ENVIRONMENT")
class dotEnv : EnvTools {
  [EnvCfg] $config
  static hidden $X509CertHelper
  [System.Security.Cryptography.X509Certificates.X509Certificate2] $Cert
  static hidden [string]$VarName_Suffix = '7fb2e877_6c2b_406a_af40_e1d915c62cdf'
  static [bool] $useDebug = (Get-Variable DebugPreference -ValueOnly) -eq 'Continue'
  static [ValidateNotNullOrEmpty()][string]$path = [IO.Path]::Combine((Get-Location), ".env")
  # static hidden [ValidateNotNullOrEmpty()][string]$path_Secure = (Resolve-Path ./.env.secure -ea Ignore).Path
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