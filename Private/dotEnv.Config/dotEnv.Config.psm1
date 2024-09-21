#!/usr/bin/env pwsh
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
class EnvCfg : CfgList {
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
  param (

  )

  begin {
  }

  process {
    if ($PSCmdlet.ShouldProcess("Localhost", "Initialize dotEnv")) {
      # do stuff here
      # Write-Host "Hello from Private/dotEnv.Config/Set-dotEnvConfig" -f Green
    }
  }

  end {
  }
}