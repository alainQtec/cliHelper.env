﻿<#
.SYNOPSIS
    Run Tests
.EXAMPLE
    .\Test-Module.ps1 -version 0.1.0
    Will test the module in .\BuildOutput\cliHelper.env\0.1.0\
.EXAMPLE
    .\Test-Module.ps1
    Will test the latest  module version in .\BuildOutput\cliHelper.env\
#>
[CmdletBinding()]
param (
  [Parameter(Mandatory = $false, Position = 0)]
  [Alias('Module')][string]$ModulePath = $PSScriptRoot,
  # Path Containing Tests
  [Parameter(Mandatory = $false, Position = 1)]
  [Alias('Tests')][string]$TestsPath = [IO.Path]::Combine($PSScriptRoot, 'Tests'),

  # Version string
  [Parameter(Mandatory = $false, Position = 2)]
  [ValidateScript({ if (($_ -as 'version') -is [version]) { return $true } else { throw [System.IO.InvalidDataException]::New('Please Provide a valid version') } })]
  [ArgumentCompleter({
      [OutputType([System.Management.Automation.CompletionResult])]
      param([string]$CommandName, [string]$ParameterName, [string]$WordToComplete, [System.Management.Automation.Language.CommandAst]$CommandAst, [System.Collections.IDictionary]$FakeBoundParameters)
      $CompletionResults = [System.Collections.Generic.List[System.Management.Automation.CompletionResult]]::new()
      $b_Path = [IO.Path]::Combine($PSScriptRoot, 'BuildOutput', 'cliHelper.env')
      if ((Test-Path -Path $b_Path -PathType Container -ErrorAction Ignore)) {
        [IO.DirectoryInfo]::New($b_Path).GetDirectories().Name | Where-Object { $_ -like "*$wordToComplete*" -and $_ -as 'version' -is 'version' } | ForEach-Object { [void]$CompletionResults.Add([System.Management.Automation.CompletionResult]::new($_, $_, "ParameterValue", $_)) }
      }
      return $CompletionResults
    })]
  [string]$version,
  [switch]$skipBuildOutputTest,
  [switch]$CleanUp
)

begin {
  $TestResults = $null
  # Get latest version
  if ([string]::IsNullOrWhiteSpace($version)) {
    $version = [version[]][IO.DirectoryInfo]::New([IO.Path]::Combine($PSScriptRoot, 'BuildOutput', 'cliHelper.env')).GetDirectories().Name | Select-Object -Last 1
  }
  $BuildOutDir = [IO.DirectoryInfo]::New((Resolve-Path ([IO.Path]::Combine($PSScriptRoot, 'BuildOutput', 'cliHelper.env', $version)) -ErrorAction Stop))
  $manifestFile = [IO.FileInfo]::New([IO.Path]::Combine($BuildOutDir.FullName, "cliHelper.env.psd1"))
  Write-Host "[+] Checking Prerequisites ..." -ForegroundColor Green
  if (!$BuildOutDir.Exists) {
    $msg = 'Directory "{0}" Not Found' -f ([IO.Path]::GetRelativePath($PSScriptRoot, $BuildOutDir.FullName))
    if ($skipBuildOutputTest.IsPresent) {
      Write-Warning "$msg"
    } else {
      throw [System.IO.DirectoryNotFoundException]::New($msg)
    }
  }
  if (!$skipBuildOutputTest.IsPresent -and !$manifestFile.Exists) {
    throw [System.IO.FileNotFoundException]::New("Could Not Find Module manifest File $([IO.Path]::GetRelativePath($PSScriptRoot, $manifestFile.FullName))")
  }
  if (!(Test-Path -Path $([IO.Path]::Combine($PSScriptRoot, "cliHelper.env.psd1")) -PathType Leaf -ErrorAction Ignore)) { throw [System.IO.FileNotFoundException]::New("Module manifest file Was not Found in '$($BuildOutDir.FullName)'.") }
}
process {
  Get-Module cliHelper.env | Remove-Module
  Write-Host "[+] Testing Module ..." -ForegroundColor Green
  if (!$skipBuildOutputTest.IsPresent) {
    Test-ModuleManifest -Path $manifestFile.FullName -ErrorAction Stop -Verbose
  }
  $TestResults = Invoke-Pester -Path $TestsPath -OutputFormat NUnitXml -OutputFile "$TestsPath\results.xml" -PassThru
}
end {
  return $TestResults
}