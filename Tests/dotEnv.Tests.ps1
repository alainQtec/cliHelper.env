$ModuleName = (Get-Item $PSScriptRoot).Name
$ModulePath = [IO.Path]::Combine($PSScriptRoot, "BuildOutput", $ModuleName) | Get-Item
$moduleVersion = ((Get-ChildItem $ModulePath).Where({ $_.Name -as 'version' -is 'version' }).Name -as 'version[]' | Sort-Object -Descending)[0].ToString()
Get-Module -Name $ModuleName | Remove-Module # Make sure no versions of the module are loaded

Write-Host "[+] Import the module and store the information about the module ..." -ForegroundColor Green
$ModuleInformation = Import-Module -Name "$ModulePath" -PassThru
$ModuleInformation | Format-List

Write-Host "[+] Get all functions present in the Manifest ..." -ForegroundColor Green
$ExportedFunctions = $ModuleInformation.ExportedFunctions.Values.Name

Write-Host "[+] Get all functions present in the Public folder ..." -ForegroundColor Green
$PS1Functions = Get-ChildItem -Path "$ModulePath\$moduleVersion\Public\*.ps1"


Describe "$ModuleName Module - Testing Manifest File (.psd1)" {
  Context "Manifest" {
    It "Should contain RootModule" {
      $ModuleInformation.RootModule | Should Not BeNullOrEmpty
    }

    It "Should contain ModuleVersion" {
      $ModuleInformation.Version | Should Not BeNullOrEmpty
    }

    It "Should contain GUID" {
      $ModuleInformation.Guid | Should Not BeNullOrEmpty
    }

    It "Should contain Author" {
      $ModuleInformation.Author | Should Not BeNullOrEmpty
    }

    It "Should contain Description" {
      $ModuleInformation.Description | Should Not BeNullOrEmpty
    }

    It "Compare the count of Function Exported and the PS1 files found" {
      $status = $ExportedFunctions.Count -eq $PS1Functions.Count
      $status | Should Be $true
    }

    It "Compare the missing function" {
      If ($ExportedFunctions.count -ne $PS1Functions.count) {
        $Compare = Compare-Object -ReferenceObject $ExportedFunctions -DifferenceObject $PS1Functions.Basename
        $Compare.InputObject -Join ',' | Should BeNullOrEmpty
      }
    }
  }
}
Get-Module -Name $ModuleName | Remove-Module