﻿$ModuleName = (Get-Item $PSScriptRoot).Name
$ModulePath = [IO.Path]::Combine($PSScriptRoot, "BuildOutput", $ModuleName) | Get-Item
$ProjectName = [Environment]::GetEnvironmentVariable($env:RUN_ID + 'ProjectName')
$moduleVersion = ((Get-ChildItem $ModulePath).Where({ $_.Name -as 'version' -is 'version' }).Name -as 'version[]' | Sort-Object -Descending)[0].ToString()
Get-Module -Name $ModuleName | Remove-Module # Make sure no versions of the module are loaded

Write-Host "[+] Import the module and store the information about the module ..." -ForegroundColor Green
$ModuleInformation = Import-Module -Name "$ModulePath" -PassThru
$ModuleInformation | Format-List

Write-Host "[+] Get all functions present in the Manifest ..." -ForegroundColor Green
$ExportedFunctions = $ModuleInformation.ExportedFunctions.Values.Name

Write-Host "[+] Get all functions present in the Public folder ..." -ForegroundColor Green
$PS1Functions = Get-ChildItem -Path "$ModulePath\$moduleVersion\Public\*.ps1"


Describe "Module tests: $ProjectName" -Tag 'Module' {
  Context " Confirm valid Manifest file" {
    It "Should contain RootModule" {
      $ModuleInformation.RootModule | Should -Not -BeNullOrEmpty
    }

    It "Should contain ModuleVersion" {
      $ModuleInformation.Version | Should -Not -BeNullOrEmpty
    }

    It "Should contain GUID" {
      $ModuleInformation.Guid | Should -Not -BeNullOrEmpty
    }

    It "Should contain Author" {
      $ModuleInformation.Author | Should -Not -BeNullOrEmpty
    }

    It "Should contain Description" {
      $ModuleInformation.Description | Should -Not -BeNullOrEmpty
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
  Context " Confirm files are valid Powershell syntax" {
    $_scripts = $(Get-Item -Path "$ModulePath/$moduleVersion").GetFiles(
      "*", [System.IO.SearchOption]::AllDirectories
    ).Where({ $_.Extension -in ('.ps1', '.psd1', '.psm1') })
    $testCase = $_scripts | ForEach-Object { @{ file = $_ } }
    It "Script <file> Should have valid Powershell sysntax" -TestCases $testCase {
      param($file) $contents = Get-Content -Path $file.fullname -ErrorAction Stop
      $errors = $null; [void][System.Management.Automation.PSParser]::Tokenize($contents, [ref]$errors)
      $errors.Count | Should -Be 0
    }
  }
  Context " Confirm there are no duplicate function names in private and public folders" {
    It ' Should have no duplicate functions' {
      $Publc_Dir = Get-Item -Path ([IO.Path]::Combine("$ModulePath/$moduleVersion", 'Public'))
      $Privt_Dir = Get-Item -Path ([IO.Path]::Combine("$ModulePath/$moduleVersion", 'Private'))
      $funcNames = @(); Test-Path -Path ([string[]]($Publc_Dir, $Privt_Dir)) -PathType Container -ErrorAction Stop
      $Publc_Dir.GetFiles("*", [System.IO.SearchOption]::AllDirectories) + $Privt_Dir.GetFiles("*", [System.IO.SearchOption]::AllDirectories) | Where-Object { $_.Extension -eq '.ps1' } | ForEach-Object { $funcNames += $_.BaseName }
      $($funcNames | Group-Object | Where-Object { $_.Count -gt 1 }).Count | Should -BeLessThan 1
    }
  }
}
Describe "Integration tests:$ProjectName" {
  BeforeAll {
    $testEnvFile = "TestEnv.env"
    "TEST_KEY1=value1`nTEST_KEY2=value2" | Set-Content $testEnvFile
  }
  AfterAll {
    Remove-Item $testEnvFile -ErrorAction SilentlyContinue
  }
  Context " Reading and writing .env files" {
    It "Should read an existing .env file" {
      $env = Read-Env -Path $testEnvFile
      $env | Should -BeOfType [dotEnv]
      $env.TEST_KEY1 | Should -Be "value1"
      $env.TEST_KEY2 | Should -Be "value2"
    }
    It "Should write changes to .env file" {
      $env = Read-Env -Path $testEnvFile
      $env.TEST_KEY1 = "new_value1"
      Write-Env -dotEnv $env -Path $testEnvFile

      $newEnv = Read-Env -Path $testEnvFile
      $newEnv.TEST_KEY1 | Should -Be "new_value1"
    }
  }
  Context " Modifying system environment variables" {
    It "Should set a system environment variable" {
      Add-Env -Name "TEST_SYSTEM_VAR" -Value "test_value"
      [Environment]::GetEnvironmentVariable("TEST_SYSTEM_VAR") | Should -Be "test_value"
    }
    It "Should remove a system environment variable" {
      Remove-Env -Name "TEST_SYSTEM_VAR"
      [Environment]::GetEnvironmentVariable("TEST_SYSTEM_VAR") | Should -BeNullOrEmpty
    }
  }
}
Describe "Feature tests: $ProjectName" {
  BeforeAll {
    $testEnvFile = "TestEnv.env"
    "TEST_KEY1=value1`nTEST_KEY2=value2" | Set-Content $testEnvFile
  }
  AfterAll {
    Remove-Item $testEnvFile -ErrorAction SilentlyContinue
  }
  Context " Add-Env" {
    It "Should add a new environment variable" {
      Add-Env -Name "NEW_VAR" -Value "new_value" -Path $testEnvFile
      $env = Read-Env -Path $testEnvFile
      $env.NEW_VAR | Should -Be "new_value"
    }
  }
  Context " Get-Env" {
    It "Should retrieve an environment variable" {
      $value = Get-Env -Name "TEST_KEY1" -Path $testEnvFile
      $value | Should -Be "value1"
    }
  }
  Context " Get-EnvFile" {
    It "Should return the path of the .env file" {
      $path = Get-EnvFile
      $path | Should -Exist
    }
  }
  Context " Protect-Env and Unprotect-Env functions" {
    It "Should protect and unprotect .env file" {
      Protect-Env -Path $testEnvFile
      $content = Get-Content $testEnvFile -Raw
      $content | Should -Not -Match "TEST_KEY1=value1"

      Unprotect-Env -Path $testEnvFile
      $content = Get-Content $testEnvFile -Raw
      $content | Should -Match "TEST_KEY1=value1"
    }
  }
  Context " Remove-Env function" {
    It "Should remove an environment variable" {
      Remove-Env -Name "TEST_KEY2" -Path $testEnvFile
      $env = Read-Env -Path $testEnvFile
      $env.TEST_KEY2 | Should -BeNullOrEmpty
    }
  }
  Context " Update-SessionEnv function" {
    It "Should update the current session with .env variables" {
      $env:TEST_SESSION_VAR = $null
      "TEST_SESSION_VAR=session_value" | Add-Content $testEnvFile
      Update-SessionEnv -Path $testEnvFile
      $env:TEST_SESSION_VAR | Should -Be "session_value"
    }
  }
  Context " Write-Env function" {
    It "Should write changes to .env file" {
      $env = [dotEnv]::new()
      $env.NEW_KEY = "new_value"
      Write-Env -dotEnv $env -Path $testEnvFile
      $newEnv = Read-Env -Path $testEnvFile
      $newEnv.NEW_KEY | Should -Be "new_value"
    }
  }
}