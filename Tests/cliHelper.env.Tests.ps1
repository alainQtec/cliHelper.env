$script:ModuleName = "cliHelper.env"
$script:ProjectRoot = switch ((Get-Item $PSScriptRoot).BaseName) {
  $ModuleName { $PSScriptRoot; break }
  "Tests" { [IO.Path]::GetDirectoryName($PSScriptRoot); break }
  Default {
    throw "can't resolve project root"
  }
}
Write-Host "[+] ProjectRoot: $ProjectRoot" -f Green
$script:ModulePath = [IO.Path]::Combine($ProjectRoot, "BuildOutput", $ModuleName) | Get-Item
$script:ProjectName = [Environment]::GetEnvironmentVariable($env:RUN_ID + 'ProjectName')
$script:moduleVersion = ((Get-ChildItem $ModulePath).Where({ $_.Name -as 'version' -is 'version' }).Name -as 'version[]' | Sort-Object -Descending)[0].ToString()
$script:ModuleInformation = Import-Module -Name "$ModulePath" -PassThru -Verbose:$false
Write-Host "[+] Imported module:" -ForegroundColor Green
$ModuleInformation | Format-List | Out-String | Write-Host -f Green
$envFile = [IO.Path]::Combine($ProjectRoot, '.env')
if ([IO.File]::Exists($envFile)) {
  Write-Host "[+] Load .env file ..." -ForegroundColor Green
  [void](Read-Env $envFile)
}
Write-Host "[+] Get all functions present in the Manifest ..." -ForegroundColor Green
$ExportedFunctions = $ModuleInformation.ExportedFunctions.Values.Name
Write-Host "[+] Get all functions present in the Public folder ..." -ForegroundColor Green
$PS1Functions = Get-ChildItem -Path "$ModulePath/$moduleVersion/Public/*.ps1"

Describe "Module tests for $ProjectName" -Tag 'Module' {
  Context " Manifest file" {
    It " Should contain RootModule" {
      [string]::IsNullOrWhiteSpace($ModuleInformation.RootModule) | Should -Be $false
    }

    It " Should contain ModuleVersion" {
      [string]::IsNullOrEmpty($ModuleInformation.Version.ToString()) | Should -Be $false
    }

    It " Should contain GUID" {
      $ModuleInformation.Guid | Should -Not -BeNullOrEmpty
    }

    It " Should contain Author" {
      $ModuleInformation.Author | Should -Not -BeNullOrEmpty
    }

    It " Should contain Description" {
      $ModuleInformation.Description | Should -Not -BeNullOrEmpty
    }

    It " Compare the count of Function Exported and the PS1 files found" {
      $status = $PS1Functions.Count -eq $ExportedFunctions.Count
      $status | Should -Be $true
    }

    It " Compare the missing function" {
      If ($ExportedFunctions.count -ne $PS1Functions.count) {
        $Compare = Compare-Object -ReferenceObject $ExportedFunctions -DifferenceObject $PS1Functions.Basename
        $Compare.InputObject -Join ',' | Should -BeNullOrEmpty
      }
    }
  }
  Context " Powershell syntax" {
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
  Context " Private and public folders" {
    It ' Should have no duplicate functions' {
      $Publc_Dir = Get-Item -Path ([IO.Path]::Combine($ModulePath, $moduleVersion, 'Public'))
      $Privt_Dir = Get-Item -Path ([IO.Path]::Combine($ModulePath, $moduleVersion, 'Private'))
      $funcNames = @(); Test-Path -Path ([string[]]($Publc_Dir, $Privt_Dir)) -PathType Container -ErrorAction Stop
      $Publc_Dir.GetFiles("*", [System.IO.SearchOption]::AllDirectories) + $Privt_Dir.GetFiles("*", [System.IO.SearchOption]::AllDirectories) | Where-Object { $_.Extension -eq '.ps1' } | ForEach-Object { $funcNames += $_.BaseName }
      $($funcNames | Group-Object | Where-Object { $_.Count -gt 1 }).Count | Should -BeLessThan 1
    }
  }
}
Describe "Integration tests for $ProjectName" {
  BeforeAll {
    $testEnvFile = New-Item $([IO.Path]::GetTempFileName().Replace('.tmp', '.env.test'));
    [IO.File]::WriteAllLines($testEnvFile.FullName, ("TEST_KEY1=value1", "TEST_KEY2=value2"))
  }
  AfterAll {
    Remove-Item $testEnvFile -ErrorAction SilentlyContinue
  }
  Context " Reading and writing .env files" {
    It " Should read an existing .env file" {
      $env = Read-Env $testEnvFile
      $env[0].Value | Should -Be "value1"
      $env[1].Value | Should -Be "value2"
    }
    It " Should write changes to .env file" {
      Write-Env -Path $testEnvFile.FullName -Name "NUMS" -Value "123456"
      $newEnv = Read-Env -Path $testEnvFile
      $newEnv.Where({ $_.Name -eq "NUMS" }).value | Should -Be "123456"
    }
  }
  Context " Modifying system environment variables" {
    It " Add-Env should set/Add an environment variable" {
      Add-Env -Name "TEST_SYSTEM_VAR" -Value "test_value"
      [Environment]::GetEnvironmentVariable("TEST_SYSTEM_VAR") | Should -Be "test_value"
    }
    It " Remove-Env Should remove an environment variable" {
      Remove-Env -Name "TEST_SYSTEM_VAR"
      [Environment]::GetEnvironmentVariable("TEST_SYSTEM_VAR") | Should -BeNullOrEmpty
    }
  }
}
Describe "Feature tests for $ProjectName" {
  BeforeAll {
    $testEnvFile = New-Item $([IO.Path]::GetTempFileName().Replace('.tmp', '.env.test'));
    "TEST_KEY1=value1`nTEST_KEY2=value2" | Set-Content $testEnvFile
  }
  AfterAll {
    Remove-Item $testEnvFile -ErrorAction SilentlyContinue
  }
  Context " Add-Env" {
    It "Should add a new environment variable" {
      Add-Env -Name "NEW_VAR" -Value "new_value" -OutFile $testEnvFile
      $env = Read-Env -Path $testEnvFile
      $env.where({ $_.Name -like "NEW_VAR" }).value | Should -Be "new_value"
    }
  }
  # TODO: Add real feature tests not these chatgpity generated ones :D
  # Context " Get-Env" {
  #   It "Should retrieve an environment variable" {
  #     $value = Get-Env -Name "TEST_KEY1" -Path $testEnvFile
  #     $value | Should -Be "value1"
  #   }
  # }
  # Context " Get-EnvFile" {
  #   It "Should return the path of the .env file" {
  #     $path = Get-EnvFile
  #     $path | Should -Exist
  #   }
  # }
  # Context " Protect-Env and Unprotect-Env functions" {
  #   It "Should protect and unprotect .env file" {
  #     Protect-Env -Path $testEnvFile
  #     $content = Get-Content $testEnvFile -Raw
  #     $content | Should -Not -Match "TEST_KEY1=value1"
  #     Unprotect-Env -Path $testEnvFile
  #     $content = Get-Content $testEnvFile -Raw
  #     $content | Should -Match "TEST_KEY1=value1"
  #   }
  # }
  # Context " Remove-Env" {
  #   It "Should remove an environment variable" {
  #     Remove-Env -Name "TEST_KEY2" -Path $testEnvFile
  #     $env = Read-Env -Path $testEnvFile
  #     $env.TEST_KEY2 | Should -BeNullOrEmpty
  #   }
  # }
  # Context " Update-SessionEnv" {
  #   It "Should refresh the current session with any new .env variables" {
  #     $env:TEST_SESSION_VAR = $null
  #     "TEST_SESSION_VAR=session_value" | Add-Content $testEnvFile
  #     Update-SessionEnv -Path $testEnvFile
  #     $env:TEST_SESSION_VAR | Should -Be "session_value"
  #   }
  # }
  # Context " Write-Env" {
  #   It "Should write changes to .env file" {
  #     $env = [dotEnv]::new()
  #     $env.NEW_KEY = "new_value"
  #     Write-Env -dotEnv $env -Path $testEnvFile
  #     $newEnv = Read-Env -Path $testEnvFile
  #     $newEnv.NEW_KEY | Should -Be "new_value"
  #   }
  # }
}