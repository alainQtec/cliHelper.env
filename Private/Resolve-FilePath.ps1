function Resolve-FilePath {
  # .SYNOPSIS
  #     Resolve FilePath
  # .DESCRIPTION
  #     Gets the full Path of any file in a repo
  # .INPUTS
  #     [string[]]
  # .OUTPUTS
  #     [String[]]
  # .EXAMPLE
  #     Resolve-FilePath * -Extensions ('.ps1', '.psm1')
  #     Will get paths of powershell files in current location; thus [ModuleX]::ParseFile("*") will parse any powershell file in current location.
  # .EXAMPLE
  #     Resolve-FilePath "Tests\Resources\Test-H*", "Tests\Resources\Test-F*"
  # .EXAMPLE
  #     Resolve-FilePath ..\*.Tests.ps1
  # .NOTES
  #     Created to work with the "ModuleX" module. (Its not tested for other use cases)
  #     TopLevel directory search takes Priority.
  #         eg: Resolve-FilePath ModuleX.ps1 will return ./.env instead of ./BuildOutput/module/0.1.1/.env
  #             Unless ./.env doesn't exist; In that case it will Recursively search for other Names in the repo.
  # .LINK
  #     https://github.com/alainQtec/cliHelper.env/blob/main/Private/Resolve-FilePath.ps1
  #
  [CmdletBinding(DefaultParameterSetName = 'Query')]
  [OutputType([System.Object[]])]
  param (
    [Parameter(Mandatory = $true, Position = 0, ValueFromPipeline = $true, ValueFromPipelineByPropertyName = $true, ParameterSetName = 'Query')]
    [ValidateNotNullOrEmpty()]
    [Alias('Path')]
    [string]$Query,

    [Parameter(Mandatory = $true, Position = 0, ValueFromPipeline = $true, ParameterSetName = 'Paths')]
    [ValidateNotNullOrEmpty()]
    [string[]]$Paths,

    [Parameter(Mandatory = $false, Position = 1, ValueFromPipeline = $false, ParameterSetName = '__AllParameterSets')]
    [ValidateNotNullOrEmpty()]
    [Alias('Extension')]
    [string[]]$Extensions,

    [Parameter(Mandatory = $false, Position = 2, ValueFromPipeline = $false, ParameterSetName = '__AllParameterSets')]
    [string[]]$Exclude,

    [switch]$throwOnFailure,

    [switch]$NoAmbiguous
  )

  begin {
    $pathsToSearch = @(); $resolved = @(); $error_Msg = $null; $throwOnFailure = [string]$ErrorActionPreference -eq 'Stop'
    $pathsToSearch += if ($PSCmdlet.ParameterSetName.Equals('Query')) { @($Query) } else { $Paths }
    $GitHubRoot = $(if (Get-Command -Name git -CommandType Application -ErrorAction Ignore) { git rev-parse --show-toplevel }else { $null }) -as [IO.DirectoryInfo]
    $GetFiles = [scriptblock]::Create({
        param ([Parameter(Mandatory)][string]$qr)
        $f = Get-ChildItem -Path $qr -File -ErrorAction Ignore
        if ($PSBoundParameters.ContainsKey('Extensions')) {
          return ($Files | Where-Object { $_.Extension -in $Extensions })
        }; return $f
      }
    )
    [string[]]$Exclude = [IO.File]::ReadAllLines([IO.Path]::Combine($ExecutionContext.SessionState.Path.CurrentLocation, '.gitignore')).Where({ !$_.StartsWith('#') -and ![string]::IsNullOrWhiteSpace($_) })
  }
  process {
    forEach ($p in $pathsToSearch) {
      if ([Regex]::IsMatch($p, '^https?:\/\/[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}(:[0-9]+)?\/?.*$')) { $error_Msg += " '$p' is a Url! Please provide a valid File Path."; continue }
      # TopLevel directory search:
      $rslvdPaths, $error_Msg = $validPaths, $null
      [string[]]$rslvdPaths = (Resolve-Path $p -ErrorAction Ignore).Path
      [string[]]$validPaths = ($rslvdPaths | Where-Object { (Test-Path -Path "$_" -PathType Any -ErrorAction Ignore) })
      if ($validPaths.Count -gt 1 -and $NoAmbiguous) { $error_Msg += "Path '$p' is ambiguous: $($validPaths -join ', ')" }
      $Files = $GetFiles.Invoke($p); if ($Files.FullName) { $resolved += $Files.FullName; Continue }
      $q = $p; $p = $ExecutionContext.SessionState.Path.GetUnresolvedProviderPathFromPSPath($p);
      if ((Test-Path -Path $GitHubRoot.FullName -PathType Container -ErrorAction Ignore)) {
        $rslvdPaths = $( # Multi-Level directory search / -Recurse :
          switch ($true) {
                        ([IO.Path]::IsPathFullyQualified($q)) {
              Get-Item -Path $q -ErrorAction Ignore
              break
            }
            $(![IO.Path]::IsPathFullyQualified($q) -and $q.Contains([IO.Path]::DirectorySeparatorChar)) {
              $relPath = '([IO.Path]::GetRelativePath($ExecutionContext.SessionState.Path.CurrentLocation, $_.FullName))'
              $IsMatch = if ($q.Contains('*')) {
                [scriptblock]::Create("$relPath -like `"$q`" -or `$_.FullName -like `"$q`"")
              } elseif ($q.EndsWith([IO.Path]::DirectorySeparatorChar)) {
                [scriptblock]::Create("$relPath -like `"$q*`" -or `$_.FullName -like `"$q*`"")
              } else {
                [scriptblock]::Create("$relPath -eq `"$q`" -or `$_.FullName -eq `"$q`"")
              }
              $(Get-ChildItem -Path $GitHubRoot.FullName -File -Recurse -ErrorAction Ignore).Where($IsMatch)
              break
            }
            $(![IO.Path]::IsPathFullyQualified($q) -and !$q.Contains([IO.Path]::DirectorySeparatorChar)) {
              $IsMatch = if ($q.Contains('*')) { [scriptblock]::Create('$_.Name -like $q -or $_.BaseName -like $q') } else { [scriptblock]::Create('$_.Name -eq $q -or $_.BaseName -eq $q') }
              $(Get-ChildItem -Path $GitHubRoot.FullName -File -Recurse -ErrorAction Ignore).Where($IsMatch)
              break
            }
            Default {
              Get-ChildItem -Path $GitHubRoot.FullName -File -Recurse -Filter $q -ErrorAction Ignore
            }
          }
        ) | Select-Object -ExpandProperty FullName
      }; if (!$rslvdPaths) { $error_Msg += "No files were found in Path '$p'."; Continue }
      $resolved += $rslvdPaths
    }
    $resolved = $resolved | Sort-Object -Unique
    if ($PSBoundParameters.ContainsKey('Extensions')) { $resolved = $($resolved -as [IO.FileInfo[]] | Where-Object { $_.Extension -in $Extensions }).FullName }
    if ($resolved.Count -gt 1 -and $NoAmbiguous) {
      $error_Msg += ' Error: Resolved to Multiple paths'
    }
  }

  end {
    if ($error_Msg) {
      if ($throwOnFailure) {
        $PSCmdlet.ThrowTerminatingError(
          [System.Management.Automation.ErrorRecord]::New(
            [System.Management.Automation.ItemNotFoundException]::new($error_Msg), 'ItemNotFoundException', 'OperationStopped', [PSCustomObject]@{
              Params = $PSCmdlet.MyInvocation.BoundParameters
            }
          )
        )
      } else {
        Write-Verbose $error_Msg
      }
    }
    return $resolved
  }
}