function Set-EnvConfig {
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
  param ()

  process {
    if ($PSCmdlet.ShouldProcess("Localhost", "Initialize dotEnv")) {
      # do stuff here
      # Write-Host "Hello from Private/cliHelper.env.Config/Set-dotEnvConfig" -f Green
      # [dotEnv]::config.Set("Path", (CryptoBase)::GetUnResolvedPath([IO.Path]::Combine([dotEnv]::DataPath, "Config.enc")))
    }
  }

  end {
  }
}