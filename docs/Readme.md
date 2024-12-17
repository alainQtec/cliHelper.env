# Docs

... Using Environment variables can cost you if you're not diligent.

## **Security best practices**

Here are some tips to handle environment variables on different platforms
without facing security issues:

- **Do not share your environment variables**: Environment variables can contain
  sensitive information such as passwords and API keys. It is important to keep
  them private and not share them with others.

- **Do not keep the variables inside your code**: Hardcoding environment
  variables inside your code can make it difficult to manage them. Instead, you
  can use a `.env` file to store your environment variables.

- **Use a secure vault for encryption and decryption of your secret
  information**: You can use a secure vault such as
  [HashiCorp Vault](https://www.vaultproject.io/) or
  [AWS Secrets Manager](https://aws.amazon.com/secrets-manager/) to store your
  secrets.

- **Do not commit your environment variables to version controls like git**:
  Committing environment variables to version control systems like Git can
  expose them to others. Instead, you can use a `.gitignore` file to exclude
  them from version control.

## **Compatibility best practices**

Here are some tips to handle environment variables on different platforms
without facing compatibility issues:

- **Use cross-platform scripting**: Cross-platform scripting can help you write
  scripts that work on different platforms. You can use tools like
  [Azure Pipelines](https://learn.microsoft.com/en-us/azure/devops/pipelines/scripts/cross-platform-scripting?view=azure-devops)
  to write cross-platform scripts.

- **Use a `.env` file**: You can use a `.env` file to store your environment
  variables. This file can be read by different platforms.

- **Use your deployment platform’s variable storage**: Most deployment
  environments such as Heroku, AWS, Netlify, etc., provide a space for users to
  upload secrets which are later injected into the runtime of your application.

## **Testing locally**

When you want to test stuff before pushing to remote.

<details>
  <summary>Step(1): Try any new changes you made before commit.</summary>

⤷ **& preBuild.ps1**

- Create `preBuild.ps1` and paste the following script

```PowerShell
Write-Host "[+] Test Module Import ..." -f Green
[IO.Path]::Combine((Split-Path $MyInvocation.MyCommand.Path),"cliHelper.env.psm1") | Import-Module
Write-Host "    Done." -f DarkGreen
# Do other stuff with the module ...
```

- Run the script

```PowerShell
./preBuild.ps1
```

If everything works fine, then you can build the module.

</details>

<details>
  <summary>Step(2): Build the
module.</summary>

⤷ **Run the build script and tests.**

run

```PowerShell
./build.ps1 -Task test
```

If tests (Intergration, Freature and module tests) pass, then create your pull
request.

Deploying:

```PowerShell
./build.ps1 -Task Deploy
```

Commit with message: !deploy and thats it.

</details>

<details>
  <summary>Step(3): Commit && create a PR.</summary>

⤷ **You already know how to do this step.**

Remember to follow the contribution guidelines.

</details>

## **CI/CD**

...

## contribution guidelines

- No long names. ex: ex:
  `Get-MgEntitlementManagementResourceRequestCatalogResourceScopeResourceRoleResourceEnvironment`

  (from `Microsoft.Graph.Identity.Governance` 2.23.0)
