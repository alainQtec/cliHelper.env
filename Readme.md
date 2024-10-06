# [cliHelper.env](dotEnv)

A module for reading and editing `.env` values. & has
[`extra security`](/docs/Readme.md#security-best-practices) cmdlets.

## install

```PowerShell
Install-Module cliHelper.env
```

## usage

0-risk editing environment variables

<!--
recomended vscode extensions
temitope1909.dotenv-intellisense
 -->

- **Security**:

  Environment variables can be easily accessed by anyone who has access to the
  system. This can lead to security breaches if sensitive information is stored
  in environment variables. This module has cmdlets to create
  [encrypted Enviromment variables](https://github.com/alainQtec/cliHelper.env/wiki#enc)

- **Debugging**:

  Debugging issues can arise when environment variables are not set correctly or
  when they are not being passed correctly between different parts of the
  system.

- **Performance**:

  Cmdlets are benchmarked during tests to make sure they will not slow down the
  system.

example:

```PowerShell
# Import the module
Import-Module cliHelper.env

# sick usage examples go here ...
```

## TODOs

- [ ] Complete Protect-Env & UnProtect-Env
- [x] Update build script
- [ ] Add fancy cli. ex animations, progressbar & logging
- [x] Add tests
- [ ] Add zstandard compression
- [ ] complete the docs

## license

This module is licensed under the
[MIT License](https://alainQtec.MIT-license.org).
