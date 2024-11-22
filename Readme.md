## [cliHelper.env](dotEnv)

[result] by using [feature] for [whom]

A module for reading and editing `.env` values. & has
[`extra security`](/docs/Readme.md#security-best-practices) cmdlets.

[![CI](https://github.com/alainQtec/cliHelper.env/actions/workflows/CI.yaml/badge.svg)](https://github.com/alainQtec/cliHelper.env/actions/workflows/CI.yaml)

## install

```PowerShell
Install-Module cliHelper.env
```

## usage

demo :

<!-- thumbnail : http://i.ytimg.com/vi/$Id/hqdefault.jpg -->
<!-- ex: id is YuCyE8HiLTY in https://www.youtube.com/watch?v=YuCyE8HiLTY -->

<div style="position: relative; width: 100%; padding-bottom: 56.25%">
<iframe src="https://www.youtube.com/embed/jgEYn-ldr30"
        title="Web Load Testing with West Wind WebSurge 2" frameborder="0" allowfullscreen
        allow="accelerometer; autoplay; clipboard-write; encrypted-media; gyroscope; picture-in-picture"
        style="position: absolute; width: 100%; height: 100%; border-radius:15px;">
</iframe>
</div>
</br>

Notes:

_Its recomended to use with vscode extensions temitope1909.dotenv-intellisense_

0-risk editing environment variables

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
