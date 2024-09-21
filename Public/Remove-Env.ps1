function Remove-Env {
    <#
    .SYNOPSIS
        **NOTE:** Administrative Access Required when `-VariableType 'Machine'.`

        Removes a persistent environment variable.

    .DESCRIPTION
        Removes an environment variable
        with the specified name and value. The variable can be scoped either to
        the User or to the Machine. If Machine level scoping is specified, the
        command is elevated to an administrative session.

    .INPUTS
        None

    .OUTPUTS
        None

    .PARAMETER VariableName
        The name or key of the environment variable to remove.

    .PARAMETER VariableType
        Specifies whether this variable is at either the individual User level
        or at the Machine level.

    .PARAMETER IgnoredArguments
        Allows splatting with arguments that do not apply. Do not use directly.

    .EXAMPLE
        >
        # Remove an environment variable
        Remove-Env -VariableName 'bob'

    .EXAMPLE
        >
        # Remove an environment variable from Machine
        Remove-Env -VariableName 'bob' -VariableType 'Machine'

    #>
    [CmdletBinding(SupportsShouldProcess = $true)]
    param(
        [parameter(Mandatory = $true, Position = 0)]
        [string]$variableName,

        [parameter(Mandatory = $false, Position = 1)]
        [System.EnvironmentVariableTarget]$variableType = [System.EnvironmentVariableTarget]::User,

        [parameter(ValueFromRemainingArguments = $true)]
        [Object[]]$ignoredArguments
    )

    # Log Invocation  and Parameters used. $MyInvocation, $PSBoundParameters
    $fxn = ('[' + $MyInvocation.MyCommand.Name + ']')

    [bool]$IsAdmin = $((New-Object Security.Principal.WindowsPrincipal $([Security.Principal.WindowsIdentity]::GetCurrent())).IsInRole([Security.Principal.WindowsBuiltinRole]::Administrator));
    if ($variableType -eq [System.EnvironmentVariableTarget]::Machine) {
        if ($IsAdmin) {
            Add-Env -Name $variableName -Value $null -Scope $variableType
        } else {
            Write-Warning "$fxn : [!]  It seems You're not Admin [!] "
            $psArgs = "Add-Env -Name `'$variableName`' -Value $null -variableType `'$variableType`'"
            Start-ProcessAsAdmin "$psArgs"
        }
    } else {
        Add-Env -Name $variableName -Value $null -Scope $variableType
    }

    Set-Content Env:\$variableName $null
}