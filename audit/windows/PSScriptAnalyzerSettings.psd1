@{
    Severity     = @('Error', 'Warning')
    ExcludeRules = @(
        # Colored console output is the point of the script; the JSON report is the
        # machine-readable output.
        'PSAvoidUsingWriteHost',
        # New-Result only builds an object; it changes no system state.
        'PSUseShouldProcessForStateChangingFunctions'
    )
}
