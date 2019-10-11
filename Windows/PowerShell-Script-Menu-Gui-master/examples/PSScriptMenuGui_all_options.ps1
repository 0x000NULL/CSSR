Set-Location $PSScriptRoot
Remove-Module PSScriptMenuGui -ErrorAction SilentlyContinue
Import-Module ..\PSScriptMenuGui
$params = @{
    csvPath = '.\example_data.csv'
    windowTitle = 'Example with all options'
    buttonForegroundColor = 'Azure'
    buttonBackgroundColor = '#C00077'
    iconPath = '.\pwsh7.ico'
    hideConsole = $true
    noExit = $true
}
Show-ScriptMenuGui @params