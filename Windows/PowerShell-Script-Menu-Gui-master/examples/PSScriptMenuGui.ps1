Set-Location $PSScriptRoot
Remove-Module PSScriptMenuGui -ErrorAction SilentlyContinue
Import-Module ..\PSScriptMenuGui
Show-ScriptMenuGui -csvPath '.\example_data.csv'