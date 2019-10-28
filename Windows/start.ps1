Set-Location $PSScriptRoot
Remove-Module PSScriptMenuGui -ErrorAction SilentlyContinue
Import-Module \SScriptMenuGui\
Show-ScriptMenuGui -csvPath '.\example_data.csv'