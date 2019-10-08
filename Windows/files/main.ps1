# Variables
$computerName = 'localhost1'
$currentDir = $PSScriptRoot 
#Write-Output "My directory is $currentdir"

# Create the MOFs
& $currentDir\lcmpush.ps1 $computerName $currentDir

& $currentDir\measuresconfig.ps1 $computerName $currentDir

