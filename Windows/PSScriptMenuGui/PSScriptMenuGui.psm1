# Based on: https://github.com/RamblingCookieMonster/PSStackExchange/blob/db1277453374cb16684b35cf93a8f5c97288c41f/PSStackExchange/PSStackExchange.psm1

# Get public and private function definition files
$scripts = @()
$scripts += Get-ChildItem -Path $PSScriptRoot\public\*.ps1 -ErrorAction SilentlyContinue
$scripts += Get-ChildItem -Path $PSScriptRoot\private\*.ps1 -ErrorAction SilentlyContinue

# Dot source the files
ForEach ($script in $scripts) {
    try {
        . $script.FullName
    }
    catch {
        Write-Error -Message "Failed to import function $($script.FullName): $_"
    }
}

# Used to load files from xaml subfolder
$moduleRoot = $PSScriptRoot