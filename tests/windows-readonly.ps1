# Smoke test for audit/windows/CSSR-Audit.ps1. Run elevated (GitHub-hosted runners are).
# Checks that the audit runs, exits 0 or 1, writes valid JSON with one result per check and
# no crashed checks, and leaves policy, firewall, services and accounts unchanged.
$ErrorActionPreference = 'Stop'
$root = Split-Path -Parent $PSScriptRoot
$audit = Join-Path $root 'audit\windows\CSSR-Audit.ps1'
$work = Join-Path $env:TEMP ("cssr-test-{0}" -f [guid]::NewGuid())
New-Item -ItemType Directory -Path $work | Out-Null

function Get-StateSnapshot {
    $inf = Join-Path $work 'secpol.inf'
    & secedit.exe /export /cfg $inf /quiet | Out-Null
    $policy = Get-Content -LiteralPath $inf | Where-Object { $_ -notmatch '^\s*(Unicode|signature|Revision)\s*=' }
    Remove-Item -LiteralPath $inf -Force
    [ordered]@{
        policy   = $policy -join "`n"
        audit    = (& auditpol.exe /get /category:* /r) -join "`n"
        firewall = (Get-NetFirewallProfile | ForEach-Object { "$($_.Name):$($_.Enabled):$($_.DefaultInboundAction)" }) -join ';'
        services = (Get-CimInstance Win32_Service | Sort-Object Name | ForEach-Object { "$($_.Name)=$($_.StartMode)" }) -join ';'
        users    = (Get-LocalUser | Sort-Object Name | ForEach-Object { "$($_.Name):$($_.Enabled)" }) -join ';'
    }
}

try {
    $before = Get-StateSnapshot
    $json = Join-Path $work 'report.json'
    & $audit -NoColor -UsersFile (Join-Path $root 'audit\examples\users.txt') `
        -AdminsFile (Join-Path $root 'audit\examples\admins.txt') -JsonPath $json
    $status = $LASTEXITCODE
    $after = Get-StateSnapshot

    Write-Host "exit code: $status"
    if ($status -gt 1) { throw "unexpected exit code $status (2 = bad arguments, 3 = a check crashed)" }

    foreach ($k in $before.Keys) {
        if ($before[$k] -ne $after[$k]) { throw "the audit changed system state: $k" }
    }
    Write-Host 'OK: policy, audit policy, firewall, services and accounts are unchanged'

    $report = Get-Content -LiteralPath $json -Raw | ConvertFrom-Json
    $expected = @(& $audit -ListChecks).Count
    $results = @($report.results)
    if ($results.Count -ne $expected) { throw "$($results.Count) results, expected $expected" }
    $errors = @($results | Where-Object { $_.status -eq 'ERROR' })
    if ($errors.Count) { throw "crashed checks: $(($errors | ForEach-Object { "$($_.id): $($_.message)" }) -join '; ')" }
    $bad = @($results | Where-Object { $_.status -notin 'PASS', 'FAIL', 'WARN', 'INFO', 'SKIP' })
    if ($bad.Count) { throw "unexpected statuses: $(($bad | ForEach-Object status) -join ', ')" }
    Write-Host "OK: JSON report has $expected results"
} finally {
    Remove-Item -LiteralPath $work -Recurse -Force -ErrorAction SilentlyContinue
}
