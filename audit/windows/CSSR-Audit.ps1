<#
.SYNOPSIS
    Check-only security audit for CyberPatriot-style Windows images.

.DESCRIPTION
    Reports what looks wrong and prints the command that would fix it. It never changes the
    system. It reads the registry, local accounts and status cmdlets, and exports the local
    security policy to a temporary file (deleted afterwards) because that's the only way to
    read it. It makes no network calls.

    Targets Windows 10/11 and Server 2019/2022/2025, and runs on Windows PowerShell 5.1.
    Run it from an elevated PowerShell for the full set of checks.
    Part of CSSR (https://github.com/0x000NULL/CSSR), MIT License.

.PARAMETER UsersFile
    Authorized users, one name per line (# comments allowed). Use every user the README lists,
    administrators included.

.PARAMETER AdminsFile
    Authorized administrators, same format.

.PARAMETER JsonPath
    Also write a JSON report (UTF-8) to this path.

.PARAMETER ListChecks
    Print the list of checks and exit. Add -Markdown for a Markdown table.

.EXAMPLE
    powershell -ExecutionPolicy Bypass -File .\CSSR-Audit.ps1 -UsersFile users.txt -AdminsFile admins.txt

.NOTES
    Exit codes: 0 no FAIL findings, 1 at least one FAIL, 2 bad arguments, 3 a check crashed (a bug).
#>
[CmdletBinding()]
param(
    [string]$UsersFile,
    [string]$AdminsFile,
    [string]$JsonPath,
    [switch]$ListChecks,
    [switch]$Markdown,
    [switch]$NoColor
)

$Version = '2026.1'

# Thresholds (CIS-style). Keep in sync with docs/guides/windows-hardening.md.
$MinPasswordLengthPass = 14     # PASS at or above
$MinPasswordLengthFail = 10     # FAIL below, WARN in between
$MaxPasswordAgeMax     = 90
$MinPasswordAgeMin     = 1
$PasswordHistoryPass   = 24
$PasswordHistoryFail   = 5
$LockoutThresholdMax   = 5
$LockoutDurationMin    = 15
$LockoutResetMin       = 15
$SignatureAgeMaxDays   = 7
$HotfixAgeMaxDays      = 60

# Services that are rarely needed on a CyberPatriot image. Check the README first: a service it
# names as critical is not a vulnerability.
$RiskyServices = @('RemoteRegistry', 'TlntSvr', 'ftpsvc', 'MSFTPSVC', 'SNMP', 'W3SVC', 'SSDPSRV',
    'upnphost', 'RemoteAccess', 'SharedAccess', 'simptcp', 'WMSvc', 'Fax')
$ProhibitedSoftwarePattern = 'Wireshark|Nmap|Npcap|Cain|John the Ripper|Hydra|Ophcrack|Angry IP Scanner|' +
    'Metasploit|NetBus|uTorrent|BitTorrent|qBittorrent|Vuze|FrostWire|LimeWire|Shareaza|TeamViewer|' +
    'AnyDesk|RealVNC|TightVNC|UltraVNC'
$MediaExtensions = @('mp3', 'mp4', 'm4a', 'm4v', 'avi', 'mkv', 'mov', 'wmv', 'flv', 'wav', 'flac',
    'ogg', 'aac', 'wma', '3gp', 'mid', 'midi')
# Programs reachable from the logon screen. Replacing one with a shell is a classic backdoor.
$AccessibilityPrograms = @('sethc.exe', 'utilman.exe', 'osk.exe', 'Magnify.exe', 'Narrator.exe',
    'DisplaySwitch.exe', 'AtBroker.exe')
$KeyAuditSubcategories = [ordered]@{
    'Credential Validation'     = 'Success and Failure'
    'Logon'                     = 'Success and Failure'
    'Account Lockout'           = 'Failure'
    'User Account Management'   = 'Success and Failure'
    'Security Group Management' = 'Success'
    'Audit Policy Change'       = 'Success'
    'Sensitive Privilege Use'   = 'Success and Failure'
    'Process Creation'          = 'Success'
    'Security System Extension' = 'Success'
    'System Integrity'          = 'Success and Failure'
}

# ------------------------------------------------------------------------------------------
# Check registry

$Checks = New-Object System.Collections.Generic.List[object]
function Register-Check {
    param([string]$Id, [string]$Category, [string]$Description, [bool]$Admin, [scriptblock]$Test)
    $Checks.Add([pscustomobject]@{ Id = $Id; Category = $Category; Description = $Description; Admin = $Admin; Test = $Test })
}

function New-Result {
    param([string]$Status, [string]$Message, [string]$Fix = '')
    [pscustomobject]@{ Status = $Status; Message = $Message; Fix = $Fix }
}
function Pass { param([string]$Message) New-Result PASS $Message }
function Fail { param([string]$Message, [string]$Fix = '') New-Result FAIL $Message $Fix }
function Warn { param([string]$Message, [string]$Fix = '') New-Result WARN $Message $Fix }
function Info { param([string]$Message, [string]$Fix = '') New-Result INFO $Message $Fix }
function Skip { param([string]$Message) New-Result SKIP $Message }

# --- helpers (only called while checks run) ---

function Read-NameList {
    param([string]$Path)
    Get-Content -LiteralPath $Path | ForEach-Object { ($_ -replace '#.*', '').Trim() } |
        Where-Object { $_ } | Sort-Object -Unique
}

function Get-RegValue {
    param([string]$Path, [string]$Name)
    $item = Get-ItemProperty -LiteralPath $Path -Name $Name -ErrorAction SilentlyContinue
    if ($null -eq $item) { return $null }
    return $item.$Name
}

$script:SecPolicy = $null
function Get-SecPolicy {
    if ($null -eq $script:SecPolicy) {
        $tmp = Join-Path $env:TEMP ("cssr-secpol-{0}.inf" -f [guid]::NewGuid())
        try {
            & secedit.exe /export /cfg $tmp /areas SECURITYPOLICY /quiet | Out-Null
            $policy = @{}
            if (Test-Path -LiteralPath $tmp) {
                foreach ($line in Get-Content -LiteralPath $tmp) {
                    if ($line -match '^\s*([A-Za-z]+)\s*=\s*(.*?)\s*$') { $policy[$Matches[1]] = $Matches[2] }
                }
            }
            $script:SecPolicy = $policy
        } finally {
            Remove-Item -LiteralPath $tmp -Force -ErrorAction SilentlyContinue
        }
    }
    return $script:SecPolicy
}
function Get-PolicyInt {
    param([string]$Name)
    $p = Get-SecPolicy
    if ($p.ContainsKey($Name) -and $p[$Name] -match '^-?\d+$') { return [int]$p[$Name] }
    return $null
}

$script:AuditPolicy = $null
function Get-AuditPolicy {
    if ($null -eq $script:AuditPolicy) {
        $map = @{}
        $csv = & auditpol.exe /get /category:* /r 2>$null
        if ($csv) {
            foreach ($row in ($csv | Where-Object { $_ } | ConvertFrom-Csv)) {
                $map[$row.Subcategory.Trim()] = $row.'Inclusion Setting'.Trim()
            }
        }
        $script:AuditPolicy = $map
    }
    return $script:AuditPolicy
}

function Get-LocalAccount {
    # Enabled and disabled local users with their well-known RID.
    Get-LocalUser | ForEach-Object {
        $rid = [int]($_.SID.Value -split '-')[-1]
        [pscustomobject]@{ Name = $_.Name; Enabled = $_.Enabled; Rid = $rid; User = $_ }
    }
}
function Get-RegularAccount {
    # Skip Guest (501), DefaultAccount (503) and WDAGUtilityAccount (504); the built-in
    # Administrator (500) has its own check.
    Get-LocalAccount | Where-Object { $_.Rid -notin 500, 501, 503, 504 }
}

function Get-AdministratorsMember {
    $sid = New-Object System.Security.Principal.SecurityIdentifier 'S-1-5-32-544'
    $groupName = $sid.Translate([System.Security.Principal.NTAccount]).Value.Split('\')[-1]
    $group = [ADSI]"WinNT://./$groupName,group"
    @($group.psbase.Invoke('Members')) | ForEach-Object {
        $_.GetType().InvokeMember('Name', 'GetProperty', $null, $_, $null)
    } | Sort-Object -Unique
}

function Get-InstalledSoftware {
    $paths = @('HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\*',
        'HKLM:\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall\*',
        'HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\*')
    foreach ($p in $paths) {
        Get-ItemProperty -Path $p -ErrorAction SilentlyContinue |
            Where-Object { $_.PSObject.Properties['DisplayName'] -and $_.DisplayName } |
            Select-Object -ExpandProperty DisplayName
    }
}

function Join-Short {
    param([object[]]$Items, [int]$Max = 15)
    $list = @($Items)
    $text = ($list | Select-Object -First $Max) -join ', '
    if ($list.Count -gt $Max) { $text += (", ... ({0} total)" -f $list.Count) }
    return $text
}

# --- Accounts ---

Register-Check 'WIN-ACC-01' 'Accounts' 'Guest account is disabled' $false {
    $guest = Get-LocalAccount | Where-Object { $_.Rid -eq 501 }
    if ($guest -and $guest.Enabled) { Fail "The Guest account ($($guest.Name)) is enabled." "Disable-LocalUser -Name '$($guest.Name)'" }
    else { Pass 'The Guest account is disabled.' }
}
Register-Check 'WIN-ACC-02' 'Accounts' 'Built-in Administrator account is disabled' $false {
    $admin = Get-LocalAccount | Where-Object { $_.Rid -eq 500 }
    if ($admin -and $admin.Enabled) { Warn "The built-in Administrator account ($($admin.Name)) is enabled." "Disable-LocalUser -Name '$($admin.Name)'   (unless the README says to use it)" }
    else { Pass 'The built-in Administrator account is disabled.' }
}
Register-Check 'WIN-ACC-03' 'Accounts' 'Every enabled local user is authorized (-UsersFile)' $false {
    if (-not $UsersFile) { return Skip 'Pass -UsersFile with the users from the README.' }
    $allowed = Read-NameList $UsersFile
    $bad = @(Get-RegularAccount | Where-Object { $_.Enabled -and ($allowed -notcontains $_.Name) } | ForEach-Object Name)
    if ($bad.Count) { Warn "Enabled users not in the authorized list: $(Join-Short $bad)" "Confirm against the README, then: Remove-LocalUser -Name NAME   (or Disable-LocalUser)" }
    else { Pass 'Every enabled local user is authorized.' }
}
Register-Check 'WIN-ACC-04' 'Accounts' 'Every authorized user exists (-UsersFile)' $false {
    if (-not $UsersFile) { return Skip 'Pass -UsersFile with the users from the README.' }
    $existing = @(Get-LocalAccount | ForEach-Object Name)
    $missing = @(Read-NameList $UsersFile | Where-Object { $existing -notcontains $_ })
    if ($missing.Count) { Warn "Authorized users that don't exist: $(Join-Short $missing)" "New-LocalUser -Name NAME   (if the README asks for it)" }
    else { Pass 'Every authorized user exists.' }
}
Register-Check 'WIN-ACC-05' 'Accounts' 'Only authorized admins are in Administrators (-AdminsFile)' $false {
    $members = @(Get-AdministratorsMember)
    if (-not $AdminsFile) { return Info "Administrators members: $(Join-Short $members). Pass -AdminsFile to compare with the README." }
    $allowed = Read-NameList $AdminsFile
    $builtin = (Get-LocalAccount | Where-Object { $_.Rid -eq 500 }).Name
    $bad = @($members | Where-Object { ($allowed -notcontains $_) -and ($_ -ne $builtin) -and ($_ -ne 'Domain Admins') })
    if ($bad.Count) { Fail "Unauthorized administrators: $(Join-Short $bad)" "Remove-LocalGroupMember -SID S-1-5-32-544 -Member NAME" }
    else { Pass 'Only authorized users are administrators.' }
}
Register-Check 'WIN-ACC-06' 'Accounts' 'No enabled user has a password that never expires' $false {
    $bad = @(Get-RegularAccount | Where-Object { $_.Enabled -and $null -eq $_.User.PasswordExpires } | ForEach-Object Name)
    if ($bad.Count) { Warn "Passwords never expire for: $(Join-Short $bad)" "Set-LocalUser -Name NAME -PasswordNeverExpires `$false" }
    else { Pass 'Every enabled user has an expiring password.' }
}
Register-Check 'WIN-ACC-07' 'Accounts' 'Every enabled user is required to have a password' $false {
    $bad = @(Get-RegularAccount | Where-Object { $_.Enabled -and -not $_.User.PasswordRequired } | ForEach-Object Name)
    if ($bad.Count) { Fail "Users who may have no password: $(Join-Short $bad)" "net user NAME /passwordreq:yes   then set a password: net user NAME *" }
    else { Pass 'Every enabled user requires a password.' }
}

# --- Password and lockout policy (secedit export) ---

Register-Check 'WIN-POL-01' 'Policy' "Minimum password length >= $MinPasswordLengthPass" $true {
    $v = Get-PolicyInt MinimumPasswordLength
    $fix = "net accounts /minpwlen:$MinPasswordLengthPass"
    if ($null -eq $v) { Warn "Couldn't read MinimumPasswordLength." $fix }
    elseif ($v -ge $MinPasswordLengthPass) { Pass "Minimum password length is $v." }
    elseif ($v -ge $MinPasswordLengthFail) { Warn "Minimum password length is $v (CIS recommends $MinPasswordLengthPass)." $fix }
    else { Fail "Minimum password length is $v." $fix }
}
Register-Check 'WIN-POL-02' 'Policy' 'Password complexity is required' $true {
    if ((Get-PolicyInt PasswordComplexity) -eq 1) { Pass 'Password complexity is enabled.' }
    else { Fail 'Passwords are not required to meet complexity requirements.' 'secpol.msc > Account Policies > Password Policy > Password must meet complexity requirements: Enabled' }
}
Register-Check 'WIN-POL-03' 'Policy' "Maximum password age is 1-$MaxPasswordAgeMax days" $true {
    $v = Get-PolicyInt MaximumPasswordAge
    if ($null -ne $v -and $v -ge 1 -and $v -le $MaxPasswordAgeMax) { Pass "Maximum password age is $v days." }
    else { Fail "Maximum password age is $(if ($null -eq $v -or $v -le 0) { 'unlimited' } else { "$v days" })." "net accounts /maxpwage:$MaxPasswordAgeMax" }
}
Register-Check 'WIN-POL-04' 'Policy' "Minimum password age >= $MinPasswordAgeMin day" $true {
    $v = Get-PolicyInt MinimumPasswordAge
    if ($null -ne $v -and $v -ge $MinPasswordAgeMin) { Pass "Minimum password age is $v days." }
    else { Fail "Minimum password age is $(if ($null -eq $v) { 'unset' } else { $v }) days." "net accounts /minpwage:$MinPasswordAgeMin" }
}
Register-Check 'WIN-POL-05' 'Policy' "Password history remembers >= $PasswordHistoryPass passwords" $true {
    $v = Get-PolicyInt PasswordHistorySize
    $fix = "net accounts /uniquepw:$PasswordHistoryPass"
    if ($null -eq $v) { $v = 0 }
    if ($v -ge $PasswordHistoryPass) { Pass "The last $v passwords are remembered." }
    elseif ($v -ge $PasswordHistoryFail) { Warn "The last $v passwords are remembered (CIS recommends $PasswordHistoryPass)." $fix }
    else { Fail "Password history is $v." $fix }
}
Register-Check 'WIN-POL-06' 'Policy' 'Passwords are not stored with reversible encryption' $true {
    if ((Get-PolicyInt ClearTextPassword) -eq 1) { Fail 'Passwords are stored using reversible encryption.' 'secpol.msc > Account Policies > Password Policy > Store passwords using reversible encryption: Disabled' }
    else { Pass 'Reversible password encryption is disabled.' }
}
Register-Check 'WIN-POL-07' 'Policy' "Account lockout threshold is 1-$LockoutThresholdMax attempts" $true {
    $v = Get-PolicyInt LockoutBadCount
    if ($null -ne $v -and $v -ge 1 -and $v -le $LockoutThresholdMax) { Pass "Accounts lock after $v failed attempts." }
    else { Fail "Lockout threshold is $(if ($null -eq $v -or $v -eq 0) { 'off (0)' } else { $v })." "net accounts /lockoutthreshold:$LockoutThresholdMax" }
}
Register-Check 'WIN-POL-08' 'Policy' "Account lockout duration >= $LockoutDurationMin minutes" $true {
    $v = Get-PolicyInt LockoutDuration
    if ($null -eq $v) { Skip 'Lockout is off, so there is no duration (see WIN-POL-07).' }
    elseif ($v -ge $LockoutDurationMin -or $v -eq -1) { Pass "Lockout duration is $(if ($v -eq -1) { 'until an admin unlocks' } else { "$v minutes" })." }
    else { Fail "Lockout duration is $v minutes." "net accounts /lockoutduration:$LockoutDurationMin" }
}
Register-Check 'WIN-POL-09' 'Policy' "Lockout counter resets after >= $LockoutResetMin minutes" $true {
    $v = Get-PolicyInt ResetLockoutCount
    if ($null -eq $v) { Skip 'Lockout is off (see WIN-POL-07).' }
    elseif ($v -ge $LockoutResetMin) { Pass "The lockout counter resets after $v minutes." }
    else { Fail "The lockout counter resets after $v minutes." "net accounts /lockoutwindow:$LockoutResetMin" }
}

# --- Auditing ---

Register-Check 'WIN-AUD-01' 'Auditing' 'Key audit subcategories log success/failure' $true {
    $audit = Get-AuditPolicy
    if ($audit.Count -eq 0) { return Skip "Couldn't read the audit policy (auditpol returned nothing)." }
    $missing = @()
    foreach ($name in $KeyAuditSubcategories.Keys) {
        $want = $KeyAuditSubcategories[$name]
        if (-not $audit.ContainsKey($name)) { continue }   # non-English Windows: names differ
        $have = $audit[$name]
        $ok = ($have -eq 'Success and Failure') -or ($have -eq $want)
        if (-not $ok) { $missing += "$name ($have, want $want)" }
    }
    if ($missing.Count) {
        Fail "Audit subcategories not configured: $(Join-Short $missing 20)" 'auditpol /set /subcategory:"NAME" /success:enable /failure:enable'
    } else { Pass 'Key audit subcategories are enabled.' }
}

# --- Security options (registry) ---

Register-Check 'WIN-SEC-01' 'Security options' 'Blank passwords only work at the console' $false {
    if ((Get-RegValue 'HKLM:\SYSTEM\CurrentControlSet\Control\Lsa' LimitBlankPasswordUse) -eq 1) { Pass 'LimitBlankPasswordUse is 1.' }
    else { Fail 'Accounts with blank passwords can log on over the network.' 'reg add HKLM\SYSTEM\CurrentControlSet\Control\Lsa /v LimitBlankPasswordUse /t REG_DWORD /d 1 /f' }
}
Register-Check 'WIN-SEC-02' 'Security options' 'UAC is on and prompts administrators on the secure desktop' $false {
    $key = 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System'
    $lua = Get-RegValue $key EnableLUA
    $consent = Get-RegValue $key ConsentPromptBehaviorAdmin
    $secure = Get-RegValue $key PromptOnSecureDesktop
    $problems = @()
    if ($lua -ne 1) { $problems += "EnableLUA=$lua" }
    if ($consent -notin 1, 2) { $problems += "ConsentPromptBehaviorAdmin=$consent" }
    if ($secure -ne 1) { $problems += "PromptOnSecureDesktop=$secure" }
    if ($problems.Count) { Fail "UAC is weakened: $($problems -join ', ')" "reg add $($key -replace 'HKLM:', 'HKLM') /v EnableLUA /t REG_DWORD /d 1 /f  (likewise ConsentPromptBehaviorAdmin=2, PromptOnSecureDesktop=1; reboot)" }
    else { Pass 'UAC is on and prompts on the secure desktop.' }
}
Register-Check 'WIN-SEC-03' 'Security options' 'Anonymous users cannot enumerate accounts and shares' $false {
    $key = 'HKLM:\SYSTEM\CurrentControlSet\Control\Lsa'
    $problems = @()
    if ((Get-RegValue $key RestrictAnonymousSAM) -ne 1) { $problems += 'RestrictAnonymousSAM' }
    if ((Get-RegValue $key RestrictAnonymous) -ne 1) { $problems += 'RestrictAnonymous' }
    if ((Get-RegValue $key EveryoneIncludesAnonymous) -eq 1) { $problems += 'EveryoneIncludesAnonymous' }
    if ($problems.Count) { Fail "Anonymous access is not restricted: $($problems -join ', ')" 'reg add HKLM\SYSTEM\CurrentControlSet\Control\Lsa /v RestrictAnonymous /t REG_DWORD /d 1 /f  (also RestrictAnonymousSAM=1, EveryoneIncludesAnonymous=0)' }
    else { Pass 'Anonymous enumeration is restricted.' }
}
Register-Check 'WIN-SEC-04' 'Security options' 'No LM hashes are stored and only NTLMv2 is sent' $false {
    $key = 'HKLM:\SYSTEM\CurrentControlSet\Control\Lsa'
    $nolm = Get-RegValue $key NoLMHash
    $level = Get-RegValue $key LmCompatibilityLevel
    $problems = @()
    if ($nolm -ne 1) { $problems += "NoLMHash=$nolm" }
    if ($null -eq $level -or $level -lt 5) { $problems += "LmCompatibilityLevel=$level" }
    if ($problems.Count) { Warn "Older authentication is allowed: $($problems -join ', ')" 'reg add HKLM\SYSTEM\CurrentControlSet\Control\Lsa /v LmCompatibilityLevel /t REG_DWORD /d 5 /f  (and NoLMHash=1)' }
    else { Pass 'LM hashes are off and only NTLMv2 is used.' }
}
Register-Check 'WIN-SEC-05' 'Security options' "Logon screen hides the last user and requires Ctrl+Alt+Del" $false {
    $key = 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System'
    $problems = @()
    if ((Get-RegValue $key DontDisplayLastUserName) -ne 1) { $problems += 'last user name is shown' }
    if ((Get-RegValue $key DisableCAD) -eq 1) { $problems += 'Ctrl+Alt+Del is not required' }
    if ($problems.Count) { Warn "Logon screen: $($problems -join '; ')" 'reg add HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System /v DontDisplayLastUserName /t REG_DWORD /d 1 /f  (and DisableCAD=0)' }
    else { Pass 'The logon screen hides the last user and requires Ctrl+Alt+Del.' }
}
Register-Check 'WIN-SEC-06' 'Security options' 'AutoRun is disabled for all drives' $false {
    $v = Get-RegValue 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer' NoDriveTypeAutoRun
    if ($v -eq 255) { Pass 'AutoRun is disabled for all drive types.' }
    else { Warn "NoDriveTypeAutoRun is $(if ($null -eq $v) { 'unset' } else { $v })." 'reg add HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer /v NoDriveTypeAutoRun /t REG_DWORD /d 255 /f' }
}

# --- Network ---

Register-Check 'WIN-NET-01' 'Network' 'Windows Firewall is on for every profile' $false {
    $off = @(Get-NetFirewallProfile | Where-Object { -not $_.Enabled } | ForEach-Object Name)
    if ($off.Count) { Fail "Firewall is off for: $($off -join ', ')" 'Set-NetFirewallProfile -Profile Domain,Private,Public -Enabled True' }
    else { Pass 'Firewall is on for Domain, Private and Public.' }
}
Register-Check 'WIN-NET-02' 'Network' 'Windows Firewall blocks inbound connections by default' $false {
    $allow = @(Get-NetFirewallProfile | Where-Object { "$($_.DefaultInboundAction)" -eq 'Allow' } | ForEach-Object Name)
    if ($allow.Count) { Fail "Inbound connections are allowed by default on: $($allow -join ', ')" 'Set-NetFirewallProfile -Profile Domain,Private,Public -DefaultInboundAction Block' }
    else { Pass 'Inbound connections are blocked by default.' }
}
Register-Check 'WIN-NET-03' 'Network' 'SMBv1 is disabled' $true {
    $cfg = Get-SmbServerConfiguration
    if ($cfg.EnableSMB1Protocol) { Fail 'The SMBv1 server protocol is enabled.' 'Set-SmbServerConfiguration -EnableSMB1Protocol $false -Force; Disable-WindowsOptionalFeature -Online -FeatureName SMB1Protocol' }
    else { Pass 'SMBv1 is disabled.' }
}
Register-Check 'WIN-NET-04' 'Network' 'Remote Desktop requires Network Level Authentication when on' $false {
    $deny = Get-RegValue 'HKLM:\SYSTEM\CurrentControlSet\Control\Terminal Server' fDenyTSConnections
    if ($deny -ne 0) { return Info 'Remote Desktop is off. Turn it on only if the README requires it.' }
    $nla = Get-RegValue 'HKLM:\SYSTEM\CurrentControlSet\Control\Terminal Server\WinStations\RDP-Tcp' UserAuthentication
    if ($nla -eq 1) { Pass 'Remote Desktop is on and requires NLA. Check that the README needs it.' }
    else { Fail 'Remote Desktop is on without Network Level Authentication.' 'reg add "HKLM\SYSTEM\CurrentControlSet\Control\Terminal Server\WinStations\RDP-Tcp" /v UserAuthentication /t REG_DWORD /d 1 /f   (or turn RDP off if not required)' }
}
Register-Check 'WIN-NET-05' 'Network' 'No non-default file shares' $true {
    $shares = @(Get-SmbShare | Where-Object { $_.Name -notmatch '^([A-Z]\$|ADMIN\$|IPC\$|print\$|NETLOGON|SYSVOL)$' } | ForEach-Object { "$($_.Name) ($($_.Path))" })
    if ($shares.Count) { Warn "Shares: $(Join-Short $shares). Keep only what the README needs." 'Remove-SmbShare -Name NAME -Force' }
    else { Pass 'Only default administrative shares exist.' }
}

# --- Microsoft Defender ---

Register-Check 'WIN-DEF-01' 'Defender' 'Microsoft Defender real-time protection is on' $false {
    if (-not (Get-Command Get-MpComputerStatus -ErrorAction SilentlyContinue)) { return Skip 'Microsoft Defender cmdlets are not available.' }
    $policy = Get-RegValue 'HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender' DisableAntiSpyware
    $s = Get-MpComputerStatus
    if ($policy -eq 1) { Fail 'Defender is turned off by policy (DisableAntiSpyware=1).' 'reg delete "HKLM\SOFTWARE\Policies\Microsoft\Windows Defender" /v DisableAntiSpyware /f   then reboot' }
    elseif (-not $s.AntivirusEnabled -or -not $s.RealTimeProtectionEnabled) { Fail 'Defender antivirus or real-time protection is off.' 'Set-MpPreference -DisableRealtimeMonitoring $false   (and check Windows Security > Virus & threat protection)' }
    else { Pass 'Defender antivirus and real-time protection are on.' }
}
Register-Check 'WIN-DEF-02' 'Defender' "Defender signatures are less than $SignatureAgeMaxDays days old" $false {
    if (-not (Get-Command Get-MpComputerStatus -ErrorAction SilentlyContinue)) { return Skip 'Microsoft Defender cmdlets are not available.' }
    $age = (Get-MpComputerStatus).AntivirusSignatureAge
    if ($age -le $SignatureAgeMaxDays) { Pass "Signatures are $age days old." }
    else { Warn "Signatures are $age days old." 'Update-MpSignature' }
}
Register-Check 'WIN-DEF-03' 'Defender' 'Defender has no exclusions' $true {
    if (-not (Get-Command Get-MpPreference -ErrorAction SilentlyContinue)) { return Skip 'Microsoft Defender cmdlets are not available.' }
    $p = Get-MpPreference
    $ex = @()
    foreach ($prop in 'ExclusionPath', 'ExclusionExtension', 'ExclusionProcess', 'ExclusionIpAddress') {
        if ($p.PSObject.Properties[$prop] -and $p.$prop) { $ex += @($p.$prop | ForEach-Object { "$prop=$_" }) }
    }
    if ($ex.Count) { Warn "Defender exclusions: $(Join-Short $ex)" 'Remove-MpPreference -ExclusionPath PATH   (or -ExclusionExtension/-ExclusionProcess)' }
    else { Pass 'No Defender exclusions are set.' }
}

# --- Updates ---

Register-Check 'WIN-UPD-01' 'Updates' 'Windows Update is not disabled' $false {
    $svc = Get-CimInstance Win32_Service -Filter "Name='wuauserv'"
    $noAuto = Get-RegValue 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate\AU' NoAutoUpdate
    if ($svc -and $svc.StartMode -eq 'Disabled') { Fail 'The Windows Update service is disabled.' 'Set-Service wuauserv -StartupType Manual; Start-Service wuauserv' }
    elseif ($noAuto -eq 1) { Fail 'Automatic updates are turned off by policy (NoAutoUpdate=1).' 'reg delete HKLM\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate\AU /v NoAutoUpdate /f' }
    else { Pass 'Windows Update is enabled.' }
}
Register-Check 'WIN-UPD-02' 'Updates' "An update was installed in the last $HotfixAgeMaxDays days" $false {
    $latest = Get-HotFix | Where-Object { $_.InstalledOn } | Sort-Object InstalledOn -Descending | Select-Object -First 1
    if (-not $latest) { return Warn 'No installed updates were found.' 'Settings > Windows Update > Check for updates' }
    $days = [int]((Get-Date) - $latest.InstalledOn).TotalDays
    if ($days -le $HotfixAgeMaxDays) { Pass "Latest update ($($latest.HotFixID)) was installed $days days ago." }
    else { Warn "Latest update ($($latest.HotFixID)) was installed $days days ago." 'Settings > Windows Update > Check for updates' }
}

# --- Services and software ---

Register-Check 'WIN-SVC-01' 'Services' 'No commonly-unwanted services are running' $false {
    $found = @(Get-CimInstance Win32_Service | Where-Object {
            ($RiskyServices -contains $_.Name) -and ($_.State -eq 'Running' -or $_.StartMode -eq 'Auto')
        } | ForEach-Object { "$($_.Name) ($($_.State), $($_.StartMode))" })
    if ($found.Count) { Warn "Running or automatic: $(Join-Short $found). Keep only what the README lists as critical." 'Stop-Service NAME; Set-Service NAME -StartupType Disabled' }
    else { Pass 'None of the commonly-unwanted services are running.' }
}
Register-Check 'WIN-SW-01' 'Software' 'No hacking tools, P2P or remote-access programs installed' $false {
    $found = @(Get-InstalledSoftware | Where-Object { $_ -match $ProhibitedSoftwarePattern } | Sort-Object -Unique)
    if ($found.Count) { Warn "Installed: $(Join-Short $found). Remove them unless the README requires them." 'Settings > Apps > Installed apps (or appwiz.cpl) > Uninstall' }
    else { Pass 'None of the listed programs are installed.' }
}
Register-Check 'WIN-FIL-01' 'Files' 'No media files in user folders' $false {
    $root = Join-Path $env:SystemDrive 'Users'
    $patterns = $MediaExtensions | ForEach-Object { "*.$_" }
    $files = @(Get-ChildItem -LiteralPath $root -Recurse -File -Force -Include $patterns -ErrorAction SilentlyContinue |
            Where-Object { $_.FullName -notmatch '\\AppData\\Local\\(Microsoft|Packages)\\' } | ForEach-Object FullName)
    if ($files.Count) { Warn "$($files.Count) media files under ${root}: $(Join-Short $files 10)" "Answer forensics questions first, then delete what the README doesn't allow: Remove-Item -LiteralPath 'PATH'" }
    else { Pass "No media files under $root." }
}

# --- Backdoors and persistence ---

Register-Check 'WIN-BKD-01' 'Backdoors' 'Logon-screen accessibility programs are genuine' $false {
    $sys32 = Join-Path $env:SystemRoot 'System32'
    $shellHashes = @()
    foreach ($s in 'cmd.exe', 'WindowsPowerShell\v1.0\powershell.exe', 'explorer.exe') {
        $p = Join-Path $sys32 $s
        if (-not (Test-Path -LiteralPath $p)) { $p = Join-Path $env:SystemRoot $s }
        if (Test-Path -LiteralPath $p) { $shellHashes += (Get-FileHash -LiteralPath $p -Algorithm SHA256).Hash }
    }
    $bad = @()
    foreach ($name in $AccessibilityPrograms) {
        $p = Join-Path $sys32 $name
        if (-not (Test-Path -LiteralPath $p)) { continue }
        $hash = (Get-FileHash -LiteralPath $p -Algorithm SHA256).Hash
        $orig = "$((Get-Item -LiteralPath $p).VersionInfo.OriginalFilename)".Trim()
        if (($shellHashes -contains $hash) -or ($orig -match '^(cmd|powershell|explorer)\.exe(\.mui)?$')) { $bad += $name }
    }
    if ($bad.Count) { Fail "Replaced with a shell: $($bad -join ', '). Anyone at the logon screen gets a SYSTEM prompt." 'sfc /scannow   (restores the original files; if it fails: DISM /Online /Cleanup-Image /RestoreHealth, then sfc again)' }
    else { Pass 'Accessibility programs are the genuine Windows files.' }
}
Register-Check 'WIN-BKD-02' 'Backdoors' 'No debugger hijacks on accessibility programs (IFEO)' $false {
    $base = 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options'
    $bad = @()
    foreach ($name in $AccessibilityPrograms) {
        $d = Get-RegValue (Join-Path $base $name) Debugger
        if ($d) { $bad += "$name -> $d" }
    }
    if ($bad.Count) { Fail "Image File Execution Options debuggers: $($bad -join '; ')" "reg delete `"HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options\NAME.exe`" /v Debugger /f" }
    else { Pass 'No IFEO debuggers on accessibility programs.' }
}
Register-Check 'WIN-BKD-03' 'Backdoors' 'hosts file has only default entries' $false {
    $hosts = Join-Path $env:SystemRoot 'System32\drivers\etc\hosts'
    $entries = @(Get-Content -LiteralPath $hosts -ErrorAction SilentlyContinue | Where-Object { $_ -match '^\s*[^#\s]' } |
            Where-Object { $_ -notmatch '^\s*(127\.0\.0\.1|::1)\s+localhost\s*$' })
    if ($entries.Count) { Warn "hosts entries: $(Join-Short ($entries | ForEach-Object { $_.Trim() }))" "Remove entries the README doesn't explain from $hosts" }
    else { Pass 'The hosts file has no extra entries.' }
}
Register-Check 'WIN-INF-01' 'Persistence' 'Startup programs (Run keys) for review' $false {
    $keys = @('HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Run', 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce',
        'HKLM:\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Run', 'HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Run',
        'HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce')
    $items = @()
    foreach ($k in $keys) {
        $props = Get-ItemProperty -LiteralPath $k -ErrorAction SilentlyContinue
        if ($props) {
            $items += @($props.PSObject.Properties | Where-Object { $_.Name -notmatch '^PS' } | ForEach-Object { "$($_.Name)=$($_.Value)" })
        }
    }
    if ($items.Count) { Info "Startup entries: $(Join-Short $items 10)" 'Remove unknown entries: Remove-ItemProperty -Path KEY -Name NAME   (or Task Manager > Startup)' }
    else { Info 'No Run-key startup entries.' }
}
Register-Check 'WIN-INF-02' 'Persistence' 'Non-Microsoft scheduled tasks for review' $false {
    $tasks = @(Get-ScheduledTask | Where-Object { $_.TaskPath -notlike '\Microsoft\*' } | ForEach-Object { "$($_.TaskPath)$($_.TaskName)" })
    if ($tasks.Count) { Info "Scheduled tasks: $(Join-Short $tasks)" 'Unregister-ScheduledTask -TaskName NAME   (after checking what it runs)' }
    else { Info 'No non-Microsoft scheduled tasks.' }
}

# ------------------------------------------------------------------------------------------
# List mode

if ($ListChecks) {
    if ($Markdown) {
        '| ID | Category | Check |'
        '|---|---|---|'
        foreach ($c in $Checks) { '| `{0}` | {1} | {2} |' -f $c.Id, $c.Category, $c.Description }
    } else {
        foreach ($c in $Checks) { '{0,-11} {1,-17} {2}' -f $c.Id, $c.Category, $c.Description }
    }
    exit 0
}

# ------------------------------------------------------------------------------------------
# Run

foreach ($f in @($UsersFile, $AdminsFile)) {
    if ($f -and -not (Test-Path -LiteralPath $f -PathType Leaf)) {
        Write-Error "Cannot read $f"
        exit 2
    }
}

$IsAdmin = ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole(
    [Security.Principal.WindowsBuiltInRole]::Administrator)

$Results = New-Object System.Collections.Generic.List[object]
foreach ($c in $Checks) {
    if ($c.Admin -and -not $IsAdmin) {
        $r = Skip 'Needs an elevated PowerShell (Run as administrator).'
    } else {
        try {
            $ErrorActionPreference = 'Stop'
            $r = & $c.Test | Select-Object -Last 1
            if ($null -eq $r) { $r = New-Result ERROR 'Check returned no result.' }
        } catch {
            $r = New-Result ERROR ("Check error: {0}" -f $_.Exception.Message)
        } finally {
            $ErrorActionPreference = 'Continue'
        }
    }
    $Results.Add([pscustomobject]@{ id = $c.Id; category = $c.Category; status = $r.Status; message = $r.Message; fix = $r.Fix })
}

$os = (Get-CimInstance Win32_OperatingSystem -ErrorAction SilentlyContinue).Caption
$colors = @{ PASS = 'Green'; FAIL = 'Red'; WARN = 'Yellow'; INFO = 'Cyan'; SKIP = 'DarkGray'; ERROR = 'Magenta' }
Write-Host "CSSR Windows audit $Version - $os - $env:COMPUTERNAME"
if (-not $IsAdmin) { Write-Host 'Not elevated: some checks are skipped. Re-run from an elevated PowerShell.' }
Write-Host 'This script only reads; it changes nothing.'
Write-Host ''
foreach ($r in $Results) {
    $tag = "[$($r.status)]"
    if ($NoColor) { Write-Host -NoNewline $tag } else { Write-Host -NoNewline $tag -ForegroundColor $colors[$r.status] }
    Write-Host (' {0,-11} {1}' -f $r.id, $r.message)
    if ($r.fix -and $r.status -ne 'PASS') {
        if ($NoColor) { Write-Host "       fix: $($r.fix)" } else { Write-Host "       fix: $($r.fix)" -ForegroundColor DarkGray }
    }
}

$summary = [ordered]@{}
foreach ($s in 'FAIL', 'WARN', 'PASS', 'INFO', 'SKIP', 'ERROR') { $summary[$s] = @($Results | Where-Object { $_.status -eq $s }).Count }
Write-Host ''
Write-Host ('Summary: {0} FAIL, {1} WARN, {2} PASS, {3} INFO, {4} SKIP{5}' -f $summary.FAIL, $summary.WARN, $summary.PASS,
    $summary.INFO, $summary.SKIP, $(if ($summary.ERROR) { ", $($summary.ERROR) ERROR" } else { '' }))

if ($JsonPath) {
    $report = [ordered]@{
        tool      = 'cssr-audit'
        version   = $Version
        os        = "$os"
        host      = $env:COMPUTERNAME
        admin     = $IsAdmin
        generated = (Get-Date).ToUniversalTime().ToString('yyyy-MM-ddTHH:mm:ssZ')
        summary   = $summary
        results   = $Results
    }
    $json = $report | ConvertTo-Json -Depth 5
    $full = $JsonPath
    if (-not [System.IO.Path]::IsPathRooted($full)) { $full = Join-Path (Get-Location).Path $full }
    $full = [System.IO.Path]::GetFullPath($full)
    [System.IO.File]::WriteAllText($full, $json, (New-Object System.Text.UTF8Encoding $false))
    Write-Host "JSON report written to $full"
}

if ($summary.ERROR) { exit 3 }
if ($summary.FAIL) { exit 1 }
exit 0
