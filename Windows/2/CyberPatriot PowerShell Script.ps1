Clear-Host 
Set-ExecutionPolicy Unrestricted -force
Start-Transcript

#Set Services
$s = Get-Service -Name "TermService"
Stop-Service -InputObject $s -Force
Set-Service TermService -StartupType Disabled
Write-Host "Remote Desktop Services Stopped and Disabled"  

$s2 = Get-Service -Name "RemoteRegistry"
Stop-Service -InputObject $s2 -Force
Set-Service RemoteRegistry -StartupType Disabled
Write-Host "Remote Registry Stopped and Disabled"  

$s3 = Get-Service -Name "RpcLocator"
Stop-Service -InputObject $s3 -Force
Set-Service RpcLocator -StartupType Disabled
Write-Host "Remote Procedure Call (RPC) Locator Stopped and Disabled"  

$s4 = Get-Service -Name "wuauserv"
start-Service -InputObject $s4 
Set-Service RpcLocator -StartupType Automatic
Write-Host "Windows Update is Started and Set to Automatic start" 

$s5 = Get-Service -Name "SharedAccess"
Stop-Service -InputObject $s5 -Force
Set-Service SharedAccess -StartupType Disabled
Write-Host "Internet Connection Sharing (ICS) Stopped and Disabled" 

$s6 = Get-Service -Name "SessionEnv"
Stop-Service -InputObject $s6 -Force
Set-Service SessionEnv -StartupType Disabled
Write-Host "Remote Desktop Configuration Stopped and Disabled"  

$s7 = Get-Service -Name "SSDPSRV"
Stop-Service -InputObject $s7 -Force
Set-Service SSDPSRV -StartupType Disabled
Write-Host "SSDP Discovery Stopped and Disabled"  

$s8 = Get-Service -Name "upnphost"
Stop-Service -InputObject $s8 -Force
Set-Service upnphost -StartupType Disabled
Write-Host "UPnP Device Host Stopped and Disabled" 

$s9 = Get-Service -Name "EventLog"
start-Service -InputObject $s9 
Set-Service EventLog -StartupType Automatic
Write-Host "Windows EventLog is Started and Set to Automatic start"

$s10 = Get-Service -Name "DcpSvc"
Stop-Service -InputObject $s10 -Force
Set-Service DcpSvc -StartupType Disabled
Write-Host "Data Collection and Publishing Service Stopped and Disabled"

$s11 = Get-Service -Name "DiagTrack"
Stop-Service -InputObject $s11 -Force
Set-Service DiagTrack -StartupType Disabled
Write-Host "Diagnostics Tracking Service Stopped and Disabled"

$s12 = Get-Service -Name "SensrSvc"
Stop-Service -InputObject $s12 -Force
Set-Service SensrSvc -StartupType Disabled
Write-Host "Monitors Various Sensors Stopped and Disabled"

$s13 = Get-Service -Name "dmwappushservice"
Stop-Service -InputObject $s13  -Force
Set-Service dmwappushservice -StartupType Disabled
Write-Host "Push Message Routing Service Stopped and Disabled"

$s14 = Get-Service -Name "lfsvc"
Stop-Service -InputObject $s14  -Force
Set-Service lfsvc -StartupType Disabled
Write-Host "Geolocation Service Stopped and Disabled"

$s15 = Get-Service -Name "MapsBroker"
Stop-Service -InputObject $s15  -Force
Set-Service MapsBroker -StartupType Disabled
Write-Host "Downloaded Maps Manager Stopped and Disabled"

$s16 = Get-Service -Name "NetTcpPortSharing"
Stop-Service -InputObject $s16  -Force
Set-Service NetTcpPortSharing -StartupType Disabled
Write-Host "Net.Tcp Port Sharing Service Stopped and Disabled"

$s17 = Get-Service -Name "RemoteAccess"
Stop-Service -InputObject $s17  -Force
Set-Service RemoteAccess -StartupType Disabled
Write-Host "Routing and Remote Access Stopped and Disabled"

$s18 = Get-Service -Name "TrkWks"
Stop-Service -InputObject $s18  -Force
Set-Service TrkWks -StartupType Disabled
Write-Host "Distributed Link Tracking Client Stopped and Disabled"

$s19 = Get-Service -Name "WbioSrvc"
Stop-Service -InputObject $s19  -Force
Set-Service WbioSrvc -StartupType Disabled
Write-Host "Windows Biometric Service Stopped and Disabled"

$s20 = Get-Service -Name "WMPNetworkSvc"
Stop-Service -InputObject $s20  -Force
Set-Service WMPNetworkSvc -StartupType Disabled
Write-Host "Windows Media Player Network Sharing Service Stopped and Disabled"

$s21 = Get-Service -Name "WSearch"
Stop-Service -InputObject $s21  -Force
Set-Service WSearch -StartupType Disabled
Write-Host "Windows Search Stopped and Disabled"

$s22 = Get-Service -Name "XblAuthManager"
Stop-Service -InputObject $s22  -Force
Set-Service XblAuthManager -StartupType Disabled
Write-Host "Xbox Live Auth Manager Stopped and Disabled"

$s23 = Get-Service -Name "XblGameSave"
Stop-Service -InputObject $s23  -Force
Set-Service XblGameSave -StartupType Disabled
Write-Host "Xbox Live Game Save Service Stopped and Disabled"

$s24 = Get-Service -Name "XboxNetApiSvc"
Stop-Service -InputObject $s24  -Force
Set-Service XboxNetApiSvc -StartupType Disabled
Write-Host "Xbox Live Networking Service Stopped and Disabled"

$s25 = Get-Service -Name "HomeGroupListener"
Stop-Service -InputObject $s25  -Force
Set-Service HomeGroupListener -StartupType Disabled
Write-Host "HomeGroup Listener Stopped and Disabled"

$s26 = Get-Service -Name "HomeGroupProvider"
Stop-Service -InputObject $s26  -Force
Set-Service HomeGroupProvider -StartupType Disabled
Write-Host "HomeGroup Provider Stopped and Disabled"

$s27 = Get-Service -Name "bthserv"
Stop-Service -InputObject $s27  -Force
Set-Service bthserv -StartupType Disabled
Write-Host "Bluetooth Support Service Stopped and Disabled"

$s28 = Get-Service -Name "WinHttpAutoProxySvc"
Stop-Service -InputObject $s28  -Force
Set-Service WinHttpAutoProxySvc -StartupType Disabled
Write-Host "WinHTTP Web Proxy Auto-Discovery Stopped and Disabled"





#Setting FireWall Enabled, enforcing ports
Set-NetFirewallProfile -Profile Domain,Public,Private -Enabled True
Write-Host "Firewall Enabled"

#TCP Ports
New-NetFirewallRule -DisplayName "Block Outbound Port 21" -Direction Inbound -LocalPort 21 -Protocol TCP -Action Block
New-NetFirewallRule -DisplayName "Block Outbound Port 22" -Direction Inbound -LocalPort 22 -Protocol TCP -Action Block
New-NetFirewallRule -DisplayName "Block Outbound Port 23" -Direction Inbound -LocalPort 23 -Protocol TCP -Action Block
New-NetFirewallRule -DisplayName "Block Outbound Port 25" -Direction Inbound -LocalPort 25 -Protocol TCP -Action Block
New-NetFirewallRule -DisplayName "Block Outbound Port 80" -Direction Inbound -LocalPort 80 -Protocol TCP -Action Block
New-NetFirewallRule -DisplayName "Block Outbound Port 161" -Direction Inbound -LocalPort 161 -Protocol TCP -Action Block
New-NetFirewallRule -DisplayName "Block Outbound Port 162" -Direction Inbound -LocalPort 162 -Protocol TCP -Action Block
New-NetFirewallRule -DisplayName "Block Outbound Port 3389" -Direction Inbound -LocalPort 3389 -Protocol TCP -Action Block
New-NetFirewallRule -DisplayName "Block Outbound Port 4444" -Direction Inbound -LocalPort 4444 -Protocol TCP -Action Block
New-NetFirewallRule -DisplayName "Block Outbound Port 8080" -Direction Inbound -LocalPort 8080 -Protocol TCP -Action Block
New-NetFirewallRule -DisplayName "Block Outbound Port 8088" -Direction Inbound -LocalPort 8088 -Protocol TCP -Action Block
New-NetFirewallRule -DisplayName "Block Outbound Port 8888" -Direction Inbound -LocalPort 8888 -Protocol TCP -Action Block
Write-Host "Disabled TCP 21, TCP 22, TCP 23, TCP 25, TCP 80, TCP 8080, TCP 3389, TCP 161 and 162, TCP and UDP on 389 and 636 from inbound rules"

#UDP Ports
New-NetFirewallRule -DisplayName "Block UDP Outbound Port 3389" -Direction Inbound -LocalPort 3389 -Protocol UDP -Action Block
New-NetFirewallRule -DisplayName "Block UDP Outbound Port 161" -Direction Inbound -LocalPort 161 -Protocol UDP -Action Block
New-NetFirewallRule -DisplayName "Block UDP Outbound Port 162" -Direction Inbound -LocalPort 162 -Protocol UDP -Action Block
New-NetFirewallRule -DisplayName "Block UDP Outbound Port 389" -Direction Inbound -LocalPort 389 -Protocol UDP -Action Block
New-NetFirewallRule -DisplayName "Block UDP Outbound Port 636" -Direction Inbound -LocalPort 636 -Protocol UDP -Action Block
Write-Host "Disabled UDP 3389, UDP 161, UDP 162, UDP 389, UDP 636"

#Disable Guest Account 
Get-LocalUser Guest | Disable-LocalUser
Write-Host "Disabled Guest Account"

#List Files in Documents
Get-ChildItem -Force C:\Users\Default\Documents | Out-File -filepath C:\Users\Default\Desktop\process.txt



# Powershell script for adding/removing/showing entries to the hosts file.
#
# Known limitations:
# - does not handle entries with comments afterwards ("<ip>    <host>    # comment")
#

$file = "C:\Windows\System32\drivers\etc\hosts"

function add-host([string]$filename, [string]$ip, [string]$hostname) {
    remove-host $filename $hostname
    $ip + "`t`t" + $hostname | Out-File -encoding ASCII -append $filename
}

function remove-host([string]$filename, [string]$hostname) {
    $c = Get-Content $filename
    $newLines = @()

    foreach ($line in $c) {
        $bits = [regex]::Split($line, "\t+")
        if ($bits.count -eq 2) {
            if ($bits[1] -ne $hostname) {
                $newLines += $line
            }
        } else {
            $newLines += $line
        }
    }

    # Write file
    Clear-Content $filename
    foreach ($line in $newLines) {
        $line | Out-File -encoding ASCII -append $filename
    }
}

function print-hosts([string]$filename) {
    $c = Get-Content $filename

    foreach ($line in $c) {
        $bits = [regex]::Split($line, "\t+")
        if ($bits.count -eq 2) {
            Write-Host $bits[0] `t`t $bits[1]
        }
    }
}

try {
    if ($args[0] -eq "add") {

        if ($args.count -lt 3) {
            throw "Not enough arguments for add."
        } else {
            add-host $file $args[1] $args[2]
        }

    } elseif ($args[0] -eq "remove") {

        if ($args.count -lt 2) {
            throw "Not enough arguments for remove."
        } else {
            remove-host $file $args[1]
        }

    } elseif ($args[0] -eq "show") {
        print-hosts $file
    } else {
        throw "Invalid operation '" + $args[0] + "' - must be one of 'add', 'remove', 'show'."
    }
} catch  {
    Write-Host $error[0]
    Write-Host "`nUsage: hosts add <ip> <hostname>`n       hosts remove <hostname>`n       hosts show"
}




#Finds Files with set extensions in the C:\ drive
Write-Host "Searching for Files..."
Get-ChildItem -Path C:\Users -Include *.jpg,*.png,*.jpeg,*.avi,*.mp4,*.mp3,*.wav -Exclude *.dll,*.doc,*.docx,  -File -Recurse -ErrorAction SilentlyContinue | Out-File -filepath C:\UnwantedFiles.txt
Write-Host "Searching Complete Check in the Main C:\ directory for file!"


#Enforces Password Complexity 
secedit /export /cfg c:\secpol.cfg
(GC C:\secpol.cfg) -Replace "PasswordComplexity = 0","PasswordComplexity = 1" | Out-File C:\secpol.cfg
secedit /configure /db c:\windows\security\local.sdb /cfg c:\secpol.cfg /areas SECURITYPOLICY
Remove-Item C:\secpol.cfg -Force
Write-Host "Password Complexity Enforced"

 
#Lists and outputs Schedule Tasks
Get-ScheduledTask | where state -EQ 'ready' | Get-ScheduledTaskInfo | 
Export-Csv -NoTypeInformation -Path C:\scheduledTasksResults.csv

#Get netstat info
netstat -ano | Out-File $Dir\netstat.txt

#Uninstall programs
control appwiz.cpl

echo "Uninstall programs"
Read-Host -Prompt "Press enter to continue"

$Processes = @(get-process | select-object name,company,path -uniq |
        where-object {$_.Path -like 'C:\Program Files\*' -or $_.Path -like 'C:\ProgramData\*' -and $_.Company -notmatch "Google" -and $_.Company -notmatch "Opera" -and $_.Company -notmatch "Mozilla" -and $_.Company -notmatch "VMware"})
foreach($Process in $Processes){
    Stop-Process -name $Process.name -force
}

$ProgramFiles = Get-ChildItem 'C:\Program Files' -exclude *Windows*,*Microsoft* -force | 
       Where-Object {$_.PSIsContainer} | 
       Foreach-Object {$_.Name}
$ProgramFiles86 = Get-ChildItem 'C:\Program Files (x86)' -exclude *Windows*,*Microsoft* -force | 
       Where-Object {$_.PSIsContainer} | 
       Foreach-Object {$_.Name}
$ProgramData = Get-ChildItem 'C:\ProgramData' -exclude *Windows*,*Microsoft* -force | 
       Where-Object {$_.PSIsContainer} | 
       Foreach-Object {$_.Name}
$Programs = $ProgramFiles + $ProgramFiles86 + $ProgramData | Sort-object | Out-File $Dir\ProgramFiles.txt
Get-Content $Dir\ProgramFiles.txt

do {
$DeleteProg = Read-Host -Prompt "Should a program be deleted? Y/N"
    if ($DeleteProg -eq "Y") {
        $Programs
        $DelProg = Read-Host -Prompt "What program?"
            Remove-Item "C:\Program Files\$DelProg" -Recurse -ErrorAction SilentlyContinue | out-null 
            Remove-Item "C:\Program Files (x86)\$DelProg" -Recurse -ErrorAction SilentlyContinue | out-null 
            Remove-Item "C:\Program Data\$DelProg" -Recurse -ErrorAction SilentlyContinue | out-null }
    else {break}
    } while ($DeleteProg -eq "Y")


#Delete users
Net user

do {
$Delete = Read-host -Prompt "Should a user be deleted? Y/N"
    if ($Delete -eq "Y") {
        $DelUser = Read-host -Prompt "What user?"
            net user $DelUser /DELETE | out-null }
    else {break}
    net user
    } while ($Delete -eq "Y")

do {
$Add = Read-host -Prompt "Should a user be added? Y/N"
    if ($Add -eq "Y") {
        $AddUser = Read-host -Prompt "Username?"
            net user $AddUser /Add | out-null }
    else {break}
    net user
    } while ($Add -eq "Y")



#Set passwords for all accounts
$Usernames = Get-WmiObject -class win32_useraccount -filter "LocalAccount='True'"
foreach ($Username in $Usernames) {
    net user $Username.Name Cyb3rP@tr10t /passwordreq:yes /logonpasswordchg:yes | out-null }
wmic UserAccount set PasswordExpires=True | out-null
wmic UserAccount set Lockout=False | out-null


#Delete shares
net share

do {
$Share = Read-host -Prompt "Should a share be removed? Y/N"
    if ($Share -eq "Y") {
        $DelShare = Read-Host -Prompt "Share?"
            net share $DelShare /delete | out-null }
    else {break}
    net share
    } while ($Share -eq "Y") 


#Enable Structured Exception Handling Overwrite Protection
Set-ItemProperty -path "HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager\kernel" -name DisableExceptionChainValidation -value 0 | out-null

#Enable Structured Exception Handling Overwrite Protection
Set-ItemProperty -path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" -name LocalAccountTokenFilterPolicy -value 0 | out-null

#Disable Autoplay
$TestPath = Test-Path "HKLM:\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer"
if($TestPath -match 'False'){
    New-Item -Path "HKLM:\Software\Microsoft\Windows\CurrentVersion\Policies" -Name Explorer | out-null }
New-ItemProperty -Path "HKLM:\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer" -name NoDriveTypeAutoRun -value 0xff -ErrorAction SilentlyContinue | out-null
Set-ItemProperty -Path "HKLM:\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer" -name NoDriveTypeAutoRun -value 0xff | out-null
New-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\AutoplayHandlers" -name DisableAutoplay -value 1 -ErrorAction SilentlyContinue | out-null
Set-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\AutoplayHandlers" -name DisableAutoplay -value 1 | out-null

#Disable offline files
Set-ItemProperty -path "HKLM:\SYSTEM\CurrentControlSet\Services\CSC" -name Start -value 4 | out-null

#Disable ipv6
New-ItemProperty -path "HKLM:\SYSTEM\CurrentControlSet\Services\tcpip6\Parameters" -name DisabledComponents -value 0xff | out-null

#Show hidden files and file extensions 

Set-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced" -name Hidden -value 1 | out-null
Set-ItemProperty -path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced" -name HideFileExt -value 0 | out-null
Set-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced" -name ShowSuperHidden -value 1 | out-null

Stop-Process -ProcessName Explorer | out-null


#Disable optional features
servermanager
echo "Remove Features"
echo "Remove Roles"
Read-Host -prompt "Press enter to continue"


#Turn on audits
auditpol.exe /set /category:* /success:enable | out-null
auditpol.exe /set /category:* /failure:enable | out-null

#Require a password on wakeup
powercfg -SETACVALUEINDEX SCHEME_BALANCED SUB_NONE CONSOLELOCK 1 | out-null

echo "netstat info in netstat.txt"
Read-Host -Prompt "Press enter to continue"

#Open control panel applets for extra configuration
echo "A bunch of control panel applets are set to open after this"
read-host -prompt "Press enter to continue"

control inetcpl.cpl
control firewall.cpl

echo "Reminders:"
echo "Check the hosts file"

#Check for updates
echo "Begin updates"
control /name Microsoft.WindowsUpdate
read-host -prompt "Press enter to continue"
