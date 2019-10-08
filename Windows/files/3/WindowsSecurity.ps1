#Get directory of script folder
$oldDir = Get-ChildItem C:\Users\$env:USERNAME -Filter MainScript.ps1 -Recurse -ErrorAction SilentlyContinue
$Dir = @($oldDir.Directoryname)

#Turn on automatic updates
$AutoUpdate = (New-Object -com "Microsoft.Update.AutoUpdate").Settings
$AutoUpdate.NotificationLevel = 4
$AutoUpdate.Save()

#Check for updates
echo "Begin updates"
control /name Microsoft.WindowsUpdate
read-host -prompt "Press enter to continue"

#Save your username as variable $You
$You = $env:USERNAME

#Import taskmanager settings and open taskmanager

regedit.exe /S $Dir\Scriptfiles\TaskManager.reg

#Get netstat info
netstat -ano | Out-File $Dir\netstat.txt

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

#Disable guest and administrator
net user administrator /active:no | out-null
net user guest /active:no | out-null

#Set passwords for all accounts
$Usernames = Get-WmiObject -class win32_useraccount -filter "LocalAccount='True'"
foreach ($Username in $Usernames) {
    net user $Username.Name Cyb3rP@tr10t /passwordreq:yes /logonpasswordchg:yes | out-null }
wmic UserAccount set PasswordExpires=True | out-null
wmic UserAccount set Lockout=False | out-null

#Delete groups and remove users
net localgroup

do {
$DelGroup = Read-host -Prompt "Should a group be deleted? Y/N"
    if ($DelGroup -eq "Y") {
        $DeleteGroup = Read-host -Prompt "What group?"
            net localgroup $DeleteGroup /delete | out-null }
    else {break}
    net localgroup
    } while ($DelGroup -eq "Y")

net localgroup Administrators

do {
$RemoveFromGroup = Read-host -Prompt "Should a user be removed from Administrators Y/N"
    if ($RemoveFromGroup -eq "Y") {
        $UserRemoveFromGroup = Read-Host -Prompt "User? (case sensitive)"
            net localgroup Administrators $UserRemoveFromGroup /delete | out-null }
    else {break}
    net localgroup Administrators
    } while ($RemoveFromGroup -eq "Y")
    
do {
$AddToGroup = Read-host -Prompt "Should a user be added to Administrators Y/N"
    if ($AddToGroup -eq "Y") {
        $UserAddToGroup = Read-Host -Prompt "User? (case sensitive)"
            net localgroup Administrators $UserAddToGroup /add | out-null }
    else {break}
    net localgroup Administrators
    } while ($AddToGroup -eq "Y")

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

#Enable firewall
echo "Turning on firewall"
netsh advfirewall set allprofiles state on | out-null

#Disable remote desktop
Set-ItemProperty -Path "HKLM:\System\CurrentControlSet\Control\Terminal Server" -Name "fDenyTSConnections" -Value 1 | out-null

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

#Services
$DisableServices = @("tapisrv","bthserv","mcx2svc","remoteregistry","seclogon","telnet","tlntsvr","p2pimsvc","simptcp","fax","msftpsvc","cscservice","fax","msftpsvc","webclient")
foreach($DisableService in $DisableServices){
Stop-Service $DisableService -Force -ErrorAction SilentlyContinue | out-null
Set-Service $DisableService -StartupType Disabled -ErrorAction SilentlyContinue | out-null}

$EnableServices = @("eventlog","mpssvc","windefend","sppsvc","wuauserv","wscsvc")
foreach($EnableService in $EnableServices){
Set-Service $EnableService -StartupType Automatic -ErrorAction SilentlyContinue | out-null 
Start-Service $EnableService -ErrorAction SilentlyContinue | out-null }

$ManualServices = @("wersvc","wecsvc")
foreach($ManualService in $ManualServices){
Set-Service $ManualService -StartupType Manual -ErrorAction SilentlyContinue | out-null }

#Disable optional features
servermanager
echo "Remove Features"
echo "Remove Roles"
Read-Host -prompt "Press enter to continue"

#Scheduled Tasks
schtasks /query /fo CSV /v | out-file $Dir\schtasks.csv
$oldSchTasks = Import-CSV $Dir\schtasks.csv | Where-Object {$_.TaskName -notmatch "Microsoft" -and $_.TaskName -notmatch "Windows" -and $_.TaskName -notmatch "TaskName" -and $_.TaskName -notmatch "GoogleUpdate" -and $_.TaskName -notmatch "ScoringEngine" -and $_.TaskName -notmatch "Opera" -and $_.TaskName -notmatch "Firefox"}
$SchTasks = @($oldSchTasks) | out-file $Dir\schtasks.txt
$TaskName = $SchTasks.TaskName | out-file $Dir\schtasks2.txt
Get-Content $Dir\schtasks2.txt
$SchTask = Read-Host -prompt "Delete a schtask?"
if($SchTask = "Y"){
    $DelSchTask = Read-Host -prompt "What schtask?"
        schtasks /DELETE /TN $DelSchTask /F | out-null
}

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