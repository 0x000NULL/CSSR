@echo off
echo Checking if script contains Administrative rights...
net sessions
if %errorlevel%==0 (
echo Success!
) else (
echo No admin, please run with Administrative rights...
pause
exit
)
:MENU
echo Choose An option:
echo 1. A bunch of automated things I guess
echo 2. List Processes
echo 3. Changing Password Policies
echo 4. Find Files
echo 5. Disable Remote Desktop
echo 6. Enable Auto-Update
echo 7. Disable Weak services
echo 8. System Integrity Scan
echo 9. Powershell rootkit detection

CHOICE /C 123456789 /M "Enter your choice:"
if ERRORLEVEL 9 goto Nine
if ERRORLEVEL 8 goto Eight
if ERRORLEVEL 7 goto Seven
if ERRORLEVEL 6 goto Six
if ERRORLEVEL 5 goto Five
if ERRORLEVEL 4 goto Four
if ERRORLEVEL 3 goto Three
if ERRORLEVEL 2 goto Two
if ERRORLEVEL 1 goto One
:One
REM Automation found from all over the interwebs, sources unknown, please open issue.
REM Turns on UAC
reg ADD HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System /v EnableLUA /t REG_DWORD /d 1 /f
REM Turns off RDP
reg add "HKLM\SYSTEM\CurrentControlSet\Control\Terminal Server" /v fDenyTSConnections /t REG_DWORD /d 1 /f
reg add "HKLM\SYSTEM\CurrentControlSet\Control\Terminal Server\WinStations\RDP-Tcp" /v UserAuthentication /t REG_DWORD /d 0 /f

REM Failsafe
if %errorlevel%==1 netsh advfirewall firewall set service type = remotedesktop mode = disable
REM Windows auomatic updates
reg add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WindowsUpdate\Auto Update" /v AUOptions /t REG_DWORD /d 3 /f


echo Cleaning out the DNS cache...
ipconfig /flushdns
echo Writing over the hosts file...
attrib -r -s C:\WINDOWS\system32\drivers\etc\hosts
echo > C:\Windows\System32\drivers\etc\hosts
if %errorlevel%==1 echo There was an error in writing to the hosts file (not running this as Admin probably)
REM Services
echo Showing you the services...
net start
echo Now writing services to a file and searching for vulnerable services...
net start > servicesstarted.txt
echo This is only common services, not nessecarily going to catch 100%
REM looks to see if remote registry is on
net start | findstr Remote Registry
if %errorlevel%==0 (
	echo Remote Registry is running!
	echo Attempting to stop...
	net stop RemoteRegistry
	sc config RemoteRegistry start=disabled
	if %errorlevel%==1 echo Stop failed... sorry...
) else ( 
	echo Remote Registry is already indicating stopped.
)
REM Remove all saved credentials
cmdkey.exe /list > "%TEMP%\List.txt"
findstr.exe Target "%TEMP%\List.txt" > "%TEMP%\tokensonly.txt"
FOR /F "tokens=1,2 delims= " %%G IN (%TEMP%\tokensonly.txt) DO cmdkey.exe /delete:%%H
del "%TEMP%\*.*" /s /f /q
set SRVC_LIST=(RemoteAccess Telephony tlntsvr p2pimsvc simptcp fax msftpsvc)
	for %%i in %HITHERE% do net stop %%i
	for %%i in %HITHERE% sc config %%i start= disabled
netsh advfirewall firewall set rule name="Remote Assistance (DCOM-In)" new enable=no >NUL
netsh advfirewall firewall set rule name="Remote Assistance (PNRP-In)" new enable=no >NUL
netsh advfirewall firewall set rule name="Remote Assistance (RA Server TCP-In)" new enable=no >NUL
netsh advfirewall firewall set rule name="Remote Assistance (SSDP TCP-In)" new enable=no >NUL
netsh advfirewall firewall set rule name="Remote Assistance (SSDP UDP-In)" new enable=no >NUL
netsh advfirewall firewall set rule name="Remote Assistance (TCP-In)" new enable=no >NUL
netsh advfirewall firewall set rule name="Telnet Server" new enable=no >NUL
netsh advfirewall firewall set rule name="netcat" new enable=no >NUL
dism /online /disable-feature /featurename:IIS-WebServerRole >NUL
dism /online /disable-feature /featurename:IIS-WebServer >NUL
dism /online /disable-feature /featurename:IIS-CommonHttpFeatures >NUL
dism /online /disable-feature /featurename:IIS-HttpErrors >NUL
dism /online /disable-feature /featurename:IIS-HttpRedirect >NUL
dism /online /disable-feature /featurename:IIS-ApplicationDevelopment >NUL
dism /online /disable-feature /featurename:IIS-NetFxExtensibility >NUL
dism /online /disable-feature /featurename:IIS-NetFxExtensibility45 >NUL
dism /online /disable-feature /featurename:IIS-HealthAndDiagnostics >NUL
dism /online /disable-feature /featurename:IIS-HttpLogging >NUL
dism /online /disable-feature /featurename:IIS-LoggingLibraries >NUL
dism /online /disable-feature /featurename:IIS-RequestMonitor >NUL
dism /online /disable-feature /featurename:IIS-HttpTracing >NUL
dism /online /disable-feature /featurename:IIS-Security >NUL
dism /online /disable-feature /featurename:IIS-URLAuthorization >NUL
dism /online /disable-feature /featurename:IIS-RequestFiltering >NUL
dism /online /disable-feature /featurename:IIS-IPSecurity >NUL
dism /online /disable-feature /featurename:IIS-Performance >NUL
dism /online /disable-feature /featurename:IIS-HttpCompressionDynamic >NUL
dism /online /disable-feature /featurename:IIS-WebServerManagementTools >NUL
dism /online /disable-feature /featurename:IIS-ManagementScriptingTools >NUL
dism /online /disable-feature /featurename:IIS-IIS6ManagementCompatibility >NUL
dism /online /disable-feature /featurename:IIS-Metabase >NUL
dism /online /disable-feature /featurename:IIS-HostableWebCore >NUL
dism /online /disable-feature /featurename:IIS-StaticContent >NUL
dism /online /disable-feature /featurename:IIS-DefaultDocument >NUL
dism /online /disable-feature /featurename:IIS-DirectoryBrowsing >NUL
dism /online /disable-feature /featurename:IIS-WebDAV >NUL
dism /online /disable-feature /featurename:IIS-WebSockets >NUL
dism /online /disable-feature /featurename:IIS-ApplicationInit >NUL
dism /online /disable-feature /featurename:IIS-ASPNET >NUL
dism /online /disable-feature /featurename:IIS-ASPNET45 >NUL
dism /online /disable-feature /featurename:IIS-ASP >NUL
dism /online /disable-feature /featurename:IIS-CGI >NUL
dism /online /disable-feature /featurename:IIS-ISAPIExtensions >NUL
dism /online /disable-feature /featurename:IIS-ISAPIFilter >NUL
dism /online /disable-feature /featurename:IIS-ServerSideIncludes >NUL
dism /online /disable-feature /featurename:IIS-CustomLogging >NUL
dism /online /disable-feature /featurename:IIS-BasicAuthentication >NUL
dism /online /disable-feature /featurename:IIS-HttpCompressionStatic >NUL
dism /online /disable-feature /featurename:IIS-ManagementConsole >NUL
dism /online /disable-feature /featurename:IIS-ManagementService >NUL
dism /online /disable-feature /featurename:IIS-WMICompatibility >NUL
dism /online /disable-feature /featurename:IIS-LegacyScripts >NUL
dism /online /disable-feature /featurename:IIS-LegacySnapIn >NUL
dism /online /disable-feature /featurename:IIS-FTPServer >NUL
dism /online /disable-feature /featurename:IIS-FTPSvc >NUL
dism /online /disable-feature /featurename:IIS-FTPExtensibility >NUL
dism /online /disable-feature /featurename:TFTP >NUL
dism /online /disable-feature /featurename:TelnetClient >NUL
dism /online /disable-feature /featurename:TelnetServer >NUL
reg ADD "HKCU\Software\Microsoft\Internet Explorer\Main" /v DoNotTrack /t REG_DWORD /d 1 /f
reg ADD "HKCU\Software\Microsoft\Internet Explorer\Download" /v RunInvalidSignatures /t REG_DWORD /d 1 /f
reg ADD "HKCU\Software\Microsoft\Internet Explorer\Main\FeatureControl\FEATURE_LOCALMACHINE_LOCKDOWN\Settings" /v LOCALMACHINE_CD_UNLOCK /t REG_DWORD /d 1 /t
reg ADD "HKCU\Software\Microsoft\Windows\CurrentVersion\Internet Settings" /v WarnonBadCertRecving /t REG_DWORD /d /1 /f
reg ADD "HKCU\Software\Microsoft\Windows\CurrentVersion\Internet Settings" /v WarnOnPostRedirect /t REG_DWORD /d 1 /f
reg ADD "HKCU\Software\Microsoft\Windows\CurrentVersion\Internet Settings" /v WarnonZoneCrossing /t REG_DWORD /d 1 /f
reg ADD "HKCU\Software\Microsoft\Windows\CurrentVersion\Internet Settings" /v DisablePasswordCaching /t REG_DWORD /d 1 /f 
reg ADD HKCU\SYSTEM\CurrentControlSet\Services\CDROM /v AutoRun /t REG_DWORD /d 1 /f
reg ADD HKLM\SYSTEM\CurrentControlSet\Control\CrashControl /v CrashDumpEnabled /t REG_DWORD /d 0 /f
REM Common Policies
REM Restrict CD ROM drive
reg ADD "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon" /v AllocateCDRoms /t REG_DWORD /d 1 /f
REM Automatic Admin logon
reg ADD "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon" /v AutoAdminLogon /t REG_DWORD /d 0 /f
REM Logo message text
reg ADD "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon" /v LegalNoticeText /t REG_SZ /d "Lol noobz pl0x don't hax, thx bae"
REM Logon message title bar
reg ADD "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon" /v LegalNoticeCaption /t REG_SZ /d "Dnt hax me"
REM Wipe page file from shutdown
reg ADD "HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\Memory Management" /v ClearPageFileAtShutdown /t REG_DWORD /d 1 /f
REM LOL this is a key? Disallow remote access to floppie disks
reg ADD "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon" /v AllocateFloppies /t REG_DWORD /d 1 /f
REM Prevent print driver installs 
reg ADD "HKLM\SYSTEM\CurrentControlSet\Control\Print\Providers\LanMan Print Services\Servers" /v AddPrinterDrivers /t REG_DWORD /d 1 /f
REM Limit local account use of blank passwords to console
reg ADD "HKLM\SYSTEM\CurrentControlSet\Control\Lsa" /v LimitBlankPasswordUse /t REG_DWORD /d 1 /f
REM Auditing access of Global System Objects
reg ADD "HKLM\SYSTEM\CurrentControlSet\Control\Lsa" /v auditbaseobjects /t REG_DWORD /d 1 /f
REM Auditing Backup and Restore
reg ADD "HKLM\SYSTEM\CurrentControlSet\Control\Lsa" /v fullprivilegeauditing /t REG_DWORD /d 1 /f
REM Do not display last user on logon
reg ADD HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System /v dontdisplaylastusername /t REG_DWORD /d 1 /f
REM UAC setting (Prompt on Secure Desktop)
reg ADD HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System /v PromptOnSecureDesktop /t REG_DWORD /d 1 /f
REM Enable Installer Detection
reg ADD HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System /v EnableInstallerDetection /t REG_DWORD /d 1 /f
REM Undock without logon
reg ADD HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System /v undockwithoutlogon /t REG_DWORD /d 0 /f
REM Maximum Machine Password Age
reg ADD HKLM\SYSTEM\CurrentControlSet\services\Netlogon\Parameters /v MaximumPasswordAge /t REG_DWORD /d 15 /f
REM Disable machine account password changes
reg ADD HKLM\SYSTEM\CurrentControlSet\services\Netlogon\Parameters /v DisablePasswordChange /t REG_DWORD /d 1 /f
REM Require Strong Session Key
reg ADD HKLM\SYSTEM\CurrentControlSet\services\Netlogon\Parameters /v RequireStrongKey /t REG_DWORD /d 1 /f
REM Require Sign/Seal
reg ADD HKLM\SYSTEM\CurrentControlSet\services\Netlogon\Parameters /v RequireSignOrSeal /t REG_DWORD /d 1 /f
REM Sign Channel
reg ADD HKLM\SYSTEM\CurrentControlSet\services\Netlogon\Parameters /v SignSecureChannel /t REG_DWORD /d 1 /f
REM Seal Channel
reg ADD HKLM\SYSTEM\CurrentControlSet\services\Netlogon\Parameters /v SealSecureChannel /t REG_DWORD /d 1 /f
REM Don't disable CTRL+ALT+DEL even though it serves no purpose
reg ADD HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System /v DisableCAD /t REG_DWORD /d 0 /f 
REM Restrict Anonymous Enumeration #1
reg ADD HKLM\SYSTEM\CurrentControlSet\Control\Lsa /v restrictanonymous /t REG_DWORD /d 1 /f 
REM Restrict Anonymous Enumeration #2
reg ADD HKLM\SYSTEM\CurrentControlSet\Control\Lsa /v restrictanonymoussam /t REG_DWORD /d 1 /f 
REM Idle Time Limit - 45 mins
reg ADD HKLM\SYSTEM\CurrentControlSet\services\LanmanServer\Parameters /v autodisconnect /t REG_DWORD /d 45 /f 
REM Require Security Signature - Disabled pursuant to checklist
reg ADD HKLM\SYSTEM\CurrentControlSet\services\LanmanServer\Parameters /v enablesecuritysignature /t REG_DWORD /d 0 /f 
REM Enable Security Signature - Disabled pursuant to checklist
reg ADD HKLM\SYSTEM\CurrentControlSet\services\LanmanServer\Parameters /v requiresecuritysignature /t REG_DWORD /d 0 /f 
REM Disable Domain Credential Storage
reg ADD HKLM\SYSTEM\CurrentControlSet\Control\Lsa /v disabledomaincreds /t REG_DWORD /d 1 /f 
REM Don't Give Anons Everyone Permissions
reg ADD HKLM\SYSTEM\CurrentControlSet\Control\Lsa /v everyoneincludesanonymous /t REG_DWORD /d 0 /f 
REM SMB Passwords unencrypted to third party? How bout nah
reg ADD HKLM\SYSTEM\CurrentControlSet\services\LanmanWorkstation\Parameters /v EnablePlainTextPassword /t REG_DWORD /d 0 /f
REM Null Session Pipes Cleared
reg ADD HKLM\SYSTEM\CurrentControlSet\services\LanmanServer\Parameters /v NullSessionPipes /t REG_MULTI_SZ /d "" /f
REM Remotely accessible registry paths cleared
reg ADD HKLM\SYSTEM\CurrentControlSet\Control\SecurePipeServers\winreg\AllowedExactPaths /v Machine /t REG_MULTI_SZ /d "" /f
REM Remotely accessible registry paths and sub-paths cleared
reg ADD HKLM\SYSTEM\CurrentControlSet\Control\SecurePipeServers\winreg\AllowedPaths /v Machine /t REG_MULTI_SZ /d "" /f
REM Restict anonymous access to named pipes and shares
reg ADD HKLM\SYSTEM\CurrentControlSet\services\LanmanServer\Parameters /v NullSessionShares /t REG_MULTI_SZ /d "" /f
REM Allow to use Machine ID for NTLM
reg ADD HKLM\SYSTEM\CurrentControlSet\Control\Lsa /v UseMachineId /t REG_DWORD /d 0 /f

goto MENU
:Two
REM Listing possible penetrations
cd C:\
echo "STARTING TO OUTPUT PROCESS FILES DIRECTLY TO THE C:\ DRIVE!"
wmic process list brief > BriefProcesses.txt
if %errorlevel%==1 echo Brief Processes failed to write
wmic process list full >FullProcesses.txt
if %errorlevel%==1 echo Full Processes failed to write
wmic startup list full > StartupLists.txt
if %errorlevel%==1 echo Startup Processes failed to write
net start > StartedProcesses.txt
if %errorlevel%==1 echo Started processes failed to write
reg export HKLM\Software\Microsoft\Windows\CurrentVersion\Run  Run.reg
if %errorlevel%==1 echo Run processes failed to write
goto MENU
:Three
echo "OUTPUT DONE, CHANGING PASSWORD POLICIES!"
REM Passwords must be 10 digits
net accounts /minpwlen:10
REM Passwords must be changed every 30 days
net accounts /maxpwage:30
REM Passwords can only be changed after 5 day has passed
net accounts /minpwage:5
REM Display current password policy
echo "CURRENT POLICY"
PAUSE
net accounts
goto MENU
:Four
REM Find file
@echo off
color 0f
cls
echo Flashing Disk to .flashed Files to reference....
dir /b /s "C:\Program Files\" > programfiles.flashed
dir /b /s "C:\Program Files (x86)\" >> programfiles.flashed
echo Program Files flashed
dir /b /s "C:\Users\" > users.flashed
dir /b /s "C:\Documents and Settings" >> users.flashed
echo User profiles flashed
dir /b /s "C:\" > c.flashed
echo C:\ Flashed
pause
echo Finding media files in C:\Users and/or C:\Documents and Settings...
findstr .mp3 users.flashed >NUL
if %errorlevel%==0 where /r c:\Users\ *.mp3 > media_audio
findstr .ac3 users.flashed >NUL
if %errorlevel%==0 where /r c:\Users\ *.ac3 >> media_audio
findstr .aac users.flashed >NUL
if %errorlevel%==0 where /r c:\Users\ *.aac >> media_audio
findstr .aiff users.flashed >NUL
if %errorlevel%==0 where /r c:\Users\ *.aiff >> media_audio
findstr .flac users.flashed >NUL
if %errorlevel%==0 where /r c:\Users\ *.flac >> media_audio
findstr .m4a users.flashed >NUL
if %errorlevel%==0 where /r c:\Users\ *.m4a >> media_audio
findstr .m4p users.flashed >NUL
if %errorlevel%==0 where /r c:\Users\ *.m4p >> media_audio
findstr .midi users.flashed >NUL
if %errorlevel%==0 where /r c:\Users\ *.midi >> media_audio
findstr .mp2 users.flashed >NUL
if %errorlevel%==0 where /r c:\Users\ *.mp2 >> media_audio
findstr .m3u users.flashed >NUL
if %errorlevel%==0 where /r c:\Users\ *.m3u >> media_audio
findstr .ogg users.flashed >NUL
if %errorlevel%==0 where /r c:\Users\ *.ogg >> media_audio
findstr .vqf users.flashed >NUL
if %errorlevel%==0 where /r c:\Users\ *.vqf >> media_audio
findstr .wav users.flashed >NUL
if %errorlevel%==0 where /r c:\Users\ *.wav >> media_audio
findstr .wma users.flashed >NUL
if %errorlevel%==0 where /r c:\Users\ *.wma >> media_video
findstr .mp4 users.flashed >NUL
if %errorlevel%==0 where /r c:\Users\ *.mp4 >> media_video
findstr .avi users.flashed >NUL
if %errorlevel%==0 where /r c:\Users\ *.avi >> media_video
findstr .mpeg4 users.flashed >NUL
if %errorlevel%==0 where /r c:\Users\ .mpeg4 >> media_video
REM BREAKLINE
findstr .gif users.flashed >NUL
if %errorlevel%==0 where /r c:\Users\ *.gif >> media_pics
findstr .png users.flashed >NUL
if %errorlevel%==0 where /r c:\Users\ *.png >> media_pics
findstr .bmp users.flashed >NUL
if %errorlevel%==0 where /r c:\Users\ *.bmp >> media_pics
findstr .jpg users.flashed >NUL
if %errorlevel%==0 where /r c:\Users\ .jpg >> media_pics
findstr .jpeg users.flashed >NUL
if %errorlevel%==0 where /r c:\Users\ .jpeg >> media_pics
C:\WINDOWS\system32\notepad.exe media_video
C:\WINDOWS\system32\notepad.exe media_audio
C:\WINDOWS\system32\notepad.exe media_pics
echo Finding Hacktools now...
findstr "Cain" programfiles.flashed
if %errorlevel%==0 (
echo Cain detected. Please take note, then press any key.
pause >NUL
)
cls
findstr "nmap" programfiles.flashed
if %errorlevel%==0 (
echo Nmap detected. Please take note, then press any key.
pause >NUL
)
cls
findstr "keylogger" programfiles.flashed
if %errorlevel%==0 (
echo Potential keylogger detected. Please take note, then press any key.
pause >NUL
)
cls
findstr "Armitage" programfiles.flashed
if %errorlevel%==0 (
echo Potential Armitage detected. Please take note, then press any key.
pause >NUL
)
cls
findstr "Metasploit" programfiles.flashed
if %errorlevel%==0 (
echo Potential Metasploit framework detected. Please take note, then press any key.
pause >NUL
)
cls
findstr "Shellter" programfiles.flashed
if %errorlevel%==0 (
echo Potential Shellter detected. Please take note, then press any key.
pause >NUL
)
cls
goto MENU
:Five
REM No Remote Desktop
echo "DISABLING REMOTE DESKTOP"
reg add "HKLM\SYSTEM\CurrentControlSet\Control\Terminal Server" /v fDenyTSConnections /t REG_DWORD /d 1 /f
reg add "HKLM\SYSTEM\CurrentControlSet\Control\Terminal Server\WinStations\RDP-Tcp" /v UserAuthentication /t REG_DWORD /d 0 /f
goto MENU
:Six
REM Windows auomatic updates
echo "ENABLING AUTO-UPDATES"
reg add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WindowsUpdate\Auto Update" /v AUOptions /t REG_DWORD /d 3 /f
goto MENU
:Seven
REM Removing good ol' insecure stuff
echo "DISABLING WEAK SERVICES"
dism /online /disable-feature /featurename:IIS-WebServerRole
dism /online /disable-feature /featurename:IIS-WebServer
dism /online /disable-feature /featurename:IIS-CommonHttpFeatures
dism /online /disable-feature /featurename:IIS-HttpErrors
dism /online /disable-feature /featurename:IIS-HttpRedirect
dism /online /disable-feature /featurename:IIS-ApplicationDevelopment
dism /online /disable-feature /featurename:IIS-NetFxExtensibility
dism /online /disable-feature /featurename:IIS-NetFxExtensibility45
dism /online /disable-feature /featurename:IIS-HealthAndDiagnostics
dism /online /disable-feature /featurename:IIS-HttpLogging
dism /online /disable-feature /featurename:IIS-LoggingLibraries
dism /online /disable-feature /featurename:IIS-RequestMonitor
dism /online /disable-feature /featurename:IIS-HttpTracing
dism /online /disable-feature /featurename:IIS-Security
dism /online /disable-feature /featurename:IIS-URLAuthorization
dism /online /disable-feature /featurename:IIS-RequestFiltering
dism /online /disable-feature /featurename:IIS-IPSecurity
dism /online /disable-feature /featurename:IIS-Performance
dism /online /disable-feature /featurename:IIS-HttpCompressionDynamic
dism /online /disable-feature /featurename:IIS-WebServerManagementTools
dism /online /disable-feature /featurename:IIS-ManagementScriptingTools
dism /online /disable-feature /featurename:IIS-IIS6ManagementCompatibility
dism /online /disable-feature /featurename:IIS-Metabase
dism /online /disable-feature /featurename:IIS-HostableWebCore
dism /online /disable-feature /featurename:IIS-StaticContent
dism /online /disable-feature /featurename:IIS-DefaultDocument
dism /online /disable-feature /featurename:IIS-DirectoryBrowsing
dism /online /disable-feature /featurename:IIS-WebDAV
dism /online /disable-feature /featurename:IIS-WebSockets
dism /online /disable-feature /featurename:IIS-ApplicationInit
dism /online /disable-feature /featurename:IIS-ASPNET
dism /online /disable-feature /featurename:IIS-ASPNET45
dism /online /disable-feature /featurename:IIS-ASP
dism /online /disable-feature /featurename:IIS-CGI
dism /online /disable-feature /featurename:IIS-ISAPIExtensions
dism /online /disable-feature /featurename:IIS-ISAPIFilter
dism /online /disable-feature /featurename:IIS-ServerSideIncludes
dism /online /disable-feature /featurename:IIS-CustomLogging
dism /online /disable-feature /featurename:IIS-BasicAuthentication
dism /online /disable-feature /featurename:IIS-HttpCompressionStatic
dism /online /disable-feature /featurename:IIS-ManagementConsole
dism /online /disable-feature /featurename:IIS-ManagementService
dism /online /disable-feature /featurename:IIS-WMICompatibility
dism /online /disable-feature /featurename:IIS-LegacyScripts
dism /online /disable-feature /featurename:IIS-LegacySnapIn
dism /online /disable-feature /featurename:IIS-FTPServer
dism /online /disable-feature /featurename:IIS-FTPSvc
dism /online /disable-feature /featurename:IIS-FTPExtensibility
dism /online /disable-feature /featurename:TFTP
dism /online /disable-feature /featurename:TelnetClient
dism /online /disable-feature /featurename:TelnetServer
goto MENU
:Eight
REM START SYS INTEG SCAN!
echo "STARTING SYSTEM INTERGRITY SCAN"
echo "If it fails make sure you can access Sfc.exe"
Sfc.exe /scannow
goto MENU
:Nine
REM PowerShell RootKit detection start
echo "POWERSHELL ROOTKIT DETECTION WITH MALWAREBYTES ROOTKIT BETA (Requires powershell execution policy)"
REM Downloads MalwareBytes scan file
powershell Invoke-WebRequest -OutFile MBRTKit.exe https://data-cdn.mbamupdates.com/web/mbar-1.10.3.1001.exe
MBRTKit.exe
goto MENU
PAUSE
