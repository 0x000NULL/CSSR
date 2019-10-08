@echo off
set functions=checkFiles firewall lsp audit usrRights services winFeatures registry checkUsr misc netShare flushDNS defAccounts passwords rdp installMalwarebytes installAVG installMBAnti installMBSA installRevo installSUPER lockdown tools verifySys
::Get current running directory
set path=%~dp0
echo %path%output> "%path%resources\path.txt"
reg query "HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\PowerShell\1\PowerShellEngine" /v "PowerShellVersion" /z >nul
If %ERRORLEVEL% == 1 (
	echo POWERSHELL NOT INSTALLED, please install before continuing
	pause>nul
	exit
)
:: Get list of users on the computer
echo Users and Administrators output to %path%output\users.txt
start C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe "%path%resources\usrList.ps1"
:main
set /p mode="Auto or Manual mode? (a/m) "
if %mode%==a goto auto
if %mode%==A goto auto
if %mode%==m goto manual
if %mode%==M goto manual
echo invalid input %mode%
goto main

:auto
for %%a in (%functions%) do call:%%a
exit

:manual
pause
cls
for %%a in (%functions%) do echo %%a
set /p func="Enter function (exit to exit): "
if "%func%"=="exit" exit
call:%func%
goto:manual

:checkFiles
start C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe "%path%resources\Check_Files.ps1" /wait
goto:EOF

:firewall
echo Enabling firewall (make sure group policy is allowing modifications to the firewall)
netsh advfirewall set allprofiles state on
echo Firewall enabled
echo Setting basic firewall rules..
netsh advfirewall firewall set rule name="Remote Assistance (DCOM-In)" new enable=no 
netsh advfirewall firewall set rule name="Remote Assistance (PNRP-In)" new enable=no 
netsh advfirewall firewall set rule name="Remote Assistance (RA Server TCP-In)" new enable=no 
netsh advfirewall firewall set rule name="Remote Assistance (SSDP TCP-In)" new enable=no 
netsh advfirewall firewall set rule name="Remote Assistance (SSDP UDP-In)" new enable=no 
netsh advfirewall firewall set rule name="Remote Assistance (TCP-In)" new enable=no 
netsh advfirewall firewall set rule name="Telnet Server" new enable=no 
netsh advfirewall firewall set rule name="netcat" new enable=no
echo Set basic firewall rules
goto:EOF

:lsp
echo Setting password policy...
::Set account lockout to 5, min length to 8, max age to 30, min age to 1, and history to 5
net accounts /lockoutthreshold:5 /MINPWLEN:8 /MAXPWAGE:30 /MINPWAGE:1 /UNIQUEPW:5 
echo Set password policy: Password policy must meet complexity to enable
echo Set password policy: Store passwords using reversible encryption to disabled
echo Secpol.msc will be started for manual process
start secpol.msc /wait
pause
goto:EOF

:audit
echo Setting auditing success and failure for all categories
auditpol /set /category:* /success:enable
auditpol /set /category:* /failure:enable
echo Set auditing success and failure
goto:EOF

:usrRights
echo Installing ntrights.exe to C:\Windows\System32
copy %path%resources\ntrights.exe C:\Windows\System32
if exist C:\Windows\System32\ntrights.exe (
	echo Installation succeeded, managing user rights..
	set remove=("Backup Operators" "Everyone" "Power Users" "Users" "NETWORK SERVICE" "LOCAL SERVICE" "Remote Desktop User" "ANONOYMOUS LOGON" "Guest" "Performance Log Users")
	for %%a in (%remove%) do (
			ntrights -U %%a -R SeNetworkLogonRight 
			ntrights -U %%a -R SeIncreaseQuotaPrivilege
			ntrights -U %%a -R SeInteractiveLogonRight
			ntrights -U %%a -R SeRemoteInteractiveLogonRight
			ntrights -U %%a -R SeSystemtimePrivilege
			ntrights -U %%a +R SeDenyNetworkLogonRight
			ntrights -U %%a +R SeDenyRemoteInteractiveLogonRight
			ntrights -U %%a -R SeProfileSingleProcessPrivilege
			ntrights -U %%a -R SeBatchLogonRight
			ntrights -U %%a -R SeUndockPrivilege
			ntrights -U %%a -R SeRestorePrivilege
			ntrights -U %%a -R SeShutdownPrivilege
		)
		ntrights -U "Administrators" -R SeImpersonatePrivilege
		ntrights -U "Administrator" -R SeImpersonatePrivilege
		ntrights -U "SERVICE" -R SeImpersonatePrivilege
		ntrights -U "LOCAL SERVICE" +R SeImpersonatePrivilege
		ntrights -U "NETWORK SERVICE" +R SeImpersonatePrivilege
		ntrights -U "Administrators" +R SeMachineAccountPrivilege
		ntrights -U "Administrator" +R SeMachineAccountPrivilege
		ntrights -U "Administrators" -R SeIncreaseQuotaPrivilege
		ntrights -U "Administrator" -R SeIncreaseQuotaPrivilege
		ntrights -U "Administrators" -R SeDebugPrivilege
		ntrights -U "Administrator" -R SeDebugPrivilege
		ntrights -U "Administrators" +R SeLockMemoryPrivilege
		ntrights -U "Administrator" +R SeLockMemoryPrivilege
		ntrights -U "Administrators" -R SeBatchLogonRight
		ntrights -U "Administrator" -R SeBatchLogonRight
		echo Managed User Rights
)
goto:EOF

:services
set servicesD=RemoteAccess Telephony TapiSrv Tlntsvr tlntsvr p2pimsvc simptcp fax msftpsvc iprip ftpsvc RemoteRegistry RasMan RasAuto seclogon MSFTPSVC W3SVC SMTPSVC Dfs TrkWks MSDTC DNS ERSVC NtFrs MSFtpsvc helpsvc HTTPFilter IISADMIN IsmServ WmdmPmSN Spooler RDSessMgr RPCLocator RsoPProv	ShellHWDetection ScardSvr Sacsvr TermService Uploadmgr VDS VSS WINS WinHttpAutoProxySvc SZCSVC CscService hidserv IPBusEnum PolicyAgent SCPolicySvc SharedAccess SSDPSRV Themes upnphost nfssvc nfsclnt MSSQLServerADHelper
set servicesM=dmserver SrvcSurg
set servicesG=Dhcp Dnscache NtLmSsp
echo Disabling bad services...
for %%a in (%servicesD%) do (
	echo Service: %%a
	sc stop "%%a"
	sc config "%%a" start= disabled
)
echo Disabled bad services
echo Setting services to manual...
for %%b in (%servicesM%) do (
	echo Service: %%b
	sc config "%%b" start= demand
)
echo Set services to manual
echo Seting services to auto...
for %%c in (%servicesG%) do (
	echo Service: %%c
	sc config "%%c" start= auto
)
echo Started auto services
goto:EOF

:winFeatures
echo Installing Dism.exe
copy %path%resources\Dism.exe C:\Windows\System32
xcopy %path%resources\Dism C:\Windows\System32
echo Disabling Windows features...
set features=IIS-WebServerRole IIS-WebServer IIS-CommonHttpFeatures IIS-HttpErrors IIS-HttpRedirect IIS-ApplicationDevelopment IIS-NetFxExtensibility IIS-NetFxExtensibility45 IIS-HealthAndDiagnostics IIS-HttpLogging IIS-LoggingLibraries IIS-RequestMonitor IIS-HttpTracing IIS-Security IIS-URLAuthorization IIS-RequestFiltering IIS-IPSecurity IIS-Performance IIS-HttpCompressionDynamic IIS-WebServerManagementTools IIS-ManagementScriptingTools IIS-IIS6ManagementCompatibility IIS-Metabase IIS-HostableWebCore IIS-StaticContent IIS-DefaultDocument IIS-DirectoryBrowsing IIS-WebDAV IIS-WebSockets IIS-ApplicationInit IIS-ASPNET IIS-ASPNET45 IIS-ASP IIS-CGI IIS-ISAPIExtensions IIS-ISAPIFilter IIS-ServerSideIncludes IIS-CustomLogging IIS-BasicAuthentication IIS-HttpCompressionStatic IIS-ManagementConsole IIS-ManagementService IIS-WMICompatibility IIS-LegacyScripts IIS-LegacySnapIn IIS-FTPServer IIS-FTPSvc IIS-FTPExtensibility TFTP TelnetClient TelnetServer
for %%a in (%features%) do dism /online /disable-feature /featurename:%%a
echo Disabled Windows features
goto:EOF

:registry
echo Managing registry keys...
::Windows auomatic updates
reg add HKLM\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate\AU /v AutoInstallMinorUpdates /t REG_DWORD /d 1 /f
reg add HKLM\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate\AU /v NoAutoUpdate /t REG_DWORD /d 0 /f
reg add HKLM\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate\AU /v AUOptions /t REG_DWORD /d 4 /f
reg add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WindowsUpdate\Auto Update" /v AUOptions /t REG_DWORD /d 4 /f
reg add HKLM\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate /v DisableWindowsUpdateAccess /t REG_DWORD /d 0 /f
reg add HKLM\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate /v ElevateNonAdmins /t REG_DWORD /d 0 /f
reg add HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer /v NoWindowsUpdate /t REG_DWORD /d 0 /f
reg add "HKLM\SYSTEM\Internet Communication Management\Internet Communication" /v DisableWindowsUpdateAccess /t REG_DWORD /d 0 /f
reg add HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\WindowsUpdate /v DisableWindowsUpdateAccess /t REG_DWORD /d 0 /f
::Restrict CD ROM drive
reg ADD "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon" /v AllocateCDRoms /t REG_DWORD /d 1 /f
::Disallow remote access to floppy disks
reg ADD "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon" /v AllocateFloppies /t REG_DWORD /d 1 /f
::Disable auto Admin logon
reg ADD "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon" /v AutoAdminLogon /t REG_DWORD /d 0 /f
::Clear page file (Will take longer to shutdown)
reg ADD "HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\Memory Management" /v ClearPageFileAtShutdown /t REG_DWORD /d 1 /f
::Prevent users from installing printer drivers 
reg ADD "HKLM\SYSTEM\CurrentControlSet\Control\Print\Providers\LanMan Print Services\Servers" /v AddPrinterDrivers /t REG_DWORD /d 1 /f
::Add auditing to Lsass.exe
reg add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options\LSASS.exe" /v AuditLevel /t REG_DWORD /d 00000008 /f
::Enable LSA protection
reg add HKLM\SYSTEM\CurrentControlSet\Control\Lsa /v RunAsPPL /t REG_DWORD /d 00000001 /f
::Limit use of blank passwords
reg ADD HKLM\SYSTEM\CurrentControlSet\Control\Lsa /v LimitBlankPasswordUse /t REG_DWORD /d 1 /f
::Auditing access of Global System Objects
reg ADD HKLM\SYSTEM\CurrentControlSet\Control\Lsa /v auditbaseobjects /t REG_DWORD /d 1 /f
::Auditing Backup and Restore
reg ADD HKLM\SYSTEM\CurrentControlSet\Control\Lsa /v fullprivilegeauditing /t REG_DWORD /d 1 /f
::Restrict Anonymous Enumeration #1
reg ADD HKLM\SYSTEM\CurrentControlSet\Control\Lsa /v restrictanonymous /t REG_DWORD /d 1 /f
::Restrict Anonymous Enumeration #2
reg ADD HKLM\SYSTEM\CurrentControlSet\Control\Lsa /v restrictanonymoussam /t REG_DWORD /d 1 /f
::Disable storage of domain passwords
reg ADD HKLM\SYSTEM\CurrentControlSet\Control\Lsa /v disabledomaincreds /t REG_DWORD /d 1 /f
::Take away Anonymous user Everyone permissions
reg ADD HKLM\SYSTEM\CurrentControlSet\Control\Lsa /v everyoneincludesanonymous /t REG_DWORD /d 0 /f
::Allow Machine ID for NTLM
reg ADD HKLM\SYSTEM\CurrentControlSet\Control\Lsa /v UseMachineId /t REG_DWORD /d 0 /f
::Do not display last user on logon
reg ADD HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System /v dontdisplaylastusername /t REG_DWORD /d 1 /f
::Enable UAC
reg ADD HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System /v EnableLUA /t REG_DWORD /d 1 /f
::UAC setting (Prompt on Secure Desktop)
reg ADD HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System /v PromptOnSecureDesktop /t REG_DWORD /d 1 /f
::Enable Installer Detection
reg ADD HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System /v EnableInstallerDetection /t REG_DWORD /d 1 /f
::Disable undocking without logon
reg ADD HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System /v undockwithoutlogon /t REG_DWORD /d 0 /f
::Enable CTRL+ALT+DEL
reg ADD HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System /v DisableCAD /t REG_DWORD /d 0 /f
::Max password age
reg ADD HKLM\SYSTEM\CurrentControlSet\services\Netlogon\Parameters /v MaximumPasswordAge /t REG_DWORD /d 15 /f
::Disable machine account password changes
reg ADD HKLM\SYSTEM\CurrentControlSet\services\Netlogon\Parameters /v DisablePasswordChange /t REG_DWORD /d 1 /f
::Require strong session key
reg ADD HKLM\SYSTEM\CurrentControlSet\services\Netlogon\Parameters /v RequireStrongKey /t REG_DWORD /d 1 /f
::Require Sign/Seal
reg ADD HKLM\SYSTEM\CurrentControlSet\services\Netlogon\Parameters /v RequireSignOrSeal /t REG_DWORD /d 1 /f
::Sign Channel
reg ADD HKLM\SYSTEM\CurrentControlSet\services\Netlogon\Parameters /v SignSecureChannel /t REG_DWORD /d 1 /f
::Seal Channel
reg ADD HKLM\SYSTEM\CurrentControlSet\services\Netlogon\Parameters /v SealSecureChannel /t REG_DWORD /d 1 /f
::Set idle time to 45 minutes
reg ADD HKLM\SYSTEM\CurrentControlSet\services\LanmanServer\Parameters /v autodisconnect /t REG_DWORD /d 45 /f
::Require Security Signature - Disabled pursuant to checklist:::
reg ADD HKLM\SYSTEM\CurrentControlSet\services\LanmanServer\Parameters /v enablesecuritysignature /t REG_DWORD /d 0 /f
::Enable Security Signature - Disabled pursuant to checklist:::
reg ADD HKLM\SYSTEM\CurrentControlSet\services\LanmanServer\Parameters /v requiresecuritysignature /t REG_DWORD /d 0 /f
::Clear null session pipes
reg ADD HKLM\SYSTEM\CurrentControlSet\services\LanmanServer\Parameters /v NullSessionPipes /t REG_MULTI_SZ /d "" /f
::Restict Anonymous user access to named pipes and shares
reg ADD HKLM\SYSTEM\CurrentControlSet\services\LanmanServer\Parameters /v NullSessionShares /t REG_MULTI_SZ /d "" /f
::Encrypt SMB Passwords
reg ADD HKLM\SYSTEM\CurrentControlSet\services\LanmanWorkstation\Parameters /v EnablePlainTextPassword /t REG_DWORD /d 0 /f
::Clear remote registry paths
reg ADD HKLM\SYSTEM\CurrentControlSet\Control\SecurePipeServers\winreg\AllowedExactPaths /v Machine /t REG_MULTI_SZ /d "" /f
::Clear remote registry paths and sub-paths
reg ADD HKLM\SYSTEM\CurrentControlSet\Control\SecurePipeServers\winreg\AllowedPaths /v Machine /t REG_MULTI_SZ /d "" /f
::Enable smart screen for IE8
reg ADD "HKCU\Software\Microsoft\Internet Explorer\PhishingFilter" /v EnabledV8 /t REG_DWORD /d 1 /f
::Enable smart screen for IE9 and up
reg ADD "HKCU\Software\Microsoft\Internet Explorer\PhishingFilter" /v EnabledV9 /t REG_DWORD /d 1 /f
::Disable IE password caching
reg ADD "HKCU\Software\Microsoft\Windows\CurrentVersion\Internet Settings" /v DisablePasswordCaching /t REG_DWORD /d 1 /f
::Warn users if website has a bad certificate
reg ADD "HKCU\Software\Microsoft\Windows\CurrentVersion\Internet Settings" /v WarnonBadCertRecving /t REG_DWORD /d 1 /f
::Warn users if website redirects
reg ADD "HKCU\Software\Microsoft\Windows\CurrentVersion\Internet Settings" /v WarnOnPostRedirect /t REG_DWORD /d 1 /f
::Enable Do Not Track
reg ADD "HKCU\Software\Microsoft\Internet Explorer\Main" /v DoNotTrack /t REG_DWORD /d 1 /f
reg ADD "HKCU\Software\Microsoft\Internet Explorer\Download" /v RunInvalidSignatures /t REG_DWORD /d 1 /f
reg ADD "HKCU\Software\Microsoft\Internet Explorer\Main\FeatureControl\FEATURE_LOCALMACHINE_LOCKDOWN\Settings" /v LOCALMACHINE_CD_UNLOCK /t REG_DWORD /d 1 /f
reg ADD "HKCU\Software\Microsoft\Windows\CurrentVersion\Internet Settings" /v WarnonZoneCrossing /t REG_DWORD /d 1 /f
::Show hidden files
reg ADD HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced /v Hidden /t REG_DWORD /d 1 /f
::Disable sticky keys
reg ADD "HKU\.DEFAULT\Control Panel\Accessibility\StickyKeys" /v Flags /t REG_SZ /d 506 /f
::Show super hidden files
reg ADD HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced /v ShowSuperHidden /t REG_DWORD /d 1 /f
::Disable dump file creation
reg ADD HKLM\SYSTEM\CurrentControlSet\Control\CrashControl /v CrashDumpEnabled /t REG_DWORD /d 0 /f
::Disable autoruns
reg ADD HKCU\SYSTEM\CurrentControlSet\Services\CDROM /v AutoRun /t REG_DWORD /d 1 /f
echo Managed registry keys
goto:EOF

:checkUsr
echo Manage users...
start %path%output\users.txt
start C:\Windows\System32\lusrmgr.msc /wait
echo Managed users
goto:EOF

:misc
echo Setting power settings...
powercfg -SETDCVALUEINDEX SCHEME_BALANCED SUB_NONE CONSOLELOCK 1
powercfg -SETDCVALUEINDEX SCHEME_MIN SUB_NONE CONSOLELOCK 1
powercfg -SETDCVALUEINDEX SCHEME_MAX SUB_NONE CONSOLELOCK 1
echo Set power settings
goto:EOF

:netShare
echo Echoing network shares to %path%output\shares.txt, make sure to check for out of place shares
net share > %path%output\shares.txt
echo Echoed network shares
goto:EOF

:flushDNS
echo Flushing DNS
ipconfig /flushdns >nul
echo Flushed DNS
echo Clearing contents of: C:\Windows\System32\drivers\etc\hosts
attrib -r -s C:\WINDOWS\system32\drivers\etc\hosts
echo > C:\Windows\System32\drivers\etc\hosts
attrib +r +s C:\WINDOWS\system32\drivers\etc\hosts
echo Cleared hosts file
goto:EOF

:defAccounts
echo Disabling Administrator account...
net user Administrator /active:no && (
	echo Disabled administrator account
	(call)
) || echo Administrator account not disabled
echo Disabling Guest account...
net user Guest /active:no && (
	echo Disabled Guest account
	(call)
) || echo Guest account not disabled
echo Disabled guest account
echo Renaming Administrator to "Dude" and Guest to "LameDude"
start C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe "%path%resources\RenameDefAccounts.ps1"
echo Renamed Administrator to "Dude" and Guest to "LameDude"
goto:EOF

:passwords
echo Making passwords expire, and setting password to: CyberPatriot1 IMPORTANT
echo Please change the main account password after script
for /f "tokens=*" %%a in ('type %path%resources\users.txt') do (
	net user "%%a" "CyberPatriot1"
	C:\Windows\System32\wbem\wmic UserAccount where Name="%%a" set PasswordExpires=True
)
echo Made passwords expire, and set passwords
goto:EOF

:rdp
set /p rdpChk="Enable remote desktop (y/n)"
if %rdpChk%==y (
	echo Enabling remote desktop...
	reg add "HKLM\SYSTEM\CurrentControlSet\Control\Terminal Server" /v AllowTSConnections /t REG_DWORD /d 1 /f
	reg add "HKLM\SYSTEM\CurrentControlSet\Control\Terminal Server" /v fAllowToGetHelp /t REG_DWORD /d 1 /f
	reg add "HKLM\SYSTEM\CurrentControlSet\Control\Terminal Server\WinStations\RDP-Tcp" /v UserAuthentication /t REG_DWORD /d 1 /f
	REG ADD "HKLM\SYSTEM\CurrentControlSet\Control\Terminal Server" /v fDenyTSConnections /t REG_DWORD /d 0 /f
	netsh advfirewall firewall set rule group="remote desktop" new enable=yes
	echo Please select "Allow connections only from computers running Remote Desktop with Network Level Authentication (more secure)"
	start SystemPropertiesRemote.exe /wait
	echo Enabled remote desktop
	goto:EOF
)
if %rdpChk%==n (
	echo Disabling remote desktop...
	reg add "HKLM\SYSTEM\CurrentControlSet\Control\Terminal Server" /v fDenyTSConnections /t REG_DWORD /d 1 /f
	reg add "HKLM\SYSTEM\CurrentControlSet\Control\Terminal Server" /v AllowTSConnections /t REG_DWORD /d 0 /f
	reg add "HKLM\SYSTEM\CurrentControlSet\Control\Terminal Server" /v fAllowToGetHelp /t REG_DWORD /d 0 /f
	reg add "HKLM\SYSTEM\CurrentControlSet\Control\Terminal Server\WinStations\RDP-Tcp" /v UserAuthentication /t REG_DWORD /d 0 /f
	netsh advfirewall firewall set rule group="remote desktop" new enable=no
	echo Disabled remote desktop
	goto:EOF
)
echo Invalid input %rdpChk%
goto rdp

:installMalwarebytes
set result=F
if exist "C:\Program Files (x86)\Malwarebytes"	set result=T
if exist "C:\Program Files\Malwarebytes" set result=T
if %result%==T (
	echo Malwarebytes already installed, skipping..
	goto:EOF
)
if exist "%path%installers\malwarebytes.exe" (
	echo Found Malwarebytes installer..
	goto installMalwarebytesChecked
) else echo Couldn't find installer in: "%path%installers\malwarebytes.exe"
goto:EOF
	
:installMalwarebytesChecked
set /p chk="Install Malwarebytes? (y/n) "
if %chk%==y (
	start %path%installers\malwarebytes.exe
	goto:EOF
)
if %chk%==Y (
	start %path%installers\malwarebytes.exe
	goto:EOF
)
if %chk%==n (
	echo Skipping installation of Malwarebytes
	goto:EOF
)
if %chk%==N (
	echo Skipping installation of Malwarebytes
	goto:EOF
)
echo Invalid input %chk%
goto installMalwarebytesChecked


:installAVG
set result=F
if exist "C:\Program Files (x86)\AVG" set result=T
if exist "C:\Program Files\AVG" set result=T
if %result%==T (
	echo AVG already installed, skipping..
	goto:EOF
)
if exist "%path%installers\avg.exe" (
	echo Found AVG installer..
	goto installAVGChecked
) else echo Couldn't find installer in: "%path%installers\avg.exe"
goto:EOF

:installAVGChecked
set /p chk="Install AVG? (y/n) "
if %chk%==y (
	start %path%installers\avg.exe
	goto:EOF
)
if %chk%==Y (
	start %path%installers\avg.exe
	goto:EOF
)
if %chk%==n (
	echo Skipping installation of AVG
	goto:EOF
)
if %chk%==N (
	echo Skipping installation of AVG
	goto:EOF
)
echo Invalid input %chk%
goto installAVGChecked


:installMBAnti
if exist "C:\Users\%USERNAME%\Desktop\mbar" (
	echo MBAntiRootkit already installed, skipping..
	goto:EOF
)
if exist "%path%installers\MB-Anti-rootkit.exe" (
	echo Found MBAntiRootkit installer..
	goto installMBAntiChecked
) else echo Couldn't find installer in: "%path%installers\MB-Anti-rootkit.exe"
goto:EOF
	
:installMBAntiChecked
set /p chk="Install MBAntiRootkit? (y/n) "
if %chk%==y (
	start %path%installers\MB-Anti-rootkit.exe
	goto:EOF
)
if %chk%==Y (
	start %path%installers\MB-Anti-rootkit.exe
	goto:EOF
)
if %chk%==n (
	echo Skipping installation of MBAntiRootkit
	goto:EOF
)
if %chk%==N (
	echo Skipping installation of MBAntiRootkit
	goto:EOF
)
echo Invalid input %chk%
goto installMBAnti

:installMBSA
if exist "C:\Program Files\Microsoft Baseline Security Analyzer 2" (
	echo MBAntiRootkit already installed, skipping..
	goto:EOF
)
if exist "%path%installers\MBSA-x86.msi" (
	echo Found Microsoft Baseline Security Analyzer..
	goto installMBSAChecked
) else echo Couldn't find installer in: "%path%installers\MBSA-x86.msi"
goto:EOF

:installMBSAChecked
set /p chk="Install Microsoft Baseline Security Analyzer? (y/n) "
if %chk%==y (
	start %path%installers\MBSA-x86.msi
	goto:EOF
)
if %chk%==Y (
	start %path%installers\MBSA-x86.msi
	goto:EOF
)
if %chk%==n (
	echo Skipping installation of Microsoft Baseline Security Analyzer
	goto:EOF
)
if %chk%==N (
	echo Skipping installation of Microsoft Baseline Security Analyzer
	goto:EOF
)
echo Invalid input %chk%
goto installMBSA

:installRevo
if exist "C:\Program Files\VS Revo Group\Revo Uninstaller Pro" (
	echo Revo already installed, skipping..
	goto:EOF
)
if exist "%path%installers\Revo.exe" (
	echo Found Revo Uninstaller Pro..
	goto installRevoChecked
) else echo Couldn't find the installer in: "%path%\installers\Revo.exe"
goto:EOF

:installRevoChecked
set /p chk="Install Revo Uninstaller Pro? (y/n) "
if %chk%==y (
	start %path%installers\Revo.exe
	goto:EOF
)
if %chk%==Y (
	start %path%installers\Revo.exe
	goto:EOF
)
if %chk%==n (
	echo Skipping installation of Revo
	goto:EOF
)
if %chk%==N (
	echo Skipping installation of Revo
	goto:EOF
)
echo Invalid input %chk%
goto installRevo

:installSUPER
if exist "C:\Program Files\SUPERAntiSpyware" (
	echo SUPER already installed, skipping..
	goto:EOF
)
if exist "%path%installers\SUPER.exe" (
	echo Found SUPER AntiSpyware..
	goto installSUPERChecked
) else echo Couldn't find the installer in: "%path%installers\SUPER.exe"
goto:EOF
:installSUPERChecked
set /p chk="Install SUPER? (y/n) "
if %chk%==y (
	start %path%installers\SUPER.exe
	goto:EOF
)
if %chk%==Y (
	start %path%installers\SUPER.exe
	goto:EOF
)
if %chk%==n (
	echo Skipping installation of SUPER
	goto:EOF
)
if %chk%==N (
	echo Skipping installation of SUPER
	goto:EOF
)
echo Invalid input %chk%
goto installSUPER

:lockdown
echo Check the lockdown file for this image!
goto:EOF

:tools
echo Process Explorer, startup tab, verify signatures
start %path%resources\WSCC\Sysinternals\procexp.exe
echo Autoruns
start %path%resources\WSCC\Sysinternals\Autoruns.exe
goto:EOF

:verifySys
sfc /verifyonly
goto:EOF
