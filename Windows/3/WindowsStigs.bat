@echo off
cls

net session >> nul 2>&1
if %errorLevel% == 0 ( echo. ) else ( echo Run me as an admin. & goto :end)
echo. > %cd%\ScriptOutput\deletedfiles.txt

echo Starting script
echo --------------------------------------------------------------------------------

echo. & echo Generating media report
dir /S /B "C:\Users\" > %APPDATA%\dirlist.txt
echo. & echo Sanitizing...
REM Filter out uneeded entries based on keyword
find /I /V "Microsoft" %APPDATA%\dirlist.txt | find /I /V "appdata" | find /I /V "sample" > %APPDATA%\dirlist2.txt
echo. > mediafiles.txt

REM Find all entries with the listed extensions
for %%E in (AIF,M3U,TXT,M4A,MID,MP3,MPA,RA,WAV,WMA,3G2,3GP,ASF,ASX,AVI,FLV,M4V,MOV,MP4,MPG,RM,SRT,SWF,VOB,WMV,BMP,GIF,JPG,PNG,PSD,TIF,YUV,GAM,SAV,TORRENT,WEBM,FLV,OG) do (
	findstr /I "\.%%E" %APPDATA%\dirlist2.txt >> %cd%\ScriptOutput\mediafiles.txt
)

REM Clean up temp files
del %APPDATA%\dirlist.txt & del %APPDATA%\dirlist2.txt
	
echo. & echo Media report generated at %cd%\ScriptOutput\mediafiles.txt
echo --------------------------------------------------------------------------------

echo. & echo Cleaning Scheduled Tasks
REM Get rid of microsoft and internet browser tasks from the query
schtasks /query /Fo list | find "TaskName:" | find /V /I "Microsoft" | find /V /I "Windows" | find /V /I "Scoring" | find /V /I "Google" | find /V /I "Firefox" | find /V /I "Opera" > %APPDATA%\stasks.txt
echo. > %APPDATA%\stasks2.txt

REM Pick out task directories
REM Look up ENABLEDELAYEDEXPANSION to understand why my variable syntax changes from % to !
SETLOCAL ENABLEDELAYEDEXPANSION
for /F "tokens=*" %%T in (%APPDATA%\stasks.txt) do (
	set tempy=%%T
	set tempyy=!tempy:~15,100!
	echo !tempyy! >> %APPDATA%\stasks2.txt
)

REM Remove the remaining tasks
for /F "tokens=*" %%T in (%APPDATA%\stasks2.txt) do (
	set tempy=%%T
	REM for some reason, the transfer of variable > file adds a space.
	schtasks /Delete /TN "!tempy:~0,-1!" /F >> nul 2>&1
)
ENDLOCAL

REM Clean up temp files
del %APPDATA%\stasks.txt & del %APPDATA%\stasks2.txt

echo. & echo Scheduled tasks cleansed
echo --------------------------------------------------------------------------------

echo. & echo Cleaning startup files
reg delete HKLM\Software\Microsoft\Windows\CurrentVersion\Run /VA /F >> nul 2>&1
reg delete HKLM\Software\Microsoft\Windows\CurrentVersion\RunOnce /VA /F >> nul 2>&1 
reg delete HKCU\Software\Microsoft\Windows\CurrentVersion\Run /VA /F >> nul 2>&1
reg delete HKCU\Software\Microsoft\Windows\CurrentVersion\RunOnce /VA /F >> nul 2>&1
REM Never ask me if I'm sure I want to do what I want to do
dir /B "C:\ProgramData\Microsoft\Windows\Start Menu\Programs\Startup\" >> %cd%\ScriptOutput\deletedfiles.txt
del /S "C:\ProgramData\Microsoft\Windows\Start Menu\Programs\Startup\*" /F /Q
dir /B "C:\Users\%username%\AppData\Roaming\Microsoft\Windows\Start Menu\Programs\Startup\" >> %cd%\ScriptOutput\deletedfiles.txt
del /S "C:\Users\%username%\AppData\Roaming\Microsoft\Windows\Start Menu\Programs\Startup\*" /F /Q
echo. & echo Startup files cleansed
echo --------------------------------------------------------------------------------

echo. & echo Setting folder-view options

reg add HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced /V Hidden /T REG_DWORD /D 1 /F >> nul 2>&1
reg add HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced /V HideFileExt /T REG_DWORD /D 0 /F >> nul 2>&1
reg add HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced /V ShowSuperHidden /T REG_DWORD /D 1 /F >> nul 2>&1
REM Set up the task-manager with my likeable preferences
reg import %cd%\scriptResources\TaskManager.reg >> nul 2>&1
REM Reset explorer to let changes take effect
taskkill /IM explorer.exe /F >> nul 2>&1
start explorer.exe

echo. & echo Folder-view options set
echo --------------------------------------------------------------------------------

echo. & echo Configuring UAC

REM Pretty self-explainatory, google value names to figure out what each one means.
reg add HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System /V PromptOnSecureDesktop /T REG_DWORD /D 1 /F >> nul 2>&1
reg add HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System /V ConsentPromptBehaviorAdmin /T REG_DWORD /D 1 /F >> nul 2>&1
reg add HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System /V ConsentPromptBehaviorUser /T REG_DWORD /D 0 /F >> nul 2>&1
reg add HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System /V FilterAdministratorToken /T REG_DWORD /D 1 /F >> nul 2>&1
reg add HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System /V EnableInstallerDetection /T REG_DWORD /D 1 /F >> nul 2>&1
reg add HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System /V EnableLUA /T REG_DWORD /D 1 /F >> nul 2>&1
reg add HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System /V EnableVirtualization /T REG_DWORD /D 1 /F >> nul 2>&1

echo. & echo UAC configured
echo --------------------------------------------------------------------------------

echo. & echo Setting security options

REM This was really tedious
reg add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon" /V AllocateCDRoms /T REG_DWORD /D 1 /F >> nul 2>&1
reg add "HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\Memory Management" /V ClearPageFileAtShutdown /T REG_DWORD /D 1 /F >> nul 2>&1
reg add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon" /V AllocateFloppies /T REG_DWORD /D 1 /F >> nul 2>&1
reg add "HKLM\SYSTEM\CurrentControlSet\Control\Print\Providers\LanMan Print Services\Servers" /V AddPrinterDrivers /T REG_DWORD /D 1 /F >> nul 2>&1
reg add "HKLM\SYSTEM\CurrentControlSet\Control\Lsa" /V LimitBlankPasswordUse /T REG_DWORD /D 1 /F >> nul 2>&1
reg add "HKLM\SYSTEM\CurrentControlSet\Control\Lsa" /V AuditBaseObjects /T REG_DWORD /D 1 /F >> nul 2>&1
reg add "HKLM\SYSTEM\CurrentControlSet\Control\Lsa" /V FullPrivilegeAuditing /T REG_DWORD /D 1 /F >> nul 2>&1
reg add HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System /V DontDisplayLastUsername /T REG_DWORD /D 1 /F >> nul 2>&1
reg add HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System /V UndockWithoutLogon /T REG_DWORD /D 0 /F >> nul 2>&1
reg add HKLM\SYSTEM\CurrentControlSet\services\Netlogon\Parameters /V MaximumPasswordAge /T REG_DWORD /D 15 /F >> nul 2>&1
reg add HKLM\SYSTEM\CurrentControlSet\services\Netlogon\Parameters /V DisablePasswordChange /T REG_DWORD /D 1 /F >> nul 2>&1
reg add HKLM\SYSTEM\CurrentControlSet\services\Netlogon\Parameters /V RequireStrongKey /T REG_DWORD /D 1 /F >> nul 2>&1
reg add HKLM\SYSTEM\CurrentControlSet\services\Netlogon\Parameters /V RequireSignOrSeal /T REG_DWORD /D 1 /F >> nul 2>&1
reg add HKLM\SYSTEM\CurrentControlSet\services\Netlogon\Parameters /V SignSecureChannel /T REG_DWORD /D 1 /F >> nul 2>&1
reg add HKLM\SYSTEM\CurrentControlSet\services\Netlogon\Parameters /V SealSecureChannel /T REG_DWORD /D 1 /F >> nul 2>&1
reg add HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System /V DisableCAD /T REG_DWORD /D 0 /F >> nul 2>&1
reg add HKLM\SYSTEM\CurrentControlSet\Control\Lsa /V RestrictAnonymous /T REG_DWORD /D 1 /F >> nul 2>&1
reg add HKLM\SYSTEM\CurrentControlSet\Control\Lsa /V RestrictAnonymousSAM /T REG_DWORD /D 1 /F >> nul 2>&1
reg add HKLM\SYSTEM\CurrentControlSet\services\LanmanServer\Parameters /V AutoDisconnect /T REG_DWORD /D 45 /F >> nul 2>&1
reg add HKLM\SYSTEM\CurrentControlSet\services\LanmanServer\Parameters /V EnableSecuritySignature /T REG_DWORD /D 0 /F >> nul 2>&1
reg add HKLM\SYSTEM\CurrentControlSet\services\LanmanServer\Parameters /V RequireSecuritySignature /T REG_DWORD /D 0 /F >> nul 2>&1
reg add HKLM\SYSTEM\CurrentControlSet\Control\Lsa /V DisableDomainCreds /T REG_DWORD /D 1 /F >> nul 2>&1
reg add HKLM\SYSTEM\CurrentControlSet\Control\Lsa /V EveryoneIncludesAnonymous /T REG_DWORD /D 0 /F >> nul 2>&1
reg add HKLM\SYSTEM\CurrentControlSet\services\LanmanWorkstation\Parameters /V EnablePlainTextPassword /T REG_DWORD /D 0 /F >> nul 2>&1
reg add HKLM\SYSTEM\CurrentControlSet\services\LanmanServer\Parameters /V NullSessionPipes /T REG_MULTI_SZ /D "" /F >> nul 2>&1
reg add HKLM\SYSTEM\CurrentControlSet\Control\SecurePipeServers\winreg\AllowedExactPaths /V Machine /T REG_MULTI_SZ /D "" /F >> nul 2>&1
reg add HKLM\SYSTEM\CurrentControlSet\Control\SecurePipeServers\winreg\AllowedPaths /V Machine /T REG_MULTI_SZ /D "" /F >> nul 2>&1
reg add HKLM\SYSTEM\CurrentControlSet\services\LanmanServer\Parameters /V NullSessionShares /T REG_MULTI_SZ /D "" /F >> nul 2>&1
reg add HKLM\SYSTEM\CurrentControlSet\Control\Lsa /V UseMachineId /T REG_DWORD /D 0 /F >> nul 2>&1
reg add "HKCU\Software\Microsoft\Internet Explorer\PhishingFilter" /V EnabledV8 /T REG_DWORD /D 1 /F >> nul 2>&1
reg add "HKCU\Software\Microsoft\Internet Explorer\PhishingFilter" /V EnabledV9 /T REG_DWORD /D 1 /F >> nul 2>&1
reg add HKLM\SYSTEM\CurrentControlSet\Control\CrashControl /V CrashDumpEnabled /T REG_DWORD /D 0 /F >> nul 2>&1
reg add HKCU\SYSTEM\CurrentControlSet\Services\CDROM /V AutoRun /T REG_DWORD /D 1 /F >> nul 2>&1
reg add HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\policies\Explorer /V NoDriveTypeAutorun /T REG_DWORD /D 255 /F >> nul 2>&1
reg add HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\policies\Explorer /V NoDriveTypeAutorun /T REG_DWORD /D 255 /F >> nul 2>&1
reg add HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\policies\Explorer /V NoAutorun /T REG_DWORD /D 1 /F >> nul 2>&1
reg add HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\policies\Explorer /V NoAutorun /T REG_DWORD /D 1 /F >> nul 2>&1 
reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\Internet Settings" /V DisablePasswordCaching /T REG_DWORD /D 1 /F >> nul 2>&1
reg add "HKCU\Software\Microsoft\Internet Explorer\Main" /V DoNotTrack /T REG_DWORD /D 1 /F >> nul 2>&1
reg add "HKCU\Software\Microsoft\Internet Explorer\Download" /V RunInvalidSignatures /T REG_DWORD /D 1 /F >> nul 2>&1
reg add "HKCU\Software\Microsoft\Internet Explorer\Main\FeatureControl\FEATURE_LOCALMACHINE_LOCKDOWN\Settings" /V LOCALMACHINE_CD_UNLOCK /T REG_DWORD /D 1 /T >> nul 2>&1
reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\Internet Settings" /V WarnonBadCertRecving /T REG_DWORD /D /1 /F >> nul 2>&1
reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\Internet Settings" /V WarnOnPostRedirect /T REG_DWORD /D 1 /F >> nul 2>&1
reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\Internet Settings" /V WarnonZoneCrossing /T REG_DWORD /D 1 /F >> nul 2>&1
reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\Internet Settings" /V DisablePasswordCaching /T REG_DWORD /D 1 /F >> nul 2>&1
REM Internet explorer
auditpol /set /category:* /success:enable >> nul 2>&1
auditpol /set /category:* /failure:enable >> nul 2>&1
reg add "HKLM\Software\Microsoft\Windows NT\Current Version\Winlogon\" /V CachedLogonsCount /T REG_SZ /D 0 /F >> nul 2>&1

set /P choice=Windows 8 or 10[Y/N]?
if /I "%choice%" EQU "Y" (
	reg add "HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\kernel" /V DisableExceptionChainValidation /T REG_DWORD /D 0 /F >> nul 2>&1
	reg add HKLM\SOFTWARE\Microsoft\PolicyManager\default\Settings\AllowSignInOptions /V value /T REG_DWORD /D 0 /F >> nul 2>&1
	reg add HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\DeliveryOptimization\Config /V DownloadMode /T REG_DWORD /D 0 /F  >> nul 2>&1
	reg add HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\DeliveryOptimization\Config /V DODownloadMode /T REG_DWORD /D 0 /F  >> nul 2>&1
	REM They kept changing the value name for this, so I'm just doing all of them.
	reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\Windows Search" /V AllowCortana /T REG_DWORD /D 0 /F >> nul 2>&1
	reg add HKLM\SOFTWARE\Microsoft\WcmSvc\wifinetworkmanager\config /V AutoConnectAllowedOEM /T REG_DWORD /D 0 /F >> nul 2>&1
	reg add HKLM\Software\Policies\Microsoft\Windows\OneDrive /V DisableFileSyncNGSC /T REG_DWORD /D 1 /F >> nul 2>&1
	reg add HKLM\Software\Policies\Microsoft\Windows\OneDrive /V DisableFileSync /T REG_DWORD /D 1 /F >> nul 2>&1
	REM Make sure onedrive is dead
	taskkill /f /im OneDrive.exe >> nul 2>&1
	%SystemRoot%\System32\OneDriveSetup.exe /uninstall
	REM Location
	reg add HKLM\Software\Policies\Microsoft\Windows\LocationAndSensors /V DisableWindowsLocationProvider /T REG_DWORD /D 1 /F >> nul 2>&1
) else (
	echo Not Windows 8 or 10
)
set /P choicetwo=Win10Enterprise [Y/N]?
if /I "%choicetwo%" EQU "Y" (
	reg add HLKM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\DataCollection /V AllowTelemetry /T REG_DWORD /D 0 /F >> nul 2>&1
) else (
	reg add HLKM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\DataCollection /V AllowTelemetry /T REG_DWORD /D 1 /F >> nul 2>&1
)
echo. & echo Security options set
echo --------------------------------------------------------------------------------


echo. & echo Configuring Windows Update

reg add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WindowsUpdate\Auto Update" /V AUOptions /T REG_DWORD /D 4 /F >> nul 2>&1
reg add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WindowsUpdate\Auto Update" /V ElevateNonAdmins /T REG_DWORD /D 1 /F >> nul 2>&1
reg add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WindowsUpdate\Auto Update" /V IncludeRecommendedUpdates /T REG_DWORD /D 1 /F >> nul 2>&1
reg add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WindowsUpdate\Auto Update" /V ScheduledInstallTime /T REG_DWORD /D 22 /F >> nul 2>&1

echo. & echo Windows Update configured
echo --------------------------------------------------------------------------------

echo. & echo Configuring Windows Firewall

netsh advfirewall set allprofiles state on >> nul 2>&1
netsh advfirewall set allprofiles firewallpolicy blockinbound,allowoutbound >> nul 2>&1
netsh advfirewall firewall add rule name="Block135tout" protocol=TCP dir=out remoteport=135 action=block
netsh advfirewall firewall add rule name="Block135uout" protocol=UDP dir=out remoteport=135 action=block
netsh advfirewall firewall add rule name="Block135tin" protocol=TCP dir=in localport=135 action=block
netsh advfirewall firewall add rule name="Block135tout" protocol=UDP dir=in localport=135 action=block

netsh advfirewall firewall add rule name="Block137tout" protocol=TCP dir=out remoteport=137 action=block
netsh advfirewall firewall add rule name="Block137uout" protocol=UDP dir=out remoteport=137 action=block
netsh advfirewall firewall add rule name="Block137tin" protocol=TCP dir=in localport=137 action=block
netsh advfirewall firewall add rule name="Block137tout" protocol=UDP dir=in localport=137 action=block

netsh advfirewall firewall add rule name="Block138tout" protocol=TCP dir=out remoteport=138 action=block
netsh advfirewall firewall add rule name="Block138uout" protocol=UDP dir=out remoteport=138 action=block
netsh advfirewall firewall add rule name="Block138tin" protocol=TCP dir=in localport=138 action=block
netsh advfirewall firewall add rule name="Block138tout" protocol=UDP dir=in localport=138 action=block

netsh advfirewall firewall add rule name="Block139tout" protocol=TCP dir=out remoteport=139 action=block
netsh advfirewall firewall add rule name="Block139uout" protocol=UDP dir=out remoteport=139 action=block
netsh advfirewall firewall add rule name="Block139tin" protocol=TCP dir=in localport=139 action=block
netsh advfirewall firewall add rule name="Block139tout" protocol=UDP dir=in localport=139 action=block

echo. & echo Windows Firewall configured
echo --------------------------------------------------------------------------------

echo. & echo Deleting Windows Shares

REG QUERY HKLM\System\CurrentControlSet\Services\LanmanServer\Shares > %APPDATA%\shares.txt

findstr /I /V HKEY_LOCAL_MACHINE %APPDATA%\shares.txt | findstr /I /V HKLM >> %APPDATA%\shares2.txt

setlocal EnableDelayedExpansion
for /F "usebackq delims=" %%S in ("%APPDATA%\shares2.txt") do (
    set "tempy=%%S"
	REM Grabs the first section in the line deliniated by 4 spaces.
    for /F "tokens=1 delims=|" %%N in ("!tempy:    =|!") do (
        net share "%%N" /Delete >> nul 2>&1
    )
)
endlocal

del %APPDATA%\shares.txt & del %APPDATA%\shares2.txt

echo. & echo Windows Shares deleted.
echo --------------------------------------------------------------------------------

echo. & echo Configuring Remote Services

set /P choice=Disable Remote Services[Y/N]?
if /I "%choice%" EQU "Y" (
	reg add "HKLM\SYSTEM\CurrentControlSet\Control\Terminal Server" /V fDenyTSConnections /T REG_DWORD /D 1 /F >> nul 2>&1
	sc config iphlpsvc start= disabled >> nul 2>&1
	sc stop iphlpsvc >> nul 2>&1
	sc config umrdpservice start= disabled >> nul 2>&1
	sc stop umrdpservice >> nul 2>&1
	sc config termservice start= disabled >> nul 2>&1
	sc stop termservice >> nul 2>&1
) else (
	reg add "HKLM\SYSTEM\CurrentControlSet\Control\Terminal Server" /V fDenyTSConnections /T REG_DWORD /D 0 /F >> nul 2>&1
    reg add "HKLM\System\CurrentControlSet\Control\Terminal Server\WinStations\RDP-Tcp" /V UserAuthentication /T REG_DWORD /D 1 /F >> nul 2>&1
) 
REM Regardless, set these keys
reg add "HKLM\SYSTEM\ControlSet001\Control\Remote Assistance" /V CreateEncryptedOnlyTickets /T REG_DWORD /D 1 /F >> nul 2>&1
reg add "HKLM\System\CurrentControlSet\Control\Terminal Server\WinStations\RDP-Tcp" /V fDisableEncryption /T REG_DWORD /D 0 /F >> nul 2>&1
reg add "HKLM\SYSTEM\ControlSet001\Control\Remote Assistance" /V fAllowFullControl /T REG_DWORD /D 0 /F >> nul 2>&1
reg add "HKLM\SYSTEM\ControlSet001\Control\Remote Assistance" /V fAllowToGetHelp /T REG_DWORD /D 0 /F >> nul 2>&1
reg add "HKLM\SYSTEM\CurrentControlSet\Control\Terminal Server" /V AllowRemoteRPC /T REG_DWORD /D 0 /F >> nul 2>&1

echo. & echo Remote Services Configured
echo --------------------------------------------------------------------------------

echo. & echo Configuring Default Accounts

net user Administrator /active:no >> nul 2>&1
set /P choice=Disable the Guest Account[Y/N]?
if /I "%choice%" EQU "Y" (
	net user Guest /active:no >> nul 2>&1
) else (
	net user Guest /active:yes >> nul 2>&1
)
wmic useraccount where name='Guest' rename notguest >> nul 2>&1

echo. & echo Default Accounts Configured
echo --------------------------------------------------------------------------------

echo. & echo Setting user passwords

wmic useraccount get name/value | find /V /I "%username%" > %APPDATA%\userlist.txt

REM Get everything after the equals
for /F "tokens=2* delims==" %%U in (%APPDATA%\userlist.txt) do (
	REM So after further inspection, there is this weird line ending to WMIC output, so this loop removes the ending and just passes the username.
	for %%u in (%%~U) do (
		net user %%~u M@nkD3m35 >> nul 2>&1
		WMIC USERACCOUNT WHERE "Name='%%~u'" SET PasswordExpires=TRUE >> nul 2>&1
		WMIC USERACCOUNT WHERE "Name='%%~u'" SET PasswordRequired=TRUE >> nul 2>&1
		WMIC USERACCOUNT WHERE "Name='%%~u'" SET PasswordChangeable=TRUE >> nul 2>&1
	)
)



del %APPDATA%\userlist.txt

echo. & echo User passwords set
echo --------------------------------------------------------------------------------

echo. & echo Configuring services

REM Services that should be burned at the stake.
for %%S in (tapisrv,bthserv,mcx2svc,remoteregistry,seclogon,telnet,tlntsvr,p2pimsvc,simptcp,fax,msftpsvc,nettcpportsharing,iphlpsvc,lfsvc,bthhfsrv,irmon,sharedaccess,xblauthmanager,xblgamesave,xboxnetapisvc) do (
	sc config %%S start= disabled >> nul 2>&1
	sc stop %%S >> nul 2>&1
)

REM Services that are an automatic start.
for %%S in (eventlog,mpssvc) do (
	sc config %%S start= auto >> nul 2>&1
	sc start %%S >> nul 2>&1
)

REM Services that are an automatic (delayed) start.
for %%S in (windefend,sppsvc,wuauserv) do (
	sc config %%S start= delayed-auto >> nul 2>&1
	sc start %%S >> nul 2>&1
)

REM Services that are a manual start.
for %%S in (wersvc,wecsvc) do (
	sc config %%S start= demand >> nul 2>&1
)

echo. & echo Services configured.
echo --------------------------------------------------------------------------------

echo. & echo Misc. stuff (hosts, dns flushing, etc...)
ipconfig /flushdns >> nul 2>&1
REM Wasn't sure how CP would check it, so I just copied the default hosts file in.
attrib -r -s %systemroot%\system32\drivers\etc\hosts >> nul 2>&1 
REM Covering all my bases with these switches
xcopy %cd%\scriptResources\hosts %systemroot%\system32\drivers\etc /Q /R /H /Y >> nul 2>&1
REM Power configuration (require password on wakeup)
powercfg -SETDCVALUEINDEX SCHEME_BALANCED SUB_NONE CONSOLELOCK 1
powercfg -SETACVALUEINDEX SCHEME_BALANCED SUB_NONE CONSOLELOCK 1
powercfg -SETDCVALUEINDEX SCHEME_MIN SUB_NONE CONSOLELOCK 1
powercfg -SETDCVALUEINDEX SCHEME_MIN SUB_NONE CONSOLELOCK 1
powercfg -SETDCVALUEINDEX SCHEME_MAX SUB_NONE CONSOLELOCK 1
powercfg -SETDCVALUEINDEX SCHEME_MAX SUB_NONE CONSOLELOCK 1
powercfg /SETACVALUEINDEX SCHEME_CURRENT SUB_NONE CONSOLELOCK 1
powercfg /SETDCVALUEINDEX SCHEME_CURRENT SUB_NONE CONSOLELOCK 1

echo. & echo It's all done folks.
echo --------------------------------------------------------------------------------

:end
echo. & echo The paths of files that were deleted can be found in %cd%\ScriptOutput\deletedfiles.txt
echo. & echo When you press a key, the Windows Features window will open.  If you don't want to change anything, just hit cancel.
pause
optionalfeatures.exe
