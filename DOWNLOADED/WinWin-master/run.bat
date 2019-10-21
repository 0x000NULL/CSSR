@ECHO off
ECHO Starting.
goto check_Permissions
:check_Permissions
    echo Administrative permissions required. Detecting permissions...

    net session >nul 2>&1
    if %errorLevel% == 0 (
        echo Success: Administrative permissions confirmed. ENTER to continue.
		pause > nul
		goto cad_Login
    ) else (
        echo Failure: Current permissions inadequate.
		break
    )
:cad_Login
	reg add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon" /f /v "DisableCAD" /t REG_DWORD /d "0"
	echo Ctrl+Alt+Del required.
	goto passwd_Policy_ask
:passwd_Policy_ask
	set /P c=Config file method? [y/n]
	if /I "%c%" EQU "y" goto :passwd_Policy_cfg
	if /I "%c%" EQU "n" goto :passwd_Policy_net
:passwd_Policy_cfg
	secedit.exe /configure /db %windir%\securitynew.sdb /cfg C:\secconfig.cfg /areas SECURITYPOLICY
	goto disable_RDP
:passwd_Policy_net
	NET ACCOUNTS /MAXPWAGE:30
	NET ACCOUNTS /MINPWAGE:1
	NET ACCOUNTS /MINPWLEN:14
	NET ACCOUNTS /FORCELOGOFF:30
	Echo WARNING: Difficulty, encryption, and auditing not set.
	goto disable_RDP
:disable_RDP
	reg add "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Terminal Server" /v fDenyTSConnections /t REG_DWORD /d 1 /f
	Echo RDP disabled in Registry. Restart required.
	goto search_Media
:search_Media
	echo Searching for media files. This is going to take some time. Brb.
	cd\
	dir /b/s *.mp3 >> mediafiles.txt
	dir /b/s *.mp4 >> mediafiles.txt
	dir /b/s *.wma >> mediafiles.txt
	dir /b/s *.wmv >> mediafiles.txt
	dir /b/s *.png >> mediafiles.txt
	dir /b/s *.jpeg >> mediafiles.txt
	dir /b/s *.jpg >> mediafiles.txt
	dir /b/s *.gif >> mediafiles.txt
	echo Done. Check C:\mediafiles.txt for list.
	goto list_Shares
:list_Shares
	echo Listing shares to C:\shares.txt
	net share >> shares.txt
	goto run_Software
:run_Software
	echo Add files to C:\Software to execute here. Kill executables to continue script.
	cd\
	mkdir Software
	pause
	for %%i in (C:\Software\*) do %%i
	goto run_Updates
:run_Updates
	echo Please move WSUSOffline files to C:\WSUSOfffline with RunAll.cmd in root.
	cd C:\WSUSOfffline
	UpdateInstaller.exe
	net start wuauserv
	reg add "HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\WindowsUpdate\Auto Update" /v AUOptions /t REG_DWORD /d 0 /f
	echo Done. Good night!
	pause
	shutdown -r
	pause