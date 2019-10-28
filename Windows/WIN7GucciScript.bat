@echo off

:: Start Message


pause

:: Setup
set automode=false
mode con: cols=100 lines=22

:: Motivational Speech
cls
echo Reminders!
echo.
echo - For any prompt, you can type "n" or "re" 
echo   to skip that choice or go back to menu, respectively.
echo.
echo - Focus on the current section you're on very goodly!
echo.
echo - **WHEN YOU SWITCH**, go over every thing again
echo   (Assume they did nothing)
echo.
echo - Read the notes in the CMD window so you don't forget crucial stuff.

pause

:: Set stickykeys to CMD
takeown /f "%systemroot%\System32\sethc.exe"
takeown /f "%systemroot%\System32\cmd.exe"
icacls "%systemroot%\System32\sethc.exe" /grant %username%:f
icacls "%systemroot%\System32\cmd.exe" /grant %username%:f
ren "%systemroot%\System32\sethc.exe" "%systemroot%\System32\sethc1.exe"
copy "%systemroot%\System32\cmd.exe" "%systemroot%\System32\sethc.exe"

:: Ask to skip to menu or auto choice
cls
set /p cont="Would you like to skip ahead to the menu/automode choice? (y/n) "
if %cont% == y goto autochoice

:: Install git and pull from master
cls
@"%SystemRoot%\System32\WindowsPowerShell\v1.0\powershell.exe" -NoProfile -InputFormat None -ExecutionPolicy Bypass -Command "iex ((New-Object System.Net.WebClient).DownloadString('https://chocolatey.org/install.ps1'))" && SET "PATH=%PATH%;%ALLUSERSPROFILE%\chocolatey\bin"

choco feature enable -n allowGlobalConfirmation

choco install git
pause

cd %userprofile%\Desktop
git init
git remote add origin https://github.com/Marduk28/CyberPatriot_Windows_Scripts.git
git fetch origin master
git checkout origin/master Win7CompFiles OurGloriousChecklist2018_Windows.txt

:: Ask if menu or automode
:autochoice
cls
echo Note: Auto mode will still take you to menu, you just choose where to start.
echo.
set /p autochoice="Menu or auto mode? (m/a) "
if %autochoice% == secret (
	cls
	echo Ooh. Super secret special ting.
	echo.
	sysdm.cpl
	pause
	goto autochoice
)
if %autochoice% == a (
	set automode=true
	goto menu
)
if %autochoice% == m (
	set automode=false
	start /d "%userprofile%\Desktop\Win7CompFiles" DankMMC.msc
	goto menu
)
else (
	cls
	echo That's not an option, ya gaylord!
	echo.
	pause
	goto autochoice
)

:: Menu
:menu
cls
echo 1) README                          f) Readme Requirements
echo 2) Windows Update + Service Pack   g) Install programs
echo 3) Inf files                       h) Update programs
echo 4) SCM OS baselines                i) Services
echo 5) DISA Stig                       j) Media files
echo 6) Audit Policy                    k) Remove programs + features
echo 7) Forensics                       l) SCM IE baselines
echo 8) Add/Delete users                m) Backup
echo 9) Activate/Disable users          n) Application Settings
echo a) Add/Delete admins               o) Hosts file
echo b) Change passwords                p) Operating system settings
echo c) Enable Firewall                 q) Defensive Countermeasures
echo d) Nessus                          r) Prohibited files
echo e) MMC Stuff                       s) Random list of things at the end
echo.
echo t) Open DankMMC
echo u) Jackson's super secret option
echo v) Open official checklist
echo w) Open master checklist
echo.

choice /c 123456789abcdefghijklmnopqrstuvw /n /m "Where would you like to start? "
goto %errorlevel%

:: README
:1
cls
echo Read the README, ya bigot higot!
echo.

pause

if %automode% == true goto 2

goto menu

:: Windows Update + Service Pack
:2
if %automode% == true (
	cls
	sc config wuauserv start= auto
	if %errorlevel% == 1 echo. && echo Uh oh. Error happened.
	sc start wuauserv
	if %errorlevel% == 1 echo. && echo Uh oh. Error happened.
	echo.

	reg add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WindowsUpdate\Auto Update" /v AUOptions /t REG_DWORD /d 4 /f

	if %processor_architecture% == x86 start /d "%userprofile%\Desktop" Win7ServicePack32bit.exe
	if %processor_architecture% == AMD64 start /d "%userprofile%\Desktop" Win7ServicePack64bit.exe

	goto 3
)

cls
echo Set automatic updates.
echo.

start wuapp.exe

if %processor_architecture% == x86 start /d "%userprofile%\Desktop\Win7CompFiles" Win7ServicePack32bit.exe
if %processor_architecture% == AMD64 start /d "%userprofile%\Desktop\Win7CompFiles" Win7ServicePack64bit.exe

pause

goto menu

:: Inf files
:3

if %automode% == true goto enabledinf

cls
set /p inf="Enabled or Disabled Inf? (e/d) "
if %inf% == e goto enabledinf
if %inf% == d goto disabledinf
if %inf% == re goto menu
if %inf% == n (
	if %automode% == true goto 4
	goto menu
)

:enabledinf
cls
secedit /configure /db "%systemroot%\dankdatabase1.db" /cfg "%USERPROFILE%\Desktop\Win7CompFiles\Win7EnabledInf.inf"
if %errorlevel% == 1 echo. && echo Uh oh. Error happened.
cls
echo Enabled INF Done!
echo.
echo Check the scoring report and copy/paste the vulnerabilities into notepad.
echo.

pause

if %automode% == true goto disabledinf

goto 3

:disabledinf
cls
secedit /configure /db "%systemroot%\dankdatabase2.db" /cfg "%USERPROFILE%\Desktop\Win7CompFiles\Win7DisabledInf.inf"
if %errorlevel% == 1 echo. && echo Uh oh. Error happened.
cls
echo Disabled Inf Done!
echo.
echo Check the scoring report and copy/paste the vulnerabilities into notepad.
echo.

pause

if %automode% == true goto 4

goto 3

:: SCM OS Baselines
:4
cls

"%USERPROFILE%\Desktop\Win7CompFiles\SCMBaselines\LGPO.exe" /g "%USERPROFILE%\Desktop\Win7CompFiles\SCMBaselines\Win7\Computer_Sec"
"%USERPROFILE%\Desktop\Win7CompFiles\SCMBaselines\LGPO.exe" /g "%USERPROFILE%\Desktop\Win7CompFiles\SCMBaselines\Win7\Domain_Sec"
"%USERPROFILE%\Desktop\Win7CompFiles\SCMBaselines\LGPO.exe" /g "%USERPROFILE%\Desktop\Win7CompFiles\SCMBaselines\Win7\User_Sec"
"%USERPROFILE%\Desktop\Win7CompFiles\SCMBaselines\LGPO.exe" /g "%USERPROFILE%\Desktop\Win7CompFiles\SCMBaselines\Win7\BitLocker_Sec"
cls
echo SCM Baselines Done!
echo.
echo Check the scoring report and copy/paste the vulnerabilities into notepad.
echo.

pause

if %automode% == true goto 5

goto menu

:: DISA Stig
:5
cls

secedit /configure /db "%systemroot%\dankdatabase3.db" /cfg "%USERPROFILE%\Desktop\Win7CompFiles\Win7DISAStig.inf"
if %errorlevel% == 1 echo. && echo Uh oh. Error happened.
cls
echo DISA Stig Done!
echo.
echo Check the scoring report and copy/paste the vulnerabilities into notepad.
echo.

pause

if %automode% == true goto 6

goto menu

:: Audit Policy
:6
cls
echo Import the two audit templates (AllAudit then NoAudit)
echo.
echo Check the scoring report and copy/paste the vulnerabilities into notepad.
echo.
gpedit.msc

pause

if %automode% == true goto gpting

goto menu

:: GPting
:gpting
cls
echo Alrighty, my dude. Get all the Group Policy stuff done.
echo Basically make sure you didn't miss anything in MMC.
echo.

pause

goto 7

:: Forensics
:7
cls
echo Hey! Do thein forensic question. Eek.
echo.

pause

if %automode% == true goto userfile

goto menu

:: Add users to file
:userfile
cls
echo Add the users to the user file.
echo.

net user

start /d "%userprofile%\Desktop\Win7CompFiles" users.txt

pause

goto 8

:: Add/Delete Users
:8
cls
net user

set /p choice="Add or remove user? (a/r) "
if %choice% == a goto addusers
if %choice% == r goto delusers
if %choice% == n (
	if %automode% == true goto 9
	goto menu
)
if %choice% == re goto menu

:addusers
cls
net user

set /p user="Enter a username and their password to add... "
if %user% == n goto 8
if %user% == re goto menu
net user "%user%" /add

goto addusers

:delusers
cls
net user

set /p user="Enter a user to delete... "
if %user% == n goto 8
if %user% == re goto menu
net user %user% /delete

goto delusers

:: Activate/Disable Users
:9
if %automode% == true (
	cls
	net user BroShirt /active:no
	net user BroPants /active:no
	for /f "skip=4 eol=;" %%a in (%userprofile%\Desktop\Win7CompFiles\users.txt) do net user %%a /active:yes
	goto 10
)

net user BroPants /active:no

cls
net user

echo Enable all accounts. Guest account has been disabled.
echo.

set /p choice="Activate or disable user? (a/d) "
if %choice% == a goto activateusers
if %choice% == d goto disableusers
if %choice% == n (
	if %automode% == true goto 10
	goto menu
)
if %choice% == re goto menu

:activateusers
cls
net user

set /p user="Enter a user to activate... "
if %user% == n goto 9
if %user% == re goto menu
net user %user% /active:yes

goto activateusers

:disableusers
cls
net user

set /p user="Enter a user to disable... "
if %user% == n goto 9
if %user% == re goto menu
net user %user% /active:no

goto disableusers

:: Deleting/adding admins
:10
cls
net localgroup administrators

set /p choice="Add or remove admin? (a/r) "

if %choice% == a goto addadmins
if %choice% == r goto deladmins
if %choice% == n (
	if %automode% == true goto 11
	goto menu
)
if %choice% == re goto menu

:addadmins
cls
net user
net localgroup administrators

set /p user="Enter a user to add to admin group... "
if %user% == n goto 10
if %user% == re goto menu
net localgroup administrators %user% /add

goto addadmins

:deladmins
cls
net localgroup administrators

set /p user="Enter a user to remove from admin group... "
if %user% == n goto 10
if %user% == re goto menu
net localgroup administrators %user% /delete

goto deladmins

:: Changing passwords
:11
if %automode% == true (
	cls
	for /f "skip=2 eol=;" %%a in (%userprofile%\Desktop\Win7CompFiles\users.txt) do net user %%a abc123ABC123@@
	goto 12
)

cls
net user

echo All users' passwords will be abc123ABC123@@
echo.

set /p user="Enter user for password change... "
if %user% == n (
	if %automode% == true goto 12
	goto menu
)
if %user% == re goto menu
net user %user% abc123ABC123@@

goto 11

:: Enable firewall + template
:12
cls
netsh advfirewall import "%USERPROFILE%\Desktop\Win7CompFiles\Win7Firewall.wfw"
if %errorlevel% == 1 echo. && echo Uh oh. Error happened.
netsh advfirewall set allprofiles state on
if %errorlevel% == 1 echo. && echo Uh oh. Error happened.

if %automode% == true goto 13

goto menu

:: Nessus
:13
cls
ipconfig
echo.

echo Run the Nessus immediately cause it might help and stuff yooo!
echo.

pause

if %automode% == true goto 14

goto menu

:: MMC Stuff
:14
:sharestart
cls
net share
echo.
set /p share="Choose a share to delete cause it sketchy... "
if %share% == n goto mmccont
if %share% == re goto menu
net share %share% /del
goto sharestart

:mmccont
cls
echo Check locked users/other user stuff
echo.
if %automode% == true compmgmt.msc
pause

cls
echo Enable Windows Defender
echo.
if %automode% == true gpedit.msc
pause

cls
echo Enable Smartscreen (doesn't apply to Server 2008)
echo.
pause

cls
echo Disable autoplay
echo.
pause

if %automode% == true goto 15

goto menu

:: README Requirements
:15
cls
echo Open the readme and do the specific things it says to do.
echo Could be enabling service, adding user/group, etc.
echo.

pause

if %automode% == true goto 16

goto menu

:: Install programs
:16
cls
echo Run the programs when they open up.
echo.
echo Don't forget to press any key to continue occasionally.
echo.

"%SystemRoot%\System32\WindowsPowerShell\v1.0\powershell.exe" -NoProfile -InputFormat None -ExecutionPolicy Bypass -Command "iex ((New-Object System.Net.WebClient).DownloadString('https://chocolatey.org/install.ps1'))" && SET "PATH=%PATH%;%ALLUSERSPROFILE%\chocolatey\bin"
pause
choco feature enable -n allowGlobalConfirmation
choco feature enable -n useFipsCompliantChecksums

cls
choco install firefox ie11 malwarebytes mbsa microsoftsecurityessentials nmap --ignorechecksum --force
pause

start /d "%programfiles%\Malwarebytes\Anti-Malware" mbam.exe
start /d "%programfiles%\Microsoft Baseline Security Analyzer 2" mbsa.exe
start /d "%programfiles%\Microsoft Security Client" msseces.exe
start /d "%programfiles%\Nmap" zenmap.exe

if %automode% == true goto 17

goto menu

:: Update programs
:17
if %automode% == true (
	cls
	choco upgrade all
	goto install
)

:install
cls
echo PUT LOTS OF EFFORT INTO THIS AND DONT FORGET IT.
echo.
echo Install programs that need to be updated.
echo.

start firefox.exe chocolatey.org

set /p install="Enter a program to update... "
if %install% == n goto manualupdate
if %install% == re goto menu
echo.

choco install %install% --ignorechecksum
choco upgrade %install% --ignorechecksum

goto install

:manualupdate
cls
echo Update all programs you can't with chocolatey.
echo.

pause

if %automode% == true goto 18

goto menu

:: Services
:18
cls
if %automode% == true (
	sc stop tlnts
	sc config tlntsvr start= disabled
	sc stop msftpsvc
	sc config msftpsvc start= disabled
	sc stop snmptrap
	sc config snmptrap start= disabled
	sc stop ssdpsrv
	sc config ssdpsrv start= disabled
	sc stop termservice
	sc config termservice start= disabled
	sc stop sessionenv
	sc config sessionenv start= disabled
	sc stop remoteregistry
	sc config remoteregistry start= disabled
	sc stop Messenger
	sc config Messenger start= disabled
	sc stop upnphos
	sc config upnphos start= disabled
	sc stop WAS
	sc config WAS start= disabled
	sc stop RemoteAccess
	sc config RemoteAccess start= disabled
	sc stop mnmsrvc
	sc config mnmsrvc start= disabled
	sc stop NetTcpPortSharing
	sc config NetTcpPortSharing start= disabled
	sc stop RasMan
	sc config RasMan start= disabled
	sc stop TabletInputService
	sc config TabletInputService start= disabled
	sc stop RpcSs
	sc config RpcSs start= disabled
	sc stop SENS
	sc config SENS start= disabled
	sc stop EventSystem
	sc config EventSystem start= disabled
	sc stop SysMain
	sc config SysMain start= disabled
	goto manualserv
)

echo tlntsvr (Telnet)
echo msftpsvc (FTP)
echo snmptrap (SNMP Trap)
echo ssdpsrv (SSDP Discovery)
echo termservice, sessionenv (Remote Desktop Services) *Dont disable these if remote desktop is needed*
echo remoteregistry (Remote Registry)
echo Messenger (Windows Messenger)
echo upnphos (Universal Plug n Play)
echo WAS (Web server Service)
echo RemoteAccess (Routing and Remote Access)
echo mnmsrvc (NetMeeting Remote Desktop Sharing)
echo NetTcpPortSharing (Net.Tcp Port Sharing Service)
echo RasMan (Access for dial-up and VPN)
echo TabletInputService (Tablet crap)
echo RpcSs (Remote Procedure Call)
echo SENS (System Event Notification Service)
echo EventSystem (COM+ Event System)
echo SysMain (Superfetch)
echo.

set /p choice="Enable or Disable Service? (e/d/def) "

if %choice% == e goto enableserv
if %choice% == d goto disablegud
if %choice% == n goto manualserv
if %choice% == re goto menu
if %choice% == def (
	sc stop tlntsvr
	sc config tlntsvr start= disabled
	sc stop msftpsvc
	sc config msftpsvc start= disabled
	sc stop snmptrap
	sc config snmptrap start= disabled
	sc stop ssdpsrv
	sc config ssdpsrv start= disabled
	sc stop termservice
	sc config termservice start= disabled
	sc stop sessionenv
	sc config sessionenv start= disabled
	sc stop remoteregistry
	sc config remoteregistry start= disabled
	sc stop Messenger
	sc config Messenger start= disabled
	sc stop upnphos
	sc config upnphos start= disabled
	sc stop WAS
	sc config WAS start= disabled
	sc stop RemoteAccess
	sc config RemoteAccess start= disabled
	sc stop mnmsrvc
	sc config mnmsrvc start= disabled
	sc stop NetTcpPortSharing
	sc config NetTcpPortSharing start= disabled
	sc stop RasMan
	sc config RasMan start= disabled
	sc stop TabletInputService
	sc config TabletInputService start= disabled
	sc stop RpcSs
	sc config RpcSs start= disabled
	sc stop SENS
	sc config SENS start= disabled
	sc stop EventSystem
	sc config EventSystem start= disabled
	sc stop SysMain
	sc config SysMain start= disabled
	goto 18
)

:enableserv
cls
echo tlntsvr (Telnet)
echo msftpsvc (FTP)
echo snmptrap (SNMP Trap)
echo ssdpsrv (SSDP Discovery)
echo termservice, sessionenv (Remote Desktop Services) *Dont disable these if remote desktop is needed*
echo remoteregistry (Remote Registry)
echo Messenger (Windows Messenger)
echo upnphos (Universal Plug n Play)
echo WAS (Web server Service)
echo RemoteAccess (Routing and Remote Access)
echo mnmsrvc (NetMeeting Remote Desktop Sharing)
echo NetTcpPortSharing (Net.Tcp Port Sharing Service)
echo RasMan (Access for dial-up and VPN)
echo TabletInputService (Tablet crap)
echo RpcSs (Remote Procedure Call)
echo SENS (System Event Notification Service)
echo EventSystem (COM+ Event System)
echo SysMain (Superfetch)
echo.

set /p serv="Enter a service to enable... "
if %serv% == n goto 18
if %serv% == re goto menu

sc config %serv% start= auto
sc start %serv%

goto enableserv

:disablegud
cls
echo tlntsvr (Telnet)
echo msftpsvc (FTP)
echo snmptrap (SNMP Trap)
echo ssdpsrv (SSDP Discovery)
echo termservice, sessionenv (Remote Desktop Services) *Dont disable these if remote desktop is needed*
echo remoteregistry (Remote Registry)
echo Messenger (Windows Messenger)
echo upnphos (Universal Plug n Play)
echo WAS (Web server Service)
echo RemoteAccess (Routing and Remote Access)
echo mnmsrvc (NetMeeting Remote Desktop Sharing)
echo NetTcpPortSharing (Net.Tcp Port Sharing Service)
echo RasMan (Access for dial-up and VPN)
echo TabletInputService (Tablet crap)
echo RpcSs (Remote Procedure Call)
echo SENS (System Event Notification Service)
echo EventSystem (COM+ Event System)
echo SysMain (Superfetch)
echo.

set /p serv="Enter a service to disable... "
if %serv% == n goto 18
if %serv% == re goto menu

sc stop %serv%
sc config %serv% start= disabled

goto disablegud

:manualserv
cls
echo Now look for sketchy services to disable and stuff
echo.
services.msc
pause

if %automode% == true goto 19

goto menu

:: Media Files
:19

if %automode% == true goto deletemf

cls
set /p choice="Search for or delete media files? (s/d) "
if %choice% == s goto searchmf
if %choice% == d goto deletemf
if %choice% == n (
	if %automode% == true goto 20
	goto menu
)
if %choice% == re goto menu

:deletemf
cls
echo Note: "Couldn't find mediafiles.txt" is expected here.
echo.

del "%homedrive%\mediafiles.txt" /f /q

del /s "%homedrive%\*.mp3" /f /q /a
del /s "%homedrive%\*.mp4" /f /q /a
del /s "%homedrive%\*.avi" /f /q /a
del /s "%homedrive%\*.wmv" /f /q /a
del /s "%homedrive%\*.mid" /f /q /a
del /s "%homedrive%\*.mov" /f /q /a
del /s "%homedrive%\*.m4v" /f /q /a
del /s "%homedrive%\*.3gp" /f /q /a
del /s "%homedrive%\*.wma" /f /q /a

cls
echo Media files deleted.
echo.
echo Now check for ones missed. Wait for dis.
echo.

cd %homedrive%\
dir /s /a /b /o-d *.mp3 *.mp4 *.avi *.wmv *.mid *.mov *.m4v *.3gp *.wma *.wav >> mediafiles.txt

start mediafiles.txt

pause

if %automode% == true goto 20

goto 19

:searchmf
cls
echo Note: "Couldn't find mediafiles.txt" is expected here.
echo.
echo Searching for media files...
echo.

del "%homedrive%\mediafiles.txt" /f /q

cd %homedrive%\
dir /s /a /b /o-d *.mp3 *.mp4 *.avi *.wmv *.mid *.mov *.m4v *.3gp *.wma *.wav >> mediafiles.txt

start mediafiles.txt

pause

if %automode% == true goto 20

goto 19

:: Remove Programs + Features
:20
cls
echo MAKE SURE YOU DO ALL OF THE TINGS. DO IT GOOD.
echo.
echo Uninstall programs
echo.
echo Remove features
echo.
echo Remove folders in Program Files
echo.
echo Remove .zip, .exe, .msi
echo.

appwiz.cpl
cd %homedrive%\
dir /s /a /b /o-d *.zip *.exe *.msi >> sketchyfiles.txt
start sketchyfiles.txt

pause

if %automode% == true goto 21

goto menu

:: SCM IE Baselines
:21
cls
"%USERPROFILE%\Desktop\Win7CompFiles\SCMBaselines\LGPO.exe" /g "%USERPROFILE%\Desktop\Win7CompFiles\SCMBaselines\IE11_Com_Sec"
"%USERPROFILE%\Desktop\Win7CompFiles\SCMBaselines\LGPO.exe" /g "%USERPROFILE%\Desktop\Win7CompFiles\SCMBaselines\IE11_User_Sec"

if %automode% == true goto 22

goto menu

:: Backup
:22
cls
set /p location="Enter the drive letter for the backup location... "

wbadmin enable backup -addtarget:%location%: -include:C: -schedule:03:00 -quiet

if %automode% == true goto 23

goto menu

:: Application Settings
:23
cls
echo IF YOU'RE ON A SERVER OS, focus on this a little more.
echo.
echo Set all dem application security settings.
echo.
echo Firefox:
echo	- Warn when try to install addons
echo	- Popup blocker
echo	- other crap
echo.
echo See if there are security settings for other programs.
echo Use the interwebs to your advantage.
echo.

start firefox.exe

pause

if %automode% == true goto 24

goto menu

:: Hosts file
:24
cls
takeown /f "%systemroot%\system32\drivers\etc"

del "%systemroot%\system32\drivers\etc\hosts"
copy "%userprofile%\Desktop\Win7CompFiles\hosts" "%systemroot%\system32\drivers\etc\hosts"

if %automode% == true goto 25

goto menu

:: Operating System Settings
:25
cls
echo IF YOU'RE ON A SERVER OS, focus on this a little more.
echo.
echo Enable screen saver + check "logon on resume"
echo.
control desktop
pause

cls
echo Check file permissions for danko folders
echo.
pause

cls
echo Disable remote desktop
echo.
sysdm.cpl
pause

cls
echo Check action center (doesn't apply to Server 2008)
wscui.cpl
echo.
pause

cls
echo Enable UAC
echo.
pause

if %automode% == true goto 26

goto menu

:: Defensive Countermeasures
:26
cls
echo Make sure windows defender is danko enabled
echo.
pause

cls
echo Make sure you have the security programs installed
echo.
pause

cls
echo Scan on all those programs
echo.
pause

if %automode% == true goto 27

goto menu

:: Prohibited files
:27
cls
echo Yaboi prohibited files.
echo.
echo - Look for xml, txt, etc. in notepad that will open in a second.
echo.
echo - Look in folders for files (sort by date modified)
echo.

cd %homedrive%\
dir /s /a /b /o-d >> eek.txt
start eek.txt

pause

if %automode% == true goto 28

goto menu

:: Random Things At The End
:28
cls
echo Check processes for sketchiness.
echo.
start taskmgr.exe
start firefox.exe www.processlibrary.com
pause

cls
echo Vulns from other images
echo.
pause

cls
echo Go through every single step again (extreme thorough-ness not super necessary)
echo.
pause

cls
echo Past comp vulns (Make Peter or someone read them)
echo.
pause

cls
echo Go through everthing AGAIN MY MAN
echo.
pause

cls
echo Official checklist
echo.
start /d "%userprofile%\Desktop\Win7CompFiles" OfficialWin7Checklist.pdf
pause

if %automode% == true goto end

goto menu

:: End
:end
echo If you reached this screen, you did a good. Maybe. Idk man.
echo.
echo Sending you back to the menu now...
echo.

pause

goto menu

:: Open DankMMC
:29
start /d "%userprofile%\Desktop\Win7CompFiles" DankMMC.msc
goto menu

:: Change visual effects for performance
:30
sysdm.cpl
goto menu

:: Open official checklist
:31
start /d "%userprofile%\Desktop\Win7CompFiles" OfficialWin7Checklist.pdf
goto menu

:: Open master checklist
:32
start /d "%userprofile%\Desktop" OurGloriousChecklist2018_Windows.txt
goto menu