@echo off
title Ez PoIntS
echo ----------------------------------
echo Server 2016 Ultimate Combo Script!
echo      It runs all the things
echo ----------------------------------
echo.

pause

:: Check if 64 bit or 32 bit
cls
wmic os get osarchitecture
echo.

pause

:: Set all variables for choices
set a=Inf files
set c=SCM Baselines
set d=Windows Update
set e=Delete/Add users
set f=Activate/Disable users
set g=Delete/add admins
set h=Change passwords
set i=Uninstall un-litty programs and features
set j=Firewall
set k=Nessus
set l=Install + update programs
set m=Services
set n=Media files
set o=Manual Stuff and things
set p=Last steps
set q=Hosts file

:: Choices menu
:begin
cls
echo 1) %a%
echo 2) %c%
echo 3) %d%
echo 4) %e%
echo 5) %f%
echo 6) %g%
echo 7) %h%
echo 8) %i%
echo 9) %j%
echo a) %k%
echo b) %l%
echo c) %m%
echo d) %n%
echo e) %o%
echo f) %p%
echo g) %q%
echo.

choice /c 123456789abcdefg /m "Choose an option. " /n
goto %errorlevel%

:: Run inf files
:1
cls
secedit /configure /db "C:\dankdatabase1.db" /cfg "%USERPROFILE%\Desktop\Server2016CompFiles\Server2016Inf.inf"
echo.

set /p cont="Continue to bad inf? "
if %cont% == n goto begin
echo.

:: Run BAD inf
secedit /configure /db "C:\dankdatabase2.db" /cfg "%USERPROFILE%\Desktop\Server2016CompFiles\Server2016BadInf.inf"
echo.

pause

set a=Inf files *DONE*

goto begin

:: SCM Baselines
:2
cls
:: Import IE baselines
"%USERPROFILE%\Desktop\Server2016CompFiles\SCMBaselines\LGPO.exe" /g "%USERPROFILE%\Desktop\Server2016CompFiles\SCMBaselines\IE11_Com_Sec"
"%USERPROFILE%\Desktop\Server2016CompFiles\SCMBaselines\LGPO.exe" /g "%USERPROFILE%\Desktop\Server2016CompFiles\SCMBaselines\IE11_User_Sec"
echo.

set /p cont="Continue to OS baselines? "
if %cont% == n goto begin
echo.

:: Import OS baselines
"%USERPROFILE%\Desktop\Server2016CompFiles\SCMBaselines\LGPO.exe" /g "%USERPROFILE%\Desktop\Server2016CompFiles\SCMBaselines\Server2016\MS_Sec"
"%USERPROFILE%\Desktop\Server2016CompFiles\SCMBaselines\LGPO.exe" /g "%USERPROFILE%\Desktop\Server2016CompFiles\SCMBaselines\Server2016\Dom_Sec"
"%USERPROFILE%\Desktop\Server2016CompFiles\SCMBaselines\LGPO.exe" /g "%USERPROFILE%\Desktop\Server2016CompFiles\SCMBaselines\Server2016\DC_Sec"

echo.
pause

set c=SCM Baselines *DONE*

goto begin

:: Opening windows update
:3
cls
echo Opening windows update cause YA LITTY
echo.

start ms-settings:windowsupdate

pause

set d=Windows Update *DONE*

goto begin

:: Manual stuff and things
:14
cls
echo Open DankMMC.
echo.
echo Forensics Questions!
echo.
echo Check folder/file sharing
echo.
echo Disable autoplay
echo (MMC, Administrative Templates, Windows Components, Autoplay Policies)
echo.
echo Disable remote desktop thingy
echo (MMC, Administrative Templates, Windows Components, Remote Desktop Services, Remote Desktop Session Host, Connections)
echo.
echo Disable smartscreen
echo (MMC, Administrative Templates, Windows Components, File Explorer, Configure Smartscreen)
echo.
echo Enable Windows defender (it is a good)
echo (MMC, Administrative Templates, Windows Components, Windows Defender)
echo.

pause

set o=Manual Stuff and things *DONE*

goto begin

:: Enable firewall + template
:9
cls
netsh advfirewall import "%USERPROFILE%\Desktop\Server2016CompFiles\Server2016Firewall.wfw"
netsh advfirewall set allprofiles state on

pause

set j=Firewall *DONE*

goto begin

:: Showing IP for nessus
:10
cls
ipconfig
echo.
pause

set k=Nessus *DONE*

goto begin

:: Deleting/adding users
:4
cls
net user

set /p choice="Add or remove user? "
if %choice% == a goto addusers
if %choice% == r goto delusers
if %choice% == n goto begin

:addusers
cls
net user

set /p user="Enter a user to add... "
if %user% == n goto 4
net user %user% /add

echo Done!
echo.

set /p cont="Continue? "
if %cont% == y goto addusers
if %cont% == n goto 4

:delusers
cls
net user

set /p user="Enter a user to delete... "
if %user% == n goto 4
net user %user% /delete

echo Done!
echo.

set /p cont="Continue? "
if %cont% == y goto delusers
if %cont% == n goto 4

:: Deleting/adding admins
:6
cls
net localgroup administrators

set /p choice="Add or remove admin? "

if %choice% == a goto addadmins
if %choice% == r goto deladmins
if %choice% == n goto begin

:addadmins
cls
net user
net localgroup administrators

set /p user="Enter a user to add to admin group... "
if %user% == n goto 6
net localgroup administrators %user% /add

echo Done!
echo.

set /p cont="Continue? "
if %cont% == y goto addadmins
if %cont% == n goto 6

:deladmins
cls
net localgroup administrators

set /p user="Enter a user to remove from admin group... "
if %user% == n goto 6
net localgroup administrators %user% /delete

echo Done!
echo.

set /p cont="Continue? "
if %cont% == y goto deladmins
if %cont% == n goto 6

:: Changing passwords
:7
cls
net user

echo All users' passwords will be abc123ABC123@@
echo.

set /p user="Enter user for password change... "
if %user% == n goto begin
net user %user% abc123ABC123@@

echo Done!
echo.

set /p cont="Continue? "
if %cont% == y goto 7
if %cont% == n goto begin

:: Install programs + update
:11
cls
echo Installing default/security programs.
echo Open up the programs after they install and stuff.
echo.

@"%SystemRoot%\System32\WindowsPowerShell\v1.0\powershell.exe" -NoProfile -InputFormat None -ExecutionPolicy Bypass -Command "iex ((New-Object System.Net.WebClient).DownloadString('https://chocolatey.org/install.ps1'))" && SET "PATH=%PATH%;%ALLUSERSPROFILE%\chocolatey\bin"
choco feature enable -n allowGlobalConfirmation
choco feature enable -n useFipsCompliantChecksums
choco install firefox ie11 malwarebytes mbsa secunia.psi microsoftsecurityessentials --ignore-checksums
cls

:install
set /p install="Enter a program to install... "
if %install% == n goto begin
echo.

choco install %install% --ignore-checksums
echo.

set /p cont="Continue? "
if %cont% == y goto install
if %cont% == n goto begin

:: Uninstall programs and features
:8
cls
echo Uninstall all dem programs!
echo Remove features!
echo Check program files folder too for stuff.
echo.

appwiz.cpl

pause

set i=Uninstall un-litty programs and features *DONE*

goto begin

:: Media files
:15
cls
cd C:\
echo Wait for dis thing to be done, ya NORMIE
dir /s *.mp3 *.mp4 *.png *.jpg *.wav *.avi *.wma *.mid *.aif *.wmv *.mov *.m4v *.3gp *.txt *.exe >> "%USERPROFILE%\Desktop\mediafiles.txt"

echo Done!
echo.
echo Look for mp3, mp4, png, jpg, wav, avi, wma, mid, aif, wmv, mov, m4v, 3gp, txt, exe
echo.

"%USERPROFILE%\Desktop\mediafiles.txt"

set n=Media files *DONE*

goto begin

:: Stop and disable services
:12
cls
echo tlntsvr (Telnet)
echo msftpsvc (FTP)
echo snmptrap (SNMP Trap)
echo ssdpsrv (SSDP Discovery)
echo termservice, sessionenv (Remote Desktop Services)
echo remoteregistry (Remote Registry)
echo Messenger (Windows Messenger)
echo upnphos (Universal Plug n Play)
echo WAS (Web server Service)
echo RemoteAccess (Routing and Remote Access)
echo mnmsrvc (NetMeeting Remote Desktop Sharing)
echo.

set /p choice="Choose a service to disable... "
if %choice% == n goto begin
sc stop %choice%
sc config %choice% start= disabled

echo Done!
echo.

set /p cont="Continue? "
if %cont% == y goto 12
if %cont% == n goto begin

:: Last things
:15
cls
echo Check all these things:
echo.
echo IE SCM Baselines
echo.
echo Vulns from other images
echo.
echo Check simple stuff again and again and again and again and again
echo.
echo Past vulnerabilities
echo.
echo Past comp tips
echo.
echo Official checklist
echo.

pause

goto begin

:: Disable and activate users
:5
cls
net user

echo PROBABLY SHOULD DISABLE GUEST ACCOUNT, YA KNOW?
echo.

set /p choice="Activate or disable user? "
if %choice% == a goto activateusers
if %choice% == d goto disableusers
if %choice% == n goto begin

:activateusers
cls
net user

set /p user="Enter a user to activate... "
if %user% == n goto 5
net user %user% /active:yes

echo Done!
echo.

set /p cont="Continue? "
if %cont% == y goto activateusers
if %cont% == n goto 5

:disableusers
cls
net user

set /p user="Enter a user to disable... "
if %user% == n goto 5
net user %user% /active:no

echo Done!
echo.

set /p cont="Continue? "
if %cont% == y goto disableusers
if %cont% == n goto 5

:: Hosts file
:16
cls
echo Opening hosts file...
echo.
echo Check for sketchy stuff, I guess?
echo.

notepad C:\windows\system32\drivers\etc\hosts

pause

set q=Hosts file *DONE*

goto begin