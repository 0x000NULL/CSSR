@echo off
echo [ [96mINFO[0m ] Performing premilinary checks...

echo [ [96mINFO[0m ] Checking if script is running as Administrator...
net session >nul 2>&1
if %ERRORLEVEL% EQU 0 (
  echo [ [92mOK[0m ] Script is running with elevated permissions
) else (
  cls
  echo [ [91mFAIL[0m ] Script is not running as administrator
  timeout 30 >nul
  exit
)

echo [ [96mINFO[0m ] Checking if computer has working internet connection...
ping roen.us -n 2 -w 1000
if %ERRORLEVEL% EQU 1 (
  cls
  echo [ [91mFAIL[0m ] Not connected to the internet
  timeout 30 >nul
  exit
) else (
  echo [ [92mOK[0m ] Connected to the internet
)

cls
echo [ [92mOK[0m ] All preliminary checks have passed.
echo [ [96mINFO[0m ] CCS Client can take a while to award points, so it's reccomended to have a delay between commands.
SET /P INTCMD=Enter a delay (in seconds) between commands (Reccomended: 15) 
timeout 5 >nul
cls

REM -----------------------------------------------------------------------------------------

echo [ [96mINFO[0m ] Disabling Guest account...
net user Guest /active:no >nul

if ERRORLEVEL 1 (
  echo [ [91mFAIL[0m ] Disabling Guest Account failed.
  timeout 30 >nul
  exit
)

echo [ [92mOK[0m ] Guest account disabled
timeout %INTCMD% >nul

REM -----------------------------------------------------------------------------------------

echo [ [96mINFO[0m ] Disabling Admin account...
net user Administrator /active:no >nul

if ERRORLEVEL 1 (
  echo [ [91mFAIL[0m ] Disabling Admin Account failed.
  timeout 30 >nul
  exit
)

echo [ [92mOK[0m ] Admin account disabled
timeout %INTCMD% >nul

REM -----------------------------------------------------------------------------------------

echo [ [96mINFO[0m ] Setting MAXPWAGE to 14 days...
net accounts /maxpwage:14 >nul

if ERRORLEVEL 1 (
  echo [ [91mFAIL[0m ] An error occured while setting MAXPWAGE.
  timeout 30 >nul
  exit
)

echo [ [92mOK[0m ] Maximum password life set.
timeout %INTCMD% >nul

REM -----------------------------------------------------------------------------------------

echo [ [96mINFO[0m ] Setting MINPWLENGTH to 10 characters...
net accounts /minpwlen:10 >nul

if ERRORLEVEL 1 (
  echo [ [91mFAIL[0m ] An error occured while setting MINPWLENGTH.
  timeout 30 >nul
  exit
)

echo [ [92mOK[0m ] Minimum password length set.
timeout %INTCMD% >nul

REM -----------------------------------------------------------------------------------------

echo [ [96mINFO[0m ] Setting lockout duration to 45 minutes...
net accounts /lockoutduration:45 >nul

if ERRORLEVEL 1 (
  echo [ [91mFAIL[0m ] An error occured while setting lockout duration.
  timeout 30 >nul
  exit
)

echo [ [92mOK[0m ] Lockout duration policy is enforced.
timeout %INTCMD% >nul

REM -----------------------------------------------------------------------------------------

echo [ [96mINFO[0m ] Setting lockout threshold to 3 attempts...
net accounts /lockoutthreshold:3 >nul

if ERRORLEVEL 1 (
  echo [ [91mFAIL[0m ] An error occured while setting lockout threshold.
  timeout 30 >nul
  exit
)

echo [ [92mOK[0m ] Lockout threshold enforced.
timeout %INTCMD% >nul

REM -----------------------------------------------------------------------------------------

echo [ [96mINFO[0m ] Setting lockout window to 15 minutes...
net accounts /lockoutwindow:15 >nul

if ERRORLEVEL 1 (
  echo [ [91mFAIL[0m ] An error occured while setting lockout window.
  timeout 30 >nul
  exit
)

echo [ [92mOK[0m ] Lockout window enforced.
timeout %INTCMD% >nul

REM -----------------------------------------------------------------------------------------

echo [ [96mINFO[0m ] Begin auditing successful and unsuccessful logon/logoff attempts...
auditpol /set /category:"Account Logon" /Success:enable /failure:enable >nul
auditpol /set /category:"Logon/Logoff" /Success:enable /failure:enable >nul
auditpol /set /category:"Account Management" /Success:enable /failure:enable >nul
Auditpol /set /category:"DS Access" /failure:enable >nul
Auditpol /set /category:"Object Access" /failure:enable >nul
Auditpol /set /category:"policy change" /Success:enable /failure:enable >nul
Auditpol /set /category:"Privilege use" /Success:enable /failure:enable >nul
Auditpol /set /category:"System" /failure:enable >nul

if ERRORLEVEL 1 (
  echo [ [91mFAIL[0m ] An error occured while enabling logging for logon and logoff attempts.
  timeout 30 >nul
  exit
)

echo [ [92mOK[0m ] Now logging all logon and logoff attempts.
timeout %INTCMD% >nul

REM -----------------------------------------------------------------------------------------


echo [ [96mINFO[0m ] Disabling shutdown without logon...
REGEDIT.EXE  /S  "%~dp0\bundle\Disable_Shutdown_without_Logon.reg" >nul

if ERRORLEVEL 1 (
  echo [ [91mFAIL[0m ] Executing premade regedit file to disable shutdown without logon failed.
  timeout 30 >nul
  exit
)

echo [ [92mOK[0m ] Shutdown without logon disabled.
timeout %INTCMD% >nul

REM -----------------------------------------------------------------------------------------

echo [ [96mINFO[0m ] Changing all user passwords except self...
setlocal
for /f "delims=" %%u in ('cscript //NoLogo %~dp0\bundle\GetLocalUsers.vbs') do (
  net user "%%u" "kalaheo 5up3r53cur3pa55w0rD$~"
)

if ERRORLEVEL 1 (
  echo [ [91mFAIL[0m ] Changing passwords failed.
  timeout 30 >nul
  exit
)

echo [ [92mOK[0m ] All user passwords except self have been changed.
timeout %INTCMD% >nul

REM -----------------------------------------------------------------------------------------

echo [ [96mINFO[0m ] Attempting to block FTP (20, 21)...
netsh advfirewall firewall add rule name="BlockFTP20" protocol=TCP dir=in localport=20 action=block >nul
netsh advfirewall firewall add rule name="BlockFTP21" protocol=TCP dir=in localport=21 action=block >nul

if ERRORLEVEL 1 (
  echo [ [91mFAIL[0m ] An error occured while blocking FTP.
  timeout 30 >nul
  exit
)

echo [ [92mOK[0m ] FTP is blocked.
timeout %INTCMD% >nul

REM -----------------------------------------------------------------------------------------

echo [ [96mINFO[0m ] Attempting to block TCP/Telnet (23)...
netsh advfirewall firewall add rule name="BlockTelNet23" protocol=TCP dir=in localport=23 action=block >nul

if ERRORLEVEL 1 (
  echo [ [91mFAIL[0m ] An error occured while blocking TelNet.
  timeout 30 >nul
  exit
)

echo [ [92mOK[0m ] TelNet is blocked.
timeout %INTCMD% >nul

REM -----------------------------------------------------------------------------------------

echo [ [96mINFO[0m ] Attempting to deny RDP access...
reg add "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Terminal Server" /v fDenyTSConnections /t REG_DWORD /d 1 /f >nul

if ERRORLEVEL 1 (
  echo [ [91mFAIL[0m ] An error occured while denying RDP.
  timeout 30 >nul
  exit
)

echo [ [92mOK[0m ] RDP connections are now being denied.
timeout %INTCMD% >nul

REM -----------------------------------------------------------------------------------------
:PROMPT
SET /P AREYOUSURE=Would you like to update Windows now? This is a slow process and will take a lot of time. (y/n)
IF /I "%AREYOUSURE%" NEQ "Y" GOTO NEXT

echo [ [96mINFO[0m ] Attempting to force-check for updates and perform updates...
echo [ [96mINFO[0m ] If the computer updates, you will have to restart the script to execute remaining actions.
cscript //NoLogo %~dp0\bundle\UpdateAllSoftware.vbs

if ERRORLEVEL 1 (
  echo [ [91mFAIL[0m ] Error updating Windows automatically.
  timeout 30 >nul
  exit
)

echo [ [92mOK[0m ] Windows updated!
timeout %INTCMD% >nul

REM -----------------------------------------------------------------------------------------

:NEXT
echo [ [96mINFO[0m ] Attempting to enable Windows Firewall...
NetSh Advfirewall set allprofiles state on
Netsh Advfirewall show allprofiles

if ERRORLEVEL 1 (
  echo [ [91mFAIL[0m ] Error enabling Windows Firewall.
  timeout 30 >nul
  exit
)

echo [ [92mOK[0m ] Windows Firewall enabled.
timeout %INTCMD% >nul

REM -----------------------------------------------------------------------------------------

cls
echo [ [92mOK[0m ] The script has finished executing with no errors. Hope it helped your score out a bit!
echo [ [96mINFO[0m ] It's likely that this script installed updates that require a restart.
echo [ [96mINFO[0m ] Press any key to restart, or [ X ] to exit without restarting.
pause >nul
shutdown /r /t 0
