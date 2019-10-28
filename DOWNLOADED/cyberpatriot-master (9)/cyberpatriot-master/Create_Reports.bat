@echo off
color 0a
cls
echo This script is meant for Win7 and higher. Lower ones will not have Features/Firewall report functional.
mkdir %userprofile%\Desktop\reports
set basedpath=%userprofile%\Desktop\reports
del /q %basedpath%\*.*
echo Collecting Information...
echo This Information run through %username% on %computername% at %time% %date% > %basedpath%\sysinforeport.txt
echo -------------------------------------------------------------------------- >> %basedpath%\sysinforeport.txt
systeminfo >> %basedpath%\sysinforeport.txt
echo System Info Report Compiled
echo This Information run through %username% on %computername% at %time% %date% >> %basedpath%\tasksreport.txt
tasklist /svc >> %basedpath%\tasksreport.txt
echo. >> %basedpath%\tasksreport.txt
echo ------VERBOSE REPORT BELOW------ >> %basedpath%\tasksreport.txt
tasklist /v >> %basedpath%\tasksreport.txt
echo Tasks/Processes Report Compiled
schtasks >> %basedpath%\scheduledtasksreport.txt
echo Scheduled Tasks Report Compiled
net users > %basedpath%\usersreport.txt
(
  for /F %%h in (%basedpath%\usersreport.txt) do (
    net user %%h >NUL
	if %errorlevel%==0 net user %%h >> %basedpath%\usersreport.txt 
  )
)
echo. >> %basedpath%\usersreport.txt
echo Below is the administrators group: >> %basedpath%\usersreport.txt
net localgroup Administrators >> %basedpath%\usersreport.txt
echo. >> %basedpath%\usersreport.txt
echo Below is the account lockout policy
net accounts >> %basedpath%\usersreport.txt
echo Users Report Compiled
net share >> %basedpath%\sharesreport.txt
echo Shares Report Compiled
dism /online /get-features >> %basedpath%\featuresreport.txt
echo Features Report Compiled
netsh advfirewall firewall show rule name=all > %basedpath%\firewallreport.txt
echo --Port Information Below-- >> %basedpath%\firewallreport.txt
netstat -ano >> %basedpath%\firewallreport.txt
dir /r /s C:\*.* | findstr /v "AM" | findstr /v "PM" | findstr /v "File(s)" | findstr /v "Dir(s)" | findstr /v "Directory of" | findstr /v "Zone.Identifier" > basedads.txt
echo ADS Report Generated
echo Done Compiling, go to the reports folder on your desktop 
pause
