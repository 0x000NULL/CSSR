@echo off
title NotaVirus Windows Script
echo Welcome to Ethan's Script!
cd files
pause
clear
Echo Running scripts
cd 2
start CyberPatriotPowerShellScript.ps1
cd ..
pause
cd 3
start WindowsStigs.bat
pause 
start WidnowsSecurity.ps1
pause
cd ..
cd DOFIRST
pause
start FirstRun.bat
pause
start Main.bat
pause
cd ..
cd scripts

echo SERVER2008?
SET /P M=Type y or n then press ENTER:
IF %M%==y goto SERVER2008GucciScript.bat
IF %M%==n goto skip19
:WIN7GucciScript.bat
start WIN7GucciScript.bat
:skip19
pause 
clear

echo SERVER2016?
SET /P M=Type y or n then press ENTER:
IF %M%==y goto SERVER2016GucciScript.bat
IF %M%==n goto skip20
:SERVER2016GucciScript.bat
start SERVER2016GucciScript.bat
:skip20
pause 
clear

echo WIN 7?
SET /P M=Type y or n then press ENTER:
IF %M%==y goto WIN7GucciScript.bat
IF %M%==n goto skip21
:WIN7GucciScript.bat
start WIN7GucciScript.bat
:skip21
pause 
clear

echo WIN 8?
SET /P M=Type y or n then press ENTER:
IF %M%==y goto WIN8GucciScript.bat
IF %M%==n goto skip22
:WIN8GucciScript.bat
start WIN8GucciScript.bat
:skip22
pause 
clear

echo WIN 10?
SET /P M=Type y or n then press ENTER:
IF %M%==y goto WIN10GucciScript.bat
IF %M%==n goto skip23
:WIN10GucciScript.bat
start WIN10GucciScript.bat
:skip23
pause 
clear

echo block-telementry?
SET /P M=Type y or n then press ENTER:
IF %M%==y goto block-telementry
IF %M%==n goto skip1
:block-telementry
start files/scripts/block-telementry.ps1
:skip1
pause 
clear

echo disable services? This will diable many services. Please editthe file.
SET /P M=Type y or n then press ENTER:
IF %M%==y goto disable-services
IF %M%==n goto skip2
:disable-services
notepad files/scripts/disable-services.ps1
pause
start files/scripts/disable-services.ps1
:skip2
pause 
clear


cd WindowsFirewall
cd tools 

echo Open Firewall tools? 
SET /P M=Type y or n then press ENTER:
IF %M%==y goto FirewallToolsWithGui
IF %M%==n goto skip10
:FirewallToolsWithGui
start FirewallToolsWithGui.ps1
:skip10
pause 
clear

echo run misc script? 
SET /P M=Type y or n then press ENTER:
IF %M%==y goto all
IF %M%==n goto skip11
:all
start all.bat
:skip11
pause 
clear

echo opening gui!
start hardentools.exe
pause
clear

echo run audits?  These will allow you to check for compleatness. each will open in a new window.
SET /P M=Type y or n then press ENTER:
IF %M%==y goto audits
IF %M%==n goto end
:audits
start ASD1709HardeningComplianceCheck.ps1
start ASDOffice2016HardeningComplianceCheck.ps1
:end
pause 
clear