@echo off
title NotaVirus Windows Script
rem CSSR legacy Windows runner (2018-2019). Not maintained: read legacy\README.md first,
rem and use audit\windows\CSSR-Audit.ps1 on current images instead.
rem Run from an elevated (Administrator) command prompt.
cd /d "%~dp0"
echo Welcome to Ethan's Script!
pause
cls

echo Running the DOFIRST scripts (Wellesley CyberPatriotScripts)...
pause
start "" "%~dp0files\DOFIRST\FirstRun.bat"
pause
start "" "%~dp0files\DOFIRST\Main.bat"
pause
cls

echo SERVER 2008?
set "M="
set /p M=Type y or n then press ENTER:
if /i "%M%"=="y" start "" "%~dp0SERVER2008GucciScript.bat"
pause
cls

echo SERVER 2016?
set "M="
set /p M=Type y or n then press ENTER:
if /i "%M%"=="y" start "" "%~dp0SERVER2016GucciScript.bat"
pause
cls

echo WIN 7?
set "M="
set /p M=Type y or n then press ENTER:
if /i "%M%"=="y" start "" "%~dp0WIN7GucciScript.bat"
pause
cls

echo WIN 8?
set "M="
set /p M=Type y or n then press ENTER:
if /i "%M%"=="y" start "" "%~dp0WIN8GucciScript.bat"
pause
cls

echo WIN 10?
set "M="
set /p M=Type y or n then press ENTER:
if /i "%M%"=="y" start "" "%~dp0WIN10GucciScript.bat"
pause
cls

echo Block telemetry?
set "M="
set /p M=Type y or n then press ENTER:
if /i "%M%"=="y" powershell -NoProfile -ExecutionPolicy Bypass -File "%~dp0files\scripts\block-telemetry.ps1"
pause
cls

echo Disable services? This will disable many services. Edit the file first: it opens in Notepad.
set "M="
set /p M=Type y or n then press ENTER:
if /i "%M%"=="y" (
	notepad "%~dp0files\scripts\disable-services.ps1"
	pause
	powershell -NoProfile -ExecutionPolicy Bypass -File "%~dp0files\scripts\disable-services.ps1"
)
pause
cls

echo hardentools is no longer bundled. If you want it, download it from
echo https://github.com/securitywithoutborders/hardentools/releases
echo.
echo FINISHED. Check users, the README and the forensics questions!
pause
