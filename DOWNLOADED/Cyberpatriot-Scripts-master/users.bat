echo off
cls
echo Warning! Make sure that you have completed ALL forensics questions before execution. Some files may be permanently deleted and some settings may be permanently changed.
echo.
pause

Powershell.exe -Command "& '%~dpn0.ps1'" -Verb RunAs
pause

echo on