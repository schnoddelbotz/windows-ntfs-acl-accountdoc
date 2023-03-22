@echo off
cls
echo please wait ...

call powershell %~dp0\accountdoc.ps1 %~dp0

echo AccountDoc.ps1 completed. Press any key to close this window.
pause
