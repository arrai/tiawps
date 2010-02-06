@echo off
echo "Tiawps decrypter"

SET PATH=%~dp0
REM Switch to drive
%PATH:~0,2%

cd %PATH%
tiawps_decrypter.exe %*
PAUSE
