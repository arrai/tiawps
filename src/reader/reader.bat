@echo off
echo "Tiawps sessionkey reader Build 11723 3.3.3"

SET PATH=%~dp0
REM Switch to drive
%PATH:~0,2%

cd %PATH%

tiawps_reader.exe 12272644 1288
PAUSE
