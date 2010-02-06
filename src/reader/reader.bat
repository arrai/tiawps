@echo off
echo "Tiawps sessionkey reader Build 11403 3.3.2"

SET PATH=%~dp0
REM Switch to drive
%PATH:~0,2%

cd %PATH%

tiawps_reader.exe 13186064 1288
PAUSE
