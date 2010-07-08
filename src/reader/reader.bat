@echo off
echo "Tiawps sessionkey reader Build 12340 3.3.5"

SET PATH=%~dp0
REM Switch to drive
%PATH:~0,2%

cd %PATH%

tiawps_reader.exe 13081844 1288
PAUSE
