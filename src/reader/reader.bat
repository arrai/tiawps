@echo off
+echo "Tiawps sessionkey reader Build 13205 4.0.1"

SET PATH=%~dp0
REM Switch to drive
%PATH:~0,2%

cd %PATH%

tiawps_reader.exe 13261876 1288
PAUSE
