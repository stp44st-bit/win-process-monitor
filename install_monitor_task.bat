@echo off
chcp 65001 >nul
net session >nul 2>&1
if errorlevel 1 (
  echo ต้องรันไฟล์นี้ด้วยสิทธิ์ Administrator
  echo คลิกขวาที่ไฟล์ แล้วเลือก Run as administrator
  pause
  exit /b 1
)

set "PYW=%LOCALAPPDATA%\Programs\Python\Python312\pythonw.exe"
if not exist "%PYW%" (
  for /f "delims=" %%P in ('where pythonw 2^>nul') do if not defined FOUND set "PYW=%%P" & set FOUND=1
)
if not exist "%PYW%" (
  echo ไม่พบ pythonw.exe
  pause
  exit /b 1
)

set "SCRIPT=%~dp0process_monitor.py"
echo Python : %PYW%
echo Script : %SCRIPT%
echo.

schtasks /Create /TN "ProcessMonitor" /SC ONLOGON /RL HIGHEST /F ^
  /TR "\"%PYW%\" \"%SCRIPT%\" --watch --notify --min-score 30 --interval 5"
if errorlevel 1 ( pause & exit /b 1 )

echo.
echo === สร้าง Scheduled Task สำเร็จ กำลังเริ่มทำงานทันที...
schtasks /Run /TN "ProcessMonitor"
echo.
echo ถ้าต้องการปิด:  schtasks /End /TN ProcessMonitor
echo ถ้าต้องการลบ :  schtasks /Delete /TN ProcessMonitor /F
pause
