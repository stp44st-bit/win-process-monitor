@echo off
chcp 65001 >nul
cd /d "%~dp0"

set "PY=python"

echo === ใช้ Python: %PY%
"%PY%" --version
echo.
echo === ติดตั้ง psutil
"%PY%" -m pip install --upgrade psutil
echo.
echo === สแกนโปรเซส
"%PY%" process_monitor.py
echo.
pause
