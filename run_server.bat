@echo off
title Thalapathi Studio - SHOP SERVER (keep this window open)
cd /d "%~dp0"

set PY=python
where py >nul 2>nul && set PY=py

if not exist "venv\Scripts\activate.bat" (
  echo First-time setup - installing what the server needs. This takes a minute...
  %PY% -m venv venv
  if errorlevel 1 (
    echo.
    echo Could not set up Python. Please install Python from python.org
    echo and tick "Add python.exe to PATH" during installation, then try again.
    pause
    exit /b 1
  )
)
call "venv\Scripts\activate.bat"
pip install -q -r requirements.txt

echo.
echo Starting the shop server. Leave this window OPEN while the shop is working.
echo The address to type into each PC's app is shown below once it starts.
echo.
python server.py

echo.
echo The server has stopped. Press any key to close this window.
pause >nul
