@echo off
setlocal
cd /d "%~dp0"
if not exist ".venv\Scripts\python.exe" (
  py -m venv .venv
  if errorlevel 1 (
    echo Python 3.11+ is required. Install Python and try again.
    exit /b 1
  )
)
call ".venv\Scripts\activate.bat"
python -m pip install -r requirements.txt
if errorlevel 1 exit /b 1
echo.
echo SignalHarbor is available at http://127.0.0.1:8088
python run.py
