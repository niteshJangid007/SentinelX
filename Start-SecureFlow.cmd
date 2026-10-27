@echo off
setlocal
cd /d "%~dp0"
if not exist ".venv\Scripts\python.exe" (
  python -m venv .venv
  if errorlevel 1 goto failed
)
".venv\Scripts\python.exe" -m pip install -r requirements.lock
if errorlevel 1 goto failed
".venv\Scripts\python.exe" scripts\start.py
if errorlevel 1 goto failed
exit /b 0
:failed
echo Sentinelx could not start. Review the error above.
pause
exit /b 1
