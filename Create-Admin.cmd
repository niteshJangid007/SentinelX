@echo off
setlocal
cd /d "%~dp0"
if not exist ".venv\Scripts\python.exe" (
  python -m venv .venv
  if errorlevel 1 goto failed
)
".venv\Scripts\python.exe" -m pip install -r requirements.lock
if errorlevel 1 goto failed
".venv\Scripts\python.exe" scripts\start.py create-admin
if errorlevel 1 goto failed
echo Administrator setup completed. You can now start Sentinelx and open /admin.
pause
exit /b 0
:failed
echo Administrator setup failed. Review the error above.
pause
exit /b 1
