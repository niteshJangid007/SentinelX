@echo off
setlocal
cd /d "%~dp0"
if not exist ".venv\Scripts\python.exe" (
  echo Run Start-Sentinelx.cmd once to install the project dependencies, then run this repair.
  pause
  exit /b 1
)
".venv\Scripts\python.exe" scripts\repair_postgres.py
if errorlevel 1 goto failed
echo Start Sentinelx again using Start-Sentinelx.cmd.
pause
exit /b 0
:failed
echo Repair could not finish. Share only the error message, never your .env file.
pause
exit /b 1
