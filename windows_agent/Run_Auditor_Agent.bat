@echo off
setlocal
cd /d "%~dp0"

echo ================================================================
echo SECURE FILE TRANSFER MONITORING SYSTEM - WINDOWS AGENT
echo ================================================================
echo This agent monitors only the bundled TransferTest and Destination folders.
echo File contents are NOT uploaded. Event metadata and filenames are sent over HTTPS.
echo.
set /p MONITOR_API_URL=Enter the Render service URL (example: https://your-service.onrender.com):
set /p MONITOR_API_TOKEN=Enter the auditor API token supplied by the project owner:
if "%MONITOR_API_URL%"=="" (
  echo ERROR: Render service URL is required.
  pause
  exit /b 1
)
if "%MONITOR_API_TOKEN%"=="" (
  echo ERROR: API token is required for live cloud event forwarding.
  pause
  exit /b 1
)
set MONITOR_AGENT_ID=%COMPUTERNAME%

echo.
echo Installing Windows monitoring dependencies...
py -m pip install -r requirements.txt
if errorlevel 1 (
  echo Dependency installation failed. Install Python 3 and try again.
  pause
  exit /b 1
)

echo.
echo Starting Windows monitoring agent...
py src\main.py

echo.
echo Monitoring agent stopped.
pause
endlocal
