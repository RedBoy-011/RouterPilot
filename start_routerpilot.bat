@echo off
title RouterPilot Control Plane v1.0
cd /d "%~dp0"
echo ================================================================
echo   RouterPilot Control Plane v1.0 - Windows Portable Launcher
echo ================================================================
echo.
echo Launching standalone Control Plane...
py scripts\run_simulator.py
if %ERRORLEVEL% NEQ 0 (
    python scripts\run_simulator.py
)
pause
