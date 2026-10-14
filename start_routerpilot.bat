@echo off
chcp 65001 >nul
title RouterPilot Control Plane v2.0 Enterprise [Windows Launcher]
cd /d "%~dp0"

echo +==============================================================================+
echo ^|             RouterPilot Control Plane v2.0 Enterprise Launcher               ^|
echo +==============================================================================+
echo ^| [*] Vaziat: Dar hale rah-andazi Control Plane va Web Dashboard...            ^|
echo ^| [*] Port: 8080 ^| MNDP L2 Discovery: Fa'al                                    ^|
echo +==============================================================================+
echo.

py scripts\run_simulator.py
if %ERRORLEVEL% NEQ 0 (
    python scripts\run_simulator.py
)

if %ERRORLEVEL% NEQ 0 (
    echo.
    echo [ERROR] Khata dar ejraye barnameh. Lotfan motmaen shavid Python nasb ast.
    pause
)
