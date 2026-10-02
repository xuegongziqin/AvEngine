@echo off
REM One-click setup: configure Sysmon, then install and configure ClamAV.
REM Run this script as Administrator.
setlocal

call "%~dp0config_sysmon.bat"
if errorlevel 1 (
    echo [install] Sysmon configuration failed.
    exit /b 1
)

powershell -NoProfile -ExecutionPolicy Bypass -File "%~dp0setup_clamav.ps1"
if errorlevel 1 (
    echo [install] ClamAV setup failed.
    exit /b 1
)

echo [install] Done.
endlocal
