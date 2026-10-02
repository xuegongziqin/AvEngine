@echo off
REM Apply the project Sysmon configuration (requires Administrator and an
REM installed Sysmon service). The Sysmon binary lives in bina\Sysmon\.
setlocal

set "SYSMON=%~dp0..\bina\Sysmon\Sysmon.exe"
if not exist "%SYSMON%" set "SYSMON=%~dp0..\Sysmon.exe"

if not exist "%SYSMON%" (
    echo [config_sysmon] Sysmon.exe not found. Place it in bina\Sysmon\ and retry.
    exit /b 1
)

"%SYSMON%" -accepteula -c "%~dp0sysmon_config.xml"
if errorlevel 1 (
    echo [config_sysmon] Failed to apply sysmon_config.xml. Run as Administrator.
    exit /b 1
)

echo [config_sysmon] Configuration applied.
endlocal
