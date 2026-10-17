@echo off
REM sysmon_which.bat - show which Sysmon binary this Windows version would use.
REM Read-only diagnostic: touches nothing, installs nothing.
setlocal EnableExtensions
cd /d "%~dp0"

echo ============================================
echo  Sysmon binary selection
echo ============================================
echo.
ver
echo.
powershell -NoProfile -ExecutionPolicy Bypass -File "%~dp0lib_sysmon.ps1" -Explain
if errorlevel 1 (
    echo.
    echo [sysmon_which] No usable Sysmon binary was found.
    echo [sysmon_which]   modern ^(Win8.1+^): bina\Sysmon\Sysmon.exe ^| Sysmon64.exe ^| Sysmon64a.exe
    echo [sysmon_which]   legacy ^(Win7 SP1^): bina\Sysmon\sysmonwin7\Sysmon.exe ^| Sysmon64.exe
    endlocal
    exit /b 1
)
echo.
echo Apply it with:  scripts\config_sysmon.bat
endlocal
exit /b 0
