@echo off
REM One-click setup: configure Sysmon, then set up ClamAV.
REM Run this script as Administrator.
REM
REM ClamAV note: ClamAV 1.x (bina\clamav.msi) does not support Windows 7.
REM On Windows 7 this script lets you choose between a LAN clamd and
REM YARA-only operation instead of installing ClamAV locally.
setlocal EnableExtensions

call "%~dp0config_sysmon.bat"
if errorlevel 1 (
    echo [install] Sysmon configuration failed.
    exit /b 1
)

set "ISWIN7="
ver | findstr /c:"6.1." >nul && set "ISWIN7=1"
if not defined ISWIN7 goto :local_clamav

echo.
echo [install] Windows 7 detected: ClamAV 1.x is not supported here.
echo           1 = connect to a clamd running on another machine (LAN)
echo           2 = use YARA only (no ClamAV)
set "CHOICE="
set /p "CHOICE=Choose [1/2]: "
if "%CHOICE%"=="1" goto :remote_clamd
if "%CHOICE%"=="2" goto :yara_only
echo [install] Invalid choice; defaulting to YARA only.
goto :yara_only

:local_clamav
powershell -NoProfile -ExecutionPolicy Bypass -File "%~dp0setup_clamav.ps1"
if errorlevel 1 (
    echo [install] ClamAV setup failed.
    exit /b 1
)
goto :done

:remote_clamd
set "CLAMHOST="
set /p "CLAMHOST=Enter clamd host/IP (e.g. 192.168.1.50): "
if "%CLAMHOST%"=="" (
    echo [install] No host entered; using YARA only.
    goto :yara_only
)
powershell -NoProfile -ExecutionPolicy Bypass -File "%~dp0set_clamav.ps1" -ClamdHost "%CLAMHOST%"
if errorlevel 1 (
    echo [install] Failed to update config.yaml.
    exit /b 1
)
echo [install] Done. Verify with:  avengine.exe status
goto :done

:yara_only
powershell -NoProfile -ExecutionPolicy Bypass -File "%~dp0set_clamav.ps1" -ClamdHost none
if errorlevel 1 (
    echo [install] Failed to update config.yaml.
    exit /b 1
)
echo [install] ClamAV disabled (YARA-only). Scanning still works.
goto :done

:done
echo [install] Done.
endlocal
