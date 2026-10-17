@echo off
REM One-click setup: pick the Sysmon build for this Windows version, configure
REM Sysmon, then set up ClamAV. Run this script as Administrator.
REM
REM Sysmon note: Sysmon 15.x needs Windows 8.1 / Server 2012 R2 or newer.
REM Windows 7 SP1 / Server 2008 R2 must use the legacy 13.x build that lives in
REM bina\Sysmon\sysmonwin7\. scripts\lib_sysmon.ps1 does the selection (version
REM + architecture) and this script shows which binary was chosen.
REM
REM ClamAV note: the installer package is chosen by OS version (same rule as
REM avengine\paths.py clamav_msi() and scripts\setup_clamav.bat):
REM   Windows 8.1+                    -> bina\clamav.msi      (modern 1.x)
REM   Windows 7 SP1 / Server 2008 R2  -> bina\clamwin7\*.msi  (last build supporting Win7)
REM So this script now offers the SAME three choices on every OS:
REM   1) install ClamAV locally (version-appropriate package)
REM   2) connect to a clamd on another machine (LAN)
REM   3) YARA only
setlocal EnableExtensions

REM ---- 1. detect Windows version and native architecture ----------------
set "OSVER="
for /f "tokens=4,5 delims=[]. " %%a in ('ver') do if not defined OSVER set "OSVER=%%a.%%b"
if not defined OSVER set "OSVER=unknown"
set "NATIVEARCH=%PROCESSOR_ARCHITEW6432%"
if not defined NATIVEARCH set "NATIVEARCH=%PROCESSOR_ARCHITECTURE%"
if not defined NATIVEARCH set "NATIVEARCH=X86"
echo [install] Windows %OSVER% (%NATIVEARCH%)

REM ---- 2. pick the Sysmon binary that matches this system ----------------
set "SYSMON_BIN="
for /f "usebackq delims=" %%i in (`powershell -NoLogo -NoProfile -ExecutionPolicy Bypass -File "%~dp0lib_sysmon.ps1" -Print`) do set "SYSMON_BIN=%%i"
REM If PowerShell misbehaves its banner can land in stdout: keep only real files.
if defined SYSMON_BIN if not exist "%SYSMON_BIN%" set "SYSMON_BIN="
if not defined SYSMON_BIN call :pick_sysmon_batch
if defined SYSMON_BIN (
    echo [install] Sysmon binary: %SYSMON_BIN%
) else (
    echo [install] Sysmon binary not found - realtime monitor stays unavailable.
    echo [install]   modern ^(Win8.1+^): bina\Sysmon\Sysmon.exe ^| Sysmon64.exe ^| Sysmon64a.exe
    echo [install]   legacy ^(Win7 SP1^): bina\Sysmon\sysmonwin7\Sysmon.exe ^| Sysmon64.exe
    echo [install]   run scripts\sysmon_which.bat to see what was detected
)

call "%~dp0config_sysmon.bat" "%SYSMON_BIN%"
set "SM_RC=%ERRORLEVEL%"
if "%SM_RC%"=="2" (
    echo [install] Skipping Sysmon setup ^(no binary available^); continuing with ClamAV.
) else (
    if not "%SM_RC%"=="0" (
        echo [install] Sysmon configuration failed ^(exit %SM_RC%^).
        exit /b 1
    )
)

REM ---- ClamAV: same three choices on every OS (default = install locally) ----
echo.
echo [install] ClamAV options:
echo           1 = install ClamAV on this machine  ^(default^)
echo               Windows 8.1+  uses bina\clamav.msi
echo               Windows 7 SP1 uses bina\clamwin7\*.msi
echo           2 = connect to a clamd on another machine ^(LAN^)
echo           3 = YARA only ^(no ClamAV^)
set "CHOICE="
set /p "CHOICE=Choose [1/2/3] (default 1): "
if not defined CHOICE set "CHOICE=1"
if "%CHOICE%"=="2" goto :remote_clamd
if "%CHOICE%"=="3" goto :yara_only
if not "%CHOICE%"=="1" (
    echo [install] Invalid choice; defaulting to installing ClamAV locally.
)
goto :local_clamav

:local_clamav
call "%~dp0setup_clamav.bat"
if errorlevel 1 (
    echo [install] ClamAV setup failed - see the diagnostics printed above.
    echo [install] The clamd service may still be startable later:
    echo [install]     scripts\start_clamav.bat      (starts the service, or runs clamd in the foreground)
    echo [install] Sysmon is already configured; you can rerun scripts\install.bat after fixing ClamAV.
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
call "%~dp0set_clamav.bat" -ClamdHost "%CLAMHOST%"
if errorlevel 1 (
    echo [install] Failed to update config.yaml.
    exit /b 1
)
echo [install] Done. Verify with:  avengine.exe status
goto :done

:yara_only
call "%~dp0set_clamav.bat" -ClamdHost none
if errorlevel 1 (
    echo [install] Failed to update config.yaml.
    exit /b 1
)
echo [install] ClamAV disabled (YARA-only). Scanning still works.
goto :done

REM ---- fallback selection used only when PowerShell is unavailable -------
REM Same rule as lib_sysmon.ps1: 6.0/6.1 -> sysmonwin7 (13.x), newer -> bina\Sysmon (15.x)
:pick_sysmon_batch
set "PICK_DIR=%~dp0..\bina\Sysmon"
set "ALT_DIR=%~dp0..\bina\Sysmon\sysmonwin7"
ver | findstr /c:"6.0." /c:"6.1." >nul && set "PICK_DIR=%~dp0..\bina\Sysmon\sysmonwin7"
ver | findstr /c:"6.0." /c:"6.1." >nul && set "ALT_DIR=%~dp0..\bina\Sysmon"
set "PICK_NAME=Sysmon.exe"
if /i "%NATIVEARCH%"=="AMD64" set "PICK_NAME=Sysmon64.exe"
if /i "%NATIVEARCH%"=="ARM64" set "PICK_NAME=Sysmon64a.exe"
if exist "%PICK_DIR%\%PICK_NAME%" set "SYSMON_BIN=%PICK_DIR%\%PICK_NAME%"
if not defined SYSMON_BIN if exist "%PICK_DIR%\Sysmon64.exe" set "SYSMON_BIN=%PICK_DIR%\Sysmon64.exe"
if not defined SYSMON_BIN if exist "%PICK_DIR%\Sysmon.exe" set "SYSMON_BIN=%PICK_DIR%\Sysmon.exe"
if not defined SYSMON_BIN if exist "%ALT_DIR%\%PICK_NAME%" set "SYSMON_BIN=%ALT_DIR%\%PICK_NAME%"
if not defined SYSMON_BIN if exist "%ALT_DIR%\Sysmon64.exe" set "SYSMON_BIN=%ALT_DIR%\Sysmon64.exe"
if not defined SYSMON_BIN if exist "%ALT_DIR%\Sysmon.exe" set "SYSMON_BIN=%ALT_DIR%\Sysmon.exe"
if not defined SYSMON_BIN if exist "%~dp0..\Sysmon.exe" set "SYSMON_BIN=%~dp0..\Sysmon.exe"
exit /b 0

:done
echo [install] Done.
endlocal
exit /b 0
