@echo off
REM Apply the project Sysmon configuration (requires Administrator).
REM The Sysmon binary is selected by scripts\lib_sysmon.ps1 so that Windows 7
REM SP1 / Server 2008 R2 uses the legacy 13.x build in bina\Sysmon\sysmonwin7\
REM while Windows 8.1+ uses bina\Sysmon\ (15.x). install.bat passes the chosen
REM path as %1; this script also resolves it when run standalone.
REM
REM Exit codes: 0 = configured, 1 = configuration failed, 2 = no Sysmon binary.
REM
REM NOTE: keep the resolution below at top level (labels, no parenthesised
REM blocks). Inside a block %VAR% is expanded when the block is parsed, so a
REM variable set inside that same block would read as empty.
setlocal EnableExtensions EnableDelayedExpansion

REM Native architecture, used by the batch fallback further down.
set "ARCH=%PROCESSOR_ARCHITEW6432%"
if not defined ARCH set "ARCH=%PROCESSOR_ARCHITECTURE%"
if not defined ARCH set "ARCH=X86"

REM ---- 1. path passed by install.bat (must be a real .exe) ----------------
set "SYSMON=%~1"
if defined SYSMON if /i not "%~x1"==".exe" set "SYSMON="
if defined SYSMON if not exist "%SYSMON%" set "SYSMON="
if defined SYSMON goto :have_sysmon

REM ---- 2. ask lib_sysmon.ps1 (single source of truth) --------------------
for /f "usebackq delims=" %%i in (`powershell -NoLogo -NoProfile -ExecutionPolicy Bypass -File "%~dp0lib_sysmon.ps1" -Print`) do set "SYSMON=%%i"
REM If PowerShell misbehaves its banner can land in stdout: keep only real files.
if defined SYSMON if not exist "%SYSMON%" set "SYSMON="
if defined SYSMON goto :have_sysmon

REM ---- 3. batch fallback when PowerShell is unavailable ------------------
REM Same rule as lib_sysmon.ps1: 6.0/6.1 -> sysmonwin7 (13.x), newer -> 15.x;
REM if the expected folder holds no build, the other folder is tried too.
set "PICK_DIR=%~dp0..\bina\Sysmon"
set "ALT_DIR=%~dp0..\bina\Sysmon\sysmonwin7"
ver | findstr /c:"6.0." /c:"6.1." >nul && set "PICK_DIR=%~dp0..\bina\Sysmon\sysmonwin7"
ver | findstr /c:"6.0." /c:"6.1." >nul && set "ALT_DIR=%~dp0..\bina\Sysmon"
set "PICK_NAME=Sysmon.exe"
if /i "%ARCH%"=="AMD64" set "PICK_NAME=Sysmon64.exe"
if /i "%ARCH%"=="ARM64" set "PICK_NAME=Sysmon64a.exe"
if exist "%PICK_DIR%\%PICK_NAME%" set "SYSMON=%PICK_DIR%\%PICK_NAME%"
if not defined SYSMON if exist "%PICK_DIR%\Sysmon64.exe" set "SYSMON=%PICK_DIR%\Sysmon64.exe"
if not defined SYSMON if exist "%PICK_DIR%\Sysmon.exe" set "SYSMON=%PICK_DIR%\Sysmon.exe"
if not defined SYSMON if exist "%ALT_DIR%\%PICK_NAME%" set "SYSMON=%ALT_DIR%\%PICK_NAME%"
if not defined SYSMON if exist "%ALT_DIR%\Sysmon64.exe" set "SYSMON=%ALT_DIR%\Sysmon64.exe"
if not defined SYSMON if exist "%ALT_DIR%\Sysmon.exe" set "SYSMON=%ALT_DIR%\Sysmon.exe"
if not defined SYSMON if exist "%~dp0..\Sysmon.exe" set "SYSMON=%~dp0..\Sysmon.exe"

:have_sysmon
set "CFG=%~dp0sysmon_config.xml"
if not exist "%CFG%" (
    echo [config_sysmon] sysmon_config.xml not found: %CFG%
    endlocal
    exit /b 1
)

if not defined SYSMON (
    echo [config_sysmon] No Sysmon binary found.
    echo [config_sysmon]   modern ^(Win8.1+^): bina\Sysmon\Sysmon.exe ^| Sysmon64.exe ^| Sysmon64a.exe
    echo [config_sysmon]   legacy ^(Win7 SP1^): bina\Sysmon\sysmonwin7\Sysmon.exe ^| Sysmon64.exe
    echo [config_sysmon] Run scripts\sysmon_which.bat to see what was detected.
    endlocal
    exit /b 2
)

if not exist "%SYSMON%" (
    echo [config_sysmon] Sysmon binary not found: %SYSMON%
    endlocal
    exit /b 2
)

echo [config_sysmon] Using: %SYSMON%

REM ---- is Sysmon REALLY installed? --------------------------------------
REM Neither the SysmonDrv registry key nor the service entry proves it: on a broken
REM install both can survive while the driver is gone, and then Sysmon prints
REM   "Error: Sysmon is not installed."
REM **while still exiting 0** - so checking errorlevel alone is not enough
REM (real report from a Windows 7 box: "Configuration applied" but no telemetry).
REM Decision: trust what Sysmon itself says, and require the SysmonDrv driver to run.
REM Service names: Sysmon64 on x64/ARM64, Sysmon on x86.
set "SYSMONSVC=Sysmon"
if /i "%ARCH%"=="AMD64" set "SYSMONSVC=Sysmon64"
if /i "%ARCH%"=="ARM64" set "SYSMONSVC=Sysmon64"
set "SYSMON_OUT=%TEMP%\avx_sysmon_out.txt"
set "NEEDS_CLEAN_INSTALL="

sc query "%SYSMONSVC%" >nul 2>&1
if errorlevel 1 (
    set "NEEDS_CLEAN_INSTALL=service missing"
) else (
    echo [config_sysmon] Sysmon service present - applying configuration...
    "%SYSMON%" -accepteula -c "%CFG%" > "%SYSMON_OUT%" 2>&1
    type "%SYSMON_OUT%"
    findstr /i /c:"Error:" "%SYSMON_OUT%" >nul
    if not errorlevel 1 set "NEEDS_CLEAN_INSTALL=Sysmon said it is not installed"
    sc query SysmonDrv | findstr /i "RUNNING" >nul
    if errorlevel 1 if not defined NEEDS_CLEAN_INSTALL set "NEEDS_CLEAN_INSTALL=driver not running"
)

if defined NEEDS_CLEAN_INSTALL (
    echo [config_sysmon] installing ^(!NEEDS_CLEAN_INSTALL!^) with the project configuration...
    REM A clean -u first: a leftover SysmonDrv / service entry makes -i fail
    REM with "already installed".
    "%SYSMON%" -accepteula -u > "%SYSMON_OUT%" 2>&1
    "%SYSMON%" -accepteula -i "%CFG%" > "%SYSMON_OUT%" 2>&1
    type "%SYSMON_OUT%"
    if errorlevel 1 (
        echo [config_sysmon] ERROR: Sysmon -i failed. Run this script as Administrator.
        echo [config_sysmon]   output above; retry by hand:
        echo [config_sysmon]     "%SYSMON%" -accepteula -u
        echo [config_sysmon]     "%SYSMON%" -accepteula -i "%CFG%"
        endlocal
        exit /b 1
    )
    findstr /i /c:"Error:" "%SYSMON_OUT%" >nul
    if not errorlevel 1 (
        echo [config_sysmon] ERROR: Sysmon reported an error while installing ^(see above^).
        endlocal
        exit /b 1
    )
)

REM ---- verify it really runs, so "no telemetry" cannot pass silently -----
sc query "%SYSMONSVC%" >nul 2>&1
if errorlevel 1 (
    echo [config_sysmon] ERROR: service %SYSMONSVC% still missing after install.
    echo [config_sysmon]   check the Sysmon output above, then try:
    echo [config_sysmon]     "%SYSMON%" -accepteula -u
    echo [config_sysmon]     "%SYSMON%" -accepteula -i "%~dp0sysmon_config.xml"
    endlocal
    exit /b 1
)
sc query SysmonDrv | findstr /i "RUNNING" >nul
if errorlevel 1 (
    echo [config_sysmon] ERROR: the SysmonDrv driver is not RUNNING - Sysmon collects nothing.
    echo [config_sysmon]   try:  sc start SysmonDrv
    echo [config_sysmon]   or:   "%SYSMON%" -accepteula -u  then  -accepteula -i "%CFG%"
    endlocal
    exit /b 1
)

echo [config_sysmon] Configuration applied (service %SYSMONSVC% present, driver SysmonDrv running).
endlocal
exit /b 0
