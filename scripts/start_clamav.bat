@echo off
REM Start the local ClamAV daemon.
REM   * clamd service registered -> start the service (official background mode)
REM   * no service               -> run clamd in the foreground (Ctrl+C stops it)
REM Never run "clamd.exe --daemon --service-mode" by hand: that is the service-only
REM command line; without the SCM it listens on 3310 but never answers any request.
setlocal EnableExtensions

set "CLAMDIR=%ProgramFiles%\ClamAV"
if not exist "%CLAMDIR%\clamd.exe" set "CLAMDIR=%ProgramFiles(x86)%\ClamAV"
set "CLAMD=%CLAMDIR%\clamd.exe"
set "CLAMD_CONF=%CLAMDIR%\clamd.conf"
set "CLAMD_LOG=%CLAMDIR%\clamd.log"

if not exist "%CLAMD%" (
    echo [start_clamav] ClamAV not found under "%CLAMDIR%".
    echo [start_clamav] Run scripts\install.bat as Administrator first.
    exit /b 1
)

sc query clamd >nul 2>nul
if not errorlevel 1 goto :service

echo [start_clamav] No clamd service registered - running in the foreground.
echo [start_clamav] Keep this window open; press Ctrl+C to stop clamd.
echo [start_clamav] To install the background service instead, run as Administrator:
echo [start_clamav]     scripts\install.bat
"%CLAMD%" --foreground --config-file="%CLAMD_CONF%"
endlocal
exit /b %errorlevel%

:service
echo [start_clamav] Starting the clamd service ...
net start clamd
if errorlevel 1 (
    echo [start_clamav] Service failed to start. The real reason is usually in:
    echo [start_clamav]     "%CLAMD_LOG%"
    echo [start_clamav] Diagnose in the foreground with:
    echo [start_clamav]     "%CLAMD%" --foreground --debug --config-file="%CLAMD_CONF%"
    exit /b 1
)
echo [start_clamav] clamd service is running on 127.0.0.1:3310.
echo [start_clamav] Verify with: avengine.exe status
endlocal
exit /b 0
