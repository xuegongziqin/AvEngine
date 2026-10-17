@echo off
REM install_privsvc.bat - install and start the AvEngine privileged helper service.
REM Must run elevated (Administrator): it registers a LocalSystem service and writes HKLM.
setlocal EnableExtensions
set "ROOT=%~dp0.."
set "EXE="
if exist "%ROOT%\service\AvEnginePrivSvc.exe" set "EXE=%ROOT%\service\AvEnginePrivSvc.exe"
if not defined EXE if exist "%ROOT%\service\bin\AvEnginePrivSvc.exe" set "EXE=%ROOT%\service\bin\AvEnginePrivSvc.exe"
if not defined EXE (
    echo [privsvc] AvEnginePrivSvc.exe not found.
    echo [privsvc] Build it first:  service\build_service.bat
    exit /b 1
)

net session >nul 2>nul
if errorlevel 1 (
    echo [privsvc] Administrator rights are required.
    echo [privsvc] Right-click this file and choose "Run as administrator".
    exit /b 1
)

echo [privsvc] service binary: %EXE%
"%EXE%" --check-pin
if errorlevel 2 (
    echo.
    echo [privsvc] WARNING: no certificate pin is configured - the service will DENY every request.
    echo [privsvc] One-time setup:
    echo [privsvc]   1^) powershell -ExecutionPolicy Bypass -File scripts\gen_signing_cert.ps1
    echo [privsvc]   2^) service\build_service.bat          ^(pin is compiled in^)
    echo [privsvc]   3^) re-run this script
    echo.
)

"%EXE%" --install
if errorlevel 1 (
    echo [privsvc] install failed
    exit /b 1
)
sc start AvEnginePrivSvc >nul 2>nul
"%EXE%" --status

echo.
echo [privsvc] Next steps:
echo [privsvc]   * avengine.exe service status     (check pin / installation)
echo [privsvc]   * avengine.exe service ping       (verify this shell passes the gate)
echo [privsvc]   * avengine.exe run-system -- status
echo [privsvc] Note: the caller must be the SIGNED avengine.exe inside the install folder
echo [privsvc]       and must already be running as Administrator.
exit /b 0
