@echo off
REM Start the ClamAV daemon (clamd) with the project-managed config file.
setlocal

set "CLAMD=%ProgramFiles%\ClamAV\clamd.exe"
set "CLAMD_CONF=%ProgramFiles%\ClamAV\clamd.conf"

if not exist "%CLAMD%" (
    echo [start_clamav] ClamAV not found. Run scripts\install.bat first.
    exit /b 1
)

"%CLAMD%" --config-file="%CLAMD_CONF%"
endlocal
