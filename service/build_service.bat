@echo off
REM build_service.bat - build the AvEngine privileged helper service (MSVC)
REM
REM Uses cl.exe from PATH (VS Developer Command Prompt) or locates VS via vswhere and
REM calls vcvars64.bat. Links the CRT statically (/MT) so the service needs no VC++ runtime.
REM Output: service\bin\AvEnginePrivSvc.exe
setlocal EnableExtensions
set "ROOT=%~dp0.."
set "SRC=%ROOT%\service\AvEnginePrivSvc.cpp"
set "OUTDIR=%ROOT%\service\bin"
set "OUT=%OUTDIR%\AvEnginePrivSvc.exe"

if not exist "%SRC%" (
    echo [service] source not found: %SRC%
    exit /b 1
)
if not exist "%OUTDIR%" mkdir "%OUTDIR%" >nul 2>nul

set "CL_ARGS=/nologo /std:c++17 /O2 /W4 /MT /EHsc /utf-8 /DUNICODE /D_UNICODE /D_WIN32_WINNT=0x0601"
set "LINK_LIBS=advapi32.lib crypt32.lib wintrust.lib userenv.lib wtsapi32.lib shell32.lib ole32.lib"

REM cl.exe can sit in PATH without the VS environment (no INCLUDE/LIB) - trust it only
REM when INCLUDE is already set, otherwise initialize the environment via vcvars64.bat.
set "HAVE_VS_ENV="
if defined INCLUDE set "HAVE_VS_ENV=1"
if defined HAVE_VS_ENV (
    where cl >nul 2>nul
    if not errorlevel 1 (
        echo [service] compiler: cl in PATH with VS environment
        cl %CL_ARGS% "%SRC%" /Fe:"%OUT%" /Fo:"%OUTDIR%\\" /link %LINK_LIBS%
        if errorlevel 1 goto :fail
        goto :ok
    )
)

set "VSWHERE=%ProgramFiles(x86)%\Microsoft Visual Studio\Installer\vswhere.exe"
if not exist "%VSWHERE%" (
    echo [service] vswhere not found. Visual Studio with C++ tools is required to build the service.
    echo [service] Run this from a "Developer Command Prompt for VS", or install VS Build Tools.
    exit /b 1
)

for /f "usebackq delims=" %%i in (`"%VSWHERE%" -latest -products * -requires Microsoft.VisualStudio.Component.VC.Tools.x86.x64 -property installationPath`) do (
    if exist "%%i\VC\Auxiliary\Build\vcvars64.bat" (
        echo [service] using VS at %%i
        call "%%i\VC\Auxiliary\Build\vcvars64.bat" >nul 2>nul
        cl %CL_ARGS% "%SRC%" /Fe:"%OUT%" /Fo:"%OUTDIR%\\" /link %LINK_LIBS%
        if errorlevel 1 goto :fail
        goto :ok
    )
)

echo [service] no usable cl.exe / vcvars64.bat found.
exit /b 1

:ok
echo [service] OK: %OUT%
if not exist "%ROOT%\service\generated\cert_pin.h" (
    echo [service] NOTE: service\generated\cert_pin.h is missing - no certificate pin is
    echo [service]       compiled in, so the service will DENY every request.
    echo [service]       Run scripts\gen_signing_cert.ps1 once, then rebuild.
)
exit /b 0

:fail
echo [service] compilation failed
exit /b 1
