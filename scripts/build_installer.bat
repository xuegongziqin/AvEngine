@echo off
REM Build the one-click installer: installer\AvInstaller.exe
REM Tries MinGW gcc first, then MSVC (cl), then locates Visual Studio via vswhere.
setlocal

set "ROOT=%~dp0.."
set "SRC=%ROOT%\installer\install.c"
set "OUT=%ROOT%\installer\AvInstaller.exe"

if not exist "%SRC%" (
    echo [build] source not found: %SRC%
    exit /b 1
)

where gcc >nul 2>nul
if not errorlevel 1 (
    echo [build] compiler: MinGW gcc
    gcc -O2 -Wall -Wextra -municode -o "%OUT%" "%SRC%" -ladvapi32
    if errorlevel 1 goto :fail
    goto :ok
)

where cl >nul 2>nul
if not errorlevel 1 (
    echo [build] compiler: MSVC cl
    cl /nologo /O2 /W4 /DUNICODE /D_UNICODE "%SRC%" /link /OUT:"%OUT%" advapi32.lib
    if errorlevel 1 goto :fail
    goto :ok
)

set "VSWHERE=%ProgramFiles(x86)%\Microsoft Visual Studio\Installer\vswhere.exe"
if exist "%VSWHERE%" (
    echo [build] locating Visual Studio with vswhere...
    for /f "usebackq delims=" %%i in (`"%VSWHERE%" -latest -products * -requires Microsoft.VisualStudio.Component.VC.Tools.x86.x64 -property installationPath`) do (
        call "%%i\VC\Auxiliary\Build\vcvars64.bat" >nul 2>nul
        cl /nologo /O2 /W4 /DUNICODE /D_UNICODE "%SRC%" /link /OUT:"%OUT%" advapi32.lib
        if not errorlevel 1 goto :ok
    )
)

echo [build] no C compiler found.
echo         Install MSYS2/MinGW-w64, or Visual Studio Build Tools,
echo         or run this from an "x64 Native Tools Command Prompt".
exit /b 1

:ok
echo [build] OK: %OUT%
exit /b 0

:fail
echo [build] compilation failed
exit /b 1
