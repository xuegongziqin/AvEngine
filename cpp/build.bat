@echo off
rem build.bat - Build avengine_core.dll with CMake + Ninja + MinGW-w64
rem Requires gcc/g++/cmake/ninja under D:\msys64\mingw64 (override via MSYS2_MINGW)
setlocal

if "%MSYS2_MINGW%"=="" set MSYS2_MINGW=D:\msys64\mingw64\bin
set PATH=%MSYS2_MINGW%;%PATH%

set ROOT=%~dp0
set BUILD=%ROOT%build

cmake -S "%ROOT%." -B "%BUILD%" -G Ninja -DCMAKE_BUILD_TYPE=Release
if errorlevel 1 exit /b 1

cmake --build "%BUILD%"
if errorlevel 1 exit /b 1

echo.
echo Build complete: third_party\dist\bin\avengine_core.dll
