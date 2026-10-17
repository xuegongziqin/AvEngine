@echo off
rem build_nuitka.bat - Build AvEngine as a Nuitka standalone distribution (NOT onefile).
rem
rem Compiler selection (set NUITKA_COMPILER before running):
rem   msvc    - MSVC (default; Nuitka refuses the system MinGW g++ and would
rem             download its own winlibs MinGW, so MSVC is used unless overridden)
rem   clang   - Clang (requires a standalone clang/clang-cl on PATH)
rem   mingw64 - Nuitka's own winlibs MinGW64 (downloads ~130MB if not cached)
rem
rem Prereq: cpp\build.bat must have produced third_party\dist\bin\avengine_core.dll
rem
rem Two options below exist for the GUI (see README section 16):
rem   --enable-plugin=tk-inter       without it the packaged exe cannot use tkinter at all
rem   --windows-console-mode=attach  double-click -> no black console window (GUI only);
rem                                  run from cmd   -> output still goes to that console.
rem   Do NOT use "disable"/"hide": they also kill stdout/stderr, so the CLI
rem   (avengine.exe status / scan / ai ...) would print nothing at all.
setlocal

set ROOT=%~dp0..
set PY=%ROOT%\venv\Scripts\python.exe
if not exist "%PY%" set PY=python

set COMPILER=%NUITKA_COMPILER%
if "%COMPILER%"=="" set COMPILER=msvc

set COMPFLAG=--msvc=latest
if /I "%COMPILER%"=="mingw64" set COMPFLAG=--mingw64
if /I "%COMPILER%"=="clang" set COMPFLAG=--clang

set DLL=%ROOT%\third_party\dist\bin\avengine_core.dll
if not exist "%DLL%" (
  echo [ERROR] avengine_core.dll not found: %DLL%
  echo         Run cpp\build.bat first.
  exit /b 1
)

echo [Nuitka] compiler=%COMPILER%
"%PY%" -m nuitka ^
  --standalone ^
  --enable-plugin=tk-inter ^
  --windows-console-mode=attach ^
  %COMPFLAG% ^
  --assume-yes-for-downloads ^
  --show-memory ^
  --verbose ^
  --include-package=avengine ^
  --include-data-files="%DLL%=avengine/_native/avengine_core.dll" ^
  --include-data-files="%ROOT%\config.example.yaml=config.example.yaml" ^
  --include-data-files="%ROOT%\config.ini.example=config.ini.example" ^
  --output-dir="%ROOT%\dist" ^
  --output-filename=avengine.exe ^
  --company-name=AntierX ^
  --product-name=AvEngine ^
  --file-version=0.1.0 ^
  --product-version=0.1.0 ^
  "%ROOT%\avengine_main.py"

if errorlevel 1 (
  echo [Nuitka] build FAILED
  exit /b 1
)

rem Ship the Win7 deployment self-check inside the distribution folder.
copy /y "%ROOT%\scripts\deploy_win7.bat" "%ROOT%\dist\avengine_main.dist\deploy_win7.bat" >nul

echo.
echo [Nuitka] Build complete: %ROOT%\dist\avengine_main.dist\avengine.exe
