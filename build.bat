@echo off
rem build.bat - Full build: C++ core -> Nuitka standalone -> releases\AvEngine-<ver>
rem
rem Usage:
rem   build.bat                     build everything, assemble the release, smoke test
rem   set NUITKA_COMPILER=clang     (then run) Nuitka compiler: msvc (default) | clang | mingw64
rem
rem Steps:
rem   [1/5] libyara.a preflight   - only rebuilt through MSYS2 when missing
rem   [2/5] cpp\build.bat         -> third_party\dist\bin\avengine_core.dll
rem   [3/5] scripts\build_nuitka.bat -> dist\avengine_main.dist\avengine.exe (standalone)
rem   [4/5] assemble releases\AvEngine-<ver>\  (app + rules\ + bina\ + scripts\)
rem   [5/5] smoke test avengine.exe --version / status inside the release folder
rem
rem The release folder is self-contained: copy it anywhere and run avengine.exe.
setlocal

set "ROOT=%~dp0"
set "PY=%ROOT%venv\Scripts\python.exe"
if not exist "%PY%" set "PY=python"

set "MSYS2=%MSYS2_ROOT%"
if "%MSYS2%"=="" set "MSYS2=D:\msys64"

rem ---- version, from the pyproject.toml line: version = "0.1.0" ----
set "VERSION=0.1.0"
for /f "tokens=3" %%v in ('findstr /b /c:"version = " "%ROOT%pyproject.toml"') do set "VERSION=%%v"
set "VERSION=%VERSION:"=%"

set "DIST=%ROOT%dist\avengine_main.dist"
set "REL=%ROOT%releases\AvEngine-%VERSION%"
set "LIBYARA=%ROOT%third_party\dist\lib\libyara.a"
set "COREDLL=%ROOT%third_party\dist\bin\avengine_core.dll"

echo ============================================================
echo  AvEngine full build   version %VERSION%
echo ============================================================
echo.

rem ================= [1/5] libyara =================
echo [1/5] libyara
if exist "%LIBYARA%" goto :yara_ok
if not exist "%MSYS2%\usr\bin\bash.exe" (
  echo   [ERROR] libyara.a missing and MSYS2 not found at %MSYS2%
  echo           Build it first:  bash cpp/scripts/build_libyara.sh
  goto :fail
)
set "YSH=%ROOT:\=/%cpp/scripts/build_libyara.sh"
set "YSRC=%ROOT:\=/%third_party/src/yara-4.5.4"
set "YOUT=%ROOT:\=/%third_party/dist"
echo   libyara.a missing, rebuilding through MSYS2 ...
"%MSYS2%\usr\bin\bash.exe" -lc "YARA_SRC='%YSRC%' OUT='%YOUT%' bash '%YSH%'"
if errorlevel 1 (
  echo   [ERROR] libyara build failed
  goto :fail
)
if not exist "%LIBYARA%" (
  echo   [ERROR] libyara.a was not produced
  goto :fail
)
:yara_ok
echo   OK: %LIBYARA%
echo.

rem ================= [2/5] C++ core =================
echo [2/5] C++ core  (cpp\build.bat)
call "%ROOT%cpp\build.bat"
if errorlevel 1 (
  echo   [ERROR] C++ core build failed
  goto :fail
)
if not exist "%COREDLL%" (
  echo   [ERROR] expected output missing: %COREDLL%
  goto :fail
)
echo   OK: %COREDLL%
echo.

rem ================= [3/5] Nuitka standalone =================
echo [3/5] Nuitka standalone  (scripts\build_nuitka.bat)
call "%ROOT%scripts\build_nuitka.bat"
if errorlevel 1 (
  echo   [ERROR] Nuitka build failed
  goto :fail
)
if not exist "%DIST%\avengine.exe" (
  echo   [ERROR] expected output missing: %DIST%\avengine.exe
  goto :fail
)
echo   OK: %DIST%\avengine.exe
echo.

rem ================= [4/5] assemble release =================
echo [4/5] assembling %REL%
if exist "%REL%" rmdir /s /q "%REL%"
mkdir "%REL%" >nul 2>nul
if not exist "%REL%" (
  echo   [ERROR] cannot create %REL%
  goto :fail
)

xcopy /e /i /y /q "%DIST%\*" "%REL%\" >nul
if errorlevel 1 (
  echo   [ERROR] copying the Nuitka output failed
  goto :fail
)

rem never ship local state or secrets: the app and deploy_win7.bat
rem recreate them from the bundled examples on first run
if exist "%REL%\config.ini"  del /f /q "%REL%\config.ini"
if exist "%REL%\config.yaml" del /f /q "%REL%\config.yaml"
if exist "%REL%\logs"        rmdir /s /q "%REL%\logs"
if exist "%REL%\quarantine"  rmdir /s /q "%REL%\quarantine"

xcopy /e /i /y /q "%ROOT%rules\*" "%REL%\rules\" >nul
if errorlevel 1 (
  echo   [ERROR] copying rules\ failed
  goto :fail
)
xcopy /e /i /y /q "%ROOT%bina\*" "%REL%\bina\" >nul
if errorlevel 1 (
  echo   [ERROR] copying bina\ failed  ^(Sysmon / ClamAV installer^)
  goto :fail
)
xcopy /e /i /y /q "%ROOT%scripts\*" "%REL%\scripts\" >nul
if errorlevel 1 (
  echo   [ERROR] copying scripts\ failed
  goto :fail
)

rem build helpers are not part of a deployable copy;
rem deploy_win7.bat stays in the release root, bundled by build_nuitka.bat
del /f /q "%REL%\scripts\build_nuitka.bat"    >nul 2>nul
del /f /q "%REL%\scripts\build_installer.bat" >nul 2>nul
del /f /q "%REL%\scripts\deploy_win7.bat"     >nul 2>nul
copy /y "%ROOT%README.md" "%REL%\README.md" >nul
echo.

rem ================= [5/5] smoke test =================
echo [5/5] smoke test inside the release folder
pushd "%REL%" >nul 2>nul
if errorlevel 1 (
  echo   [ERROR] cannot enter %REL%
  goto :fail
)

echo   --- avengine.exe --version ---
"avengine.exe" --version
if errorlevel 1 (
  popd
  echo   [ERROR] avengine.exe --version failed
  goto :fail
)

echo   --- avengine.exe status ---
"avengine.exe" status
if errorlevel 1 (
  popd
  echo   [ERROR] avengine.exe status failed
  goto :fail
)
popd

rem the smoke run recreated logs\ and config.yaml - drop them again
if exist "%REL%\logs"        rmdir /s /q "%REL%\logs"
if exist "%REL%\quarantine"  rmdir /s /q "%REL%\quarantine"
if exist "%REL%\config.yaml" del /f /q "%REL%\config.yaml"
if exist "%REL%\config.ini"  del /f /q "%REL%\config.ini"

echo.
echo ============================================================
echo  BUILD OK
echo ============================================================
echo  Release folder : %REL%
echo  Run it         : cd into that folder, then  avengine.exe status
echo  Win7 deploy    : double-click  deploy_win7.bat  in that folder
echo  Sysmon / ClamAV: run  scripts\install.bat  as Administrator
echo  AI             : copy config.ini.example to config.ini, set api_key
echo ============================================================
exit /b 0

:fail
echo.
echo ============================================================
echo  BUILD FAILED  - see the message above
echo ============================================================
exit /b 1
