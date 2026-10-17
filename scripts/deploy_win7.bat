@echo off
rem deploy_win7.bat - Win7 deployment self-check for the Nuitka standalone build.
rem Place this file next to avengine.exe (inside the .dist folder) and run it.
setlocal
cd /d "%~dp0"

echo ============================================
echo  AvEngine Win7 deployment self-check
echo ============================================
echo.

if not exist "avengine.exe" (
  echo [FAIL] avengine.exe not found in this folder.
  echo        Put deploy_win7.bat next to avengine.exe.
  goto :end
)

echo [1/6] OS version:
ver
echo.

echo [2/6] UCRT check ^(Win7 SP1 needs KB2999226^):
ver | findstr /c:"6.1." >nul && set ISWIN7=1
if defined ISWIN7 (
  if exist "%SystemRoot%\System32\api-ms-win-crt-runtime-l1-1-0.dll" (
    echo   OK: UCRT present
  ) else (
    echo   WARN: UCRT missing. On Win7 SP1 install KB2999226 ^(Universal C Runtime^).
  )
) else (
  echo   SKIP: not detected as Win7; UCRT check applies to Win7 only
)
echo.

echo [3/6] MSVC / Python runtime:
if exist "vcruntime140.dll" (echo   OK: vcruntime140.dll bundled) else (echo   WARN: vcruntime140.dll missing)
if exist "python38.dll"     (echo   OK: python38.dll bundled)     else (echo   WARN: python38.dll missing)
if exist "avengine\_native\avengine_core.dll" (echo   OK: avengine_core.dll present) else (echo   FAIL: avengine_core.dll missing)
echo.

echo [4/6] config.ini:
if exist "config.ini" goto :cfg_ok
if exist "config.ini.example" goto :cfg_make
echo   WARN: neither config.ini nor config.ini.example found
goto :cfg_done
:cfg_ok
echo   OK: config.ini present
goto :cfg_done
:cfg_make
copy /y "config.ini.example" "config.ini" >nul
echo   CREATED: config.ini from example ^(edit base_url/model/api_key to enable AI^)
:cfg_done
echo.

echo [5/6] data folders ^(rules / bina^):
call :ensure_data rules
call :ensure_data bina
echo.

echo [6/6] runtime check:
"avengine.exe" --version
echo --------------------------------------------
"avengine.exe" status
echo.
echo ClamAV on Windows 7:
echo   ClamAV 1.x is not supported on Windows 7. AvEngine talks to clamd over TCP only.
echo   * YARA only (no ClamAV):  scripts\set_clamav.bat -ClamdHost none
echo   * clamd on the LAN:       scripts\set_clamav.bat -ClamdHost ^<ip^>
echo   Then re-run: avengine.exe status
echo.
echo Deployment check finished.
echo   Next: "avengine.exe scan C:\path\to\sample"  or  "avengine.exe" for the menu.

:end
echo.
pause
exit /b 0

:ensure_data
if exist "%~1" (
  echo   OK: %~1 present
  exit /b 0
)
if exist "..\%~1" (
  echo   COPY: ..\%~1  -^>  %~1
  xcopy /e /i /y "..\%~1" "%~1" >nul
  exit /b 0
)
echo   WARN: %~1 not found next to app or in parent folder
echo         Copy the project's %~1 folder here for full functionality
exit /b 0
