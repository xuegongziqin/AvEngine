@echo off
rem ---------------------------------------------------------------------------
rem lib_avengine.bat - find a way to run the avengine CLI, for other .bat files.
rem
rem Usage:   call "%~dp0lib_avengine.bat"
rem Sets:    AVENGINE       command prefix, e.g. "C:\AvEngine\avengine.exe"
rem          AVENGINE_KIND  release | venv | path | (empty = not found)
rem
rem NOTE: there is deliberately NO setlocal here - the variables must survive in
rem the caller's scope, which is the whole point of a batch "library".
rem
rem Why this exists: the ClamAV setup path must not depend on Windows PowerShell.
rem Windows 7 SP1 ships PowerShell 2.0 while the scripts used 3.0+ syntax, which
rem fails at PARSE time and silently skipped the whole install. config.yaml is now
rem written by the CLI itself (avengine config --clamav-host ...), i.e. by the same
rem Python code the GUI uses.
rem ---------------------------------------------------------------------------
set "AVENGINE="
set "AVENGINE_KIND="
set "AVENGINE_ROOT=%~dp0.."

if exist "%AVENGINE_ROOT%\avengine.exe" (
    set "AVENGINE="%AVENGINE_ROOT%\avengine.exe""
    set "AVENGINE_KIND=release"
    goto :lib_avengine_done
)

if exist "%AVENGINE_ROOT%\venv\Scripts\python.exe" (
    set "AVENGINE="%AVENGINE_ROOT%\venv\Scripts\python.exe" -m avengine"
    set "AVENGINE_KIND=venv"
    goto :lib_avengine_done
)

for %%p in (python.exe) do if not defined AVENGINE if not "%%~$PATH:p"=="" (
    set "AVENGINE=python -m avengine"
    set "AVENGINE_KIND=path"
)

:lib_avengine_done
if defined AVENGINE (
    if /i not "%AVENGINE_QUIET%"=="1" echo [avengine] CLI: %AVENGINE_KIND% -^> %AVENGINE%
) else (
    echo [avengine] ERROR: no avengine CLI found ^(looked for avengine.exe, venv\Scripts\python.exe, python on PATH^).
    echo [avengine]        run this from the release folder, or install Python to edit config.yaml.
)
exit /b 0
