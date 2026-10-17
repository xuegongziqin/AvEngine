@echo off
rem ---------------------------------------------------------------------------
rem set_clamav.bat - point AvEngine at a clamd (local or on the LAN), or disable
rem                  ClamAV entirely (YARA-only). No administrator rights needed.
rem
rem Usage:
rem   scripts\set_clamav.bat -ClamdHost 192.168.1.50        (clamd on the LAN)
rem   scripts\set_clamav.bat -ClamdHost 127.0.0.1 -Port 3310 (local clamd)
rem   scripts\set_clamav.bat -ClamdHost none                (YARA only)
rem   scripts\set_clamav.bat none                           (positional form)
rem
rem It only rewrites the clamav section of config.yaml - via the CLI
rem (`avengine config --clamav-host ...`), which is the same comment-preserving
rem writer the GUI uses. This replaces the old PowerShell version: Windows 7 SP1
rem ships PowerShell 2.0 and the script used 3.0+ syntax, which failed at parse
rem time and left the config untouched.
rem
rem Exit codes: 0 = updated, 1 = failed, 2 = no avengine CLI found.
rem ---------------------------------------------------------------------------
setlocal EnableExtensions

set "CLAMHOST="
set "CLAMPORT="

rem NOTE: `shift` also shifts %0, which DESTROYS %~dp0 for every later line
rem (verified: after one shift %~dp0 became the first argument's directory).
rem Capture the script directory before parsing any arguments.
set "SCRIPT_DIR=%~dp0"

:parse_args
if "%~1"=="" goto :args_done
if /i "%~1"=="-ClamdHost" (
    set "CLAMHOST=%~2"
    shift
    shift
    goto :parse_args
)
if /i "%~1"=="--clamd-host" (
    set "CLAMHOST=%~2"
    shift
    shift
    goto :parse_args
)
if /i "%~1"=="-Port" (
    set "CLAMPORT=%~2"
    shift
    shift
    goto :parse_args
)
if /i "%~1"=="--port" (
    set "CLAMPORT=%~2"
    shift
    shift
    goto :parse_args
)
if /i "%~1"=="-ConfigYaml" (
    set "AVENGINE_CONFIG=%~2"
    shift
    shift
    goto :parse_args
)
if not defined CLAMHOST (
    set "CLAMHOST=%~1"
    shift
    goto :parse_args
)
echo [set_clamav] ignoring unexpected argument: %~1
shift
goto :parse_args

:args_done
if not defined CLAMHOST (
    echo [set_clamav] Usage: set_clamav.bat -ClamdHost ^<ip^|none^> [-Port 3310]
    endlocal
    exit /b 1
)

set "AVENGINE_QUIET=1"
call "%SCRIPT_DIR%lib_avengine.bat"
if not defined AVENGINE (
    endlocal
    exit /b 2
)

set "ARGS=config --clamav-host "%CLAMHOST%""
if defined CLAMPORT set "ARGS=%ARGS% --clamav-port %CLAMPORT%"
if defined AVENGINE_CONFIG (
    %AVENGINE% -c "%AVENGINE_CONFIG%" %ARGS%
) else (
    %AVENGINE% %ARGS%
)
set "CODE=%ERRORLEVEL%"
if not "%CODE%"=="0" echo [set_clamav] failed ^(exit %CODE%^) - see the message above.
endlocal & exit /b %CODE%
