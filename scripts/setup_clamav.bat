@echo off
rem ---------------------------------------------------------------------------
rem setup_clamav.bat - install and configure ClamAV **without PowerShell**.
rem
rem   * picks the installer package by OS version (same rule as
rem     avengine/paths.py clamav_msi(), installer/install.c, install.bat):
rem         Windows 8.1+                    -> bina\clamav.msi        (modern 1.x)
rem         Windows 7 SP1 / Server 2008 R2  -> bina\clamwin7\*.msi    (last Win7 build)
rem   * runs msiexec, writes clamd.conf / freshclam.conf, updates the virus DB,
rem     registers the clamd service the way ClamAV requires, starts it and checks it
rem   * writes the clamav section of config.yaml through the CLI
rem     (`avengine config --clamav-host ...`) - the same comment-preserving Python
rem     writer the GUI uses.
rem
rem Why not PowerShell: Windows 7 SP1 ships PowerShell 2.0, while the previous
rem script used 3.0+ syntax (-notin, Get-ChildItem -File, -Tail, Get-NetTCPConnection).
rem That fails at PARSE time, so the whole install was silently skipped (real report).
rem
rem Usage (Administrator):
rem   scripts\setup_clamav.bat                       install + configure + start
rem   scripts\setup_clamav.bat --print-package       just print the package it would use
rem   scripts\setup_clamav.bat --msi <path.msi>      force a specific package
rem   scripts\setup_clamav.bat --port 3310           TCP port for clamd
rem   scripts\setup_clamav.bat --pause               wait for a key at the end
rem
rem Exit codes: 0 = ok, 1 = failed, 2 = no installer package found.
rem ---------------------------------------------------------------------------
setlocal EnableExtensions EnableDelayedExpansion

set "PORT=3310"
set "MSI="
set "PRINT_ONLY="
set "DO_PAUSE="

rem NOTE: `shift` also shifts %0, which DESTROYS %~dp0 for every later line
rem (verified: after one shift %~dp0 became the first argument's directory).
rem Capture the script directory before parsing any arguments.
set "SCRIPT_DIR=%~dp0"

:parse_args
if "%~1"=="" goto :args_done
if /i "%~1"=="--msi" (
    set "MSI=%~2"
    shift
    shift
    goto :parse_args
)
if /i "%~1"=="--port" (
    set "PORT=%~2"
    shift
    shift
    goto :parse_args
)
if /i "%~1"=="-Port" (
    set "PORT=%~2"
    shift
    shift
    goto :parse_args
)
if /i "%~1"=="--print-package" (
    set "PRINT_ONLY=1"
    shift
    goto :parse_args
)
if /i "%~1"=="/print-package" (
    set "PRINT_ONLY=1"
    shift
    goto :parse_args
)
if /i "%~1"=="--pause" (
    set "DO_PAUSE=1"
    shift
    goto :parse_args
)
if /i "%~1"=="--no-pause" (
    set "DO_PAUSE="
    shift
    goto :parse_args
)
if /i "%~1"=="-NoPause" (
    set "DO_PAUSE="
    shift
    goto :parse_args
)
echo [clamav] ignoring unexpected argument: %~1
shift
goto :parse_args

:args_done
for %%i in ("%SCRIPT_DIR%..") do set "ROOT=%%~fi"

rem ---- 1. OS version and installer package --------------------------------
set "OSVER="
for /f "tokens=4,5 delims=[]. " %%a in ('ver') do if not defined OSVER set "OSVER=%%a.%%b"
if not defined OSVER set "OSVER=unknown"
set "WANTS_LEGACY="
if "%OSVER%"=="6.0" set "WANTS_LEGACY=1"
if "%OSVER%"=="6.1" set "WANTS_LEGACY=1"

if not defined MSI (
    if defined WANTS_LEGACY (
        set "PICK_DIR=%ROOT%\bina\clamwin7"
        set "ALT_DIR=%ROOT%\bina"
    ) else (
        set "PICK_DIR=%ROOT%\bina"
        set "ALT_DIR=%ROOT%\bina\clamwin7"
    )
    rem any *.msi in the version-appropriate directory is accepted (first by name)
    for %%f in ("!PICK_DIR!\*.msi") do if not defined MSI set "MSI=%%~ff"
    if not defined MSI for %%f in ("!ALT_DIR!\*.msi") do if not defined MSI set "MSI=%%~ff"
    if not defined MSI set "MSI=!PICK_DIR!\clamav.msi"
) else (
    rem explicit path: make it absolute (the caller may pass a relative one)
    for %%i in ("%MSI%") do set "MSI=%%~fi"
)

if defined PRINT_ONLY (
    echo %MSI%
    endlocal
    exit /b 0
)

echo [clamav] Windows %OSVER%
if defined WANTS_LEGACY (
    echo [clamav] package: %MSI%  ^(Windows 7/2008 -> legacy build^)
) else (
    echo [clamav] package: %MSI%  ^(modern build^)
)

rem ---- 2. locate ClamAV (Program Files, then Program Files (x86)) ---------
call :find_clamav
if not defined CLAMD_EXE (
    if not exist "%MSI%" (
        echo [clamav] ERROR: installer package not found: %MSI%
        echo [clamav]   modern ^(Win8.1+^): bina\clamav.msi
        echo [clamav]   legacy ^(Win7 SP1^): bina\clamwin7\*.msi
        if defined DO_PAUSE pause
        endlocal
        exit /b 2
    )
    echo [clamav] installing ClamAV ^(msiexec /qn; this can take several minutes^)...
    set "MSI_LOG=%TEMP%\clamav_msi.log"
    msiexec.exe /i "%MSI%" /qn /norestart /l*v "%MSI_LOG%"
    set "MSI_CODE=!ERRORLEVEL!"
    echo [clamav] msiexec exit code: !MSI_CODE!  ^(log: !MSI_LOG!^)
    rem 0=ok, 3010/1641=reboot needed, 1638=another version installed
    if not "!MSI_CODE!"=="0" if not "!MSI_CODE!"=="3010" if not "!MSI_CODE!"=="1641" if not "!MSI_CODE!"=="1638" (
        echo [clamav] WARNING: unusual msiexec exit code - still checking the install dir.
    )
    call :find_clamav
)
if not defined CLAMD_EXE (
    echo [clamav] ERROR: ClamAV install failed - clamd.exe not found in:
    rem Use the pre-expanded !PF_DIR!/!PF86_DIR! - expanding %ProgramFiles(x86)% inside a
    rem parenthesized block breaks cmd's parser ("\ClamAV was unexpected at this time").
    echo [clamav]   !PF_DIR!\ClamAV
    echo [clamav]   !PF86_DIR!\ClamAV
    if exist "%MSI_LOG%" (
        echo [clamav] msiexec log: %MSI_LOG%
        call :tail_log "%MSI_LOG%" 20
    )
    echo [clamav] manual install, then rerun this script: msiexec /i "%MSI%"
    if defined DO_PAUSE pause
    endlocal
    exit /b 1
)
echo [clamav] ClamAV dir: %CLAMAV_DIR%
echo [clamav] clamd: %CLAMD_EXE%

rem ---- 3. freshclam.conf / clamd.conf ------------------------------------
if not exist "%DB_DIR%" mkdir "%DB_DIR%" >nul 2>&1

echo [clamav] writing clamd.conf / freshclam.conf...
if exist "%CLAMD_CONF%" copy /y "%CLAMD_CONF%" "%CLAMD_CONF%.bak" >nul
> "%CLAMD_CONF%" echo TCPSocket %PORT%
>> "%CLAMD_CONF%" echo TCPAddr 127.0.0.1
>> "%CLAMD_CONF%" echo MaxThreads 50
>> "%CLAMD_CONF%" echo LogFile %CLAMD_LOG%
>> "%CLAMD_CONF%" echo LogTime yes
>> "%CLAMD_CONF%" echo DatabaseDirectory %DB_DIR%

if exist "%FRESHCLAM_CONF%" copy /y "%FRESHCLAM_CONF%" "%FRESHCLAM_CONF%.bak" >nul
> "%FRESHCLAM_CONF%" echo DatabaseMirror database.clamav.net
>> "%FRESHCLAM_CONF%" echo DatabaseDirectory %DB_DIR%
>> "%FRESHCLAM_CONF%" echo UpdateLogFile %CLAMAV_DIR%\freshclam.log
>> "%FRESHCLAM_CONF%" echo LogTime yes

rem ---- 4. virus database --------------------------------------------------
if exist "%FRESHCLAM_EXE%" (
    echo [clamav] updating the virus database ^(freshclam^)...
    set "TRY=3"
    :freshclam_loop
    "%FRESHCLAM_EXE%" --quiet
    if "!ERRORLEVEL!"=="0" (
        echo [clamav] freshclam OK
        goto :freshclam_done
    )
    echo [clamav] WARNING: freshclam returned !ERRORLEVEL! ^(network or mirror problem^)
    set /a TRY-=1
    if !TRY! gtr 0 (
        echo [clamav] retrying in 5s ^(!TRY! left^)...
        timeout /t 5 /nobreak >nul
        goto :freshclam_loop
    )
    echo [clamav] WARNING: could not update the database - clamd may fail to start.
    :freshclam_done
) else (
    echo [clamav] WARNING: freshclam.exe not found - download the DB into %DB_DIR% manually.
)

set "DB_COUNT=0"
for /f %%c in ('dir /b /a-d "%DB_DIR%\*.cvd" "%DB_DIR%\*.cld" "%DB_DIR%\*.hdb" "%DB_DIR%\*.hsb" "%DB_DIR%\*.ndb" "%DB_DIR%\*.ldb" 2^>nul ^| find /c /v ""') do set "DB_COUNT=%%c"
if "%DB_COUNT%"=="0" (
    echo [clamav] WARNING: no .cvd/.cld files in %DB_DIR% - clamd will refuse to start.
    echo [clamav]          run: "%FRESHCLAM_EXE%"
) else (
    echo [clamav] database files: %DB_COUNT%
)

rem ---- 5. port owner warning ---------------------------------------------
netstat -ano | findstr /r /c:":%PORT% .*LISTENING" > "%TEMP%\avx_port_%PORT%.txt" 2>nul
if not errorlevel 1 (
    echo [clamav] WARNING: TCP %PORT% is already in use:
    type "%TEMP%\avx_port_%PORT%.txt"
    for /f "tokens=5" %%p in ('findstr /r /c:":%PORT% .*LISTENING" "%TEMP%\avx_port_%PORT%.txt"') do (
        tasklist /fi "PID eq %%p" /fo csv /nh 2>nul | findstr /i /c:"clamd" >nul && (
            echo [clamav] stopping the foreground clamd.exe ^(PID %%p^) - the service needs the port
            taskkill /f /pid %%p >nul 2>&1
        )
    )
)
del "%TEMP%\avx_port_%PORT%.txt" >nul 2>&1

rem ---- 6. register the clamd service -------------------------------------
echo [clamav] configuring the clamd service...
sc query clamd >nul 2>&1
if not errorlevel 1 (
    sc stop clamd >nul 2>&1
    set "WAIT=0"
    :svc_stop_wait
    sc query clamd | findstr /i "STOPPED" >nul
    if errorlevel 1 (
        set /a WAIT+=1
        if !WAIT! lss 10 (
            timeout /t 1 /nobreak >nul
            goto :svc_stop_wait
        )
    )
    sc delete clamd >nul 2>&1
    set "WAIT=0"
    :svc_del_wait
    sc query clamd >nul 2>&1
    if not errorlevel 1 (
        set /a WAIT+=1
        if !WAIT! lss 10 (
            timeout /t 1 /nobreak >nul
            goto :svc_del_wait
        )
    )
)

rem ClamAV's official way: the ImagePath becomes "<clamd.exe>" --daemon --service-mode
"%CLAMD_EXE%" --install-service >nul 2>&1
sc query clamd >nul 2>&1
if errorlevel 1 (
    echo [clamav] --install-service did not register it; using the equivalent sc create...
    rem --daemon registers with the SCM, --service-mode reports SERVICE_RUNNING after the DB loads.
    rem Without them: "net start clamd" fails with 1053 while clamd.exe runs fine by hand.
    sc create clamd binPath= "\"%CLAMD_EXE%\" --daemon --service-mode --config-file=\"%CLAMD_CONF%\"" start= auto DisplayName= "ClamAV ClamD" >nul
)
sc config clamd start= auto >nul 2>&1
sc query clamd >nul 2>&1
if errorlevel 1 (
    echo [clamav] ERROR: could not register the clamd service.
    echo [clamav]   run this script as Administrator, or register it by hand:
    echo [clamav]   sc create clamd binPath= "\"%CLAMD_EXE%\" --daemon --service-mode" start= auto
    if defined DO_PAUSE pause
    endlocal
    exit /b 1
)

rem ---- 7. point AvEngine at this clamd (config.yaml via the CLI) ----------
set "AVENGINE_QUIET=1"
call "%SCRIPT_DIR%lib_avengine.bat"
if defined AVENGINE (
    echo [clamav] writing config.yaml ^(clamav.host=127.0.0.1, port=%PORT%^)...
    %AVENGINE% config --clamav-host 127.0.0.1 --clamav-port %PORT%
    if not "!ERRORLEVEL!"=="0" (
        echo [clamav] WARNING: could not update config.yaml - set it by hand:
        echo [clamav]   scripts\set_clamav.bat -ClamdHost 127.0.0.1 -Port %PORT%
    )
) else (
    echo [clamav] WARNING: no avengine CLI found - set config.yaml by hand:
    echo [clamav]   clamav:  host: "127.0.0.1"   port: %PORT%
)

rem ---- 8. start it and verify -------------------------------------------
echo [clamav] starting the clamd service...
sc start clamd >nul 2>&1
set "WAIT=0"
:srv_start_wait
sc query clamd | findstr /i "RUNNING" >nul
if not errorlevel 1 goto :srv_running
set /a WAIT+=1
if !WAIT! lss 15 (
    timeout /t 2 /nobreak >nul
    goto :srv_start_wait
)

echo [clamav] ERROR: clamd did not reach RUNNING within 30s.
sc query clamd
echo [clamav] service config:
sc qc clamd
call :tail_log "%CLAMD_LOG%" 20
echo [clamav] hints:
echo [clamav]   * no virus database?  run "%FRESHCLAM_EXE%"
echo [clamav]   * port %PORT% busy?   stop the other clamd first
echo [clamav]   * run it in the foreground to see the error:
echo [clamav]     cd /d "%CLAMAV_DIR%" ^&^& clamd.exe --foreground --debug
if defined DO_PAUSE pause
endlocal
exit /b 1

:srv_running
echo [clamav] OK: clamd service is RUNNING on 127.0.0.1:%PORT%
echo [clamav] verify with:  avengine status
if defined DO_PAUSE pause
endlocal
exit /b 0

rem ------------------------------------------------------------------ helpers
:find_clamav
set "CLAMAV_DIR="
set "CLAMD_EXE="
set "CLAMD_CONF="
set "CLAMD_LOG="
set "FRESHCLAM_EXE="
set "FRESHCLAM_CONF="
set "DB_DIR="
rem %ProgramFiles(x86)% contains parentheses; expanding it inside a parenthesized
rem block breaks cmd's parser ("\ClamAV was unexpected at this time" - real report).
rem So the two directories are resolved once, here, and used as !PF_DIR!/!PF86_DIR!.
if not defined PF_DIR set "PF_DIR=%ProgramFiles%"
if not defined PF86_DIR set "PF86_DIR=%ProgramFiles(x86)%"
if not defined PF86_DIR set "PF86_DIR=%ProgramFiles%"
if not exist "!PF_DIR!\ClamAV\clamd.exe" if not exist "!PF86_DIR!\ClamAV\clamd.exe" goto :fc_no_exe
if exist "!PF_DIR!\ClamAV\clamd.exe" goto :fc_use_pf
set "CLAMAV_DIR=!PF86_DIR!\ClamAV"
goto :fc_dirs
:fc_use_pf
set "CLAMAV_DIR=!PF_DIR!\ClamAV"
goto :fc_dirs
:fc_no_exe
rem no clamd.exe yet (not installed): pick whichever ClamAV dir exists, else the native one
if exist "!PF_DIR!\ClamAV\" set "CLAMAV_DIR=!PF_DIR!\ClamAV"
if not defined CLAMAV_DIR if exist "!PF86_DIR!\ClamAV\" set "CLAMAV_DIR=!PF86_DIR!\ClamAV"
if not defined CLAMAV_DIR set "CLAMAV_DIR=!PF_DIR!\ClamAV"
:fc_dirs
if defined CLAMAV_DIR (
    if exist "!CLAMAV_DIR!\clamd.exe" set "CLAMD_EXE=!CLAMAV_DIR!\clamd.exe"
    set "CLAMD_CONF=!CLAMAV_DIR!\clamd.conf"
    set "CLAMD_LOG=!CLAMAV_DIR!\clamd.log"
    set "FRESHCLAM_EXE=!CLAMAV_DIR!\freshclam.exe"
    set "FRESHCLAM_CONF=!CLAMAV_DIR!\freshclam.conf"
    set "DB_DIR=!CLAMAV_DIR!\db"
)
exit /b 0

:tail_log
rem %1 = file, %2 = number of trailing lines (pure batch: find /c + more +N)
set "TAIL_FILE=%~1"
set "TAIL_N=%~2"
if not exist "%TAIL_FILE%" exit /b 0
set "TAIL_TOTAL="
for /f "delims=" %%L in ('find /c /v "" ^< "%TAIL_FILE%"') do set "TAIL_TOTAL=%%L"
if not defined TAIL_TOTAL exit /b 0
set /a TAIL_SKIP=TAIL_TOTAL-TAIL_N
if %TAIL_SKIP% lss 0 set "TAIL_SKIP=0"
echo     --- %TAIL_FILE% (last %TAIL_N% of %TAIL_TOTAL% lines) ---
more +%TAIL_SKIP% "%TAIL_FILE%"
exit /b 0
