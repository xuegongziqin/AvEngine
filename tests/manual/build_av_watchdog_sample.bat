@echo off
REM Build the AV behavior test sample (tests\manual\av_watchdog_sample.cpp).
REM Try MinGW g++ first, then MSVC cl.
setlocal

set "SRC=%~dp0av_watchdog_sample.cpp"
set "OUT=%~dp0av_watchdog_sample.exe"

if not exist "%SRC%" (
    echo [build] source not found: %SRC%
    exit /b 1
)

where g++ >nul 2>nul
if not errorlevel 1 (
    echo [build] compiler: MinGW g++
    g++ -O2 -Wall -Wextra -municode -static -o "%OUT%" "%SRC%"
    if not errorlevel 1 goto :ok
    echo [build] g++ failed, trying cl ...
)

where cl >nul 2>nul
if not errorlevel 1 (
    echo [build] compiler: MSVC cl
    cl /nologo /O2 /EHsc /DUNICODE /D_UNICODE "%SRC%" /link /OUT:"%OUT%"
    if not errorlevel 1 goto :ok
)

echo [build] no usable compiler found (need MSYS2 g++ or a VS developer prompt)
echo         build details are in the header comment of av_watchdog_sample.cpp
exit /b 1

:ok
echo [build] OK: %OUT%
echo [build] usage: av_watchdog_sample.exe --help
exit /b 0
