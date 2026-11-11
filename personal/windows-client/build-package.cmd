@echo off
setlocal
cd /d "%~dp0"

set "ROOT=%~dp0"
set "PAYLOAD=%ROOT%setup_payload"
set "DIST=%ROOT%dist"
set "SETUP=%DIST%\Jerislink-0.0.9.5-windows-x64-setup.exe"
set "LOG=%ROOT%build-v0.0.9.5.log"

if not exist "%PAYLOAD%" mkdir "%PAYLOAD%"
if not exist "%DIST%" mkdir "%DIST%"

>"%LOG%" echo Jerislink v0.0.9.5 build log
>>"%LOG%" echo Started: %DATE% %TIME%
>>"%LOG%" echo.

echo [1/5] Configuring Jerislink...
>>"%LOG%" echo [1/5] Configuring Jerislink...
"C:\Program Files\CMake\bin\cmake.exe" -S . -B build -A x64 >>"%LOG%" 2>&1
if errorlevel 1 goto :fail

echo [2/5] Building Jerislink application...
>>"%LOG%" echo [2/5] Building Jerislink application...
"C:\Program Files\CMake\bin\cmake.exe" --build build --config Release --target Jerislink >>"%LOG%" 2>&1
if errorlevel 1 goto :fail

echo [3/5] Embedding installer payload...
copy /Y "build\Release\Jerislink.exe" "%PAYLOAD%\Jerislink.exe" >nul
if errorlevel 1 goto :fail
copy /Y "README-Windows.txt" "%PAYLOAD%\README.txt" >nul
if errorlevel 1 goto :fail
copy /Y "uninstall.cmd" "%PAYLOAD%\uninstall.cmd" >nul
if errorlevel 1 goto :fail

echo [4/5] Building self-contained Jerislink Setup...
>>"%LOG%" echo [4/5] Building self-contained Jerislink Setup...
"C:\Program Files\CMake\bin\cmake.exe" --build build --config Release --target JerislinkSetup >>"%LOG%" 2>&1
if errorlevel 1 goto :fail

echo [5/5] Publishing setup package...
copy /Y "build\Release\JerislinkSetup.exe" "%SETUP%" >nul
if errorlevel 1 goto :fail
if not exist "%SETUP%" goto :fail

echo.
echo BUILD OK
echo Setup: %SETUP%
echo Log: %LOG%
>>"%LOG%" echo.
>>"%LOG%" echo BUILD OK
>>"%LOG%" echo Finished: %DATE% %TIME%
pause
exit /b 0

:fail
echo.
echo BUILD FAILED
echo Log: %LOG%
>>"%LOG%" echo.
>>"%LOG%" echo BUILD FAILED
>>"%LOG%" echo Finished: %DATE% %TIME%
type "%LOG%"
pause
exit /b 1
