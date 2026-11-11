@echo off
setlocal
cd /d "%~dp0"
echo Building Jerislink 0.0.4 stable CPU renderer...
"C:\Program Files\CMake\bin\cmake.exe" --build build --config Release --target Jerislink
if errorlevel 1 (
  echo.
  echo BUILD FAILED
  pause
  exit /b 1
)
echo.
echo BUILD OK
echo New app: %~dp0build\Release\Jerislink.exe
pause
