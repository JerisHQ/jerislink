@echo off
setlocal
set "TARGET=%LOCALAPPDATA%\Programs\Jeris\Jerislink"
del /q "%USERPROFILE%\Desktop\Jerislink.lnk" 2>nul
del /q "%APPDATA%\Microsoft\Windows\Start Menu\Programs\Jerislink.lnk" 2>nul
del /q "%APPDATA%\Microsoft\Windows\Start Menu\Programs\Uninstall Jerislink.lnk" 2>nul
reg delete "HKCU\Software\Microsoft\Windows\CurrentVersion\Uninstall\Jerislink" /f >nul 2>nul
start "" cmd.exe /c "timeout /t 1 /nobreak >nul & rmdir /s /q \"%TARGET%\""
exit /b 0
