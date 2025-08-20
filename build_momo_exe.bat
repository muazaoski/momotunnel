@echo off
setlocal ENABLEDELAYEDEXPANSION
cd /d "%~dp0"

echo === Momo Tunnel - Build EXE ===
echo.

REM Ensure Python and pip
where py >nul 2>&1 || where python >nul 2>&1
if errorlevel 1 (
  echo Python not found. Please install Python 3.10+ and re-run.
  pause
  exit /b 1
)

REM Use py if available, else python
set PY=py -3
%PY% -V >nul 2>&1 || set PY=python

echo Installing/Updating build dependencies...
%PY% -m pip install --upgrade pip setuptools wheel >nul
%PY% -m pip install -r requirements.txt pyinstaller pypiwin32 >nul

REM Prefer 256x icon, then fallback chain
set ICON=%USERPROFILE%\Downloads\iconmomotunnel256.ico
set ICONARG=
if exist "%ICON%" (
  set ICONARG=--icon "%ICON%"
) else (
  echo Icon file not found at %ICON% ^(trying iconmomotunnel48.ico^)
  set ICON=%USERPROFILE%\Downloads\iconmomotunnel48.ico
  if exist "%ICON%" (
    set ICONARG=--icon "%ICON%"
  ) else (
    echo Icon 48 not found. Trying iconmomotunnel2.ico
    set ICON=%USERPROFILE%\Downloads\iconmomotunnel2.ico
    if exist "%ICON%" (
      set ICONARG=--icon "%ICON%"
    ) else (
      echo Trying iconmomotunnel.ico
      set ICON=%USERPROFILE%\Downloads\iconmomotunnel.ico
      if exist "%ICON%" (
        set ICONARG=--icon "%ICON%"
      ) else (
        echo No custom icon found. Using default icon.
      )
    )
  )
)

echo Cleaning previous build artifacts...
if exist build rmdir /s /q build
if exist dist rmdir /s /q dist

echo Running PyInstaller...
%PY% -m PyInstaller --clean --noconfirm --noconsole --onefile ^
  --name "Momo Tunnel" ^
  %ICONARG% ^
  "c:\Users\muaz\Downloads\npv_tunnel_pc.py"

echo.
echo Build complete. Check the dist\ folder for Momo Tunnel.exe
pause


