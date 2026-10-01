@echo off
:: ==============================================================================
:: SURFACEGUARD OS ARCHITECT - 1-CLICK WINDOWS DESKTOP LAUNCHER
:: Double-click this file on Windows to run the application in a dedicated window!
:: ===============================================================================

title SurfaceGuard Architect - Windows Desktop Launcher
color 0B
cls

echo ==============================================================================
echo    SURFACEGUARD OS ARCHITECT - WINDOWS DESKTOP APPLICATION LAUNCHER
echo ==============================================================================
echo.
echo [*] Checking Windows system prerequisites...

:: Check Node.js
where node >nul 2>nul
if %errorlevel% neq 0 (
    echo [!] Node.js is not found on your PC.
    echo [*] Please install Node.js from https://nodejs.org/ to compile and run.
    pause
    exit /b 1
)

echo [✓] Node.js is installed.
echo.
echo [*] Checking node_modules and dependencies...
if not exist "node_modules\" (
    echo [*] Installing dependencies (first run only, please wait)...
    call npm install
)

echo [*] Launching local security workstation server...
start /b cmd /c "npm run dev"

:: Wait 3 seconds for server to start
timeout /t 3 /nobreak >nul

echo [✓] Starting SurfaceGuard in dedicated Windows App Window...

:: Launch in Microsoft Edge App Mode (Built into every Windows 10 and 11 PC)
:: This opens it as a clean standalone desktop app without browser toolbars!
start msedge.exe --app="http://localhost:3000" --new-window --window-size=1440,900

if %errorlevel% neq 0 (
    :: Fallback to default browser if Edge fails
    start http://localhost:3000
)

echo.
echo [✓] SurfaceGuard is now running as a Windows Desktop Application!
echo [*] Keep this window open while using the application.
echo [*] Press Ctrl+C or close this window when done.
pause
