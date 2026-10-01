@echo off
:: ==============================================================================
:: SURFACEGUARD OS ARCHITECT - BUILD WINDOWS STANDALONE .EXE
:: Compiles the React + Electron project into a native Windows executable installer!
:: ===============================================================================

title Build Windows .exe - SurfaceGuard Architect
color 0A
cls

echo ==============================================================================
echo    SURFACEGUARD - NATIVE WINDOWS .EXE BUILD AUTOMATOR
echo ==============================================================================
echo.
echo [*] Step 1/2: Building production React static assets...
call npm run build

echo.
echo [*] Step 2/2: Packaging Windows Native .exe executable...
call npx electron-builder --win --x64

echo.
echo ==============================================================================
echo [✓] SUCCESS! Your Windows Application .exe has been generated in:
echo     \dist-electron\SurfaceGuard Setup.exe
echo ==============================================================================
pause
