@echo off
echo ================================================
echo   AI SENTINEL - Hardware Power Malware Detection
echo ================================================
echo.

REM Check if Python is available
python --version >nul 2>&1
if %errorlevel% neq 0 (
    echo [ERROR] Python not found. Please install Python 3.8+
    echo Download: https://www.python.org/downloads/
    pause
    exit /b 1
)

REM Try to install dependencies
echo [INFO] Checking dependencies...
pip install websockets aiohttp numpy --quiet >nul 2>&1

REM Check if backend should start
if "%1"=="backend" goto start_backend

:menu
cls
echo ================================================
echo   AI SENTINEL - Main Menu
echo ================================================
echo.
echo  1. Start Frontend Only (Simulation Mode)
echo  2. Start Backend + Frontend (Full System)
echo  3. Install Dependencies
echo  4. Exit
echo.
set /p choice="Select option (1-4): "

if "%choice%"=="1" goto start_frontend
if "%choice%"=="2" goto start_full
if "%choice%"=="3" goto install_deps
if "%choice%"=="4" exit /b 0

goto menu

:start_frontend
echo.
echo [INFO] Starting frontend in simulation mode...
echo [INFO] Opening browser...
start "" "frontend\index.html"
goto done

:start_backend
echo.
echo [INFO] Starting backend server...
cd /d "%~dp0"
start cmd /k "cd backend ^&^& python sensor.py"
timeout /t 2 >nul
goto :eof

:start_full
echo.
echo [INFO] Starting backend server...
start cmd /k "cd /d %~dp0 ^&^& cd backend ^&^& python sensor.py"
timeout /t 3 >nul

echo [INFO] Starting frontend...
start "" "frontend\index.html"
goto done

:install_deps
echo.
echo [INFO] Installing dependencies...
pip install websockets aiohttp numpy
if %errorlevel% equ 0 (
    echo [SUCCESS] Dependencies installed!
) else (
    echo [ERROR] Failed to install dependencies
)
pause
goto menu

:done
echo.
echo ================================================
echo   AI SENTINEL is running!
echo.
echo   Frontend: http://localhost:8765 (after backend starts)
echo   Backend:  ws://localhost:8765
echo.
echo   NOTE: Run this script as Administrator for 
echo         real hardware power monitoring.
echo ================================================
pause
