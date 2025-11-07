@echo off
REM Check if Docker is ready and app container is running

echo.
echo ========================================
echo Docker Status Check
echo ========================================
echo.

REM Check if Docker daemon is running
docker ps >nul 2>&1
IF %ERRORLEVEL% NEQ 0 (
    echo [ERROR] Docker Desktop is not running
    echo.
    echo Please start Docker Desktop:
    echo 1. Open Docker Desktop from Start Menu
    echo 2. Wait for green icon in system tray
    echo 3. Run this script again
    echo.
    pause
    exit /b 1
)

echo [OK] Docker Desktop is running
echo.

REM Check if Fashion Hub app container is running
docker ps | findstr fashionhub-app >nul
IF %ERRORLEVEL% NEQ 0 (
    echo [INFO] Fashion Hub app is NOT running
    echo.
    echo To start the app:
    echo   start-fashionhub-app.bat
    echo.
) ELSE (
    echo [OK] Fashion Hub app is running
    echo.
    
    REM Show container details
    echo Container Details:
    docker ps --filter "name=fashionhub-app" --format "  Name: {{.Names}}\n  Status: {{.Status}}\n  Ports: {{.Ports}}"
    echo.
    
    REM Test if app responds
    echo Testing app connection...
    curl -s -o nul -w "  HTTP Status: %%{http_code}\n" http://localhost:3000
    echo.
    
    echo App URL: http://localhost:3000
    echo.
)

echo ========================================
echo Docker Resources:
echo ========================================
docker stats --no-stream --format "  Container: {{.Name}}\n  CPU: {{.CPUPerc}}\n  RAM: {{.MemUsage}}"
echo.

pause
