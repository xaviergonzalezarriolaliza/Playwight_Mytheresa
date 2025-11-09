@echo off@echo off

REM Check Docker Desktop and Container StatusREM Check if Docker is ready and app container is running



echo ========================================echo.

echo Docker Status Checkerecho ========================================

echo ========================================echo Docker Status Check

echo ========================================

REM Check if Docker Desktop is runningecho.

docker info >nul 2>&1

IF %ERRORLEVEL% NEQ 0 (REM Check if Docker daemon is running

    echo ERROR: Docker Desktop is not running or not installed.docker ps >nul 2>&1

    echo Please start Docker Desktop and try again.IF %ERRORLEVEL% NEQ 0 (

    pause    echo [ERROR] Docker Desktop is not running

    exit /b 1    echo.

)    echo Please start Docker Desktop:

    echo 1. Open Docker Desktop from Start Menu

echo Docker Desktop is running.    echo 2. Wait for green icon in system tray

    echo 3. Run this script again

REM List running containers    echo.

echo.    pause

echo Running Containers:    exit /b 1

docker ps)



echo.echo [OK] Docker Desktop is running

echo To see all containers, use: docker ps -aecho.

echo To see Docker system info, use: docker info

echo ========================================REM Check if Fashion Hub app container is running

pausedocker ps | findstr fashionhub-app >nul

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
