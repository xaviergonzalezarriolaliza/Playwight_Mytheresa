                      @echo off
REM Start Fashion Hub Demo App Docker Container
REM Optimized for: AMD A4-5000 APU, 3.44GB RAM
REM Docker Hub: https://hub.docker.com/r/pocketaces2/fashionhub-demo-app

echo.
echo ========================================
echo Fashion Hub Demo App - Starting...
echo ========================================
echo Docker Image: pocketaces2/fashionhub-demo-app
echo Port: 3000 (http://localhost:3000)
echo Memory Limit: 256MB
echo ========================================
echo.

REM Stop any existing container with the same name
docker stop fashionhub-app 2>nul
docker rm fashionhub-app 2>nul

REM Start the Fashion Hub app container
REM Using minimal resources suitable for 3.44GB RAM system
docker run -d ^
  --name fashionhub-app ^
  --memory="256m" ^
  --memory-swap="512m" ^
  --cpus="1.0" ^
  -p 3000:4000 ^
  pocketaces2/fashionhub-demo-app

IF %ERRORLEVEL% NEQ 0 (
    echo.
    echo ========================================
    echo ERROR: Failed to start container
    echo ========================================
    echo.
    echo Possible issues:
    echo 1. Docker Desktop not running
    echo 2. Port 3000 already in use
    echo 3. Image not pulled yet
    echo.
    echo To pull the image manually:
    echo   docker pull pocketaces2/fashionhub-demo-app
    echo.
    pause
    exit /b 1
)

echo.
echo ========================================
echo Container started successfully!
echo ========================================
echo.
echo Waiting for app to be ready...
timeout /t 5 /nobreak >nul

REM Check if container is still running
docker ps | findstr fashionhub-app >nul
IF %ERRORLEVEL% NEQ 0 (
    echo.
    echo WARNING: Container may have stopped
    echo Check logs with: docker logs fashionhub-app
    echo.
    pause
    exit /b 1
)

echo.
echo ========================================
echo App is running at: http://localhost:3000
echo ========================================
echo.
echo To check status:  docker ps
echo To view logs:     docker logs fashionhub-app
echo To stop app:      docker stop fashionhub-app
echo.
echo Press any key to view logs (Ctrl+C to exit logs)...
pause >nul

docker logs -f fashionhub-app
