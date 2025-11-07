@echo off
REM Stop Fashion Hub Demo App Docker Container

echo.
echo ========================================
echo Fashion Hub Demo App - Stopping...
echo ========================================
echo.

docker stop fashionhub-app
docker rm fashionhub-app

echo.
echo ========================================
echo Container stopped and removed
echo ========================================
echo.
