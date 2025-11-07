@echo off
REM Run Playwright tests against LOCAL Fashion Hub Docker container
REM Optimized for: AMD A4-5000 APU, 3.44GB RAM
REM Usage: run-tests-against-local-docker.bat [test-file] [browser]
REM Example: run-tests-against-local-docker.bat test-case-1-console-errors.spec.ts chromium

SET TEST_FILE=%1
SET BROWSER=%2

IF "%TEST_FILE%"=="" (
    SET TEST_FILE=tests/challenge/
)

IF "%BROWSER%"=="" (
    SET BROWSER=chromium
)

echo.
echo ========================================
echo Playwright Tests - Against Local Docker
echo ========================================
echo Device: DESKTOP-R9L3ONV (3.44GB RAM)
echo Target: http://localhost:3000
echo Test: %TEST_FILE%
echo Browser: %BROWSER%
echo ========================================
echo.

REM Check if Fashion Hub app container is running
docker ps | findstr fashionhub-app >nul
IF %ERRORLEVEL% NEQ 0 (
    echo ERROR: Fashion Hub app container is not running!
    echo.
    echo Please start the app first:
    echo   start-fashionhub-app.bat
    echo.
    pause
    exit /b 1
)

echo Fashion Hub app is running...
echo.

REM Run Playwright tests with BASE_URL pointing to localhost
REM Using npm test (local execution, no Docker for tests)
SET BASE_URL=http://localhost:3000
npm test %TEST_FILE% -- --project=%BROWSER%

echo.
echo ========================================
echo Test execution completed
echo ========================================
echo.
echo To view test report:
echo   npx playwright show-report reports/[latest]
echo.
