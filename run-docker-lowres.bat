@echo off
REM Run Playwright tests in Docker - ULTRA LOW RESOURCES
REM Optimized for: AMD A4-5000 APU, 3.44GB RAM
REM Usage: run-docker-lowres.bat [test-file] [browser]
REM Example: run-docker-lowres.bat test-case-1-console-errors.spec.ts chromium

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
echo Playwright Docker - ULTRA LOW RESOURCES
echo ========================================
echo Device: DESKTOP-R9L3ONV
echo CPU: AMD A4-5000 (1.5GHz, 4 cores)
echo RAM: 3.44GB usable
echo ========================================
echo Test: %TEST_FILE%
echo Browser: %BROWSER%
echo Memory Limit: 768MB
echo CPU Limit: 1.0 cores
echo Workers: 1 (serial execution)
echo ========================================
echo.

REM Ultra-minimal settings for 3.44GB RAM system
docker run --rm ^
  --memory="768m" ^
  --memory-swap="1g" ^
  --cpus="1.0" ^
  --shm-size="256m" ^
  -v "%cd%:/work" ^
  -w /work ^
  mcr.microsoft.com/playwright:v1.56.1-jammy ^
  npx playwright test %TEST_FILE% --project=%BROWSER% --workers=1

echo.
echo ========================================
echo Test execution completed
echo ========================================
