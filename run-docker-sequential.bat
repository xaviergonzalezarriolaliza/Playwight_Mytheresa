@echo off
REM Run each test case individually - ULTRA MINIMAL MEMORY USAGE
REM Optimized for: AMD A4-5000 APU, 3.44GB RAM
REM This is the SAFEST approach for low-memory systems

echo.
echo ========================================
echo Running Challenge Tests - SEQUENTIAL MODE
echo (One test at a time - Ultra Low Memory)
echo ========================================
echo Device: DESKTOP-R9L3ONV
echo RAM: 3.44GB usable
echo Memory per test: 768MB
echo ========================================
echo.

SET DOCKER_CMD=docker run --rm --memory="768m" --memory-swap="1g" --cpus="1.0" --shm-size="256m" -v "%cd%:/work" -w /work mcr.microsoft.com/playwright:v1.56.1-jammy

echo [1/5] Running Test Case 1: Console Error Detection...
%DOCKER_CMD% npx playwright test tests/challenge/test-case-1-console-errors.spec.ts --project=chromium --workers=1
IF ERRORLEVEL 1 (
    echo *** Test Case 1 FAILED ***
) ELSE (
    echo *** Test Case 1 PASSED ***
)
echo.
timeout /t 5 /nobreak >nul
echo Waiting 5 seconds before next test (memory cleanup)...
echo.

echo [2/5] Running Test Case 2: Link Checker...
%DOCKER_CMD% npx playwright test tests/challenge/test-case-2-link-checker.spec.ts --project=chromium --workers=1
IF ERRORLEVEL 1 (
    echo *** Test Case 2 FAILED ***
) ELSE (
    echo *** Test Case 2 PASSED ***
)
echo.
timeout /t 5 /nobreak >nul
echo.

echo [3/5] Running Test Case 3: Login Functionality...
%DOCKER_CMD% npx playwright test tests/challenge/test-case-3-login.spec.ts --project=chromium --workers=1
IF ERRORLEVEL 1 (
    echo *** Test Case 3 FAILED ***
) ELSE (
    echo *** Test Case 3 PASSED ***
)
echo.
timeout /t 5 /nobreak >nul
echo.

echo [4/5] Running Test Case 4: GitHub PR Scraper...
%DOCKER_CMD% npx playwright test tests/challenge/test-case-4-github-pr.spec.ts --project=chromium --workers=1
IF ERRORLEVEL 1 (
    echo *** Test Case 4 FAILED ***
) ELSE (
    echo *** Test Case 4 PASSED ***
)
echo.
timeout /t 5 /nobreak >nul
echo.

echo [5/5] Running Test Case 5: Bug Hunting Suite...
%DOCKER_CMD% npx playwright test tests/challenge/test-case-5-bug-hunting.spec.ts --project=chromium --workers=1
IF ERRORLEVEL 1 (
    echo *** Test Case 5 FAILED ***
) ELSE (
    echo *** Test Case 5 PASSED ***
)
echo.

echo ========================================
echo All tests completed!
echo Check results above for pass/fail status
echo ========================================
