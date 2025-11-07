# Testing Against Local Docker Container

This guide explains how to run Playwright tests against the Fashion Hub app running in a local Docker container.

## Overview

**Two separate Docker containers:**
1. **Fashion Hub App** - The application being tested (`pocketaces2/fashionhub-demo-app`)
2. **Playwright Tests** - Run locally via npm (no Docker needed)

## Quick Start

### 1. Start the Fashion Hub App

```bash
# Start the app container (runs at http://localhost:3000)
start-fashionhub-app.bat
```

This will:
- Pull the `pocketaces2/fashionhub-demo-app` image (if needed)
- Start container with 256MB RAM (suitable for your 3.44GB system)
- Expose app on port 3000
- Show logs automatically

### 2. Run Tests Against Local Container

```bash
# Run all tests against localhost:3000
run-tests-against-local-docker.bat

# Run specific test on specific browser
run-tests-against-local-docker.bat test-case-1-console-errors.spec.ts chromium
```

### 3. Stop the App When Done

```bash
stop-fashionhub-app.bat
```

## Resource Usage

**Fashion Hub App Container:**
- Memory: 256MB
- CPU: 1 core
- Port: 3000

**Playwright Tests (npm):**
- Runs natively on Windows (no container)
- Uses remaining system RAM
- Connects to http://localhost:3000

**Total RAM usage:** ~500-800MB (app + browser + test runner)

## Manual Commands

### Check App Status
```bash
# See if container is running
docker ps

# View container logs
docker logs fashionhub-app

# Follow logs in real-time
docker logs -f fashionhub-app
```

### Test the App Manually
Open browser: http://localhost:3000

### Pull Image Manually
```bash
docker pull pocketaces2/fashionhub-demo-app
```

### Advanced: Run Tests in Playwright Docker Container

If you want to run tests inside a Playwright Docker container (not recommended for 3.44GB RAM):

```bash
# Start Fashion Hub app first
start-fashionhub-app.bat

# Run tests in Playwright container (requires more RAM)
docker run --rm ^
  --memory="768m" ^
  --network="host" ^
  -v "%cd%:/work" ^
  -w /work ^
  mcr.microsoft.com/playwright:v1.56.1-jammy ^
  npx playwright test --base-url=http://localhost:3000
```

**Note:** On Windows, `--network="host"` doesn't work. Use `host.docker.internal` instead:

```bash
npx playwright test --base-url=http://host.docker.internal:3000
```

## Troubleshooting

### Port 3000 Already in Use
```bash
# Find process using port 3000
netstat -ano | findstr :3000

# Kill process (replace PID with actual process ID)
taskkill /PID <PID> /F
```

### Container Won't Start
```bash
# Check Docker Desktop is running
docker ps

# Check logs for errors
docker logs fashionhub-app

# Remove old container
docker stop fashionhub-app
docker rm fashionhub-app

# Try again
start-fashionhub-app.bat
```

### Tests Can't Connect to localhost:3000
```bash
# Verify app is accessible
curl http://localhost:3000

# Or open in browser
start http://localhost:3000
```

### Out of Memory
```bash
# Stop the app
stop-fashionhub-app.bat

# Close other applications
# Free up RAM before retrying
```

## Comparison: Local Docker vs GitHub Actions

| Aspect | Local Docker | GitHub Actions |
|--------|--------------|----------------|
| **App Container** | 256MB on your PC | N/A (tests remote site) |
| **Test Execution** | Native (npm) | Native (Ubuntu VM) |
| **Total RAM** | ~500-800MB | 7GB available |
| **Speed** | Slower (1.5GHz CPU) | 3-4x faster (2+ GHz) |
| **Setup** | Manual start/stop | Automatic |
| **Target** | localhost:3000 | pocketaces2.github.io/fashionhub |

## When to Use Each Approach

### Use Local Docker When:
- Testing unreleased features
- Debugging specific scenarios
- Need to modify app code locally
- Testing app configuration changes

### Use GitHub Actions When:
- Running full test suite
- CI/CD automated testing
- Testing production site
- Limited local resources (< 4GB RAM)

## GitHub Actions Configuration

To test against a local Docker container in GitHub Actions, modify `.github/workflows/run-challenge-tests.yml`:

```yaml
# Add service container
services:
  fashionhub:
    image: pocketaces2/fashionhub-demo-app
    ports:
      - 3000:3000

# Update BASE_URL
env:
  BASE_URL: http://localhost:3000
```

This way GitHub Actions will:
1. Start Fashion Hub container automatically
2. Run tests against localhost:3000
3. Clean up container after tests

## Next Steps

1. **Start the app:** `start-fashionhub-app.bat`
2. **Verify it's running:** Open http://localhost:3000 in browser
3. **Run tests:** `run-tests-against-local-docker.bat`
4. **View results:** Check reports folder
5. **Stop app:** `stop-fashionhub-app.bat` when done
