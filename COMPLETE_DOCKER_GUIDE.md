# Complete Docker Testing Guide

## Overview

This project supports **three testing approaches**:

1. **GitHub Actions + Production Site** - Tests remote GitHub Pages (fastest, no local resources)
2. **GitHub Actions + Docker Container** - Tests Docker container on GitHub (recommended for Docker testing)
3. **Local Docker + Local Tests** - Tests Docker container locally (requires 4GB+ RAM)

## Architecture

```
┌─────────────────────────────────────────────────────────────────┐
│                    TESTING APPROACHES                           │
├─────────────────────────────────────────────────────────────────┤
│                                                                 │
│  1. GITHUB ACTIONS + PRODUCTION SITE                           │
│     ┌─────────────────────────────────────────┐               │
│     │ GitHub Actions (Ubuntu VM, 7GB RAM)    │               │
│     │  ├─ Playwright Tests (native)          │               │
│     │  └─ Target: pocketaces2.github.io      │               │
│     └─────────────────────────────────────────┘               │
│     Workflow: run-challenge-tests.yml                          │
│     Speed: ~3-5 minutes                                        │
│     Cost: FREE                                                 │
│                                                                 │
│  2. GITHUB ACTIONS + DOCKER CONTAINER (RECOMMENDED)            │
│     ┌─────────────────────────────────────────┐               │
│     │ GitHub Actions (Ubuntu VM, 7GB RAM)    │               │
│     │  ├─ Docker: fashionhub-demo-app        │               │
│     │  ├─ Playwright Tests (native)          │               │
│     │  └─ Target: localhost:3000             │               │
│     └─────────────────────────────────────────┘               │
│     Workflow: run-tests-docker-app.yml                         │
│     Speed: ~3-5 minutes                                        │
│     Cost: FREE                                                 │
│                                                                 │
│  3. LOCAL DOCKER + LOCAL TESTS                                 │
│     ┌─────────────────────────────────────────┐               │
│     │ Your PC (Windows 10, 3.44GB RAM)       │               │
│     │  ├─ Docker: fashionhub-demo-app (256MB)│               │
│     │  ├─ Playwright Tests (npm, native)     │               │
│     │  └─ Target: localhost:3000             │               │
│     └─────────────────────────────────────────┘               │
│     Scripts: start-fashionhub-app.bat                          │
│     Speed: ~15-20 minutes (slow CPU)                           │
│     RAM: ~500-800MB total                                      │
│                                                                 │
└─────────────────────────────────────────────────────────────────┘
```

## Approach Comparison

| Feature | Production Site | Docker on GitHub | Docker Locally |
|---------|----------------|------------------|----------------|
| **Target** | GitHub Pages | Docker container | Docker container |
| **Where Tests Run** | GitHub | GitHub | Your PC |
| **RAM Required** | 0 (cloud) | 0 (cloud) | ~800MB |
| **Speed** | ⚡ Fast (3-5 min) | ⚡ Fast (3-5 min) | 🐌 Slow (15-20 min) |
| **Cost** | FREE | FREE | FREE |
| **Setup Effort** | ✅ None | ✅ None | ⚠️ Manual |
| **Best For** | Production testing | Docker validation | Local debugging |

## Recommendation for Your System

**System:** AMD A4-5000, 3.44GB RAM, Windows 10 Home

### ✅ RECOMMENDED: GitHub Actions + Docker Container

**Why:** 
- Tests actual Docker container (not GitHub Pages)
- Zero local resource usage
- 7GB RAM available (vs 3.44GB locally)
- Automatic execution on every push
- FREE for public repos

**How:** Already configured! Just push your code.

### ⚠️ OPTIONAL: Local Docker Testing

**When to use:**
- Debugging specific Docker issues
- Testing before pushing to GitHub
- Offline development

**Requirements:**
- Docker Desktop installed and running
- At least 1GB RAM free
- Port 3000 available

---

## Quick Start: GitHub Actions (Recommended)

### Option 1: Test Production Site
Already working! Pushes to `main` automatically trigger tests.

**Manual trigger:**
1. Go to: https://github.com/xaviergonzalezarriolaliza/Playwight_Mytheresa/actions
2. Click "Run Challenge Tests with Report"
3. Click "Run workflow"

### Option 2: Test Docker Container
Also automatic! Pushes to `main` trigger both workflows.

**Manual trigger:**
1. Go to: https://github.com/xaviergonzalezarriolaliza/Playwight_Mytheresa/actions
2. Click "Run Tests Against Docker Container"
3. Click "Run workflow"

**View results:**
- Tests complete in ~3-5 minutes
- Download artifacts: HTML report, PDF report, screenshots, videos
- Artifacts kept for 30 days

---

## Local Docker Testing (Optional)

### Prerequisites

1. **Docker Desktop** - See `DOCKER_CONFIG.md` for setup
2. **At least 1GB free RAM** - Close other apps
3. **Node.js** - Already installed

### Step 1: Start Fashion Hub App

```bash
# Pull the Docker image (first time only)
docker pull pocketaces2/fashionhub-demo-app

# Start the app container
start-fashionhub-app.bat
```

**What happens:**
- Downloads/starts `pocketaces2/fashionhub-demo-app` image
- Allocates 256MB RAM (minimal for your system)
- Exposes app on http://localhost:3000
- Shows logs automatically

**Verify:** Open http://localhost:3000 in browser

### Step 2: Run Tests

```bash
# Run all tests against localhost:3000
run-tests-against-local-docker.bat

# Run specific test
run-tests-against-local-docker.bat test-case-1-console-errors.spec.ts chromium
```

**What happens:**
- Checks if Fashion Hub container is running
- Sets `BASE_URL=http://localhost:3000`
- Runs Playwright tests natively (no Docker for tests)
- Generates reports in `reports/` folder

### Step 3: View Results

```bash
# Open HTML report
npx playwright show-report reports/[latest-folder]/html
```

### Step 4: Stop App

```bash
# Stop and remove container
stop-fashionhub-app.bat
```

---

## Troubleshooting

### Container Won't Start

**Symptom:** `Error: Cannot connect to Docker daemon`

**Fix:**
1. Open Docker Desktop
2. Wait for it to fully start (green icon in taskbar)
3. Try again: `start-fashionhub-app.bat`

### Port 3000 Already in Use

**Symptom:** `Port 3000 is already allocated`

**Fix:**
```bash
# Find process using port 3000
netstat -ano | findstr :3000

# Kill process (replace 1234 with actual PID)
taskkill /PID 1234 /F

# Try again
start-fashionhub-app.bat
```

### Tests Can't Connect

**Symptom:** `connect ECONNREFUSED 127.0.0.1:3000`

**Fix:**
```bash
# Check if container is running
docker ps

# Check logs
docker logs fashionhub-app

# Test manually
curl http://localhost:3000
# Or open in browser: http://localhost:3000
```

### Out of Memory

**Symptom:** Container keeps stopping, system freezes

**Fix:**
1. Close all unnecessary apps
2. Check RAM usage: Task Manager → Performance
3. Need at least 1GB free RAM
4. Consider using GitHub Actions instead

---

## Advanced: Manual Docker Commands

### Check Container Status
```bash
# List running containers
docker ps

# View logs
docker logs fashionhub-app

# Follow logs in real-time
docker logs -f fashionhub-app

# Container stats (CPU, RAM usage)
docker stats fashionhub-app
```

### Restart Container
```bash
# Stop container
docker stop fashionhub-app

# Start again
docker start fashionhub-app

# Or full restart
stop-fashionhub-app.bat
start-fashionhub-app.bat
```

### Clean Up Docker
```bash
# Remove stopped containers
docker container prune

# Remove unused images
docker image prune

# Full cleanup (use with caution!)
docker system prune -a
```

---

## CI/CD Workflow Details

### Workflow 1: Production Site Testing
**File:** `.github/workflows/run-challenge-tests.yml`

```yaml
Target: https://pocketaces2.github.io/fashionhub/
Triggers: Push to main, manual
Browsers: Chromium, Firefox, WebKit, Chrome, Edge
Duration: ~3-5 minutes
Artifacts: HTML report, PDF, screenshots, videos
```

### Workflow 2: Docker Container Testing
**File:** `.github/workflows/run-tests-docker-app.yml`

```yaml
Target: http://localhost:3000 (Docker service)
Image: pocketaces2/fashionhub-demo-app
Triggers: Push to main, manual
Browsers: Chromium, Firefox, WebKit, Chrome, Edge
Duration: ~3-5 minutes
Health Check: Automatic retry until app ready
Artifacts: HTML report, PDF, screenshots, videos
```

**Key Feature:** Uses GitHub Actions Service Containers
- Container starts automatically before tests
- Health checks ensure app is ready
- Logs available if tests fail
- Container cleaned up after job

---

## File Reference

### Local Testing Scripts
- `start-fashionhub-app.bat` - Start Docker container
- `stop-fashionhub-app.bat` - Stop Docker container
- `run-tests-against-local-docker.bat` - Run tests locally

### Low-Resource Docker Scripts (Legacy)
- `run-docker-lowres.bat` - Run tests in Playwright Docker (768MB)
- `run-docker-sequential.bat` - Run tests one at a time

### GitHub Actions Workflows
- `.github/workflows/run-challenge-tests.yml` - Test production site
- `.github/workflows/run-tests-docker-app.yml` - Test Docker container

### Documentation
- `LOCAL_DOCKER_TESTING.md` - This guide
- `DOCKER_CONFIG.md` - Docker Desktop setup
- `SETUP_FOR_LOW_RAM.md` - Low RAM optimizations
- `GITHUB_ACTIONS_GUIDE.md` - GitHub Actions usage

---

## Summary: What Should You Use?

### For Regular Development: ✅ GitHub Actions + Docker
```bash
# Just push your code
git add .
git commit -m "your changes"
git push

# Tests run automatically in ~3-5 minutes
# Download results from GitHub Actions page
```

### For Local Debugging: ⚠️ Local Docker (if needed)
```bash
# Start app
start-fashionhub-app.bat

# Run tests
run-tests-against-local-docker.bat

# Stop app
stop-fashionhub-app.bat
```

### ⚡ Fastest: GitHub Actions only
Zero setup, zero local resources, automatic execution.

---

## Questions?

- **How do I view GitHub Actions results?**  
  https://github.com/xaviergonzalezarriolaliza/Playwight_Mytheresa/actions

- **Where are test artifacts?**  
  Click on completed workflow → Artifacts section → Download

- **Which workflow tests the Docker container?**  
  "Run Tests Against Docker Container" workflow

- **Do I need Docker Desktop?**  
  No, if you only use GitHub Actions. Yes, for local testing.

- **Why two workflows?**  
  One tests production site (GitHub Pages), one tests Docker container. Pick what you need.
