# Docker Setup for DESKTOP-R9L3ONV (Low-End System)

## ⚠️ CRITICAL: Your System Specs

```
Device:     DESKTOP-R9L3ONV
CPU:        AMD A4-5000 APU @ 1.50 GHz (4 cores)
RAM:        4 GB (3.44 GB usable) ⚠️ VERY LOW
Storage:    224 GB SSD (CT240BX500SSD1) ✅ Good
GPU:        AMD Radeon HD 8330 (494 MB)
OS:         Windows 10 Home 64-bit (Build 19045.6456)
```

## ⚠️ IMPORTANT WARNINGS

With only **3.44 GB usable RAM**, running Docker Desktop will be **extremely challenging**:

1. **Docker Desktop alone uses ~1-1.5GB RAM**
2. **Windows needs ~1.5GB RAM**
3. **Playwright tests need ~0.5-1GB RAM**

**Total needed: ~3-4GB** → You're at the absolute limit!

---

## Recommended Approach: **GitHub Actions (BEST)**

Instead of Docker locally, use GitHub Actions (free, better resources):

```bash
# Simply push your code
git add .
git commit -m "test: run challenge tests"
git push origin main

# View results at:
# https://github.com/xaviergonzalezarriolaliza/Playwight_Mytheresa/actions
```

**Why this is better:**
- ✅ Free 2-core CPU, 7GB RAM (much more than your system)
- ✅ No Docker Desktop overhead
- ✅ Your PC stays usable
- ✅ Automatic test artifacts (videos, screenshots, reports)

---

## If You MUST Use Docker Locally

### Step 1: Create C:\temp folder

```cmd
mkdir C:\temp
```

This will store the swap file (virtual memory on your SSD).

### Step 2: Apply WSL2 Configuration

1. The `.wslconfig` file is already created at `C:\Users\adria\.wslconfig`
2. Open PowerShell as **Administrator** and run:

```powershell
wsl --shutdown
```

3. Wait 10 seconds, then restart Docker Desktop

### Step 3: Configure Docker Desktop (Minimal Settings)

Open Docker Desktop → Settings → Resources:

```
CPUs: 1
Memory: 1 GB (1024 MB)  ⚠️ Minimum possible
Swap: 512 MB
Disk: 20 GB
```

**⚠️ CRITICAL**: Uncheck "Start Docker Desktop when you log in"

### Step 4: Before Running Tests

1. **Close ALL other applications** (browsers, editors, everything)
2. **Restart your PC** (fresh memory state)
3. **Start Docker Desktop manually**
4. Wait until Docker shows "Running" status

### Step 5: Run Tests (Use Sequential Script)

```cmd
# Navigate to project folder
cd C:\Users\adria\Downloads\Playwight_Mytheresa

# Run ONE test at a time (safest)
run-docker-lowres.bat tests/challenge/test-case-1-console-errors.spec.ts chromium
```

**OR** run all tests with delays between each:

```cmd
run-docker-sequential.bat
```

---

## Performance Tips for Your System

### 1. Disable Windows Features You Don't Need

```cmd
# Run as Administrator
sc config "DiagTrack" start= disabled
sc config "dmwappushservice" start= disabled
sc stop "DiagTrack"
sc stop "dmwappushservice"
```

### 2. Increase Virtual Memory

1. Right-click "This PC" → Properties
2. Advanced system settings → Performance Settings → Advanced → Virtual Memory
3. Set custom size:
   - Initial: 4096 MB
   - Maximum: 8192 MB

### 3. Close Resource-Heavy Programs

Before running Docker/tests, close:
- Chrome/Firefox (use Edge if needed, it's lighter)
- VS Code (run tests from command line only)
- Any background apps in system tray

### 4. Monitor Memory Usage

Open Task Manager (Ctrl+Shift+Esc) and watch:
- **Total RAM usage should stay below 90%**
- **Vmmem process** = WSL2 memory (Docker)
- If it reaches 95%, tests will fail

---

## Troubleshooting

### "Out of memory" errors:
```bash
# Stop Docker
docker stop $(docker ps -aq)

# Restart WSL
wsl --shutdown

# Clear Docker cache
docker system prune -a --volumes
```

### System freezing:
- Your RAM is too low for Docker
- **Use GitHub Actions instead** (see top of document)

### Tests timing out:
- CPU is slow (1.5 GHz)
- This is normal for your hardware
- Increase timeout in `playwright.config.ts`:
  ```typescript
  timeout: 60_000,  // Change to 60 seconds
  ```

---

## Docker Resource Limits in Scripts

Your batch files now use **ultra-minimal settings**:

```batch
--memory="768m"       # Only 768MB RAM
--memory-swap="1g"    # 1GB total with swap
--cpus="1.0"          # 1 CPU core only
--shm-size="256m"     # Minimal shared memory
--workers=1           # No parallel execution
```

---

## Alternative: Native Playwright (No Docker)

If Docker doesn't work, run natively:

```bash
# Already installed
npm test
```

**Pros:**
- No Docker overhead
- Uses less RAM (~500MB vs ~1.5GB)

**Cons:**
- Only tests on your Windows environment
- Doesn't match production Linux environment

---

## Final Recommendation

🎯 **Best solution for your system**: **GitHub Actions**

Your hardware is below the minimum recommended for Docker Desktop. You'll spend more time fighting memory issues than running tests.

GitHub Actions gives you:
- Free, unlimited runs
- Better hardware (2 cores, 7GB RAM)
- Professional CI/CD setup
- Automatic artifact storage

**Just push your code and let GitHub do the heavy lifting!**

```bash
git push origin main
```

Then check: https://github.com/xaviergonzalezarriolaliza/Playwight_Mytheresa/actions
