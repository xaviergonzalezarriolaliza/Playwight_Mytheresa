# Docker Desktop Configuration for Windows 10 Home (Low Resources)

## Your System Specs
- **OS**: Windows 10 Home 22H2 (Build 19045.6456)
- **Install Date**: December 7, 2020
- **Docker Backend**: WSL2 (required for Windows Home)

---

## Recommended Docker Desktop Settings

### 1. Open Docker Desktop Settings
- Right-click Docker icon in system tray
- Click "Settings" or "Preferences"

### 2. Resources Settings

Navigate to: **Settings → Resources → Advanced**

#### If you have 4GB Total RAM:
```
CPUs: 1
Memory: 1.5 GB (1536 MB)
Swap: 512 MB
Disk image size: 20 GB
```

#### If you have 8GB Total RAM (Recommended Minimum):
```
CPUs: 2
Memory: 2 GB (2048 MB)
Swap: 1 GB (1024 MB)
Disk image size: 30 GB
```

#### If you have 16GB+ Total RAM:
```
CPUs: 2-3
Memory: 4 GB (4096 MB)
Swap: 2 GB (2048 MB)
Disk image size: 40 GB
```

### 3. WSL Integration

Navigate to: **Settings → Resources → WSL Integration**

- ✅ Enable integration with my default WSL distro
- ✅ Enable Ubuntu (or your installed distro)

### 4. General Settings

Navigate to: **Settings → General**

- ✅ Use the WSL 2 based engine (should be enabled by default on Home)
- ⬜ Start Docker Desktop when you log in (disable to save resources)
- ⬜ Open Docker Dashboard at startup (disable to save resources)
- ✅ Use Docker Compose V2

### 5. Advanced Settings (Optional)

Navigate to: **Settings → Docker Engine**

Add resource limits to daemon.json:
```json
{
  "builder": {
    "gc": {
      "defaultKeepStorage": "5GB",
      "enabled": true
    }
  },
  "experimental": false,
  "log-level": "error"
}
```

---

## After Configuration

1. **Click "Apply & Restart"** in Docker Desktop

2. **Restart WSL2** (PowerShell as Admin):
   ```powershell
   wsl --shutdown
   ```

3. **Restart Docker Desktop** from Start Menu

4. **Verify Docker is running**:
   ```bash
   docker --version
   docker ps
   ```

---

## Running Playwright Tests with Low Resources

Use the provided batch files:

```batch
# Single test with Chromium only (1GB memory, 1.5 CPUs)
run-docker-lowres.bat tests/challenge/test-case-1-console-errors.spec.ts chromium

# All tests sequentially (lowest memory usage)
run-docker-sequential.bat
```

---

## Troubleshooting

### If Docker won't start:
1. Check WSL2 is installed: `wsl --status`
2. Check Virtualization enabled in BIOS
3. Update Docker Desktop to latest version

### If tests fail with "Out of Memory":
1. Close other applications (browser, IDE)
2. Reduce memory in .wslconfig to 1.5GB
3. Run tests one at a time with sequential script

### If system is slow:
1. Disable "Start Docker Desktop when you log in"
2. Start Docker only when needed
3. Stop Docker after tests: Right-click icon → Quit Docker Desktop

---

## Performance Tips

1. **Clean up regularly**:
   ```bash
   docker system prune -a --volumes
   ```

2. **Monitor resource usage**:
   - Open Task Manager (Ctrl+Shift+Esc)
   - Check "Vmmem" process (WSL2 memory usage)

3. **Restart WSL2 if it uses too much memory**:
   ```powershell
   wsl --shutdown
   ```

---

## Alternative: Use GitHub Actions

If Docker is still too resource-intensive, use GitHub Actions (free):

```bash
git add .
git commit -m "test: run challenge tests"
git push origin main
```

View results at:
https://github.com/xaviergonzalezarriolaliza/Playwight_Mytheresa/actions
