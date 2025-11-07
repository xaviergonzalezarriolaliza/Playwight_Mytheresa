# New Machine Migration Guide

This document details the exact steps to move development of this Playwright + Docker test workspace to a new computer (laptop or desktop) and get back to green test runs quickly.

---
## 1. Hardware Quick Checklist
Minimum acceptable (budget):
- CPU: Ryzen 5 5600H / 6600H / 7535HS or Intel i5‑11400H / 12450H (avoid U‑series)
- RAM: 16 GB upgradeable (target 32 GB soon)
- SSD: 512 GB NVMe (second M.2 slot ideal)

Recommended (performance):
- CPU: Ryzen 7 7700X / Ryzen 9 7940HS (laptop) or Intel i7‑13700H / i7‑13700K
- RAM: 32 GB (expandable to 64 GB)
- SSD: 1 TB NVMe Gen4 (plus second for Docker cache/artifacts)

## 2. OS Decision
| Scenario | Choose | Notes |
|----------|--------|-------|
| Pure dev performance | Ubuntu 24.04 LTS | Simplest for Docker & Playwright | 
| Need Windows apps | Windows 11 Pro + WSL2 | Keep repo inside WSL Linux FS |
| Unsure / hybrid | Start Windows + WSL2 | Optionally dual‑boot later |

## 3. Pre‑Migration Inventory (Old Machine)
Before you move, collect:
- Git status: `git branch`, `git status` (ensure main is clean or pushed).
- Unpushed branches: `git branch -vv | grep ahead`.
- Tags or release refs if used: `git tag`.
- Local environment files (.env) – DO NOT COMMIT; copy manually.
- SSH keys (if needed) – or generate new on new machine.
- npm global tools you rely on: `npm ls -g --depth=0`.
- Docker images you care about (optional): `docker images`.
- Test artifacts you want to preserve: `reports/`, `playwright-report/`, `logs/`.

## 4. Transfer Strategy
Preferred: fresh clone (avoid copying node_modules). Then selectively copy:
- `/logs` (if you want historical run lines)
- Any custom config files you added
- PDF test reports if needed for audit

Avoid copying: `node_modules`, Playwright browsers cache, Docker layer cache directories (rebuild fresh).

## 5. New Machine Base Setup
### 5.1 Windows + WSL2
1. Enable virtualization in BIOS (VT‑x / AMD‑V).
2. Open PowerShell (Admin): `wsl --install` (Ubuntu) then reboot.
3. Install Docker Desktop (enable WSL backend, disable legacy Hyper‑V).
4. Inside WSL: install core packages:
   - `sudo apt update && sudo apt install -y git curl build-essential`.
5. Install Node (LTS) via nvm:
   - `curl -o- https://raw.githubusercontent.com/nvm-sh/nvm/v0.39.7/install.sh | bash`
   - `nvm install --lts`.

### 5.2 Native Linux (Ubuntu 24.04)
1. `sudo apt update && sudo apt install -y git curl build-essential docker.io docker-compose-plugin`
2. Add user to docker group: `sudo usermod -aG docker $USER` then log out/in.
3. Install nvm (same as above) and Node LTS.

## 6. Clone & Install
```bash
git clone <repo-url> Playwight_Mytheresa
cd Playwight_Mytheresa
npm ci
npx playwright install
```
If behind corporate proxy, configure npm + git before install.

## 7. Environment & Secrets
Create `.env` (if the project uses one). Keep secrets out of version control.
Example template (adjust):
```
# .env (NOT COMMITTED)
API_BASE=https://api.example.com
AUTH_TOKEN=<insert>
```
Never put tokens inside test specs; read from process.env.

## 8. Validating Setup
Run a quick subset:
```bash
npx playwright test tests/challenge/test-case-4-github-pr-scraper.spec.ts --project=chromium
```
Then full suite:
```bash
npm test
```
Check `playwright-report/` or `reports/` for HTML report.

## 9. Docker Tasks (Optional)
Pull or rebuild required images:
```bash
docker compose pull || true
docker compose build --pull
docker compose up -d
```
Prune old/unused data occasionally:
```bash
docker system prune --volumes
```
(Review output carefully first.)

## 10. Performance Tweaks
- Increase Playwright workers: edit `playwright.config.ts` or pass `--workers=<cores-2>`.
- Disable videos/screenshots for passing tests to reduce I/O.
- Use NVMe for Docker data (optionally symlink or custom data-root).

## 11. Regenerating PDF Reports
Playwright HTML report → PDF:
```bash
npm run report:pdf
```
Custom markdown to PDF (this guide):
```bash
node scripts/generate-migration-pdf.js MIGRATION_GUIDE.md
```
Output lands in root as `MIGRATION_GUIDE_<timestamp>.pdf`.

## 12. Keeping Repo Updated
- Pull frequently: `git pull --rebase`.
- Keep feature branches short-lived; merge back quickly.
- Commit new machine config only if generic (avoid absolute local paths or secrets).

## 13. Checklist (Copy/Paste)
```
[ ] BIOS virtualization enabled
[ ] OS installed / WSL2 ready
[ ] Git + Node installed
[ ] Docker installed / user in docker group
[ ] Repo cloned
[ ] npm ci completed
[ ] Playwright browsers installed
[ ] .env recreated
[ ] Smoke test passes
[ ] Full suite passes
[ ] PDF reports generated (optional)
```

## 14. Troubleshooting
| Symptom | Likely Cause | Fix |
|---------|--------------|-----|
| Slow installs | Using /mnt/c in WSL | Work in Linux FS (/home) |
| Docker permission denied | Not in docker group | `sudo usermod -aG docker $USER` logout/login |
| Playwright browsers missing | Skipped install step | `npx playwright install` |
| Tests flaky on new machine | Resource contention / low RAM | Close background apps; reduce workers |

## 15. Security Notes
- Never commit `.env` or secrets.
- Rotate tokens when moving machines if policy requires.
- Delete old machine copies of sensitive files.

---
**End of Migration Guide**
