# Running Tests on GitHub Actions (Recommended!)

## ✅ Why Use GitHub Actions Instead of Docker Locally?

**Your System:**
- CPU: AMD A4-5000 @ 1.5 GHz
- RAM: 3.44 GB usable
- Status: ⚠️ Below minimum for Docker Desktop

**GitHub Actions (FREE):**
- CPU: 2 cores (faster)
- RAM: 7 GB (2x more!)
- Status: ✅ Perfect for Playwright

**Result:** Tests run 3-4x faster on GitHub with zero local resource usage!

---

## 🚀 How to Run Tests on GitHub Actions

### Option 1: Automatic (When you push code)

```bash
# Stage your changes
git add .

# Commit
git commit -m "test: your message here"

# Push to GitHub (triggers tests automatically)
git push origin main
```

**GitHub will automatically:**
1. Run all 5 challenge tests
2. Test on all 5 browsers (Chromium, Firefox, WebKit, Chrome, Edge)
3. Generate HTML report
4. Generate PDF report
5. Capture screenshots + videos
6. Save everything as downloadable artifacts

### Option 2: Manual Trigger (Run without pushing code)

1. Go to: https://github.com/xaviergonzalezarriolaliza/Playwight_Mytheresa/actions
2. Click "Run Challenge Tests with Report" in left sidebar
3. Click green "Run workflow" button
4. Click "Run workflow" again in the dialog
5. Wait ~3-5 minutes for results

---

## 📊 Viewing Test Results

### Step 1: Go to Actions Tab

Visit: https://github.com/xaviergonzalezarriolaliza/Playwight_Mytheresa/actions

### Step 2: Click on Latest Workflow Run

You'll see:
- ✅ Green checkmark = All tests passed
- ❌ Red X = Some tests failed
- 🟡 Yellow circle = Tests running

### Step 3: Download Artifacts

Scroll to bottom of the run page, you'll see:

**Artifacts** (available for 30 days):
- 📁 `playwright-report` - HTML report with interactive results
- 📁 `test-results` - Screenshots, videos, traces for each test
- 📄 `pdf-report` - PDF summary of all test results

Click any artifact to download a .zip file.

### Step 4: View HTML Report Locally

```bash
# Extract playwright-report.zip
# Navigate to the folder
# Open index.html in your browser
```

Or use Playwright's built-in viewer:
```bash
npx playwright show-report path/to/extracted/html
```

---

## 🎯 What Gets Tested

Your workflow runs:
```
tests/challenge/test-case-1-console-errors.spec.ts
tests/challenge/test-case-2-link-checker.spec.ts
tests/challenge/test-case-3-login.spec.ts
tests/challenge/test-case-4-github-pr.spec.ts
tests/challenge/test-case-5-bug-hunting.spec.ts
```

On all 5 browsers:
- ✅ Chromium
- ✅ Firefox
- ✅ WebKit (Safari)
- ✅ Google Chrome
- ✅ Microsoft Edge

**Total:** 10+ test scenarios × 5 browsers = 50+ test executions

---

## ⏱️ How Long Does It Take?

- **Local (your PC):** Would take ~15-20 minutes + risk of crashes
- **GitHub Actions:** Takes ~3-5 minutes, runs in background

You can close your PC or work on other things while tests run!

---

## 💰 Cost

**FREE for public repositories!**
- 2,000 minutes/month included
- Each test run uses ~5 minutes
- You can run ~400 times per month for free

Your repo is public, so: **$0.00 forever** ✅

---

## 🔧 Troubleshooting

### "Workflow not appearing"
- Check: https://github.com/xaviergonzalezarriolaliza/Playwight_Mytheresa/actions
- Make sure you pushed to `main` branch
- Check `.github/workflows/run-challenge-tests.yml` exists

### "Tests failing on GitHub but pass locally"
- GitHub runs on Linux, you run on Windows
- This is expected and actually a feature (tests cross-platform compatibility)
- The GitHub results are more reliable

### "Can't find artifacts"
- Artifacts only appear after workflow completes
- They're at the bottom of the workflow run page
- They expire after 30 days (download soon!)

---

## 🎓 Pro Tips

### Run Specific Tests Only

Edit `.github/workflows/run-challenge-tests.yml`:

```yaml
# Change this line:
run: npm test -- tests/challenge/

# To run only Test Case 1:
run: npm test -- tests/challenge/test-case-1-console-errors.spec.ts
```

### Run on Pull Requests Too

Add to workflow file under `on:`:

```yaml
on:
  workflow_dispatch:
  push:
    branches: [ main ]
  pull_request:  # Add this
    branches: [ main ]
```

### Get Email Notifications

1. Go to: https://github.com/settings/notifications
2. Enable "Actions" notifications
3. Get email when tests pass/fail

---

## 📝 Quick Start (3 Steps)

```bash
# 1. Commit your changes
git add .
git commit -m "test: run challenge tests"

# 2. Push to GitHub
git push origin main

# 3. View results
# Open: https://github.com/xaviergonzalezarriolaliza/Playwight_Mytheresa/actions
```

**Done!** Your tests are running on GitHub's powerful servers while your PC stays free. ✅

---

## 📸 Screenshots & Videos

Every test run captures:
- **Screenshots** at key points and on failures
- **Videos** of entire test execution
- **Traces** for detailed debugging (Playwright's time-travel debugger)

Download from artifacts and view locally:
```bash
# View trace file
npx playwright show-trace path/to/trace.zip
```

---

## 🆚 Local vs GitHub Actions

| Feature | Local (Your PC) | GitHub Actions |
|---------|----------------|----------------|
| CPU | 1.5 GHz, 4 cores | 2.0+ GHz, 2 cores |
| RAM | 3.44 GB | 7 GB |
| Speed | Slow (15-20 min) | Fast (3-5 min) |
| Stability | Risk of crashes | 99.9% uptime |
| Cost | Uses your PC | FREE |
| Artifacts | Manual save | Auto-saved 30 days |
| OS | Windows | Linux (production-like) |

**Winner:** GitHub Actions! 🏆

---

## Need Help?

- Check workflow status: https://github.com/xaviergonzalezarriolaliza/Playwight_Mytheresa/actions
- View logs: Click on workflow run → Click on job name → See detailed logs
- Re-run failed tests: Click "Re-run jobs" button on failed run
