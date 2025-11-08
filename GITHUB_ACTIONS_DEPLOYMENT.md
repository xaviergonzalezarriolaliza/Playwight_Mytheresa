# 🚀 GitHub Actions Deployment Guide

## Overview

This guide explains how to activate and use the GitHub Actions workflow for automated testing of the FashionHub application.

## ✅ Prerequisites

- GitHub account
- Repository pushed to GitHub
- Docker image available at `ghcr.io/pocketaces2/fashionhub:latest`

## 📦 What's Included

The workflow automatically runs:
1. **Docker Local Tests** - Pulls and runs Docker container, tests against localhost:4000
2. **Production Tests** - Tests against GitHub Pages deployment
3. **Independent Tests** - GitHub API scraper tests
4. **GitHub Actions Tests** - CI-specific tests with extended timeouts

## 🏗️ Setup Steps

### 1. Push to GitHub

```bash
# Add the workflow file
git add .github/workflows/playwright-tests.yml

# Add the README with badge
git add README.md

# Add updated test file with @github-actions tag
git add tests/challenge/test-case-3-login.spec.ts

# Commit
git commit -m "Add GitHub Actions workflow for automated testing"

# Push to main branch
git push origin main
```

### 2. Verify Workflow Activation

1. Go to your repository on GitHub
2. Click on **Actions** tab
3. You should see "Playwright Tests" workflow running
4. Click on it to see real-time progress

### 3. Check the Workflow

The workflow will:
- ✅ Install Node.js and dependencies
- ✅ Install Playwright browsers
- ✅ Pull FashionHub Docker image
- ✅ Start container on port 4000
- ✅ Run all tests with CI environment variables
- ✅ Upload test reports and screenshots
- ✅ Create a summary with test results

## 🎯 Workflow Features

### Automatic Triggers

The workflow runs automatically on:
- **Push** to `main` or `develop` branches
- **Pull Requests** to `main` branch
- **Manual dispatch** (you can trigger it manually)

### Manual Trigger

To manually run the workflow:
1. Go to **Actions** tab
2. Click **Playwright Tests** workflow
3. Click **Run workflow** button
4. Select branch and click **Run workflow**

## 📊 Test Execution Matrix

| Job | Tests Run | Environment |
|-----|-----------|-------------|
| **test-docker-local** | 135 tests + 5 CI tests | Docker container on port 4000 |
| **test-production** | 135 tests + 5 CI tests | GitHub Pages |
| **test-independent** | 5 tests | GitHub API |
| **summary** | N/A | Aggregates results |

## 🏷️ Tag System

Tests are organized with tags for selective execution:

| Tag | Description | Usage |
|-----|-------------|-------|
| `@docker-local` | Tests for local Docker environment | `--grep "@docker-local"` |
| `@production` | Tests for production environment | `--grep "@production"` |
| `@independent` | Tests that don't need FashionHub | `--grep "@independent"` |
| `@github-actions` | CI-specific tests | `--grep "@github-actions"` |
| `@ci` | CI environment tests | `--grep "@ci"` |

## 📁 Artifacts

After each run, the following artifacts are available:

### Docker Local Artifacts
- `playwright-report-docker-local` - HTML test report
- `test-screenshots-docker-local` - Screenshots and videos

### Production Artifacts
- `playwright-report-production` - HTML test report
- `test-screenshots-production` - Screenshots and videos

### Independent Artifacts
- `playwright-report-independent` - HTML test report

**Retention**: All artifacts are kept for **30 days**

## 🔍 Viewing Results

### 1. GitHub Actions Summary

After each run, a summary is automatically generated showing:
- ✅ Pass/Fail status for each environment
- 📊 Test coverage information
- 🔒 Security test results
- 📦 Available artifacts

### 2. HTML Reports

To download and view HTML reports:
1. Go to the workflow run
2. Scroll to **Artifacts** section at bottom
3. Download the report you want
4. Extract the ZIP file
5. Open `index.html` in a browser

### 3. Screenshots and Videos

Failed tests automatically capture:
- Screenshots at failure point
- Video recordings of the entire test
- Available in test artifacts

## 🔧 CI Environment Detection

Tests automatically detect CI environment using:
```typescript
const isCI = process.env.CI === 'true' || process.env.GITHUB_ACTIONS === 'true';
```

**CI Adjustments**:
- Extended timeouts (15s vs 5s)
- Performance threshold relaxed (10s vs 5s)
- Enhanced logging
- Explicit wait strategies

## 🐛 Troubleshooting

### Workflow Not Running

**Issue**: Workflow doesn't appear in Actions tab

**Solutions**:
1. Ensure `.github/workflows/playwright-tests.yml` is in the repository
2. Check file is in `main` or `develop` branch
3. Verify YAML syntax is correct
4. Check repository settings allow workflows

### Docker Container Fails to Start

**Issue**: Tests fail because container isn't ready

**Solutions**:
1. Check Docker image is accessible: `ghcr.io/pocketaces2/fashionhub:latest`
2. Verify port 4000 is not in use
3. Check container logs in workflow output
4. Increase wait timeout in workflow file

### Tests Failing in CI but Passing Locally

**Issue**: Tests pass locally but fail in GitHub Actions

**Solutions**:
1. Run tests locally with `CI=true`: `CI=true npx playwright test`
2. Check if timeouts need adjustment
3. Verify explicit waits are in place
4. Review GitHub Actions logs for specific errors

### Artifacts Not Uploading

**Issue**: Reports/screenshots not available after run

**Solutions**:
1. Check `playwright-report/` directory exists
2. Verify `test-results/` directory has content
3. Ensure tests ran (check logs)
4. Verify upload step completed successfully

## 📈 Performance Tips

### Optimize Workflow Speed

1. **Cache Dependencies**:
   - Already configured with `cache: 'npm'`
   - Speeds up npm install

2. **Parallel Jobs**:
   - Three jobs run in parallel
   - Reduces total execution time

3. **Skip Unnecessary Tests**:
   ```bash
   # Run only changed test files
   npx playwright test --only-changed
   ```

## 🎨 Customization

### Add More Environments

Edit `.github/workflows/playwright-tests.yml`:

```yaml
test-staging:
  name: Test Staging Environment
  runs-on: ubuntu-latest
  steps:
    # ... setup steps ...
    - name: Run tests against Staging
      run: BASE_URL=https://staging.example.com npx playwright test --grep "@staging"
```

### Add Slack Notifications

```yaml
- name: Notify Slack
  if: failure()
  uses: slackapi/slack-github-action@v1
  with:
    webhook-url: ${{ secrets.SLACK_WEBHOOK }}
    payload: |
      {
        "text": "Playwright tests failed on ${{ github.ref }}"
      }
```

### Schedule Nightly Tests

```yaml
on:
  push:
    branches: [ main, develop ]
  schedule:
    - cron: '0 2 * * *'  # Run at 2 AM daily
```

## 📊 Badge in README

The README now includes a status badge:

```markdown
[![Playwright Tests](https://github.com/xaviergonzalezarriolaliza/Playwight_Mytheresa/actions/workflows/playwright-tests.yml/badge.svg)](https://github.com/xaviergonzalezarriolaliza/Playwight_Mytheresa/actions/workflows/playwright-tests.yml)
```

This shows:
- ✅ Green badge when all tests pass
- ❌ Red badge when tests fail
- 🟡 Yellow badge when running

## 🔐 Security Considerations

### Secrets Management

If you need to add secrets (API keys, credentials):

1. Go to repository **Settings**
2. Click **Secrets and variables** → **Actions**
3. Click **New repository secret**
4. Add your secret
5. Reference in workflow: `${{ secrets.YOUR_SECRET }}`

### Docker Image Security

- Uses official image from GitHub Container Registry
- Image is public and maintained
- Pulled fresh on each run

## 📚 Additional Resources

- [Playwright CI Guide](https://playwright.dev/docs/ci)
- [GitHub Actions Documentation](https://docs.github.com/en/actions)
- [Docker in GitHub Actions](https://docs.github.com/en/actions/using-containerized-services/about-service-containers)

## ✅ Verification Checklist

After setup, verify:

- [ ] Workflow appears in Actions tab
- [ ] First run completes successfully
- [ ] Badge appears in README
- [ ] Artifacts are uploaded
- [ ] Summary is generated
- [ ] Docker container starts correctly
- [ ] All 3 environments tested
- [ ] CI-specific tests run with correct environment variables

## 🎉 Success Criteria

Your GitHub Actions setup is complete when:

1. ✅ Badge shows green in README
2. ✅ All 3 jobs pass (docker-local, production, independent)
3. ✅ Summary shows test results
4. ✅ Artifacts are available for download
5. ✅ Tests run automatically on push
6. ✅ CI-specific tests detect GitHub Actions environment

---

**Questions or Issues?**

Check the workflow logs in the Actions tab for detailed error messages and debugging information.
