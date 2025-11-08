# 🎭 Playwright Test Suite - FashionHub Challenge

[![Playwright Tests](https://github.com/xaviergonzalezarriolaliza/Playwight_Mytheresa/actions/workflows/playwright-tests.yml/badge.svg)](https://github.com/xaviergonzalezarriolaliza/Playwight_Mytheresa/actions/workflows/playwright-tests.yml)

Comprehensive E2E test suite for the FashionHub application using Playwright with TypeScript.

## 📋 Test Coverage

### Test Case 1: Console Error Detection
- ✅ Monitors console for errors, warnings, and failures
- ✅ Validates clean console output across all pages

### Test Case 2: Link Validation
- ✅ Checks all links are valid and accessible
- ✅ Verifies no broken links exist

### Test Case 3: Login Functionality (24 Tests)
- ✅ **Valid Credentials** - Full authentication flow with strict validation
- ✅ **Invalid Credentials** - Error handling and rejection
- ✅ **Empty Fields** - Form validation testing
- ✅ **Security Tests**:
  - SQL Injection protection
  - XSS attack prevention
  - LDAP injection protection
  - NoSQL injection protection
- ✅ **Edge Cases**:
  - Special characters handling
  - Unicode and emoji support
  - Long input handling
  - Whitespace trimming
  - Case sensitivity
  - Rapid login attempts
- ✅ **Environment Tests**:
  - CI/CD compatibility (GitHub Actions)
  - Headless browser mode
  - Screenshot capture verification

### Test Case 4: GitHub API Scraper
- ✅ Scrapes pull requests from Mytheresa repository
- ✅ Validates PR data structure and content
- ✅ Independent test (doesn't require FashionHub app)

### Test Case 5: Bug Hunting
- 📝 Currently skipped - documented issues for investigation

## 🌐 Test Environments

### Docker Local
- **URL**: `http://localhost:4000/fashionhub`
- **Setup**: Docker container with FashionHub app
- **Tag**: `@docker-local`

### Production
- **URL**: `https://pocketaces2.github.io/fashionhub/`
- **Hosting**: GitHub Pages
- **Tag**: `@production`

### Independent
- **Tests**: GitHub API scraper
- **Tag**: `@independent`

### CI/CD
- **Platform**: GitHub Actions
- **Tag**: `@github-actions`, `@ci`

## 🚀 Quick Start

### Prerequisites
```bash
# Node.js 18+ required
node --version

# Install dependencies
npm install

# Install Playwright browsers
npx playwright install
```

### Running Tests

#### Local Docker Environment
```bash
# Start Docker container
docker run -d --name fashionhub -p 4000:80 ghcr.io/pocketaces2/fashionhub:latest

# Run all docker-local tests
BASE_URL=http://localhost:4000/fashionhub npx playwright test --grep "@docker-local"

# Run specific test file
BASE_URL=http://localhost:4000/fashionhub npx playwright test tests/challenge/test-case-3-login.spec.ts

# Stop container
docker stop fashionhub && docker rm fashionhub
```

#### Production Environment
```bash
# Run all production tests
BASE_URL=https://pocketaces2.github.io/fashionhub npx playwright test --grep "@production"
```

#### All Environments
```bash
# Run all tests (Docker local + Production + Independent)
npm test

# Run with HTML report
npx playwright test --reporter=html

# Run specific browser
npx playwright test --project=webkit
```

#### CI/GitHub Actions Tests
```bash
# Run CI-specific tests
BASE_URL=http://localhost:4000/fashionhub npx playwright test --grep "@github-actions"
```

## 🧪 Browser Support

Tests run on **5 browsers** in parallel:
- ✅ Chromium
- ✅ Firefox
- ✅ Webkit (Safari)
- ✅ Chrome
- ✅ Edge

## 📊 Test Results

### Latest Run Statistics
- **Total Tests**: 275 (135 per environment + 5 independent)
- **Pass Rate**: 100%
- **Browsers**: 5
- **Environments**: 2 (Docker local + Production)
- **Webkit Stability**: Fixed with explicit waits

### Performance Benchmarks
- Login duration: < 5s (local) / < 10s (CI)
- 100% strict validation on all success indicators

## 🔒 Security Testing

All login tests include security validations:
- **SQL Injection**: Blocks `admin' OR '1'='1` payloads
- **XSS**: Sanitizes `<script>` tags
- **LDAP Injection**: Rejects LDAP query payloads
- **NoSQL Injection**: Blocks MongoDB operator payloads
- **Null Bytes**: Handles null byte injection attempts

## 📁 Project Structure

```
Playwight_Mytheresa/
├── .github/
│   └── workflows/
│       └── playwright-tests.yml      # CI/CD workflow
├── tests/
│   └── challenge/
│       ├── test-case-1-console-errors.spec.ts
│       ├── test-case-2-link-checker.spec.ts
│       ├── test-case-3-login.spec.ts         # 24 login tests
│       ├── test-case-4-github-pr-scraper.spec.ts
│       └── test-case-5-bug-hunting.spec.ts.skip
├── playwright.config.ts              # Playwright configuration
├── package.json
└── README.md
```

## ⚙️ Configuration

### Playwright Config Highlights
- **Retries**: 0 (strict, no retries)
- **Timeout**: 30s per test
- **Workers**: 1 (sequential execution)
- **HTML Reporter**: Automatic on failure
- **Screenshots**: On failure
- **Videos**: On first retry

### Tags System
- `@docker-local` - Tests for local Docker environment
- `@production` - Tests for production environment
- `@independent` - Tests that don't need FashionHub
- `@github-actions` - CI-specific tests
- `@ci` - CI environment tests

## 🤖 GitHub Actions

Automated testing runs on:
- ✅ Push to `main` or `develop`
- ✅ Pull requests
- ✅ Manual workflow dispatch

**Workflow Jobs**:
1. **test-docker-local**: Pulls Docker image, runs all local tests
2. **test-production**: Runs tests against GitHub Pages
3. **test-independent**: Runs GitHub API scraper
4. **summary**: Aggregates results and creates summary

**Artifacts** (30-day retention):
- Playwright HTML reports
- Test screenshots
- Test videos

## 📝 Documentation

- **[CHALLENGE_README.md](./CHALLENGE_README.md)** - Original challenge requirements
- **[TEST_REPORT.md](./TEST_REPORT.md)** - Detailed test execution report
- **[GITHUB_ACTIONS_GUIDE.md](./GITHUB_ACTIONS_GUIDE.md)** - CI/CD setup guide
- **[DOCKER_CONFIG.md](./DOCKER_CONFIG.md)** - Docker setup instructions
- **[COMPLETE_DOCKER_GUIDE.md](./COMPLETE_DOCKER_GUIDE.md)** - Comprehensive Docker guide

## 🐛 Known Issues

- Test Case 5 is currently skipped (bug hunting scenarios under investigation)
- Webkit tests require explicit waits for success indicators (now fixed)

## 🛠️ Development

### Adding New Tests
```typescript
test('your test name', {
  tag: ['@docker-local', '@production']
}, async ({ page, baseURL }) => {
  // Your test code here
});
```

### Running Tests in Debug Mode
```bash
# Debug mode with Playwright Inspector
npx playwright test --debug

# Headed mode (see browser)
npx playwright test --headed

# Specific browser in headed mode
npx playwright test --project=webkit --headed
```

### Generating Test Report
```bash
# Run tests and generate HTML report
npx playwright test --reporter=html

# Open report
npx playwright show-report
```

## 📈 Continuous Improvement

### Recent Enhancements
- ✅ Added explicit waits to fix webkit flakiness
- ✅ Implemented 100% strict validation for login tests
- ✅ Added comprehensive test documentation
- ✅ Created GitHub Actions workflow
- ✅ Improved security testing coverage

### Future Improvements
- [ ] Add visual regression testing
- [ ] Implement performance monitoring
- [ ] Add accessibility (a11y) tests
- [ ] Create test data factories
- [ ] Add API testing layer

## 👥 Contributing

1. Fork the repository
2. Create a feature branch
3. Add tests for new features
4. Ensure all tests pass
5. Submit a pull request

## 📄 License

This project is part of the Mytheresa QA Automation Challenge.

## 🎯 Test Execution Summary

Run the full test suite:
```bash
npm test
```

Expected output:
```
✓ Console Error Detection: 10 tests
✓ Link Validation: 10 tests
✓ Login Functionality: 120 tests (24 tests × 5 browsers)
✓ GitHub PR Scraper: 5 tests
─────────────────────────────
Total: 275 tests
Pass Rate: 100%
Duration: ~5 minutes
```

---

**Built with** ❤️ **using Playwright + TypeScript**
