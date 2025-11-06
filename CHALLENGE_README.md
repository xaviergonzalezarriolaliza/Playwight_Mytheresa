# QA Engineer - Technical Challenge

This repository contains automated test suite for the Fashionhub application using Playwright with TypeScript.

## Table of Contents
- [Overview](#overview)
- [Prerequisites](#prerequisites)
- [Installation](#installation)
- [Configuration](#configuration)
- [Running Tests](#running-tests)
- [Test Cases](#test-cases)
- [Docker Support](#docker-support)
- [CI/CD Integration](#cicd-integration)
- [Project Structure](#project-structure)

## Overview

This test automation framework implements comprehensive test coverage for the Fashionhub application with support for:
- ✅ Cross-browser testing (Chromium, Firefox, WebKit)
- ✅ Multiple environments (local, staging, production)
- ✅ Console error detection
- ✅ Link validation and status code verification
- ✅ Login functionality testing
- ✅ GitHub PR scraping with CSV export
- ✅ Docker container support
- ✅ CI/CD ready

## Prerequisites

- **Node.js** v18 or higher
- **npm** v8 or higher
- **Docker** (optional, for running the app locally)

## Installation

1. Clone the repository:
```bash
git clone https://github.com/xaviergonzalezarriolaliza/Playwight_Mytheresa.git
cd Playwight_Mytheresa
```

2. Install dependencies:
```bash
npm install
```

3. Install Playwright browsers:
```bash
npx playwright install
```

## Configuration

### Environment Configuration

The test suite supports multiple ways to configure the target environment:

#### Priority Order:
1. **Command-line argument** (highest priority)
2. **Environment variable**
3. **Default** (production environment)

### Option 1: Command-line argument
```bash
npm test -- --base-url=http://localhost:4000/fashionhub/
```

### Option 2: Environment variable
```bash
export BASE_URL=http://localhost:4000/fashionhub/
npm test
```

Or on Windows:
```cmd
set BASE_URL=http://localhost:4000/fashionhub/
npm test
```

### Option 3: Default (no configuration needed)
```bash
npm test
# Runs against production: https://pocketaces2.github.io/fashionhub/
```

### Available Environments

#### Production (default)
```bash
npm test
# or explicitly:
npm test -- --base-url=https://pocketaces2.github.io/fashionhub/
```

#### Local (Docker)
```bash
npm test -- --base-url=http://localhost:4000/fashionhub/
```

#### Staging (example)
```bash
npm test -- --base-url=https://staging-env/fashionhub/
```

## Running Tests

### Run all tests
```bash
npm test
```

### Run specific test case
```bash
# Test Case 1: Console errors
npm test -- tests/challenge/test-case-1-console-errors.spec.ts

# Test Case 2: Link checker
npm test -- tests/challenge/test-case-2-link-checker.spec.ts

# Test Case 3: Login
npm test -- tests/challenge/test-case-3-login.spec.ts

# Test Case 4: GitHub PR scraper
npm test -- tests/challenge/test-case-4-github-pr-scraper.spec.ts
```

### Run on specific browser
```bash
# Chromium only
npm test -- --project=chromium

# Firefox only
npm test -- --project=firefox

# WebKit only
npm test -- --project=webkit

# All browsers
npm test
```

### Run with UI mode (interactive)
```bash
npx playwright test --ui
```

### Run in headed mode (see the browser)
```bash
npm test -- --headed
```

### Debug mode
```bash
npx playwright test --debug
```

### Generate and view HTML report
```bash
npm test
npx playwright show-report
```

## Test Cases

### Test Case 1: Console Error Detection
**Objective:** Verify there are no console errors when visiting the application.

**Implementation:**
- Monitors console messages and page errors
- Tests homepage for clean console (should pass)
- Tests about page which has intentional errors (should detect them)

**Run:**
```bash
npm test -- tests/challenge/test-case-1-console-errors.spec.ts
```

### Test Case 2: Link Status Code Verification
**Objective:** Check all links return valid HTTP status codes (200/30x, not 40x).

**Implementation:**
- Extracts all links from the homepage
- Verifies each link returns valid status codes
- Filters out external links
- Provides detailed summary

**Run:**
```bash
npm test -- tests/challenge/test-case-2-link-checker.spec.ts
```

### Test Case 3: Login Functionality
**Objective:** Verify user can log in with valid credentials.

**Credentials:**
- Username: `demouser`
- Password: `fashion123`

**Implementation:**
- Tests successful login with valid credentials
- Tests error handling with invalid credentials
- Verifies redirection or success indicators

**Run:**
```bash
npm test -- tests/challenge/test-case-3-login.spec.ts
```

### Test Case 4: GitHub Pull Request Scraper
**Objective:** Extract open pull requests from GitHub and generate CSV report.

**Implementation:**
- Navigates to https://github.com/appwrite/appwrite/pulls
- Extracts PR name, created date, and author
- Generates CSV file in `test-results/` directory
- Provides console output with summary

**Run:**
```bash
npm test -- tests/challenge/test-case-4-github-pr-scraper.spec.ts
```

**Output:** CSV file saved to `test-results/github-prs-<timestamp>.csv`

## Docker Support

### Run the Fashionhub application locally using Docker

1. Pull and run the Docker image:
```bash
docker run -d -p 4000:80 --name fashionhub-app pocketaces2/fashionhub
```

2. Verify the app is running:
```bash
curl http://localhost:4000/fashionhub/
```

3. Run tests against local Docker instance:
```bash
npm test -- --base-url=http://localhost:4000/fashionhub/
```

4. Stop and remove the container:
```bash
docker stop fashionhub-app
docker rm fashionhub-app
```

### Run tests in Docker

You can also run the tests themselves in a Docker container:

```bash
# Build a Docker image for tests (create Dockerfile first)
docker build -t fashionhub-tests .

# Run tests
docker run --rm -v $(pwd)/test-results:/app/test-results fashionhub-tests
```

## CI/CD Integration

### Jenkins Pipeline Example

```groovy
pipeline {
    agent any
    
    environment {
        BASE_URL = 'https://staging-env/fashionhub/'
    }
    
    stages {
        stage('Install Dependencies') {
            steps {
                sh 'npm ci'
                sh 'npx playwright install --with-deps'
            }
        }
        
        stage('Run Tests') {
            steps {
                sh 'npm test'
            }
        }
        
        stage('Publish Reports') {
            steps {
                publishHTML([
                    reportDir: 'playwright-report',
                    reportFiles: 'index.html',
                    reportName: 'Playwright Test Report'
                ])
                junit 'test-results/junit.xml'
            }
        }
    }
}
```

### GitHub Actions Example

```yaml
name: Playwright Tests
on: [push, pull_request]

jobs:
  test:
    runs-on: ubuntu-latest
    strategy:
      matrix:
        browser: [chromium, firefox, webkit]
    steps:
      - uses: actions/checkout@v3
      - uses: actions/setup-node@v3
        with:
          node-version: 18
      - name: Install dependencies
        run: npm ci
      - name: Install Playwright
        run: npx playwright install --with-deps
      - name: Run tests
        run: npm test -- --project=${{ matrix.browser }}
      - uses: actions/upload-artifact@v3
        if: always()
        with:
          name: playwright-report-${{ matrix.browser }}
          path: playwright-report/
```

## Project Structure

```
Playwight_Mytheresa/
├── tests/
│   ├── challenge/
│   │   ├── test-case-1-console-errors.spec.ts
│   │   ├── test-case-2-link-checker.spec.ts
│   │   ├── test-case-3-login.spec.ts
│   │   └── test-case-4-github-pr-scraper.spec.ts
│   └── ... (other test suites)
├── test-results/            # Test results and CSV outputs
├── playwright-report/       # HTML test reports
├── playwright.config.ts     # Playwright configuration
├── package.json
├── tsconfig.json
└── README.md
```

## Best Practices Implemented

✅ **Page Object Model (POM):** Reusable page components for maintainability  
✅ **Environment Flexibility:** Support for multiple environments via CLI/env vars  
✅ **Cross-browser Testing:** Tests run on Chromium, Firefox, and WebKit  
✅ **Detailed Reporting:** HTML reports, JUnit XML, and console output  
✅ **Error Handling:** Graceful failures with screenshots and traces  
✅ **Scalability:** Well-structured code for easy additions  
✅ **CI/CD Ready:** Works with Jenkins, GitHub Actions, and other CI tools  
✅ **Docker Support:** Can run both app and tests in containers  

## Troubleshooting

### Issue: Tests fail with "baseURL is not set"
**Solution:** Ensure you're passing the base URL via CLI or environment variable.

### Issue: Login test fails
**Solution:** Verify the application is running and credentials are correct (demouser/fashion123).

### Issue: GitHub PR scraper fails
**Solution:** Check if GitHub page structure has changed. May need to update selectors.

### Issue: Docker container won't start
**Solution:** Ensure port 4000 is not in use: `lsof -i :4000` (Mac/Linux) or `netstat -ano | findstr :4000` (Windows)

## Author

Xavier Gonzalez Arriola Liza  
Email: xavier.gonzalez.arriola.liza@gmail.com  
GitHub: [@xaviergonzalezarriolaliza](https://github.com/xaviergonzalezarriolaliza)

## License

ISC
