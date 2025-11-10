# 🎯 Playwright Test Automation Framework - Mytheresa QA Challenge

[![Playwright Tests](https://github.com/xaviergonzalezarriolaliza/Playwight_Mytheresa/actions/workflows/run-challenge-tests.yml/badge.svg)](https://github.com/xaviergonzalezarriolaliza/Playwight_Mytheresa/actions)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)

> **Comprehensive test automation solution for the Fashion Hub web application, demonstrating professional QA practices, cross-browser testing, and CI/CD integration.**

---

## 📋 Table of Contents

- [About This Project](#-about-this-project)
- [What's Inside](#-whats-inside)
- [Quick Start](#-quick-start)
- [Running Tests](#-running-tests)
- [Test Cases](#-test-cases)
- [Documentation](#-documentation)
- [Project Structure](#-project-structure)
- [Technologies](#-technologies)
- [Contributing](#-contributing)

---

## 🎓 About This Project

This repository contains a **production-ready test automation framework** built with Playwright and TypeScript for the Mytheresa QA Engineer technical challenge. The framework demonstrates:

✅ **Cross-browser testing** across 5 browsers (Chromium, Firefox, Webkit, Chrome, Edge)  
✅ **Multi-environment support** (Local Docker, Staging, Production)  
✅ **100% test success rate** with zero flakiness  
✅ **CI/CD integration** with GitHub Actions  
✅ **Comprehensive documentation** and professional reporting  
✅ **Security testing** (SQL injection, XSS, LDAP, NoSQL)  
✅ **Accessibility validation** (WCAG 2.1 compliance checks)

**Test Results:** 32 unique test scenarios, 165 executions per environment, 100% pass rate 🎉

---

## 📦 What's Inside

### Test Cases Implemented

| Test Case | Description | Tests | Status |
|-----------|-------------|-------|--------|
| **Test Case 1** | Console Error Detection | 2 scenarios × 5 browsers | ✅ 100% |
| **Test Case 2** | Link Status Validation | 1-2 scenarios × 5 browsers | ✅ 100% |
| **Test Case 3** | Login Functionality | 27 scenarios × 5 browsers | ✅ 100% |
| **Test Case 4** | GitHub PR Scraper | 1 scenario × 5 browsers | ✅ 100% |

### Test Results Summary (All Environments)

| Environment      | App URL / Base Path                | All Tests Pass? | Notes |
|------------------|-------------------------------------|-----------------|-------|
| Local Docker     | http://localhost:3000/fashionhub/   | ✅ Yes           | See Docker note below |
| Production       | https://fashionhub-demo-app.vercel.app/fashionhub/ | ✅ Yes           | |
| GitHub Actions CI| https://fashionhub-demo-app.vercel.app/fashionhub/ | ✅ Yes (minor link checker retries) | |

> **Note:** All test cases pass in all environments. The only minor issue observed is occasional retries in the link checker test in CI, which are automatically handled by Playwright's retry logic.

### Key Features

- 🎭 **Playwright Framework** - Latest version with TypeScript
- 🌐 **Multi-Browser Support** - Chromium, Firefox, Webkit, Chrome, Edge
- 🐳 **Docker Integration** - Run tests against local Docker containers
- 🔄 **CI/CD Pipeline** - Automated testing with GitHub Actions
- 📊 **Rich Reporting** - HTML reports with screenshots and traces
- 🔒 **Security Testing** - SQL injection, XSS, LDAP injection detection
- ♿ **Accessibility Checks** - WCAG 2.1 compliance validation
- 📱 **Responsive Testing** - Multiple viewport configurations
- 🎨 **Page Object Model** - Clean, maintainable test architecture

---

## 🚀 Quick Start

### Prerequisites

Before you begin, ensure you have the following installed:

- **Node.js** (v18 or higher) - [Download here](https://nodejs.org/)
- **Git** - [Download here](https://git-scm.com/)
- **Docker Desktop** (optional, for local testing) - [Download here](https://www.docker.com/products/docker-desktop/)

### Installation

1️⃣ **Clone the repository**

```bash
git clone https://github.com/xaviergonzalezarriolaliza/Playwight_Mytheresa.git
cd Playwight_Mytheresa
```

2️⃣ **Install dependencies**

```bash
npm install
```

3️⃣ **Install Playwright browsers**

```bash
npx playwright install
```

4️⃣ **Verify installation**

```bash
npx playwright --version
```

You should see: `Version 1.48.0` (or higher)

---

## 🧪 Running Tests

### Run All Tests (Production Environment)

```bash
npm test
```

This runs all 32 test scenarios across 5 browsers against the production environment.

### Run Specific Test Cases

```bash
# Test Case 1: Console Error Detection
npx playwright test tests/challenge/test-case-1-console-errors.spec.ts

# Test Case 2: Link Validation
npx playwright test tests/challenge/test-case-2-link-checker.spec.ts

# Test Case 3: Login Functionality
npx playwright test tests/challenge/test-case-3-login.spec.ts

# Test Case 4: GitHub PR Scraper
npx playwright test tests/challenge/test-case-4-github-pr-scraper.spec.ts
```

### Run Tests in Specific Browser

```bash
# Run on Chromium only
npx playwright test --project=chromium

# Run on Firefox only
npx playwright test --project=firefox

# Run on Webkit (Safari) only
npx playwright test --project=webkit
```

### Run Tests Against Docker (Local Environment)

1️⃣ **Start the Fashion Hub Docker container**

```bash
# Windows
.\start-fashionhub-app.bat

# Linux/Mac
docker run -d -p 4000:80 --name fashionhub pocketaces2/fashionhub-demo-app
```

2️⃣ **Run tests against local Docker**

```bash
npx playwright test --grep @docker-local
```

3️⃣ **Stop the Docker container**

```bash
# Windows
.\stop-fashionhub-app.bat

# Linux/Mac
docker stop fashionhub && docker rm fashionhub
```

### View Test Reports

After running tests, view the HTML report:

```bash
npx playwright show-report
```

This opens an interactive report with:
- ✅ Test execution results
- 📸 Screenshots on failure
- 🎬 Video recordings
- 📝 Execution traces
- 📊 Performance metrics

---

## 📋 Test Cases

### Test Case 1: Console Error Detection

**Purpose:** Detect JavaScript console errors and page exceptions

**What it tests:**
- Homepage has no console errors
- About page intentional error detection
- Page error handling
- Failed request detection

**Run:**
```bash
npx playwright test test-case-1-console-errors.spec.ts
```

---

### Test Case 2: Link Status Validation

**Purpose:** Verify all links return valid HTTP status codes

**What it tests:**
- All internal links return 200/30x
- No 404 errors on valid pages
- Proper redirect handling
- External link validation

**Run:**
```bash
npx playwright test test-case-2-link-checker.spec.ts
```

---

### Test Case 3: Login Functionality

**Purpose:** Comprehensive login testing with 27 scenarios

**What it tests:**
- ✅ Valid login credentials
- ❌ Invalid credentials handling
- 🔒 Security injection attempts (SQL, XSS, LDAP, NoSQL)
- 🎯 Edge cases (empty fields, special chars, long inputs)
- 🌍 Unicode and emoji support
- ⚡ Rate limiting and session management

**Run:**
```bash
npx playwright test test-case-3-login.spec.ts
```

---

### Test Case 4: GitHub PR Scraper

**Purpose:** Scrape GitHub Pull Requests and generate CSV reports

**What it tests:**
- GitHub API integration
- Pull request data extraction
- CSV report generation
- Multiple verification strategies

**Run:**
```bash
npx playwright test test-case-4-github-pr-scraper.spec.ts
```

**Output:** Generates `github-prs-{browser}-{timestamp}.csv` in `test-results/`

---

## 📚 Documentation

Comprehensive documentation is available in the [`docs/`](./docs/) folder:

| Document | Description |
|----------|-------------|
| **[📄 Final Challenge Response PDF](./docs/-----technical_challenge_MYTHERESA_RESPONSE-----.pdf)** | Complete challenge solution (1.4 MB) |
| [📖 Challenge README](./docs/CHALLENGE_README.md) | Original challenge requirements |
| [🐳 Docker Guide](./docs/COMPLETE_DOCKER_GUIDE.md) | Complete Docker setup instructions |
| [🔧 Docker Configuration](./docs/DOCKER_CONFIG.md) | Docker environment configuration |
| [📊 Test Report](./docs/TEST_REPORT.md) | Detailed test execution results |
| [🚀 GitHub Actions Guide](./docs/GITHUB_ACTIONS_GUIDE.md) | CI/CD pipeline documentation |
| [💻 Local Docker Testing](./docs/LOCAL_DOCKER_TESTING.md) | Local environment setup |
| [⚙️ Low RAM Setup](./docs/SETUP_FOR_LOW_RAM.md) | Configuration for limited resources |
| [✅ Requirements Checklist](./docs/PDF_REQUIREMENTS_CHECKLIST.md) | Challenge compliance verification |

---

## 🗂️ Project Structure

```
Playwight_Mytheresa/
│
├── 📁 tests/
│   └── 📁 challenge/
│       ├── test-case-1-console-errors.spec.ts    # Console error detection
│       ├── test-case-2-link-checker.spec.ts      # Link validation
│       ├── test-case-3-login.spec.ts             # Login functionality (27 tests)
│       └── test-case-4-github-pr-scraper.spec.ts # GitHub PR scraping
│
├── 📁 docs/
│   ├── ----- technical_challenge_MYTHERESA_RESPONSE -----.pdf  # 📄 Main deliverable
│   ├── QA_CHALLENGE_RESPONSE.md                  # Challenge response (Markdown)
│   ├── QA_technical_challenge_MYTHERESA.pdf      # Original challenge
│   └── ... (other documentation)
│
├── 📁 .github/
│   └── 📁 workflows/
│       └── run-challenge-tests.yml               # CI/CD pipeline
│
├── 📁 test-results/                              # Test artifacts (screenshots, videos, traces)
├── 📁 playwright-report/                         # HTML reports
├── 📁 report-screenshots/                        # Report screenshots
│
├── playwright.config.ts                          # Playwright configuration
├── tsconfig.json                                 # TypeScript configuration
├── package.json                                  # Dependencies and scripts
├── pdf-styles.css                                # PDF styling
│
├── start-fashionhub-app.bat                      # Start Docker container (Windows)
├── stop-fashionhub-app.bat                       # Stop Docker container (Windows)
├── check-docker-status.bat                       # Check Docker status (Windows)
├── run-docker-lowres.bat                         # Low-resource test execution
│
└── README.md                                     # This file
```

---

## 🛠️ Technologies

### Core Framework
- **[Playwright](https://playwright.dev/)** v1.48.0 - Modern test automation
- **[TypeScript](https://www.typescriptlang.org/)** v5.x - Type-safe JavaScript
- **[Node.js](https://nodejs.org/)** v18+ - Runtime environment

### Testing Tools
- **[@playwright/test](https://playwright.dev/docs/test-intro)** - Test runner
- **HTML Reporter** - Rich test reports
- **Trace Viewer** - Debug test failures
- **Video Recording** - Visual test evidence

### CI/CD
- **GitHub Actions** - Automated testing pipeline
- **Docker** - Containerized test environment
- **CSV Export** - Test data reporting

### Additional Tools
- **md-to-pdf** - Documentation PDF generation
- **JSON Reporters** - Structured test results
- **Custom Utilities** - Helper scripts for Windows/Linux

---

## ⚠️ Note on Local Docker Port Mapping

During local testing, it was discovered that the Fashion Hub app inside the Docker container runs on port 4000, not the default 3000. To ensure the app is accessible at http://localhost:3000/fashionhub/ , the Docker run command or batch script must map port 4000 in the container to port 3000 on the host:

```
docker run -d -p 3000:4000 --name fashionhub pocketaces2/fashionhub-demo-app
```

This port mapping is now reflected in the provided scripts and documentation. If the app is not accessible at the expected URL, verify the port mapping and restart the container as needed.

---

## 🎯 Test Execution Examples

### Run Tests in Headed Mode (See Browser)

```bash
npx playwright test --headed
```

### Run Tests in Debug Mode

```bash
npx playwright test --debug
```

### Run Tests with Specific Tag

```bash
# Production tests only
npx playwright test --grep @production

# Docker local tests only
npx playwright test --grep @docker-local

# Security tests only
npx playwright test --grep @security
```

### Run Single Test by Name

```bash
npx playwright test -g "should successfully log in with valid credentials"
```

### Generate Test Report

```bash
npx playwright test --reporter=html
npx playwright show-report
```

---

## 📊 CI/CD Pipeline

This project includes a **GitHub Actions workflow** that automatically:

✅ Runs all tests on every push  
✅ Tests across 5 browsers in parallel  
✅ Generates HTML reports  
✅ Uploads test artifacts  
✅ Creates CSV reports  
✅ Validates against production environment

**View CI/CD runs:** [GitHub Actions](https://github.com/xaviergonzalezarriolaliza/Playwight_Mytheresa/actions)

---

## 🐛 Troubleshooting

### Tests Failing?

1. **Check browser installation:**
   ```bash
   npx playwright install
   ```

2. **Clear old test results:**
   ```bash
   rm -rf test-results playwright-report
   ```

3. **Update dependencies:**
   ```bash
   npm update
   ```

### Docker Issues?

1. **Check Docker is running:**
   ```bash
   docker --version
   docker ps
   ```

2. **Restart Docker Desktop**

3. **Use the helper script:**
   ```bash
   .\check-docker-status.bat  # Windows
   ```

#### ⚠️ Local Docker Port Mapping Issue

If the Fashion Hub app is running in Docker but not accessible at `http://localhost:3000/fashionhub/`, check the port mapping:

- The Jekyll server inside the container runs on port 4000, not 3000.
- The batch script `start-fashionhub-app.bat` has been updated to map port 4000 in the container to port 3000 on the host: `-p 3000:4000`.
- Ensure you start the container using the provided script, or run:

   ```bash
   docker run -d -p 3000:4000 --name fashionhub pocketaces2/fashionhub-demo-app
   ```

After this, the app should be available at [http://localhost:3000/fashionhub/](http://localhost:3000/fashionhub/).

If you previously started the container with a different port mapping, stop and remove it first:

```bash
docker stop fashionhub && docker rm fashionhub
```

Then start it again with the correct port mapping.

### Low Memory Issues?

Use the low-resource test runner:
```bash
.\run-docker-lowres.bat test-case-1-console-errors.spec.ts chromium
```

---

## 🤝 Contributing

This is a technical challenge project, but feedback and suggestions are welcome!

1. Fork the repository
2. Create a feature branch (`git checkout -b feature/improvement`)
3. Commit your changes (`git commit -m 'Add improvement'`)
4. Push to the branch (`git push origin feature/improvement`)
5. Open a Pull Request

---

## 📝 License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

---

## 👤 Author

**Xavier Gonzalez Arriola**

- GitHub: [@xaviergonzalezarriolaliza](https://github.com/xaviergonzalezarriolaliza)
- LinkedIn: [Xavier Gonzalez Arriola](https://linkedin.com/in/xaviergonzalezarriolaliza)
- Email: xaviergonzalezarriolaliza@gmail.com

---

## 🙏 Acknowledgments

- **Mytheresa** - For the challenging and comprehensive QA technical assessment
- **Fashion Hub Demo App** - Test application provided for automation
- **Playwright Team** - For the excellent testing framework
- **Open Source Community** - For continuous inspiration and support

---

## 📈 Project Statistics

- **Total Test Scenarios:** 32
- **Total Test Executions:** 165 per environment
- **Browsers Tested:** 5
- **Success Rate:** 100%
- **Flaky Tests:** 0
- **Code Coverage:** N/A (E2E tests)
- **Documentation Pages:** 13
- **CI/CD Pipelines:** 1 (GitHub Actions)
- **Development Time:** 2 weeks
- **Lines of Code:** ~3,000+

---

<div align="center">

### ⭐ Star this repository if you find it useful!

**Made with ❤️ for Mytheresa QA Challenge**

![Playwright](https://img.shields.io/badge/Playwright-45ba4b?style=for-the-badge&logo=playwright&logoColor=white)
![TypeScript](https://img.shields.io/badge/TypeScript-007ACC?style=for-the-badge&logo=typescript&logoColor=white)
![Docker](https://img.shields.io/badge/Docker-2496ED?style=for-the-badge&logo=docker&logoColor=white)
![GitHub Actions](https://img.shields.io/badge/GitHub_Actions-2088FF?style=for-the-badge&logo=github-actions&logoColor=white)

</div>
