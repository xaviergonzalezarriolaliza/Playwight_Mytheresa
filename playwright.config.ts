import { defineConfig, devices } from '@playwright/test';

// Helper functions for timestamped reports
function pad(n: number) { return String(n).padStart(2, '0'); }
function timestamp() {
  const d = new Date();
  return `${d.getFullYear()}-${pad(d.getMonth() + 1)}-${pad(d.getDate())}_${pad(d.getHours())}-${pad(d.getMinutes())}-${pad(d.getSeconds())}`;
}
function safeSegment(s?: string) {
  return (s || '')
    .trim()
    .replace(/\s+/g, '-')
    .replace(/[^a-zA-Z0-9._-]/g, '')
    .toLowerCase();
}

function selectedProjectsHintFromArgv() {
  const args = process.argv.slice(2);
  const picked: string[] = [];
  for (let i = 0; i < args.length; i++) {
    const a = args[i];
    if (a.startsWith('--project=')) {
      const val = a.substring('--project='.length);
      if (val) picked.push(val);
    } else if (a === '--project') {
      const next = args[i + 1];
      if (next && !next.startsWith('-')) {
        picked.push(next);
        i++;
      }
    }
  }
  if (picked.length === 0) return 'all';
  return picked.map(safeSegment).join('+');
}

const reportLabel = safeSegment(process.env.REPORT_LABEL);
const browsersHint = safeSegment(process.env.REPORT_BROWSERS) || selectedProjectsHintFromArgv();
const reportBase = `reports/${timestamp()}${reportLabel ? '_' + reportLabel : ''}_${browsersHint}`;

// Environment configuration with CLI args taking precedence over env vars
function getBaseURL(): string {
  // Check CLI args first (--base-url=...)
  const baseUrlArg = process.argv.find(arg => arg.startsWith('--base-url='));
  if (baseUrlArg) {
    return baseUrlArg.split('=')[1];
  }
  
  // Check environment variable
  if (process.env.BASE_URL) {
    return process.env.BASE_URL;
  }
  
  // Default to production
  return 'https://pocketaces2.github.io/fashionhub/';
}

export default defineConfig({
  testDir: './tests',
  timeout: 30_000,
  expect: {
    timeout: 5000,
  },
  fullyParallel: true,
  forbidOnly: !!process.env.CI,
  retries: process.env.CI ? 2 : 0,
  workers: process.env.CI ? 1 : undefined,
  reporter: [
    ['list'],
    ['html', { outputFolder: `${reportBase}/html`, open: 'never' }],
    ['junit', { outputFile: `${reportBase}/junit.xml` }],
  ],
  use: {
    baseURL: getBaseURL(),
    headless: true,
    viewport: { width: 1280, height: 720 },
    actionTimeout: 10000,
    trace: 'on', // Always capture trace for comprehensive reporting
    screenshot: 'on', // Always capture screenshots
    video: {
      mode: 'on',
      size: { width: 1280, height: 720 }
    },
  },
  projects: [
    {
      name: 'chromium',
      use: { ...devices['Desktop Chrome'] },
    },
    {
      name: 'firefox',
      use: { ...devices['Desktop Firefox'] },
    },
    {
      name: 'webkit',
      use: { ...devices['Desktop Safari'] },
    },
  ],
});
