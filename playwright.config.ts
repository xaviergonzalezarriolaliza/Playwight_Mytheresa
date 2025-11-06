import { defineConfig, devices } from '@playwright/test';

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
    ['html', { outputFolder: 'playwright-report', open: 'never' }],
    ['junit', { outputFile: 'test-results/junit.xml' }],
  ],
  use: {
    baseURL: getBaseURL(),
    headless: true,
    viewport: { width: 1280, height: 720 },
    actionTimeout: 10000,
    trace: 'retain-on-failure',
    screenshot: 'only-on-failure',
    video: 'retain-on-failure',
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
