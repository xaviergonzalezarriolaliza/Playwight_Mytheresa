import { test, expect } from '@playwright/test';

test.describe('Test Case 1: Console Error Detection', () => {
  type LoggedError = { message: string; source: 'console' | 'pageerror' };
  let consoleErrors: LoggedError[] = [];
  
  // Treat some known browser noise as benign (esp. Firefox CSP favicon noise)
  function isBenignConsoleError(message: string): boolean {
    const m = message.toLowerCase();
    return (
      m.includes('failed to load resource') ||
      m.includes('404') ||
      m.includes('content-security-policy') ||
      m.includes('favicon') ||
      m.includes('faviconloader.sys.mjs') ||
      // Sometimes browsers log blocked resource due to CSP/img-src
      m.includes('blocked the loading of a resource') ||
      m.includes('img-src')
    );
  }
  
  test.beforeEach(async ({ page }) => {
    consoleErrors = [];

    // Listen for console errors
    page.on('console', msg => {
      if (msg.type() === 'error') {
        const loc = msg.location?.() as any;
        const locStr = loc && loc.url ? ` @ ${loc.url}${typeof loc.lineNumber === 'number' ? `:${loc.lineNumber}` : ''}` : '';
        consoleErrors.push({ message: `${msg.text()}${locStr}`, source: 'console' });
      }
    });

    // Listen for page errors
    page.on('pageerror', error => {
      consoleErrors.push({ message: `Page Error: ${error.message}`, source: 'pageerror' });
    });
  });

  test('should detect any console errors on homepage', async ({ page }) => {
    await page.goto('/');
    await page.waitForLoadState('networkidle');
    
    // Report console errors found
    const browserName = test.info().project.name;
    console.log(`[${browserName}] Console errors on homepage: ${consoleErrors.length}`);
    if (consoleErrors.length > 0) {
      console.log(`[${browserName}] Errors detected:`);
      consoleErrors.forEach((entry, index) => console.log(`[${browserName}]   ${index + 1}. ${entry.message}`));
    }
    
    // For demonstration: we log errors but don't fail if there are only 404s
    // In production, you might want to fail on any console error
  const criticalErrors = consoleErrors.filter(e => !isBenignConsoleError(e.message)).map(e => e.message);
    
    expect(criticalErrors, `Critical console errors found: ${criticalErrors.join(', ')}`).toHaveLength(0);
  });

  test('should detect console errors on about page (intentional error)', async ({ page }) => {
    await page.goto('/about.html');
    await page.waitForLoadState('networkidle');
    
    // This test expects errors on the about page
    const browserName = test.info().project.name;
    expect(consoleErrors.length, 'Expected to find console errors on about page').toBeGreaterThan(0);
    console.log(`[${browserName}] Console errors detected on about page:`);
    consoleErrors.forEach((entry, index) => console.log(`[${browserName}]   ${index + 1}. ${entry.message}`));
  });
});
