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

  test('should detect any console errors on homepage - dual strategy validation', async ({ page }) => {
    const browserName = test.info().project.name;
    
    // STRATEGY 1: Playwright Event Listeners (Standard Approach)
    const strategy1Errors: string[] = [];
    const consoleHandler = (msg: any) => {
      if (msg.type() === 'error') {
        const loc = msg.location?.() as any;
        const locStr = loc && loc.url ? ` @ ${loc.url}:${loc.lineNumber || '?'}` : '';
        strategy1Errors.push(`${msg.text()}${locStr}`);
      }
    };
    const pageerrorHandler = (error: Error) => {
      strategy1Errors.push(`PageError: ${error.message}`);
    };
    
    page.on('console', consoleHandler);
    page.on('pageerror', pageerrorHandler);

    // STRATEGY 2: Request Failure Monitoring (Cross-Browser Compatible)
    const strategy2Errors: string[] = [];
    
    const requestfailedHandler = (request: any) => {
      const failure = request.failure();
      strategy2Errors.push(`Request failed: ${request.url()} - ${failure?.errorText || 'Unknown error'}`);
    };
    
    const responseHandler = (response: any) => {
      // Capture HTTP errors (4xx, 5xx)
      if (response.status() >= 400) {
        strategy2Errors.push(`HTTP ${response.status()}: ${response.url()}`);
      }
    };
    
    page.on('requestfailed', requestfailedHandler);
    page.on('response', responseHandler);

    // Single page load for both strategies
    await page.goto('/', { timeout: 60000 });
    await page.waitForLoadState('networkidle');
    await page.waitForTimeout(500); // Let async errors surface
    
    // Remove listeners to prevent teardown issues
    page.off('console', consoleHandler);
    page.off('pageerror', pageerrorHandler);
    page.off('requestfailed', requestfailedHandler);
    page.off('response', responseHandler);
    
    console.log(`[${browserName}] === STRATEGY 1: Playwright Event Listeners ===`);
    console.log(`[${browserName}] Captures: console.error + unhandled exceptions`);
    console.log(`[${browserName}] Errors found: ${strategy1Errors.length}`);
    if (strategy1Errors.length > 0) {
      strategy1Errors.forEach((err, i) => console.log(`[${browserName}]   ${i + 1}. ${err}`));
    }
    
    console.log(`[${browserName}] === STRATEGY 2: Request Failure Monitoring ===`);
    console.log(`[${browserName}] Captures: Failed network requests, HTTP errors (4xx, 5xx)`);
    console.log(`[${browserName}] Errors found: ${strategy2Errors.length}`);
    if (strategy2Errors.length > 0) {
      strategy2Errors.forEach((err, i) => console.log(`[${browserName}]   ${i + 1}. ${err}`));
    }

    // Consolidate and validate
    const allErrors = [...strategy1Errors, ...strategy2Errors];
    const uniqueErrors = [...new Set(allErrors)]; // Deduplicate
    
    console.log(`[${browserName}] === CONSOLIDATED RESULTS ===`);
    console.log(`[${browserName}] Total unique errors: ${uniqueErrors.length}`);
    console.log(`[${browserName}]   Strategy 1: ${strategy1Errors.length}`);
    console.log(`[${browserName}]   Strategy 2: ${strategy2Errors.length}`);
    
    // Filter benign errors
    const criticalErrors = uniqueErrors.filter(e => !isBenignConsoleError(e));
    
    console.log(`[${browserName}] Critical errors (after filtering benign): ${criticalErrors.length}`);
    if (criticalErrors.length > 0) {
      console.log(`[${browserName}] Critical errors:`);
      criticalErrors.forEach((err, i) => console.log(`[${browserName}]   ${i + 1}. ${err}`));
    }
    
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
