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
    page.on('console', msg => {
      if (msg.type() === 'error') {
        const loc = msg.location?.() as any;
        const locStr = loc && loc.url ? ` @ ${loc.url}:${loc.lineNumber || '?'}` : '';
        strategy1Errors.push(`${msg.text()}${locStr}`);
      }
    });
    page.on('pageerror', error => {
      strategy1Errors.push(`PageError: ${error.message}`);
    });

    await page.goto('/');
    await page.waitForLoadState('networkidle');
    await page.waitForTimeout(500); // Let async errors surface
    
    console.log(`[${browserName}] === STRATEGY 1: Playwright Event Listeners ===`);
    console.log(`[${browserName}] Captures: console.error + unhandled exceptions`);
    console.log(`[${browserName}] Errors found: ${strategy1Errors.length}`);
    if (strategy1Errors.length > 0) {
      strategy1Errors.forEach((err, i) => console.log(`[${browserName}]   ${i + 1}. ${err}`));
    }

    // STRATEGY 2: Chrome DevTools Protocol (Browser-Level Comprehensive)
    // Only run CDP on Chromium-based browsers
    let strategy2Errors: string[] = [];
    const projectName = test.info().project.name.toLowerCase();
    const isChromiumBased = projectName.includes('chromium') || projectName.includes('chrome') || projectName.includes('edge');
    
    if (isChromiumBased) {
      try {
        const client = await page.context().newCDPSession(page);
        await client.send('Log.enable');
        
        const cdpErrors: string[] = [];
        client.on('Log.entryAdded', (entry: any) => {
          if (entry.entry && entry.entry.level === 'error') {
            cdpErrors.push(`${entry.entry.text || entry.entry.source || 'Unknown error'}`);
          }
        });
        
        await page.goto('/');
        await page.waitForLoadState('networkidle');
        await page.waitForTimeout(500);
        
        strategy2Errors = cdpErrors;
        
        console.log(`[${browserName}] === STRATEGY 2: Chrome DevTools Protocol (CDP) ===`);
        console.log(`[${browserName}] Captures: Browser-level logs, security violations, deprecations`);
        console.log(`[${browserName}] Errors found: ${strategy2Errors.length}`);
        if (strategy2Errors.length > 0) {
          strategy2Errors.forEach((err, i) => console.log(`[${browserName}]   ${i + 1}. ${err}`));
        }
      } catch (error) {
        console.log(`[${browserName}] CDP not available (non-Chromium browser)`);
      }
    } else {
      console.log(`[${browserName}] === STRATEGY 2: CDP skipped (Firefox/WebKit) ===`);
      console.log(`[${browserName}] CDP is Chromium-only; using Strategy 1 results`);
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
