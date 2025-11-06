import { test, expect, Page } from '@playwright/test';

test.describe('Test Case 1: Console Error Detection', () => {
  let consoleErrors: string[] = [];
  
  test.beforeEach(async ({ page }) => {
    consoleErrors = [];
    
    // Listen for console errors
    page.on('console', msg => {
      if (msg.type() === 'error') {
        consoleErrors.push(`${msg.text()}`);
      }
    });
    
    // Listen for page errors
    page.on('pageerror', error => {
      consoleErrors.push(`Page Error: ${error.message}`);
    });
  });

  test('should detect any console errors on homepage', async ({ page }) => {
    await page.goto('/');
    await page.waitForLoadState('networkidle');
    
    // Report console errors found
    console.log(`Console errors on homepage: ${consoleErrors.length}`);
    if (consoleErrors.length > 0) {
      console.log('Errors detected:');
      consoleErrors.forEach((error, index) => console.log(`  ${index + 1}. ${error}`));
    }
    
    // For demonstration: we log errors but don't fail if there are only 404s
    // In production, you might want to fail on any console error
    const criticalErrors = consoleErrors.filter(err => 
      !err.includes('404') && !err.includes('Failed to load resource')
    );
    
    expect(criticalErrors, `Critical console errors found: ${criticalErrors.join(', ')}`).toHaveLength(0);
  });

  test('should detect console errors on about page (intentional error)', async ({ page }) => {
    await page.goto('/about.html');
    await page.waitForLoadState('networkidle');
    
    // This test expects errors on the about page
    expect(consoleErrors.length, 'Expected to find console errors on about page').toBeGreaterThan(0);
    console.log('Console errors detected on about page:', consoleErrors);
  });
});
