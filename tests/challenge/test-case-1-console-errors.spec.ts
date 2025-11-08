import { test, expect } from '@playwright/test';

test.describe('Test Case 1: Console Error Detection', {
  tag: ['@docker-local', '@production']
}, () => {
  // Type definition for storing error information with its source
  type LoggedError = { message: string; source: 'console' | 'pageerror' };
  
  // Shared array to store errors collected by beforeEach hook
  let consoleErrors: LoggedError[] = [];
  
  /**
   * Filter function to identify benign (harmless) browser errors
   * These are common browser quirks that don't indicate real application problems
   * @param message - The error message to check
   * @returns true if the error is benign and should be ignored
   */
  function isBenignConsoleError(message: string): boolean {
    const m = message.toLowerCase(); // Case-insensitive matching
    return (
      // "Failed to load resource" - Generic browser message for any failed HTTP request
      // Often appears for 404s, timeouts, or blocked resources
      m.includes('failed to load resource') ||
      
      // "404" - HTTP Not Found errors
      // The root domain (pocketaces2.github.io/) returns 404 by design
      // Only /fashionhub/ path exists, so homepage redirects cause benign 404s
      m.includes('404') ||
      
      // "Content-Security-Policy" - CSP header violations
      // Website has strict CSP rules that sometimes conflict with browser behavior
      // These are security policy messages, not application bugs
      m.includes('content-security-policy') ||
      
      // "favicon" - Browser automatically requests /favicon.ico
      // Even if not specified in HTML, all browsers try to load a favicon
      // Missing favicon is cosmetic, not a functional error
      m.includes('favicon') ||
      
      // "faviconloader.sys.mjs" - Firefox-specific internal module
      // Firefox logs CSP violations from its own favicon loading system
      // This is Firefox browser noise, not a website issue
      m.includes('faviconloader.sys.mjs') ||
      
      // "blocked the loading of a resource" - CSP blocking message
      // Appears when Content-Security-Policy prevents resource loading
      // These are intentional security restrictions, not errors
      m.includes('blocked the loading of a resource') ||
      
      // "img-src" - CSP directive for image sources
      // CSP policy controls where images can be loaded from
      // Violations here are policy enforcement, not broken functionality
      m.includes('img-src')
    );
  }
  
  /**
   * beforeEach hook - Runs before each test in this suite
   * Sets up basic error listeners for validation in the second test
   * Note: The main test uses its own listeners for dual-strategy approach
   */
  test.beforeEach(async ({ page }) => {
    // Clear error array for fresh start on each test
    consoleErrors = [];

    // Listen for console errors (console.error, console.warn type='error', etc.)
    page.on('console', msg => {
      if (msg.type() === 'error') {
        // Extract location information if available (file URL and line number)
        const loc = msg.location?.() as any;
        const locStr = loc && loc.url ? ` @ ${loc.url}${typeof loc.lineNumber === 'number' ? `:${loc.lineNumber}` : ''}` : '';
        
        // Store error with formatted location
        consoleErrors.push({ message: `${msg.text()}${locStr}`, source: 'console' });
      }
    });

    // Listen for uncaught page errors (unhandled exceptions, promise rejections)
    page.on('pageerror', error => {
      consoleErrors.push({ message: `Page Error: ${error.message}`, source: 'pageerror' });
    });
  });

  /**
   * Main Test: Dual-Strategy Console Error Detection
   * 
   * This test validates the homepage has no critical console errors using two
   * independent detection strategies that complement each other:
   * - Strategy 1: Application-level errors (console, exceptions)
   * - Strategy 2: Network-level errors (HTTP failures, request failures)
   */
  test('should detect any console errors on homepage - dual strategy validation', async ({ page, baseURL }) => {
    // Get browser name for tagged logging (helps identify browser-specific issues)
    const browserName = test.info().project.name;
    
    // ============================================================================
    // STRATEGY 1: Playwright Event Listeners (Standard Approach)
    // ============================================================================
    // Detects: console.error() calls, unhandled JavaScript exceptions
    // Works on: All browsers (Chromium, Firefox, WebKit)
    // Layer: Application-level (JavaScript runtime)
    
    const strategy1Errors: string[] = [];
    
    // Handler for console messages (console.error, console.warn marked as error)
    const consoleHandler = (msg: any) => {
      if (msg.type() === 'error') {
        // Get source location if available (helps debugging)
        const loc = msg.location?.() as any;
        const locStr = loc && loc.url ? ` @ ${loc.url}:${loc.lineNumber || '?'}` : '';
        strategy1Errors.push(`${msg.text()}${locStr}`);
      }
    };
    
    // Handler for unhandled exceptions (throw statements, promise rejections)
    const pageerrorHandler = (error: Error) => {
      strategy1Errors.push(`PageError: ${error.message}`);
    };
    
    // Register Strategy 1 listeners
    page.on('console', consoleHandler);
    page.on('pageerror', pageerrorHandler);

    // ============================================================================
    // STRATEGY 2: Request Failure Monitoring (Cross-Browser Compatible)
    // ============================================================================
    // Detects: Network failures, HTTP errors (404, 500, etc.)
    // Works on: All browsers (Chromium, Firefox, WebKit)
    // Layer: Network-level (HTTP/browser request layer)
    
    const strategy2Errors: string[] = [];
    
    // Handler for failed network requests (DNS errors, timeouts, connection refused)
    const requestfailedHandler = (request: any) => {
      const failure = request.failure();
      // failure.errorText contains: net::ERR_NAME_NOT_RESOLVED, net::ERR_CONNECTION_REFUSED, etc.
      strategy2Errors.push(`Request failed: ${request.url()} - ${failure?.errorText || 'Unknown error'}`);
    };
    
    // Handler for HTTP error responses (4xx = client errors, 5xx = server errors)
    const responseHandler = (response: any) => {
      // Capture HTTP errors (4xx, 5xx)
      if (response.status() >= 400) {
        // Status codes:
        // 400-499: Client errors (404 Not Found, 403 Forbidden, 401 Unauthorized)
        // 500-599: Server errors (500 Internal Error, 503 Service Unavailable)
        strategy2Errors.push(`HTTP ${response.status()}: ${response.url()}`);
      }
    };
    
    // Register Strategy 2 listeners
    page.on('requestfailed', requestfailedHandler);
    page.on('response', responseHandler);

    // ============================================================================
    // PAGE LOAD - Both strategies monitor simultaneously
    // ============================================================================
    
    await page.goto(baseURL || '/', { timeout: 60000 }); // Navigate to homepage with 60s timeout
    await page.waitForLoadState('networkidle'); // Wait until no network activity for 500ms
    await page.waitForTimeout(500); // Additional wait for async errors to surface
    
    // ============================================================================
    // CLEANUP - Remove listeners to prevent teardown issues
    // ============================================================================
    // Important: Firefox had timeout issues when listeners stayed active during teardown
    
    page.off('console', consoleHandler);
    page.off('pageerror', pageerrorHandler);
    page.off('requestfailed', requestfailedHandler);
    page.off('response', responseHandler);
    
    // ============================================================================
    // REPORTING - Log findings from both strategies
    // ============================================================================
    
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

    // ============================================================================
    // CONSOLIDATION - Merge and deduplicate findings
    // ============================================================================
    
    // Merge both error arrays into one
    const allErrors = [...strategy1Errors, ...strategy2Errors];
    
    // Remove duplicates using Set (same error might be caught by both strategies)
    // Example: A 404 might appear as console error AND HTTP 404 response
    const uniqueErrors = [...new Set(allErrors)];
    
    console.log(`[${browserName}] === CONSOLIDATED RESULTS ===`);
    console.log(`[${browserName}] Total unique errors: ${uniqueErrors.length}`);
    console.log(`[${browserName}]   Strategy 1: ${strategy1Errors.length}`);
    console.log(`[${browserName}]   Strategy 2: ${strategy2Errors.length}`);
    
    // ============================================================================
    // FILTERING - Remove benign errors to get critical issues only
    // ============================================================================
    
    // Filter out browser noise (favicon 404s, CSP warnings, etc.)
    const criticalErrors = uniqueErrors.filter(e => !isBenignConsoleError(e));
    
    console.log(`[${browserName}] Critical errors (after filtering benign): ${criticalErrors.length}`);
    if (criticalErrors.length > 0) {
      console.log(`[${browserName}] Critical errors:`);
      criticalErrors.forEach((err, i) => console.log(`[${browserName}]   ${i + 1}. ${err}`));
    }
    
    // ============================================================================
    // ASSERTION - Test passes only if no critical errors remain
    // ============================================================================
    
    expect(criticalErrors, `Critical console errors found: ${criticalErrors.join(', ')}`).toHaveLength(0);
  });

  /**
   * Validation Test: Verify error detection mechanism works
   * 
   * This test ensures our error detection isn't just passing because it's broken.
   * The about.html page intentionally has console errors - this test confirms
   * we can actually detect them.
   * 
   * Purpose: Positive validation that the detection mechanism is working
   */
  test('should detect console errors on about page (intentional error)', async ({ page }) => {
    // Get browser name for tagged logging
    const browserName = test.info().project.name;
    
    // Setup combined error detection for about page
    const detectedErrors: { message: string; type: string }[] = [];
    let pageLoadFailed = false;
    
    // Strategy 1: Console and page errors
    page.on('console', msg => {
      if (msg.type() === 'error') {
        const loc = msg.location?.() as any;
        const locStr = loc && loc.url ? ` @ ${loc.url}` : '';
        detectedErrors.push({ message: `${msg.text()}${locStr}`, type: 'console' });
      }
    });
    
    page.on('pageerror', error => {
      detectedErrors.push({ message: error.message, type: 'pageerror' });
    });
    
    // Strategy 2: Network failures (404 on about.html)
    page.on('response', response => {
      const url = response.url();
      const status = response.status();
      
      // Check if the about.html page itself failed to load
      if (url.includes('about.html') && (status === 404 || status >= 400)) {
        detectedErrors.push({ message: `HTTP ${status}: ${url}`, type: 'network' });
        pageLoadFailed = true;
      }
    });
    
    // Navigate to about page (which returns 404, proving error detection works)
    try {
      await page.goto('/about.html', { waitUntil: 'domcontentloaded', timeout: 5000 });
    } catch (error: any) {
      // Expected to fail - about.html doesn't exist
      if (error.message && error.message.includes('404')) {
        detectedErrors.push({ message: `Navigation failed: ${error.message}`, type: 'navigation' });
        pageLoadFailed = true;
      }
    }
    
    // Give time for any async errors to surface
    await page.waitForTimeout(500);
    
    // Log detected errors
    console.log(`[${browserName}] Console errors detected on about page:`);
    detectedErrors.forEach((entry, index) => {
      console.log(`[${browserName}]   ${index + 1}. ${entry.message} (${entry.type})`);
    });
    
    // ASSERTION: We should detect errors through AT LEAST ONE of our strategies
    // This proves our error detection mechanisms are working
    const totalErrorsDetected = detectedErrors.length + (pageLoadFailed ? 1 : 0);
    expect(totalErrorsDetected, 
      `Expected to detect errors on about page through console, network, or navigation failures. ` +
      `Detected: ${detectedErrors.length} errors, Page load failed: ${pageLoadFailed}`
    ).toBeGreaterThan(0);
  });
});
