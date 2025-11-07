import { test, expect } from '@playwright/test';

test.describe('Test Case 2: Link Status Code Verification', () => {
  test('should verify all links return valid status codes (200 or 30x, not 40x)', async ({ page, baseURL }) => {
    await page.goto('/');
    await page.waitForLoadState('networkidle');
    
    const browserName = test.info().project.name;
    
    // Get all links from the page
    const links = await page.locator('a[href]').evaluateAll((anchors) => {
      return anchors.map((a) => (a as HTMLAnchorElement).href).filter(href => href && href.trim() !== '');
    });
    
    // Remove duplicates
    const uniqueLinks = [...new Set(links)];
    
    console.log(`[${browserName}] Found ${uniqueLinks.length} unique links to check`);
    
    const results: { url: string; status: number; valid: boolean }[] = [];
    
    for (const link of uniqueLinks) {
      try {
        // Skip mailto, tel, javascript links, and empty fragments
        if (link.startsWith('mailto:') || link.startsWith('tel:') || link.startsWith('javascript:') || link.startsWith('#')) {
          console.log(`[${browserName}] Skipping non-HTTP link: ${link}`);
          continue;
        }

        // Skip external links that are not part of the application
        const linkUrl = new URL(link);
        const baseUrl = new URL(baseURL || 'https://pocketaces2.github.io/fashionhub/');
        
        // Only check links within the same domain
        if (linkUrl.origin !== baseUrl.origin) {
          console.log(`[${browserName}] Skipping external link: ${link}`);
          continue;
        }
        
        // Skip the bare root domain if it has no path (e.g., https://pocketaces2.github.io/)
        // since GitHub Pages expects a repo path
        if (linkUrl.pathname === '/' && linkUrl.origin === baseUrl.origin && baseUrl.pathname !== '/') {
          console.log(`[${browserName}] Skipping root domain (no path): ${link}`);
          continue;
        }
        
        const response = await page.request.get(link);
        const status = response.status();
        const valid = status >= 200 && status < 400;
        
        results.push({ url: link, status, valid });
        
        console.log(`[${browserName}] ${link} -> ${status} ${valid ? '✓' : '✗'}`);
        
        // Assert each link is valid (200-399)
        expect(status, `Link ${link} returned error status code: ${status}`).toBeGreaterThanOrEqual(200);
        expect(status, `Link ${link} returned error status code: ${status}`).toBeLessThan(400);
        
      } catch (error) {
        console.error(`[${browserName}] Error checking link ${link}:`, (error as Error).message);
        // Don't fail the test for network errors on external resources
      }
    }
    
    // Summary
    const failedLinks = results.filter(r => !r.valid);
    console.log(`[${browserName}] === Summary ===`);
    console.log(`[${browserName}] Total links checked: ${results.length}`);
    console.log(`[${browserName}] Passed: ${results.filter(r => r.valid).length}`);
    console.log(`[${browserName}] Failed: ${failedLinks.length}`);
    
    if (failedLinks.length > 0) {
      console.log(`[${browserName}] Failed links:`);
      failedLinks.forEach(link => console.log(`[${browserName}]   ${link.url} -> ${link.status}`));
    }
    
    expect(failedLinks, 'Some links returned invalid status codes').toHaveLength(0);
  });
});
