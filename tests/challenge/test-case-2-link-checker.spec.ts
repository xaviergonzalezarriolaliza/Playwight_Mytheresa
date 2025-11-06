import { test, expect } from '@playwright/test';

test.describe('Test Case 2: Link Status Code Verification', () => {
  test('should verify all links return valid status codes (200 or 30x, not 40x)', async ({ page, baseURL }) => {
    await page.goto('/');
    await page.waitForLoadState('networkidle');
    
    // Get all links from the page
    const links = await page.locator('a[href]').evaluateAll((anchors) => {
      return anchors.map((a) => (a as HTMLAnchorElement).href).filter(href => href && href.trim() !== '');
    });
    
    // Remove duplicates
    const uniqueLinks = [...new Set(links)];
    
    console.log(`Found ${uniqueLinks.length} unique links to check`);
    
    const results: { url: string; status: number; valid: boolean }[] = [];
    
    for (const link of uniqueLinks) {
      try {
        // Skip external links that are not part of the application
        const linkUrl = new URL(link);
        const baseUrl = new URL(baseURL || '');
        
        // Only check links within the same domain or relative links
        if (linkUrl.origin !== baseUrl.origin && !link.startsWith('/')) {
          console.log(`Skipping external link: ${link}`);
          continue;
        }
        
        const response = await page.request.get(link);
        const status = response.status();
        const valid = (status >= 200 && status < 400) && !(status >= 400 && status < 500);
        
        results.push({ url: link, status, valid });
        
        console.log(`${link} -> ${status} ${valid ? '✓' : '✗'}`);
        
        // Assert each link
        expect(status, `Link ${link} returned 40x status code: ${status}`).not.toBeGreaterThanOrEqual(400);
        expect(status, `Link ${link} returned unexpected status code: ${status}`).toBeLessThan(500);
        
      } catch (error) {
        console.error(`Error checking link ${link}:`, error);
        results.push({ url: link, status: -1, valid: false });
      }
    }
    
    // Summary
    const failedLinks = results.filter(r => !r.valid);
    console.log(`\n=== Summary ===`);
    console.log(`Total links checked: ${results.length}`);
    console.log(`Passed: ${results.filter(r => r.valid).length}`);
    console.log(`Failed: ${failedLinks.length}`);
    
    if (failedLinks.length > 0) {
      console.log('\nFailed links:');
      failedLinks.forEach(link => console.log(`  ${link.url} -> ${link.status}`));
    }
    
    expect(failedLinks, 'Some links returned invalid status codes').toHaveLength(0);
  });
});
