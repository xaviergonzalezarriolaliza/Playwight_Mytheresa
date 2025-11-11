"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
const test_1 = require("@playwright/test");
test_1.test.describe('Test Case 2: Link Status Code Verification', () => {
    (0, test_1.test)('should verify all links return valid status codes (200 or 30x, not 40x) - Triple Strategy Validation', async ({ page, baseURL }) => {
        // Navigate to the full URL to avoid GitHub 404 page
        const fullURL = baseURL || 'https://pocketaces2.github.io/fashionhub/';
        await page.goto(fullURL);
        await page.waitForLoadState('networkidle');
        const browserName = test_1.test.info().project.name;
        // Get all links from the page
        const links = await page.locator('a[href]').evaluateAll((anchors) => {
            return anchors.map((a) => a.href).filter(href => href && href.trim() !== '');
        });
        // Remove duplicates  
        const uniqueLinks = [...new Set(links)];
        console.log(`\n[${browserName}] ========================================`);
        console.log(`[${browserName}] Test Case 2: Triple Strategy Link Validation`);
        console.log(`[${browserName}] ========================================`);
        console.log(`[${browserName}] Found ${uniqueLinks.length} unique links\n`);
        // Filter links to check
        const linksToCheck = uniqueLinks.filter(link => {
            // Skip non-HTTP links
            if (link.startsWith('mailto:') || link.startsWith('tel:') || link.startsWith('javascript:') || link === '#') {
                return false;
            }
            // Skip CSS, JS, and image files
            if (link.match(/\.(css|js|png|jpg|jpeg|gif|ico|svg|woff|woff2|ttf)(\?|$)/i)) {
                return false;
            }
            try {
                const linkUrl = new URL(link);
                const baseUrl = new URL(baseURL || 'https://pocketaces2.github.io/fashionhub/');
                // Only check links within the same domain
                if (linkUrl.origin !== baseUrl.origin) {
                    return false;
                }
                // Include all paths that start with /fashionhub/ and end with .html or are directories
                if (linkUrl.pathname.startsWith('/fashionhub/')) {
                    // Include .html files and paths without extensions (directories)
                    if (linkUrl.pathname.endsWith('.html') || !linkUrl.pathname.includes('.')) {
                        return true;
                    }
                }
                return false;
            }
            catch {
                return false;
            }
        });
        console.log(`[${browserName}] Links to validate: ${linksToCheck.length}\n`);
        // STRATEGY 1: Page Request API
        console.log(`[${browserName}] --- Strategy 1: Page Request API ---`);
        const strategy1Results = [];
        for (const link of linksToCheck) {
            try {
                const response = await page.request.get(link);
                const status = response.status();
                const valid = status >= 200 && status < 400;
                strategy1Results.push({ url: link, status, valid, method: 'page-request' });
                console.log(`[${browserName}] [Strategy 1] ${link} -> ${status} ${valid ? '✓' : '✗'}`);
            }
            catch (error) {
                console.error(`[${browserName}] [Strategy 1] Error checking ${link}:`, error.message);
                strategy1Results.push({ url: link, status: 0, valid: false, method: 'page-request' });
            }
        }
        // STRATEGY 2: Page Navigation
        console.log(`\n[${browserName}] --- Strategy 2: Page Navigation ---`);
        const strategy2Results = [];
        for (const link of linksToCheck) {
            try {
                const response = await page.goto(link, { waitUntil: 'domcontentloaded', timeout: 10000 });
                const status = response?.status() || 0;
                const valid = status >= 200 && status < 400;
                strategy2Results.push({ url: link, status, valid, method: 'navigation' });
                console.log(`[${browserName}] [Strategy 2] ${link} -> ${status} ${valid ? '✓' : '✗'}`);
            }
            catch (error) {
                console.error(`[${browserName}] [Strategy 2] Error navigating to ${link}:`, error.message);
                strategy2Results.push({ url: link, status: 0, valid: false, method: 'navigation' });
            }
        }
        // Return to homepage for Strategy 3
        await page.goto('/');
        await page.waitForLoadState('networkidle');
        // STRATEGY 3: Browser Fetch API
        console.log(`\n[${browserName}] --- Strategy 3: Browser Fetch API ---`);
        const strategy3Results = [];
        for (const link of linksToCheck) {
            try {
                const result = await page.evaluate(async (url) => {
                    try {
                        const response = await fetch(url, { method: 'HEAD' });
                        return { status: response.status, valid: response.status >= 200 && response.status < 400 };
                    }
                    catch (error) {
                        // If HEAD fails, try GET
                        try {
                            const response = await fetch(url);
                            return { status: response.status, valid: response.status >= 200 && response.status < 400 };
                        }
                        catch {
                            return { status: 0, valid: false };
                        }
                    }
                }, link);
                strategy3Results.push({ url: link, status: result.status, valid: result.valid, method: 'fetch-api' });
                console.log(`[${browserName}] [Strategy 3] ${link} -> ${result.status} ${result.valid ? '✓' : '✗'}`);
            }
            catch (error) {
                console.error(`[${browserName}] [Strategy 3] Error fetching ${link}:`, error.message);
                strategy3Results.push({ url: link, status: 0, valid: false, method: 'fetch-api' });
            }
        }
        // VERIFICATION: Compare all 3 strategies
        console.log(`\n[${browserName}] ========================================`);
        console.log(`[${browserName}] Strategy Comparison & Agreement Analysis`);
        console.log(`[${browserName}] ========================================\n`);
        const comparisonResults = [];
        for (let i = 0; i < linksToCheck.length; i++) {
            const url = linksToCheck[i];
            const s1 = strategy1Results[i];
            const s2 = strategy2Results[i];
            const s3 = strategy3Results[i];
            // All strategies must agree on validity
            const allAgree = s1.valid === s2.valid && s2.valid === s3.valid;
            const finalValid = allAgree && s1.valid;
            comparisonResults.push({
                url,
                strategy1: { status: s1.status, valid: s1.valid },
                strategy2: { status: s2.status, valid: s2.valid },
                strategy3: { status: s3.status, valid: s3.valid },
                allAgree,
                finalValid
            });
            const agreement = allAgree ? '✓ AGREE' : '✗ DISAGREE';
            console.log(`[${browserName}] ${url}`);
            console.log(`[${browserName}]   Strategy 1 (Request): ${s1.status} ${s1.valid ? '✓' : '✗'}`);
            console.log(`[${browserName}]   Strategy 2 (Navigate): ${s2.status} ${s2.valid ? '✓' : '✗'}`);
            console.log(`[${browserName}]   Strategy 3 (Fetch): ${s3.status} ${s3.valid ? '✓' : '✗'}`);
            console.log(`[${browserName}]   → ${agreement} - Final: ${finalValid ? 'VALID' : 'INVALID'}\n`);
        }
        // Final Summary
        const allStrategiesAgree = comparisonResults.every(r => r.allAgree);
        const failedLinks = comparisonResults.filter(r => !r.finalValid);
        const disagreements = comparisonResults.filter(r => !r.allAgree);
        console.log(`[${browserName}] ========================================`);
        console.log(`[${browserName}] Final Summary`);
        console.log(`[${browserName}] ========================================`);
        console.log(`[${browserName}] Total links checked: ${linksToCheck.length}`);
        console.log(`[${browserName}] Valid links: ${comparisonResults.filter(r => r.finalValid).length}`);
        console.log(`[${browserName}] Invalid links: ${failedLinks.length}`);
        console.log(`[${browserName}] Strategy disagreements: ${disagreements.length}`);
        console.log(`[${browserName}] All strategies agree: ${allStrategiesAgree ? 'YES ✓' : 'NO ✗'}`);
        if (disagreements.length > 0) {
            console.log(`\n[${browserName}] ⚠️  Strategy Disagreements:`);
            disagreements.forEach(d => {
                console.log(`[${browserName}]   ${d.url}`);
                console.log(`[${browserName}]     S1: ${d.strategy1.status} (${d.strategy1.valid ? 'valid' : 'invalid'})`);
                console.log(`[${browserName}]     S2: ${d.strategy2.status} (${d.strategy2.valid ? 'valid' : 'invalid'})`);
                console.log(`[${browserName}]     S3: ${d.strategy3.status} (${d.strategy3.valid ? 'valid' : 'invalid'})`);
            });
        }
        if (failedLinks.length > 0) {
            console.log(`\n[${browserName}] ❌ Failed links (all strategies agree):`);
            failedLinks.forEach(link => {
                console.log(`[${browserName}]   ${link.url}`);
                console.log(`[${browserName}]     Status: ${link.strategy1.status}, ${link.strategy2.status}, ${link.strategy3.status}`);
            });
        }
        console.log(`[${browserName}] ========================================\n`);
        // Assertions
        (0, test_1.expect)(allStrategiesAgree, `Not all validation strategies agree on results. Found ${disagreements.length} disagreements.`).toBe(true);
        (0, test_1.expect)(failedLinks, `Found ${failedLinks.length} links with invalid status codes (all strategies agree)`).toHaveLength(0);
        // Individual strategy assertions
        const strategy1Failures = strategy1Results.filter(r => !r.valid);
        const strategy2Failures = strategy2Results.filter(r => !r.valid);
        const strategy3Failures = strategy3Results.filter(r => !r.valid);
        (0, test_1.expect)(strategy1Failures, `Strategy 1 (Page Request) found ${strategy1Failures.length} invalid links`).toHaveLength(0);
        (0, test_1.expect)(strategy2Failures, `Strategy 2 (Navigation) found ${strategy2Failures.length} invalid links`).toHaveLength(0);
        (0, test_1.expect)(strategy3Failures, `Strategy 3 (Fetch API) found ${strategy3Failures.length} invalid links`).toHaveLength(0);
    });
});
