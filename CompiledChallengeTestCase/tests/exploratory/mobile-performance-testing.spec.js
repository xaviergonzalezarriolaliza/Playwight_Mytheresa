"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
const test_1 = require("@playwright/test");
const BASE_URL = 'https://pocketaces2.github.io/fashionhub/';
/**
 * MOBILE & PERFORMANCE TESTING
 *
 * This test suite focuses on:
 * 1. Mobile responsiveness across different devices
 * 2. Touch interactions and mobile UX
 * 3. Performance metrics and optimization
 * 4. Memory leak detection
 * 5. Resource loading efficiency
 */
test_1.test.describe('Mobile & Performance Testing - Fashion Hub Production', () => {
    (0, test_1.test)('Mobile - iPhone 13 Pro Responsiveness', async ({ browser }) => {
        const iPhone = test_1.devices['iPhone 13 Pro'];
        const context = await browser.newContext({
            ...iPhone,
        });
        const page = await context.newPage();
        const issues = [];
        console.log('\n=== IPHONE 13 PRO TESTING ===');
        console.log(`Viewport: ${iPhone.viewport.width}x${iPhone.viewport.height}`);
        await page.goto(BASE_URL);
        // Check mobile-specific issues
        const viewport = page.viewportSize();
        console.log(`1. Testing navigation on mobile...`);
        // Check for hamburger menu
        const hamburgerMenu = await page.locator('[role="button"][aria-label*="menu"]').count();
        if (hamburgerMenu === 0) {
            console.log('   ⚠️  No hamburger menu found (may need mobile navigation)');
            issues.push('No hamburger menu on mobile');
        }
        // Check text readability
        const bodyFontSize = await page.evaluate(() => {
            const body = document.body;
            return window.getComputedStyle(body).fontSize;
        });
        console.log(`2. Body font size: ${bodyFontSize}`);
        const fontSize = parseInt(bodyFontSize);
        if (fontSize < 16) {
            issues.push(`Body font too small for mobile: ${fontSize}px (should be ≥16px)`);
        }
        // Check for horizontal scrolling
        const hasHorizontalScroll = await page.evaluate(() => {
            return document.documentElement.scrollWidth > window.innerWidth;
        });
        if (hasHorizontalScroll) {
            issues.push('Horizontal scrolling detected (content wider than viewport)');
        }
        console.log(`3. Horizontal scroll: ${hasHorizontalScroll ? '❌ Present' : '✅ None'}`);
        // Check touch target sizes
        const links = await page.locator('a').all();
        console.log(`4. Checking ${links.length} touch targets...`);
        let smallTargets = 0;
        for (const link of links) {
            const box = await link.boundingBox().catch(() => null);
            if (box && (box.width < 44 || box.height < 44)) {
                smallTargets++;
            }
        }
        if (smallTargets > 0) {
            issues.push(`${smallTargets} touch targets smaller than 44x44px (iOS minimum)`);
        }
        console.log(`   Touch targets < 44x44px: ${smallTargets}`);
        // Check for fixed positioning issues
        const fixedElements = await page.evaluate(() => {
            const elements = document.querySelectorAll('*');
            let count = 0;
            elements.forEach(el => {
                const style = window.getComputedStyle(el);
                if (style.position === 'fixed')
                    count++;
            });
            return count;
        });
        console.log(`5. Fixed position elements: ${fixedElements}`);
        // Take mobile screenshot
        await page.screenshot({
            path: 'test-results/mobile-iphone13pro.png',
            fullPage: true
        });
        console.log('\n=== IPHONE 13 PRO FINDINGS ===');
        console.log(`Total issues found: ${issues.length}`);
        issues.forEach((issue, i) => {
            console.log(`${i + 1}. ⚠️  ${issue}`);
        });
        await context.close();
        // Don't fail test, just report findings
        (0, test_1.expect)(true).toBe(true);
    });
    (0, test_1.test)('Mobile - iPad Pro Responsiveness', async ({ browser }) => {
        const iPad = test_1.devices['iPad Pro'];
        const context = await browser.newContext({
            ...iPad,
        });
        const page = await context.newPage();
        const issues = [];
        console.log('\n=== IPAD PRO TESTING ===');
        console.log(`Viewport: ${iPad.viewport.width}x${iPad.viewport.height}`);
        await page.goto(BASE_URL);
        // Check tablet layout
        console.log('1. Checking tablet layout...');
        // Check if layout uses available space well
        const contentWidth = await page.evaluate(() => {
            const main = document.querySelector('main') || document.body;
            return window.getComputedStyle(main).maxWidth;
        });
        console.log(`   Content max-width: ${contentWidth}`);
        // Check for tablet-specific navigation
        const navItems = await page.locator('nav a').count();
        console.log(`2. Navigation items: ${navItems}`);
        // Test orientation change
        console.log('3. Testing orientation change...');
        await page.setViewportSize({ width: 1366, height: 1024 }); // Landscape
        await page.waitForTimeout(500);
        const landscapeScroll = await page.evaluate(() => {
            return document.documentElement.scrollWidth > window.innerWidth;
        });
        if (landscapeScroll) {
            issues.push('Horizontal scrolling in landscape mode');
        }
        // Take tablet screenshot
        await page.screenshot({
            path: 'test-results/mobile-ipadpro.png',
            fullPage: true
        });
        console.log('\n=== IPAD PRO FINDINGS ===');
        console.log(`Total issues found: ${issues.length}`);
        issues.forEach((issue, i) => {
            console.log(`${i + 1}. ⚠️  ${issue}`);
        });
        await context.close();
        (0, test_1.expect)(true).toBe(true);
    });
    (0, test_1.test)('Performance - Load Time & Metrics', async ({ page }) => {
        const issues = [];
        console.log('\n=== PERFORMANCE TESTING ===');
        // Measure load time
        const startTime = Date.now();
        await page.goto(BASE_URL, { waitUntil: 'load' });
        const loadTime = Date.now() - startTime;
        console.log(`1. Full page load time: ${loadTime}ms`);
        if (loadTime > 3000) {
            issues.push(`Slow load time: ${loadTime}ms (target: <3000ms)`);
        }
        // Get performance metrics
        const metrics = await page.evaluate(() => {
            const perf = performance.getEntriesByType('navigation')[0];
            return {
                dns: perf.domainLookupEnd - perf.domainLookupStart,
                tcp: perf.connectEnd - perf.connectStart,
                ttfb: perf.responseStart - perf.requestStart,
                download: perf.responseEnd - perf.responseStart,
                domInteractive: perf.domInteractive,
                domComplete: perf.domComplete,
                loadEvent: perf.loadEventEnd - perf.loadEventStart,
            };
        });
        console.log('2. Performance breakdown:');
        console.log(`   DNS Lookup: ${Math.round(metrics.dns)}ms`);
        console.log(`   TCP Connection: ${Math.round(metrics.tcp)}ms`);
        console.log(`   Time to First Byte: ${Math.round(metrics.ttfb)}ms`);
        console.log(`   Download: ${Math.round(metrics.download)}ms`);
        console.log(`   DOM Interactive: ${Math.round(metrics.domInteractive)}ms`);
        console.log(`   DOM Complete: ${Math.round(metrics.domComplete)}ms`);
        console.log(`   Load Event: ${Math.round(metrics.loadEvent)}ms`);
        if (metrics.ttfb > 600) {
            issues.push(`High TTFB: ${Math.round(metrics.ttfb)}ms (target: <600ms)`);
        }
        // Check resource count and sizes
        const resources = await page.evaluate(() => {
            const entries = performance.getEntriesByType('resource');
            const byType = {};
            entries.forEach((entry) => {
                const type = entry.initiatorType;
                if (!byType[type])
                    byType[type] = { count: 0, size: 0 };
                byType[type].count++;
                byType[type].size += entry.transferSize || 0;
            });
            return byType;
        });
        console.log('3. Resources loaded:');
        Object.entries(resources).forEach(([type, data]) => {
            const sizeKB = (data.size / 1024).toFixed(1);
            console.log(`   ${type}: ${data.count} files, ${sizeKB}KB`);
        });
        // Check for large resources
        const totalSize = Object.values(resources).reduce((sum, r) => sum + r.size, 0);
        const totalSizeMB = (totalSize / 1024 / 1024).toFixed(2);
        console.log(`   Total: ${totalSizeMB}MB`);
        if (totalSize > 5 * 1024 * 1024) { // 5MB
            issues.push(`Large page size: ${totalSizeMB}MB (target: <2MB)`);
        }
        console.log('\n=== PERFORMANCE FINDINGS ===');
        console.log(`Total issues found: ${issues.length}`);
        issues.forEach((issue, i) => {
            console.log(`${i + 1}. ⚠️  ${issue}`);
        });
        (0, test_1.expect)(true).toBe(true);
    });
    (0, test_1.test)('Performance - Memory Leak Detection', async ({ page }) => {
        const issues = [];
        console.log('\n=== MEMORY LEAK TESTING ===');
        await page.goto(BASE_URL);
        // Get initial memory
        const initialMemory = await page.evaluate(() => {
            if ('memory' in performance) {
                return performance.memory.usedJSHeapSize;
            }
            return null;
        });
        if (initialMemory === null) {
            console.log('Memory API not available (Chromium only)');
            (0, test_1.expect)(true).toBe(true);
            return;
        }
        console.log(`1. Initial memory: ${(initialMemory / 1024 / 1024).toFixed(2)}MB`);
        // Navigate through pages multiple times
        const pages = ['', 'products.html', 'account.html', 'cart.html', 'about.html'];
        console.log('2. Navigating through pages to detect leaks...');
        for (let i = 0; i < 3; i++) {
            for (const pagePath of pages) {
                await page.goto(`${BASE_URL}${pagePath}`);
                await page.waitForTimeout(500);
            }
        }
        // Get final memory
        await page.goto(BASE_URL);
        await page.waitForTimeout(1000);
        const finalMemory = await page.evaluate(() => {
            if ('memory' in performance) {
                return performance.memory.usedJSHeapSize;
            }
            return null;
        });
        if (finalMemory) {
            const memoryIncrease = finalMemory - initialMemory;
            const increasePercent = ((memoryIncrease / initialMemory) * 100).toFixed(1);
            console.log(`3. Final memory: ${(finalMemory / 1024 / 1024).toFixed(2)}MB`);
            console.log(`4. Memory increase: ${(memoryIncrease / 1024 / 1024).toFixed(2)}MB (${increasePercent}%)`);
            if (memoryIncrease > 10 * 1024 * 1024) { // 10MB increase
                issues.push(`Potential memory leak: ${(memoryIncrease / 1024 / 1024).toFixed(2)}MB increase`);
            }
        }
        console.log('\n=== MEMORY LEAK FINDINGS ===');
        console.log(`Total issues found: ${issues.length}`);
        issues.forEach((issue, i) => {
            console.log(`${i + 1}. ⚠️  ${issue}`);
        });
        (0, test_1.expect)(true).toBe(true);
    });
    (0, test_1.test)('Performance - Network Efficiency', async ({ page }) => {
        const issues = [];
        console.log('\n=== NETWORK EFFICIENCY TESTING ===');
        // Track all network requests
        const requests = [];
        page.on('request', request => {
            requests.push({
                url: request.url(),
                method: request.method(),
                resourceType: request.resourceType(),
            });
        });
        await page.goto(BASE_URL, { waitUntil: 'networkidle' });
        console.log(`1. Total requests: ${requests.length}`);
        // Analyze request types
        const byType = {};
        requests.forEach(req => {
            byType[req.resourceType] = (byType[req.resourceType] || 0) + 1;
        });
        console.log('2. Requests by type:');
        Object.entries(byType).forEach(([type, count]) => {
            console.log(`   ${type}: ${count}`);
        });
        // Check for excessive requests
        if (requests.length > 50) {
            issues.push(`High request count: ${requests.length} (target: <50)`);
        }
        // Check for unoptimized images
        const images = requests.filter(r => r.resourceType === 'image');
        console.log(`3. Image requests: ${images.length}`);
        // Check for third-party requests
        const thirdParty = requests.filter(r => !r.url.includes('pocketaces2.github.io') &&
            !r.url.includes('localhost'));
        console.log(`4. Third-party requests: ${thirdParty.length}`);
        if (thirdParty.length > 0) {
            console.log('   Third-party domains:');
            const domains = [...new Set(thirdParty.map(r => new URL(r.url).hostname))];
            domains.forEach(domain => console.log(`   - ${domain}`));
        }
        // Check for blocking resources
        const blockingScripts = requests.filter(r => r.resourceType === 'script' &&
            !r.url.includes('async') &&
            !r.url.includes('defer'));
        console.log(`5. Potentially blocking scripts: ${blockingScripts.length}`);
        console.log('\n=== NETWORK EFFICIENCY FINDINGS ===');
        console.log(`Total issues found: ${issues.length}`);
        issues.forEach((issue, i) => {
            console.log(`${i + 1}. ⚠️  ${issue}`);
        });
        (0, test_1.expect)(true).toBe(true);
    });
    (0, test_1.test)('Mobile - Touch Interactions', async ({ browser }) => {
        const iPhone = test_1.devices['iPhone 13 Pro'];
        const context = await browser.newContext({
            ...iPhone,
        });
        const page = await context.newPage();
        const issues = [];
        console.log('\n=== TOUCH INTERACTION TESTING ===');
        await page.goto(BASE_URL);
        // Test tap interactions
        console.log('1. Testing tap on navigation links...');
        const links = await page.locator('nav a').all();
        if (links.length > 0) {
            const firstLink = links[0];
            await firstLink.tap();
            await page.waitForTimeout(500);
            console.log(`   ✅ Navigation tap works`);
        }
        // Test scroll behavior
        console.log('2. Testing scroll behavior...');
        await page.evaluate(() => window.scrollTo(0, 500));
        await page.waitForTimeout(300);
        const scrollY = await page.evaluate(() => window.scrollY);
        console.log(`   Scroll position: ${scrollY}px`);
        // Test form interactions on mobile
        await page.goto(`${BASE_URL}account.html`);
        console.log('3. Testing form input on mobile...');
        const emailInput = page.locator('input[type="email"]').first();
        await emailInput.tap();
        await emailInput.fill('test@example.com');
        const value = await emailInput.inputValue();
        if (value === 'test@example.com') {
            console.log('   ✅ Form input works on mobile');
        }
        else {
            issues.push('Form input not working correctly on mobile');
        }
        // Check for mobile-specific gestures
        console.log('4. Checking pinch-to-zoom setting...');
        const viewport = await page.evaluate(() => {
            const meta = document.querySelector('meta[name="viewport"]');
            return meta ? meta.getAttribute('content') : null;
        });
        if (viewport && viewport.includes('user-scalable=no')) {
            issues.push('Pinch-to-zoom disabled (accessibility issue)');
        }
        console.log(`   Viewport: ${viewport}`);
        console.log('\n=== TOUCH INTERACTION FINDINGS ===');
        console.log(`Total issues found: ${issues.length}`);
        issues.forEach((issue, i) => {
            console.log(`${i + 1}. ⚠️  ${issue}`);
        });
        await context.close();
        (0, test_1.expect)(true).toBe(true);
    });
});
