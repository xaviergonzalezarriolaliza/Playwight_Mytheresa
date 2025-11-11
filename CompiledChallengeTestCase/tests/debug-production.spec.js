"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
const test_1 = require("@playwright/test");
(0, test_1.test)('debug production navigation', async ({ page, baseURL }) => {
    console.log('BaseURL:', baseURL);
    await page.goto('/');
    const finalUrl = page.url();
    console.log('Final URL after goto("/"):', finalUrl);
    const title = await page.title();
    console.log('Page title:', title);
    const links = await page.locator('a[href]').evaluateAll((anchors) => {
        return anchors.map((a) => a.href);
    });
    console.log('Links found:', links);
});
