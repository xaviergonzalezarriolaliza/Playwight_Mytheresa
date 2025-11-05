import { test, expect } from '@playwright/test';
import { acceptCookiesIfPresent } from '../utils/cookies';

const LIVE_ONLY = process.env.LIVE_TESTS === '1';

(LIVE_ONLY ? test : test.skip)('open a product page and check add-to-bag button', async ({ page }) => {
  await page.goto('/');
  await acceptCookiesIfPresent(page);
  // Try to click first product card if present
  const productCard = page.locator('a:has([data-testid*="product" i]), a[href*="/shopping/"]').first();
  if (await productCard.isVisible().catch(() => false)) {
    await productCard.click();
    const addToCart = page.locator('button:has-text("Add to")').first();
    await expect(addToCart).toBeVisible();
  } else {
    test.skip(true, 'No product link found on homepage');
  }
});
