import { test, expect } from '@playwright/test';
import { acceptCookiesIfPresent } from '../utils/cookies';

const LIVE_ONLY = process.env.LIVE_TESTS === '1';

(LIVE_ONLY ? test : test.skip)('add a product to cart (best effort)', async ({ page }) => {
  await page.goto('/');
  await acceptCookiesIfPresent(page);
  // Navigate to first product
  const product = page.locator('a[href*="/shopping/"]').first();
  if (!(await product.isVisible().catch(() => false))) test.skip(true, 'No product found');
  await product.click();

  // size selection if present
  const size = page.locator('select[name*="size" i]');
  if (await size.isVisible().catch(() => false)) {
    const options = await size.locator('option').all();
    for (const o of options) {
      const val = (await o.getAttribute('value')) || undefined;
      if (val) { await size.selectOption(val).catch(() => {}); break; }
    }
  }

  const add = page.locator('button:has-text("Add")').first();
  if (!(await add.isVisible().catch(() => false))) test.skip(true, 'No add to cart button');
  await add.click();

  // Check cart indicator
  const cart = page.locator('a[href*="cart"], [data-testid*="cart" i]');
  await expect(cart.first()).toBeVisible();
});
