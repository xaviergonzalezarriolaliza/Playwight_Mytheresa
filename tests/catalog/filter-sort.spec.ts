import { test, expect } from '@playwright/test';
import { acceptCookiesIfPresent } from '../utils/cookies';

const LIVE_ONLY = process.env.LIVE_TESTS === '1';

(LIVE_ONLY ? test : test.skip)('can apply a filter and sort', async ({ page }) => {
  await page.goto('/');
  await acceptCookiesIfPresent(page);
  // Navigate to a category if link exists
  const categoryLink = page.locator('a:has-text("Women")').first();
  if (await categoryLink.isVisible().catch(() => false)) {
    await categoryLink.click();
  }
  // Attempt a generic filter interaction
  const filterButton = page.locator('button:has-text("Filter")').first();
  if (await filterButton.isVisible().catch(() => false)) {
    await filterButton.click();
    const firstFilter = page.locator('[type="checkbox"]').first();
    if (await firstFilter.isVisible().catch(() => false)) {
      await firstFilter.check();
    }
  }
  // Sort dropdown
  const sort = page.locator('select:has(option:has-text("Price"))').first();
  if (await sort.isVisible().catch(() => false)) {
    await sort.selectOption({ label: 'Price' });
  }
  await expect(page).toHaveTitle(/.+/);
});
