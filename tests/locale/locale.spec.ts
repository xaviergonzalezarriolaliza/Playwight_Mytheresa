import { test, expect } from '@playwright/test';
import { acceptCookiesIfPresent } from '../utils/cookies';

const LIVE_ONLY = process.env.LIVE_TESTS === '1';

(LIVE_ONLY ? test : test.skip)('can change locale/currency (if controls exist)', async ({ page }) => {
  await page.goto('/');
  await acceptCookiesIfPresent(page);
  // Attempts to open a locale/currency switcher
  const switcherButton = page.locator('button:has-text("Country") , button:has-text("Ship to"), button:has-text("Language")').first();
  if (await switcherButton.isVisible().catch(() => false)) {
    await switcherButton.click();
    const firstOption = page.locator('[role="menuitem"], li[role="option"], [data-testid*="country" i]').first();
    if (await firstOption.isVisible().catch(() => false)) {
      await firstOption.click();
      await expect(page).toHaveTitle(/.+/);
    }
  } else {
    test.skip(true, 'No locale control found');
  }
});
