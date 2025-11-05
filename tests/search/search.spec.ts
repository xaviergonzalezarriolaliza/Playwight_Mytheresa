import { test, expect } from '@playwright/test';
import { acceptCookiesIfPresent } from '../utils/cookies';

const LIVE_ONLY = process.env.LIVE_TESTS === '1';

(LIVE_ONLY ? test : test.skip)('can search for a term', async ({ page }) => {
  await page.goto('/');
  await acceptCookiesIfPresent(page);
  // Try common search selectors
  const searchSelectors = [
    'input[type="search"]',
    'input[placeholder*="Search" i]',
    '[role="search"] input',
  ];
  let search = page.locator('input[type="search"]');
  for (const sel of searchSelectors) {
    if (await page.locator(sel).first().isVisible().catch(() => false)) {
      search = page.locator(sel).first();
      break;
    }
  }
  await search.fill('dress');
  await search.press('Enter');
  // Expect some result-like content
  await expect(page.locator('text=/dress/i')).toBeVisible({ timeout: 15000 });
});
