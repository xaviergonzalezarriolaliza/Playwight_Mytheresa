import { test, expect } from '@playwright/test';
import { acceptCookiesIfPresent } from '../utils/cookies';

const LIVE_ONLY = process.env.LIVE_TESTS === '1';

(LIVE_ONLY ? test : test.skip)('header has main nav links', async ({ page }) => {
  await page.goto('/');
  await acceptCookiesIfPresent(page);
  // Loosely assert presence of a header and some links
  await expect(page.locator('header')).toBeVisible();
  const links = page.locator('header a');
  const count = await links.count();
  expect(count).toBeGreaterThan(0);
});
