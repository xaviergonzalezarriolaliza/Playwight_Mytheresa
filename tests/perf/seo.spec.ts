import { test, expect } from '@playwright/test';
import { acceptCookiesIfPresent } from '../utils/cookies';

const LIVE_ONLY = process.env.LIVE_TESTS === '1';

(LIVE_ONLY ? test : test.skip)('basic SEO tags present on homepage', async ({ page }) => {
  await page.goto('/');
  await acceptCookiesIfPresent(page);
  const title = await page.title();
  expect(title.length).toBeGreaterThan(0);
  const desc = await page.locator('head meta[name="description"]').getAttribute('content');
  expect(desc ?? '').not.toEqual('');
  const canonical = await page.locator('head link[rel="canonical"]').getAttribute('href');
  expect(canonical ?? '').not.toEqual('');
});
