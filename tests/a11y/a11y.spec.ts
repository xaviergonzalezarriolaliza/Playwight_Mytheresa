import { test, expect } from '@playwright/test';
import AxeBuilder from '@axe-core/playwright';
import { acceptCookiesIfPresent } from '../utils/cookies';

const LIVE_ONLY = process.env.LIVE_TESTS === '1';

(LIVE_ONLY ? test : test.skip)('homepage has no critical a11y violations', async ({ page }) => {
  await page.goto('/');
  await acceptCookiesIfPresent(page);
  const accessibilityScanResults = await new AxeBuilder({ page }).analyze();
  const critical = accessibilityScanResults.violations.filter(v => v.impact === 'critical');
  // Allow minor issues by default, flag critical ones
  expect(critical).toHaveLength(0);
});
