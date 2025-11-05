import { test } from '@playwright/test';
import { HomePage } from '../pages/HomePage';

const LIVE_ONLY = process.env.LIVE_TESTS === '1';

// Basic smoke: can load homepage and basic elements appear
(LIVE_ONLY ? test : test.skip)('homepage loads and shows header', async ({ page }) => {
  const home = new HomePage(page);
  await home.goto();
  await home.expectLoaded();
});
