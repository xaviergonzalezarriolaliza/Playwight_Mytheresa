import { Page, expect } from '@playwright/test';
import { acceptCookiesIfPresent } from '../utils/cookies';

export class HomePage {
  constructor(private page: Page) {}

  async goto() {
    await this.page.goto('/');
    await acceptCookiesIfPresent(this.page);
  }

  async expectLoaded() {
    await expect(this.page).toHaveTitle(/.+/);
    // Header presence as a minimal sanity check
    await expect(this.page.locator('header')).toBeVisible({ timeout: 5000 });
  }
}
