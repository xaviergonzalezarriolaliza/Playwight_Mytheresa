import { Page } from '@playwright/test';

// Best-effort cookie banner acceptor; ignores errors if banner not present
export async function acceptCookiesIfPresent(page: Page) {
  const candidates = [
    // Common selectors/texts used by CMPs
    'button:has-text("Accept All")',
    'button:has-text("Accept all")',
    'button:has-text("I Accept")',
    'button:has-text("Allow all")',
    '[data-testid="uc-accept-all-button"]',
    '#onetrust-accept-btn-handler',
  ];
  for (const sel of candidates) {
    const btn = page.locator(sel);
    if (await btn.first().isVisible().catch(() => false)) {
      await btn.first().click({ trial: false }).catch(() => {});
      break;
    }
  }
}
