import { test } from '@playwright/test';

test('debug production navigation', async ({ page, baseURL }) => {
  console.log('BaseURL:', baseURL);
  
  await page.goto('/');
  
  const finalUrl = page.url();
  console.log('Final URL after goto("/"):', finalUrl);
  
  const title = await page.title();
  console.log('Page title:', title);
  
  const links = await page.locator('a[href]').evaluateAll((anchors) => {
    return anchors.map((a) => (a as HTMLAnchorElement).href);
  });
  
  console.log('Links found:', links);
});
