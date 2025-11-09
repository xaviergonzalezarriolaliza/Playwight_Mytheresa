import { test, expect } from '@playwright/test';

/**
 * COMPREHENSIVE BUG HUNTING SESSION
 * Deep exploratory testing of Fashion Hub production environment
 * Goal: Find every possible bug, issue, or improvement opportunity
 */

test.describe('Deep Bug Hunting - Fashion Hub Production', () => {
  const baseURL = 'https://pocketaces2.github.io/fashionhub/';
  
  test('Homepage - Comprehensive Analysis', async ({ page }) => {
    console.log('\n=== HOMEPAGE DEEP DIVE ===\n');
    
    const issues: string[] = [];
    
    // Navigate to homepage
    await page.goto(baseURL);
    await page.waitForLoadState('networkidle');
    
    // 1. Check all images load properly
    console.log('1. Checking images...');
    const images = await page.locator('img').all();
    for (const img of images) {
      const src = await img.getAttribute('src');
      const alt = await img.getAttribute('alt');
      const naturalWidth = await img.evaluate((el: HTMLImageElement) => el.naturalWidth);
      
      if (!src) {
        issues.push(`❌ Image missing src attribute`);
      }
      if (!alt || alt.trim() === '') {
        issues.push(`⚠️  Image missing alt text: ${src}`);
      }
      if (naturalWidth === 0) {
        issues.push(`❌ Image failed to load: ${src}`);
      }
    }
    console.log(`   Found ${images.length} images`);
    
    // 2. Check all links
    console.log('2. Checking links...');
    const links = await page.locator('a').all();
    for (const link of links) {
      const href = await link.getAttribute('href');
      const text = await link.textContent();
      const isVisible = await link.isVisible();
      
      if (!href) {
        issues.push(`❌ Link missing href: "${text}"`);
      }
      if (href && href.startsWith('javascript:')) {
        issues.push(`⚠️  JavaScript link found: "${text}" - potential security concern`);
      }
      if (isVisible && (!text || text.trim() === '')) {
        issues.push(`⚠️  Visible link has no text: ${href}`);
      }
    }
    console.log(`   Found ${links.length} links`);
    
    // 3. Check forms
    console.log('3. Checking forms...');
    const forms = await page.locator('form').all();
    for (const form of forms) {
      const action = await form.getAttribute('action');
      const method = await form.getAttribute('method');
      const inputs = await form.locator('input, textarea, select').all();
      
      if (!action && inputs.length > 0) {
        issues.push(`⚠️  Form has no action attribute`);
      }
      
      for (const input of inputs) {
        const type = await input.getAttribute('type');
        const name = await input.getAttribute('name');
        const id = await input.getAttribute('id');
        const label = await page.locator(`label[for="${id}"]`).count();
        
        if (!name && !id) {
          issues.push(`⚠️  Input missing both name and id attributes`);
        }
        if (type === 'password' && await input.getAttribute('autocomplete') !== 'current-password') {
          issues.push(`⚠️  Password field missing proper autocomplete attribute`);
        }
        if (id && label === 0) {
          issues.push(`⚠️  Input has id but no associated label: ${id}`);
        }
      }
    }
    console.log(`   Found ${forms.length} forms`);
    
    // 4. Check for console errors
    console.log('4. Monitoring console errors...');
    const consoleErrors: string[] = [];
    page.on('console', msg => {
      if (msg.type() === 'error') {
        consoleErrors.push(msg.text());
      }
    });
    
    // 5. Check page title and meta tags
    console.log('5. Checking SEO and meta tags...');
    const title = await page.title();
    if (!title || title.length === 0) {
      issues.push(`❌ Page title is empty`);
    }
    if (title && title.length > 60) {
      issues.push(`⚠️  Page title too long (${title.length} chars): "${title}"`);
    }
    
    const metaDescription = await page.locator('meta[name="description"]').getAttribute('content').catch(() => null);
    if (!metaDescription) {
      issues.push(`⚠️  Missing meta description`);
    }
    
    // 6. Check for missing semantic HTML
    console.log('6. Checking semantic HTML...');
    const hasMain = await page.locator('main').count();
    const hasHeader = await page.locator('header').count();
    const hasFooter = await page.locator('footer').count();
    const hasNav = await page.locator('nav').count();
    
    if (hasMain === 0) issues.push(`⚠️  Missing <main> landmark`);
    if (hasHeader === 0) issues.push(`⚠️  Missing <header> element`);
    if (hasFooter === 0) issues.push(`⚠️  Missing <footer> element`);
    if (hasNav === 0) issues.push(`⚠️  Missing <nav> element`);
    
    // 7. Check heading hierarchy
    console.log('7. Checking heading hierarchy...');
    const h1Count = await page.locator('h1').count();
    if (h1Count === 0) {
      issues.push(`❌ No H1 heading found`);
    } else if (h1Count > 1) {
      issues.push(`⚠️  Multiple H1 headings (${h1Count}) - should have only one`);
    }
    
    // 8. Check for broken internal links
    console.log('8. Testing internal navigation...');
    const internalLinks = await page.locator('a[href^="/fashionhub"]').all();
    for (const link of internalLinks.slice(0, 5)) { // Test first 5
      const href = await link.getAttribute('href');
      if (href) {
        try {
          const response = await page.request.get(`https://pocketaces2.github.io${href}`);
          if (response.status() >= 400) {
            issues.push(`❌ Broken internal link: ${href} (${response.status()})`);
          }
        } catch (error) {
          issues.push(`❌ Failed to check link: ${href}`);
        }
      }
    }
    
    // 9. Check for text issues
    console.log('9. Checking text content...');
    const bodyText = await page.locator('body').textContent();
    if (bodyText && bodyText.includes('Lorem ipsum')) {
      issues.push(`⚠️  Placeholder text (Lorem ipsum) found`);
    }
    if (bodyText && bodyText.includes('TODO') || bodyText?.includes('FIXME')) {
      issues.push(`⚠️  Development comments visible: TODO/FIXME`);
    }
    
    // 10. Check viewport meta tag
    console.log('10. Checking mobile responsiveness...');
    const viewport = await page.locator('meta[name="viewport"]').getAttribute('content');
    if (!viewport) {
      issues.push(`❌ Missing viewport meta tag - not mobile friendly`);
    }
    
    // 11. Check for HTTPS issues
    console.log('11. Checking mixed content...');
    const httpResources = await page.evaluate(() => {
      const resources: string[] = [];
      document.querySelectorAll('img, script, link').forEach(el => {
        const src = el.getAttribute('src') || el.getAttribute('href');
        if (src && src.startsWith('http://')) {
          resources.push(src);
        }
      });
      return resources;
    });
    if (httpResources.length > 0) {
      issues.push(`⚠️  Mixed content: ${httpResources.length} HTTP resources on HTTPS page`);
    }
    
    // 12. Check performance
    console.log('12. Checking performance...');
    const performanceMetrics = await page.evaluate(() => {
      const navigation = performance.getEntriesByType('navigation')[0] as PerformanceNavigationTiming;
      return {
        domComplete: navigation.domComplete,
        loadComplete: navigation.loadEventEnd,
        domInteractive: navigation.domInteractive
      };
    });
    if (performanceMetrics.domComplete > 3000) {
      issues.push(`⚠️  Slow page load: ${performanceMetrics.domComplete}ms DOM complete`);
    }
    
    // Report findings
    console.log(`\n=== HOMEPAGE FINDINGS ===`);
    console.log(`Total issues found: ${issues.length}`);
    if (issues.length > 0) {
      console.log('\nIssues:');
      issues.forEach((issue, i) => console.log(`${i + 1}. ${issue}`));
    } else {
      console.log('✅ No major issues found on homepage!');
    }
    
    // Take screenshot for evidence
    await page.screenshot({ path: 'test-results/homepage-bug-hunting.png', fullPage: true });
    
    expect(issues.length).toBeLessThan(100); // Allow some issues but not excessive
  });

  test('Products Page - Comprehensive Analysis', async ({ page }) => {
    console.log('\n=== PRODUCTS PAGE DEEP DIVE ===\n');
    
    const issues: string[] = [];
    
    await page.goto(`${baseURL}products.html`);
    await page.waitForLoadState('networkidle');
    
    // 1. Check product cards
    console.log('1. Analyzing product cards...');
    const products = await page.locator('.product-card, .product, [class*="product"]').all();
    console.log(`   Found ${products.length} potential product elements`);
    
    for (const product of products.slice(0, 10)) { // Check first 10
      const image = await product.locator('img').first();
      const title = await product.locator('h2, h3, .title, [class*="title"]').first();
      const price = await product.locator('.price, [class*="price"]').first();
      
      if (await image.count() === 0) {
        issues.push(`⚠️  Product missing image`);
      }
      if (await title.count() === 0) {
        issues.push(`⚠️  Product missing title`);
      }
      if (await price.count() === 0) {
        issues.push(`⚠️  Product missing price`);
      }
    }
    
    // 2. Check for search functionality
    console.log('2. Checking search functionality...');
    const searchInput = await page.locator('input[type="search"], input[placeholder*="search" i]').count();
    if (searchInput > 0) {
      const search = page.locator('input[type="search"], input[placeholder*="search" i]').first();
      await search.fill('test search query');
      // Check if search has any validation or response
      const searchValue = await search.inputValue();
      if (searchValue !== 'test search query') {
        issues.push(`❌ Search input not accepting text properly`);
      }
    } else {
      console.log('   No search functionality found');
    }
    
    // 3. Check filters/sorting
    console.log('3. Checking filters and sorting...');
    const selects = await page.locator('select').all();
    for (const select of selects) {
      const options = await select.locator('option').all();
      if (options.length === 0) {
        issues.push(`⚠️  Select element has no options`);
      }
    }
    
    // 4. Test product interaction
    console.log('4. Testing product interactions...');
    const firstProduct = page.locator('.product-card, .product, [class*="product"]').first();
    if (await firstProduct.count() > 0) {
      try {
        await firstProduct.click({ timeout: 5000 });
        // Check if something happens (navigation, modal, etc.)
        await page.waitForTimeout(1000);
      } catch (error) {
        console.log('   Product click had no effect (might be expected)');
      }
    }
    
    // 5. Check pagination
    console.log('5. Checking pagination...');
    const pagination = await page.locator('.pagination, [class*="pagination"], nav[aria-label*="pagination" i]').count();
    if (pagination === 0 && products.length > 12) {
      issues.push(`⚠️  Many products (${products.length}) but no pagination found`);
    }
    
    // Report
    console.log(`\n=== PRODUCTS PAGE FINDINGS ===`);
    console.log(`Total issues found: ${issues.length}`);
    if (issues.length > 0) {
      issues.forEach((issue, i) => console.log(`${i + 1}. ${issue}`));
    }
    
    await page.screenshot({ path: 'test-results/products-bug-hunting.png', fullPage: true });
  });

  test('Account/Login Page - Security & Validation Deep Dive', async ({ page }) => {
    console.log('\n=== ACCOUNT PAGE DEEP DIVE ===\n');
    
    const issues: string[] = [];
    
    await page.goto(`${baseURL}account.html`);
    await page.waitForLoadState('networkidle');
    
    // 1. Check if login form exists
    console.log('1. Analyzing login form...');
    const usernameInput = page.locator('input[type="text"], input[type="email"], input[name*="user" i], input[placeholder*="user" i]').first();
    const passwordInput = page.locator('input[type="password"]').first();
    const submitButton = page.locator('button[type="submit"], input[type="submit"]').first();
    
    if (await usernameInput.count() === 0) {
      issues.push(`❌ No username/email input found`);
    }
    if (await passwordInput.count() === 0) {
      issues.push(`❌ No password input found`);
    }
    if (await submitButton.count() === 0) {
      issues.push(`⚠️  No submit button found`);
    }
    
    // 2. Check password field security
    console.log('2. Checking password field security...');
    if (await passwordInput.count() > 0) {
      const autocomplete = await passwordInput.getAttribute('autocomplete');
      if (!autocomplete || !autocomplete.includes('password')) {
        issues.push(`⚠️  Password field missing proper autocomplete`);
      }
      
      const type = await passwordInput.getAttribute('type');
      if (type !== 'password') {
        issues.push(`❌ CRITICAL: Password input not type="password"`);
      }
    }
    
    // 3. Test XSS vulnerability
    console.log('3. Testing XSS vulnerability...');
    if (await usernameInput.count() > 0) {
      await usernameInput.fill('<script>alert("XSS")</script>');
      if (await submitButton.count() > 0) {
        await submitButton.click();
        await page.waitForTimeout(1000);
        
        // Check if script tag appears in DOM (bad!)
        const scriptInDom = await page.evaluate(() => {
          return document.body.innerHTML.includes('<script>alert("XSS")</script>');
        });
        if (scriptInDom) {
          issues.push(`❌ CRITICAL: XSS vulnerability detected - script tags not sanitized`);
        }
      }
    }
    
    // 4. Test SQL injection strings
    console.log('4. Testing SQL injection patterns...');
    const sqlPatterns = ["' OR '1'='1", "admin'--", "'; DROP TABLE users--"];
    for (const pattern of sqlPatterns) {
      if (await usernameInput.count() > 0) {
        await usernameInput.fill(pattern);
        const value = await usernameInput.inputValue();
        // Just check if input accepts it (server-side should handle)
        console.log(`   Tested: ${pattern} - Input accepted: ${value === pattern}`);
      }
    }
    
    // 5. Check CSRF protection
    console.log('5. Checking CSRF protection...');
    const csrfToken = await page.locator('input[name*="csrf" i], input[name*="token" i]').count();
    if (csrfToken === 0) {
      issues.push(`⚠️  No CSRF token found in form`);
    }
    
    // 6. Check session handling
    console.log('6. Checking session/cookie handling...');
    const cookies = await page.context().cookies();
    console.log(`   Found ${cookies.length} cookies`);
    for (const cookie of cookies) {
      if (!cookie.secure && cookie.name.toLowerCase().includes('session')) {
        issues.push(`❌ CRITICAL: Session cookie not marked as Secure`);
      }
      if (!cookie.httpOnly && cookie.name.toLowerCase().includes('session')) {
        issues.push(`❌ CRITICAL: Session cookie not marked as HttpOnly`);
      }
    }
    
    // Report
    console.log(`\n=== ACCOUNT PAGE FINDINGS ===`);
    console.log(`Total issues found: ${issues.length}`);
    if (issues.length > 0) {
      issues.forEach((issue, i) => console.log(`${i + 1}. ${issue}`));
    }
    
    await page.screenshot({ path: 'test-results/account-bug-hunting.png', fullPage: true });
    
    expect(issues.filter(i => i.includes('CRITICAL')).length).toBe(0); // No critical issues allowed
  });

  test('Cart Page - State & Calculation Testing', async ({ page }) => {
    console.log('\n=== CART PAGE DEEP DIVE ===\n');
    
    const issues: string[] = [];
    
    await page.goto(`${baseURL}cart.html`);
    await page.waitForLoadState('networkidle');
    
    // 1. Check cart structure
    console.log('1. Analyzing cart structure...');
    const cartItems = await page.locator('.cart-item, [class*="cart"][class*="item"]').all();
    console.log(`   Found ${cartItems.length} cart items`);
    
    // 2. Check for quantity controls
    console.log('2. Checking quantity controls...');
    const quantityInputs = await page.locator('input[type="number"], input[name*="quantity" i]').all();
    for (const input of quantityInputs) {
      const min = await input.getAttribute('min');
      const max = await input.getAttribute('max');
      const value = await input.inputValue();
      
      if (!min || parseInt(min) < 0) {
        issues.push(`⚠️  Quantity input allows negative numbers`);
      }
      if (value && parseInt(value) < 0) {
        issues.push(`❌ Quantity has negative value: ${value}`);
      }
    }
    
    // 3. Test quantity manipulation
    console.log('3. Testing quantity changes...');
    if (quantityInputs.length > 0) {
      const firstQty = quantityInputs[0];
      await firstQty.fill('0');
      await page.waitForTimeout(500);
      // Check if item disappears or shows error
      
      await firstQty.fill('-1');
      const negValue = await firstQty.inputValue();
      if (negValue === '-1') {
        issues.push(`❌ Quantity accepts negative values`);
      }
      
      await firstQty.fill('9999');
      const largeValue = await firstQty.inputValue();
      if (largeValue === '9999') {
        console.log('   ⚠️  No maximum quantity validation');
      }
    }
    
    // 4. Check price calculations
    console.log('4. Checking price calculations...');
    const prices = await page.locator('.price, [class*="price"]').allTextContents();
    for (const price of prices) {
      // Check for valid price format
      const hasCurrency = /[\$€£]/.test(price);
      const hasNumber = /\d+/.test(price);
      if (!hasCurrency && !hasNumber) {
        issues.push(`⚠️  Invalid price format: "${price}"`);
      }
    }
    
    // 5. Check total calculation
    console.log('5. Verifying total calculation...');
    const totalElement = await page.locator('.total, [class*="total"]').first().count();
    if (totalElement > 0) {
      const total = await page.locator('.total, [class*="total"]').first().textContent();
      console.log(`   Total displayed: ${total}`);
    } else {
      console.log('   No total element found');
      issues.push(`⚠️  No total/subtotal displayed in cart`);
    }
    
    // 6. Check localStorage usage
    console.log('6. Checking cart persistence (localStorage)...');
    const localStorageData = await page.evaluate(() => {
      const cart = localStorage.getItem('cart');
      return cart;
    });
    if (!localStorageData) {
      console.log('   No cart data in localStorage');
    } else {
      console.log(`   Cart data found in localStorage`);
      try {
        const parsed = JSON.parse(localStorageData);
        console.log(`   Cart items in storage: ${Array.isArray(parsed) ? parsed.length : 'unknown'}`);
      } catch {
        issues.push(`❌ Cart localStorage data is invalid JSON`);
      }
    }
    
    // 7. Test remove item functionality
    console.log('7. Testing remove item buttons...');
    const removeButtons = await page.locator('button:has-text("remove"), button:has-text("delete"), .remove, [class*="remove"]').all();
    console.log(`   Found ${removeButtons.length} remove buttons`);
    
    // Report
    console.log(`\n=== CART PAGE FINDINGS ===`);
    console.log(`Total issues found: ${issues.length}`);
    if (issues.length > 0) {
      issues.forEach((issue, i) => console.log(`${i + 1}. ${issue}`));
    }
    
    await page.screenshot({ path: 'test-results/cart-bug-hunting.png', fullPage: true });
  });

  test('About Page - Content & Accessibility', async ({ page }) => {
    console.log('\n=== ABOUT PAGE DEEP DIVE ===\n');
    
    const issues: string[] = [];
    
    await page.goto(`${baseURL}about.html`);
    await page.waitForLoadState('networkidle');
    
    // 1. Check page structure
    console.log('1. Checking page structure...');
    const main = await page.locator('main').count();
    const article = await page.locator('article').count();
    const section = await page.locator('section').count();
    
    if (main === 0 && article === 0 && section === 0) {
      issues.push(`⚠️  No semantic content structure (main, article, or section)`);
    }
    
    // 2. Check content quality
    console.log('2. Analyzing content...');
    const bodyText = await page.locator('body').textContent();
    const wordCount = bodyText?.split(/\s+/).length || 0;
    console.log(`   Word count: ${wordCount}`);
    
    if (wordCount < 50) {
      issues.push(`⚠️  Very little content (${wordCount} words)`);
    }
    
    // 3. Check for working links
    console.log('3. Testing all links...');
    const links = await page.locator('a[href]').all();
    for (const link of links) {
      const href = await link.getAttribute('href');
      if (href && !href.startsWith('#') && !href.startsWith('javascript:')) {
        try {
          const response = await page.request.head(href.startsWith('http') ? href : `https://pocketaces2.github.io${href}`);
          if (response.status() >= 400) {
            issues.push(`❌ Broken link: ${href} (${response.status()})`);
          }
        } catch (error) {
          issues.push(`❌ Failed to check link: ${href}`);
        }
      }
    }
    
    // Report
    console.log(`\n=== ABOUT PAGE FINDINGS ===`);
    console.log(`Total issues found: ${issues.length}`);
    if (issues.length > 0) {
      issues.forEach((issue, i) => console.log(`${i + 1}. ${issue}`));
    }
    
    await page.screenshot({ path: 'test-results/about-bug-hunting.png', fullPage: true });
  });

  test('Cross-Browser Compatibility Issues', async ({ page, browserName }) => {
    console.log(`\n=== BROWSER-SPECIFIC TESTING (${browserName}) ===\n`);
    
    const issues: string[] = [];
    
    await page.goto(baseURL);
    await page.waitForLoadState('networkidle');
    
    // 1. Check CSS features
    console.log('1. Checking CSS compatibility...');
    const hasFlexbox = await page.evaluate(() => {
      const div = document.createElement('div');
      div.style.display = 'flex';
      return div.style.display === 'flex';
    });
    if (!hasFlexbox) {
      issues.push(`❌ Flexbox not supported in ${browserName}`);
    }
    
    // 2. Check JavaScript features
    console.log('2. Checking JavaScript compatibility...');
    const hasLocalStorage = await page.evaluate(() => {
      try {
        localStorage.setItem('test', 'test');
        localStorage.removeItem('test');
        return true;
      } catch {
        return false;
      }
    });
    if (!hasLocalStorage) {
      issues.push(`❌ localStorage not available in ${browserName}`);
    }
    
    // 3. Check for browser-specific console warnings
    const warnings: string[] = [];
    page.on('console', msg => {
      if (msg.type() === 'warning') {
        warnings.push(msg.text());
      }
    });
    
    await page.reload();
    await page.waitForTimeout(2000);
    
    if (warnings.length > 0) {
      console.log(`   Found ${warnings.length} console warnings`);
      warnings.slice(0, 3).forEach(w => console.log(`   - ${w}`));
    }
    
    // Report
    console.log(`\n=== ${browserName.toUpperCase()} FINDINGS ===`);
    console.log(`Total issues found: ${issues.length}`);
    if (issues.length > 0) {
      issues.forEach((issue, i) => console.log(`${i + 1}. ${issue}`));
    }
  });
});
