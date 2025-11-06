import { test, expect } from '@playwright/test';

test.describe('Test Case 3: Login Functionality', () => {
  test('should successfully log in with valid credentials', async ({ page }) => {
    // Navigate to login page
    await page.goto('/login.html');
    await page.waitForLoadState('networkidle');
    
    // Try multiple selector strategies for username field
    const usernameField = page.locator('#username, input[name="username"], input[id*="user" i], input[placeholder*="username" i]').first();
    const passwordField = page.locator('#password, input[name="password"], input[type="password"], input[placeholder*="password" i]').first();
    const loginButton = page.locator('#loginBtn, button[type="submit"], button:has-text("Login"), button:has-text("Sign In"), input[type="submit"]').first();
    
    // Wait for form to be visible
    await usernameField.waitFor({ state: 'visible', timeout: 10000 });
    
    // Enter credentials
    await usernameField.fill('demouser');
    await passwordField.fill('fashion123');
    
    // Click login button
    await loginButton.click();
    
    // Wait for navigation or success indicator
    await page.waitForTimeout(2000); // Give time for any redirect/message
    
    // Verify successful login
    const currentURL = page.url();
    const hasError = await page.locator('text=/error|invalid|incorrect|failed/i').isVisible().catch(() => false);
    
    // Check various success indicators
    const hasSuccessMessage = await page.locator('text=/welcome|success|logged in|dashboard/i').isVisible().catch(() => false);
    const notOnLoginPage = !currentURL.includes('login.html');
    const hasUserIndicator = await page.locator('text=/demouser|logout|sign out/i').isVisible().catch(() => false);
    
    console.log(`Current URL after login: ${currentURL}`);
    console.log(`Error message visible: ${hasError}`);
    console.log(`Success message: ${hasSuccessMessage}`);
    console.log(`Not on login page: ${notOnLoginPage}`);
    console.log(`User indicator visible: ${hasUserIndicator}`);
    
    // Assertions - login should succeed
    expect(hasError, 'Login failed - error message displayed').toBe(false);
    
    // At least one success indicator should be true
    const loginSuccessful = hasSuccessMessage || notOnLoginPage || hasUserIndicator;
    expect(loginSuccessful, 'User should be logged in (success message, redirected, or user indicator visible)').toBeTruthy();
  });

  test('should show error or remain on login page with invalid credentials', async ({ page }) => {
    await page.goto('/login.html');
    await page.waitForLoadState('networkidle');
    
    const usernameField = page.locator('#username, input[name="username"], input[id*="user" i], input[placeholder*="username" i]').first();
    const passwordField = page.locator('#password, input[name="password"], input[type="password"], input[placeholder*="password" i]').first();
    const loginButton = page.locator('#loginBtn, button[type="submit"], button:has-text("Login"), button:has-text("Sign In"), input[type="submit"]').first();
    
    // Wait for form
    await usernameField.waitFor({ state: 'visible', timeout: 10000 });
    
    // Enter invalid credentials
    await usernameField.fill('invaliduser');
    await passwordField.fill('wrongpassword');
    await loginButton.click();
    
    await page.waitForTimeout(2000);
    
    // Should still be on login page or show error
    const currentURL = page.url();
    const hasError = await page.locator('text=/error|invalid|incorrect|failed/i').isVisible().catch(() => false);
    
    console.log(`URL after failed login: ${currentURL}`);
    console.log(`Error shown: ${hasError}`);
    
    // Either still on login page OR error is shown
    expect(currentURL.includes('login.html') || hasError, 'Should remain on login page or show error with invalid credentials').toBeTruthy();
  });
});
