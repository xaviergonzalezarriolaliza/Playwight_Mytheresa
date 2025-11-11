import { test, expect } from '@playwright/test';
import * as fs from 'fs';
import * as path from 'path';

interface PullRequest {
  title: string;
  createdDate: string;
  author: string;
}

test.describe('Test Case 4: GitHub Pull Request Scraper', {
  tag: ['@external', '@github', '@api-scraping', '@independent']
}, () => {
  test('should fetch open PRs and generate CSV report with dual verification', async ({ page }, testInfo) => {
    // Increase timeout significantly for full pagination
    test.setTimeout(600000); // 10 minutes for all pages
    
    const repoUrl = 'https://github.com/appwrite/appwrite/pulls';
    
    // Get browser name from test info
    const browserName = testInfo.project.name;
    
    await page.goto(repoUrl);
    await page.waitForLoadState('domcontentloaded');
    
    // Wait for PR list to load
    await page.waitForSelector('.js-issue-row', { timeout: 10000 });
    
    // Extract total PR count from the PR navigation tab
    let totalPRs = 0;
    try {
      // Use the correct selector for the PRs tab counter
      const counterText = await page.locator('a.btn-link.selected[data-ga-click*="Pull Requests"] .Counter').first().textContent({ timeout: 5000 });
      totalPRs = parseInt(counterText?.replace(/[^\d]/g, '') || '0', 10);
    } catch {
      try {
        // Method 2: Count visible PRs and estimate from pagination
        const visiblePRs = await page.locator('.js-issue-row').count();
        // Check if there's a "Next" button to determine if there are more pages
        const hasNextPage = await page.locator('a[rel="next"]').count() > 0;
        if (hasNextPage) {
          // GitHub typically shows 25 per page
          totalPRs = visiblePRs * 10; // Rough estimate
          console.log(`⚠️  Could not find exact count, estimating ~${totalPRs} PRs`);
        } else {
          totalPRs = visiblePRs;
        }
      } catch {
        // Fallback: just scrape the first page 
        totalPRs = 25;
        console.log(`⚠️  Could not determine total, will scrape first page only`);
      }
    }
    console.log(`\n📊 Total Open PRs: ${totalPRs}`);
    
    // Calculate number of pages (25 PRs per page on GitHub)
    const prsPerPage = 25;
    const totalPages = Math.ceil(totalPRs / prsPerPage);
    console.log(`📄 Total Pages to scrape: ${totalPages}`);
    console.log(`⏱️  Estimated time: ${Math.ceil(totalPages * 15 / 60)} minutes\n`);
    
    // Store all PRs from all pages
    const allPullRequests1: { title: string; createdDate: string; author: string; url: string }[] = [];
    const allPullRequests2: { title: string; createdDate: string; author: string; url: string }[] = [];
    const allPullRequests3: { title: string; createdDate: string; author: string; url: string }[] = [];
    
    // Loop through all pages
    for (let currentPage = 1; currentPage <= totalPages; currentPage++) {
      console.log(`\n━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━`);
      console.log(`📄 PAGE ${currentPage}/${totalPages} (${Math.round(currentPage/totalPages*100)}% complete)`);
      console.log(`━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━`);
      
      // Navigate to specific page if not on page 1
      if (currentPage > 1) {
        const pageUrl = `${repoUrl}?page=${currentPage}`;
        await page.goto(pageUrl);
        await page.waitForLoadState('domcontentloaded');
        
        // Check if PRs exist on this page
        const prCount = await page.locator('.js-issue-row').count();
        if (prCount === 0) {
          console.log(`  ⚠️  No PRs found on page ${currentPage}, stopping pagination`);
          break;
        }
        
        await page.waitForSelector('.js-issue-row', { timeout: 10000 });
        // Small delay to ensure page is fully loaded
        await page.waitForTimeout(1000);
      }
    
    // ============================================================================
    // STRATEGY 1: DOM Query with Multiple Selectors (Defensive)
    // Uses multiple fallback selectors and thorough validation
    // ============================================================================
    console.log('  Strategy 1: DOM Query with Fallbacks...');
    const pullRequests1 = await page.evaluate(() => {
      // Try the most reliable selector first
      let prElements = document.querySelectorAll('.js-issue-row');
      
      // Fallback to aria labels if needed
      if (prElements.length === 0) {
        prElements = document.querySelectorAll('[aria-label*="pull request"]');
      }
      
      const prs: { title: string; createdDate: string; author: string; url: string }[] = [];
      
      prElements.forEach((prElement) => {
        try {
          // Find title link - try multiple selectors
          const titleElement = prElement.querySelector('a[href*="/pull/"]') ||
                              prElement.querySelector('a.Link--primary') ||
                              prElement.querySelector('.Link--primary');
          
          if (!titleElement) return;
          
          const title = titleElement.textContent?.trim() || '';
          const href = (titleElement as HTMLAnchorElement).href || '';
          
          // Build full URL
          let url = href;
          if (href && !href.startsWith('http')) {
            url = `https://github.com${href}`;
          }
          
          // Find author
          const authorElement = prElement.querySelector('[data-hovercard-type="user"]') ||
                               prElement.querySelector('a[href^="/"][href*="/"]');
          const author = authorElement?.textContent?.trim() || 'N/A';
          
          // Find date
          const dateElement = prElement.querySelector('relative-time');
          const createdDate = dateElement?.getAttribute('datetime') || 'N/A';
          
          if (title && url && url.includes('/pull/')) {
            prs.push({ title, createdDate, author, url });
          }
        } catch (error) {
          // Skip problematic elements
        }
      });
      
      return prs;
    });
    
    allPullRequests1.push(...pullRequests1);
    console.log(`    Found ${pullRequests1.length} PRs (Total so far: ${allPullRequests1.length})`);
    
    // ============================================================================
    // STRATEGY 2: Class-based Selector Strategy
    // ============================================================================
    console.log('  Strategy 2: Class-based Selectors...');
    const pullRequests2 = await page.evaluate(() => {
      const prElements = document.querySelectorAll('.js-issue-row');
      const prs: { title: string; createdDate: string; author: string; url: string }[] = [];
      
      prElements.forEach((prElement) => {
        try {
          const titleElement = prElement.querySelector('a[href*="/pull/"]') ||
                              prElement.querySelector('.Link--primary');
          const title = titleElement?.textContent?.trim() || '';
          const url = (titleElement as HTMLAnchorElement)?.href || '';
          
          const authorElement = prElement.querySelector('[data-hovercard-type="user"]');
          const author = authorElement?.textContent?.trim() || '';
          
          const dateElement = prElement.querySelector('relative-time');
          const createdDate = dateElement?.getAttribute('datetime') || '';
          
          if (title && url && url.includes('/pull/')) {
            prs.push({ title, createdDate: createdDate || 'N/A', author: author || 'N/A', url });
          }
        } catch (error) {
          // Skip problematic elements
        }
      });
      
      return prs;
    });
    
    allPullRequests2.push(...pullRequests2);
    console.log(`    Found ${pullRequests2.length} PRs (Total so far: ${allPullRequests2.length})`);
    
    // ============================================================================
    // STRATEGY 3: Playwright Locator API with Robust Selectors
    // Uses .js-issue-row like Strategy 2 but with Playwright's API for comparison
    // ============================================================================
    console.log('  Strategy 3: Playwright Locator API...');
    
    // Wait for PR list using the class-based selector
    await page.waitForSelector('.js-issue-row', { timeout: 10000 });
    const prRows = await page.locator('.js-issue-row').all();
    const pullRequests3: { title: string; createdDate: string; author: string; url: string }[] = [];
    
    for (const prRow of prRows) {
      try {
        // Try multiple selectors for title (more robust)
        const titleLoc = prRow.locator('a[href*="/pull/"]').first();
        const titleExists = await titleLoc.count() > 0;
        
        if (!titleExists) continue;
        
        const title = await titleLoc.textContent() || '';
        const href = await titleLoc.getAttribute('href') || '';
        
        // Build full URL if it's relative
        let url = href;
        if (href && !href.startsWith('http')) {
          url = `https://github.com${href}`;
        }
        
        // Get author with fallback
        let author = 'N/A';
        const authorLoc = prRow.locator('[data-hovercard-type="user"]').first();
        if (await authorLoc.count() > 0) {
          author = await authorLoc.textContent() || 'N/A';
        }
        
        // Get date with fallback
        let createdDate = 'N/A';
        const dateLoc = prRow.locator('relative-time').first();
        if (await dateLoc.count() > 0) {
          createdDate = await dateLoc.getAttribute('datetime') || 'N/A';
        }
        
        if (title.trim() && url.includes('/pull/')) {
          pullRequests3.push({ 
            title: title.trim(), 
            createdDate, 
            author: author.trim(), 
            url 
          });
        }
      } catch (error) {
        // Skip rows that don't have complete data
        console.log(`  Skipped row due to error: ${error}`);
      }
    }
    
    allPullRequests3.push(...pullRequests3);
    console.log(`    Found ${pullRequests3.length} PRs (Total so far: ${allPullRequests3.length})`);
    }
    
    // ============================================================================
    // SUMMARY AFTER ALL PAGES
    // ============================================================================
    console.log(`\n\n${'='.repeat(80)}`);
    console.log(`✅ SCRAPING COMPLETE - All ${totalPages} pages processed`);
    console.log(`${'='.repeat(80)}`);
    console.log(`Strategy 1 Total: ${allPullRequests1.length} PRs`);
    console.log(`Strategy 2 Total: ${allPullRequests2.length} PRs`);
    console.log(`Strategy 3 Total: ${allPullRequests3.length} PRs`);
    
    // ============================================================================
    // TRIPLE VERIFICATION: Compare all three strategies
    // ============================================================================
    console.log('\n=== TRIPLE VERIFICATION ANALYSIS ===');
    
    // All three must agree (exact match required)
    const allAgree = (allPullRequests1.length === allPullRequests2.length) && 
                     (allPullRequests2.length === allPullRequests3.length);
    
    console.log(`All strategies agree: ${allAgree ? '✅ PERFECT' : '⚠️  MISMATCH DETECTED'}`);
    console.log(`  Strategy 1 (data attributes): ${allPullRequests1.length} PRs`);
    console.log(`  Strategy 2 (classes):          ${allPullRequests2.length} PRs`);
    console.log(`  Strategy 3 (Playwright API):   ${allPullRequests3.length} PRs`);
    
    if (!allAgree) {
      console.log('\n⚠️  WARNING: Strategies returned different counts!');
      console.log('  This might indicate:');
      console.log('  - DOM structure changed');
      console.log('  - Incomplete data in some PRs');
      console.log('  - Different filtering logic');
    }
    
    // Cross-verify by URL (most reliable unique identifier)
    const urls1 = new Set(allPullRequests1.map(pr => pr.url));
    const urls2 = new Set(allPullRequests2.map(pr => pr.url));
    const urls3 = new Set(allPullRequests3.map(pr => pr.url));
    
    // Find common URLs across all strategies
    const commonUrls = [...urls1].filter(url => urls2.has(url) && urls3.has(url));
    console.log(`\nCommon PRs across all strategies: ${commonUrls.length}`);
    
    // Find unique to each strategy
    const onlyIn1 = [...urls1].filter(url => !urls2.has(url) || !urls3.has(url));
    const onlyIn2 = [...urls2].filter(url => !urls1.has(url) || !urls3.has(url));
    const onlyIn3 = [...urls3].filter(url => !urls1.has(url) || !urls2.has(url));
    
    if (onlyIn1.length > 0) console.log(`  Only in Strategy 1: ${onlyIn1.length}`);
    if (onlyIn2.length > 0) console.log(`  Only in Strategy 2: ${onlyIn2.length}`);
    if (onlyIn3.length > 0) console.log(`  Only in Strategy 3: ${onlyIn3.length}`);
    
    // Use strategy with most results, but require at least 2 strategies for verification
    const finalPullRequests: { title: string; createdDate: string; author: string; url: string; verifiedBy: number }[] = [];
    
    // Combine all PRs and track which strategies found them
    const allUrls = new Set([...urls1, ...urls2, ...urls3]);
    
    allUrls.forEach(url => {
      let foundCount = 0;
      let prData = null;
      
      if (urls1.has(url)) { foundCount++; prData = allPullRequests1.find(pr => pr.url === url); }
      if (urls2.has(url)) { foundCount++; prData = prData || allPullRequests2.find(pr => pr.url === url); }
      if (urls3.has(url)) { foundCount++; prData = prData || allPullRequests3.find(pr => pr.url === url); }
      
      // Only include PRs found by at least 2 strategies for quality assurance
      if (foundCount >= 2 && prData) {
        finalPullRequests.push({ ...prData, verifiedBy: foundCount });
      }
    });
    
    console.log(`\nFinal verified dataset: ${finalPullRequests.length} PRs`);
    console.log(`  Verified by 3 strategies: ${finalPullRequests.filter(pr => pr.verifiedBy === 3).length}`);
    console.log(`  Verified by 2 strategies: ${finalPullRequests.filter(pr => pr.verifiedBy === 2).length}`);
    
    console.log(`\n=== Generating CSV Report ===`);
    console.log(`Total PRs in final dataset: ${finalPullRequests.length}`);
    
    // Generate CSV content
    const csvHeader = 'PR Name,Created Date,Author,PR URL,Verified By\n';
    const csvRows = finalPullRequests.map(pr => {
      // Escape commas and quotes in CSV
      const escapeCsv = (str: string) => {
        if (str.includes(',') || str.includes('"') || str.includes('\n')) {
          return `"${str.replace(/"/g, '""')}"`;
        }
        return str;
      };
      
      const verificationStatus = `${pr.verifiedBy}/3 strategies`;
      
      return `${escapeCsv(pr.title)},${escapeCsv(pr.createdDate)},${escapeCsv(pr.author)},${escapeCsv(pr.url)},${verificationStatus}`;
    }).join('\n');
    
    const csvContent = csvHeader + csvRows;
    
    // Create output directory if it doesn't exist
    const outputDir = path.join(process.cwd(), 'test-results');
    if (!fs.existsSync(outputDir)) {
      fs.mkdirSync(outputDir, { recursive: true });
    }
    
    // Write CSV file with browser name in filename
    const timestamp = new Date().toISOString().replace(/[:.]/g, '-');
    const csvFilePath = path.join(outputDir, `github-prs-${browserName}-${timestamp}.csv`);
    fs.writeFileSync(csvFilePath, csvContent, 'utf-8');
    
    console.log(`\n=== Pull Requests CSV Report ===`);
    console.log(`Browser: ${browserName}`);
    console.log(`Total PRs: ${finalPullRequests.length}`);
    console.log(`CSV file saved to: ${csvFilePath}`);
    console.log(`Verification column: Shows how many strategies found each PR (x/3)`);
    console.log('\nFirst 5 PRs:');
    finalPullRequests.slice(0, 5).forEach((pr, index) => {
      const icon = pr.verifiedBy === 3 ? '✅✅✅' : pr.verifiedBy === 2 ? '✅✅' : '✅';
      console.log(`${index + 1}. ${pr.title} ${icon}`);
      console.log(`   Author: ${pr.author}, Created: ${pr.createdDate}`);
      console.log(`   Verified by: ${pr.verifiedBy}/3 strategies`);
    });
    
    // Assertions - Strict mode: All strategies must agree
    expect(finalPullRequests.length, 'Should find at least one open PR').toBeGreaterThan(0);
    expect(fs.existsSync(csvFilePath), 'CSV file should be created').toBeTruthy();
    
    // All strategies MUST agree for the test to pass
    expect(allAgree, 'All three strategies must return the same count for robust verification').toBeTruthy();
    
    // Verify CSV content
    const csvFileContent = fs.readFileSync(csvFilePath, 'utf-8');
    expect(csvFileContent).toContain('PR Name,Created Date,Author,PR URL,Verified By');
    expect(csvFileContent.split('\n').length).toBeGreaterThan(1);
    
    // Additional verification: ensure we have meaningful data
    const hasValidData = finalPullRequests.every(pr => 
      pr.title.length > 0 && 
      pr.author.length > 0 &&
      pr.createdDate.length > 0 &&
      pr.url.includes('/pull/')
    );
    expect(hasValidData, 'All PRs should have valid title, author, date, and URL').toBeTruthy();
    
    // Verify high verification rate: at least 90% verified by all 3 strategies
    const fullyVerified = finalPullRequests.filter(pr => pr.verifiedBy === 3).length;
    const verificationRate = (fullyVerified / finalPullRequests.length) * 100;
    console.log(`\nVerification rate: ${verificationRate.toFixed(1)}% verified by all 3 strategies`);
    expect(verificationRate, 'At least 90% of PRs should be verified by all 3 strategies').toBeGreaterThanOrEqual(90);
  });
});
