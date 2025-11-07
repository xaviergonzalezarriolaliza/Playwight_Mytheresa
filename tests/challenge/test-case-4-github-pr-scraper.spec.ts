import { test, expect } from '@playwright/test';
import * as fs from 'fs';
import * as path from 'path';

interface PullRequest {
  title: string;
  createdDate: string;
  author: string;
}

test.describe('Test Case 4: GitHub Pull Request Scraper', () => {
  test('should fetch open PRs and generate CSV report with dual verification', async ({ page }, testInfo) => {
    const repoUrl = 'https://github.com/appwrite/appwrite/pulls';
    
    // Get browser name from test info
    const browserName = testInfo.project.name;
    
    await page.goto(repoUrl);
    await page.waitForLoadState('networkidle');
    
    // Wait for PR list to load
    await page.waitForSelector('[data-hovercard-type="pull_request"], .js-issue-row', { timeout: 10000 });
    
    // ============================================================================
    // STRATEGY 1: Primary Selector Strategy (data attributes + semantic classes)
    // ============================================================================
    console.log('\n=== STRATEGY 1: Primary Selectors ===');
    const pullRequests1 = await page.evaluate(() => {
      const prElements = document.querySelectorAll('[data-hovercard-type="pull_request"], .js-issue-row');
      const prs: { title: string; createdDate: string; author: string }[] = [];
      
      prElements.forEach((prElement) => {
        try {
          // Primary selector: data attribute for title
          const titleElement = prElement.querySelector('a.Link--primary, .markdown-title');
          const title = titleElement?.textContent?.trim() || 'N/A';
          
          // Primary selector: data attribute for author
          const authorElement = prElement.querySelector('[data-hovercard-type="user"], .opened-by a');
          const author = authorElement?.textContent?.trim() || 'N/A';
          
          // Primary selector: relative-time component
          const dateElement = prElement.querySelector('relative-time, time, .opened-by relative-time');
          const createdDate = dateElement?.getAttribute('datetime') || 
                            dateElement?.getAttribute('title') ||
                            dateElement?.textContent?.trim() || 'N/A';
          
          if (title !== 'N/A') {
            prs.push({ title, createdDate, author });
          }
        } catch (error) {
          console.error('Strategy 1 - Error extracting PR data:', error);
        }
      });
      
      return prs;
    });
    
    console.log(`Strategy 1 found: ${pullRequests1.length} PRs`);
    
    // ============================================================================
    // STRATEGY 2: Alternative Selector Strategy (structural navigation)
    // ============================================================================
    console.log('\n=== STRATEGY 2: Alternative Selectors ===');
    const pullRequests2 = await page.evaluate(() => {
      // Alternative approach: Use different structural selectors
      const prElements = document.querySelectorAll('div[id^="issue_"], .js-navigation-item, [data-id]');
      const prs: { title: string; createdDate: string; author: string }[] = [];
      
      prElements.forEach((prElement) => {
        try {
          // Alternative selector: look for any link in the PR row
          const titleElement = prElement.querySelector('a[id^="issue_"], a.js-navigation-open, a[href*="/pull/"]') ||
                              prElement.querySelector('a:not([data-hovercard-type="user"])');
          const title = titleElement?.textContent?.trim() || 'N/A';
          
          // Alternative selector: find author by relationship to title
          const authorElement = prElement.querySelector('a[href^="/"][href*="/"][data-hovercard-type="user"]') ||
                               prElement.querySelector('.opened-by a:first-of-type');
          const author = authorElement?.textContent?.trim() || 'N/A';
          
          // Alternative selector: find time element by tag and attributes
          const dateElement = prElement.querySelector('relative-time[datetime]') ||
                             prElement.querySelector('time[datetime]') ||
                             prElement.querySelector('[datetime]');
          const createdDate = dateElement?.getAttribute('datetime') || 
                            dateElement?.getAttribute('title') ||
                            'N/A';
          
          // Only add if we got meaningful data
          if (title !== 'N/A' && title.length > 0 && !title.includes('Author') && !title.includes('Label')) {
            prs.push({ title, createdDate, author });
          }
        } catch (error) {
          console.error('Strategy 2 - Error extracting PR data:', error);
        }
      });
      
      return prs;
    });
    
    console.log(`Strategy 2 found: ${pullRequests2.length} PRs`);
    
    // ============================================================================
    // VERIFICATION: Compare results from both strategies
    // ============================================================================
    console.log('\n=== DUAL VERIFICATION ANALYSIS ===');
    
    // Use Strategy 1 as primary, but validate with Strategy 2
    const pullRequests = pullRequests1;
    
    // Check if both strategies found similar number of PRs (within 10% tolerance)
    const difference = Math.abs(pullRequests1.length - pullRequests2.length);
    const tolerance = Math.max(pullRequests1.length, pullRequests2.length) * 0.1;
    const strategiesAgree = difference <= tolerance;
    
    console.log(`Strategy agreement: ${strategiesAgree ? '✅ PASS' : '⚠️  WARNING'}`);
    console.log(`  Strategy 1: ${pullRequests1.length} PRs`);
    console.log(`  Strategy 2: ${pullRequests2.length} PRs`);
    console.log(`  Difference: ${difference} (tolerance: ${Math.round(tolerance)})`);
    
    // Cross-verify titles exist in both strategies
    if (pullRequests1.length > 0 && pullRequests2.length > 0) {
      const titles1 = new Set(pullRequests1.map(pr => pr.title));
      const titles2 = new Set(pullRequests2.map(pr => pr.title));
      
      let matchCount = 0;
      titles1.forEach(title => {
        if (titles2.has(title)) matchCount++;
      });
      
      const matchPercentage = (matchCount / Math.max(titles1.size, titles2.size)) * 100;
      console.log(`\nTitle cross-verification:`);
      console.log(`  Matching titles: ${matchCount}/${Math.max(titles1.size, titles2.size)} (${matchPercentage.toFixed(1)}%)`);
      
      if (matchPercentage < 80) {
        console.log(`  ⚠️  WARNING: Low match percentage might indicate selector changes`);
      } else {
        console.log(`  ✅ High confidence in data accuracy`);
      }
    }
    
    // Use the strategy with more results as primary data
    const primaryData = pullRequests1.length >= pullRequests2.length ? pullRequests1 : pullRequests2;
    const primaryStrategy = pullRequests1.length >= pullRequests2.length ? 'Strategy 1' : 'Strategy 2';
    console.log(`\nUsing ${primaryStrategy} as primary data source (${primaryData.length} PRs)`);
    
    // Final dataset
    const finalPullRequests = primaryData;
    
    console.log(`\n=== Generating CSV Report ===`);
    console.log(`Total PRs in final dataset: ${finalPullRequests.length}`);
    
    // Generate CSV content
    const csvHeader = 'PR Name,Created Date,Author,Verification Status\n';
    const csvRows = finalPullRequests.map(pr => {
      // Escape commas and quotes in CSV
      const escapeCsv = (str: string) => {
        if (str.includes(',') || str.includes('"') || str.includes('\n')) {
          return `"${str.replace(/"/g, '""')}"`;
        }
        return str;
      };
      
      // Check if this PR was found by both strategies
      const foundInBoth = pullRequests1.some(p1 => p1.title === pr.title) && 
                         pullRequests2.some(p2 => p2.title === pr.title);
      const verificationStatus = foundInBoth ? 'Verified' : 'Single Source';
      
      return `${escapeCsv(pr.title)},${escapeCsv(pr.createdDate)},${escapeCsv(pr.author)},${verificationStatus}`;
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
    console.log(`Verification column added: Shows if PR was found by both strategies`);
    console.log('\nFirst 5 PRs:');
    finalPullRequests.slice(0, 5).forEach((pr, index) => {
      const verified = pullRequests1.some(p1 => p1.title === pr.title) && 
                      pullRequests2.some(p2 => p2.title === pr.title);
      console.log(`${index + 1}. ${pr.title} ${verified ? '✅' : '⚠️'}`);
      console.log(`   Author: ${pr.author}, Created: ${pr.createdDate}`);
    });
    
    // Assertions
    expect(finalPullRequests.length, 'Should find at least one open PR').toBeGreaterThan(0);
    expect(fs.existsSync(csvFilePath), 'CSV file should be created').toBeTruthy();
    expect(strategiesAgree, 'Both selector strategies should find similar number of PRs').toBeTruthy();
    
    // Verify CSV content
    const csvFileContent = fs.readFileSync(csvFilePath, 'utf-8');
    expect(csvFileContent).toContain('PR Name,Created Date,Author,Verification Status');
    expect(csvFileContent.split('\n').length).toBeGreaterThan(1);
    
    // Additional verification: ensure we have meaningful data
    const hasValidData = finalPullRequests.every(pr => 
      pr.title.length > 0 && 
      pr.title !== 'N/A' &&
      pr.author.length > 0
    );
    expect(hasValidData, 'All PRs should have valid title and author').toBeTruthy();
  });
});
