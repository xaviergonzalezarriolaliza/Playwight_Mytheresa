import { test, expect } from '@playwright/test';
import * as fs from 'fs';
import * as path from 'path';

interface PullRequest {
  title: string;
  createdDate: string;
  author: string;
}

test.describe('Test Case 4: GitHub Pull Request Scraper', () => {
  test('should fetch open PRs and generate CSV report', async ({ page }) => {
    const repoUrl = 'https://github.com/appwrite/appwrite/pulls';
    
    await page.goto(repoUrl);
    await page.waitForLoadState('networkidle');
    
    // Wait for PR list to load
    await page.waitForSelector('[data-hovercard-type="pull_request"], .js-issue-row', { timeout: 10000 });
    
    // Extract PR information
    const pullRequests = await page.evaluate(() => {
      const prElements = document.querySelectorAll('[data-hovercard-type="pull_request"], .js-issue-row');
      const prs: { title: string; createdDate: string; author: string }[] = [];
      
      prElements.forEach((prElement) => {
        try {
          // Get PR title
          const titleElement = prElement.querySelector('a.Link--primary, .markdown-title');
          const title = titleElement?.textContent?.trim() || 'N/A';
          
          // Get author
          const authorElement = prElement.querySelector('[data-hovercard-type="user"], .opened-by a');
          const author = authorElement?.textContent?.trim() || 'N/A';
          
          // Get created date
          const dateElement = prElement.querySelector('relative-time, time, .opened-by relative-time');
          const createdDate = dateElement?.getAttribute('datetime') || 
                            dateElement?.getAttribute('title') ||
                            dateElement?.textContent?.trim() || 'N/A';
          
          if (title !== 'N/A') {
            prs.push({ title, createdDate, author });
          }
        } catch (error) {
          console.error('Error extracting PR data:', error);
        }
      });
      
      return prs;
    });
    
    console.log(`Found ${pullRequests.length} open pull requests`);
    
    // Generate CSV content
    const csvHeader = 'PR Name,Created Date,Author\n';
    const csvRows = pullRequests.map(pr => {
      // Escape commas and quotes in CSV
      const escapeCsv = (str: string) => {
        if (str.includes(',') || str.includes('"') || str.includes('\n')) {
          return `"${str.replace(/"/g, '""')}"`;
        }
        return str;
      };
      
      return `${escapeCsv(pr.title)},${escapeCsv(pr.createdDate)},${escapeCsv(pr.author)}`;
    }).join('\n');
    
    const csvContent = csvHeader + csvRows;
    
    // Create output directory if it doesn't exist
    const outputDir = path.join(process.cwd(), 'test-results');
    if (!fs.existsSync(outputDir)) {
      fs.mkdirSync(outputDir, { recursive: true });
    }
    
    // Write CSV file
    const timestamp = new Date().toISOString().replace(/[:.]/g, '-');
    const csvFilePath = path.join(outputDir, `github-prs-${timestamp}.csv`);
    fs.writeFileSync(csvFilePath, csvContent, 'utf-8');
    
    console.log(`\n=== Pull Requests CSV Report ===`);
    console.log(`Total PRs: ${pullRequests.length}`);
    console.log(`CSV file saved to: ${csvFilePath}`);
    console.log('\nFirst 5 PRs:');
    pullRequests.slice(0, 5).forEach((pr, index) => {
      console.log(`${index + 1}. ${pr.title}`);
      console.log(`   Author: ${pr.author}, Created: ${pr.createdDate}`);
    });
    
    // Assertions
    expect(pullRequests.length, 'Should find at least one open PR').toBeGreaterThan(0);
    expect(fs.existsSync(csvFilePath), 'CSV file should be created').toBeTruthy();
    
    // Verify CSV content
    const csvFileContent = fs.readFileSync(csvFilePath, 'utf-8');
    expect(csvFileContent).toContain('PR Name,Created Date,Author');
    expect(csvFileContent.split('\n').length).toBeGreaterThan(1);
  });
});
