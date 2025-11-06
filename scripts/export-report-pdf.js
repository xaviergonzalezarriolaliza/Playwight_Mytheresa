// Export the latest Playwright HTML report to a PDF file
// Usage: node scripts/export-report-pdf.js [optional:path-to-report-folder]
// If no path is provided, it finds the newest folder under reports/ automatically.

const fs = require('fs');
const path = require('path');
const { chromium } = require('@playwright/test');

function isDirectory(p) {
  try {
    return fs.statSync(p).isDirectory();
  } catch {
    return false;
  }
}

function findLatestReportDir(root) {
  if (!fs.existsSync(root)) return null;
  const entries = fs.readdirSync(root)
    .map(name => ({ name, full: path.join(root, name) }))
    .filter(e => isDirectory(e.full));
  if (entries.length === 0) return null;
  // Sort by mtime desc
  entries.sort((a, b) => fs.statSync(b.full).mtimeMs - fs.statSync(a.full).mtimeMs);
  return entries[0].full;
}

async function main() {
  const provided = process.argv[2] ? path.resolve(process.argv[2]) : null;
  const reportsRoot = path.resolve('reports');
  const reportDir = provided || findLatestReportDir(reportsRoot);
  if (!reportDir) {
    console.error('No report directory found under reports/. Make sure tests have generated a report.');
    process.exit(1);
  }

  const htmlDir = path.join(reportDir, 'html');
  const indexHtml = path.join(htmlDir, 'index.html');
  if (!fs.existsSync(indexHtml)) {
    console.error(`HTML report not found at: ${indexHtml}`);
    process.exit(1);
  }

  const pdfOut = path.join(reportDir, 'TEST_REPORT.pdf');

  const browser = await chromium.launch({ headless: true });
  const page = await browser.newPage();

  // Build file:// URL compatible with Windows and POSIX
  const fileUrl = 'file:///' + indexHtml.replace(/\\/g, '/');

  await page.goto(fileUrl, { waitUntil: 'load' });
  // Give the SPA a moment to render everything
  await page.waitForTimeout(1000);

  // Try to expand any collapsible sections if present (best-effort)
  try {
    await page.evaluate(() => {
      // Expand any details elements
      document.querySelectorAll('details').forEach(d => (d.open = true));
    });
  } catch {}

  // Generate PDF
  await page.pdf({
    path: pdfOut,
    format: 'A4',
    printBackground: true,
    margin: { top: '10mm', right: '10mm', bottom: '10mm', left: '10mm' },
  });

  console.log(`✅ Report PDF created: ${pdfOut}`);
  await browser.close();
}

main().catch(err => {
  console.error('Failed to export report to PDF:', err);
  process.exit(1);
});
