// This script generates a PDF from a markdown file using Playwright, similar to generate-pdf.js
// Usage: node generate-pdf-generic.js <input-md> <output-pdf>

const { chromium } = require('@playwright/test');
const fs = require('fs');
const path = require('path');
const marked = require('marked');

(async () => {
  const [,, inputMd, outputPdf] = process.argv;
  if (!inputMd || !outputPdf) {
    console.error('Usage: node generate-pdf-generic.js <input-md> <output-pdf>');
    process.exit(1);
  }
  const browser = await chromium.launch();
  const page = await browser.newPage();
  const markdown = fs.readFileSync(inputMd, 'utf-8');
  const html = marked.parse(markdown);
  const fullHtml = `<!DOCTYPE html><html><head><meta charset=\"UTF-8\"><style>body{font-family:Arial,sans-serif;font-size:13px;line-height:1.5;max-width:900px;margin:0 auto;padding:20px;}h1{color:#111;border-bottom:3px solid #111;padding-bottom:8px;margin-top:32px;}h2{color:#222;border-bottom:2px solid #111;padding-bottom:6px;margin-top:24px;}h3{color:#333;margin-top:18px;}code{background-color:#f4f4f4;padding:2px 6px;border-radius:3px;}img{max-width:100%;height:auto;border:1px solid #ddd;margin:10px 0;}table{border-collapse:collapse;width:100%;margin:20px 0;font-size:13px;}th,td{border:1px solid #888;padding:8px 10px;text-align:left;}th{background-color:#222;color:#fff;}tbody tr:nth-child(even){background-color:#f6f6f6;}tbody tr:nth-child(odd){background-color:#fff;}li{margin:4px 0;}</style></head><body>${html}</body></html>`;
  await page.setContent(fullHtml);
  await page.pdf({ path: outputPdf, format: 'A4', margin: { top: '20mm', right: '20mm', bottom: '20mm', left: '20mm' }, printBackground: true });
  console.log(`✅ PDF generated: ${outputPdf}`);
  await browser.close();
})();
