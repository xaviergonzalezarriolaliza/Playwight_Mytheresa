// Generic markdown -> PDF generator for migration guide (or any markdown file)
// Usage: node scripts/generate-migration-pdf.js MIGRATION_GUIDE.md
// Default file if omitted: MIGRATION_GUIDE.md

const { chromium } = require('@playwright/test');
const fs = require('fs');
const path = require('path');

(async () => {
  const target = process.argv[2] || 'MIGRATION_GUIDE.md';
  if (!fs.existsSync(target)) {
    console.error(`Markdown file not found: ${target}`);
    process.exit(1);
  }
  const browser = await chromium.launch();
  const page = await browser.newPage();
  const markdown = fs.readFileSync(target, 'utf-8');

  // Basic markdown to HTML (lightweight)
  let html = markdown
    .replace(/^# (.*$)/gim, '<h1>$1</h1>')
    .replace(/^## (.*$)/gim, '<h2>$1</h2>')
    .replace(/^### (.*$)/gim, '<h3>$1</h3>')
    .replace(/^#### (.*$)/gim, '<h4>$1</h4>')
    .replace(/^\- (.*$)/gim, '<li>$1</li>')
    .replace(/\*\*(.*?)\*\*/g, '<strong>$1</strong>')
    .replace(/`([^`]+)`/g, '<code>$1</code>')
    .replace(/\[(.*?)\]\((.*?)\)/g, '<a href="$2">$1</a>')
    .replace(/\n\n/g, '<br/><br/>');

  const fullHtml = `<!DOCTYPE html><html><head><meta charset='UTF-8'>
    <style>
      body { font-family: Arial, sans-serif; line-height:1.55; max-width:960px; margin:0 auto; padding:32px; }
      h1 { color:#2c3e50; border-bottom:3px solid #3498db; padding-bottom:10px; }
      h2 { color:#34495e; border-bottom:2px solid #95a5a6; padding-bottom:6px; margin-top:28px; }
      h3 { color:#555; margin-top:22px; }
      code { background:#f5f5f5; padding:3px 6px; border-radius:4px; }
      li { margin:4px 0; }
      a { color:#2980b9; text-decoration:none; }
      a:hover { text-decoration:underline; }
      table { border-collapse: collapse; width:100%; margin:16px 0; }
      th, td { border:1px solid #ccc; padding:8px 10px; text-align:left; }
      th { background:#3498db; color:#fff; }
    </style></head><body>${html}</body></html>`;

  await page.setContent(fullHtml);
  const baseName = path.basename(target, path.extname(target));
  const timestamp = new Date().toISOString().replace(/[:.]/g, '-').slice(0,19);
  const outName = `${baseName}_${timestamp}.pdf`;

  await page.pdf({
    path: outName,
    format: 'A4',
    margin: { top: '15mm', right: '15mm', bottom: '15mm', left: '15mm' },
    printBackground: true
  });

  console.log(`✅ Migration guide PDF generated: ${outName}`);
  await browser.close();
})();
