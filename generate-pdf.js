const { chromium } = require('@playwright/test');
const fs = require('fs');
const path = require('path');
const marked = require('marked');

(async () => {
  const browser = await chromium.launch();
  const page = await browser.newPage();

  // Support CLI args: node generate-pdf.js [input.md] [output.pdf]
  const inputFile = process.argv[2] || 'docs/QA_TECHNICAL_CHALLENGE_SOLUTION.md';
  const outputFile = process.argv[3] || 'docs/LUX_QA_CHALLENGE_SOLUTION_XGA.pdf';

  // Read the markdown and convert to HTML
  const markdown = fs.readFileSync(inputFile, 'utf-8');
  
  // Convert markdown tables to ASCII-art tables in <pre> blocks
  function mdTableToAscii(md) {
    return md.replace(/\n\|(.+\|)+\n\|([\-: ]+\|)+\n([\s\S]+?)(?=\n\n|$)/g, (match) => {
      const lines = match.trim().split('\n');
      if (lines.length < 3) return match;
      const headers = lines[0].split('|').map(h => h.trim()).filter(Boolean);
      const aligns = lines[1].split('|').map(a => a.trim()).filter(Boolean);
      const rows = lines.slice(2).map(row => row.split('|').map(c => c.trim()).filter(Boolean));
      // Calculate column widths
      const colWidths = headers.map((h, i) => Math.max(h.length, ...rows.map(r => (r[i] || '').length)));
      // Helper to pad left/right/center
      const pad = (str, len, align) => {
        const s = str || '';
        if (align === 'right') return ' '.repeat(len - s.length) + s;
        if (align === 'center') {
          const total = len - s.length;
          const left = Math.floor(total / 2);
          const right = total - left;
          return ' '.repeat(left) + s + ' '.repeat(right);
        }
        return s + ' '.repeat(len - s.length); // left
      };
      // Determine alignment from markdown (default left)
      const getAlign = (i) => {
        if (!aligns[i]) return 'left';
        if (/^:-+:$/.test(aligns[i])) return 'center';
        if (/^-+:$/.test(aligns[i])) return 'right';
        return 'left';
      };
      // Build ASCII table
      let out = '';
      // Top border
      out += '+' + colWidths.map(w => '-'.repeat(w + 2)).join('+') + '+\n';
      // Header row (centered)
      out += '|' + headers.map((h, i) => ' ' + pad(h, colWidths[i], 'center') + ' ').join('|') + '|\n';
      // Header separator
      out += '+' + colWidths.map(w => '-'.repeat(w + 2)).join('+') + '+\n';
      // Data rows
      for (const row of rows) {
        out += '|' + headers.map((_, i) => ' ' + pad(row[i] || '', colWidths[i], getAlign(i)) + ' ').join('|') + '|\n';
      }
      // Bottom border
      out += '+' + colWidths.map(w => '-'.repeat(w + 2)).join('+') + '+\n';
      return '\n<pre style="font-size:12px;line-height:1.2;margin:16px 0;">' + out + '</pre>\n';
    });
  }

  // Preprocess markdown to replace tables with ASCII tables
  const asciiMarkdown = mdTableToAscii(markdown);

  // Use marked for the rest
  let html = marked.parse(asciiMarkdown)
    .replace(/✅/g, '&#9989;')
    .replace(/❌/g, '&#10060;')
    .replace(/⚠️/g, '&#9888;')
    .replace(/ℹ️/g, '&#8505;');
  
  const fullHtml = `
    <!DOCTYPE html>
    <html>
    <head>
      <meta charset="UTF-8">
      <style>
        body {
          font-family: Arial, sans-serif;
          font-size: 13px;
          line-height: 1.5;
          max-width: 900px;
          margin: 0 auto;
          padding: 20px;
        }
        h1 {
          color: #111;
          border-bottom: 3px solid #111;
          padding-bottom: 8px;
          margin-top: 32px;
        }
        h2 {
          color: #222;
          border-bottom: 2px solid #111;
          padding-bottom: 6px;
          margin-top: 24px;
        }
        h3 {
          color: #333;
          margin-top: 18px;
          }
          tr:hover td {
            background: #e6f0fa;
          }
          table {
            border-radius: 8px;
            overflow: hidden;
        }
        code {
          background-color: #f4f4f4;
          padding: 2px 6px;
          border-radius: 3px;
        }
        img {
          max-width: 100%;
          height: auto;
          border: 1px solid #ddd;
          margin: 10px 0;
        }
        table {
          border-collapse: collapse;
          width: 100%;
          margin: 20px 0;
          font-size: 13px;
        }
        th, td {
          border: 1px solid #888;
          padding: 8px 10px;
          text-align: left;
        }
        th {
          background-color: #222;
          color: #fff;
        }
        tbody tr:nth-child(even) {
          background-color: #f6f6f6;
        }
        tbody tr:nth-child(odd) {
          background-color: #fff;
        }
        li {
          margin: 4px 0;
        }
      </style>
    </head>
    <body>
      ${html}
    </body>
    </html>
  `;
  
  await page.setContent(fullHtml);
  

  await page.pdf({
    path: outputFile,
    format: 'A4',
    margin: { top: '20mm', right: '20mm', bottom: '20mm', left: '20mm' },
    printBackground: true
  });
  console.log(`✅ PDF generated: ${outputFile}`);
  
  await browser.close();
})();
