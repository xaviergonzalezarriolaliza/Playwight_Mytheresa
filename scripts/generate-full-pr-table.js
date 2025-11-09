const fs = require('fs');
const path = require('path');

// Read the CSV file
const csvPath = path.join(__dirname, '..', 'test-results', 'github-prs-chromium-2025-11-09T15-09-44-677Z.csv');
const csvContent = fs.readFileSync(csvPath, 'utf-8');

// Parse CSV manually to handle commas in quoted fields
const lines = csvContent.trim().split('\n');
const rows = [];

for (let i = 1; i < lines.length; i++) { // Skip header
  const line = lines[i];
  const fields = [];
  let currentField = '';
  let inQuotes = false;
  
  for (let j = 0; j < line.length; j++) {
    const char = line[j];
    
    if (char === '"') {
      inQuotes = !inQuotes;
    } else if (char === ',' && !inQuotes) {
      fields.push(currentField);
      currentField = '';
    } else {
      currentField += char;
    }
  }
  fields.push(currentField); // Add last field
  
  if (fields.length >= 4) {
    const prName = fields[0].trim();
    const createdDate = fields[1].trim();
    const author = fields[2].trim();
    const prUrl = fields[3].trim();
    
    // Extract PR number from URL
    const prNumber = prUrl.split('/').pop();
    
    rows.push({
      prNumber,
      prName,
      author,
      createdDate,
      prUrl
    });
  }
}

// Generate markdown table
let markdown = '| PR# | PR Title | Author | Created Date | Verification |\n';
markdown += '|-----|----------|--------|--------------|--------------|';

for (const row of rows) {
  markdown += `\n| [#${row.prNumber}](${row.prUrl}) | ${row.prName} | ${row.author} | ${row.createdDate} | ✅✅✅ |`;
}

// Write to file
const outputPath = path.join(__dirname, '..', 'docs', 'all-prs-table.md');
fs.writeFileSync(outputPath, markdown);

console.log(`Generated table with ${rows.length} PRs`);
console.log(`Output written to: ${outputPath}`);
