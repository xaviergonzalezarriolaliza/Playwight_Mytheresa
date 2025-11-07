/**
 * Script to organize test artifacts (screenshots, videos, traces) into timestamped folders
 * This helps maintain a clean documentation structure for each test run
 * 
 * Usage: node scripts/organize-test-artifacts.js
 */

const fs = require('fs');
const path = require('path');

// Helper to format timestamp
function pad(n) { return String(n).padStart(2, '0'); }
function timestamp() {
  const d = new Date();
  return `${d.getFullYear()}-${pad(d.getMonth() + 1)}-${pad(d.getDate())}_${pad(d.getHours())}-${pad(d.getMinutes())}-${pad(d.getSeconds())}`;
}

// Main function
function organizeArtifacts() {
  const testResultsDir = path.join(__dirname, '..', 'test-results');
  const reportsDir = path.join(__dirname, '..', 'reports');
  const artifactsDir = path.join(__dirname, '..', 'test-artifacts');
  
  // Check if test-results exists
  if (!fs.existsSync(testResultsDir)) {
    console.log('No test-results directory found. Run tests first.');
    return;
  }
  
  // Create artifacts directory if it doesn't exist
  if (!fs.existsSync(artifactsDir)) {
    fs.mkdirSync(artifactsDir, { recursive: true });
  }
  
  // Create timestamped folder for this run
  const runFolder = path.join(artifactsDir, `run_${timestamp()}`);
  fs.mkdirSync(runFolder, { recursive: true });
  
  console.log(`\n📁 Organizing test artifacts into: ${runFolder}\n`);
  
  // Get all test result folders
  const testFolders = fs.readdirSync(testResultsDir)
    .filter(file => {
      const fullPath = path.join(testResultsDir, file);
      return fs.statSync(fullPath).isDirectory();
    });
  
  let totalScreenshots = 0;
  let totalVideos = 0;
  let totalTraces = 0;
  
  // Process each test folder
  testFolders.forEach(folder => {
    const sourcePath = path.join(testResultsDir, folder);
    const destPath = path.join(runFolder, folder);
    
    // Create destination folder
    fs.mkdirSync(destPath, { recursive: true });
    
    // Copy all artifacts
    const files = fs.readdirSync(sourcePath);
    files.forEach(file => {
      const sourceFile = path.join(sourcePath, file);
      const destFile = path.join(destPath, file);
      
      if (fs.statSync(sourceFile).isFile()) {
        fs.copyFileSync(sourceFile, destFile);
        
        // Count artifacts
        if (file.endsWith('.png')) totalScreenshots++;
        if (file.endsWith('.webm')) totalVideos++;
        if (file.endsWith('.zip')) totalTraces++;
      }
    });
  });
  
  // Create a summary file
  const summary = {
    timestamp: new Date().toISOString(),
    testFolders: testFolders.length,
    artifacts: {
      screenshots: totalScreenshots,
      videos: totalVideos,
      traces: totalTraces
    }
  };
  
  fs.writeFileSync(
    path.join(runFolder, 'SUMMARY.json'),
    JSON.stringify(summary, null, 2)
  );
  
  // Create README
  const readme = `# Test Run Artifacts - ${summary.timestamp}

## Summary
- **Test Folders**: ${testFolders.length}
- **Screenshots**: ${totalScreenshots}
- **Videos**: ${totalVideos}
- **Traces**: ${totalTraces}

## Folder Structure
Each test case has its own folder containing:
- **Screenshots** (.png) - Captured at key points and on failure
- **Videos** (.webm) - Full video recording of the test execution
- **Traces** (.zip) - Detailed Playwright trace for debugging

## Viewing Artifacts

### Screenshots
Open .png files with any image viewer.

### Videos
Open .webm files with a modern browser or media player.

### Traces
View traces using Playwright's trace viewer:
\`\`\`bash
npx playwright show-trace <folder>/trace.zip
\`\`\`

## Test Folders
${testFolders.map(f => `- ${f}`).join('\n')}
`;
  
  fs.writeFileSync(
    path.join(runFolder, 'README.md'),
    readme
  );
  
  console.log('✅ Artifacts organized successfully!\n');
  console.log(`📊 Summary:`);
  console.log(`   - Test Folders: ${testFolders.length}`);
  console.log(`   - Screenshots: ${totalScreenshots}`);
  console.log(`   - Videos: ${totalVideos}`);
  console.log(`   - Traces: ${totalTraces}`);
  console.log(`\n📍 Location: ${runFolder}\n`);
}

// Run the script
try {
  organizeArtifacts();
} catch (error) {
  console.error('❌ Error organizing artifacts:', error.message);
  process.exit(1);
}
