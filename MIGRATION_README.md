# Migration Guide Quick Reference

## 🚀 Regenerate the Migration PDF
After editing `MIGRATION_GUIDE.md`, run:

```bash
npm run migration:pdf
```

This generates a timestamped PDF (e.g. `MIGRATION_GUIDE_<timestamp>.pdf`) for easy sharing.

## 📄 Files Added
- `MIGRATION_GUIDE.md` – Full markdown guide for switching computers
- `MIGRATION_GUIDE_<timestamp>.pdf` – Pre-generated PDF snapshot
- `scripts/generate-migration-pdf.js` – PDF generator script
- `package.json` → Added `migration:pdf` npm script

## 🧭 Using the Migration Guide
When you get a new laptop/desktop:
1. Open `MIGRATION_GUIDE.md` or the PDF on your current machine.
2. Follow hardware recommendations (CPU, RAM, SSD).
3. Set up OS (Linux or WSL2).
4. Clone repo, install dependencies, validate tests.
5. Optional: regenerate the PDF on the new machine to confirm setup is working.

## ✅ Quick Test After Migration
```bash
npx playwright test tests/challenge/test-case-4-github-pr-scraper.spec.ts --project=chromium
```

---
This README tracks migration documentation artifacts. Keep it updated if the guide evolves.
