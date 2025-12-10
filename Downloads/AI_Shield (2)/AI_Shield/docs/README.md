# Documentation Directory

This directory contains all project documentation, PDFs, and documentation generation scripts.

## Contents

### PDF Documents
- `AI_Shield_Documentation.pdf` - Main project documentation
- `AI_Shield_Full_Summary.pdf` - Comprehensive project summary
- `AI_Shield_Report.pdf` - Standard project report

### Markdown Documentation
- `SYSTEM_DOCUMENTATION.md` - System architecture and design documentation
- `FULL_SUMMARY.md` - Full project summary (source for PDF)
- `AI_Shield_Report.md` - Project report (source for PDF)
- `CLOUD_SUBMISSION_SETUP.md` - Cloud protection and sample submission setup guide
- `CONTINUOUS_SCANNING.md` - Continuous scanning feature documentation
- `QUARANTINE_ALGORITHM.md` - Quarantine algorithm documentation
- `DELETE_ANOMALIES_README.md` - Delete anomalies script documentation
- `PROJECT_SUMMARY.md` - Project overview summary
- `README-INSTALL.md` - Installation instructions

### PDF Generation Scripts
- `render-full-summary-to-pdf.mjs` - Generates full summary PDF
- `render-report-to-pdf.mjs` - Generates report PDF
- `render-readme-to-pdf.mjs` - Generates README PDF
- `mdpdf.run.js` - PDF generation utility
- `mdpdf.styles.css` - PDF styling

## Generating PDFs

To generate PDFs from markdown files, use the corresponding `.mjs` script:

```bash
node render-full-summary-to-pdf.mjs
node render-report-to-pdf.mjs
node render-readme-to-pdf.mjs
```

## Organization

All documentation is centralized here for easy access and maintenance. The root directory contains only essential README files for quick reference.

