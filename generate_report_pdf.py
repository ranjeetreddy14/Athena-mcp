#!/usr/bin/env python3
"""Generate PDF/HTML from security audit markdown report."""
import markdown2
from pathlib import Path

md_path = Path(r'C:\Users\ranje\.gemini\antigravity\brain\4537c5cd-ebc9-4479-8b6c-ed8a899befec\security_audit_report.md')
html_path = md_path.parent / 'security_audit_report.html'
pdf_path = md_path.parent / 'security_audit_report.pdf'

md_content = md_path.read_text(encoding='utf-8')
html = markdown2.markdown(md_content, extras=['tables', 'fenced-code-blocks', 'cuddled-lists'])

# Create styled HTML
styled_html = '''<!DOCTYPE html>
<html>
<head>
<meta charset="utf-8">
<title>Security Audit Report - Threat Intel MCP Server v1.1</title>
<style>
body { font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif; max-width: 900px; margin: 40px auto; padding: 20px; line-height: 1.6; color: #333; }
h1 { color: #c0392b; border-bottom: 2px solid #c0392b; padding-bottom: 10px; }
h2 { color: #2c3e50; margin-top: 30px; border-bottom: 1px solid #ecf0f1; padding-bottom: 5px; }
h3 { color: #34495e; }
pre { background: #2d3436; color: #dfe6e9; padding: 15px; border-radius: 5px; overflow-x: auto; font-size: 0.9em; }
code { background: #ecf0f1; padding: 2px 6px; border-radius: 3px; font-family: Consolas, 'Courier New', monospace; font-size: 0.9em; }
pre code { background: transparent; padding: 0; }
table { border-collapse: collapse; width: 100%; margin: 20px 0; }
th, td { border: 1px solid #bdc3c7; padding: 10px; text-align: left; }
th { background: #34495e; color: white; }
tr:nth-child(even) { background: #f9f9f9; }
blockquote { border-left: 4px solid #e74c3c; margin: 20px 0; padding: 10px 20px; background: #fdf2f2; }
a { color: #3498db; }
hr { border: none; border-top: 1px solid #bdc3c7; margin: 30px 0; }
.footer { color: #7f8c8d; font-size: 0.9em; margin-top: 50px; padding-top: 20px; border-top: 1px solid #ecf0f1; }
</style>
</head>
<body>
''' + html + '''
<div class="footer">
<p>Report generated: 2026-01-05 | Classification: Internal Security Document</p>
</div>
</body>
</html>'''

html_path.write_text(styled_html, encoding='utf-8')
print(f'HTML report saved: {html_path}')

# Try to generate PDF using weasyprint if available
try:
    from weasyprint import HTML
    HTML(string=styled_html).write_pdf(str(pdf_path))
    print(f'PDF report saved: {pdf_path}')
except ImportError:
    print('WeasyPrint not available. To generate PDF, install with: pip install weasyprint')
    print(f'HTML version saved - can be printed to PDF from browser.')
except Exception as e:
    print(f'PDF generation failed: {e}')
    print(f'HTML version saved - can be printed to PDF from browser.')
