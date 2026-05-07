# Reports

| File | Purpose |
| ---- | ------- |
| `8TechBank_Security_Assessment.md` | The main 8-12 page report (Task 5). Convert to PDF before submission (`pandoc -o 8TechBank_Security_Assessment.pdf 8TechBank_Security_Assessment.md` or use any Markdown-to-PDF tool). |
| `vulnerability_assessment_matrix.md` | Standalone matrix referenced from §3 / Appendix A. |

## Converting Markdown → PDF

```bash
# install once
sudo apt install -y pandoc texlive-xetex   # Debian/Ubuntu
# convert
pandoc report/8TechBank_Security_Assessment.md \
       -o report/8TechBank_Security_Assessment.pdf \
       --from markdown --pdf-engine=xelatex --toc --number-sections
```

If you don't want to install LaTeX, paste the Markdown into Google Docs
or Word and "Save as PDF". The report uses only Markdown features that
render correctly in either tool.
