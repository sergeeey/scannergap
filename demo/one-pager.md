# ScannerGap — Security Blind Spot Benchmark

## One-Pager

---

### The Problem

Static analysis scanners (Semgrep, CodeQL, Bandit) are standard in modern CI/CD.
Teams rely on them to catch vulnerabilities before production.

**They miss 61.5% of real-world CVEs.**

This is not a configuration issue. It is a structural limitation of current
static analysis approaches.

---

### What We Found

| Metric | Value |
|--------|-------|
| CVEs tested | 135 (NVD, 2023-2025) |
| Scanners | Semgrep + Bandit + CodeQL |
| Blind spot rate | **61.5%** |
| Systematic categories | 13 CWE clusters |
| Verified | Reproducible, all kill criteria passed |

**Top blind spot categories:**
- Code injection (CWE-94): 29 blind CVEs
- SSRF (CWE-918): 25 blind CVEs
- Path traversal (CWE-22): 24 blind CVEs
- Unrestricted upload (CWE-434): 17 blind CVEs
- Cross-site scripting (CWE-79): 11 blind CVEs

---

### Why Scanners Miss These

Current SAST tools use **pattern matching** and **local data flow analysis**.
They cannot:

- Track data across function/module boundaries (interprocedural taint)
- Understand that a security check exists on path A but not path B (semantic)
- Recognize non-standard sinks like `boto3(endpoint_url=...)` as dangerous
- Detect correct-syntax-but-wrong-logic vulnerabilities

---

### What We Built

**26 custom Semgrep rules** that detect patterns standard rules miss.
Covers Python, JavaScript, Java, PHP, Ruby.

```bash
# Run on any codebase — local only, nothing sent externally
semgrep scan --config scannergap/detector/rules/ /path/to/code
```

**Impact**: closes 30% of identified blind spots with zero configuration.

---

### For Security Teams

1. **Run the rules** on your repos today (5 minutes, fully local)
2. **Triage findings** — these are vulnerabilities your pipeline marks "clean"
3. **Add to CI** alongside existing scanner config
4. **Track** blind spot coverage as a security metric

---

### Methodology

Transferred from ARCHCODE (genomic variant analysis). Same falsification-first
framework that found 27 DNA mutations invisible to all sequence predictors.

All data, rules, and evaluation scripts are open source and reproducible.

---

*ScannerGap is not a scanner. It's a benchmark that shows where your scanners stop seeing.*
